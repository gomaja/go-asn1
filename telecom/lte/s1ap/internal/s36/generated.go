// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s36 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s36

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s23 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s23"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s35 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s35"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// ResetIEContainer is the concrete ProtocolIEContainer[ResetIEValue].
type ResetIEContainer []ResetIEField

// ResetIEField is the concrete ProtocolIEField[ResetIEValue].
type ResetIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ResetIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetIEField) WithoutReplay() ResetIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *ResetIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *ResetIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ResetIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResetIEField{}
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
	var zero ResetIEValue

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

// HandoverPreparationFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[HandoverPreparationFailure].
type HandoverPreparationFailureUnsuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s25.HandoverPreparationFailure, aper.DecodeState,

	) (s25.HandoverPreparationFailure, aper.Snapshot,

	)
	compare func(s25.HandoverPreparationFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s25.HandoverPreparationFailure,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s25.HandoverPreparationFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s25.HandoverPreparationFailure,

		error)
	inject func(s25.HandoverPreparationFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b HandoverPreparationFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverPreparationFailureUnsuccessfulBinding) Codec() s25.HandoverPreparationFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s25.HandoverPreparationFailureValueCodec{}
	}
	return func() s25.HandoverPreparationFailureValueCodec {
		sealed := s25.HandoverPreparationFailureValueCodec{}
		*s25.BridgeHandoverPreparationFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s25.BridgeHandoverPreparationFailureValueCodecFieldDecode(&sealed) = b.decode
		*s25.BridgeHandoverPreparationFailureValueCodecFieldEncode(&sealed) = func(value s25.HandoverPreparationFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s25.BridgeHandoverPreparationFailureValueCodecFieldCapture(&sealed) = b.capture
		*s25.BridgeHandoverPreparationFailureValueCodecFieldCompare(&sealed) = b.compare
		*s25.BridgeHandoverPreparationFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b HandoverPreparationFailureUnsuccessfulBinding) Build(body s25.HandoverPreparationFailure,

	options ...aper.BuildOption) (UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return UnsuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// HandoverFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[HandoverFailure].
type HandoverFailureUnsuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s25.HandoverFailure, aper.DecodeState,

	) (s25.HandoverFailure, aper.Snapshot,

	)
	compare func(s25.HandoverFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s25.HandoverFailure,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s25.HandoverFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s25.HandoverFailure,

		error)
	inject func(s25.HandoverFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b HandoverFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverFailureUnsuccessfulBinding) Codec() s25.HandoverFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s25.HandoverFailureValueCodec{}
	}
	return func() s25.HandoverFailureValueCodec {
		sealed := s25.HandoverFailureValueCodec{}
		*s25.BridgeHandoverFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s25.BridgeHandoverFailureValueCodecFieldDecode(&sealed) = b.decode
		*s25.BridgeHandoverFailureValueCodecFieldEncode(&sealed) = func(value s25.HandoverFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s25.BridgeHandoverFailureValueCodecFieldCapture(&sealed) = b.capture
		*s25.BridgeHandoverFailureValueCodecFieldCompare(&sealed) = b.compare
		*s25.BridgeHandoverFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b HandoverFailureUnsuccessfulBinding) Build(body s25.HandoverFailure,

	options ...aper.BuildOption) (UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return UnsuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// PathSwitchRequestFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[PathSwitchRequestFailure].
type PathSwitchRequestFailureUnsuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s26.PathSwitchRequestFailure, aper.DecodeState,

	) (s26.PathSwitchRequestFailure, aper.Snapshot,

	)
	compare func(s26.PathSwitchRequestFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s26.PathSwitchRequestFailure,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s26.PathSwitchRequestFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s26.PathSwitchRequestFailure,

		error)
	inject func(s26.PathSwitchRequestFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestFailureUnsuccessfulBinding) Codec() s26.PathSwitchRequestFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s26.PathSwitchRequestFailureValueCodec{}
	}
	return func() s26.PathSwitchRequestFailureValueCodec {
		sealed := s26.PathSwitchRequestFailureValueCodec{}
		*s26.BridgePathSwitchRequestFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s26.BridgePathSwitchRequestFailureValueCodecFieldDecode(&sealed) = b.decode
		*s26.BridgePathSwitchRequestFailureValueCodecFieldEncode(&sealed) = func(value s26.PathSwitchRequestFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s26.BridgePathSwitchRequestFailureValueCodecFieldCapture(&sealed) = b.capture
		*s26.BridgePathSwitchRequestFailureValueCodecFieldCompare(&sealed) = b.compare
		*s26.BridgePathSwitchRequestFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b PathSwitchRequestFailureUnsuccessfulBinding) Build(body s26.PathSwitchRequestFailure,

	options ...aper.BuildOption) (UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return UnsuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// InitialContextSetupFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[InitialContextSetupFailure].
type InitialContextSetupFailureUnsuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s25.InitialContextSetupFailure, aper.DecodeState,

	) (s25.InitialContextSetupFailure, aper.Snapshot,

	)
	compare func(s25.InitialContextSetupFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s25.InitialContextSetupFailure,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s25.InitialContextSetupFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s25.InitialContextSetupFailure,

		error)
	inject func(s25.InitialContextSetupFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupFailureUnsuccessfulBinding) Codec() s25.InitialContextSetupFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s25.InitialContextSetupFailureValueCodec{}
	}
	return func() s25.InitialContextSetupFailureValueCodec {
		sealed := s25.InitialContextSetupFailureValueCodec{}
		*s25.BridgeInitialContextSetupFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s25.BridgeInitialContextSetupFailureValueCodecFieldDecode(&sealed) = b.decode
		*s25.BridgeInitialContextSetupFailureValueCodecFieldEncode(&sealed) = func(value s25.InitialContextSetupFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s25.BridgeInitialContextSetupFailureValueCodecFieldCapture(&sealed) = b.capture
		*s25.BridgeInitialContextSetupFailureValueCodecFieldCompare(&sealed) = b.compare
		*s25.BridgeInitialContextSetupFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b InitialContextSetupFailureUnsuccessfulBinding) Build(body s25.InitialContextSetupFailure,

	options ...aper.BuildOption) (UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return UnsuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// S1SetupFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[S1SetupFailure].
type S1SetupFailureUnsuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s26.S1SetupFailure, aper.DecodeState,

	) (s26.S1SetupFailure, aper.Snapshot,

	)
	compare func(s26.S1SetupFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s26.S1SetupFailure,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s26.S1SetupFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s26.S1SetupFailure,

		error)
	inject func(s26.S1SetupFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b S1SetupFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupFailureUnsuccessfulBinding) Codec() s26.S1SetupFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s26.S1SetupFailureValueCodec{}
	}
	return func() s26.S1SetupFailureValueCodec {
		sealed := s26.S1SetupFailureValueCodec{}
		*s26.BridgeS1SetupFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s26.BridgeS1SetupFailureValueCodecFieldDecode(&sealed) = b.decode
		*s26.BridgeS1SetupFailureValueCodecFieldEncode(&sealed) = func(value s26.S1SetupFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s26.BridgeS1SetupFailureValueCodecFieldCapture(&sealed) = b.capture
		*s26.BridgeS1SetupFailureValueCodecFieldCompare(&sealed) = b.compare
		*s26.BridgeS1SetupFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b S1SetupFailureUnsuccessfulBinding) Build(body s26.S1SetupFailure,

	options ...aper.BuildOption) (UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return UnsuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextModificationFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[UEContextModificationFailure].
type UEContextModificationFailureUnsuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(UEContextModificationFailure, aper.DecodeState,

	) (UEContextModificationFailure, aper.Snapshot,

	)
	compare func(UEContextModificationFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*UEContextModificationFailure,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*UEContextModificationFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (UEContextModificationFailure,

		error)
	inject func(UEContextModificationFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationFailureUnsuccessfulBinding) Codec() UEContextModificationFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return UEContextModificationFailureValueCodec{}
	}
	return UEContextModificationFailureValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value UEContextModificationFailure,

		fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates a body and constructs its bound procedure message.
func (b UEContextModificationFailureUnsuccessfulBinding) Build(body UEContextModificationFailure,

	options ...aper.BuildOption) (UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return UnsuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ENBConfigurationUpdateFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[ENBConfigurationUpdateFailure].
type ENBConfigurationUpdateFailureUnsuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s24.ENBConfigurationUpdateFailure, aper.DecodeState,

	) (s24.ENBConfigurationUpdateFailure, aper.Snapshot,

	)
	compare func(s24.ENBConfigurationUpdateFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s24.ENBConfigurationUpdateFailure,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s24.ENBConfigurationUpdateFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s24.ENBConfigurationUpdateFailure,

		error)
	inject func(s24.ENBConfigurationUpdateFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationUpdateFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationUpdateFailureUnsuccessfulBinding) Codec() s24.ENBConfigurationUpdateFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s24.ENBConfigurationUpdateFailureValueCodec{}
	}
	return func() s24.ENBConfigurationUpdateFailureValueCodec {
		sealed := s24.ENBConfigurationUpdateFailureValueCodec{}
		*s24.BridgeENBConfigurationUpdateFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s24.BridgeENBConfigurationUpdateFailureValueCodecFieldDecode(&sealed) = b.decode
		*s24.BridgeENBConfigurationUpdateFailureValueCodecFieldEncode(&sealed) = func(value s24.ENBConfigurationUpdateFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s24.BridgeENBConfigurationUpdateFailureValueCodecFieldCapture(&sealed) = b.capture
		*s24.BridgeENBConfigurationUpdateFailureValueCodecFieldCompare(&sealed) = b.compare
		*s24.BridgeENBConfigurationUpdateFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ENBConfigurationUpdateFailureUnsuccessfulBinding) Build(body s24.ENBConfigurationUpdateFailure,

	options ...aper.BuildOption) (UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return UnsuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// MMEConfigurationUpdateFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[MMEConfigurationUpdateFailure].
type MMEConfigurationUpdateFailureUnsuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s25.MMEConfigurationUpdateFailure, aper.DecodeState,

	) (s25.MMEConfigurationUpdateFailure, aper.Snapshot,

	)
	compare func(s25.MMEConfigurationUpdateFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s25.MMEConfigurationUpdateFailure,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s25.MMEConfigurationUpdateFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s25.MMEConfigurationUpdateFailure,

		error)
	inject func(s25.MMEConfigurationUpdateFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationUpdateFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationUpdateFailureUnsuccessfulBinding) Codec() s25.MMEConfigurationUpdateFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s25.MMEConfigurationUpdateFailureValueCodec{}
	}
	return func() s25.MMEConfigurationUpdateFailureValueCodec {
		sealed := s25.MMEConfigurationUpdateFailureValueCodec{}
		*s25.BridgeMMEConfigurationUpdateFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s25.BridgeMMEConfigurationUpdateFailureValueCodecFieldDecode(&sealed) = b.decode
		*s25.BridgeMMEConfigurationUpdateFailureValueCodecFieldEncode(&sealed) = func(value s25.MMEConfigurationUpdateFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s25.BridgeMMEConfigurationUpdateFailureValueCodecFieldCapture(&sealed) = b.capture
		*s25.BridgeMMEConfigurationUpdateFailureValueCodecFieldCompare(&sealed) = b.compare
		*s25.BridgeMMEConfigurationUpdateFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b MMEConfigurationUpdateFailureUnsuccessfulBinding) Build(body s25.MMEConfigurationUpdateFailure,

	options ...aper.BuildOption) (UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return UnsuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UEContextResumeFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[UEContextResumeFailure].
type UEContextResumeFailureUnsuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(UEContextResumeFailure, aper.DecodeState,

	) (UEContextResumeFailure, aper.Snapshot,

	)
	compare func(UEContextResumeFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*UEContextResumeFailure,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*UEContextResumeFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (UEContextResumeFailure,

		error)
	inject func(UEContextResumeFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UEContextResumeFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextResumeFailureUnsuccessfulBinding) Codec() UEContextResumeFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return UEContextResumeFailureValueCodec{}
	}
	return UEContextResumeFailureValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value UEContextResumeFailure,

		fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates a body and constructs its bound procedure message.
func (b UEContextResumeFailureUnsuccessfulBinding) Build(body UEContextResumeFailure,

	options ...aper.BuildOption) (UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return UnsuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// S1RemovalFailureUnsuccessfulBinding is the concrete UnsuccessfulBinding[S1RemovalFailure].
type S1RemovalFailureUnsuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s26.S1RemovalFailure, aper.DecodeState,

	) (s26.S1RemovalFailure, aper.Snapshot,

	)
	compare func(s26.S1RemovalFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s26.S1RemovalFailure,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s26.S1RemovalFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s26.S1RemovalFailure,

		error)
	inject func(s26.S1RemovalFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b S1RemovalFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1RemovalFailureUnsuccessfulBinding) Codec() s26.S1RemovalFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s26.S1RemovalFailureValueCodec{}
	}
	return func() s26.S1RemovalFailureValueCodec {
		sealed := s26.S1RemovalFailureValueCodec{}
		*s26.BridgeS1RemovalFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s26.BridgeS1RemovalFailureValueCodecFieldDecode(&sealed) = b.decode
		*s26.BridgeS1RemovalFailureValueCodecFieldEncode(&sealed) = func(value s26.S1RemovalFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s26.BridgeS1RemovalFailureValueCodecFieldCapture(&sealed) = b.capture
		*s26.BridgeS1RemovalFailureValueCodecFieldCompare(&sealed) = b.compare
		*s26.BridgeS1RemovalFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b S1RemovalFailureUnsuccessfulBinding) Build(body s26.S1RemovalFailure,

	options ...aper.BuildOption) (UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return UnsuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s21.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s21.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s21.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s21.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}
func BridgeResetIEValueCaptureS1APProtocolIEContainer(v *ResetIEContainer, s *aper.SemanticCapture) {
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
			BridgeResetIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeResetIEValueCompareS1APProtocolIEContainer(v *ResetIEContainer, s *aper.SemanticComparison) {
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
			BridgeResetIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIEContainer(v *s12.UECapabilityInfoIndicationIEContainer, s *aper.SemanticCapture) {
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
			BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIEContainer(v *s12.UECapabilityInfoIndicationIEContainer, s *aper.SemanticComparison) {
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
			BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIEContainer(v *s23.UEContextModificationConfirmIEContainer, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIEContainer(v *s23.UEContextModificationConfirmIEContainer, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIEContainer(v *s23.UEContextModificationFailureIEContainer, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEContainer(v *s23.UEContextModificationFailureIEContainer, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIEContainer(v *s21.UEContextModificationIndicationIEContainer, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIEContainer(v *s21.UEContextModificationIndicationIEContainer, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIEContainer(v *s23.UEContextModificationResponseIEContainer, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationResponseIEValueCompareS1APProtocolIEContainer(v *s23.UEContextModificationResponseIEContainer, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationResponseIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEContainer(v *s23.UEContextResumeFailureIEContainer, s *aper.SemanticCapture) {
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
			BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEContainer(v *s23.UEContextResumeFailureIEContainer, s *aper.SemanticComparison) {
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
			BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEContainer(v *s28.UEContextSuspendResponseIEContainer, s *aper.SemanticCapture) {
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
			BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEContainer(v *s28.UEContextSuspendResponseIEContainer, s *aper.SemanticComparison) {
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
			BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEInformationTransferIEValueCaptureS1APProtocolIEContainer(v *s31.UEInformationTransferIEContainer, s *aper.SemanticCapture) {
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
			BridgeUEInformationTransferIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEInformationTransferIEValueCompareS1APProtocolIEContainer(v *s31.UEInformationTransferIEContainer, s *aper.SemanticComparison) {
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
			BridgeUEInformationTransferIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIEContainer(v *s12.UERadioCapabilityIDMappingRequestIEContainer, s *aper.SemanticCapture) {
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
			BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIEContainer(v *s12.UERadioCapabilityIDMappingRequestIEContainer, s *aper.SemanticComparison) {
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
			BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEContainer(v *s23.UERadioCapabilityIDMappingResponseIEContainer, s *aper.SemanticCapture) {
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
			BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEContainer(v *s23.UERadioCapabilityIDMappingResponseIEContainer, s *aper.SemanticComparison) {
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
			BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIEContainer(v *s12.UERadioCapabilityMatchRequestIEContainer, s *aper.SemanticCapture) {
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
			BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIEContainer(v *s12.UERadioCapabilityMatchRequestIEContainer, s *aper.SemanticComparison) {
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
			BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEContainer(v *s24.UERadioCapabilityMatchResponseIEContainer, s *aper.SemanticCapture) {
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
			BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEContainer(v *s24.UERadioCapabilityMatchResponseIEContainer, s *aper.SemanticComparison) {
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
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUES1APIDPairExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.UES1APIDPairExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeUES1APIDPairExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUES1APIDPairExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.UES1APIDPairExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeUES1APIDPairExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ResetCauseIEBinding is the concrete IEBinding[Cause, ResetIEValue].
type ResetCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) ResetIEValue

	get func(*ResetIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ResetCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ResetCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ResetCauseIEBinding) New(value s14.Cause,

) (ResetIEField, error) {
	if b.inject == nil {
		return ResetIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ResetIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ResetIEField{}, aper.OperationError(err, "Value.New")
	}
	return ResetIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ResetCauseIEBinding) Get(field *ResetIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ResetResetTypeIEBinding is the concrete IEBinding[ResetType, ResetIEValue].
type ResetResetTypeIEBinding struct {
	info   s00.FieldInfo
	codec  ResetTypeValueCodec
	inject func(s35.ResetType,

	) ResetIEValue

	get func(*ResetIEValue,

	) (*s35.ResetType,

		bool)
}

// Info returns the source descriptor for this binding.
func (b ResetResetTypeIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ResetResetTypeIEBinding) Codec() ResetTypeValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b ResetResetTypeIEBinding) New(value s35.ResetType,

) (ResetIEField, error) {
	if b.inject == nil {
		return ResetIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ResetIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ResetIEField{}, aper.OperationError(err, "Value.New")
	}
	return ResetIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b ResetResetTypeIEBinding) Get(field *ResetIEField) (*s35.ResetType,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ResetTypeValueCodec is the concrete ValueCodec[ResetType].
type ResetTypeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s35.ResetType,

		error)
	encode func(s35.ResetType,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s35.ResetType, aper.DecodeState,

	) (s35.ResetType, aper.Snapshot,

	)
	compare func(s35.ResetType, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetTypeValueCodec) New(value s35.ResetType,

) (ResetTypeAPERValue, error) {
	if c.encode == nil {
		return ResetTypeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetTypeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetTypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetTypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetTypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetTypeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetTypeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetTypeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetTypeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetTypeValueCodec) EncodeAPER(value ResetTypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetTypeValueCodec) encodeBudgetValue(value s35.ResetType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetTypeValueCodec) encodeChanged(value s35.ResetType,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetValueCodec is the concrete ValueCodec[Reset].
type ResetValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (Reset,

		error)
	encode func(Reset,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(Reset, aper.DecodeState,

	) (Reset, aper.Snapshot,

	)
	compare func(Reset, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetValueCodec) New(value Reset,

) (ResetAPERValue, error) {
	if c.encode == nil {
		return ResetAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetValueCodec) EncodeAPER(value ResetAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetValueCodec) encodeBudgetValue(value Reset,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetValueCodec) encodeChanged(value Reset,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UECapabilityInfoIndicationValueCodec is the concrete ValueCodec[UECapabilityInfoIndication].
type UECapabilityInfoIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UECapabilityInfoIndication,

		error)
	encode func(UECapabilityInfoIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UECapabilityInfoIndication, aper.DecodeState,

	) (UECapabilityInfoIndication, aper.Snapshot,

	)
	compare func(UECapabilityInfoIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UECapabilityInfoIndicationValueCodec) New(value UECapabilityInfoIndication,

) (UECapabilityInfoIndicationAPERValue, error) {
	if c.encode == nil {
		return UECapabilityInfoIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UECapabilityInfoIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UECapabilityInfoIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UECapabilityInfoIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UECapabilityInfoIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UECapabilityInfoIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UECapabilityInfoIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UECapabilityInfoIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UECapabilityInfoIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UECapabilityInfoIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UECapabilityInfoIndicationValueCodec) EncodeAPER(value UECapabilityInfoIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UECapabilityInfoIndicationValueCodec) encodeBudgetValue(value UECapabilityInfoIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UECapabilityInfoIndicationValueCodec) encodeChanged(value UECapabilityInfoIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationConfirmValueCodec is the concrete ValueCodec[UEContextModificationConfirm].
type UEContextModificationConfirmValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationConfirm,

		error)
	encode func(UEContextModificationConfirm,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationConfirm, aper.DecodeState,

	) (UEContextModificationConfirm, aper.Snapshot,

	)
	compare func(UEContextModificationConfirm, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationConfirmValueCodec) New(value UEContextModificationConfirm,

) (UEContextModificationConfirmAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationConfirmAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationConfirmAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationConfirmAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationConfirmAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationConfirmValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationConfirmAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationConfirmAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationConfirmAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationConfirmAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationConfirmAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationConfirmValueCodec) EncodeAPER(value UEContextModificationConfirmAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextModificationConfirmValueCodec) encodeBudgetValue(value UEContextModificationConfirm,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationConfirmValueCodec) encodeChanged(value UEContextModificationConfirm,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationFailureValueCodec is the concrete ValueCodec[UEContextModificationFailure].
type UEContextModificationFailureValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationFailure,

		error)
	encode func(UEContextModificationFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationFailure, aper.DecodeState,

	) (UEContextModificationFailure, aper.Snapshot,

	)
	compare func(UEContextModificationFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationFailureValueCodec) New(value UEContextModificationFailure,

) (UEContextModificationFailureAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationFailureAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationFailureAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationFailureAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationFailureAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationFailureValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationFailureAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationFailureAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationFailureAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationFailureAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationFailureAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationFailureValueCodec) EncodeAPER(value UEContextModificationFailureAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextModificationFailureValueCodec) encodeBudgetValue(value UEContextModificationFailure,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationFailureValueCodec) encodeChanged(value UEContextModificationFailure,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationIndicationValueCodec is the concrete ValueCodec[UEContextModificationIndication].
type UEContextModificationIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationIndication,

		error)
	encode func(UEContextModificationIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationIndication, aper.DecodeState,

	) (UEContextModificationIndication, aper.Snapshot,

	)
	compare func(UEContextModificationIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationIndicationValueCodec) New(value UEContextModificationIndication,

) (UEContextModificationIndicationAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationIndicationValueCodec) EncodeAPER(value UEContextModificationIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextModificationIndicationValueCodec) encodeBudgetValue(value UEContextModificationIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationIndicationValueCodec) encodeChanged(value UEContextModificationIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextModificationResponseValueCodec is the concrete ValueCodec[UEContextModificationResponse].
type UEContextModificationResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextModificationResponse,

		error)
	encode func(UEContextModificationResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextModificationResponse, aper.DecodeState,

	) (UEContextModificationResponse, aper.Snapshot,

	)
	compare func(UEContextModificationResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationResponseValueCodec) New(value UEContextModificationResponse,

) (UEContextModificationResponseAPERValue, error) {
	if c.encode == nil {
		return UEContextModificationResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextModificationResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextModificationResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextModificationResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextModificationResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextModificationResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextModificationResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextModificationResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextModificationResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationResponseValueCodec) EncodeAPER(value UEContextModificationResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextModificationResponseValueCodec) encodeBudgetValue(value UEContextModificationResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationResponseValueCodec) encodeChanged(value UEContextModificationResponse,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextResumeFailureValueCodec is the concrete ValueCodec[UEContextResumeFailure].
type UEContextResumeFailureValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextResumeFailure,

		error)
	encode func(UEContextResumeFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextResumeFailure, aper.DecodeState,

	) (UEContextResumeFailure, aper.Snapshot,

	)
	compare func(UEContextResumeFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextResumeFailureValueCodec) New(value UEContextResumeFailure,

) (UEContextResumeFailureAPERValue, error) {
	if c.encode == nil {
		return UEContextResumeFailureAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextResumeFailureAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextResumeFailureAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextResumeFailureAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextResumeFailureValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextResumeFailureAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextResumeFailureAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextResumeFailureAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextResumeFailureAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextResumeFailureAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextResumeFailureValueCodec) EncodeAPER(value UEContextResumeFailureAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextResumeFailureValueCodec) encodeBudgetValue(value UEContextResumeFailure,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextResumeFailureValueCodec) encodeChanged(value UEContextResumeFailure,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextSuspendResponseValueCodec is the concrete ValueCodec[UEContextSuspendResponse].
type UEContextSuspendResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextSuspendResponse,

		error)
	encode func(UEContextSuspendResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextSuspendResponse, aper.DecodeState,

	) (UEContextSuspendResponse, aper.Snapshot,

	)
	compare func(UEContextSuspendResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextSuspendResponseValueCodec) New(value UEContextSuspendResponse,

) (UEContextSuspendResponseAPERValue, error) {
	if c.encode == nil {
		return UEContextSuspendResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextSuspendResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextSuspendResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextSuspendResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextSuspendResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextSuspendResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextSuspendResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextSuspendResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextSuspendResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextSuspendResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextSuspendResponseValueCodec) EncodeAPER(value UEContextSuspendResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextSuspendResponseValueCodec) encodeBudgetValue(value UEContextSuspendResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextSuspendResponseValueCodec) encodeChanged(value UEContextSuspendResponse,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEInformationTransferValueCodec is the concrete ValueCodec[UEInformationTransfer].
type UEInformationTransferValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEInformationTransfer,

		error)
	encode func(UEInformationTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEInformationTransfer, aper.DecodeState,

	) (UEInformationTransfer, aper.Snapshot,

	)
	compare func(UEInformationTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEInformationTransferValueCodec) New(value UEInformationTransfer,

) (UEInformationTransferAPERValue, error) {
	if c.encode == nil {
		return UEInformationTransferAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEInformationTransferAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEInformationTransferAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEInformationTransferAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEInformationTransferValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEInformationTransferAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEInformationTransferAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEInformationTransferAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEInformationTransferAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEInformationTransferAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEInformationTransferValueCodec) EncodeAPER(value UEInformationTransferAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEInformationTransferValueCodec) encodeBudgetValue(value UEInformationTransfer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEInformationTransferValueCodec) encodeChanged(value UEInformationTransfer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityIDMappingRequestValueCodec is the concrete ValueCodec[UERadioCapabilityIDMappingRequest].
type UERadioCapabilityIDMappingRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingRequest,

		error)
	encode func(UERadioCapabilityIDMappingRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityIDMappingRequest, aper.DecodeState,

	) (UERadioCapabilityIDMappingRequest, aper.Snapshot,

	)
	compare func(UERadioCapabilityIDMappingRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityIDMappingRequestValueCodec) New(value UERadioCapabilityIDMappingRequest,

) (UERadioCapabilityIDMappingRequestAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityIDMappingRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityIDMappingRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityIDMappingRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityIDMappingRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityIDMappingRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityIDMappingRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityIDMappingRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityIDMappingRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityIDMappingRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityIDMappingRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityIDMappingRequestValueCodec) EncodeAPER(value UERadioCapabilityIDMappingRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UERadioCapabilityIDMappingRequestValueCodec) encodeBudgetValue(value UERadioCapabilityIDMappingRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityIDMappingRequestValueCodec) encodeChanged(value UERadioCapabilityIDMappingRequest,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityIDMappingResponseValueCodec is the concrete ValueCodec[UERadioCapabilityIDMappingResponse].
type UERadioCapabilityIDMappingResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponse,

		error)
	encode func(UERadioCapabilityIDMappingResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityIDMappingResponse, aper.DecodeState,

	) (UERadioCapabilityIDMappingResponse, aper.Snapshot,

	)
	compare func(UERadioCapabilityIDMappingResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityIDMappingResponseValueCodec) New(value UERadioCapabilityIDMappingResponse,

) (UERadioCapabilityIDMappingResponseAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityIDMappingResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityIDMappingResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityIDMappingResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityIDMappingResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityIDMappingResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityIDMappingResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityIDMappingResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityIDMappingResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityIDMappingResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityIDMappingResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityIDMappingResponseValueCodec) EncodeAPER(value UERadioCapabilityIDMappingResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UERadioCapabilityIDMappingResponseValueCodec) encodeBudgetValue(value UERadioCapabilityIDMappingResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityIDMappingResponseValueCodec) encodeChanged(value UERadioCapabilityIDMappingResponse,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityMatchRequestValueCodec is the concrete ValueCodec[UERadioCapabilityMatchRequest].
type UERadioCapabilityMatchRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityMatchRequest,

		error)
	encode func(UERadioCapabilityMatchRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityMatchRequest, aper.DecodeState,

	) (UERadioCapabilityMatchRequest, aper.Snapshot,

	)
	compare func(UERadioCapabilityMatchRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityMatchRequestValueCodec) New(value UERadioCapabilityMatchRequest,

) (UERadioCapabilityMatchRequestAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityMatchRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityMatchRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityMatchRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityMatchRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityMatchRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityMatchRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityMatchRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityMatchRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityMatchRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityMatchRequestValueCodec) EncodeAPER(value UERadioCapabilityMatchRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UERadioCapabilityMatchRequestValueCodec) encodeBudgetValue(value UERadioCapabilityMatchRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityMatchRequestValueCodec) encodeChanged(value UERadioCapabilityMatchRequest,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityMatchResponseValueCodec is the concrete ValueCodec[UERadioCapabilityMatchResponse].
type UERadioCapabilityMatchResponseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponse,

		error)
	encode func(UERadioCapabilityMatchResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UERadioCapabilityMatchResponse, aper.DecodeState,

	) (UERadioCapabilityMatchResponse, aper.Snapshot,

	)
	compare func(UERadioCapabilityMatchResponse, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityMatchResponseValueCodec) New(value UERadioCapabilityMatchResponse,

) (UERadioCapabilityMatchResponseAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityMatchResponseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityMatchResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityMatchResponseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityMatchResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityMatchResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityMatchResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityMatchResponseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityMatchResponseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityMatchResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityMatchResponseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityMatchResponseValueCodec) EncodeAPER(value UERadioCapabilityMatchResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UERadioCapabilityMatchResponseValueCodec) encodeBudgetValue(value UERadioCapabilityMatchResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityMatchResponseValueCodec) encodeChanged(value UERadioCapabilityMatchResponse,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UnsuccessfulOutcomeValueCodec is the concrete ValueCodec[UnsuccessfulOutcome].
type UnsuccessfulOutcomeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UnsuccessfulOutcome,

		error)
	encode func(UnsuccessfulOutcome,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UnsuccessfulOutcome, aper.DecodeState,

	) (UnsuccessfulOutcome, aper.Snapshot,

	)
	compare func(UnsuccessfulOutcome, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UnsuccessfulOutcomeValueCodec) New(value UnsuccessfulOutcome,

) (UnsuccessfulOutcomeAPERValue, error) {
	if c.encode == nil {
		return UnsuccessfulOutcomeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UnsuccessfulOutcomeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UnsuccessfulOutcomeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UnsuccessfulOutcomeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UnsuccessfulOutcomeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UnsuccessfulOutcomeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UnsuccessfulOutcomeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UnsuccessfulOutcomeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UnsuccessfulOutcomeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UnsuccessfulOutcomeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UnsuccessfulOutcomeValueCodec) EncodeAPER(value UnsuccessfulOutcomeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UnsuccessfulOutcomeValueCodec) encodeBudgetValue(value UnsuccessfulOutcome,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UnsuccessfulOutcomeValueCodec) encodeChanged(value UnsuccessfulOutcome,

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
func BridgeResetIEValueValidateS1APIEContainer(fields ResetIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
func BridgeUEContextModificationResponseIEValueValidateS1APIEContainer(fields s23.UEContextModificationResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s23.BridgeUEContextModificationResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s23.BridgeUEContextModificationResponseIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s23.BridgeUEContextModificationResponseIEValueMethodRule(field.Value).Assignment
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
func BridgeUEContextModificationFailureIEValueValidateS1APIEContainer(fields s23.UEContextModificationFailureIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s23.BridgeUEContextModificationFailureIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s23.BridgeUEContextModificationFailureIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s23.BridgeUEContextModificationFailureIEValueMethodRule(field.Value).Assignment
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
func BridgeUECapabilityInfoIndicationIEValueValidateS1APIEContainer(fields s12.UECapabilityInfoIndicationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s12.BridgeUECapabilityInfoIndicationIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s12.BridgeUECapabilityInfoIndicationIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s12.BridgeUECapabilityInfoIndicationIEValueMethodRule(field.Value).Assignment
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
func BridgeUERadioCapabilityMatchRequestIEValueValidateS1APIEContainer(fields s12.UERadioCapabilityMatchRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s12.BridgeUERadioCapabilityMatchRequestIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s12.BridgeUERadioCapabilityMatchRequestIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s12.BridgeUERadioCapabilityMatchRequestIEValueMethodRule(field.Value).Assignment
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
func BridgeUERadioCapabilityMatchResponseIEValueValidateS1APIEContainer(fields s24.UERadioCapabilityMatchResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s24.BridgeUERadioCapabilityMatchResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s24.BridgeUERadioCapabilityMatchResponseIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s24.BridgeUERadioCapabilityMatchResponseIEValueMethodRule(field.Value).Assignment
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
func BridgeUEContextModificationIndicationIEValueValidateS1APIEContainer(fields s21.UEContextModificationIndicationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s21.BridgeUEContextModificationIndicationIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s21.BridgeUEContextModificationIndicationIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s21.BridgeUEContextModificationIndicationIEValueMethodRule(field.Value).Assignment
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
func BridgeUEContextModificationConfirmIEValueValidateS1APIEContainer(fields s23.UEContextModificationConfirmIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s23.BridgeUEContextModificationConfirmIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s23.BridgeUEContextModificationConfirmIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s23.BridgeUEContextModificationConfirmIEValueMethodRule(field.Value).Assignment
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
func BridgeUEContextSuspendResponseIEValueValidateS1APIEContainer(fields s28.UEContextSuspendResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s28.BridgeUEContextSuspendResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s28.BridgeUEContextSuspendResponseIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s28.BridgeUEContextSuspendResponseIEValueMethodRule(field.Value).Assignment
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
func BridgeUEContextResumeFailureIEValueValidateS1APIEContainer(fields s23.UEContextResumeFailureIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s23.BridgeUEContextResumeFailureIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s23.BridgeUEContextResumeFailureIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s23.BridgeUEContextResumeFailureIEValueMethodRule(field.Value).Assignment
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
func BridgeUEInformationTransferIEValueValidateS1APIEContainer(fields s31.UEInformationTransferIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s31.BridgeUEInformationTransferIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s31.BridgeUEInformationTransferIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s31.BridgeUEInformationTransferIEValueMethodRule(field.Value).Assignment
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
func BridgeUERadioCapabilityIDMappingRequestIEValueValidateS1APIEContainer(fields s12.UERadioCapabilityIDMappingRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s07.BridgeUERadioCapabilityIDMappingRequestIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s07.BridgeUERadioCapabilityIDMappingRequestIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s07.BridgeUERadioCapabilityIDMappingRequestIEValueMethodRule(field.Value).Assignment
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
func BridgeUERadioCapabilityIDMappingResponseIEValueValidateS1APIEContainer(fields s23.UERadioCapabilityIDMappingResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s23.BridgeUERadioCapabilityIDMappingResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s23.BridgeUERadioCapabilityIDMappingResponseIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s23.BridgeUERadioCapabilityIDMappingResponseIEValueMethodRule(field.Value).Assignment
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
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueValidateS1APIEContainer(fields s35.UEAssociatedLogicalS1ConnectionItemResIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s26.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueMethodRule(field.Value).Assignment
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
func ResetIEValueERABIEContainerListCodec(table s00.ResetIEValueIETable) ResetIEValueERABIEContainerListValueCodec {
	codec := ResetIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ResetIEValueERABIEContainerListValueCodec{}
	}
	return ResetIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ResetIEValueERABIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ResetIEValueERABIEContainerList(value), err
	}, encode: func(value ResetIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ResetIEContainer(value), fresh, budget)
	}, capture: func(v ResetIEValueERABIEContainerList, options aper.DecodeState) (ResetIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeResetIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResetIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeResetIEValueCompareS1APERABIEContainerList(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListCodec(table s00.UEAssociatedLogicalS1ConnectionItemResIEValueIETable) s35.UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec {
	codec := s35.UEAssociatedLogicalS1ConnectionItemResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s35.UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec{}
	}
	return func() s35.UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec {
		sealed := s35.UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodec{}
		*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, error) {
			value, err := (*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s35.UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList(value), err
		}
		*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s35.UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerValueCodecFieldEncode(&codec))(s35.UEAssociatedLogicalS1ConnectionItemResIEContainer(value), fresh, budget)
		}
		*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s35.UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, options aper.DecodeState) (s35.UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s35.UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UECapabilityInfoIndicationIEValueERABIEContainerListCodec(table s00.UECapabilityInfoIndicationIEValueIETable) s12.UECapabilityInfoIndicationIEValueERABIEContainerListValueCodec {
	codec := UECapabilityInfoIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UECapabilityInfoIndicationIEValueERABIEContainerListValueCodec{}
	}
	return func() s12.UECapabilityInfoIndicationIEValueERABIEContainerListValueCodec {
		sealed := s12.UECapabilityInfoIndicationIEValueERABIEContainerListValueCodec{}
		*s12.BridgeUECapabilityInfoIndicationIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEValueERABIEContainerList, error) {
			value, err := (*s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s12.UECapabilityInfoIndicationIEValueERABIEContainerList(value), err
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UECapabilityInfoIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldEncode(&codec))(s12.UECapabilityInfoIndicationIEContainer(value), fresh, budget)
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UECapabilityInfoIndicationIEValueERABIEContainerList, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUECapabilityInfoIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UECapabilityInfoIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUECapabilityInfoIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationConfirmIEValueERABIEContainerListCodec(table s00.UEContextModificationConfirmIEValueIETable) s23.UEContextModificationConfirmIEValueERABIEContainerListValueCodec {
	codec := UEContextModificationConfirmIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextModificationConfirmIEValueERABIEContainerListValueCodec{}
	}
	return func() s23.UEContextModificationConfirmIEValueERABIEContainerListValueCodec {
		sealed := s23.UEContextModificationConfirmIEValueERABIEContainerListValueCodec{}
		*s23.BridgeUEContextModificationConfirmIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationConfirmIEValueERABIEContainerList, error) {
			value, err := (*s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.UEContextModificationConfirmIEValueERABIEContainerList(value), err
		}
		*s23.BridgeUEContextModificationConfirmIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UEContextModificationConfirmIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldEncode(&codec))(s23.UEContextModificationConfirmIEContainer(value), fresh, budget)
		}
		*s23.BridgeUEContextModificationConfirmIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationConfirmIEValueERABIEContainerList, options aper.DecodeState) (s23.UEContextModificationConfirmIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationConfirmIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeUEContextModificationConfirmIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationConfirmIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationConfirmIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationConfirmIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationFailureIEValueERABIEContainerListCodec(table s00.UEContextModificationFailureIEValueIETable) s23.UEContextModificationFailureIEValueERABIEContainerListValueCodec {
	codec := UEContextModificationFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextModificationFailureIEValueERABIEContainerListValueCodec{}
	}
	return func() s23.UEContextModificationFailureIEValueERABIEContainerListValueCodec {
		sealed := s23.UEContextModificationFailureIEValueERABIEContainerListValueCodec{}
		*s23.BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationFailureIEValueERABIEContainerList, error) {
			value, err := (*s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.UEContextModificationFailureIEValueERABIEContainerList(value), err
		}
		*s23.BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UEContextModificationFailureIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldEncode(&codec))(s23.UEContextModificationFailureIEContainer(value), fresh, budget)
		}
		*s23.BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationFailureIEValueERABIEContainerList, options aper.DecodeState) (s23.UEContextModificationFailureIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationFailureIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationFailureIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationFailureIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationIndicationIEValueERABIEContainerListCodec(table s00.UEContextModificationIndicationIEValueIETable) s21.UEContextModificationIndicationIEValueERABIEContainerListValueCodec {
	codec := UEContextModificationIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s21.BridgeUEContextModificationIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s21.UEContextModificationIndicationIEValueERABIEContainerListValueCodec{}
	}
	return func() s21.UEContextModificationIndicationIEValueERABIEContainerListValueCodec {
		sealed := s21.UEContextModificationIndicationIEValueERABIEContainerListValueCodec{}
		*s21.BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.UEContextModificationIndicationIEValueERABIEContainerList, error) {
			value, err := (*s21.BridgeUEContextModificationIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s21.UEContextModificationIndicationIEValueERABIEContainerList(value), err
		}
		*s21.BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s21.UEContextModificationIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s21.BridgeUEContextModificationIndicationIEContainerValueCodecFieldEncode(&codec))(s21.UEContextModificationIndicationIEContainer(value), fresh, budget)
		}
		*s21.BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s21.UEContextModificationIndicationIEValueERABIEContainerList, options aper.DecodeState) (s21.UEContextModificationIndicationIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s21.UEContextModificationIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationResponseIEValueERABIEContainerListCodec(table s00.UEContextModificationResponseIEValueIETable) s23.UEContextModificationResponseIEValueERABIEContainerListValueCodec {
	codec := UEContextModificationResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeUEContextModificationResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextModificationResponseIEValueERABIEContainerListValueCodec{}
	}
	return func() s23.UEContextModificationResponseIEValueERABIEContainerListValueCodec {
		sealed := s23.UEContextModificationResponseIEValueERABIEContainerListValueCodec{}
		*s23.BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationResponseIEValueERABIEContainerList, error) {
			value, err := (*s23.BridgeUEContextModificationResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.UEContextModificationResponseIEValueERABIEContainerList(value), err
		}
		*s23.BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UEContextModificationResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUEContextModificationResponseIEContainerValueCodecFieldEncode(&codec))(s23.UEContextModificationResponseIEContainer(value), fresh, budget)
		}
		*s23.BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationResponseIEValueERABIEContainerList, options aper.DecodeState) (s23.UEContextModificationResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextResumeFailureIEValueERABIEContainerListCodec(table s00.UEContextResumeFailureIEValueIETable) s23.UEContextResumeFailureIEValueERABIEContainerListValueCodec {
	codec := UEContextResumeFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeUEContextResumeFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextResumeFailureIEValueERABIEContainerListValueCodec{}
	}
	return func() s23.UEContextResumeFailureIEValueERABIEContainerListValueCodec {
		sealed := s23.UEContextResumeFailureIEValueERABIEContainerListValueCodec{}
		*s23.BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextResumeFailureIEValueERABIEContainerList, error) {
			value, err := (*s23.BridgeUEContextResumeFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.UEContextResumeFailureIEValueERABIEContainerList(value), err
		}
		*s23.BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UEContextResumeFailureIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUEContextResumeFailureIEContainerValueCodecFieldEncode(&codec))(s23.UEContextResumeFailureIEContainer(value), fresh, budget)
		}
		*s23.BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UEContextResumeFailureIEValueERABIEContainerList, options aper.DecodeState) (s23.UEContextResumeFailureIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextResumeFailureIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextSuspendResponseIEValueERABIEContainerListCodec(table s00.UEContextSuspendResponseIEValueIETable) s28.UEContextSuspendResponseIEValueERABIEContainerListValueCodec {
	codec := UEContextSuspendResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s28.BridgeUEContextSuspendResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s28.UEContextSuspendResponseIEValueERABIEContainerListValueCodec{}
	}
	return func() s28.UEContextSuspendResponseIEValueERABIEContainerListValueCodec {
		sealed := s28.UEContextSuspendResponseIEValueERABIEContainerListValueCodec{}
		*s28.BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.UEContextSuspendResponseIEValueERABIEContainerList, error) {
			value, err := (*s28.BridgeUEContextSuspendResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s28.UEContextSuspendResponseIEValueERABIEContainerList(value), err
		}
		*s28.BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s28.UEContextSuspendResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s28.BridgeUEContextSuspendResponseIEContainerValueCodecFieldEncode(&codec))(s28.UEContextSuspendResponseIEContainer(value), fresh, budget)
		}
		*s28.BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s28.UEContextSuspendResponseIEValueERABIEContainerList, options aper.DecodeState) (s28.UEContextSuspendResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s28.UEContextSuspendResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEInformationTransferIEValueERABIEContainerListCodec(table s00.UEInformationTransferIEValueIETable) s31.UEInformationTransferIEValueERABIEContainerListValueCodec {
	codec := UEInformationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s31.BridgeUEInformationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s31.UEInformationTransferIEValueERABIEContainerListValueCodec{}
	}
	return func() s31.UEInformationTransferIEValueERABIEContainerListValueCodec {
		sealed := s31.UEInformationTransferIEValueERABIEContainerListValueCodec{}
		*s31.BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.UEInformationTransferIEValueERABIEContainerList, error) {
			value, err := (*s31.BridgeUEInformationTransferIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s31.UEInformationTransferIEValueERABIEContainerList(value), err
		}
		*s31.BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s31.UEInformationTransferIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s31.BridgeUEInformationTransferIEContainerValueCodecFieldEncode(&codec))(s31.UEInformationTransferIEContainer(value), fresh, budget)
		}
		*s31.BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s31.UEInformationTransferIEValueERABIEContainerList, options aper.DecodeState) (s31.UEInformationTransferIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s31.BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s31.UEInformationTransferIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s31.BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityIDMappingRequestIEValueERABIEContainerListCodec(table s00.UERadioCapabilityIDMappingRequestIEValueIETable) s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodec {
	codec := UERadioCapabilityIDMappingRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodec{}
	}
	return func() s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodec {
		sealed := s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodec{}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList, error) {
			value, err := (*s12.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList(value), err
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldEncode(&codec))(s12.UERadioCapabilityIDMappingRequestIEContainer(value), fresh, budget)
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList, options aper.DecodeState) (s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityIDMappingResponseIEValueERABIEContainerListCodec(table s00.UERadioCapabilityIDMappingResponseIEValueIETable) s23.UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec {
	codec := UERadioCapabilityIDMappingResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec{}
	}
	return func() s23.UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec {
		sealed := s23.UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec{}
		*s23.BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, error) {
			value, err := (*s23.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList(value), err
		}
		*s23.BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldEncode(&codec))(s23.UERadioCapabilityIDMappingResponseIEContainer(value), fresh, budget)
		}
		*s23.BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, options aper.DecodeState) (s23.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityMatchRequestIEValueERABIEContainerListCodec(table s00.UERadioCapabilityMatchRequestIEValueIETable) s12.UERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodec {
	codec := UERadioCapabilityMatchRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodec{}
	}
	return func() s12.UERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodec {
		sealed := s12.UERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodec{}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UERadioCapabilityMatchRequestIEValueERABIEContainerList, error) {
			value, err := (*s12.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s12.UERadioCapabilityMatchRequestIEValueERABIEContainerList(value), err
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UERadioCapabilityMatchRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldEncode(&codec))(s12.UERadioCapabilityMatchRequestIEContainer(value), fresh, budget)
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UERadioCapabilityMatchRequestIEValueERABIEContainerList, options aper.DecodeState) (s12.UERadioCapabilityMatchRequestIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UERadioCapabilityMatchRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityMatchResponseIEValueERABIEContainerListCodec(table s00.UERadioCapabilityMatchResponseIEValueIETable) s24.UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec {
	codec := UERadioCapabilityMatchResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec{}
	}
	return func() s24.UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec {
		sealed := s24.UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec{}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList, error) {
			value, err := (*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList(value), err
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldEncode(&codec))(s24.UERadioCapabilityMatchResponseIEContainer(value), fresh, budget)
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UES1APIDPairExtIEsValueExtensionFieldTableCodec(table s00.UES1APIDPairExtIEsValueExtensionTable) s12.UES1APIDPairExtIEsExtFieldValueCodec {
	if !*s00.BridgeUES1APIDPairExtIEsValueExtensionTableFieldBound(&table) {
		return s12.UES1APIDPairExtIEsExtFieldValueCodec{}
	}
	return func() s12.UES1APIDPairExtIEsExtFieldValueCodec {
		sealed := s12.UES1APIDPairExtIEsExtFieldValueCodec{}
		*s12.BridgeUES1APIDPairExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UES1APIDPairExtIEsExtField, error) {
			var field s12.UES1APIDPairExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeUES1APIDPairExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s12.BridgeUES1APIDPairExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.UES1APIDPairExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeUES1APIDPairExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeUES1APIDPairExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.UES1APIDPairExtIEsExtField, options aper.DecodeState) (s12.UES1APIDPairExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUES1APIDPairExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s12.BridgeUES1APIDPairExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.UES1APIDPairExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUES1APIDPairExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUES1APIDPairExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UES1APIDPairExtIEsValueExtensionTableCodec(table s00.UES1APIDPairExtIEsValueExtensionTable, bounds aper.ListBounds) s12.UES1APIDPairExtIEsExtContainerValueCodec {
	if !*s00.BridgeUES1APIDPairExtIEsValueExtensionTableFieldBound(&table) {
		return s12.UES1APIDPairExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.UES1APIDPairExtIEsExtContainerValueCodec {
		sealed := s12.UES1APIDPairExtIEsExtContainerValueCodec{}
		*s12.BridgeUES1APIDPairExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UES1APIDPairExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UES1APIDPairExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UES1APIDPairExtIEsExtField
					if err := s12.BridgeUES1APIDPairExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
			if _, err := aper.CaptureFinalBits(bb, "ProtocolExtensionContainer"); err != nil {
				return nil, err
			}
			return fields, nil
		}
		*s12.BridgeUES1APIDPairExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.UES1APIDPairExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeUES1APIDPairExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeUES1APIDPairExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.UES1APIDPairExtIEsExtContainer, options aper.DecodeState) (s12.UES1APIDPairExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUES1APIDPairExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUES1APIDPairExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.UES1APIDPairExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeUES1APIDPairExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUES1APIDPairExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ResetIEValueIEFieldTableCodec(table s00.ResetIEValueIETable) ResetIEFieldValueCodec {
	if !*s00.BridgeResetIEValueIETableFieldBound(&table) {
		return ResetIEFieldValueCodec{}
	}
	return ResetIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (ResetIEField, error) {
		var field ResetIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, err
		}
		if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
			return field, err
		}
		return field, nil
	}, encode: func(field ResetIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v ResetIEField, options aper.DecodeState) (ResetIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeResetIEValueCaptureS1APProtocolIEField(&v,
			&s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v ResetIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeResetIEValueCompareS1APProtocolIEField(&v, &s)
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
func UECapabilityInfoIndicationIEValueIEFieldTableCodec(table s00.UECapabilityInfoIndicationIEValueIETable) s12.UECapabilityInfoIndicationIEFieldValueCodec {
	if !*s00.BridgeUECapabilityInfoIndicationIEValueIETableFieldBound(&table) {
		return s12.UECapabilityInfoIndicationIEFieldValueCodec{}
	}
	return func() s12.UECapabilityInfoIndicationIEFieldValueCodec {
		sealed := s12.UECapabilityInfoIndicationIEFieldValueCodec{}
		*s12.BridgeUECapabilityInfoIndicationIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEField, error) {
			var field s12.UECapabilityInfoIndicationIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeUECapabilityInfoIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s12.BridgeUECapabilityInfoIndicationIEFieldValueCodecFieldEncode(&sealed) = func(field s12.UECapabilityInfoIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeUECapabilityInfoIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeUECapabilityInfoIndicationIEFieldValueCodecFieldCapture(&sealed) = func(v s12.UECapabilityInfoIndicationIEField, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s12.BridgeUECapabilityInfoIndicationIEFieldValueCodecFieldCompare(&sealed) = func(v s12.UECapabilityInfoIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUECapabilityInfoIndicationIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationConfirmIEValueIEFieldTableCodec(table s00.UEContextModificationConfirmIEValueIETable) s23.UEContextModificationConfirmIEFieldValueCodec {
	if !*s00.BridgeUEContextModificationConfirmIEValueIETableFieldBound(&table) {
		return s23.UEContextModificationConfirmIEFieldValueCodec{}
	}
	return func() s23.UEContextModificationConfirmIEFieldValueCodec {
		sealed := s23.UEContextModificationConfirmIEFieldValueCodec{}
		*s23.BridgeUEContextModificationConfirmIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationConfirmIEField, error) {
			var field s23.UEContextModificationConfirmIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s23.BridgeUEContextModificationConfirmIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s23.BridgeUEContextModificationConfirmIEFieldValueCodecFieldEncode(&sealed) = func(field s23.UEContextModificationConfirmIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s23.BridgeUEContextModificationConfirmIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s23.BridgeUEContextModificationConfirmIEFieldValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationConfirmIEField, options aper.DecodeState) (s23.UEContextModificationConfirmIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s23.BridgeUEContextModificationConfirmIEFieldValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationConfirmIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationConfirmIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationFailureIEValueIEFieldTableCodec(table s00.UEContextModificationFailureIEValueIETable) s23.UEContextModificationFailureIEFieldValueCodec {
	if !*s00.BridgeUEContextModificationFailureIEValueIETableFieldBound(&table) {
		return s23.UEContextModificationFailureIEFieldValueCodec{}
	}
	return func() s23.UEContextModificationFailureIEFieldValueCodec {
		sealed := s23.UEContextModificationFailureIEFieldValueCodec{}
		*s23.BridgeUEContextModificationFailureIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationFailureIEField, error) {
			var field s23.UEContextModificationFailureIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s23.BridgeUEContextModificationFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s23.BridgeUEContextModificationFailureIEFieldValueCodecFieldEncode(&sealed) = func(field s23.UEContextModificationFailureIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s23.BridgeUEContextModificationFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s23.BridgeUEContextModificationFailureIEFieldValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationFailureIEField, options aper.DecodeState) (s23.UEContextModificationFailureIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s23.BridgeUEContextModificationFailureIEFieldValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationFailureIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationFailureIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationIndicationIEValueIEFieldTableCodec(table s00.UEContextModificationIndicationIEValueIETable) s21.UEContextModificationIndicationIEFieldValueCodec {
	if !*s00.BridgeUEContextModificationIndicationIEValueIETableFieldBound(&table) {
		return s21.UEContextModificationIndicationIEFieldValueCodec{}
	}
	return func() s21.UEContextModificationIndicationIEFieldValueCodec {
		sealed := s21.UEContextModificationIndicationIEFieldValueCodec{}
		*s21.BridgeUEContextModificationIndicationIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.UEContextModificationIndicationIEField, error) {
			var field s21.UEContextModificationIndicationIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s21.BridgeUEContextModificationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s21.BridgeUEContextModificationIndicationIEFieldValueCodecFieldEncode(&sealed) = func(field s21.UEContextModificationIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s21.BridgeUEContextModificationIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s21.BridgeUEContextModificationIndicationIEFieldValueCodecFieldCapture(&sealed) = func(v s21.UEContextModificationIndicationIEField, options aper.DecodeState) (s21.UEContextModificationIndicationIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s21.BridgeUEContextModificationIndicationIEFieldValueCodecFieldCompare(&sealed) = func(v s21.UEContextModificationIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeUEContextModificationIndicationIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationResponseIEValueIEFieldTableCodec(table s00.UEContextModificationResponseIEValueIETable) s23.UEContextModificationResponseIEFieldValueCodec {
	if !*s00.BridgeUEContextModificationResponseIEValueIETableFieldBound(&table) {
		return s23.UEContextModificationResponseIEFieldValueCodec{}
	}
	return func() s23.UEContextModificationResponseIEFieldValueCodec {
		sealed := s23.UEContextModificationResponseIEFieldValueCodec{}
		*s23.BridgeUEContextModificationResponseIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationResponseIEField, error) {
			var field s23.UEContextModificationResponseIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s23.BridgeUEContextModificationResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s23.BridgeUEContextModificationResponseIEFieldValueCodecFieldEncode(&sealed) = func(field s23.UEContextModificationResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s23.BridgeUEContextModificationResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s23.BridgeUEContextModificationResponseIEFieldValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationResponseIEField, options aper.DecodeState) (s23.UEContextModificationResponseIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s23.BridgeUEContextModificationResponseIEFieldValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationResponseIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextResumeFailureIEValueIEFieldTableCodec(table s00.UEContextResumeFailureIEValueIETable) s23.UEContextResumeFailureIEFieldValueCodec {
	if !*s00.BridgeUEContextResumeFailureIEValueIETableFieldBound(&table) {
		return s23.UEContextResumeFailureIEFieldValueCodec{}
	}
	return func() s23.UEContextResumeFailureIEFieldValueCodec {
		sealed := s23.UEContextResumeFailureIEFieldValueCodec{}
		*s23.BridgeUEContextResumeFailureIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextResumeFailureIEField, error) {
			var field s23.UEContextResumeFailureIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s23.BridgeUEContextResumeFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s23.BridgeUEContextResumeFailureIEFieldValueCodecFieldEncode(&sealed) = func(field s23.UEContextResumeFailureIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s23.BridgeUEContextResumeFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s23.BridgeUEContextResumeFailureIEFieldValueCodecFieldCapture(&sealed) = func(v s23.UEContextResumeFailureIEField, options aper.DecodeState) (s23.UEContextResumeFailureIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s23.BridgeUEContextResumeFailureIEFieldValueCodecFieldCompare(&sealed) = func(v s23.UEContextResumeFailureIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextResumeFailureIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextSuspendResponseIEValueIEFieldTableCodec(table s00.UEContextSuspendResponseIEValueIETable) s28.UEContextSuspendResponseIEFieldValueCodec {
	if !*s00.BridgeUEContextSuspendResponseIEValueIETableFieldBound(&table) {
		return s28.UEContextSuspendResponseIEFieldValueCodec{}
	}
	return func() s28.UEContextSuspendResponseIEFieldValueCodec {
		sealed := s28.UEContextSuspendResponseIEFieldValueCodec{}
		*s28.BridgeUEContextSuspendResponseIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.UEContextSuspendResponseIEField, error) {
			var field s28.UEContextSuspendResponseIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s28.BridgeUEContextSuspendResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s28.BridgeUEContextSuspendResponseIEFieldValueCodecFieldEncode(&sealed) = func(field s28.UEContextSuspendResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s28.BridgeUEContextSuspendResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s28.BridgeUEContextSuspendResponseIEFieldValueCodecFieldCapture(&sealed) = func(v s28.UEContextSuspendResponseIEField, options aper.DecodeState) (s28.UEContextSuspendResponseIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s28.BridgeUEContextSuspendResponseIEFieldValueCodecFieldCompare(&sealed) = func(v s28.UEContextSuspendResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeUEContextSuspendResponseIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEInformationTransferIEValueIEFieldTableCodec(table s00.UEInformationTransferIEValueIETable) s31.UEInformationTransferIEFieldValueCodec {
	if !*s00.BridgeUEInformationTransferIEValueIETableFieldBound(&table) {
		return s31.UEInformationTransferIEFieldValueCodec{}
	}
	return func() s31.UEInformationTransferIEFieldValueCodec {
		sealed := s31.UEInformationTransferIEFieldValueCodec{}
		*s31.BridgeUEInformationTransferIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.UEInformationTransferIEField, error) {
			var field s31.UEInformationTransferIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s31.BridgeUEInformationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s31.BridgeUEInformationTransferIEFieldValueCodecFieldEncode(&sealed) = func(field s31.UEInformationTransferIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s31.BridgeUEInformationTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s31.BridgeUEInformationTransferIEFieldValueCodecFieldCapture(&sealed) = func(v s31.UEInformationTransferIEField, options aper.DecodeState) (s31.UEInformationTransferIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s31.BridgeUEInformationTransferIEFieldValueCodecFieldCompare(&sealed) = func(v s31.UEInformationTransferIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s31.BridgeUEInformationTransferIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityIDMappingRequestIEValueIEFieldTableCodec(table s00.UERadioCapabilityIDMappingRequestIEValueIETable) s12.UERadioCapabilityIDMappingRequestIEFieldValueCodec {
	if !*s00.BridgeUERadioCapabilityIDMappingRequestIEValueIETableFieldBound(&table) {
		return s12.UERadioCapabilityIDMappingRequestIEFieldValueCodec{}
	}
	return func() s12.UERadioCapabilityIDMappingRequestIEFieldValueCodec {
		sealed := s12.UERadioCapabilityIDMappingRequestIEFieldValueCodec{}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UERadioCapabilityIDMappingRequestIEField, error) {
			var field s12.UERadioCapabilityIDMappingRequestIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeUERadioCapabilityIDMappingRequestIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEFieldValueCodecFieldEncode(&sealed) = func(field s12.UERadioCapabilityIDMappingRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeUERadioCapabilityIDMappingRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEFieldValueCodecFieldCapture(&sealed) = func(v s12.UERadioCapabilityIDMappingRequestIEField, options aper.DecodeState) (s12.UERadioCapabilityIDMappingRequestIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEFieldValueCodecFieldCompare(&sealed) = func(v s12.UERadioCapabilityIDMappingRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityIDMappingResponseIEValueIEFieldTableCodec(table s00.UERadioCapabilityIDMappingResponseIEValueIETable) s23.UERadioCapabilityIDMappingResponseIEFieldValueCodec {
	if !*s00.BridgeUERadioCapabilityIDMappingResponseIEValueIETableFieldBound(&table) {
		return s23.UERadioCapabilityIDMappingResponseIEFieldValueCodec{}
	}
	return func() s23.UERadioCapabilityIDMappingResponseIEFieldValueCodec {
		sealed := s23.UERadioCapabilityIDMappingResponseIEFieldValueCodec{}
		*s23.BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UERadioCapabilityIDMappingResponseIEField, error) {
			var field s23.UERadioCapabilityIDMappingResponseIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s23.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s23.BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldEncode(&sealed) = func(field s23.UERadioCapabilityIDMappingResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s23.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s23.BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldCapture(&sealed) = func(v s23.UERadioCapabilityIDMappingResponseIEField, options aper.DecodeState) (s23.UERadioCapabilityIDMappingResponseIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s23.BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldCompare(&sealed) = func(v s23.UERadioCapabilityIDMappingResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityMatchRequestIEValueIEFieldTableCodec(table s00.UERadioCapabilityMatchRequestIEValueIETable) s12.UERadioCapabilityMatchRequestIEFieldValueCodec {
	if !*s00.BridgeUERadioCapabilityMatchRequestIEValueIETableFieldBound(&table) {
		return s12.UERadioCapabilityMatchRequestIEFieldValueCodec{}
	}
	return func() s12.UERadioCapabilityMatchRequestIEFieldValueCodec {
		sealed := s12.UERadioCapabilityMatchRequestIEFieldValueCodec{}
		*s12.BridgeUERadioCapabilityMatchRequestIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UERadioCapabilityMatchRequestIEField, error) {
			var field s12.UERadioCapabilityMatchRequestIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeUERadioCapabilityMatchRequestIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEFieldValueCodecFieldEncode(&sealed) = func(field s12.UERadioCapabilityMatchRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeUERadioCapabilityMatchRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEFieldValueCodecFieldCapture(&sealed) = func(v s12.UERadioCapabilityMatchRequestIEField, options aper.DecodeState) (s12.UERadioCapabilityMatchRequestIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEFieldValueCodecFieldCompare(&sealed) = func(v s12.UERadioCapabilityMatchRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityMatchResponseIEValueIEFieldTableCodec(table s00.UERadioCapabilityMatchResponseIEValueIETable) s24.UERadioCapabilityMatchResponseIEFieldValueCodec {
	if !*s00.BridgeUERadioCapabilityMatchResponseIEValueIETableFieldBound(&table) {
		return s24.UERadioCapabilityMatchResponseIEFieldValueCodec{}
	}
	return func() s24.UERadioCapabilityMatchResponseIEFieldValueCodec {
		sealed := s24.UERadioCapabilityMatchResponseIEFieldValueCodec{}
		*s24.BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEField, error) {
			var field s24.UERadioCapabilityMatchResponseIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s24.BridgeUERadioCapabilityMatchResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProtocolIEField"); err != nil {
				return field, err
			}
			return field, nil
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldEncode(&sealed) = func(field s24.UERadioCapabilityMatchResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s24.BridgeUERadioCapabilityMatchResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldCapture(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEField, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEField(&v,
				&s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldCompare(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ResetIEValueIETableCodec(table s00.ResetIEValueIETable, bounds aper.ListBounds) ResetIEContainerValueCodec {
	if !*s00.BridgeResetIEValueIETableFieldBound(&table) {
		return ResetIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return ResetIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (ResetIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields ResetIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field ResetIEField
				if err := field.unmarshalAPERFrom(bb); err != nil {
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
	},
		encode: func(fields ResetIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v ResetIEContainer, options aper.DecodeState) (ResetIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeResetIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v ResetIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeResetIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}
func UECapabilityInfoIndicationIEValueIETableCodec(table s00.UECapabilityInfoIndicationIEValueIETable, bounds aper.ListBounds) s12.UECapabilityInfoIndicationIEContainerValueCodec {
	if !*s00.BridgeUECapabilityInfoIndicationIEValueIETableFieldBound(&table) {
		return s12.UECapabilityInfoIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.UECapabilityInfoIndicationIEContainerValueCodec {
		sealed := s12.UECapabilityInfoIndicationIEContainerValueCodec{}
		*s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UECapabilityInfoIndicationIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UECapabilityInfoIndicationIEField
					if err := s12.BridgeUECapabilityInfoIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldEncode(&sealed) = func(fields s12.UECapabilityInfoIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeUECapabilityInfoIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldCapture(&sealed) = func(v s12.UECapabilityInfoIndicationIEContainer, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldCompare(&sealed) = func(v s12.UECapabilityInfoIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationConfirmIEValueIETableCodec(table s00.UEContextModificationConfirmIEValueIETable, bounds aper.ListBounds) s23.UEContextModificationConfirmIEContainerValueCodec {
	if !*s00.BridgeUEContextModificationConfirmIEValueIETableFieldBound(&table) {
		return s23.UEContextModificationConfirmIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s23.UEContextModificationConfirmIEContainerValueCodec {
		sealed := s23.UEContextModificationConfirmIEContainerValueCodec{}
		*s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationConfirmIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.UEContextModificationConfirmIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.UEContextModificationConfirmIEField
					if err := s23.BridgeUEContextModificationConfirmIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldEncode(&sealed) = func(fields s23.UEContextModificationConfirmIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s23.BridgeUEContextModificationConfirmIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationConfirmIEContainer, options aper.DecodeState) (s23.UEContextModificationConfirmIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationConfirmIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationFailureIEValueIETableCodec(table s00.UEContextModificationFailureIEValueIETable, bounds aper.ListBounds) s23.UEContextModificationFailureIEContainerValueCodec {
	if !*s00.BridgeUEContextModificationFailureIEValueIETableFieldBound(&table) {
		return s23.UEContextModificationFailureIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s23.UEContextModificationFailureIEContainerValueCodec {
		sealed := s23.UEContextModificationFailureIEContainerValueCodec{}
		*s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationFailureIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.UEContextModificationFailureIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.UEContextModificationFailureIEField
					if err := s23.BridgeUEContextModificationFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldEncode(&sealed) = func(fields s23.UEContextModificationFailureIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s23.BridgeUEContextModificationFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationFailureIEContainer, options aper.DecodeState) (s23.UEContextModificationFailureIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationFailureIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationIndicationIEValueIETableCodec(table s00.UEContextModificationIndicationIEValueIETable, bounds aper.ListBounds) s21.UEContextModificationIndicationIEContainerValueCodec {
	if !*s00.BridgeUEContextModificationIndicationIEValueIETableFieldBound(&table) {
		return s21.UEContextModificationIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s21.UEContextModificationIndicationIEContainerValueCodec {
		sealed := s21.UEContextModificationIndicationIEContainerValueCodec{}
		*s21.BridgeUEContextModificationIndicationIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.UEContextModificationIndicationIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s21.UEContextModificationIndicationIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s21.UEContextModificationIndicationIEField
					if err := s21.BridgeUEContextModificationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s21.BridgeUEContextModificationIndicationIEContainerValueCodecFieldEncode(&sealed) = func(fields s21.UEContextModificationIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s21.BridgeUEContextModificationIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s21.BridgeUEContextModificationIndicationIEContainerValueCodecFieldCapture(&sealed) = func(v s21.UEContextModificationIndicationIEContainer, options aper.DecodeState) (s21.UEContextModificationIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeUEContextModificationIndicationIEContainerValueCodecFieldCompare(&sealed) = func(v s21.UEContextModificationIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeUEContextModificationIndicationIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationResponseIEValueIETableCodec(table s00.UEContextModificationResponseIEValueIETable, bounds aper.ListBounds) s23.UEContextModificationResponseIEContainerValueCodec {
	if !*s00.BridgeUEContextModificationResponseIEValueIETableFieldBound(&table) {
		return s23.UEContextModificationResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s23.UEContextModificationResponseIEContainerValueCodec {
		sealed := s23.UEContextModificationResponseIEContainerValueCodec{}
		*s23.BridgeUEContextModificationResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.UEContextModificationResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.UEContextModificationResponseIEField
					if err := s23.BridgeUEContextModificationResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s23.BridgeUEContextModificationResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s23.UEContextModificationResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s23.BridgeUEContextModificationResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s23.BridgeUEContextModificationResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationResponseIEContainer, options aper.DecodeState) (s23.UEContextModificationResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeUEContextModificationResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEContextResumeFailureIEValueIETableCodec(table s00.UEContextResumeFailureIEValueIETable, bounds aper.ListBounds) s23.UEContextResumeFailureIEContainerValueCodec {
	if !*s00.BridgeUEContextResumeFailureIEValueIETableFieldBound(&table) {
		return s23.UEContextResumeFailureIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s23.UEContextResumeFailureIEContainerValueCodec {
		sealed := s23.UEContextResumeFailureIEContainerValueCodec{}
		*s23.BridgeUEContextResumeFailureIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextResumeFailureIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.UEContextResumeFailureIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.UEContextResumeFailureIEField
					if err := s23.BridgeUEContextResumeFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s23.BridgeUEContextResumeFailureIEContainerValueCodecFieldEncode(&sealed) = func(fields s23.UEContextResumeFailureIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s23.BridgeUEContextResumeFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s23.BridgeUEContextResumeFailureIEContainerValueCodecFieldCapture(&sealed) = func(v s23.UEContextResumeFailureIEContainer, options aper.DecodeState) (s23.UEContextResumeFailureIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeUEContextResumeFailureIEContainerValueCodecFieldCompare(&sealed) = func(v s23.UEContextResumeFailureIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextResumeFailureIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEContextSuspendResponseIEValueIETableCodec(table s00.UEContextSuspendResponseIEValueIETable, bounds aper.ListBounds) s28.UEContextSuspendResponseIEContainerValueCodec {
	if !*s00.BridgeUEContextSuspendResponseIEValueIETableFieldBound(&table) {
		return s28.UEContextSuspendResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s28.UEContextSuspendResponseIEContainerValueCodec {
		sealed := s28.UEContextSuspendResponseIEContainerValueCodec{}
		*s28.BridgeUEContextSuspendResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.UEContextSuspendResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s28.UEContextSuspendResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s28.UEContextSuspendResponseIEField
					if err := s28.BridgeUEContextSuspendResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s28.BridgeUEContextSuspendResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s28.UEContextSuspendResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s28.BridgeUEContextSuspendResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s28.BridgeUEContextSuspendResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s28.UEContextSuspendResponseIEContainer, options aper.DecodeState) (s28.UEContextSuspendResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeUEContextSuspendResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s28.UEContextSuspendResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeUEContextSuspendResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEInformationTransferIEValueIETableCodec(table s00.UEInformationTransferIEValueIETable, bounds aper.ListBounds) s31.UEInformationTransferIEContainerValueCodec {
	if !*s00.BridgeUEInformationTransferIEValueIETableFieldBound(&table) {
		return s31.UEInformationTransferIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s31.UEInformationTransferIEContainerValueCodec {
		sealed := s31.UEInformationTransferIEContainerValueCodec{}
		*s31.BridgeUEInformationTransferIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.UEInformationTransferIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s31.UEInformationTransferIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s31.UEInformationTransferIEField
					if err := s31.BridgeUEInformationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s31.BridgeUEInformationTransferIEContainerValueCodecFieldEncode(&sealed) = func(fields s31.UEInformationTransferIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s31.BridgeUEInformationTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s31.BridgeUEInformationTransferIEContainerValueCodecFieldCapture(&sealed) = func(v s31.UEInformationTransferIEContainer, options aper.DecodeState) (s31.UEInformationTransferIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s31.BridgeUEInformationTransferIEContainerValueCodecFieldCompare(&sealed) = func(v s31.UEInformationTransferIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s31.BridgeUEInformationTransferIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityIDMappingRequestIEValueIETableCodec(table s00.UERadioCapabilityIDMappingRequestIEValueIETable, bounds aper.ListBounds) s12.UERadioCapabilityIDMappingRequestIEContainerValueCodec {
	if !*s00.BridgeUERadioCapabilityIDMappingRequestIEValueIETableFieldBound(&table) {
		return s12.UERadioCapabilityIDMappingRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.UERadioCapabilityIDMappingRequestIEContainerValueCodec {
		sealed := s12.UERadioCapabilityIDMappingRequestIEContainerValueCodec{}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UERadioCapabilityIDMappingRequestIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UERadioCapabilityIDMappingRequestIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UERadioCapabilityIDMappingRequestIEField
					if err := s12.BridgeUERadioCapabilityIDMappingRequestIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s12.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldEncode(&sealed) = func(fields s12.UERadioCapabilityIDMappingRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeUERadioCapabilityIDMappingRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldCapture(&sealed) = func(v s12.UERadioCapabilityIDMappingRequestIEContainer, options aper.DecodeState) (s12.UERadioCapabilityIDMappingRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldCompare(&sealed) = func(v s12.UERadioCapabilityIDMappingRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityIDMappingResponseIEValueIETableCodec(table s00.UERadioCapabilityIDMappingResponseIEValueIETable, bounds aper.ListBounds) s23.UERadioCapabilityIDMappingResponseIEContainerValueCodec {
	if !*s00.BridgeUERadioCapabilityIDMappingResponseIEValueIETableFieldBound(&table) {
		return s23.UERadioCapabilityIDMappingResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s23.UERadioCapabilityIDMappingResponseIEContainerValueCodec {
		sealed := s23.UERadioCapabilityIDMappingResponseIEContainerValueCodec{}
		*s23.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UERadioCapabilityIDMappingResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.UERadioCapabilityIDMappingResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.UERadioCapabilityIDMappingResponseIEField
					if err := s23.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s23.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s23.UERadioCapabilityIDMappingResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s23.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s23.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s23.UERadioCapabilityIDMappingResponseIEContainer, options aper.DecodeState) (s23.UERadioCapabilityIDMappingResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s23.UERadioCapabilityIDMappingResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityMatchRequestIEValueIETableCodec(table s00.UERadioCapabilityMatchRequestIEValueIETable, bounds aper.ListBounds) s12.UERadioCapabilityMatchRequestIEContainerValueCodec {
	if !*s00.BridgeUERadioCapabilityMatchRequestIEValueIETableFieldBound(&table) {
		return s12.UERadioCapabilityMatchRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.UERadioCapabilityMatchRequestIEContainerValueCodec {
		sealed := s12.UERadioCapabilityMatchRequestIEContainerValueCodec{}
		*s12.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UERadioCapabilityMatchRequestIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UERadioCapabilityMatchRequestIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UERadioCapabilityMatchRequestIEField
					if err := s12.BridgeUERadioCapabilityMatchRequestIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s12.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldEncode(&sealed) = func(fields s12.UERadioCapabilityMatchRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeUERadioCapabilityMatchRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldCapture(&sealed) = func(v s12.UERadioCapabilityMatchRequestIEContainer, options aper.DecodeState) (s12.UERadioCapabilityMatchRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldCompare(&sealed) = func(v s12.UERadioCapabilityMatchRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityMatchResponseIEValueIETableCodec(table s00.UERadioCapabilityMatchResponseIEValueIETable, bounds aper.ListBounds) s24.UERadioCapabilityMatchResponseIEContainerValueCodec {
	if !*s00.BridgeUERadioCapabilityMatchResponseIEValueIETableFieldBound(&table) {
		return s24.UERadioCapabilityMatchResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s24.UERadioCapabilityMatchResponseIEContainerValueCodec {
		sealed := s24.UERadioCapabilityMatchResponseIEContainerValueCodec{}
		*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UERadioCapabilityMatchResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UERadioCapabilityMatchResponseIEField
					if err := s24.BridgeUERadioCapabilityMatchResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
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
		*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s24.UERadioCapabilityMatchResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s24.BridgeUERadioCapabilityMatchResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEContainer, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func ResetIEValueProtocolErrorIEContainerListCodec(table s00.ResetIEValueIETable) ResetIEValueProtocolErrorIEContainerListValueCodec {
	codec := ResetIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return ResetIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return ResetIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ResetIEValueProtocolErrorIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ResetIEValueProtocolErrorIEContainerList(value), err
	}, encode: func(value ResetIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ResetIEContainer(value), fresh, budget)
	}, capture: func(v ResetIEValueProtocolErrorIEContainerList, options aper.DecodeState) (ResetIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeResetIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResetIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.
				Begin()
		BridgeResetIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
		s.
			End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListCodec(table s00.UEAssociatedLogicalS1ConnectionItemResIEValueIETable) s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec {
	codec := s35.UEAssociatedLogicalS1ConnectionItemResIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodec{}
		*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList(value), err
		}
		*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerValueCodecFieldEncode(&codec))(s35.UEAssociatedLogicalS1ConnectionItemResIEContainer(value), fresh, budget)
		}
		*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UECapabilityInfoIndicationIEValueProtocolErrorIEContainerListCodec(table s00.UECapabilityInfoIndicationIEValueIETable) s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := UECapabilityInfoIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerListValueCodec{}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerList(value), err
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldEncode(&codec))(s12.UECapabilityInfoIndicationIEContainer(value), fresh, budget)
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationConfirmIEValueProtocolErrorIEContainerListCodec(table s00.UEContextModificationConfirmIEValueIETable) s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextModificationConfirmIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodec{}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerList(value), err
		}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldEncode(&codec))(s23.UEContextModificationConfirmIEContainer(value), fresh, budget)
		}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUEContextModificationConfirmIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationFailureIEValueProtocolErrorIEContainerListCodec(table s00.UEContextModificationFailureIEValueIETable) s23.UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextModificationFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s23.UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s23.UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec{}
		*s23.BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationFailureIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.UEContextModificationFailureIEValueProtocolErrorIEContainerList(value), err
		}
		*s23.BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UEContextModificationFailureIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldEncode(&codec))(s23.UEContextModificationFailureIEContainer(value), fresh, budget)
		}
		*s23.BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationFailureIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s23.UEContextModificationFailureIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationFailureIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationFailureIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUEContextModificationFailureIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationIndicationIEValueProtocolErrorIEContainerListCodec(table s00.UEContextModificationIndicationIEValueIETable) s21.UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextModificationIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s21.BridgeUEContextModificationIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s21.UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s21.UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s21.UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec{}
		*s21.BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.UEContextModificationIndicationIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s21.BridgeUEContextModificationIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s21.UEContextModificationIndicationIEValueProtocolErrorIEContainerList(value), err
		}
		*s21.BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s21.UEContextModificationIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s21.BridgeUEContextModificationIndicationIEContainerValueCodecFieldEncode(&codec))(s21.UEContextModificationIndicationIEContainer(value), fresh, budget)
		}
		*s21.BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s21.UEContextModificationIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s21.UEContextModificationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s21.UEContextModificationIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUEContextModificationIndicationIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationResponseIEValueProtocolErrorIEContainerListCodec(table s00.UEContextModificationResponseIEValueIETable) s23.UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextModificationResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeUEContextModificationResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s23.UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s23.UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s23.BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationResponseIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s23.BridgeUEContextModificationResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.UEContextModificationResponseIEValueProtocolErrorIEContainerList(value), err
		}
		*s23.BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UEContextModificationResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUEContextModificationResponseIEContainerValueCodecFieldEncode(&codec))(s23.UEContextModificationResponseIEContainer(value), fresh, budget)
		}
		*s23.BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s23.UEContextModificationResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUEContextModificationResponseIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextResumeFailureIEValueProtocolErrorIEContainerListCodec(table s00.UEContextResumeFailureIEValueIETable) s23.UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextResumeFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeUEContextResumeFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s23.UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s23.UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec{}
		*s23.BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextResumeFailureIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s23.BridgeUEContextResumeFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.UEContextResumeFailureIEValueProtocolErrorIEContainerList(value), err
		}
		*s23.BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UEContextResumeFailureIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUEContextResumeFailureIEContainerValueCodecFieldEncode(&codec))(s23.UEContextResumeFailureIEContainer(value), fresh, budget)
		}
		*s23.BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UEContextResumeFailureIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s23.UEContextResumeFailureIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextResumeFailureIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUEContextResumeFailureIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEContextSuspendResponseIEValueProtocolErrorIEContainerListCodec(table s00.UEContextSuspendResponseIEValueIETable) s28.UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextSuspendResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s28.BridgeUEContextSuspendResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s28.UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s28.UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s28.UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s28.BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s28.BridgeUEContextSuspendResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s28.UEContextSuspendResponseIEValueProtocolErrorIEContainerList(value), err
		}
		*s28.BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s28.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s28.BridgeUEContextSuspendResponseIEContainerValueCodecFieldEncode(&codec))(s28.UEContextSuspendResponseIEContainer(value), fresh, budget)
		}
		*s28.BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s28.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s28.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s28.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUEContextSuspendResponseIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UEInformationTransferIEValueProtocolErrorIEContainerListCodec(table s00.UEInformationTransferIEValueIETable) s31.UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEInformationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s31.BridgeUEInformationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s31.UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s31.UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s31.UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec{}
		*s31.BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.UEInformationTransferIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s31.BridgeUEInformationTransferIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s31.UEInformationTransferIEValueProtocolErrorIEContainerList(value), err
		}
		*s31.BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s31.UEInformationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s31.BridgeUEInformationTransferIEContainerValueCodecFieldEncode(&codec))(s31.UEInformationTransferIEContainer(value), fresh, budget)
		}
		*s31.BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s31.UEInformationTransferIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s31.UEInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s31.BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s31.UEInformationTransferIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUEInformationTransferIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s31.BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListCodec(table s00.UERadioCapabilityIDMappingRequestIEValueIETable) s12.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := UERadioCapabilityIDMappingRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s12.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s12.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodec{}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s12.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s12.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList(value), err
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldEncode(&codec))(s12.UERadioCapabilityIDMappingRequestIEContainer(value), fresh, budget)
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s12.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListCodec(table s00.UERadioCapabilityIDMappingResponseIEValueIETable) s24.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := UERadioCapabilityIDMappingResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s24.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s24.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s23.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList(value), err
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldEncode(&codec))(s23.UERadioCapabilityIDMappingResponseIEContainer(value), fresh, budget)
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s23.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListCodec(table s00.UERadioCapabilityMatchRequestIEValueIETable) s12.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := UERadioCapabilityMatchRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s12.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s12.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodec{}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s12.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s12.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList(value), err
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldEncode(&codec))(s12.UERadioCapabilityMatchRequestIEContainer(value), fresh, budget)
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s12.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListCodec(table s00.UERadioCapabilityMatchResponseIEValueIETable) s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := UERadioCapabilityMatchResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	return func() s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, error) {
			value, err := (*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList(value), err
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldEncode(&codec))(s24.UERadioCapabilityMatchResponseIEContainer(value), fresh, budget)
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.
					Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolErrorIEContainerList(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func ResetIEValueProtocolIEContainerListCodec(table s00.ResetIEValueIETable, bounds aper.ListBounds) ResetIEValueProtocolIEContainerListValueCodec {
	codec := ResetIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return ResetIEValueProtocolIEContainerListValueCodec{}
	}
	return ResetIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (ResetIEValueProtocolIEContainerList, error) {
		value, err := codec.decode(data, options)
		return ResetIEValueProtocolIEContainerList(value), err
	}, encode: func(value ResetIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(ResetIEContainer(value), fresh, budget)
	}, capture: func(v ResetIEValueProtocolIEContainerList, options aper.DecodeState) (ResetIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeResetIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, compare: func(v ResetIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeResetIEValueCompareS1APProtocolIEContainerList(&v, &s)
		s.End(f, root,

			false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = bounds
		return sealed
	}(),
	}
}
func UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListCodec(table s00.UEAssociatedLogicalS1ConnectionItemResIEValueIETable, bounds aper.ListBounds) s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec {
	codec := s35.UEAssociatedLogicalS1ConnectionItemResIEValueIETableCodec(table, bounds)
	if *s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerValueCodecFieldDecode(&codec) == nil {
		return s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec {
		sealed := s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodec{}
		*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, error) {
			value, err := (*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList(value), err
		}
		*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEContainerValueCodecFieldEncode(&codec))(s35.UEAssociatedLogicalS1ConnectionItemResIEContainer(value), fresh, budget)
		}
		*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, options aper.DecodeState) (s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UECapabilityInfoIndicationIEValueProtocolIEContainerListCodec(table s00.UECapabilityInfoIndicationIEValueIETable, bounds aper.ListBounds) s12.UECapabilityInfoIndicationIEValueProtocolIEContainerListValueCodec {
	codec := UECapabilityInfoIndicationIEValueIETableCodec(table, bounds)
	if *s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UECapabilityInfoIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s12.UECapabilityInfoIndicationIEValueProtocolIEContainerListValueCodec {
		sealed := s12.UECapabilityInfoIndicationIEValueProtocolIEContainerListValueCodec{}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEValueProtocolIEContainerList, error) {
			value, err := (*s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s12.UECapabilityInfoIndicationIEValueProtocolIEContainerList(value), err
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UECapabilityInfoIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUECapabilityInfoIndicationIEContainerValueCodecFieldEncode(&codec))(s12.UECapabilityInfoIndicationIEContainer(value), fresh, budget)
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UECapabilityInfoIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (s12.UECapabilityInfoIndicationIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UECapabilityInfoIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUECapabilityInfoIndicationIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationConfirmIEValueProtocolIEContainerListCodec(table s00.UEContextModificationConfirmIEValueIETable, bounds aper.ListBounds) s23.UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec {
	codec := UEContextModificationConfirmIEValueIETableCodec(table, bounds)
	if *s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s23.UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec {
		sealed := s23.UEContextModificationConfirmIEValueProtocolIEContainerListValueCodec{}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationConfirmIEValueProtocolIEContainerList, error) {
			value, err := (*s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.UEContextModificationConfirmIEValueProtocolIEContainerList(value), err
		}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UEContextModificationConfirmIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUEContextModificationConfirmIEContainerValueCodecFieldEncode(&codec))(s23.UEContextModificationConfirmIEContainer(value), fresh, budget)
		}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationConfirmIEValueProtocolIEContainerList, options aper.DecodeState) (s23.UEContextModificationConfirmIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationConfirmIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationConfirmIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationFailureIEValueProtocolIEContainerListCodec(table s00.UEContextModificationFailureIEValueIETable, bounds aper.ListBounds) s23.UEContextModificationFailureIEValueProtocolIEContainerListValueCodec {
	codec := UEContextModificationFailureIEValueIETableCodec(table, bounds)
	if *s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextModificationFailureIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s23.UEContextModificationFailureIEValueProtocolIEContainerListValueCodec {
		sealed := s23.UEContextModificationFailureIEValueProtocolIEContainerListValueCodec{}
		*s23.BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationFailureIEValueProtocolIEContainerList, error) {
			value, err := (*s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.UEContextModificationFailureIEValueProtocolIEContainerList(value), err
		}
		*s23.BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UEContextModificationFailureIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldEncode(&codec))(s23.UEContextModificationFailureIEContainer(value), fresh, budget)
		}
		*s23.BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationFailureIEValueProtocolIEContainerList, options aper.DecodeState) (s23.UEContextModificationFailureIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s23.BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationFailureIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationIndicationIEValueProtocolIEContainerListCodec(table s00.UEContextModificationIndicationIEValueIETable, bounds aper.ListBounds) s21.UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec {
	codec := UEContextModificationIndicationIEValueIETableCodec(table, bounds)
	if *s21.BridgeUEContextModificationIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s21.UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s21.UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec {
		sealed := s21.UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec{}
		*s21.BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.UEContextModificationIndicationIEValueProtocolIEContainerList, error) {
			value, err := (*s21.BridgeUEContextModificationIndicationIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s21.UEContextModificationIndicationIEValueProtocolIEContainerList(value), err
		}
		*s21.BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s21.UEContextModificationIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s21.BridgeUEContextModificationIndicationIEContainerValueCodecFieldEncode(&codec))(s21.UEContextModificationIndicationIEContainer(value), fresh, budget)
		}
		*s21.BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s21.UEContextModificationIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (s21.UEContextModificationIndicationIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s21.BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s21.UEContextModificationIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s21.BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEContextModificationResponseIEValueProtocolIEContainerListCodec(table s00.UEContextModificationResponseIEValueIETable, bounds aper.ListBounds) s23.UEContextModificationResponseIEValueProtocolIEContainerListValueCodec {
	codec := UEContextModificationResponseIEValueIETableCodec(table, bounds)
	if *s23.BridgeUEContextModificationResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextModificationResponseIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s23.UEContextModificationResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s23.UEContextModificationResponseIEValueProtocolIEContainerListValueCodec{}
		*s23.BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationResponseIEValueProtocolIEContainerList, error) {
			value, err := (*s23.BridgeUEContextModificationResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.UEContextModificationResponseIEValueProtocolIEContainerList(value), err
		}
		*s23.BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UEContextModificationResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUEContextModificationResponseIEContainerValueCodecFieldEncode(&codec))(s23.UEContextModificationResponseIEContainer(value), fresh, budget)
		}
		*s23.BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s23.UEContextModificationResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s23.BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEContextResumeFailureIEValueProtocolIEContainerListCodec(table s00.UEContextResumeFailureIEValueIETable, bounds aper.ListBounds) s23.UEContextResumeFailureIEValueProtocolIEContainerListValueCodec {
	codec := UEContextResumeFailureIEValueIETableCodec(table, bounds)
	if *s23.BridgeUEContextResumeFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextResumeFailureIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s23.UEContextResumeFailureIEValueProtocolIEContainerListValueCodec {
		sealed := s23.UEContextResumeFailureIEValueProtocolIEContainerListValueCodec{}
		*s23.BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextResumeFailureIEValueProtocolIEContainerList, error) {
			value, err := (*s23.BridgeUEContextResumeFailureIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s23.UEContextResumeFailureIEValueProtocolIEContainerList(value), err
		}
		*s23.BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UEContextResumeFailureIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUEContextResumeFailureIEContainerValueCodecFieldEncode(&codec))(s23.UEContextResumeFailureIEContainer(value), fresh, budget)
		}
		*s23.BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UEContextResumeFailureIEValueProtocolIEContainerList, options aper.DecodeState) (s23.UEContextResumeFailureIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s23.BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextResumeFailureIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s23.BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEContextSuspendResponseIEValueProtocolIEContainerListCodec(table s00.UEContextSuspendResponseIEValueIETable, bounds aper.ListBounds) s28.UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec {
	codec := UEContextSuspendResponseIEValueIETableCodec(table, bounds)
	if *s28.BridgeUEContextSuspendResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s28.UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s28.UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s28.UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec{}
		*s28.BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.UEContextSuspendResponseIEValueProtocolIEContainerList, error) {
			value, err := (*s28.BridgeUEContextSuspendResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s28.UEContextSuspendResponseIEValueProtocolIEContainerList(value), err
		}
		*s28.BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s28.UEContextSuspendResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s28.BridgeUEContextSuspendResponseIEContainerValueCodecFieldEncode(&codec))(s28.UEContextSuspendResponseIEContainer(value), fresh, budget)
		}
		*s28.BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s28.UEContextSuspendResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s28.UEContextSuspendResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s28.BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s28.UEContextSuspendResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UEInformationTransferIEValueProtocolIEContainerListCodec(table s00.UEInformationTransferIEValueIETable, bounds aper.ListBounds) s31.UEInformationTransferIEValueProtocolIEContainerListValueCodec {
	codec := UEInformationTransferIEValueIETableCodec(table, bounds)
	if *s31.BridgeUEInformationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s31.UEInformationTransferIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s31.UEInformationTransferIEValueProtocolIEContainerListValueCodec {
		sealed := s31.UEInformationTransferIEValueProtocolIEContainerListValueCodec{}
		*s31.BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.UEInformationTransferIEValueProtocolIEContainerList, error) {
			value, err := (*s31.BridgeUEInformationTransferIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s31.UEInformationTransferIEValueProtocolIEContainerList(value), err
		}
		*s31.BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s31.UEInformationTransferIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s31.BridgeUEInformationTransferIEContainerValueCodecFieldEncode(&codec))(s31.UEInformationTransferIEContainer(value), fresh, budget)
		}
		*s31.BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s31.UEInformationTransferIEValueProtocolIEContainerList, options aper.DecodeState) (s31.UEInformationTransferIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s31.BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s31.UEInformationTransferIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s31.BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListCodec(table s00.UERadioCapabilityIDMappingRequestIEValueIETable, bounds aper.ListBounds) s12.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodec {
	codec := UERadioCapabilityIDMappingRequestIEValueIETableCodec(table, bounds)
	if *s12.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s12.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodec {
		sealed := s12.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodec{}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList, error) {
			value, err := (*s12.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s12.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList(value), err
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldEncode(&codec))(s12.UERadioCapabilityIDMappingRequestIEContainer(value), fresh, budget)
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList, options aper.DecodeState) (s12.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListCodec(table s00.UERadioCapabilityIDMappingResponseIEValueIETable, bounds aper.ListBounds) s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec {
	codec := UERadioCapabilityIDMappingResponseIEValueIETableCodec(table, bounds)
	if *s23.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec{}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, error) {
			value, err := (*s23.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList(value), err
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldEncode(&codec))(s23.UERadioCapabilityIDMappingResponseIEContainer(value), fresh, budget)
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityMatchRequestIEValueProtocolIEContainerListCodec(table s00.UERadioCapabilityMatchRequestIEValueIETable, bounds aper.ListBounds) s12.UERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodec {
	codec := UERadioCapabilityMatchRequestIEValueIETableCodec(table, bounds)
	if *s12.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s12.UERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodec {
		sealed := s12.UERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodec{}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UERadioCapabilityMatchRequestIEValueProtocolIEContainerList, error) {
			value, err := (*s12.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s12.UERadioCapabilityMatchRequestIEValueProtocolIEContainerList(value), err
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UERadioCapabilityMatchRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldEncode(&codec))(s12.UERadioCapabilityMatchRequestIEContainer(value), fresh, budget)
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UERadioCapabilityMatchRequestIEValueProtocolIEContainerList, options aper.DecodeState) (s12.UERadioCapabilityMatchRequestIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UERadioCapabilityMatchRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}
func UERadioCapabilityMatchResponseIEValueProtocolIEContainerListCodec(table s00.UERadioCapabilityMatchResponseIEValueIETable, bounds aper.ListBounds) s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec {
	codec := UERadioCapabilityMatchResponseIEValueIETableCodec(table, bounds)
	if *s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec{}
	}
	return func() s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec{}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, error) {
			value, err := (*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&codec))(data, options)
			return s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList(value), err
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldEncode(&codec))(s24.UERadioCapabilityMatchResponseIEContainer(value), fresh, budget)
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// resetIEValueProtocolOpenValue is the concrete protocolOpenValue[ResetIEValue].
type ResetIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ResetIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ResetIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeResetIEValueCaptureS1APProtocolIEField(v *ResetIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeResetIEValueCompareS1APProtocolIEField(v *ResetIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// uEAssociatedLogicalS1ConnectionItemResIEValueProtocolOpenValue is the concrete protocolOpenValue[UEAssociatedLogicalS1ConnectionItemResIEValue].
type UEAssociatedLogicalS1ConnectionItemResIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s35.UEAssociatedLogicalS1ConnectionItemResIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s35.UEAssociatedLogicalS1ConnectionItemResIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// uECapabilityInfoIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[UECapabilityInfoIndicationIEValue].
type UECapabilityInfoIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s12.UECapabilityInfoIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s12.UECapabilityInfoIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIEField(v *s12.UECapabilityInfoIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s12.BridgeUECapabilityInfoIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s12.BridgeUECapabilityInfoIndicationIEFieldFieldReplay(v), *s12.BridgeUECapabilityInfoIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIEField(v *s12.UECapabilityInfoIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s12.BridgeUECapabilityInfoIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s12.BridgeUECapabilityInfoIndicationIEFieldFieldReplay(v), *s12.BridgeUECapabilityInfoIndicationIEFieldFieldWithoutReplay(v))
}

// uEContextModificationConfirmIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextModificationConfirmIEValue].
type UEContextModificationConfirmIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s23.UEContextModificationConfirmIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s23.UEContextModificationConfirmIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIEField(v *s23.UEContextModificationConfirmIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s23.BridgeUEContextModificationConfirmIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s23.BridgeUEContextModificationConfirmIEFieldFieldReplay(v), *s23.BridgeUEContextModificationConfirmIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIEField(v *s23.UEContextModificationConfirmIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s23.BridgeUEContextModificationConfirmIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s23.BridgeUEContextModificationConfirmIEFieldFieldReplay(v), *s23.BridgeUEContextModificationConfirmIEFieldFieldWithoutReplay(v))
}

// uEContextModificationFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextModificationFailureIEValue].
type UEContextModificationFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s23.UEContextModificationFailureIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s23.UEContextModificationFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIEField(v *s23.UEContextModificationFailureIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s23.BridgeUEContextModificationFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s23.BridgeUEContextModificationFailureIEFieldFieldReplay(v), *s23.BridgeUEContextModificationFailureIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEField(v *s23.UEContextModificationFailureIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s23.BridgeUEContextModificationFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s23.BridgeUEContextModificationFailureIEFieldFieldReplay(v), *s23.BridgeUEContextModificationFailureIEFieldFieldWithoutReplay(v))
}

// uEContextModificationIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextModificationIndicationIEValue].
type UEContextModificationIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s21.UEContextModificationIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s21.UEContextModificationIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIEField(v *s21.UEContextModificationIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s21.BridgeUEContextModificationIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s21.BridgeUEContextModificationIndicationIEFieldFieldReplay(v), *s21.BridgeUEContextModificationIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIEField(v *s21.UEContextModificationIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s21.BridgeUEContextModificationIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s21.BridgeUEContextModificationIndicationIEFieldFieldReplay(v), *s21.BridgeUEContextModificationIndicationIEFieldFieldWithoutReplay(v))
}

// uEContextModificationResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextModificationResponseIEValue].
type UEContextModificationResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s23.UEContextModificationResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s23.UEContextModificationResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIEField(v *s23.UEContextModificationResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s23.BridgeUEContextModificationResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s23.BridgeUEContextModificationResponseIEFieldFieldReplay(v), *s23.BridgeUEContextModificationResponseIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextModificationResponseIEValueCompareS1APProtocolIEField(v *s23.UEContextModificationResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s23.BridgeUEContextModificationResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s23.BridgeUEContextModificationResponseIEFieldFieldReplay(v), *s23.BridgeUEContextModificationResponseIEFieldFieldWithoutReplay(v))
}

// uEContextResumeFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextResumeFailureIEValue].
type UEContextResumeFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s23.UEContextResumeFailureIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s23.UEContextResumeFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEField(v *s23.UEContextResumeFailureIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s23.BridgeUEContextResumeFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s23.BridgeUEContextResumeFailureIEFieldFieldReplay(v), *s23.BridgeUEContextResumeFailureIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEField(v *s23.UEContextResumeFailureIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s23.BridgeUEContextResumeFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s23.BridgeUEContextResumeFailureIEFieldFieldReplay(v), *s23.BridgeUEContextResumeFailureIEFieldFieldWithoutReplay(v))
}

// uEContextSuspendResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextSuspendResponseIEValue].
type UEContextSuspendResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s28.UEContextSuspendResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s28.UEContextSuspendResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEField(v *s28.UEContextSuspendResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s28.BridgeUEContextSuspendResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s28.BridgeUEContextSuspendResponseIEFieldFieldReplay(v), *s28.BridgeUEContextSuspendResponseIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEField(v *s28.UEContextSuspendResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s28.BridgeUEContextSuspendResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s28.BridgeUEContextSuspendResponseIEFieldFieldReplay(v), *s28.BridgeUEContextSuspendResponseIEFieldFieldWithoutReplay(v))
}

// uEInformationTransferIEValueProtocolOpenValue is the concrete protocolOpenValue[UEInformationTransferIEValue].
type UEInformationTransferIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s31.UEInformationTransferIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s31.UEInformationTransferIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEInformationTransferIEValueCaptureS1APProtocolIEField(v *s31.UEInformationTransferIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s31.BridgeUEInformationTransferIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s31.BridgeUEInformationTransferIEFieldFieldReplay(v), *s31.BridgeUEInformationTransferIEFieldFieldWithoutReplay(v))
}
func BridgeUEInformationTransferIEValueCompareS1APProtocolIEField(v *s31.UEInformationTransferIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s31.BridgeUEInformationTransferIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s31.BridgeUEInformationTransferIEFieldFieldReplay(v), *s31.BridgeUEInformationTransferIEFieldFieldWithoutReplay(v))
}

// uERadioCapabilityIDMappingRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[UERadioCapabilityIDMappingRequestIEValue].
type UERadioCapabilityIDMappingRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s07.UERadioCapabilityIDMappingRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s07.UERadioCapabilityIDMappingRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIEField(v *s12.UERadioCapabilityIDMappingRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s07.BridgeUERadioCapabilityIDMappingRequestIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s12.BridgeUERadioCapabilityIDMappingRequestIEFieldFieldReplay(v), *s12.BridgeUERadioCapabilityIDMappingRequestIEFieldFieldWithoutReplay(v))
}
func BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIEField(v *s12.UERadioCapabilityIDMappingRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s07.BridgeUERadioCapabilityIDMappingRequestIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s12.BridgeUERadioCapabilityIDMappingRequestIEFieldFieldReplay(v), *s12.BridgeUERadioCapabilityIDMappingRequestIEFieldFieldWithoutReplay(v))
}

// uERadioCapabilityIDMappingResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[UERadioCapabilityIDMappingResponseIEValue].
type UERadioCapabilityIDMappingResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s23.UERadioCapabilityIDMappingResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s23.UERadioCapabilityIDMappingResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEField(v *s23.UERadioCapabilityIDMappingResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s23.BridgeUERadioCapabilityIDMappingResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s23.BridgeUERadioCapabilityIDMappingResponseIEFieldFieldReplay(v), *s23.BridgeUERadioCapabilityIDMappingResponseIEFieldFieldWithoutReplay(v))
}
func BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEField(v *s23.UERadioCapabilityIDMappingResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s23.BridgeUERadioCapabilityIDMappingResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s23.BridgeUERadioCapabilityIDMappingResponseIEFieldFieldReplay(v), *s23.BridgeUERadioCapabilityIDMappingResponseIEFieldFieldWithoutReplay(v))
}

// uERadioCapabilityMatchRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[UERadioCapabilityMatchRequestIEValue].
type UERadioCapabilityMatchRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s12.UERadioCapabilityMatchRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s12.UERadioCapabilityMatchRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIEField(v *s12.UERadioCapabilityMatchRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s12.BridgeUERadioCapabilityMatchRequestIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s12.BridgeUERadioCapabilityMatchRequestIEFieldFieldReplay(v), *s12.BridgeUERadioCapabilityMatchRequestIEFieldFieldWithoutReplay(v))
}
func BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIEField(v *s12.UERadioCapabilityMatchRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s12.BridgeUERadioCapabilityMatchRequestIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s12.BridgeUERadioCapabilityMatchRequestIEFieldFieldReplay(v), *s12.BridgeUERadioCapabilityMatchRequestIEFieldFieldWithoutReplay(v))
}

// uERadioCapabilityMatchResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[UERadioCapabilityMatchResponseIEValue].
type UERadioCapabilityMatchResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s24.UERadioCapabilityMatchResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s24.UERadioCapabilityMatchResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEField(v *s24.UERadioCapabilityMatchResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s24.BridgeUERadioCapabilityMatchResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s24.BridgeUERadioCapabilityMatchResponseIEFieldFieldReplay(v), *s24.BridgeUERadioCapabilityMatchResponseIEFieldFieldWithoutReplay(v))
}
func BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEField(v *s24.UERadioCapabilityMatchResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s24.BridgeUERadioCapabilityMatchResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s24.BridgeUERadioCapabilityMatchResponseIEFieldFieldReplay(v), *s24.BridgeUERadioCapabilityMatchResponseIEFieldFieldWithoutReplay(v))
}
func BridgeUES1APIDPairExtIEsValueCaptureS1APProtocolExtensionField(v *s12.UES1APIDPairExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeUES1APIDPairExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeUES1APIDPairExtIEsExtFieldFieldReplay(v), *s12.BridgeUES1APIDPairExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeUES1APIDPairExtIEsValueCompareS1APProtocolExtensionField(v *s12.UES1APIDPairExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeUES1APIDPairExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeUES1APIDPairExtIEsExtFieldFieldReplay(v), *s12.BridgeUES1APIDPairExtIEsExtFieldFieldWithoutReplay(v))
}

// ResetTypeAPERValue is the concrete APERValue[ResetType].
type ResetTypeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s35.ResetType

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetTypeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetTypeAPERValue) WithoutReplay() ResetTypeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResetAPERValue is the concrete APERValue[Reset].
type ResetAPERValue struct {
	context s00.BridgeCodecContext
	Value   Reset

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetAPERValue) WithoutReplay() ResetAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UECapabilityInfoIndicationAPERValue is the concrete APERValue[UECapabilityInfoIndication].
type UECapabilityInfoIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   UECapabilityInfoIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UECapabilityInfoIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UECapabilityInfoIndicationAPERValue) WithoutReplay() UECapabilityInfoIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationConfirmAPERValue is the concrete APERValue[UEContextModificationConfirm].
type UEContextModificationConfirmAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEContextModificationConfirm

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationConfirmAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationConfirmAPERValue) WithoutReplay() UEContextModificationConfirmAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationFailureAPERValue is the concrete APERValue[UEContextModificationFailure].
type UEContextModificationFailureAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEContextModificationFailure

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationFailureAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationFailureAPERValue) WithoutReplay() UEContextModificationFailureAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationIndicationAPERValue is the concrete APERValue[UEContextModificationIndication].
type UEContextModificationIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEContextModificationIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationIndicationAPERValue) WithoutReplay() UEContextModificationIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextModificationResponseAPERValue is the concrete APERValue[UEContextModificationResponse].
type UEContextModificationResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEContextModificationResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextModificationResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextModificationResponseAPERValue) WithoutReplay() UEContextModificationResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextResumeFailureAPERValue is the concrete APERValue[UEContextResumeFailure].
type UEContextResumeFailureAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEContextResumeFailure

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextResumeFailureAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextResumeFailureAPERValue) WithoutReplay() UEContextResumeFailureAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextSuspendResponseAPERValue is the concrete APERValue[UEContextSuspendResponse].
type UEContextSuspendResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEContextSuspendResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextSuspendResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextSuspendResponseAPERValue) WithoutReplay() UEContextSuspendResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEInformationTransferAPERValue is the concrete APERValue[UEInformationTransfer].
type UEInformationTransferAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEInformationTransfer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEInformationTransferAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEInformationTransferAPERValue) WithoutReplay() UEInformationTransferAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityIDMappingRequestAPERValue is the concrete APERValue[UERadioCapabilityIDMappingRequest].
type UERadioCapabilityIDMappingRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   UERadioCapabilityIDMappingRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityIDMappingRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityIDMappingRequestAPERValue) WithoutReplay() UERadioCapabilityIDMappingRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityIDMappingResponseAPERValue is the concrete APERValue[UERadioCapabilityIDMappingResponse].
type UERadioCapabilityIDMappingResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   UERadioCapabilityIDMappingResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityIDMappingResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityIDMappingResponseAPERValue) WithoutReplay() UERadioCapabilityIDMappingResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityMatchRequestAPERValue is the concrete APERValue[UERadioCapabilityMatchRequest].
type UERadioCapabilityMatchRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   UERadioCapabilityMatchRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityMatchRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityMatchRequestAPERValue) WithoutReplay() UERadioCapabilityMatchRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityMatchResponseAPERValue is the concrete APERValue[UERadioCapabilityMatchResponse].
type UERadioCapabilityMatchResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   UERadioCapabilityMatchResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityMatchResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityMatchResponseAPERValue) WithoutReplay() UERadioCapabilityMatchResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UES1APIDPairAPERValue is the concrete APERValue[UES1APIDPair].
type UES1APIDPairAPERValue struct {
	context s00.BridgeCodecContext
	Value   UES1APIDPair

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UES1APIDPairAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UES1APIDPairAPERValue) WithoutReplay() UES1APIDPairAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UnsuccessfulOutcomeAPERValue is the concrete APERValue[UnsuccessfulOutcome].
type UnsuccessfulOutcomeAPERValue struct {
	context s00.BridgeCodecContext
	Value   UnsuccessfulOutcome

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UnsuccessfulOutcomeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UnsuccessfulOutcomeAPERValue) WithoutReplay() UnsuccessfulOutcomeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResetIEValueERABIEContainerListValueCodec is the concrete ValueCodec[ERABIEContainerList[ResetIEValue]].
type ResetIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetIEValueERABIEContainerList, error)
	encode  func(ResetIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetIEValueERABIEContainerList, aper.DecodeState) (ResetIEValueERABIEContainerList, aper.Snapshot)
	compare func(ResetIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetIEValueERABIEContainerListValueCodec) New(value ResetIEValueERABIEContainerList) (ResetIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ResetIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetIEValueERABIEContainerListValueCodec) EncodeAPER(value ResetIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetIEValueERABIEContainerListValueCodec) encodeBudgetValue(value ResetIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetIEValueERABIEContainerListValueCodec) encodeChanged(value ResetIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetIEValueERABIEContainerList is the concrete ERABIEContainerList[ResetIEValue].
type ResetIEValueERABIEContainerList []ResetIEValueProtocolIESingleContainer

func BridgeResetIEValueCaptureS1APERABIEContainerList(v *ResetIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeResetIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeResetIEValueCompareS1APERABIEContainerList(v *ResetIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeResetIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APERABIEContainerList(v *s35.UEAssociatedLogicalS1ConnectionItemResIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUECapabilityInfoIndicationIEValueCaptureS1APERABIEContainerList(v *s12.UECapabilityInfoIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUECapabilityInfoIndicationIEValueCompareS1APERABIEContainerList(v *s12.UECapabilityInfoIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationConfirmIEValueCaptureS1APERABIEContainerList(v *s23.UEContextModificationConfirmIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationConfirmIEValueCompareS1APERABIEContainerList(v *s23.UEContextModificationConfirmIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationFailureIEValueCaptureS1APERABIEContainerList(v *s23.UEContextModificationFailureIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationFailureIEValueCompareS1APERABIEContainerList(v *s23.UEContextModificationFailureIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationIndicationIEValueCaptureS1APERABIEContainerList(v *s21.UEContextModificationIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationIndicationIEValueCompareS1APERABIEContainerList(v *s21.UEContextModificationIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationResponseIEValueCaptureS1APERABIEContainerList(v *s23.UEContextModificationResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationResponseIEValueCompareS1APERABIEContainerList(v *s23.UEContextModificationResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextResumeFailureIEValueCaptureS1APERABIEContainerList(v *s23.UEContextResumeFailureIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextResumeFailureIEValueCompareS1APERABIEContainerList(v *s23.UEContextResumeFailureIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextResumeFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextSuspendResponseIEValueCaptureS1APERABIEContainerList(v *s28.UEContextSuspendResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextSuspendResponseIEValueCompareS1APERABIEContainerList(v *s28.UEContextSuspendResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEInformationTransferIEValueCaptureS1APERABIEContainerList(v *s31.UEInformationTransferIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEInformationTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEInformationTransferIEValueCompareS1APERABIEContainerList(v *s31.UEInformationTransferIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEInformationTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APERABIEContainerList(v *s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APERABIEContainerList(v *s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APERABIEContainerList(v *s23.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APERABIEContainerList(v *s23.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APERABIEContainerList(v *s12.UERadioCapabilityMatchRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityMatchRequestIEValueCompareS1APERABIEContainerList(v *s12.UERadioCapabilityMatchRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APERABIEContainerList(v *s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityMatchResponseIEValueCompareS1APERABIEContainerList(v *s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ResetIEFieldValueCodec is the concrete ValueCodec[ProtocolIEField[ResetIEValue]].
type ResetIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetIEField, error)
	encode  func(ResetIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetIEField, aper.DecodeState) (ResetIEField, aper.Snapshot)
	compare func(ResetIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetIEFieldValueCodec) New(value ResetIEField) (ResetIEFieldAPERValue, error) {
	if c.encode == nil {
		return ResetIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetIEFieldValueCodec) EncodeAPER(value ResetIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetIEFieldValueCodec) encodeBudgetValue(value ResetIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetIEFieldValueCodec) encodeChanged(value ResetIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetIEContainerValueCodec is the concrete ValueCodec[ProtocolIEContainer[ResetIEValue]].
type ResetIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetIEContainer, error)
	encode  func(ResetIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetIEContainer, aper.DecodeState) (ResetIEContainer, aper.Snapshot)
	compare func(ResetIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetIEContainerValueCodec) New(value ResetIEContainer) (ResetIEContainerAPERValue, error) {
	if c.encode == nil {
		return ResetIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetIEContainerValueCodec) EncodeAPER(value ResetIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetIEContainerValueCodec) encodeBudgetValue(value ResetIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetIEContainerValueCodec) encodeChanged(value ResetIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[ProtocolErrorIEContainerList[ResetIEValue]].
type ResetIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetIEValueProtocolErrorIEContainerList, error)
	encode  func(ResetIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetIEValueProtocolErrorIEContainerList, aper.DecodeState) (ResetIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(ResetIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetIEValueProtocolErrorIEContainerListValueCodec) New(value ResetIEValueProtocolErrorIEContainerList) (ResetIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ResetIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value ResetIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value ResetIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value ResetIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetIEValueProtocolErrorIEContainerList is the concrete ProtocolErrorIEContainerList[ResetIEValue].
type ResetIEValueProtocolErrorIEContainerList []ResetIEValueProtocolIESingleContainer

func BridgeResetIEValueCaptureS1APProtocolErrorIEContainerList(v *ResetIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeResetIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeResetIEValueCompareS1APProtocolErrorIEContainerList(v *ResetIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeResetIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolErrorIEContainerList(v *s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *s12.UECapabilityInfoIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolErrorIEContainerList(v *s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationConfirmIEValueCompareS1APProtocolErrorIEContainerList(v *s23.UEContextModificationConfirmIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationFailureIEValueCaptureS1APProtocolErrorIEContainerList(v *s23.UEContextModificationFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationFailureIEValueCompareS1APProtocolErrorIEContainerList(v *s23.UEContextModificationFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *s21.UEContextModificationIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *s21.UEContextModificationIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *s23.UEContextModificationResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s23.UEContextModificationResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextResumeFailureIEValueCaptureS1APProtocolErrorIEContainerList(v *s23.UEContextResumeFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextResumeFailureIEValueCompareS1APProtocolErrorIEContainerList(v *s23.UEContextResumeFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextResumeFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *s28.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextSuspendResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s28.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEInformationTransferIEValueCaptureS1APProtocolErrorIEContainerList(v *s31.UEInformationTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEInformationTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEInformationTransferIEValueCompareS1APProtocolErrorIEContainerList(v *s31.UEInformationTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEInformationTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *s12.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolErrorIEContainerList(v *s12.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *s23.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s23.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *s12.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolErrorIEContainerList(v *s12.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ResetIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[ProtocolIEContainerList[ResetIEValue]].
type ResetIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (ResetIEValueProtocolIEContainerList, error)
	encode  func(ResetIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(ResetIEValueProtocolIEContainerList, aper.DecodeState) (ResetIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(ResetIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetIEValueProtocolIEContainerListValueCodec) New(value ResetIEValueProtocolIEContainerList) (ResetIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return ResetIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetIEValueProtocolIEContainerListValueCodec) EncodeAPER(value ResetIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value ResetIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetIEValueProtocolIEContainerListValueCodec) encodeChanged(value ResetIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetIEValueProtocolIEContainerList is the concrete ProtocolIEContainerList[ResetIEValue].
type ResetIEValueProtocolIEContainerList []ResetIEValueProtocolIESingleContainer

func BridgeResetIEValueCaptureS1APProtocolIEContainerList(v *ResetIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeResetIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeResetIEValueCompareS1APProtocolIEContainerList(v *ResetIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeResetIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolIEContainerList(v *s35.UEAssociatedLogicalS1ConnectionItemResIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			s35.BridgeUEAssociatedLogicalS1ConnectionItemResIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIEContainerList(v *s12.UECapabilityInfoIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIEContainerList(v *s12.UECapabilityInfoIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIEContainerList(v *s23.UEContextModificationConfirmIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIEContainerList(v *s23.UEContextModificationConfirmIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIEContainerList(v *s23.UEContextModificationFailureIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEContainerList(v *s23.UEContextModificationFailureIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIEContainerList(v *s21.UEContextModificationIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIEContainerList(v *s21.UEContextModificationIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIEContainerList(v *s23.UEContextModificationResponseIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextModificationResponseIEValueCompareS1APProtocolIEContainerList(v *s23.UEContextModificationResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextModificationResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEContainerList(v *s23.UEContextResumeFailureIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEContainerList(v *s23.UEContextResumeFailureIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextResumeFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEContainerList(v *s28.UEContextSuspendResponseIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEContainerList(v *s28.UEContextSuspendResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEInformationTransferIEValueCaptureS1APProtocolIEContainerList(v *s31.UEInformationTransferIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEInformationTransferIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEInformationTransferIEValueCompareS1APProtocolIEContainerList(v *s31.UEInformationTransferIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEInformationTransferIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIEContainerList(v *s12.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIEContainerList(v *s12.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEContainerList(v *s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEContainerList(v *s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIEContainerList(v *s12.UERadioCapabilityMatchRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIEContainerList(v *s12.UERadioCapabilityMatchRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEContainerList(v *s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEContainerList(v *s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// ResetIEValueERABIEContainerListAPERValue is the concrete APERValue[ERABIEContainerList[ResetIEValue]].
type ResetIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetIEValueERABIEContainerListAPERValue) WithoutReplay() ResetIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResetIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[ResetIEValue].
type ResetIEValueProtocolIESingleContainer = ResetIEField

func BridgeResetIEValueCaptureS1APProtocolIESingleContainer(v *ResetIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeResetIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeResetIEValueCompareS1APProtocolIESingleContainer(v *ResetIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeResetIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIESingleContainer(v *s12.UECapabilityInfoIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIESingleContainer(v *s12.UECapabilityInfoIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIESingleContainer(v *s23.UEContextModificationConfirmIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIESingleContainer(v *s23.UEContextModificationConfirmIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIESingleContainer(v *s23.UEContextModificationFailureIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextModificationFailureIEValueCompareS1APProtocolIESingleContainer(v *s23.UEContextModificationFailureIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIESingleContainer(v *s21.UEContextModificationIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIESingleContainer(v *s21.UEContextModificationIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIESingleContainer(v *s23.UEContextModificationResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextModificationResponseIEValueCompareS1APProtocolIESingleContainer(v *s23.UEContextModificationResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationResponseIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIESingleContainer(v *s23.UEContextResumeFailureIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextResumeFailureIEValueCompareS1APProtocolIESingleContainer(v *s23.UEContextResumeFailureIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIESingleContainer(v *s28.UEContextSuspendResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIESingleContainer(v *s28.UEContextSuspendResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEInformationTransferIEValueCaptureS1APProtocolIESingleContainer(v *s31.UEInformationTransferIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEInformationTransferIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEInformationTransferIEValueCompareS1APProtocolIESingleContainer(v *s31.UEInformationTransferIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEInformationTransferIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIESingleContainer(v *s12.UERadioCapabilityIDMappingRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIESingleContainer(v *s12.UERadioCapabilityIDMappingRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIESingleContainer(v *s23.UERadioCapabilityIDMappingResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIESingleContainer(v *s23.UERadioCapabilityIDMappingResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIESingleContainer(v *s12.UERadioCapabilityMatchRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIESingleContainer(v *s12.UERadioCapabilityMatchRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIESingleContainer(v *s24.UERadioCapabilityMatchResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIESingleContainer(v *s24.UERadioCapabilityMatchResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// ResetIEFieldAPERValue is the concrete APERValue[ProtocolIEField[ResetIEValue]].
type ResetIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetIEFieldAPERValue) WithoutReplay() ResetIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResetIEContainerAPERValue is the concrete APERValue[ProtocolIEContainer[ResetIEValue]].
type ResetIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetIEContainerAPERValue) WithoutReplay() ResetIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResetIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[ProtocolErrorIEContainerList[ResetIEValue]].
type ResetIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() ResetIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResetIEValueProtocolIEContainerListAPERValue is the concrete APERValue[ProtocolIEContainerList[ResetIEValue]].
type ResetIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         ResetIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetIEValueProtocolIEContainerListAPERValue) WithoutReplay() ResetIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

type UnsuccessfulValue struct {
	code                              s00.ProcedureCode
	received                          aper.WireSpan
	replay                            aper.Snapshot
	opaque                            aper.OpaqueOpenType
	isOpaque                          bool
	bodyHandoverPreparationFailure    *s25.HandoverPreparationFailure
	bodyHandoverFailure               *s25.HandoverFailure
	bodyPathSwitchRequestFailure      *s26.PathSwitchRequestFailure
	bodyInitialContextSetupFailure    *s25.InitialContextSetupFailure
	bodyS1SetupFailure                *s26.S1SetupFailure
	bodyUEContextModificationFailure  *UEContextModificationFailure
	bodyENBConfigurationUpdateFailure *s24.ENBConfigurationUpdateFailure
	bodyMMEConfigurationUpdateFailure *s25.MMEConfigurationUpdateFailure
	bodyUEContextResumeFailure        *UEContextResumeFailure
	bodyS1RemovalFailure              *s26.S1RemovalFailure
}

// Opaque returns the retained opaque open value of UnsuccessfulValue and reports whether the opaque alternative is selected.
func (v *UnsuccessfulValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}

// AsHandoverPreparationFailure returns the selected HandoverPreparationFailure value of UnsuccessfulValue and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsHandoverPreparationFailure() (*s25.HandoverPreparationFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(0) || v.bodyHandoverPreparationFailure == nil {
		return nil, false
	}
	return v.bodyHandoverPreparationFailure, true
}

// AsHandoverFailure returns the selected HandoverFailure value of UnsuccessfulValue and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsHandoverFailure() (*s25.HandoverFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(1) || v.bodyHandoverFailure == nil {
		return nil, false
	}
	return v.bodyHandoverFailure, true
}

// AsPathSwitchRequestFailure returns the selected PathSwitchRequestFailure value of UnsuccessfulValue and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsPathSwitchRequestFailure() (*s26.PathSwitchRequestFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(3) || v.bodyPathSwitchRequestFailure == nil {
		return nil, false
	}
	return v.bodyPathSwitchRequestFailure, true
}

// AsInitialContextSetupFailure returns the selected InitialContextSetupFailure value of UnsuccessfulValue and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsInitialContextSetupFailure() (*s25.InitialContextSetupFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(9) || v.bodyInitialContextSetupFailure == nil {
		return nil, false
	}
	return v.bodyInitialContextSetupFailure, true
}

// AsS1SetupFailure returns the selected S1SetupFailure value of UnsuccessfulValue and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsS1SetupFailure() (*s26.S1SetupFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(17) || v.bodyS1SetupFailure == nil {
		return nil, false
	}
	return v.bodyS1SetupFailure, true
}

// AsUEContextModificationFailure returns the selected UEContextModificationFailure value of UnsuccessfulValue and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsUEContextModificationFailure() (*UEContextModificationFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(21) || v.bodyUEContextModificationFailure == nil {
		return nil, false
	}
	return v.bodyUEContextModificationFailure, true
}

// AsENBConfigurationUpdateFailure returns the selected ENBConfigurationUpdateFailure value of UnsuccessfulValue and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsENBConfigurationUpdateFailure() (*s24.ENBConfigurationUpdateFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(29) || v.bodyENBConfigurationUpdateFailure == nil {
		return nil, false
	}
	return v.bodyENBConfigurationUpdateFailure, true
}

// AsMMEConfigurationUpdateFailure returns the selected MMEConfigurationUpdateFailure value of UnsuccessfulValue and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsMMEConfigurationUpdateFailure() (*s25.MMEConfigurationUpdateFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(30) || v.bodyMMEConfigurationUpdateFailure == nil {
		return nil, false
	}
	return v.bodyMMEConfigurationUpdateFailure, true
}

// AsUEContextResumeFailure returns the selected UEContextResumeFailure value of UnsuccessfulValue and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsUEContextResumeFailure() (*UEContextResumeFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(56) || v.bodyUEContextResumeFailure == nil {
		return nil, false
	}
	return v.bodyUEContextResumeFailure, true
}

// AsS1RemovalFailure returns the selected S1RemovalFailure value of UnsuccessfulValue and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsS1RemovalFailure() (*s26.S1RemovalFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(67) || v.bodyS1RemovalFailure == nil {
		return nil, false
	}
	return v.bodyS1RemovalFailure, true
}
func BridgeDecodeUnsuccessfulValue(code s00.ProcedureCode, raw aper.OpaqueOpenType) (UnsuccessfulValue, error) {
	v := UnsuccessfulValue{code: code}
	switch code {
	case s00.ProcedureCode(0):
		var body s25.HandoverPreparationFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s25.BridgeHandoverPreparationFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.HandoverPreparationFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverPreparationFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s25.BridgeHandoverPreparationFailureFieldPerPadding(&body) = padding
		*s25.BridgeHandoverPreparationFailureFieldReceived(&body) = true
		raw.RetainContents(s25.BridgeHandoverPreparationFailureFieldReceivedBytes(&body))
		*s25.BridgeHandoverPreparationFailureFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyHandoverPreparationFailure = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(1):
		var body s25.HandoverFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s25.BridgeHandoverFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.HandoverFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s25.BridgeHandoverFailureFieldPerPadding(&body) = padding
		*s25.BridgeHandoverFailureFieldReceived(&body) = true
		raw.RetainContents(s25.BridgeHandoverFailureFieldReceivedBytes(&body))
		*s25.BridgeHandoverFailureFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyHandoverFailure = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(3):
		var body s26.PathSwitchRequestFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s26.BridgePathSwitchRequestFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.PathSwitchRequestFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PathSwitchRequestFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s26.BridgePathSwitchRequestFailureFieldPerPadding(&body) = padding
		*s26.BridgePathSwitchRequestFailureFieldReceived(&body) = true
		raw.RetainContents(s26.BridgePathSwitchRequestFailureFieldReceivedBytes(&body))
		*s26.BridgePathSwitchRequestFailureFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyPathSwitchRequestFailure = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(9):
		var body s25.InitialContextSetupFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s25.BridgeInitialContextSetupFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.InitialContextSetupFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "InitialContextSetupFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s25.BridgeInitialContextSetupFailureFieldPerPadding(&body) = padding
		*s25.BridgeInitialContextSetupFailureFieldReceived(&body) = true
		raw.RetainContents(s25.BridgeInitialContextSetupFailureFieldReceivedBytes(&body))
		*s25.BridgeInitialContextSetupFailureFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyInitialContextSetupFailure = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(17):
		var body s26.S1SetupFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s26.BridgeS1SetupFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.S1SetupFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "S1SetupFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s26.BridgeS1SetupFailureFieldPerPadding(&body) = padding
		*s26.BridgeS1SetupFailureFieldReceived(&body) = true
		raw.RetainContents(s26.BridgeS1SetupFailureFieldReceivedBytes(&body))
		*s26.BridgeS1SetupFailureFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyS1SetupFailure = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(21):
		var body UEContextModificationFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := body.unmarshalAPERFrom(child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.UEContextModificationFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextModificationFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.ContentLocation()
		v.bodyUEContextModificationFailure = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(29):
		var body s24.ENBConfigurationUpdateFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s24.BridgeENBConfigurationUpdateFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.ENBConfigurationUpdateFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENBConfigurationUpdateFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s24.BridgeENBConfigurationUpdateFailureFieldPerPadding(&body) = padding
		*s24.BridgeENBConfigurationUpdateFailureFieldReceived(&body) = true
		raw.RetainContents(s24.BridgeENBConfigurationUpdateFailureFieldReceivedBytes(&body))
		*s24.BridgeENBConfigurationUpdateFailureFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyENBConfigurationUpdateFailure = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(30):
		var body s25.MMEConfigurationUpdateFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s25.BridgeMMEConfigurationUpdateFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.MMEConfigurationUpdateFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "MMEConfigurationUpdateFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s25.BridgeMMEConfigurationUpdateFailureFieldPerPadding(&body) = padding
		*s25.BridgeMMEConfigurationUpdateFailureFieldReceived(&body) = true
		raw.RetainContents(s25.BridgeMMEConfigurationUpdateFailureFieldReceivedBytes(&body))
		*s25.BridgeMMEConfigurationUpdateFailureFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyMMEConfigurationUpdateFailure = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(56):
		var body UEContextResumeFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := body.unmarshalAPERFrom(child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.UEContextResumeFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextResumeFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		body.receivedLocation = raw.ContentLocation()
		v.bodyUEContextResumeFailure = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(67):
		var body s26.S1RemovalFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s26.BridgeS1RemovalFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.S1RemovalFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "S1RemovalFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s26.BridgeS1RemovalFailureFieldPerPadding(&body) = padding
		*s26.BridgeS1RemovalFailureFieldReceived(&body) = true
		raw.RetainContents(s26.BridgeS1RemovalFailureFieldReceivedBytes(&body))
		*s26.BridgeS1RemovalFailureFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyS1RemovalFailure = &body
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
func (v UnsuccessfulValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v UnsuccessfulValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		if v.bodyHandoverPreparationFailure == nil {
			return nil, fmt.Errorf("%s value: missing HandoverPreparationFailure", "Unsuccessful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s25.BridgeHandoverPreparationFailureMethodMarshalAPERBudget(v.bodyHandoverPreparationFailure, budget, fresh)
	case s00.ProcedureCode(1):
		if v.bodyHandoverFailure == nil {
			return nil, fmt.Errorf("%s value: missing HandoverFailure", "Unsuccessful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s25.BridgeHandoverFailureMethodMarshalAPERBudget(v.bodyHandoverFailure, budget, fresh)
	case s00.ProcedureCode(3):
		if v.bodyPathSwitchRequestFailure == nil {
			return nil, fmt.Errorf("%s value: missing PathSwitchRequestFailure", "Unsuccessful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s26.BridgePathSwitchRequestFailureMethodMarshalAPERBudget(v.bodyPathSwitchRequestFailure, budget, fresh)
	case s00.ProcedureCode(9):
		if v.bodyInitialContextSetupFailure == nil {
			return nil, fmt.Errorf("%s value: missing InitialContextSetupFailure", "Unsuccessful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s25.BridgeInitialContextSetupFailureMethodMarshalAPERBudget(v.bodyInitialContextSetupFailure, budget, fresh)
	case s00.ProcedureCode(17):
		if v.bodyS1SetupFailure == nil {
			return nil, fmt.Errorf("%s value: missing S1SetupFailure", "Unsuccessful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s26.BridgeS1SetupFailureMethodMarshalAPERBudget(v.bodyS1SetupFailure, budget, fresh)
	case s00.ProcedureCode(21):
		if v.bodyUEContextModificationFailure == nil {
			return nil, fmt.Errorf("%s value: missing UEContextModificationFailure", "Unsuccessful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return v.bodyUEContextModificationFailure.marshalAPERBudget(budget, fresh)
	case s00.ProcedureCode(29):
		if v.bodyENBConfigurationUpdateFailure == nil {
			return nil, fmt.Errorf("%s value: missing ENBConfigurationUpdateFailure", "Unsuccessful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s24.BridgeENBConfigurationUpdateFailureMethodMarshalAPERBudget(v.bodyENBConfigurationUpdateFailure, budget, fresh)
	case s00.ProcedureCode(30):
		if v.bodyMMEConfigurationUpdateFailure == nil {
			return nil, fmt.Errorf("%s value: missing MMEConfigurationUpdateFailure", "Unsuccessful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s25.BridgeMMEConfigurationUpdateFailureMethodMarshalAPERBudget(v.bodyMMEConfigurationUpdateFailure, budget, fresh)
	case s00.ProcedureCode(56):
		if v.bodyUEContextResumeFailure == nil {
			return nil, fmt.Errorf("%s value: missing UEContextResumeFailure", "Unsuccessful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return v.bodyUEContextResumeFailure.marshalAPERBudget(budget, fresh)
	case s00.ProcedureCode(67):
		if v.bodyS1RemovalFailure == nil {
			return nil, fmt.Errorf("%s value: missing S1RemovalFailure", "Unsuccessful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s26.BridgeS1RemovalFailureMethodMarshalAPERBudget(v.bodyS1RemovalFailure, budget, fresh)
	default:
		return nil, fmt.Errorf("%s value: unknown code %d without opaque content", "Unsuccessful", v.code)
	}
}
func NewOpaqueUnsuccessfulOutcome(code s00.ProcedureCode, criticality s00.Criticality, data []byte) (UnsuccessfulOutcome, error) {
	switch code {
	case s00.ProcedureCode(0):
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Unsuccessful procedure id-HandoverPreparation requires its typed binding"), "OpaqueUnsuccessfulOutcome")
	case s00.ProcedureCode(1):
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Unsuccessful procedure id-HandoverResourceAllocation requires its typed binding"), "OpaqueUnsuccessfulOutcome")
	case s00.ProcedureCode(3):
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Unsuccessful procedure id-PathSwitchRequest requires its typed binding"), "OpaqueUnsuccessfulOutcome")
	case s00.ProcedureCode(9):
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Unsuccessful procedure id-InitialContextSetup requires its typed binding"), "OpaqueUnsuccessfulOutcome")
	case s00.ProcedureCode(17):
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Unsuccessful procedure id-S1Setup requires its typed binding"), "OpaqueUnsuccessfulOutcome")
	case s00.ProcedureCode(21):
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Unsuccessful procedure id-UEContextModification requires its typed binding"), "OpaqueUnsuccessfulOutcome")
	case s00.ProcedureCode(29):
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Unsuccessful procedure id-ENBConfigurationUpdate requires its typed binding"), "OpaqueUnsuccessfulOutcome")
	case s00.ProcedureCode(30):
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Unsuccessful procedure id-MMEConfigurationUpdate requires its typed binding"), "OpaqueUnsuccessfulOutcome")
	case s00.ProcedureCode(56):
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Unsuccessful procedure id-UEContextResume requires its typed binding"), "OpaqueUnsuccessfulOutcome")
	case s00.ProcedureCode(67):
		return UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Unsuccessful procedure id-S1Removal requires its typed binding"), "OpaqueUnsuccessfulOutcome")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "OpaqueUnsuccessfulOutcome")
	}
	opaque, err := aper.BuildOpaqueOpenType(data, budget)
	if err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "OpaqueUnsuccessfulOutcome")
	}
	message := UnsuccessfulOutcome{ProcedureCode: code, Criticality: criticality, Value: UnsuccessfulValue{code: code, opaque: opaque, isOpaque: true}}
	if _, err := message.marshalAPERBudget(budget, false); err != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(err, "OpaqueUnsuccessfulOutcome")
	}
	return message, aper.OperationError(nil, "OpaqueUnsuccessfulOutcome")
}
func BridgeCaptureS1APReset(v *Reset, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeResetIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APReset(v *Reset, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeResetIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APResetIEValue(v *ResetIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCaptureS1APCause(v.rowCause, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(92):
			{
				f := s.Begin()
				s.Bool(v.rowResetType == nil)
				if v.rowResetType != nil {
					s35.BridgeCaptureS1APResetType(v.rowResetType, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ResetIEValue) captureSemantics(s aper.SemanticCapture) ResetIEValue {
	BridgeCaptureS1APResetIEValue(&v, &s)
	return v
}
func BridgeCompareS1APResetIEValue(v *ResetIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCompareS1APCause(v.rowCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(92):
			{
				f := s.Begin()
				s.Bool(v.rowResetType == nil)
				if v.rowResetType != nil {
					s35.BridgeCompareS1APResetType(v.rowResetType, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v ResetIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APResetIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APUECapabilityInfoIndication(v *UECapabilityInfoIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUECapabilityInfoIndicationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUECapabilityInfoIndication(v *UECapabilityInfoIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUECapabilityInfoIndicationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextModificationConfirm(v *UEContextModificationConfirm, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationConfirmIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEContextModificationConfirm(v *UEContextModificationConfirm, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationConfirmIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextModificationFailure(v *UEContextModificationFailure, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEContextModificationFailure(v *UEContextModificationFailure, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextModificationIndication(v *UEContextModificationIndication, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEContextModificationIndication(v *UEContextModificationIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextModificationResponse(v *UEContextModificationResponse, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEContextModificationResponse(v *UEContextModificationResponse, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationResponseIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextResumeFailure(v *UEContextResumeFailure, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEContextResumeFailure(v *UEContextResumeFailure, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextSuspendResponse(v *UEContextSuspendResponse, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEContextSuspendResponse(v *UEContextSuspendResponse, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEInformationTransfer(v *UEInformationTransfer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEInformationTransferIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEInformationTransfer(v *UEInformationTransfer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEInformationTransferIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUERadioCapabilityIDMappingRequest(v *UERadioCapabilityIDMappingRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUERadioCapabilityIDMappingRequest(v *UERadioCapabilityIDMappingRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUERadioCapabilityIDMappingResponse(v *UERadioCapabilityIDMappingResponse, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUERadioCapabilityIDMappingResponse(v *UERadioCapabilityIDMappingResponse, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUERadioCapabilityMatchRequest(v *UERadioCapabilityMatchRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUERadioCapabilityMatchRequest(v *UERadioCapabilityMatchRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUERadioCapabilityMatchResponse(v *UERadioCapabilityMatchResponse, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUERadioCapabilityMatchResponse(v *UERadioCapabilityMatchResponse, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUES1APIDPair(v *UES1APIDPair, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APMMEUES1APID(&v.MMEUES1APID, s)
	s00.BridgeCaptureS1APENBUES1APID(&v.ENBUES1APID, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUES1APIDPairExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUES1APIDPair(v *UES1APIDPair, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APMMEUES1APID(&v.MMEUES1APID, s)
	s02.BridgeCompareS1APENBUES1APID(&v.ENBUES1APID, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUES1APIDPairExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUnsuccessfulOutcome(v *UnsuccessfulOutcome, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProcedureCode(&v.ProcedureCode, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	BridgeCaptureS1APUnsuccessfulValue(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUnsuccessfulOutcome(v *UnsuccessfulOutcome, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProcedureCode(&v.ProcedureCode, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	BridgeCompareS1APUnsuccessfulValue(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUnsuccessfulValue(v *UnsuccessfulValue, s *aper.SemanticCapture) {
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
				s.Bool(v.bodyHandoverPreparationFailure == nil)
				if v.bodyHandoverPreparationFailure != nil {
					s25.BridgeCaptureS1APHandoverPreparationFailure(v.bodyHandoverPreparationFailure, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(1):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverFailure == nil)
				if v.bodyHandoverFailure != nil {
					s25.BridgeCaptureS1APHandoverFailure(v.bodyHandoverFailure, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(3):
			{
				f := s.Begin()
				s.Bool(v.bodyPathSwitchRequestFailure == nil)
				if v.bodyPathSwitchRequestFailure != nil {
					s26.BridgeCaptureS1APPathSwitchRequestFailure(v.bodyPathSwitchRequestFailure, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(9):
			{
				f := s.Begin()
				s.Bool(v.bodyInitialContextSetupFailure == nil)
				if v.bodyInitialContextSetupFailure != nil {
					s25.BridgeCaptureS1APInitialContextSetupFailure(v.bodyInitialContextSetupFailure, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(17):
			{
				f := s.Begin()
				s.Bool(v.bodyS1SetupFailure == nil)
				if v.bodyS1SetupFailure != nil {
					s26.BridgeCaptureS1APS1SetupFailure(v.bodyS1SetupFailure, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(21):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationFailure == nil)
				if v.bodyUEContextModificationFailure != nil {
					BridgeCaptureS1APUEContextModificationFailure(v.bodyUEContextModificationFailure, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(29):
			{
				f := s.Begin()
				s.Bool(v.bodyENBConfigurationUpdateFailure == nil)
				if v.bodyENBConfigurationUpdateFailure != nil {
					s24.BridgeCaptureS1APENBConfigurationUpdateFailure(v.bodyENBConfigurationUpdateFailure, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(30):
			{
				f := s.Begin()
				s.Bool(v.bodyMMEConfigurationUpdateFailure == nil)
				if v.bodyMMEConfigurationUpdateFailure != nil {
					s25.BridgeCaptureS1APMMEConfigurationUpdateFailure(v.bodyMMEConfigurationUpdateFailure, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(56):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextResumeFailure == nil)
				if v.bodyUEContextResumeFailure != nil {
					BridgeCaptureS1APUEContextResumeFailure(v.bodyUEContextResumeFailure, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(67):
			{
				f := s.Begin()
				s.Bool(v.bodyS1RemovalFailure == nil)
				if v.bodyS1RemovalFailure != nil {
					s26.BridgeCaptureS1APS1RemovalFailure(v.bodyS1RemovalFailure, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UnsuccessfulValue) captureSemantics(s aper.SemanticCapture) UnsuccessfulValue {
	BridgeCaptureS1APUnsuccessfulValue(&v, &s)
	return v
}
func BridgeCompareS1APUnsuccessfulValue(v *UnsuccessfulValue, s *aper.SemanticComparison) {
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
				s.Bool(v.bodyHandoverPreparationFailure == nil)
				if v.bodyHandoverPreparationFailure != nil {
					s25.BridgeCompareS1APHandoverPreparationFailure(v.bodyHandoverPreparationFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(1):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverFailure == nil)
				if v.bodyHandoverFailure != nil {
					s25.BridgeCompareS1APHandoverFailure(v.bodyHandoverFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(3):
			{
				f := s.Begin()
				s.Bool(v.bodyPathSwitchRequestFailure == nil)
				if v.bodyPathSwitchRequestFailure != nil {
					s26.BridgeCompareS1APPathSwitchRequestFailure(v.bodyPathSwitchRequestFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(9):
			{
				f := s.Begin()
				s.Bool(v.bodyInitialContextSetupFailure == nil)
				if v.bodyInitialContextSetupFailure != nil {
					s25.BridgeCompareS1APInitialContextSetupFailure(v.bodyInitialContextSetupFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(17):
			{
				f := s.Begin()
				s.Bool(v.bodyS1SetupFailure == nil)
				if v.bodyS1SetupFailure != nil {
					s26.BridgeCompareS1APS1SetupFailure(v.bodyS1SetupFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(21):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationFailure == nil)
				if v.bodyUEContextModificationFailure != nil {
					BridgeCompareS1APUEContextModificationFailure(v.bodyUEContextModificationFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(29):
			{
				f := s.Begin()
				s.Bool(v.bodyENBConfigurationUpdateFailure == nil)
				if v.bodyENBConfigurationUpdateFailure != nil {
					s24.BridgeCompareS1APENBConfigurationUpdateFailure(v.bodyENBConfigurationUpdateFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(30):
			{
				f := s.Begin()
				s.Bool(v.bodyMMEConfigurationUpdateFailure == nil)
				if v.bodyMMEConfigurationUpdateFailure != nil {
					s25.BridgeCompareS1APMMEConfigurationUpdateFailure(v.bodyMMEConfigurationUpdateFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(56):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextResumeFailure == nil)
				if v.bodyUEContextResumeFailure != nil {
					BridgeCompareS1APUEContextResumeFailure(v.bodyUEContextResumeFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(67):
			{
				f := s.Begin()
				s.Bool(v.bodyS1RemovalFailure == nil)
				if v.bodyS1RemovalFailure != nil {
					s26.BridgeCompareS1APS1RemovalFailure(v.bodyS1RemovalFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UnsuccessfulValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUnsuccessfulValue(&v, &s)
	return s
}

// UES1APIDPair represents the ASN.1 type UE-S1AP-ID-pair (SEQUENCE).
type UES1APIDPair struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	received          bool
	withoutReplay     bool
	receivedAbsolute  bool
	receivedBytes     aper.WireSpan
	receivedLocation  aper.Location
	MMEUES1APID       s00.MMEUES1APID                    `asn1:"tag:0,context,implicit"`
	ENBUES1APID       s00.ENBUES1APID                    `asn1:"tag:1,context,implicit"`
	IEExtensions      s12.UES1APIDPairExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                               `asn1:"-" json:"-"`
	extCount          int64                              `asn1:"-" json:"-"`
	extPresent        []bool                             `asn1:"-" json:"-"`
	extData           [][]byte                           `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                  `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding             `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// MarshalAPER encodes UES1APIDPair to APER format.
func (v *UES1APIDPair) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UES1APIDPair) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.MMEUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
		return fmt.Errorf("encoding mME-UE-S1AP-ID: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.ENBUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false); err != nil {
		return fmt.Errorf("encoding eNB-UE-S1AP-ID: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s12.BridgeUES1APIDPairExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UES1APIDPair from APER format.
func (v *UES1APIDPair) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UES1APIDPair with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UES1APIDPair) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UES1APIDPair")
	}
	bb.EnterComponent("UES1APIDPair")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UES1APIDPair")
	}
	padding, err := aper.CaptureFinalBits(bb, "UES1APIDPair")
	if err != nil {
		return runtime.WrapDecodePath(err, "UES1APIDPair")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UES1APIDPair) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UES1APIDPair{}
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
	val_mmeues1apid, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "MMEUES1APID")
	}
	v.MMEUES1APID = s00.MMEUES1APID(val_mmeues1apid)
	val_enbues1apid, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBUES1APID")
	}
	v.ENBUES1APID = s00.ENBUES1APID(val_enbues1apid)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s12.UES1APIDPairExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.UES1APIDPairExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgeUES1APIDPairExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *UES1APIDPair) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UES1APIDPair", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UES1APIDPair", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UES1APIDPair) WithoutReplay() UES1APIDPair {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UES1APIDPair
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *UES1APIDPair) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UES1APIDPair) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UES1APIDPair.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UES1APIDPair.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UES1APIDPair) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UES1APIDPair.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UES1APIDPair.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *UES1APIDPair) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UES1APIDPair")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UES1APIDPair) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UES1APIDPair")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUES1APIDPair(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UES1APIDPair")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UES1APIDPair")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UES1APIDPair) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UES1APIDPair")
}
func (v *UES1APIDPair) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UES1APIDPair")
}
func (v *UES1APIDPair) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUES1APIDPair(v, &s)
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
func (v *UES1APIDPair) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UES1APIDPair) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UES1APIDPair) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UES1APIDPair")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UES1APIDPair
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUES1APIDPair(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UES1APIDPair{}
		return report, aper.OperationError(err, "UES1APIDPair")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UES1APIDPair")
}

// UEContextModificationResponse represents the ASN.1 type UEContextModificationResponse (SEQUENCE).
type UEContextModificationResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s23.UEContextModificationResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                         `asn1:"-" json:"-"`
	extCount         int64                                        `asn1:"-" json:"-"`
	extPresent       []bool                                       `asn1:"-" json:"-"`
	extData          [][]byte                                     `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UEContextModificationFailure represents the ASN.1 type UEContextModificationFailure (SEQUENCE).
type UEContextModificationFailure struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s23.UEContextModificationFailureIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                        `asn1:"-" json:"-"`
	extCount         int64                                       `asn1:"-" json:"-"`
	extPresent       []bool                                      `asn1:"-" json:"-"`
	extData          [][]byte                                    `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                           `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                      `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UERadioCapabilityMatchRequest represents the ASN.1 type UERadioCapabilityMatchRequest (SEQUENCE).
type UERadioCapabilityMatchRequest struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s12.UERadioCapabilityMatchRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                         `asn1:"-" json:"-"`
	extCount         int64                                        `asn1:"-" json:"-"`
	extPresent       []bool                                       `asn1:"-" json:"-"`
	extData          [][]byte                                     `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UERadioCapabilityMatchResponse represents the ASN.1 type UERadioCapabilityMatchResponse (SEQUENCE).
type UERadioCapabilityMatchResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s24.UERadioCapabilityMatchResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                          `asn1:"-" json:"-"`
	extCount         int64                                         `asn1:"-" json:"-"`
	extPresent       []bool                                        `asn1:"-" json:"-"`
	extData          [][]byte                                      `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// Reset represents the ASN.1 type Reset (SEQUENCE).
type Reset struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      ResetIEContainer       `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                   `asn1:"-" json:"-"`
	extCount         int64                  `asn1:"-" json:"-"`
	extPresent       []bool                 `asn1:"-" json:"-"`
	extData          [][]byte               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// NewResetTypeS1Interface creates a ResetType with the s1-Interface alternative.
func BridgeNewResetTypeS1InterfaceLegacy(v s00.ResetAll) s35.ResetType {
	return s35.ResetType{
		Choice:      s00.ResetTypeChoiceS1Interface,
		S1Interface: &v,
	}
}

// NewResetTypePartOfS1Interface creates a ResetType with the partOfS1-Interface alternative.
func BridgeNewResetTypePartOfS1InterfaceLegacy(v s35.UEAssociatedLogicalS1ConnectionListRes) s35.ResetType {
	return s35.ResetType{
		Choice:            s00.ResetTypeChoicePartOfS1Interface,
		PartOfS1Interface: v,
	}
}

// UECapabilityInfoIndication represents the ASN.1 type UECapabilityInfoIndication (SEQUENCE).
type UECapabilityInfoIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s12.UECapabilityInfoIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                      `asn1:"-" json:"-"`
	extCount         int64                                     `asn1:"-" json:"-"`
	extPresent       []bool                                    `asn1:"-" json:"-"`
	extData          [][]byte                                  `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UEContextModificationIndication represents the ASN.1 type UEContextModificationIndication (SEQUENCE).
type UEContextModificationIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s21.UEContextModificationIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                           `asn1:"-" json:"-"`
	extCount         int64                                          `asn1:"-" json:"-"`
	extPresent       []bool                                         `asn1:"-" json:"-"`
	extData          [][]byte                                       `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UEContextModificationConfirm represents the ASN.1 type UEContextModificationConfirm (SEQUENCE).
type UEContextModificationConfirm struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s23.UEContextModificationConfirmIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                        `asn1:"-" json:"-"`
	extCount         int64                                       `asn1:"-" json:"-"`
	extPresent       []bool                                      `asn1:"-" json:"-"`
	extData          [][]byte                                    `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                           `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                      `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UEContextSuspendResponse represents the ASN.1 type UEContextSuspendResponse (SEQUENCE).
type UEContextSuspendResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s28.UEContextSuspendResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                    `asn1:"-" json:"-"`
	extCount         int64                                   `asn1:"-" json:"-"`
	extPresent       []bool                                  `asn1:"-" json:"-"`
	extData          [][]byte                                `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UEContextResumeFailure represents the ASN.1 type UEContextResumeFailure (SEQUENCE).
type UEContextResumeFailure struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s23.UEContextResumeFailureIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                  `asn1:"-" json:"-"`
	extCount         int64                                 `asn1:"-" json:"-"`
	extPresent       []bool                                `asn1:"-" json:"-"`
	extData          [][]byte                              `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UEInformationTransfer represents the ASN.1 type UEInformationTransfer (SEQUENCE).
type UEInformationTransfer struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s31.UEInformationTransferIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                 `asn1:"-" json:"-"`
	extCount         int64                                `asn1:"-" json:"-"`
	extPresent       []bool                               `asn1:"-" json:"-"`
	extData          [][]byte                             `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                    `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding               `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// UERadioCapabilityIDMappingRequest represents the ASN.1 type UERadioCapabilityIDMappingRequest (SEQUENCE).
type UERadioCapabilityIDMappingRequest struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s12.UERadioCapabilityIDMappingRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                             `asn1:"-" json:"-"`
	extCount         int64                                            `asn1:"-" json:"-"`
	extPresent       []bool                                           `asn1:"-" json:"-"`
	extData          [][]byte                                         `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                           `asn1:"-" json:"-"`
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
	ProtocolIEs      s23.UERadioCapabilityIDMappingResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                              `asn1:"-" json:"-"`
	extCount         int64                                             `asn1:"-" json:"-"`
	extPresent       []bool                                            `asn1:"-" json:"-"`
	extData          [][]byte                                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                            `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes UEContextModificationResponse to APER format.
func (v *UEContextModificationResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEContextModificationResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s23.BridgeUEContextModificationResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEContextModificationResponse from APER format.
func (v *UEContextModificationResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEContextModificationResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEContextModificationResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationResponse")
	}
	bb.EnterComponent("UEContextModificationResponse")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEContextModificationResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UEContextModificationResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextModificationResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s23.UEContextModificationResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s23.UEContextModificationResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s23.BridgeUEContextModificationResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UEContextModificationFailure to APER format.
func (v *UEContextModificationFailure) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEContextModificationFailure) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s23.BridgeUEContextModificationFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEContextModificationFailure from APER format.
func (v *UEContextModificationFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEContextModificationFailure with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEContextModificationFailure) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationFailure")
	}
	bb.EnterComponent("UEContextModificationFailure")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationFailure")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEContextModificationFailure")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationFailure")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UEContextModificationFailure) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextModificationFailure{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s23.UEContextModificationFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s23.UEContextModificationFailureIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s23.BridgeUEContextModificationFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UERadioCapabilityMatchRequest to APER format.
func (v *UERadioCapabilityMatchRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UERadioCapabilityMatchRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s12.BridgeUERadioCapabilityMatchRequestIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UERadioCapabilityMatchRequest from APER format.
func (v *UERadioCapabilityMatchRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UERadioCapabilityMatchRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UERadioCapabilityMatchRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityMatchRequest")
	}
	bb.EnterComponent("UERadioCapabilityMatchRequest")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityMatchRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "UERadioCapabilityMatchRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityMatchRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UERadioCapabilityMatchRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UERadioCapabilityMatchRequest{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s12.UERadioCapabilityMatchRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s12.UERadioCapabilityMatchRequestIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s12.BridgeUERadioCapabilityMatchRequestIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UERadioCapabilityMatchResponse to APER format.
func (v *UERadioCapabilityMatchResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UERadioCapabilityMatchResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s24.BridgeUERadioCapabilityMatchResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UERadioCapabilityMatchResponse from APER format.
func (v *UERadioCapabilityMatchResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UERadioCapabilityMatchResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UERadioCapabilityMatchResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponse")
	}
	bb.EnterComponent("UERadioCapabilityMatchResponse")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "UERadioCapabilityMatchResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UERadioCapabilityMatchResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UERadioCapabilityMatchResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s24.UERadioCapabilityMatchResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s24.UERadioCapabilityMatchResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s24.BridgeUERadioCapabilityMatchResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes Reset to APER format.
func (v *Reset) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *Reset) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes Reset from APER format.
func (v *Reset) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes Reset with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *Reset) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "Reset")
	}
	bb.EnterComponent("Reset")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Reset")
	}
	padding, err := aper.CaptureFinalBits(bb, "Reset")
	if err != nil {
		return runtime.WrapDecodePath(err, "Reset")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *Reset) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = Reset{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(ResetIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ResetIEField
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

// MarshalAPER encodes UECapabilityInfoIndication to APER format.
func (v *UECapabilityInfoIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UECapabilityInfoIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s12.BridgeUECapabilityInfoIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UECapabilityInfoIndication from APER format.
func (v *UECapabilityInfoIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UECapabilityInfoIndication with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UECapabilityInfoIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UECapabilityInfoIndication")
	}
	bb.EnterComponent("UECapabilityInfoIndication")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UECapabilityInfoIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "UECapabilityInfoIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "UECapabilityInfoIndication")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UECapabilityInfoIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UECapabilityInfoIndication{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s12.UECapabilityInfoIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s12.UECapabilityInfoIndicationIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s12.BridgeUECapabilityInfoIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UEContextModificationIndication to APER format.
func (v *UEContextModificationIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEContextModificationIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s21.BridgeUEContextModificationIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEContextModificationIndication from APER format.
func (v *UEContextModificationIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEContextModificationIndication with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEContextModificationIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationIndication")
	}
	bb.EnterComponent("UEContextModificationIndication")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEContextModificationIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationIndication")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UEContextModificationIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextModificationIndication{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s21.UEContextModificationIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s21.UEContextModificationIndicationIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s21.BridgeUEContextModificationIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UEContextModificationConfirm to APER format.
func (v *UEContextModificationConfirm) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEContextModificationConfirm) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s23.BridgeUEContextModificationConfirmIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEContextModificationConfirm from APER format.
func (v *UEContextModificationConfirm) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEContextModificationConfirm with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEContextModificationConfirm) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationConfirm")
	}
	bb.EnterComponent("UEContextModificationConfirm")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationConfirm")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEContextModificationConfirm")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEContextModificationConfirm")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UEContextModificationConfirm) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextModificationConfirm{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s23.UEContextModificationConfirmIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s23.UEContextModificationConfirmIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s23.BridgeUEContextModificationConfirmIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UEContextSuspendResponse to APER format.
func (v *UEContextSuspendResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEContextSuspendResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s28.BridgeUEContextSuspendResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEContextSuspendResponse from APER format.
func (v *UEContextSuspendResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEContextSuspendResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEContextSuspendResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEContextSuspendResponse")
	}
	bb.EnterComponent("UEContextSuspendResponse")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextSuspendResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEContextSuspendResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEContextSuspendResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UEContextSuspendResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextSuspendResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s28.UEContextSuspendResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s28.UEContextSuspendResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s28.BridgeUEContextSuspendResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UEContextResumeFailure to APER format.
func (v *UEContextResumeFailure) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEContextResumeFailure) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s23.BridgeUEContextResumeFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEContextResumeFailure from APER format.
func (v *UEContextResumeFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEContextResumeFailure with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEContextResumeFailure) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEContextResumeFailure")
	}
	bb.EnterComponent("UEContextResumeFailure")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextResumeFailure")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEContextResumeFailure")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEContextResumeFailure")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UEContextResumeFailure) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextResumeFailure{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s23.UEContextResumeFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s23.UEContextResumeFailureIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s23.BridgeUEContextResumeFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UEInformationTransfer to APER format.
func (v *UEInformationTransfer) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEInformationTransfer) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s31.BridgeUEInformationTransferIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEInformationTransfer from APER format.
func (v *UEInformationTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEInformationTransfer with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEInformationTransfer) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEInformationTransfer")
	}
	bb.EnterComponent("UEInformationTransfer")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEInformationTransfer")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEInformationTransfer")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEInformationTransfer")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UEInformationTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEInformationTransfer{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s31.UEInformationTransferIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s31.UEInformationTransferIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s31.BridgeUEInformationTransferIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UERadioCapabilityIDMappingRequest to APER format.
func (v *UERadioCapabilityIDMappingRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UERadioCapabilityIDMappingRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s12.BridgeUERadioCapabilityIDMappingRequestIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UERadioCapabilityIDMappingRequest from APER format.
func (v *UERadioCapabilityIDMappingRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UERadioCapabilityIDMappingRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UERadioCapabilityIDMappingRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingRequest")
	}
	bb.EnterComponent("UERadioCapabilityIDMappingRequest")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "UERadioCapabilityIDMappingRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UERadioCapabilityIDMappingRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UERadioCapabilityIDMappingRequest{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s12.UERadioCapabilityIDMappingRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s12.UERadioCapabilityIDMappingRequestIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s12.BridgeUERadioCapabilityIDMappingRequestIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes UERadioCapabilityIDMappingResponse to APER format.
func (v *UERadioCapabilityIDMappingResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UERadioCapabilityIDMappingResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s23.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UERadioCapabilityIDMappingResponse from APER format.
func (v *UERadioCapabilityIDMappingResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UERadioCapabilityIDMappingResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UERadioCapabilityIDMappingResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponse")
	}
	bb.EnterComponent("UERadioCapabilityIDMappingResponse")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "UERadioCapabilityIDMappingResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UERadioCapabilityIDMappingResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
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
	v.ProtocolIEs = make(s23.UERadioCapabilityIDMappingResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s23.UERadioCapabilityIDMappingResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s23.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *Reset) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "Reset", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "Reset", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v Reset) WithoutReplay() Reset {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero Reset
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UECapabilityInfoIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UECapabilityInfoIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UECapabilityInfoIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UECapabilityInfoIndication) WithoutReplay() UECapabilityInfoIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UECapabilityInfoIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEContextModificationConfirm) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextModificationConfirm", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEContextModificationConfirm", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEContextModificationConfirm) WithoutReplay() UEContextModificationConfirm {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEContextModificationConfirm
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEContextModificationFailure) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextModificationFailure", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEContextModificationFailure", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEContextModificationFailure) WithoutReplay() UEContextModificationFailure {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEContextModificationFailure
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEContextModificationIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextModificationIndication", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEContextModificationIndication", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEContextModificationIndication) WithoutReplay() UEContextModificationIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEContextModificationIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEContextModificationResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextModificationResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEContextModificationResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEContextModificationResponse) WithoutReplay() UEContextModificationResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEContextModificationResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEContextResumeFailure) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextResumeFailure", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEContextResumeFailure", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEContextResumeFailure) WithoutReplay() UEContextResumeFailure {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEContextResumeFailure
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEContextSuspendResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextSuspendResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEContextSuspendResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEContextSuspendResponse) WithoutReplay() UEContextSuspendResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEContextSuspendResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UEInformationTransfer) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEInformationTransfer", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEInformationTransfer", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEInformationTransfer) WithoutReplay() UEInformationTransfer {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEInformationTransfer
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UERadioCapabilityIDMappingRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UERadioCapabilityIDMappingRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UERadioCapabilityIDMappingRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UERadioCapabilityIDMappingRequest) WithoutReplay() UERadioCapabilityIDMappingRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UERadioCapabilityIDMappingRequest
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
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UERadioCapabilityIDMappingResponse", v.receivedLocation, v.perPadding)
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
func (v *UERadioCapabilityMatchRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UERadioCapabilityMatchRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UERadioCapabilityMatchRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UERadioCapabilityMatchRequest) WithoutReplay() UERadioCapabilityMatchRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UERadioCapabilityMatchRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UERadioCapabilityMatchResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UERadioCapabilityMatchResponse", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UERadioCapabilityMatchResponse", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UERadioCapabilityMatchResponse) WithoutReplay() UERadioCapabilityMatchResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UERadioCapabilityMatchResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *Reset) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *Reset) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("Reset.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("Reset.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *Reset) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("Reset.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("Reset.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UECapabilityInfoIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UECapabilityInfoIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UECapabilityInfoIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UECapabilityInfoIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UECapabilityInfoIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UECapabilityInfoIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UECapabilityInfoIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEContextModificationConfirm) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEContextModificationConfirm) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextModificationConfirm.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextModificationConfirm.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEContextModificationConfirm) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextModificationConfirm.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextModificationConfirm.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEContextModificationFailure) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEContextModificationFailure) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextModificationFailure.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextModificationFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEContextModificationFailure) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextModificationFailure.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextModificationFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEContextModificationIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEContextModificationIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextModificationIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextModificationIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEContextModificationIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextModificationIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextModificationIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEContextModificationResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEContextModificationResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextModificationResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextModificationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEContextModificationResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextModificationResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextModificationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEContextResumeFailure) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEContextResumeFailure) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextResumeFailure.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextResumeFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEContextResumeFailure) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextResumeFailure.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextResumeFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEContextSuspendResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEContextSuspendResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextSuspendResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextSuspendResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEContextSuspendResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextSuspendResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextSuspendResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UEInformationTransfer) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEInformationTransfer) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEInformationTransfer.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEInformationTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEInformationTransfer) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEInformationTransfer.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEInformationTransfer.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UERadioCapabilityIDMappingRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UERadioCapabilityIDMappingRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UERadioCapabilityIDMappingRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UERadioCapabilityIDMappingRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UERadioCapabilityIDMappingRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UERadioCapabilityIDMappingRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UERadioCapabilityIDMappingRequest.Extensions[%d]", index))
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
func (v *UERadioCapabilityMatchRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UERadioCapabilityMatchRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UERadioCapabilityMatchRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UERadioCapabilityMatchRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UERadioCapabilityMatchRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UERadioCapabilityMatchRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UERadioCapabilityMatchRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UERadioCapabilityMatchResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UERadioCapabilityMatchResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UERadioCapabilityMatchResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UERadioCapabilityMatchResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UERadioCapabilityMatchResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UERadioCapabilityMatchResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UERadioCapabilityMatchResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *Reset) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "Reset")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *Reset) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "Reset")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APReset(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "Reset")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "Reset")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *Reset) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "Reset")
}
func (v *Reset) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "Reset")
}
func (v *Reset) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APReset(v, &s)
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
func (v *Reset) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *Reset) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UECapabilityInfoIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UECapabilityInfoIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UECapabilityInfoIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UECapabilityInfoIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUECapabilityInfoIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UECapabilityInfoIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UECapabilityInfoIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UECapabilityInfoIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UECapabilityInfoIndication")
}
func (v *UECapabilityInfoIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UECapabilityInfoIndication")
}
func (v *UECapabilityInfoIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUECapabilityInfoIndication(v, &s)
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
func (v *UECapabilityInfoIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UECapabilityInfoIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEContextModificationConfirm) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEContextModificationConfirm")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEContextModificationConfirm) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEContextModificationConfirm")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEContextModificationConfirm(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEContextModificationConfirm")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEContextModificationConfirm")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEContextModificationConfirm) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEContextModificationConfirm")
}
func (v *UEContextModificationConfirm) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEContextModificationConfirm")
}
func (v *UEContextModificationConfirm) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEContextModificationConfirm(v, &s)
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
func (v *UEContextModificationConfirm) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEContextModificationConfirm) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEContextModificationFailure) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEContextModificationFailure")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEContextModificationFailure) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEContextModificationFailure")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEContextModificationFailure(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEContextModificationFailure")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEContextModificationFailure")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEContextModificationFailure) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEContextModificationFailure")
}
func (v *UEContextModificationFailure) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEContextModificationFailure")
}
func (v *UEContextModificationFailure) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEContextModificationFailure(v, &s)
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
func (v *UEContextModificationFailure) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEContextModificationFailure) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEContextModificationIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEContextModificationIndication")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEContextModificationIndication) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEContextModificationIndication")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEContextModificationIndication(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEContextModificationIndication")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEContextModificationIndication")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEContextModificationIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEContextModificationIndication")
}
func (v *UEContextModificationIndication) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEContextModificationIndication")
}
func (v *UEContextModificationIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEContextModificationIndication(v, &s)
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
func (v *UEContextModificationIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEContextModificationIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEContextModificationResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEContextModificationResponse")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEContextModificationResponse) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEContextModificationResponse")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEContextModificationResponse(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEContextModificationResponse")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEContextModificationResponse")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEContextModificationResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEContextModificationResponse")
}
func (v *UEContextModificationResponse) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEContextModificationResponse")
}
func (v *UEContextModificationResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEContextModificationResponse(v, &s)
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
func (v *UEContextModificationResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEContextModificationResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEContextResumeFailure) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEContextResumeFailure")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEContextResumeFailure) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEContextResumeFailure")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEContextResumeFailure(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEContextResumeFailure")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEContextResumeFailure")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEContextResumeFailure) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEContextResumeFailure")
}
func (v *UEContextResumeFailure) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEContextResumeFailure")
}
func (v *UEContextResumeFailure) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEContextResumeFailure(v, &s)
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
func (v *UEContextResumeFailure) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEContextResumeFailure) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEContextSuspendResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEContextSuspendResponse")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEContextSuspendResponse) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEContextSuspendResponse")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEContextSuspendResponse(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEContextSuspendResponse")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEContextSuspendResponse")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEContextSuspendResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEContextSuspendResponse")
}
func (v *UEContextSuspendResponse) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEContextSuspendResponse")
}
func (v *UEContextSuspendResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEContextSuspendResponse(v, &s)
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
func (v *UEContextSuspendResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEContextSuspendResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEInformationTransfer) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEInformationTransfer")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEInformationTransfer) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEInformationTransfer")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEInformationTransfer(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEInformationTransfer")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEInformationTransfer")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEInformationTransfer) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEInformationTransfer")
}
func (v *UEInformationTransfer) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEInformationTransfer")
}
func (v *UEInformationTransfer) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEInformationTransfer(v, &s)
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
func (v *UEInformationTransfer) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEInformationTransfer) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UERadioCapabilityIDMappingRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UERadioCapabilityIDMappingRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UERadioCapabilityIDMappingRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUERadioCapabilityIDMappingRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UERadioCapabilityIDMappingRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UERadioCapabilityIDMappingRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
}
func (v *UERadioCapabilityIDMappingRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
}
func (v *UERadioCapabilityIDMappingRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUERadioCapabilityIDMappingRequest(v, &s)
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
func (v *UERadioCapabilityIDMappingRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UERadioCapabilityIDMappingRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UERadioCapabilityIDMappingResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UERadioCapabilityIDMappingResponse) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UERadioCapabilityIDMappingResponse")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUERadioCapabilityIDMappingResponse(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UERadioCapabilityIDMappingResponse")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UERadioCapabilityIDMappingResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
}
func (v *UERadioCapabilityIDMappingResponse) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
}
func (v *UERadioCapabilityIDMappingResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUERadioCapabilityIDMappingResponse(v, &s)
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
func (v *UERadioCapabilityIDMappingResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UERadioCapabilityIDMappingResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UERadioCapabilityMatchRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UERadioCapabilityMatchRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UERadioCapabilityMatchRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UERadioCapabilityMatchRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUERadioCapabilityMatchRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UERadioCapabilityMatchRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UERadioCapabilityMatchRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UERadioCapabilityMatchRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UERadioCapabilityMatchRequest")
}
func (v *UERadioCapabilityMatchRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UERadioCapabilityMatchRequest")
}
func (v *UERadioCapabilityMatchRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUERadioCapabilityMatchRequest(v, &s)
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
func (v *UERadioCapabilityMatchRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UERadioCapabilityMatchRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UERadioCapabilityMatchResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UERadioCapabilityMatchResponse")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UERadioCapabilityMatchResponse) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UERadioCapabilityMatchResponse")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUERadioCapabilityMatchResponse(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UERadioCapabilityMatchResponse")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UERadioCapabilityMatchResponse")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UERadioCapabilityMatchResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UERadioCapabilityMatchResponse")
}
func (v *UERadioCapabilityMatchResponse) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UERadioCapabilityMatchResponse")
}
func (v *UERadioCapabilityMatchResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUERadioCapabilityMatchResponse(v, &s)
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
func (v *UERadioCapabilityMatchResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UERadioCapabilityMatchResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *Reset) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "Reset")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded Reset
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APReset(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = Reset{}
		return report, aper.OperationError(err, "Reset")
	}
	*v = decoded
	return report, aper.OperationError(nil, "Reset")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UECapabilityInfoIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UECapabilityInfoIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UECapabilityInfoIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUECapabilityInfoIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UECapabilityInfoIndication{}
		return report, aper.OperationError(err, "UECapabilityInfoIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UECapabilityInfoIndication")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEContextModificationConfirm) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEContextModificationConfirm")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEContextModificationConfirm
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEContextModificationConfirm(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEContextModificationConfirm{}
		return report, aper.OperationError(err, "UEContextModificationConfirm")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEContextModificationConfirm")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEContextModificationFailure) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEContextModificationFailure")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEContextModificationFailure
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEContextModificationFailure(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEContextModificationFailure{}
		return report, aper.OperationError(err, "UEContextModificationFailure")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEContextModificationFailure")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEContextModificationIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEContextModificationIndication")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEContextModificationIndication
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEContextModificationIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEContextModificationIndication{}
		return report, aper.OperationError(err, "UEContextModificationIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEContextModificationIndication")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEContextModificationResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEContextModificationResponse")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEContextModificationResponse
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEContextModificationResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEContextModificationResponse{}
		return report, aper.OperationError(err, "UEContextModificationResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEContextModificationResponse")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEContextResumeFailure) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEContextResumeFailure")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEContextResumeFailure
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEContextResumeFailure(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEContextResumeFailure{}
		return report, aper.OperationError(err, "UEContextResumeFailure")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEContextResumeFailure")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEContextSuspendResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEContextSuspendResponse")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEContextSuspendResponse
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEContextSuspendResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEContextSuspendResponse{}
		return report, aper.OperationError(err, "UEContextSuspendResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEContextSuspendResponse")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UEInformationTransfer) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEInformationTransfer")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEInformationTransfer
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEInformationTransfer(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEInformationTransfer{}
		return report, aper.OperationError(err, "UEInformationTransfer")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEInformationTransfer")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UERadioCapabilityIDMappingRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UERadioCapabilityIDMappingRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UERadioCapabilityIDMappingRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUERadioCapabilityIDMappingRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UERadioCapabilityIDMappingRequest{}
		return report, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UERadioCapabilityIDMappingRequest")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UERadioCapabilityIDMappingResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UERadioCapabilityIDMappingResponse")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UERadioCapabilityIDMappingResponse
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUERadioCapabilityIDMappingResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UERadioCapabilityIDMappingResponse{}
		return report, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UERadioCapabilityIDMappingResponse")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UERadioCapabilityMatchRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UERadioCapabilityMatchRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UERadioCapabilityMatchRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUERadioCapabilityMatchRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UERadioCapabilityMatchRequest{}
		return report, aper.OperationError(err, "UERadioCapabilityMatchRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UERadioCapabilityMatchRequest")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UERadioCapabilityMatchResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UERadioCapabilityMatchResponse")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UERadioCapabilityMatchResponse
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUERadioCapabilityMatchResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UERadioCapabilityMatchResponse{}
		return report, aper.OperationError(err, "UERadioCapabilityMatchResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UERadioCapabilityMatchResponse")
}

// NewResetTypeS1Interface constructs a checked complete value.
func NewResetTypeS1Interface(v s00.ResetAll, options ...aper.BuildOption) (s35.ResetType, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s35.ResetType{}, aper.OperationError(err, "ResetTypeS1Interface")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s35.ResetType{}, aper.OperationError(err, "ResetTypeS1Interface")
	}
	value := BridgeNewResetTypeS1InterfaceLegacy(v)
	if _, err := s35.BridgeResetTypeMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s35.ResetType{}, aper.OperationError(err, "ResetTypeS1Interface")
	}
	return value, aper.OperationError(nil, "ResetTypeS1Interface")
}

// NewResetTypePartOfS1Interface constructs a checked complete value.
func NewResetTypePartOfS1Interface(v s35.UEAssociatedLogicalS1ConnectionListRes, options ...aper.BuildOption) (s35.ResetType, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s35.ResetType{}, aper.OperationError(err, "ResetTypePartOfS1Interface")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return s35.ResetType{}, aper.OperationError(err, "ResetTypePartOfS1Interface")
	}
	value := BridgeNewResetTypePartOfS1InterfaceLegacy(v)
	if _, err := s35.BridgeResetTypeMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s35.ResetType{}, aper.OperationError(err, "ResetTypePartOfS1Interface")
	}
	return value, aper.OperationError(nil, "ResetTypePartOfS1Interface")
}

// UnsuccessfulOutcome represents the ASN.1 type UnsuccessfulOutcome (SEQUENCE).
type UnsuccessfulOutcome struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProcedureCode    s00.ProcedureCode    `asn1:"tag:0,context,implicit"`
	Criticality      s00.Criticality      `asn1:"tag:1,context,implicit"`
	Value            UnsuccessfulValue    `asn1:"tag:2,context,explicit" asn1c:"raw-preserve"`
	perPadding       aper.CompletePadding `asn1:"-" json:"-"`
}

// MarshalAPER encodes UnsuccessfulOutcome to APER format.
func (v *UnsuccessfulOutcome) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *UnsuccessfulOutcome) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		return runtime.WrapDecodePath(fmt.Errorf("%w: procedure code %d does not match its value selector", aper.ErrInvalidValue, v.ProcedureCode), "UnsuccessfulOutcome.ProcedureCode")
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

// UnmarshalAPER decodes UnsuccessfulOutcome from APER format.
func (v *UnsuccessfulOutcome) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UnsuccessfulOutcome with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UnsuccessfulOutcome) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UnsuccessfulOutcome")
	}
	bb.EnterComponent("UnsuccessfulOutcome")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UnsuccessfulOutcome")
	}
	padding, err := aper.CaptureFinalBits(bb, "UnsuccessfulOutcome")
	if err != nil {
		return runtime.WrapDecodePath(err, "UnsuccessfulOutcome")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *UnsuccessfulOutcome) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UnsuccessfulOutcome{}
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
	opaque_value, err := aper.DecodeOpaqueOpenTypeAligned(bb, s00.UnsuccessfulReason(v.ProcedureCode), aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.2", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Descriptions", Assignment: "Unsuccessful"}})
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	opaque_value = opaque_value.WithPath("UnsuccessfulOutcome.Value")
	decoded_value, err := BridgeDecodeUnsuccessfulValue(v.ProcedureCode, opaque_value)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	v.Value = decoded_value
	bb.LeaveComponent(toleranceMark_value)
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UnsuccessfulOutcome) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UnsuccessfulOutcome", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UnsuccessfulOutcome", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UnsuccessfulOutcome) WithoutReplay() UnsuccessfulOutcome {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UnsuccessfulOutcome
	v.perPadding = zero.perPadding
	return v
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *UnsuccessfulOutcome) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UnsuccessfulOutcome")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UnsuccessfulOutcome) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UnsuccessfulOutcome")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUnsuccessfulOutcome(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UnsuccessfulOutcome")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UnsuccessfulOutcome")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UnsuccessfulOutcome) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UnsuccessfulOutcome")
}
func (v *UnsuccessfulOutcome) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UnsuccessfulOutcome")
}
func (v *UnsuccessfulOutcome) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUnsuccessfulOutcome(v, &s)
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
func (v *UnsuccessfulOutcome) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UnsuccessfulOutcome) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UnsuccessfulOutcome) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UnsuccessfulOutcome")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UnsuccessfulOutcome
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUnsuccessfulOutcome(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UnsuccessfulOutcome{}
		return report, aper.OperationError(err, "UnsuccessfulOutcome")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UnsuccessfulOutcome")
}

type ResetIEValue struct {
	id           s00.ProtocolIEID
	received     aper.WireSpan
	replay       aper.Snapshot
	opaque       aper.OpaqueOpenType
	isOpaque     bool
	rowCause     *s14.Cause
	rowResetType *s35.ResetType
}

func (v ResetIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(2):
		return v.rowCause != nil
	case s00.ProtocolIEID(92):
		return v.rowResetType != nil
	}
	return false
}

// Opaque returns the retained opaque open value of ResetIEValue and reports whether the opaque alternative is selected.
func (v *ResetIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (ResetIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ResetIEs"}}
}
func (ResetIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(92):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
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
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}

// AsCause returns the selected Cause value of ResetIEValue and reports whether that alternative is active.
func (v *ResetIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}

// AsResetType returns the selected ResetType value of ResetIEValue and reports whether that alternative is active.
func (v *ResetIEValue) AsResetType() (*s35.ResetType, bool) {
	if v == nil || v.id != s00.ProtocolIEID(92) || v.rowResetType == nil {
		return nil, false
	}
	return v.rowResetType, true
}
func (v ResetIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ResetIEValue, error) {
	out := ResetIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(2):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s14.Cause
		child := scope
		if err := s14.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "Cause:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*s14.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*s14.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(s14.BridgeCauseFieldReceivedBytes(&value))
		*s14.BridgeCauseFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowCause = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(92):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s35.ResetType
		child := scope
		if err := s35.BridgeResetTypeMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "ResetType:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ResetType")
		if err != nil {
			return out, err
		}
		*s35.BridgeResetTypeFieldPerPadding(&value) = padding.Padding()
		*s35.BridgeResetTypeFieldReceived(&value) = true
		raw.RetainContents(s35.BridgeResetTypeFieldReceivedBytes(&value))
		*s35.BridgeResetTypeFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowResetType = &value
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
func (v ResetIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v ResetIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(2):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "ResetIEs.id-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(92):
		if v.rowResetType == nil {
			return nil, fmt.Errorf("%s missing value", "ResetIEs.id-ResetType:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s35.BridgeResetTypeMethodMarshalAPERBudget(v.rowResetType, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ResetIEValue:", v.id)
	}
}

type ResetIETable struct{}

func ResetIEs() ResetIETable { return ResetIETable{} }

// ID returns the ASN.1 object-set identity of ResetIETable.
func (ResetIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ResetIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by ResetIETable.
func (ResetIETable) Table() s00.ResetIEValueIETable {
	return func() s00.ResetIEValueIETable {
		sealed := s00.ResetIEValueIETable{}
		*s00.BridgeResetIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (ResetIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: ResetIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ResetIEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of ResetIETable.
func (t ResetIETable) Cause() ResetCauseIEBinding {
	return ResetCauseIEBinding{info: t.infoCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cause")
			var zero ResetIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding ResetIEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ResetIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
		}
		*s14.BridgeCauseValueCodecFieldCapture(&sealed) = func(v s14.Cause, options aper.DecodeState) (s14.Cause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s14.BridgeCaptureS1APCause(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s14.BridgeCauseValueCodecFieldCompare(&sealed) = func(v s14.Cause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s14.BridgeCompareS1APCause(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s14.Cause) ResetIEValue { return ResetIEValue{id: s00.ProtocolIEID(2), rowCause: &value} }, get: func(value *ResetIEValue) (*s14.Cause, bool) { return value.AsCause() }}
}
func (ResetIETable) infoResetType() s00.FieldInfo {
	return s00.FieldInfo{Table: ResetIEs().ID(), ID: s00.ProtocolIEID(92), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ResetType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "ResetIEs", Row: "id-ResetType"}}}
}

// ResetType returns the typed binding for the ResetType row of ResetIETable.
func (t ResetIETable) ResetType() ResetResetTypeIEBinding {
	return ResetResetTypeIEBinding{info: t.infoResetType(), codec: ResetTypeValueCodec{path: "ResetType",
		decode: func(data []byte, options aper.DecodeState) (s35.ResetType, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s35.ResetType
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ResetType")
			var zero ResetIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(92), raw)
			if err != nil {
				var empty s35.ResetType
				return empty, err
			}
			value, ok := decoded.AsResetType()
			if !ok {
				var empty s35.ResetType
				return empty, fmt.Errorf("binding ResetIEs.id-ResetType: no selected value")
			}
			return *value, nil
		},
		encode: func(value s35.ResetType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ResetIEValue{id: s00.ProtocolIEID(92), rowResetType: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s35.ResetType, options aper.DecodeState) (s35.ResetType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s35.BridgeCaptureS1APResetType(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v s35.ResetType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s35.BridgeCompareS1APResetType(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ResetType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s35.ResetType) ResetIEValue {
		return ResetIEValue{id: s00.ProtocolIEID(92), rowResetType: &value}
	}, get: func(value *ResetIEValue) (*s35.ResetType, bool) { return value.AsResetType() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in ResetIETable.
func (t ResetIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ResetIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ResetIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(2):
		return ResetIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(92):
		return ResetIEField{}, aper.OperationError(fmt.Errorf("known IE id-ResetType requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ResetIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ResetIEField{}, aper.OperationError(err, "Opaque")
		}
		return ResetIEField{Id: id, Criticality: criticality, Value: ResetIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// ResetTypeCodec binds the complete APER value type.
func ResetTypeCodec() ResetTypeValueCodec { return ResetIEs().ResetType().Codec() }

// UnsuccessfulOutcomeCodec binds the complete source value type.
func UnsuccessfulOutcomeCodec() UnsuccessfulOutcomeValueCodec {
	return UnsuccessfulOutcomeValueCodec{path: "UnsuccessfulOutcome", decode: func(data []byte, options aper.DecodeState) (UnsuccessfulOutcome, error) {
		var value UnsuccessfulOutcome
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return UnsuccessfulOutcome{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value UnsuccessfulOutcome, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v UnsuccessfulOutcome, options aper.DecodeState) (UnsuccessfulOutcome, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APUnsuccessfulOutcome(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v UnsuccessfulOutcome, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APUnsuccessfulOutcome(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UnsuccessfulOutcome"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}
func BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldCapture(v *ENBConfigurationUpdateFailureUnsuccessfulBinding) *func(s24.ENBConfigurationUpdateFailure, aper.DecodeState) (s24.ENBConfigurationUpdateFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldCompare(v *ENBConfigurationUpdateFailureUnsuccessfulBinding) *func(s24.ENBConfigurationUpdateFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldContext(v *ENBConfigurationUpdateFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldDecode(v *ENBConfigurationUpdateFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s24.ENBConfigurationUpdateFailure, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldEncode(v *ENBConfigurationUpdateFailureUnsuccessfulBinding) *func(*s24.ENBConfigurationUpdateFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldInfo(v *ENBConfigurationUpdateFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldInject(v *ENBConfigurationUpdateFailureUnsuccessfulBinding) *func(s24.ENBConfigurationUpdateFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldValidate(v *ENBConfigurationUpdateFailureUnsuccessfulBinding) *func(*s24.ENBConfigurationUpdateFailure, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeHandoverFailureUnsuccessfulBindingFieldCapture(v *HandoverFailureUnsuccessfulBinding) *func(s25.HandoverFailure, aper.DecodeState) (s25.HandoverFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverFailureUnsuccessfulBindingFieldCompare(v *HandoverFailureUnsuccessfulBinding) *func(s25.HandoverFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverFailureUnsuccessfulBindingFieldContext(v *HandoverFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverFailureUnsuccessfulBindingFieldDecode(v *HandoverFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s25.HandoverFailure, error) {
	return &v.decode
}
func BridgeHandoverFailureUnsuccessfulBindingFieldEncode(v *HandoverFailureUnsuccessfulBinding) *func(*s25.HandoverFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverFailureUnsuccessfulBindingFieldInfo(v *HandoverFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeHandoverFailureUnsuccessfulBindingFieldInject(v *HandoverFailureUnsuccessfulBinding) *func(s25.HandoverFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeHandoverFailureUnsuccessfulBindingFieldValidate(v *HandoverFailureUnsuccessfulBinding) *func(*s25.HandoverFailure, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeHandoverPreparationFailureUnsuccessfulBindingFieldCapture(v *HandoverPreparationFailureUnsuccessfulBinding) *func(s25.HandoverPreparationFailure, aper.DecodeState) (s25.HandoverPreparationFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverPreparationFailureUnsuccessfulBindingFieldCompare(v *HandoverPreparationFailureUnsuccessfulBinding) *func(s25.HandoverPreparationFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverPreparationFailureUnsuccessfulBindingFieldContext(v *HandoverPreparationFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverPreparationFailureUnsuccessfulBindingFieldDecode(v *HandoverPreparationFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s25.HandoverPreparationFailure, error) {
	return &v.decode
}
func BridgeHandoverPreparationFailureUnsuccessfulBindingFieldEncode(v *HandoverPreparationFailureUnsuccessfulBinding) *func(*s25.HandoverPreparationFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverPreparationFailureUnsuccessfulBindingFieldInfo(v *HandoverPreparationFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeHandoverPreparationFailureUnsuccessfulBindingFieldInject(v *HandoverPreparationFailureUnsuccessfulBinding) *func(s25.HandoverPreparationFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeHandoverPreparationFailureUnsuccessfulBindingFieldValidate(v *HandoverPreparationFailureUnsuccessfulBinding) *func(*s25.HandoverPreparationFailure, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeInitialContextSetupFailureUnsuccessfulBindingFieldCapture(v *InitialContextSetupFailureUnsuccessfulBinding) *func(s25.InitialContextSetupFailure, aper.DecodeState) (s25.InitialContextSetupFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupFailureUnsuccessfulBindingFieldCompare(v *InitialContextSetupFailureUnsuccessfulBinding) *func(s25.InitialContextSetupFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupFailureUnsuccessfulBindingFieldContext(v *InitialContextSetupFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupFailureUnsuccessfulBindingFieldDecode(v *InitialContextSetupFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s25.InitialContextSetupFailure, error) {
	return &v.decode
}
func BridgeInitialContextSetupFailureUnsuccessfulBindingFieldEncode(v *InitialContextSetupFailureUnsuccessfulBinding) *func(*s25.InitialContextSetupFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupFailureUnsuccessfulBindingFieldInfo(v *InitialContextSetupFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeInitialContextSetupFailureUnsuccessfulBindingFieldInject(v *InitialContextSetupFailureUnsuccessfulBinding) *func(s25.InitialContextSetupFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeInitialContextSetupFailureUnsuccessfulBindingFieldValidate(v *InitialContextSetupFailureUnsuccessfulBinding) *func(*s25.InitialContextSetupFailure, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldCapture(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *func(s25.MMEConfigurationUpdateFailure, aper.DecodeState) (s25.MMEConfigurationUpdateFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldCompare(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *func(s25.MMEConfigurationUpdateFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldContext(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldDecode(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s25.MMEConfigurationUpdateFailure, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldEncode(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *func(*s25.MMEConfigurationUpdateFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldInfo(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldInject(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *func(s25.MMEConfigurationUpdateFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldValidate(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *func(*s25.MMEConfigurationUpdateFailure, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgePathSwitchRequestFailureUnsuccessfulBindingFieldCapture(v *PathSwitchRequestFailureUnsuccessfulBinding) *func(s26.PathSwitchRequestFailure, aper.DecodeState) (s26.PathSwitchRequestFailure, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestFailureUnsuccessfulBindingFieldCompare(v *PathSwitchRequestFailureUnsuccessfulBinding) *func(s26.PathSwitchRequestFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestFailureUnsuccessfulBindingFieldContext(v *PathSwitchRequestFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestFailureUnsuccessfulBindingFieldDecode(v *PathSwitchRequestFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s26.PathSwitchRequestFailure, error) {
	return &v.decode
}
func BridgePathSwitchRequestFailureUnsuccessfulBindingFieldEncode(v *PathSwitchRequestFailureUnsuccessfulBinding) *func(*s26.PathSwitchRequestFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestFailureUnsuccessfulBindingFieldInfo(v *PathSwitchRequestFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgePathSwitchRequestFailureUnsuccessfulBindingFieldInject(v *PathSwitchRequestFailureUnsuccessfulBinding) *func(s26.PathSwitchRequestFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgePathSwitchRequestFailureUnsuccessfulBindingFieldValidate(v *PathSwitchRequestFailureUnsuccessfulBinding) *func(*s26.PathSwitchRequestFailure, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeResetAPERValueFieldContext(v *ResetAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeResetAPERValueFieldReceived(v *ResetAPERValue) *aper.WireSpan         { return &v.received }
func BridgeResetAPERValueFieldReplay(v *ResetAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeResetAPERValueFieldWithoutReplay(v *ResetAPERValue) *bool             { return &v.withoutReplay }
func BridgeResetCauseIEBindingFieldCodec(v *ResetCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeResetCauseIEBindingFieldGet(v *ResetCauseIEBinding) *func(*ResetIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeResetCauseIEBindingFieldInfo(v *ResetCauseIEBinding) *s00.FieldInfo { return &v.info }
func BridgeResetCauseIEBindingFieldInject(v *ResetCauseIEBinding) *func(s14.Cause) ResetIEValue {
	return &v.inject
}
func BridgeResetFieldExtCount(v *Reset) *int64                       { return &v.extCount }
func BridgeResetFieldExtData(v *Reset) *[][]byte                     { return &v.extData }
func BridgeResetFieldExtOrigin(v *Reset) *[]aper.OpaqueOrigin        { return &v.extOrigin }
func BridgeResetFieldExtPresent(v *Reset) *[]bool                    { return &v.extPresent }
func BridgeResetFieldExtWire(v *Reset) *[]aper.WireSpan              { return &v.extWire }
func BridgeResetFieldPerExtPadding(v *Reset) *[]aper.CompletePadding { return &v.perExtPadding }
func BridgeResetFieldPerPadding(v *Reset) *aper.FinalPadding         { return &v.perPadding }
func BridgeResetFieldProtocolIEsIndef(v *Reset) *bool                { return &v.protocolIEsIndef }
func BridgeResetFieldReceived(v *Reset) *bool                        { return &v.received }
func BridgeResetFieldReceivedAbsolute(v *Reset) *bool                { return &v.receivedAbsolute }
func BridgeResetFieldReceivedBytes(v *Reset) *aper.WireSpan          { return &v.receivedBytes }
func BridgeResetFieldReceivedLocation(v *Reset) *aper.Location       { return &v.receivedLocation }
func BridgeResetFieldReplay(v *Reset) *aper.Snapshot                 { return &v.replay }
func BridgeResetFieldStream(v *Reset) *aper.WireSpan                 { return &v.stream }
func BridgeResetFieldWithoutReplay(v *Reset) *bool                   { return &v.withoutReplay }
func BridgeResetIEContainerAPERValueFieldContext(v *ResetIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEContainerAPERValueFieldReceived(v *ResetIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResetIEContainerAPERValueFieldReplay(v *ResetIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResetIEContainerAPERValueFieldWithoutReplay(v *ResetIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResetIEContainerValueCodecFieldCapture(v *ResetIEContainerValueCodec) *func(ResetIEContainer, aper.DecodeState) (ResetIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeResetIEContainerValueCodecFieldCompare(v *ResetIEContainerValueCodec) *func(ResetIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetIEContainerValueCodecFieldContext(v *ResetIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEContainerValueCodecFieldDecode(v *ResetIEContainerValueCodec) *func([]byte, aper.DecodeState) (ResetIEContainer, error) {
	return &v.decode
}
func BridgeResetIEContainerValueCodecFieldEncode(v *ResetIEContainerValueCodec) *func(ResetIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetIEContainerValueCodecFieldPath(v *ResetIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeResetIEContainerValueCodecMethodEncodeBudgetValue(v ResetIEContainerValueCodec, a0 ResetIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetIEContainerValueCodecMethodEncodeChanged(v ResetIEContainerValueCodec, a0 ResetIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResetIEFieldAPERValueFieldContext(v *ResetIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEFieldAPERValueFieldReceived(v *ResetIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResetIEFieldAPERValueFieldReplay(v *ResetIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResetIEFieldAPERValueFieldWithoutReplay(v *ResetIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResetIEFieldFieldReceived(v *ResetIEField) *aper.CompletePadding { return &v.received }
func BridgeResetIEFieldFieldReplay(v *ResetIEField) *aper.Snapshot          { return &v.replay }
func BridgeResetIEFieldFieldStream(v *ResetIEField) *aper.WireSpan          { return &v.stream }
func BridgeResetIEFieldFieldWithoutReplay(v *ResetIEField) *bool            { return &v.withoutReplay }
func BridgeResetIEFieldMethodMarshalAPERTo(v *ResetIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResetIEFieldMethodUnmarshalAPERFrom(v *ResetIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResetIEFieldValueCodecFieldCapture(v *ResetIEFieldValueCodec) *func(ResetIEField, aper.DecodeState) (ResetIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeResetIEFieldValueCodecFieldCompare(v *ResetIEFieldValueCodec) *func(ResetIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetIEFieldValueCodecFieldContext(v *ResetIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEFieldValueCodecFieldDecode(v *ResetIEFieldValueCodec) *func([]byte, aper.DecodeState) (ResetIEField, error) {
	return &v.decode
}
func BridgeResetIEFieldValueCodecFieldEncode(v *ResetIEFieldValueCodec) *func(ResetIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetIEFieldValueCodecFieldPath(v *ResetIEFieldValueCodec) *aper.Path { return &v.path }
func BridgeResetIEFieldValueCodecMethodEncodeBudgetValue(v ResetIEFieldValueCodec, a0 ResetIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetIEFieldValueCodecMethodEncodeChanged(v ResetIEFieldValueCodec, a0 ResetIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResetIETableMethodInfoCause(v ResetIETable) s00.FieldInfo     { return v.infoCause() }
func BridgeResetIETableMethodInfoResetType(v ResetIETable) s00.FieldInfo { return v.infoResetType() }
func BridgeResetIEValueERABIEContainerListAPERValueFieldContext(v *ResetIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEValueERABIEContainerListAPERValueFieldReceived(v *ResetIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResetIEValueERABIEContainerListAPERValueFieldReplay(v *ResetIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResetIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *ResetIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResetIEValueERABIEContainerListValueCodecFieldCapture(v *ResetIEValueERABIEContainerListValueCodec) *func(ResetIEValueERABIEContainerList, aper.DecodeState) (ResetIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeResetIEValueERABIEContainerListValueCodecFieldCompare(v *ResetIEValueERABIEContainerListValueCodec) *func(ResetIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetIEValueERABIEContainerListValueCodecFieldContext(v *ResetIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEValueERABIEContainerListValueCodecFieldDecode(v *ResetIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ResetIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeResetIEValueERABIEContainerListValueCodecFieldEncode(v *ResetIEValueERABIEContainerListValueCodec) *func(ResetIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetIEValueERABIEContainerListValueCodecFieldPath(v *ResetIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeResetIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v ResetIEValueERABIEContainerListValueCodec, a0 ResetIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetIEValueERABIEContainerListValueCodecMethodEncodeChanged(v ResetIEValueERABIEContainerListValueCodec, a0 ResetIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResetIEValueFieldId(v *ResetIEValue) *s00.ProtocolIEID         { return &v.id }
func BridgeResetIEValueFieldIsOpaque(v *ResetIEValue) *bool               { return &v.isOpaque }
func BridgeResetIEValueFieldOpaque(v *ResetIEValue) *aper.OpaqueOpenType  { return &v.opaque }
func BridgeResetIEValueFieldReceived(v *ResetIEValue) *aper.WireSpan      { return &v.received }
func BridgeResetIEValueFieldReplay(v *ResetIEValue) *aper.Snapshot        { return &v.replay }
func BridgeResetIEValueFieldRowCause(v *ResetIEValue) **s14.Cause         { return &v.rowCause }
func BridgeResetIEValueFieldRowResetType(v *ResetIEValue) **s35.ResetType { return &v.rowResetType }
func BridgeResetIEValueMethodCaptureSemantics(v ResetIEValue, a0 aper.SemanticCapture) ResetIEValue {
	return v.captureSemantics(a0)
}
func BridgeResetIEValueMethodCompareSemantics(v ResetIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeResetIEValueMethodDecode(v ResetIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ResetIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeResetIEValueMethodEncode(v ResetIEValue) ([]byte, error) { return v.encode() }
func BridgeResetIEValueMethodEncodeFresh(v ResetIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeResetIEValueMethodMatchesID(v ResetIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeResetIEValueMethodReason(v ResetIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeResetIEValueMethodRule(v ResetIEValue) aper.SourceRule { return v.rule() }
func BridgeResetIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *ResetIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *ResetIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResetIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *ResetIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResetIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *ResetIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResetIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *ResetIEValueProtocolErrorIEContainerListValueCodec) *func(ResetIEValueProtocolErrorIEContainerList, aper.DecodeState) (ResetIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeResetIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *ResetIEValueProtocolErrorIEContainerListValueCodec) *func(ResetIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *ResetIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *ResetIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ResetIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeResetIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *ResetIEValueProtocolErrorIEContainerListValueCodec) *func(ResetIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *ResetIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeResetIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v ResetIEValueProtocolErrorIEContainerListValueCodec, a0 ResetIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v ResetIEValueProtocolErrorIEContainerListValueCodec, a0 ResetIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResetIEValueProtocolIEContainerListAPERValueFieldContext(v *ResetIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEValueProtocolIEContainerListAPERValueFieldReceived(v *ResetIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResetIEValueProtocolIEContainerListAPERValueFieldReplay(v *ResetIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResetIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *ResetIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResetIEValueProtocolIEContainerListValueCodecFieldCapture(v *ResetIEValueProtocolIEContainerListValueCodec) *func(ResetIEValueProtocolIEContainerList, aper.DecodeState) (ResetIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeResetIEValueProtocolIEContainerListValueCodecFieldCompare(v *ResetIEValueProtocolIEContainerListValueCodec) *func(ResetIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetIEValueProtocolIEContainerListValueCodecFieldContext(v *ResetIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetIEValueProtocolIEContainerListValueCodecFieldDecode(v *ResetIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (ResetIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeResetIEValueProtocolIEContainerListValueCodecFieldEncode(v *ResetIEValueProtocolIEContainerListValueCodec) *func(ResetIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetIEValueProtocolIEContainerListValueCodecFieldPath(v *ResetIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeResetIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v ResetIEValueProtocolIEContainerListValueCodec, a0 ResetIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v ResetIEValueProtocolIEContainerListValueCodec, a0 ResetIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResetMethodMarshalAPERBudget(v *Reset, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResetMethodMarshalAPERBudgetValue(v *Reset, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeResetMethodMarshalAPERChanged(v *Reset, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResetMethodMarshalAPERChangedValue(v *Reset, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResetMethodMarshalAPERLegacy(v *Reset) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeResetMethodMarshalAPERNewValue(v *Reset, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeResetMethodMarshalAPERPlanned(v *Reset, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeResetMethodMarshalAPERTo(v *Reset, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResetMethodUnmarshalAPERFrom(v *Reset, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResetMethodUnmarshalAPERLegacy(v *Reset, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResetMethodUnmarshalAPERWithOptions(v *Reset, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResetResetTypeIEBindingFieldCodec(v *ResetResetTypeIEBinding) *ResetTypeValueCodec {
	return &v.codec
}
func BridgeResetResetTypeIEBindingFieldGet(v *ResetResetTypeIEBinding) *func(*ResetIEValue) (*s35.ResetType, bool) {
	return &v.get
}
func BridgeResetResetTypeIEBindingFieldInfo(v *ResetResetTypeIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeResetResetTypeIEBindingFieldInject(v *ResetResetTypeIEBinding) *func(s35.ResetType) ResetIEValue {
	return &v.inject
}
func BridgeResetTypeAPERValueFieldContext(v *ResetTypeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetTypeAPERValueFieldReceived(v *ResetTypeAPERValue) *aper.WireSpan { return &v.received }
func BridgeResetTypeAPERValueFieldReplay(v *ResetTypeAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeResetTypeAPERValueFieldWithoutReplay(v *ResetTypeAPERValue) *bool     { return &v.withoutReplay }
func BridgeResetTypeValueCodecFieldCapture(v *ResetTypeValueCodec) *func(s35.ResetType, aper.DecodeState) (s35.ResetType, aper.Snapshot) {
	return &v.capture
}
func BridgeResetTypeValueCodecFieldCompare(v *ResetTypeValueCodec) *func(s35.ResetType, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetTypeValueCodecFieldContext(v *ResetTypeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetTypeValueCodecFieldDecode(v *ResetTypeValueCodec) *func([]byte, aper.DecodeState) (s35.ResetType, error) {
	return &v.decode
}
func BridgeResetTypeValueCodecFieldEncode(v *ResetTypeValueCodec) *func(s35.ResetType, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetTypeValueCodecFieldPath(v *ResetTypeValueCodec) *aper.Path { return &v.path }
func BridgeResetTypeValueCodecMethodEncodeBudgetValue(v ResetTypeValueCodec, a0 s35.ResetType, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetTypeValueCodecMethodEncodeChanged(v ResetTypeValueCodec, a0 s35.ResetType, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResetValueCodecFieldCapture(v *ResetValueCodec) *func(Reset, aper.DecodeState) (Reset, aper.Snapshot) {
	return &v.capture
}
func BridgeResetValueCodecFieldCompare(v *ResetValueCodec) *func(Reset, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetValueCodecFieldContext(v *ResetValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeResetValueCodecFieldDecode(v *ResetValueCodec) *func([]byte, aper.DecodeState) (Reset, error) {
	return &v.decode
}
func BridgeResetValueCodecFieldEncode(v *ResetValueCodec) *func(Reset, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetValueCodecFieldPath(v *ResetValueCodec) *aper.Path { return &v.path }
func BridgeResetValueCodecMethodEncodeBudgetValue(v ResetValueCodec, a0 Reset, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeResetValueCodecMethodEncodeChanged(v ResetValueCodec, a0 Reset, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldCapture(v *S1RemovalFailureUnsuccessfulBinding) *func(s26.S1RemovalFailure, aper.DecodeState) (s26.S1RemovalFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldCompare(v *S1RemovalFailureUnsuccessfulBinding) *func(s26.S1RemovalFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldContext(v *S1RemovalFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldDecode(v *S1RemovalFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s26.S1RemovalFailure, error) {
	return &v.decode
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldEncode(v *S1RemovalFailureUnsuccessfulBinding) *func(*s26.S1RemovalFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldInfo(v *S1RemovalFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldInject(v *S1RemovalFailureUnsuccessfulBinding) *func(s26.S1RemovalFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldValidate(v *S1RemovalFailureUnsuccessfulBinding) *func(*s26.S1RemovalFailure, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldCapture(v *S1SetupFailureUnsuccessfulBinding) *func(s26.S1SetupFailure, aper.DecodeState) (s26.S1SetupFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldCompare(v *S1SetupFailureUnsuccessfulBinding) *func(s26.S1SetupFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldContext(v *S1SetupFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldDecode(v *S1SetupFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s26.S1SetupFailure, error) {
	return &v.decode
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldEncode(v *S1SetupFailureUnsuccessfulBinding) *func(*s26.S1SetupFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldInfo(v *S1SetupFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldInject(v *S1SetupFailureUnsuccessfulBinding) *func(s26.S1SetupFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldValidate(v *S1SetupFailureUnsuccessfulBinding) *func(*s26.S1SetupFailure, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUECapabilityInfoIndicationAPERValueFieldContext(v *UECapabilityInfoIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUECapabilityInfoIndicationAPERValueFieldReceived(v *UECapabilityInfoIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUECapabilityInfoIndicationAPERValueFieldReplay(v *UECapabilityInfoIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUECapabilityInfoIndicationAPERValueFieldWithoutReplay(v *UECapabilityInfoIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUECapabilityInfoIndicationFieldExtCount(v *UECapabilityInfoIndication) *int64 {
	return &v.extCount
}
func BridgeUECapabilityInfoIndicationFieldExtData(v *UECapabilityInfoIndication) *[][]byte {
	return &v.extData
}
func BridgeUECapabilityInfoIndicationFieldExtOrigin(v *UECapabilityInfoIndication) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUECapabilityInfoIndicationFieldExtPresent(v *UECapabilityInfoIndication) *[]bool {
	return &v.extPresent
}
func BridgeUECapabilityInfoIndicationFieldExtWire(v *UECapabilityInfoIndication) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUECapabilityInfoIndicationFieldPerExtPadding(v *UECapabilityInfoIndication) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUECapabilityInfoIndicationFieldPerPadding(v *UECapabilityInfoIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUECapabilityInfoIndicationFieldProtocolIEsIndef(v *UECapabilityInfoIndication) *bool {
	return &v.protocolIEsIndef
}
func BridgeUECapabilityInfoIndicationFieldReceived(v *UECapabilityInfoIndication) *bool {
	return &v.received
}
func BridgeUECapabilityInfoIndicationFieldReceivedAbsolute(v *UECapabilityInfoIndication) *bool {
	return &v.receivedAbsolute
}
func BridgeUECapabilityInfoIndicationFieldReceivedBytes(v *UECapabilityInfoIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUECapabilityInfoIndicationFieldReceivedLocation(v *UECapabilityInfoIndication) *aper.Location {
	return &v.receivedLocation
}
func BridgeUECapabilityInfoIndicationFieldReplay(v *UECapabilityInfoIndication) *aper.Snapshot {
	return &v.replay
}
func BridgeUECapabilityInfoIndicationFieldStream(v *UECapabilityInfoIndication) *aper.WireSpan {
	return &v.stream
}
func BridgeUECapabilityInfoIndicationFieldWithoutReplay(v *UECapabilityInfoIndication) *bool {
	return &v.withoutReplay
}
func BridgeUECapabilityInfoIndicationMethodMarshalAPERBudget(v *UECapabilityInfoIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUECapabilityInfoIndicationMethodMarshalAPERBudgetValue(v *UECapabilityInfoIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUECapabilityInfoIndicationMethodMarshalAPERChanged(v *UECapabilityInfoIndication, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUECapabilityInfoIndicationMethodMarshalAPERChangedValue(v *UECapabilityInfoIndication, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUECapabilityInfoIndicationMethodMarshalAPERLegacy(v *UECapabilityInfoIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUECapabilityInfoIndicationMethodMarshalAPERNewValue(v *UECapabilityInfoIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUECapabilityInfoIndicationMethodMarshalAPERPlanned(v *UECapabilityInfoIndication, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUECapabilityInfoIndicationMethodMarshalAPERTo(v *UECapabilityInfoIndication, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUECapabilityInfoIndicationMethodUnmarshalAPERFrom(v *UECapabilityInfoIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUECapabilityInfoIndicationMethodUnmarshalAPERLegacy(v *UECapabilityInfoIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUECapabilityInfoIndicationMethodUnmarshalAPERWithOptions(v *UECapabilityInfoIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUECapabilityInfoIndicationValueCodecFieldCapture(v *UECapabilityInfoIndicationValueCodec) *func(UECapabilityInfoIndication, aper.DecodeState) (UECapabilityInfoIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeUECapabilityInfoIndicationValueCodecFieldCompare(v *UECapabilityInfoIndicationValueCodec) *func(UECapabilityInfoIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUECapabilityInfoIndicationValueCodecFieldContext(v *UECapabilityInfoIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUECapabilityInfoIndicationValueCodecFieldDecode(v *UECapabilityInfoIndicationValueCodec) *func([]byte, aper.DecodeState) (UECapabilityInfoIndication, error) {
	return &v.decode
}
func BridgeUECapabilityInfoIndicationValueCodecFieldEncode(v *UECapabilityInfoIndicationValueCodec) *func(UECapabilityInfoIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUECapabilityInfoIndicationValueCodecFieldPath(v *UECapabilityInfoIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeUECapabilityInfoIndicationValueCodecMethodEncodeBudgetValue(v UECapabilityInfoIndicationValueCodec, a0 UECapabilityInfoIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUECapabilityInfoIndicationValueCodecMethodEncodeChanged(v UECapabilityInfoIndicationValueCodec, a0 UECapabilityInfoIndication, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationConfirmAPERValueFieldContext(v *UEContextModificationConfirmAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationConfirmAPERValueFieldReceived(v *UEContextModificationConfirmAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationConfirmAPERValueFieldReplay(v *UEContextModificationConfirmAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationConfirmAPERValueFieldWithoutReplay(v *UEContextModificationConfirmAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationConfirmFieldExtCount(v *UEContextModificationConfirm) *int64 {
	return &v.extCount
}
func BridgeUEContextModificationConfirmFieldExtData(v *UEContextModificationConfirm) *[][]byte {
	return &v.extData
}
func BridgeUEContextModificationConfirmFieldExtOrigin(v *UEContextModificationConfirm) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUEContextModificationConfirmFieldExtPresent(v *UEContextModificationConfirm) *[]bool {
	return &v.extPresent
}
func BridgeUEContextModificationConfirmFieldExtWire(v *UEContextModificationConfirm) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUEContextModificationConfirmFieldPerExtPadding(v *UEContextModificationConfirm) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUEContextModificationConfirmFieldPerPadding(v *UEContextModificationConfirm) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEContextModificationConfirmFieldProtocolIEsIndef(v *UEContextModificationConfirm) *bool {
	return &v.protocolIEsIndef
}
func BridgeUEContextModificationConfirmFieldReceived(v *UEContextModificationConfirm) *bool {
	return &v.received
}
func BridgeUEContextModificationConfirmFieldReceivedAbsolute(v *UEContextModificationConfirm) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextModificationConfirmFieldReceivedBytes(v *UEContextModificationConfirm) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextModificationConfirmFieldReceivedLocation(v *UEContextModificationConfirm) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEContextModificationConfirmFieldReplay(v *UEContextModificationConfirm) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationConfirmFieldStream(v *UEContextModificationConfirm) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextModificationConfirmFieldWithoutReplay(v *UEContextModificationConfirm) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationConfirmMethodMarshalAPERBudget(v *UEContextModificationConfirm, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextModificationConfirmMethodMarshalAPERBudgetValue(v *UEContextModificationConfirm, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEContextModificationConfirmMethodMarshalAPERChanged(v *UEContextModificationConfirm, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEContextModificationConfirmMethodMarshalAPERChangedValue(v *UEContextModificationConfirm, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEContextModificationConfirmMethodMarshalAPERLegacy(v *UEContextModificationConfirm) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEContextModificationConfirmMethodMarshalAPERNewValue(v *UEContextModificationConfirm, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEContextModificationConfirmMethodMarshalAPERPlanned(v *UEContextModificationConfirm, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEContextModificationConfirmMethodMarshalAPERTo(v *UEContextModificationConfirm, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextModificationConfirmMethodUnmarshalAPERFrom(v *UEContextModificationConfirm, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextModificationConfirmMethodUnmarshalAPERLegacy(v *UEContextModificationConfirm, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEContextModificationConfirmMethodUnmarshalAPERWithOptions(v *UEContextModificationConfirm, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextModificationConfirmValueCodecFieldCapture(v *UEContextModificationConfirmValueCodec) *func(UEContextModificationConfirm, aper.DecodeState) (UEContextModificationConfirm, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationConfirmValueCodecFieldCompare(v *UEContextModificationConfirmValueCodec) *func(UEContextModificationConfirm, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationConfirmValueCodecFieldContext(v *UEContextModificationConfirmValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationConfirmValueCodecFieldDecode(v *UEContextModificationConfirmValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationConfirm, error) {
	return &v.decode
}
func BridgeUEContextModificationConfirmValueCodecFieldEncode(v *UEContextModificationConfirmValueCodec) *func(UEContextModificationConfirm, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationConfirmValueCodecFieldPath(v *UEContextModificationConfirmValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationConfirmValueCodecMethodEncodeBudgetValue(v UEContextModificationConfirmValueCodec, a0 UEContextModificationConfirm, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationConfirmValueCodecMethodEncodeChanged(v UEContextModificationConfirmValueCodec, a0 UEContextModificationConfirm, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationFailureAPERValueFieldContext(v *UEContextModificationFailureAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationFailureAPERValueFieldReceived(v *UEContextModificationFailureAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationFailureAPERValueFieldReplay(v *UEContextModificationFailureAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationFailureAPERValueFieldWithoutReplay(v *UEContextModificationFailureAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationFailureFieldExtCount(v *UEContextModificationFailure) *int64 {
	return &v.extCount
}
func BridgeUEContextModificationFailureFieldExtData(v *UEContextModificationFailure) *[][]byte {
	return &v.extData
}
func BridgeUEContextModificationFailureFieldExtOrigin(v *UEContextModificationFailure) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUEContextModificationFailureFieldExtPresent(v *UEContextModificationFailure) *[]bool {
	return &v.extPresent
}
func BridgeUEContextModificationFailureFieldExtWire(v *UEContextModificationFailure) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUEContextModificationFailureFieldPerExtPadding(v *UEContextModificationFailure) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUEContextModificationFailureFieldPerPadding(v *UEContextModificationFailure) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEContextModificationFailureFieldProtocolIEsIndef(v *UEContextModificationFailure) *bool {
	return &v.protocolIEsIndef
}
func BridgeUEContextModificationFailureFieldReceived(v *UEContextModificationFailure) *bool {
	return &v.received
}
func BridgeUEContextModificationFailureFieldReceivedAbsolute(v *UEContextModificationFailure) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextModificationFailureFieldReceivedBytes(v *UEContextModificationFailure) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextModificationFailureFieldReceivedLocation(v *UEContextModificationFailure) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEContextModificationFailureFieldReplay(v *UEContextModificationFailure) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationFailureFieldStream(v *UEContextModificationFailure) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextModificationFailureFieldWithoutReplay(v *UEContextModificationFailure) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationFailureMethodMarshalAPERBudget(v *UEContextModificationFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextModificationFailureMethodMarshalAPERBudgetValue(v *UEContextModificationFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEContextModificationFailureMethodMarshalAPERChanged(v *UEContextModificationFailure, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEContextModificationFailureMethodMarshalAPERChangedValue(v *UEContextModificationFailure, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEContextModificationFailureMethodMarshalAPERLegacy(v *UEContextModificationFailure) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEContextModificationFailureMethodMarshalAPERNewValue(v *UEContextModificationFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEContextModificationFailureMethodMarshalAPERPlanned(v *UEContextModificationFailure, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEContextModificationFailureMethodMarshalAPERTo(v *UEContextModificationFailure, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextModificationFailureMethodUnmarshalAPERFrom(v *UEContextModificationFailure, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextModificationFailureMethodUnmarshalAPERLegacy(v *UEContextModificationFailure, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEContextModificationFailureMethodUnmarshalAPERWithOptions(v *UEContextModificationFailure, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldCapture(v *UEContextModificationFailureUnsuccessfulBinding) *func(UEContextModificationFailure, aper.DecodeState) (UEContextModificationFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldCompare(v *UEContextModificationFailureUnsuccessfulBinding) *func(UEContextModificationFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldContext(v *UEContextModificationFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldDecode(v *UEContextModificationFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (UEContextModificationFailure, error) {
	return &v.decode
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldEncode(v *UEContextModificationFailureUnsuccessfulBinding) *func(*UEContextModificationFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldInfo(v *UEContextModificationFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldInject(v *UEContextModificationFailureUnsuccessfulBinding) *func(UEContextModificationFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldValidate(v *UEContextModificationFailureUnsuccessfulBinding) *func(*UEContextModificationFailure, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextModificationFailureValueCodecFieldCapture(v *UEContextModificationFailureValueCodec) *func(UEContextModificationFailure, aper.DecodeState) (UEContextModificationFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationFailureValueCodecFieldCompare(v *UEContextModificationFailureValueCodec) *func(UEContextModificationFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationFailureValueCodecFieldContext(v *UEContextModificationFailureValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationFailureValueCodecFieldDecode(v *UEContextModificationFailureValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationFailure, error) {
	return &v.decode
}
func BridgeUEContextModificationFailureValueCodecFieldEncode(v *UEContextModificationFailureValueCodec) *func(UEContextModificationFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationFailureValueCodecFieldPath(v *UEContextModificationFailureValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationFailureValueCodecMethodEncodeBudgetValue(v UEContextModificationFailureValueCodec, a0 UEContextModificationFailure, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationFailureValueCodecMethodEncodeChanged(v UEContextModificationFailureValueCodec, a0 UEContextModificationFailure, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationIndicationAPERValueFieldContext(v *UEContextModificationIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationIndicationAPERValueFieldReceived(v *UEContextModificationIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationIndicationAPERValueFieldReplay(v *UEContextModificationIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationIndicationAPERValueFieldWithoutReplay(v *UEContextModificationIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationIndicationFieldExtCount(v *UEContextModificationIndication) *int64 {
	return &v.extCount
}
func BridgeUEContextModificationIndicationFieldExtData(v *UEContextModificationIndication) *[][]byte {
	return &v.extData
}
func BridgeUEContextModificationIndicationFieldExtOrigin(v *UEContextModificationIndication) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUEContextModificationIndicationFieldExtPresent(v *UEContextModificationIndication) *[]bool {
	return &v.extPresent
}
func BridgeUEContextModificationIndicationFieldExtWire(v *UEContextModificationIndication) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUEContextModificationIndicationFieldPerExtPadding(v *UEContextModificationIndication) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUEContextModificationIndicationFieldPerPadding(v *UEContextModificationIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEContextModificationIndicationFieldProtocolIEsIndef(v *UEContextModificationIndication) *bool {
	return &v.protocolIEsIndef
}
func BridgeUEContextModificationIndicationFieldReceived(v *UEContextModificationIndication) *bool {
	return &v.received
}
func BridgeUEContextModificationIndicationFieldReceivedAbsolute(v *UEContextModificationIndication) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextModificationIndicationFieldReceivedBytes(v *UEContextModificationIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextModificationIndicationFieldReceivedLocation(v *UEContextModificationIndication) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEContextModificationIndicationFieldReplay(v *UEContextModificationIndication) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationIndicationFieldStream(v *UEContextModificationIndication) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextModificationIndicationFieldWithoutReplay(v *UEContextModificationIndication) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationIndicationMethodMarshalAPERBudget(v *UEContextModificationIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextModificationIndicationMethodMarshalAPERBudgetValue(v *UEContextModificationIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEContextModificationIndicationMethodMarshalAPERChanged(v *UEContextModificationIndication, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEContextModificationIndicationMethodMarshalAPERChangedValue(v *UEContextModificationIndication, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEContextModificationIndicationMethodMarshalAPERLegacy(v *UEContextModificationIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEContextModificationIndicationMethodMarshalAPERNewValue(v *UEContextModificationIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEContextModificationIndicationMethodMarshalAPERPlanned(v *UEContextModificationIndication, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEContextModificationIndicationMethodMarshalAPERTo(v *UEContextModificationIndication, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextModificationIndicationMethodUnmarshalAPERFrom(v *UEContextModificationIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextModificationIndicationMethodUnmarshalAPERLegacy(v *UEContextModificationIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEContextModificationIndicationMethodUnmarshalAPERWithOptions(v *UEContextModificationIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextModificationIndicationValueCodecFieldCapture(v *UEContextModificationIndicationValueCodec) *func(UEContextModificationIndication, aper.DecodeState) (UEContextModificationIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationIndicationValueCodecFieldCompare(v *UEContextModificationIndicationValueCodec) *func(UEContextModificationIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationIndicationValueCodecFieldContext(v *UEContextModificationIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationIndicationValueCodecFieldDecode(v *UEContextModificationIndicationValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationIndication, error) {
	return &v.decode
}
func BridgeUEContextModificationIndicationValueCodecFieldEncode(v *UEContextModificationIndicationValueCodec) *func(UEContextModificationIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationIndicationValueCodecFieldPath(v *UEContextModificationIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationIndicationValueCodecMethodEncodeBudgetValue(v UEContextModificationIndicationValueCodec, a0 UEContextModificationIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationIndicationValueCodecMethodEncodeChanged(v UEContextModificationIndicationValueCodec, a0 UEContextModificationIndication, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextModificationResponseAPERValueFieldContext(v *UEContextModificationResponseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationResponseAPERValueFieldReceived(v *UEContextModificationResponseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextModificationResponseAPERValueFieldReplay(v *UEContextModificationResponseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationResponseAPERValueFieldWithoutReplay(v *UEContextModificationResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationResponseFieldExtCount(v *UEContextModificationResponse) *int64 {
	return &v.extCount
}
func BridgeUEContextModificationResponseFieldExtData(v *UEContextModificationResponse) *[][]byte {
	return &v.extData
}
func BridgeUEContextModificationResponseFieldExtOrigin(v *UEContextModificationResponse) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUEContextModificationResponseFieldExtPresent(v *UEContextModificationResponse) *[]bool {
	return &v.extPresent
}
func BridgeUEContextModificationResponseFieldExtWire(v *UEContextModificationResponse) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUEContextModificationResponseFieldPerExtPadding(v *UEContextModificationResponse) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUEContextModificationResponseFieldPerPadding(v *UEContextModificationResponse) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEContextModificationResponseFieldProtocolIEsIndef(v *UEContextModificationResponse) *bool {
	return &v.protocolIEsIndef
}
func BridgeUEContextModificationResponseFieldReceived(v *UEContextModificationResponse) *bool {
	return &v.received
}
func BridgeUEContextModificationResponseFieldReceivedAbsolute(v *UEContextModificationResponse) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextModificationResponseFieldReceivedBytes(v *UEContextModificationResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextModificationResponseFieldReceivedLocation(v *UEContextModificationResponse) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEContextModificationResponseFieldReplay(v *UEContextModificationResponse) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextModificationResponseFieldStream(v *UEContextModificationResponse) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextModificationResponseFieldWithoutReplay(v *UEContextModificationResponse) *bool {
	return &v.withoutReplay
}
func BridgeUEContextModificationResponseMethodMarshalAPERBudget(v *UEContextModificationResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextModificationResponseMethodMarshalAPERBudgetValue(v *UEContextModificationResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEContextModificationResponseMethodMarshalAPERChanged(v *UEContextModificationResponse, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEContextModificationResponseMethodMarshalAPERChangedValue(v *UEContextModificationResponse, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEContextModificationResponseMethodMarshalAPERLegacy(v *UEContextModificationResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEContextModificationResponseMethodMarshalAPERNewValue(v *UEContextModificationResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEContextModificationResponseMethodMarshalAPERPlanned(v *UEContextModificationResponse, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEContextModificationResponseMethodMarshalAPERTo(v *UEContextModificationResponse, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextModificationResponseMethodUnmarshalAPERFrom(v *UEContextModificationResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextModificationResponseMethodUnmarshalAPERLegacy(v *UEContextModificationResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEContextModificationResponseMethodUnmarshalAPERWithOptions(v *UEContextModificationResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextModificationResponseValueCodecFieldCapture(v *UEContextModificationResponseValueCodec) *func(UEContextModificationResponse, aper.DecodeState) (UEContextModificationResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationResponseValueCodecFieldCompare(v *UEContextModificationResponseValueCodec) *func(UEContextModificationResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationResponseValueCodecFieldContext(v *UEContextModificationResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationResponseValueCodecFieldDecode(v *UEContextModificationResponseValueCodec) *func([]byte, aper.DecodeState) (UEContextModificationResponse, error) {
	return &v.decode
}
func BridgeUEContextModificationResponseValueCodecFieldEncode(v *UEContextModificationResponseValueCodec) *func(UEContextModificationResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationResponseValueCodecFieldPath(v *UEContextModificationResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextModificationResponseValueCodecMethodEncodeBudgetValue(v UEContextModificationResponseValueCodec, a0 UEContextModificationResponse, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextModificationResponseValueCodecMethodEncodeChanged(v UEContextModificationResponseValueCodec, a0 UEContextModificationResponse, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextResumeFailureAPERValueFieldContext(v *UEContextResumeFailureAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeFailureAPERValueFieldReceived(v *UEContextResumeFailureAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextResumeFailureAPERValueFieldReplay(v *UEContextResumeFailureAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextResumeFailureAPERValueFieldWithoutReplay(v *UEContextResumeFailureAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextResumeFailureFieldExtCount(v *UEContextResumeFailure) *int64   { return &v.extCount }
func BridgeUEContextResumeFailureFieldExtData(v *UEContextResumeFailure) *[][]byte { return &v.extData }
func BridgeUEContextResumeFailureFieldExtOrigin(v *UEContextResumeFailure) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUEContextResumeFailureFieldExtPresent(v *UEContextResumeFailure) *[]bool {
	return &v.extPresent
}
func BridgeUEContextResumeFailureFieldExtWire(v *UEContextResumeFailure) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUEContextResumeFailureFieldPerExtPadding(v *UEContextResumeFailure) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUEContextResumeFailureFieldPerPadding(v *UEContextResumeFailure) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEContextResumeFailureFieldProtocolIEsIndef(v *UEContextResumeFailure) *bool {
	return &v.protocolIEsIndef
}
func BridgeUEContextResumeFailureFieldReceived(v *UEContextResumeFailure) *bool { return &v.received }
func BridgeUEContextResumeFailureFieldReceivedAbsolute(v *UEContextResumeFailure) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextResumeFailureFieldReceivedBytes(v *UEContextResumeFailure) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextResumeFailureFieldReceivedLocation(v *UEContextResumeFailure) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEContextResumeFailureFieldReplay(v *UEContextResumeFailure) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextResumeFailureFieldStream(v *UEContextResumeFailure) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextResumeFailureFieldWithoutReplay(v *UEContextResumeFailure) *bool {
	return &v.withoutReplay
}
func BridgeUEContextResumeFailureMethodMarshalAPERBudget(v *UEContextResumeFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextResumeFailureMethodMarshalAPERBudgetValue(v *UEContextResumeFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEContextResumeFailureMethodMarshalAPERChanged(v *UEContextResumeFailure, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEContextResumeFailureMethodMarshalAPERChangedValue(v *UEContextResumeFailure, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEContextResumeFailureMethodMarshalAPERLegacy(v *UEContextResumeFailure) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEContextResumeFailureMethodMarshalAPERNewValue(v *UEContextResumeFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEContextResumeFailureMethodMarshalAPERPlanned(v *UEContextResumeFailure, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEContextResumeFailureMethodMarshalAPERTo(v *UEContextResumeFailure, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextResumeFailureMethodUnmarshalAPERFrom(v *UEContextResumeFailure, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextResumeFailureMethodUnmarshalAPERLegacy(v *UEContextResumeFailure, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEContextResumeFailureMethodUnmarshalAPERWithOptions(v *UEContextResumeFailure, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextResumeFailureUnsuccessfulBindingFieldCapture(v *UEContextResumeFailureUnsuccessfulBinding) *func(UEContextResumeFailure, aper.DecodeState) (UEContextResumeFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextResumeFailureUnsuccessfulBindingFieldCompare(v *UEContextResumeFailureUnsuccessfulBinding) *func(UEContextResumeFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextResumeFailureUnsuccessfulBindingFieldContext(v *UEContextResumeFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeFailureUnsuccessfulBindingFieldDecode(v *UEContextResumeFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (UEContextResumeFailure, error) {
	return &v.decode
}
func BridgeUEContextResumeFailureUnsuccessfulBindingFieldEncode(v *UEContextResumeFailureUnsuccessfulBinding) *func(*UEContextResumeFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextResumeFailureUnsuccessfulBindingFieldInfo(v *UEContextResumeFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextResumeFailureUnsuccessfulBindingFieldInject(v *UEContextResumeFailureUnsuccessfulBinding) *func(UEContextResumeFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeUEContextResumeFailureUnsuccessfulBindingFieldValidate(v *UEContextResumeFailureUnsuccessfulBinding) *func(*UEContextResumeFailure, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextResumeFailureValueCodecFieldCapture(v *UEContextResumeFailureValueCodec) *func(UEContextResumeFailure, aper.DecodeState) (UEContextResumeFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextResumeFailureValueCodecFieldCompare(v *UEContextResumeFailureValueCodec) *func(UEContextResumeFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextResumeFailureValueCodecFieldContext(v *UEContextResumeFailureValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextResumeFailureValueCodecFieldDecode(v *UEContextResumeFailureValueCodec) *func([]byte, aper.DecodeState) (UEContextResumeFailure, error) {
	return &v.decode
}
func BridgeUEContextResumeFailureValueCodecFieldEncode(v *UEContextResumeFailureValueCodec) *func(UEContextResumeFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextResumeFailureValueCodecFieldPath(v *UEContextResumeFailureValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextResumeFailureValueCodecMethodEncodeBudgetValue(v UEContextResumeFailureValueCodec, a0 UEContextResumeFailure, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextResumeFailureValueCodecMethodEncodeChanged(v UEContextResumeFailureValueCodec, a0 UEContextResumeFailure, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextSuspendResponseAPERValueFieldContext(v *UEContextSuspendResponseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendResponseAPERValueFieldReceived(v *UEContextSuspendResponseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextSuspendResponseAPERValueFieldReplay(v *UEContextSuspendResponseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextSuspendResponseAPERValueFieldWithoutReplay(v *UEContextSuspendResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextSuspendResponseFieldExtCount(v *UEContextSuspendResponse) *int64 {
	return &v.extCount
}
func BridgeUEContextSuspendResponseFieldExtData(v *UEContextSuspendResponse) *[][]byte {
	return &v.extData
}
func BridgeUEContextSuspendResponseFieldExtOrigin(v *UEContextSuspendResponse) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUEContextSuspendResponseFieldExtPresent(v *UEContextSuspendResponse) *[]bool {
	return &v.extPresent
}
func BridgeUEContextSuspendResponseFieldExtWire(v *UEContextSuspendResponse) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUEContextSuspendResponseFieldPerExtPadding(v *UEContextSuspendResponse) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUEContextSuspendResponseFieldPerPadding(v *UEContextSuspendResponse) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEContextSuspendResponseFieldProtocolIEsIndef(v *UEContextSuspendResponse) *bool {
	return &v.protocolIEsIndef
}
func BridgeUEContextSuspendResponseFieldReceived(v *UEContextSuspendResponse) *bool {
	return &v.received
}
func BridgeUEContextSuspendResponseFieldReceivedAbsolute(v *UEContextSuspendResponse) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextSuspendResponseFieldReceivedBytes(v *UEContextSuspendResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextSuspendResponseFieldReceivedLocation(v *UEContextSuspendResponse) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEContextSuspendResponseFieldReplay(v *UEContextSuspendResponse) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextSuspendResponseFieldStream(v *UEContextSuspendResponse) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextSuspendResponseFieldWithoutReplay(v *UEContextSuspendResponse) *bool {
	return &v.withoutReplay
}
func BridgeUEContextSuspendResponseMethodMarshalAPERBudget(v *UEContextSuspendResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextSuspendResponseMethodMarshalAPERBudgetValue(v *UEContextSuspendResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEContextSuspendResponseMethodMarshalAPERChanged(v *UEContextSuspendResponse, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEContextSuspendResponseMethodMarshalAPERChangedValue(v *UEContextSuspendResponse, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEContextSuspendResponseMethodMarshalAPERLegacy(v *UEContextSuspendResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEContextSuspendResponseMethodMarshalAPERNewValue(v *UEContextSuspendResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEContextSuspendResponseMethodMarshalAPERPlanned(v *UEContextSuspendResponse, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEContextSuspendResponseMethodMarshalAPERTo(v *UEContextSuspendResponse, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextSuspendResponseMethodUnmarshalAPERFrom(v *UEContextSuspendResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextSuspendResponseMethodUnmarshalAPERLegacy(v *UEContextSuspendResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEContextSuspendResponseMethodUnmarshalAPERWithOptions(v *UEContextSuspendResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextSuspendResponseValueCodecFieldCapture(v *UEContextSuspendResponseValueCodec) *func(UEContextSuspendResponse, aper.DecodeState) (UEContextSuspendResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextSuspendResponseValueCodecFieldCompare(v *UEContextSuspendResponseValueCodec) *func(UEContextSuspendResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextSuspendResponseValueCodecFieldContext(v *UEContextSuspendResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextSuspendResponseValueCodecFieldDecode(v *UEContextSuspendResponseValueCodec) *func([]byte, aper.DecodeState) (UEContextSuspendResponse, error) {
	return &v.decode
}
func BridgeUEContextSuspendResponseValueCodecFieldEncode(v *UEContextSuspendResponseValueCodec) *func(UEContextSuspendResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextSuspendResponseValueCodecFieldPath(v *UEContextSuspendResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextSuspendResponseValueCodecMethodEncodeBudgetValue(v UEContextSuspendResponseValueCodec, a0 UEContextSuspendResponse, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextSuspendResponseValueCodecMethodEncodeChanged(v UEContextSuspendResponseValueCodec, a0 UEContextSuspendResponse, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEInformationTransferAPERValueFieldContext(v *UEInformationTransferAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferAPERValueFieldReceived(v *UEInformationTransferAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEInformationTransferAPERValueFieldReplay(v *UEInformationTransferAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEInformationTransferAPERValueFieldWithoutReplay(v *UEInformationTransferAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEInformationTransferFieldExtCount(v *UEInformationTransfer) *int64   { return &v.extCount }
func BridgeUEInformationTransferFieldExtData(v *UEInformationTransfer) *[][]byte { return &v.extData }
func BridgeUEInformationTransferFieldExtOrigin(v *UEInformationTransfer) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUEInformationTransferFieldExtPresent(v *UEInformationTransfer) *[]bool {
	return &v.extPresent
}
func BridgeUEInformationTransferFieldExtWire(v *UEInformationTransfer) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUEInformationTransferFieldPerExtPadding(v *UEInformationTransfer) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUEInformationTransferFieldPerPadding(v *UEInformationTransfer) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEInformationTransferFieldProtocolIEsIndef(v *UEInformationTransfer) *bool {
	return &v.protocolIEsIndef
}
func BridgeUEInformationTransferFieldReceived(v *UEInformationTransfer) *bool { return &v.received }
func BridgeUEInformationTransferFieldReceivedAbsolute(v *UEInformationTransfer) *bool {
	return &v.receivedAbsolute
}
func BridgeUEInformationTransferFieldReceivedBytes(v *UEInformationTransfer) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEInformationTransferFieldReceivedLocation(v *UEInformationTransfer) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEInformationTransferFieldReplay(v *UEInformationTransfer) *aper.Snapshot {
	return &v.replay
}
func BridgeUEInformationTransferFieldStream(v *UEInformationTransfer) *aper.WireSpan {
	return &v.stream
}
func BridgeUEInformationTransferFieldWithoutReplay(v *UEInformationTransfer) *bool {
	return &v.withoutReplay
}
func BridgeUEInformationTransferMethodMarshalAPERBudget(v *UEInformationTransfer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEInformationTransferMethodMarshalAPERBudgetValue(v *UEInformationTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEInformationTransferMethodMarshalAPERChanged(v *UEInformationTransfer, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEInformationTransferMethodMarshalAPERChangedValue(v *UEInformationTransfer, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEInformationTransferMethodMarshalAPERLegacy(v *UEInformationTransfer) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEInformationTransferMethodMarshalAPERNewValue(v *UEInformationTransfer, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEInformationTransferMethodMarshalAPERPlanned(v *UEInformationTransfer, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEInformationTransferMethodMarshalAPERTo(v *UEInformationTransfer, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEInformationTransferMethodUnmarshalAPERFrom(v *UEInformationTransfer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEInformationTransferMethodUnmarshalAPERLegacy(v *UEInformationTransfer, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEInformationTransferMethodUnmarshalAPERWithOptions(v *UEInformationTransfer, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEInformationTransferValueCodecFieldCapture(v *UEInformationTransferValueCodec) *func(UEInformationTransfer, aper.DecodeState) (UEInformationTransfer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEInformationTransferValueCodecFieldCompare(v *UEInformationTransferValueCodec) *func(UEInformationTransfer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEInformationTransferValueCodecFieldContext(v *UEInformationTransferValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEInformationTransferValueCodecFieldDecode(v *UEInformationTransferValueCodec) *func([]byte, aper.DecodeState) (UEInformationTransfer, error) {
	return &v.decode
}
func BridgeUEInformationTransferValueCodecFieldEncode(v *UEInformationTransferValueCodec) *func(UEInformationTransfer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEInformationTransferValueCodecFieldPath(v *UEInformationTransferValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEInformationTransferValueCodecMethodEncodeBudgetValue(v UEInformationTransferValueCodec, a0 UEInformationTransfer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEInformationTransferValueCodecMethodEncodeChanged(v UEInformationTransferValueCodec, a0 UEInformationTransfer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERadioCapabilityIDMappingRequestAPERValueFieldContext(v *UERadioCapabilityIDMappingRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingRequestAPERValueFieldReceived(v *UERadioCapabilityIDMappingRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityIDMappingRequestAPERValueFieldReplay(v *UERadioCapabilityIDMappingRequestAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityIDMappingRequestAPERValueFieldWithoutReplay(v *UERadioCapabilityIDMappingRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityIDMappingRequestFieldExtCount(v *UERadioCapabilityIDMappingRequest) *int64 {
	return &v.extCount
}
func BridgeUERadioCapabilityIDMappingRequestFieldExtData(v *UERadioCapabilityIDMappingRequest) *[][]byte {
	return &v.extData
}
func BridgeUERadioCapabilityIDMappingRequestFieldExtOrigin(v *UERadioCapabilityIDMappingRequest) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUERadioCapabilityIDMappingRequestFieldExtPresent(v *UERadioCapabilityIDMappingRequest) *[]bool {
	return &v.extPresent
}
func BridgeUERadioCapabilityIDMappingRequestFieldExtWire(v *UERadioCapabilityIDMappingRequest) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUERadioCapabilityIDMappingRequestFieldPerExtPadding(v *UERadioCapabilityIDMappingRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUERadioCapabilityIDMappingRequestFieldPerPadding(v *UERadioCapabilityIDMappingRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUERadioCapabilityIDMappingRequestFieldProtocolIEsIndef(v *UERadioCapabilityIDMappingRequest) *bool {
	return &v.protocolIEsIndef
}
func BridgeUERadioCapabilityIDMappingRequestFieldReceived(v *UERadioCapabilityIDMappingRequest) *bool {
	return &v.received
}
func BridgeUERadioCapabilityIDMappingRequestFieldReceivedAbsolute(v *UERadioCapabilityIDMappingRequest) *bool {
	return &v.receivedAbsolute
}
func BridgeUERadioCapabilityIDMappingRequestFieldReceivedBytes(v *UERadioCapabilityIDMappingRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUERadioCapabilityIDMappingRequestFieldReceivedLocation(v *UERadioCapabilityIDMappingRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeUERadioCapabilityIDMappingRequestFieldReplay(v *UERadioCapabilityIDMappingRequest) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityIDMappingRequestFieldStream(v *UERadioCapabilityIDMappingRequest) *aper.WireSpan {
	return &v.stream
}
func BridgeUERadioCapabilityIDMappingRequestFieldWithoutReplay(v *UERadioCapabilityIDMappingRequest) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityIDMappingRequestMethodMarshalAPERBudget(v *UERadioCapabilityIDMappingRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUERadioCapabilityIDMappingRequestMethodMarshalAPERBudgetValue(v *UERadioCapabilityIDMappingRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUERadioCapabilityIDMappingRequestMethodMarshalAPERChanged(v *UERadioCapabilityIDMappingRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUERadioCapabilityIDMappingRequestMethodMarshalAPERChangedValue(v *UERadioCapabilityIDMappingRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUERadioCapabilityIDMappingRequestMethodMarshalAPERLegacy(v *UERadioCapabilityIDMappingRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUERadioCapabilityIDMappingRequestMethodMarshalAPERNewValue(v *UERadioCapabilityIDMappingRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUERadioCapabilityIDMappingRequestMethodMarshalAPERPlanned(v *UERadioCapabilityIDMappingRequest, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUERadioCapabilityIDMappingRequestMethodMarshalAPERTo(v *UERadioCapabilityIDMappingRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUERadioCapabilityIDMappingRequestMethodUnmarshalAPERFrom(v *UERadioCapabilityIDMappingRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUERadioCapabilityIDMappingRequestMethodUnmarshalAPERLegacy(v *UERadioCapabilityIDMappingRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUERadioCapabilityIDMappingRequestMethodUnmarshalAPERWithOptions(v *UERadioCapabilityIDMappingRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUERadioCapabilityIDMappingRequestValueCodecFieldCapture(v *UERadioCapabilityIDMappingRequestValueCodec) *func(UERadioCapabilityIDMappingRequest, aper.DecodeState) (UERadioCapabilityIDMappingRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityIDMappingRequestValueCodecFieldCompare(v *UERadioCapabilityIDMappingRequestValueCodec) *func(UERadioCapabilityIDMappingRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityIDMappingRequestValueCodecFieldContext(v *UERadioCapabilityIDMappingRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingRequestValueCodecFieldDecode(v *UERadioCapabilityIDMappingRequestValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingRequest, error) {
	return &v.decode
}
func BridgeUERadioCapabilityIDMappingRequestValueCodecFieldEncode(v *UERadioCapabilityIDMappingRequestValueCodec) *func(UERadioCapabilityIDMappingRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityIDMappingRequestValueCodecFieldPath(v *UERadioCapabilityIDMappingRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityIDMappingRequestValueCodecMethodEncodeBudgetValue(v UERadioCapabilityIDMappingRequestValueCodec, a0 UERadioCapabilityIDMappingRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERadioCapabilityIDMappingRequestValueCodecMethodEncodeChanged(v UERadioCapabilityIDMappingRequestValueCodec, a0 UERadioCapabilityIDMappingRequest, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERadioCapabilityIDMappingResponseAPERValueFieldContext(v *UERadioCapabilityIDMappingResponseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseAPERValueFieldReceived(v *UERadioCapabilityIDMappingResponseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityIDMappingResponseAPERValueFieldReplay(v *UERadioCapabilityIDMappingResponseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityIDMappingResponseAPERValueFieldWithoutReplay(v *UERadioCapabilityIDMappingResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityIDMappingResponseFieldExtCount(v *UERadioCapabilityIDMappingResponse) *int64 {
	return &v.extCount
}
func BridgeUERadioCapabilityIDMappingResponseFieldExtData(v *UERadioCapabilityIDMappingResponse) *[][]byte {
	return &v.extData
}
func BridgeUERadioCapabilityIDMappingResponseFieldExtOrigin(v *UERadioCapabilityIDMappingResponse) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUERadioCapabilityIDMappingResponseFieldExtPresent(v *UERadioCapabilityIDMappingResponse) *[]bool {
	return &v.extPresent
}
func BridgeUERadioCapabilityIDMappingResponseFieldExtWire(v *UERadioCapabilityIDMappingResponse) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUERadioCapabilityIDMappingResponseFieldPerExtPadding(v *UERadioCapabilityIDMappingResponse) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUERadioCapabilityIDMappingResponseFieldPerPadding(v *UERadioCapabilityIDMappingResponse) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUERadioCapabilityIDMappingResponseFieldProtocolIEsIndef(v *UERadioCapabilityIDMappingResponse) *bool {
	return &v.protocolIEsIndef
}
func BridgeUERadioCapabilityIDMappingResponseFieldReceived(v *UERadioCapabilityIDMappingResponse) *bool {
	return &v.received
}
func BridgeUERadioCapabilityIDMappingResponseFieldReceivedAbsolute(v *UERadioCapabilityIDMappingResponse) *bool {
	return &v.receivedAbsolute
}
func BridgeUERadioCapabilityIDMappingResponseFieldReceivedBytes(v *UERadioCapabilityIDMappingResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUERadioCapabilityIDMappingResponseFieldReceivedLocation(v *UERadioCapabilityIDMappingResponse) *aper.Location {
	return &v.receivedLocation
}
func BridgeUERadioCapabilityIDMappingResponseFieldReplay(v *UERadioCapabilityIDMappingResponse) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityIDMappingResponseFieldStream(v *UERadioCapabilityIDMappingResponse) *aper.WireSpan {
	return &v.stream
}
func BridgeUERadioCapabilityIDMappingResponseFieldWithoutReplay(v *UERadioCapabilityIDMappingResponse) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERBudget(v *UERadioCapabilityIDMappingResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERBudgetValue(v *UERadioCapabilityIDMappingResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERChanged(v *UERadioCapabilityIDMappingResponse, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERChangedValue(v *UERadioCapabilityIDMappingResponse, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERLegacy(v *UERadioCapabilityIDMappingResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERNewValue(v *UERadioCapabilityIDMappingResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERPlanned(v *UERadioCapabilityIDMappingResponse, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERTo(v *UERadioCapabilityIDMappingResponse, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUERadioCapabilityIDMappingResponseMethodUnmarshalAPERFrom(v *UERadioCapabilityIDMappingResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUERadioCapabilityIDMappingResponseMethodUnmarshalAPERLegacy(v *UERadioCapabilityIDMappingResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUERadioCapabilityIDMappingResponseMethodUnmarshalAPERWithOptions(v *UERadioCapabilityIDMappingResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUERadioCapabilityIDMappingResponseValueCodecFieldCapture(v *UERadioCapabilityIDMappingResponseValueCodec) *func(UERadioCapabilityIDMappingResponse, aper.DecodeState) (UERadioCapabilityIDMappingResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityIDMappingResponseValueCodecFieldCompare(v *UERadioCapabilityIDMappingResponseValueCodec) *func(UERadioCapabilityIDMappingResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityIDMappingResponseValueCodecFieldContext(v *UERadioCapabilityIDMappingResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDMappingResponseValueCodecFieldDecode(v *UERadioCapabilityIDMappingResponseValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityIDMappingResponse, error) {
	return &v.decode
}
func BridgeUERadioCapabilityIDMappingResponseValueCodecFieldEncode(v *UERadioCapabilityIDMappingResponseValueCodec) *func(UERadioCapabilityIDMappingResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityIDMappingResponseValueCodecFieldPath(v *UERadioCapabilityIDMappingResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityIDMappingResponseValueCodecMethodEncodeBudgetValue(v UERadioCapabilityIDMappingResponseValueCodec, a0 UERadioCapabilityIDMappingResponse, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERadioCapabilityIDMappingResponseValueCodecMethodEncodeChanged(v UERadioCapabilityIDMappingResponseValueCodec, a0 UERadioCapabilityIDMappingResponse, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERadioCapabilityMatchRequestAPERValueFieldContext(v *UERadioCapabilityMatchRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchRequestAPERValueFieldReceived(v *UERadioCapabilityMatchRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityMatchRequestAPERValueFieldReplay(v *UERadioCapabilityMatchRequestAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityMatchRequestAPERValueFieldWithoutReplay(v *UERadioCapabilityMatchRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityMatchRequestFieldExtCount(v *UERadioCapabilityMatchRequest) *int64 {
	return &v.extCount
}
func BridgeUERadioCapabilityMatchRequestFieldExtData(v *UERadioCapabilityMatchRequest) *[][]byte {
	return &v.extData
}
func BridgeUERadioCapabilityMatchRequestFieldExtOrigin(v *UERadioCapabilityMatchRequest) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUERadioCapabilityMatchRequestFieldExtPresent(v *UERadioCapabilityMatchRequest) *[]bool {
	return &v.extPresent
}
func BridgeUERadioCapabilityMatchRequestFieldExtWire(v *UERadioCapabilityMatchRequest) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUERadioCapabilityMatchRequestFieldPerExtPadding(v *UERadioCapabilityMatchRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUERadioCapabilityMatchRequestFieldPerPadding(v *UERadioCapabilityMatchRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUERadioCapabilityMatchRequestFieldProtocolIEsIndef(v *UERadioCapabilityMatchRequest) *bool {
	return &v.protocolIEsIndef
}
func BridgeUERadioCapabilityMatchRequestFieldReceived(v *UERadioCapabilityMatchRequest) *bool {
	return &v.received
}
func BridgeUERadioCapabilityMatchRequestFieldReceivedAbsolute(v *UERadioCapabilityMatchRequest) *bool {
	return &v.receivedAbsolute
}
func BridgeUERadioCapabilityMatchRequestFieldReceivedBytes(v *UERadioCapabilityMatchRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUERadioCapabilityMatchRequestFieldReceivedLocation(v *UERadioCapabilityMatchRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeUERadioCapabilityMatchRequestFieldReplay(v *UERadioCapabilityMatchRequest) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityMatchRequestFieldStream(v *UERadioCapabilityMatchRequest) *aper.WireSpan {
	return &v.stream
}
func BridgeUERadioCapabilityMatchRequestFieldWithoutReplay(v *UERadioCapabilityMatchRequest) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityMatchRequestMethodMarshalAPERBudget(v *UERadioCapabilityMatchRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUERadioCapabilityMatchRequestMethodMarshalAPERBudgetValue(v *UERadioCapabilityMatchRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUERadioCapabilityMatchRequestMethodMarshalAPERChanged(v *UERadioCapabilityMatchRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUERadioCapabilityMatchRequestMethodMarshalAPERChangedValue(v *UERadioCapabilityMatchRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUERadioCapabilityMatchRequestMethodMarshalAPERLegacy(v *UERadioCapabilityMatchRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUERadioCapabilityMatchRequestMethodMarshalAPERNewValue(v *UERadioCapabilityMatchRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUERadioCapabilityMatchRequestMethodMarshalAPERPlanned(v *UERadioCapabilityMatchRequest, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUERadioCapabilityMatchRequestMethodMarshalAPERTo(v *UERadioCapabilityMatchRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUERadioCapabilityMatchRequestMethodUnmarshalAPERFrom(v *UERadioCapabilityMatchRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUERadioCapabilityMatchRequestMethodUnmarshalAPERLegacy(v *UERadioCapabilityMatchRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUERadioCapabilityMatchRequestMethodUnmarshalAPERWithOptions(v *UERadioCapabilityMatchRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUERadioCapabilityMatchRequestValueCodecFieldCapture(v *UERadioCapabilityMatchRequestValueCodec) *func(UERadioCapabilityMatchRequest, aper.DecodeState) (UERadioCapabilityMatchRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityMatchRequestValueCodecFieldCompare(v *UERadioCapabilityMatchRequestValueCodec) *func(UERadioCapabilityMatchRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityMatchRequestValueCodecFieldContext(v *UERadioCapabilityMatchRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchRequestValueCodecFieldDecode(v *UERadioCapabilityMatchRequestValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityMatchRequest, error) {
	return &v.decode
}
func BridgeUERadioCapabilityMatchRequestValueCodecFieldEncode(v *UERadioCapabilityMatchRequestValueCodec) *func(UERadioCapabilityMatchRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityMatchRequestValueCodecFieldPath(v *UERadioCapabilityMatchRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityMatchRequestValueCodecMethodEncodeBudgetValue(v UERadioCapabilityMatchRequestValueCodec, a0 UERadioCapabilityMatchRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERadioCapabilityMatchRequestValueCodecMethodEncodeChanged(v UERadioCapabilityMatchRequestValueCodec, a0 UERadioCapabilityMatchRequest, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERadioCapabilityMatchResponseAPERValueFieldContext(v *UERadioCapabilityMatchResponseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseAPERValueFieldReceived(v *UERadioCapabilityMatchResponseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityMatchResponseAPERValueFieldReplay(v *UERadioCapabilityMatchResponseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityMatchResponseAPERValueFieldWithoutReplay(v *UERadioCapabilityMatchResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityMatchResponseFieldExtCount(v *UERadioCapabilityMatchResponse) *int64 {
	return &v.extCount
}
func BridgeUERadioCapabilityMatchResponseFieldExtData(v *UERadioCapabilityMatchResponse) *[][]byte {
	return &v.extData
}
func BridgeUERadioCapabilityMatchResponseFieldExtOrigin(v *UERadioCapabilityMatchResponse) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUERadioCapabilityMatchResponseFieldExtPresent(v *UERadioCapabilityMatchResponse) *[]bool {
	return &v.extPresent
}
func BridgeUERadioCapabilityMatchResponseFieldExtWire(v *UERadioCapabilityMatchResponse) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUERadioCapabilityMatchResponseFieldPerExtPadding(v *UERadioCapabilityMatchResponse) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUERadioCapabilityMatchResponseFieldPerPadding(v *UERadioCapabilityMatchResponse) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUERadioCapabilityMatchResponseFieldProtocolIEsIndef(v *UERadioCapabilityMatchResponse) *bool {
	return &v.protocolIEsIndef
}
func BridgeUERadioCapabilityMatchResponseFieldReceived(v *UERadioCapabilityMatchResponse) *bool {
	return &v.received
}
func BridgeUERadioCapabilityMatchResponseFieldReceivedAbsolute(v *UERadioCapabilityMatchResponse) *bool {
	return &v.receivedAbsolute
}
func BridgeUERadioCapabilityMatchResponseFieldReceivedBytes(v *UERadioCapabilityMatchResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUERadioCapabilityMatchResponseFieldReceivedLocation(v *UERadioCapabilityMatchResponse) *aper.Location {
	return &v.receivedLocation
}
func BridgeUERadioCapabilityMatchResponseFieldReplay(v *UERadioCapabilityMatchResponse) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityMatchResponseFieldStream(v *UERadioCapabilityMatchResponse) *aper.WireSpan {
	return &v.stream
}
func BridgeUERadioCapabilityMatchResponseFieldWithoutReplay(v *UERadioCapabilityMatchResponse) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityMatchResponseMethodMarshalAPERBudget(v *UERadioCapabilityMatchResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUERadioCapabilityMatchResponseMethodMarshalAPERBudgetValue(v *UERadioCapabilityMatchResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUERadioCapabilityMatchResponseMethodMarshalAPERChanged(v *UERadioCapabilityMatchResponse, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUERadioCapabilityMatchResponseMethodMarshalAPERChangedValue(v *UERadioCapabilityMatchResponse, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUERadioCapabilityMatchResponseMethodMarshalAPERLegacy(v *UERadioCapabilityMatchResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUERadioCapabilityMatchResponseMethodMarshalAPERNewValue(v *UERadioCapabilityMatchResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUERadioCapabilityMatchResponseMethodMarshalAPERPlanned(v *UERadioCapabilityMatchResponse, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUERadioCapabilityMatchResponseMethodMarshalAPERTo(v *UERadioCapabilityMatchResponse, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUERadioCapabilityMatchResponseMethodUnmarshalAPERFrom(v *UERadioCapabilityMatchResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUERadioCapabilityMatchResponseMethodUnmarshalAPERLegacy(v *UERadioCapabilityMatchResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUERadioCapabilityMatchResponseMethodUnmarshalAPERWithOptions(v *UERadioCapabilityMatchResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUERadioCapabilityMatchResponseValueCodecFieldCapture(v *UERadioCapabilityMatchResponseValueCodec) *func(UERadioCapabilityMatchResponse, aper.DecodeState) (UERadioCapabilityMatchResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityMatchResponseValueCodecFieldCompare(v *UERadioCapabilityMatchResponseValueCodec) *func(UERadioCapabilityMatchResponse, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityMatchResponseValueCodecFieldContext(v *UERadioCapabilityMatchResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityMatchResponseValueCodecFieldDecode(v *UERadioCapabilityMatchResponseValueCodec) *func([]byte, aper.DecodeState) (UERadioCapabilityMatchResponse, error) {
	return &v.decode
}
func BridgeUERadioCapabilityMatchResponseValueCodecFieldEncode(v *UERadioCapabilityMatchResponseValueCodec) *func(UERadioCapabilityMatchResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityMatchResponseValueCodecFieldPath(v *UERadioCapabilityMatchResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityMatchResponseValueCodecMethodEncodeBudgetValue(v UERadioCapabilityMatchResponseValueCodec, a0 UERadioCapabilityMatchResponse, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERadioCapabilityMatchResponseValueCodecMethodEncodeChanged(v UERadioCapabilityMatchResponseValueCodec, a0 UERadioCapabilityMatchResponse, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUES1APIDPairAPERValueFieldContext(v *UES1APIDPairAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUES1APIDPairAPERValueFieldReceived(v *UES1APIDPairAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUES1APIDPairAPERValueFieldReplay(v *UES1APIDPairAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUES1APIDPairAPERValueFieldWithoutReplay(v *UES1APIDPairAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUES1APIDPairFieldExtCount(v *UES1APIDPair) *int64                { return &v.extCount }
func BridgeUES1APIDPairFieldExtData(v *UES1APIDPair) *[][]byte              { return &v.extData }
func BridgeUES1APIDPairFieldExtOrigin(v *UES1APIDPair) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeUES1APIDPairFieldExtPresent(v *UES1APIDPair) *[]bool             { return &v.extPresent }
func BridgeUES1APIDPairFieldExtWire(v *UES1APIDPair) *[]aper.WireSpan       { return &v.extWire }
func BridgeUES1APIDPairFieldIEExtensionsIndef(v *UES1APIDPair) *bool        { return &v.iEExtensionsIndef }
func BridgeUES1APIDPairFieldPerExtPadding(v *UES1APIDPair) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUES1APIDPairFieldPerPadding(v *UES1APIDPair) *aper.FinalPadding { return &v.perPadding }
func BridgeUES1APIDPairFieldReceived(v *UES1APIDPair) *bool                { return &v.received }
func BridgeUES1APIDPairFieldReceivedAbsolute(v *UES1APIDPair) *bool        { return &v.receivedAbsolute }
func BridgeUES1APIDPairFieldReceivedBytes(v *UES1APIDPair) *aper.WireSpan  { return &v.receivedBytes }
func BridgeUES1APIDPairFieldReceivedLocation(v *UES1APIDPair) *aper.Location {
	return &v.receivedLocation
}
func BridgeUES1APIDPairFieldReplay(v *UES1APIDPair) *aper.Snapshot { return &v.replay }
func BridgeUES1APIDPairFieldStream(v *UES1APIDPair) *aper.WireSpan { return &v.stream }
func BridgeUES1APIDPairFieldWithoutReplay(v *UES1APIDPair) *bool   { return &v.withoutReplay }
func BridgeUES1APIDPairMethodMarshalAPERBudget(v *UES1APIDPair, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUES1APIDPairMethodMarshalAPERBudgetValue(v *UES1APIDPair, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUES1APIDPairMethodMarshalAPERChanged(v *UES1APIDPair, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUES1APIDPairMethodMarshalAPERChangedValue(v *UES1APIDPair, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUES1APIDPairMethodMarshalAPERLegacy(v *UES1APIDPair) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUES1APIDPairMethodMarshalAPERNewValue(v *UES1APIDPair, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUES1APIDPairMethodMarshalAPERPlanned(v *UES1APIDPair, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUES1APIDPairMethodMarshalAPERTo(v *UES1APIDPair, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUES1APIDPairMethodUnmarshalAPERFrom(v *UES1APIDPair, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUES1APIDPairMethodUnmarshalAPERLegacy(v *UES1APIDPair, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUES1APIDPairMethodUnmarshalAPERWithOptions(v *UES1APIDPair, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUnsuccessfulOutcomeAPERValueFieldContext(v *UnsuccessfulOutcomeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUnsuccessfulOutcomeAPERValueFieldReceived(v *UnsuccessfulOutcomeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUnsuccessfulOutcomeAPERValueFieldReplay(v *UnsuccessfulOutcomeAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUnsuccessfulOutcomeAPERValueFieldWithoutReplay(v *UnsuccessfulOutcomeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUnsuccessfulOutcomeFieldPerPadding(v *UnsuccessfulOutcome) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeUnsuccessfulOutcomeFieldReceived(v *UnsuccessfulOutcome) *bool { return &v.received }
func BridgeUnsuccessfulOutcomeFieldReceivedAbsolute(v *UnsuccessfulOutcome) *bool {
	return &v.receivedAbsolute
}
func BridgeUnsuccessfulOutcomeFieldReceivedBytes(v *UnsuccessfulOutcome) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUnsuccessfulOutcomeFieldReceivedLocation(v *UnsuccessfulOutcome) *aper.Location {
	return &v.receivedLocation
}
func BridgeUnsuccessfulOutcomeFieldReplay(v *UnsuccessfulOutcome) *aper.Snapshot { return &v.replay }
func BridgeUnsuccessfulOutcomeFieldStream(v *UnsuccessfulOutcome) *aper.WireSpan { return &v.stream }
func BridgeUnsuccessfulOutcomeFieldWithoutReplay(v *UnsuccessfulOutcome) *bool {
	return &v.withoutReplay
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERBudget(v *UnsuccessfulOutcome, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERBudgetValue(v *UnsuccessfulOutcome, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERChanged(v *UnsuccessfulOutcome, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERChangedValue(v *UnsuccessfulOutcome, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERLegacy(v *UnsuccessfulOutcome) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERNewValue(v *UnsuccessfulOutcome, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERPlanned(v *UnsuccessfulOutcome, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUnsuccessfulOutcomeMethodMarshalAPERTo(v *UnsuccessfulOutcome, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUnsuccessfulOutcomeMethodUnmarshalAPERFrom(v *UnsuccessfulOutcome, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUnsuccessfulOutcomeMethodUnmarshalAPERLegacy(v *UnsuccessfulOutcome, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUnsuccessfulOutcomeMethodUnmarshalAPERWithOptions(v *UnsuccessfulOutcome, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUnsuccessfulOutcomeValueCodecFieldCapture(v *UnsuccessfulOutcomeValueCodec) *func(UnsuccessfulOutcome, aper.DecodeState) (UnsuccessfulOutcome, aper.Snapshot) {
	return &v.capture
}
func BridgeUnsuccessfulOutcomeValueCodecFieldCompare(v *UnsuccessfulOutcomeValueCodec) *func(UnsuccessfulOutcome, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUnsuccessfulOutcomeValueCodecFieldContext(v *UnsuccessfulOutcomeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUnsuccessfulOutcomeValueCodecFieldDecode(v *UnsuccessfulOutcomeValueCodec) *func([]byte, aper.DecodeState) (UnsuccessfulOutcome, error) {
	return &v.decode
}
func BridgeUnsuccessfulOutcomeValueCodecFieldEncode(v *UnsuccessfulOutcomeValueCodec) *func(UnsuccessfulOutcome, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUnsuccessfulOutcomeValueCodecFieldPath(v *UnsuccessfulOutcomeValueCodec) *aper.Path {
	return &v.path
}
func BridgeUnsuccessfulOutcomeValueCodecMethodEncodeBudgetValue(v UnsuccessfulOutcomeValueCodec, a0 UnsuccessfulOutcome, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUnsuccessfulOutcomeValueCodecMethodEncodeChanged(v UnsuccessfulOutcomeValueCodec, a0 UnsuccessfulOutcome, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUnsuccessfulValueFieldBodyENBConfigurationUpdateFailure(v *UnsuccessfulValue) **s24.ENBConfigurationUpdateFailure {
	return &v.bodyENBConfigurationUpdateFailure
}
func BridgeUnsuccessfulValueFieldBodyHandoverFailure(v *UnsuccessfulValue) **s25.HandoverFailure {
	return &v.bodyHandoverFailure
}
func BridgeUnsuccessfulValueFieldBodyHandoverPreparationFailure(v *UnsuccessfulValue) **s25.HandoverPreparationFailure {
	return &v.bodyHandoverPreparationFailure
}
func BridgeUnsuccessfulValueFieldBodyInitialContextSetupFailure(v *UnsuccessfulValue) **s25.InitialContextSetupFailure {
	return &v.bodyInitialContextSetupFailure
}
func BridgeUnsuccessfulValueFieldBodyMMEConfigurationUpdateFailure(v *UnsuccessfulValue) **s25.MMEConfigurationUpdateFailure {
	return &v.bodyMMEConfigurationUpdateFailure
}
func BridgeUnsuccessfulValueFieldBodyPathSwitchRequestFailure(v *UnsuccessfulValue) **s26.PathSwitchRequestFailure {
	return &v.bodyPathSwitchRequestFailure
}
func BridgeUnsuccessfulValueFieldBodyS1RemovalFailure(v *UnsuccessfulValue) **s26.S1RemovalFailure {
	return &v.bodyS1RemovalFailure
}
func BridgeUnsuccessfulValueFieldBodyS1SetupFailure(v *UnsuccessfulValue) **s26.S1SetupFailure {
	return &v.bodyS1SetupFailure
}
func BridgeUnsuccessfulValueFieldBodyUEContextModificationFailure(v *UnsuccessfulValue) **UEContextModificationFailure {
	return &v.bodyUEContextModificationFailure
}
func BridgeUnsuccessfulValueFieldBodyUEContextResumeFailure(v *UnsuccessfulValue) **UEContextResumeFailure {
	return &v.bodyUEContextResumeFailure
}
func BridgeUnsuccessfulValueFieldCode(v *UnsuccessfulValue) *s00.ProcedureCode     { return &v.code }
func BridgeUnsuccessfulValueFieldIsOpaque(v *UnsuccessfulValue) *bool              { return &v.isOpaque }
func BridgeUnsuccessfulValueFieldOpaque(v *UnsuccessfulValue) *aper.OpaqueOpenType { return &v.opaque }
func BridgeUnsuccessfulValueFieldReceived(v *UnsuccessfulValue) *aper.WireSpan     { return &v.received }
func BridgeUnsuccessfulValueFieldReplay(v *UnsuccessfulValue) *aper.Snapshot       { return &v.replay }
func BridgeUnsuccessfulValueMethodCaptureSemantics(v UnsuccessfulValue, a0 aper.SemanticCapture) UnsuccessfulValue {
	return v.captureSemantics(a0)
}
func BridgeUnsuccessfulValueMethodCompareSemantics(v UnsuccessfulValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUnsuccessfulValueMethodEncode(v UnsuccessfulValue) ([]byte, error) { return v.encode() }
func BridgeUnsuccessfulValueMethodEncodeFresh(v UnsuccessfulValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
