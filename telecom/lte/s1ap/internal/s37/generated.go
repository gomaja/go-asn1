// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s37 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s37

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
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// UEContextReleaseCommandIEContainer is ProtocolIE-Container {{UEContextReleaseCommand-IEs}} of TS 36.413: a list of UEContextReleaseCommandIEField values.
type UEContextReleaseCommandIEContainer []UEContextReleaseCommandIEField

// UEContextReleaseCommandIEField is ProtocolIE-Field {{UEContextReleaseCommand-IEs}} of TS 36.413: an information element field.
type UEContextReleaseCommandIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UEContextReleaseCommandIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCommandIEField) WithoutReplay() UEContextReleaseCommandIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *UEContextReleaseCommandIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *UEContextReleaseCommandIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UEContextReleaseCommandIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextReleaseCommandIEField{}
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
	var zero UEContextReleaseCommandIEValue

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
	capture func(s27.S1SetupFailure, aper.DecodeState,

	) (s27.S1SetupFailure, aper.Snapshot,

	)
	compare func(s27.S1SetupFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s27.S1SetupFailure,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s27.S1SetupFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s27.S1SetupFailure,

		error)
	inject func(s27.S1SetupFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b S1SetupFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupFailureUnsuccessfulBinding) Codec() s27.S1SetupFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s27.S1SetupFailureValueCodec{}
	}
	return func() s27.S1SetupFailureValueCodec {
		sealed := s27.S1SetupFailureValueCodec{}
		*s27.BridgeS1SetupFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s27.BridgeS1SetupFailureValueCodecFieldDecode(&sealed) = b.decode
		*s27.BridgeS1SetupFailureValueCodecFieldEncode(&sealed) = func(value s27.S1SetupFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s27.BridgeS1SetupFailureValueCodecFieldCapture(&sealed) = b.capture
		*s27.BridgeS1SetupFailureValueCodecFieldCompare(&sealed) = b.compare
		*s27.BridgeS1SetupFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b S1SetupFailureUnsuccessfulBinding) Build(body s27.S1SetupFailure,

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
	capture func(s36.UEContextModificationFailure, aper.DecodeState,

	) (s36.UEContextModificationFailure, aper.Snapshot,

	)
	compare func(s36.UEContextModificationFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s36.UEContextModificationFailure,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s36.UEContextModificationFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s36.UEContextModificationFailure,

		error)
	inject func(s36.UEContextModificationFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationFailureUnsuccessfulBinding) Codec() s36.UEContextModificationFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s36.UEContextModificationFailureValueCodec{}
	}
	return func() s36.UEContextModificationFailureValueCodec {
		sealed := s36.UEContextModificationFailureValueCodec{}
		*s36.BridgeUEContextModificationFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s36.BridgeUEContextModificationFailureValueCodecFieldDecode(&sealed) = b.decode
		*s36.BridgeUEContextModificationFailureValueCodecFieldEncode(&sealed) = func(value s36.UEContextModificationFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s36.BridgeUEContextModificationFailureValueCodecFieldCapture(&sealed) = b.capture
		*s36.BridgeUEContextModificationFailureValueCodecFieldCompare(&sealed) = b.compare
		*s36.BridgeUEContextModificationFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b UEContextModificationFailureUnsuccessfulBinding) Build(body s36.UEContextModificationFailure,

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
	capture func(s26.MMEConfigurationUpdateFailure, aper.DecodeState,

	) (s26.MMEConfigurationUpdateFailure, aper.Snapshot,

	)
	compare func(s26.MMEConfigurationUpdateFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s26.MMEConfigurationUpdateFailure,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s26.MMEConfigurationUpdateFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s26.MMEConfigurationUpdateFailure,

		error)
	inject func(s26.MMEConfigurationUpdateFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationUpdateFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationUpdateFailureUnsuccessfulBinding) Codec() s26.MMEConfigurationUpdateFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s26.MMEConfigurationUpdateFailureValueCodec{}
	}
	return func() s26.MMEConfigurationUpdateFailureValueCodec {
		sealed := s26.MMEConfigurationUpdateFailureValueCodec{}
		*s26.BridgeMMEConfigurationUpdateFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s26.BridgeMMEConfigurationUpdateFailureValueCodecFieldDecode(&sealed) = b.decode
		*s26.BridgeMMEConfigurationUpdateFailureValueCodecFieldEncode(&sealed) = func(value s26.MMEConfigurationUpdateFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s26.BridgeMMEConfigurationUpdateFailureValueCodecFieldCapture(&sealed) = b.capture
		*s26.BridgeMMEConfigurationUpdateFailureValueCodecFieldCompare(&sealed) = b.compare
		*s26.BridgeMMEConfigurationUpdateFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b MMEConfigurationUpdateFailureUnsuccessfulBinding) Build(body s26.MMEConfigurationUpdateFailure,

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
	capture func(s27.S1RemovalFailure, aper.DecodeState,

	) (s27.S1RemovalFailure, aper.Snapshot,

	)
	compare func(s27.S1RemovalFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s27.S1RemovalFailure,

		*aper.DecodeBudget) (s21.ValidationReport, error)
	encode func(*s27.S1RemovalFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s27.S1RemovalFailure,

		error)
	inject func(s27.S1RemovalFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b S1RemovalFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1RemovalFailureUnsuccessfulBinding) Codec() s27.S1RemovalFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s27.S1RemovalFailureValueCodec{}
	}
	return func() s27.S1RemovalFailureValueCodec {
		sealed := s27.S1RemovalFailureValueCodec{}
		*s27.BridgeS1RemovalFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s27.BridgeS1RemovalFailureValueCodecFieldDecode(&sealed) = b.decode
		*s27.BridgeS1RemovalFailureValueCodecFieldEncode(&sealed) = func(value s27.S1RemovalFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s27.BridgeS1RemovalFailureValueCodecFieldCapture(&sealed) = b.capture
		*s27.BridgeS1RemovalFailureValueCodecFieldCompare(&sealed) = b.compare
		*s27.BridgeS1RemovalFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b S1RemovalFailureUnsuccessfulBinding) Build(body s27.S1RemovalFailure,

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
func BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEContainer(v *UEContextReleaseCommandIEContainer, s *aper.SemanticCapture) {
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
			BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEContainer(v *UEContextReleaseCommandIEContainer, s *aper.SemanticComparison) {
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
			BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEContainer(v *s24.UEContextResumeFailureIEContainer, s *aper.SemanticCapture) {
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
func BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEContainer(v *s24.UEContextResumeFailureIEContainer, s *aper.SemanticComparison) {
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
func BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEContainer(v *s29.UEContextSuspendResponseIEContainer, s *aper.SemanticCapture) {
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
func BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEContainer(v *s29.UEContextSuspendResponseIEContainer, s *aper.SemanticComparison) {
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
func BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEContainer(v *s24.UERadioCapabilityIDMappingResponseIEContainer, s *aper.SemanticCapture) {
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
func BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEContainer(v *s24.UERadioCapabilityIDMappingResponseIEContainer, s *aper.SemanticComparison) {
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
func BridgeUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.UESecurityCapabilitiesExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.UESecurityCapabilitiesExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.UESidelinkAggregateMaximumBitratesExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// UESecurityCapabilitiesValueCodec is the concrete ValueCodec[UESecurityCapabilities].
type UESecurityCapabilitiesValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UESecurityCapabilities,

		error)
	encode func(UESecurityCapabilities,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UESecurityCapabilities, aper.DecodeState,

	) (UESecurityCapabilities, aper.Snapshot,

	)
	compare func(UESecurityCapabilities, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UESecurityCapabilitiesValueCodec) New(value UESecurityCapabilities,

) (UESecurityCapabilitiesAPERValue, error) {
	if c.encode == nil {
		return UESecurityCapabilitiesAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UESecurityCapabilitiesAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UESecurityCapabilitiesAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UESecurityCapabilitiesAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UESecurityCapabilitiesValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UESecurityCapabilitiesAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UESecurityCapabilitiesAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UESecurityCapabilitiesAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UESecurityCapabilitiesAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UESecurityCapabilitiesAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UESecurityCapabilitiesValueCodec) EncodeAPER(value UESecurityCapabilitiesAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UESecurityCapabilitiesValueCodec) encodeBudgetValue(value UESecurityCapabilities,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UESecurityCapabilitiesValueCodec) encodeChanged(value UESecurityCapabilities,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCommandUES1APIDsIEBinding binds UES1APIDs to the UEContextReleaseCommand-IEs object set of TS 36.413.
type UEContextReleaseCommandUES1APIDsIEBinding struct {
	info   s00.FieldInfo
	codec  UES1APIDsValueCodec
	inject func(UES1APIDs,

	) UEContextReleaseCommandIEValue

	get func(*UEContextReleaseCommandIEValue,

	) (*UES1APIDs,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseCommandUES1APIDsIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseCommandUES1APIDsIEBinding) Codec() UES1APIDsValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b UEContextReleaseCommandUES1APIDsIEBinding) New(value UES1APIDs,

) (UEContextReleaseCommandIEField, error) {
	if b.inject == nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextReleaseCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextReleaseCommandUES1APIDsIEBinding) Get(field *UEContextReleaseCommandIEField) (*UES1APIDs,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UES1APIDsValueCodec is the concrete ValueCodec[UES1APIDs].
type UES1APIDsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UES1APIDs,

		error)
	encode func(UES1APIDs,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UES1APIDs, aper.DecodeState,

	) (UES1APIDs, aper.Snapshot,

	)
	compare func(UES1APIDs, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UES1APIDsValueCodec) New(value UES1APIDs,

) (UES1APIDsAPERValue, error) {
	if c.encode == nil {
		return UES1APIDsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UES1APIDsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UES1APIDsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UES1APIDsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UES1APIDsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UES1APIDsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UES1APIDsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UES1APIDsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UES1APIDsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UES1APIDsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UES1APIDsValueCodec) EncodeAPER(value UES1APIDsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UES1APIDsValueCodec) encodeBudgetValue(value UES1APIDs,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UES1APIDsValueCodec) encodeChanged(value UES1APIDs,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCommandCauseIEBinding binds Cause to the UEContextReleaseCommand-IEs object set of TS 36.413.
type UEContextReleaseCommandCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s14.CauseValueCodec
	inject func(s14.Cause,

	) UEContextReleaseCommandIEValue

	get func(*UEContextReleaseCommandIEValue,

	) (*s14.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseCommandCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseCommandCauseIEBinding) Codec() s14.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b UEContextReleaseCommandCauseIEBinding) New(value s14.Cause,

) (UEContextReleaseCommandIEField, error) {
	if b.inject == nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextReleaseCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextReleaseCommandCauseIEBinding) Get(field *UEContextReleaseCommandIEField) (*s14.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
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

// UEContextReleaseCommandValueCodec is the concrete ValueCodec[UEContextReleaseCommand].
type UEContextReleaseCommandValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseCommand,

		error)
	encode func(UEContextReleaseCommand,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseCommand, aper.DecodeState,

	) (UEContextReleaseCommand, aper.Snapshot,

	)
	compare func(UEContextReleaseCommand, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCommandValueCodec) New(value UEContextReleaseCommand,

) (UEContextReleaseCommandAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCommandAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCommandAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCommandAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCommandAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCommandValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCommandAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCommandAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCommandAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCommandAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCommandAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCommandValueCodec) EncodeAPER(value UEContextReleaseCommandAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextReleaseCommandValueCodec) encodeBudgetValue(value UEContextReleaseCommand,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCommandValueCodec) encodeChanged(value UEContextReleaseCommand,

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

// UES1APIDPairValueCodec is the concrete ValueCodec[UES1APIDPair].
type UES1APIDPairValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UES1APIDPair,

		error)
	encode func(UES1APIDPair,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UES1APIDPair, aper.DecodeState,

	) (UES1APIDPair, aper.Snapshot,

	)
	compare func(UES1APIDPair, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UES1APIDPairValueCodec) New(value UES1APIDPair,

) (UES1APIDPairAPERValue, error) {
	if c.encode == nil {
		return UES1APIDPairAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UES1APIDPairAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UES1APIDPairAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UES1APIDPairAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UES1APIDPairValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UES1APIDPairAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UES1APIDPairAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UES1APIDPairAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UES1APIDPairAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UES1APIDPairAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UES1APIDPairValueCodec) EncodeAPER(value UES1APIDPairAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UES1APIDPairValueCodec) encodeBudgetValue(value UES1APIDPair,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UES1APIDPairValueCodec) encodeChanged(value UES1APIDPair,

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
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
func BridgeUEContextReleaseCommandIEValueValidateS1APIEContainer(fields UEContextReleaseCommandIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
func BridgeUEContextSuspendResponseIEValueValidateS1APIEContainer(fields s29.UEContextSuspendResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s29.BridgeUEContextSuspendResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s29.BridgeUEContextSuspendResponseIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s29.BridgeUEContextSuspendResponseIEValueMethodRule(field.Value).Assignment
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
func BridgeUEContextResumeFailureIEValueValidateS1APIEContainer(fields s24.UEContextResumeFailureIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s24.BridgeUEContextResumeFailureIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s24.BridgeUEContextResumeFailureIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s24.BridgeUEContextResumeFailureIEValueMethodRule(field.Value).Assignment
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
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
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
func BridgeUERadioCapabilityIDMappingResponseIEValueValidateS1APIEContainer(fields s24.UERadioCapabilityIDMappingResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s24.BridgeUERadioCapabilityIDMappingResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s24.BridgeUERadioCapabilityIDMappingResponseIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s24.BridgeUERadioCapabilityIDMappingResponseIEValueMethodRule(field.Value).Assignment
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
func BridgeUES1APIDPairExtIEsValueValidateS1APExtensionContainer(fields s12.UES1APIDPairExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.UES1APIDPairExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s12.UES1APIDPairExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeUES1APIDPairExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeUESecurityCapabilitiesExtIEsValueValidateS1APExtensionContainer(fields s12.UESecurityCapabilitiesExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.UESecurityCapabilitiesExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s12.UESecurityCapabilitiesExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeUESecurityCapabilitiesExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// UEContextModificationIndicationIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEContextModificationIndicationIEs}} codec of TS 36.413.
func UEContextModificationIndicationIEValueERABIEContainerListCodec(table s00.UEContextModificationIndicationIEValueIETable) s21.UEContextModificationIndicationIEValueERABIEContainerListValueCodec {
	codec := UEContextModificationIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s21.BridgeUEContextModificationIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s21.UEContextModificationIndicationIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s21.UEContextModificationIndicationIEValueERABIEContainerListValueCodec {
		sealed := s21.UEContextModificationIndicationIEValueERABIEContainerListValueCodec{}
		*s21.BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.UEContextModificationIndicationIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s21.UEContextModificationIndicationIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s21.UEContextModificationIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s21.BridgeUEContextModificationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextModificationIndicationIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationIndicationIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextModificationIndicationIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s21.BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s21.UEContextModificationIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s21.BridgeUEContextModificationIndicationIEContainerValueCodecFieldEncode(&codec))(s21.UEContextModificationIndicationIEContainer(value), fresh, budget)
		}
		*s21.BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s21.UEContextModificationIndicationIEValueERABIEContainerList, options aper.DecodeState) (s21.UEContextModificationIndicationIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s21.BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s21.UEContextModificationIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
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

// UEContextModificationResponseIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEContextModificationResponseIEs}} codec of TS 36.413.
func UEContextModificationResponseIEValueERABIEContainerListCodec(table s00.UEContextModificationResponseIEValueIETable) s23.UEContextModificationResponseIEValueERABIEContainerListValueCodec {
	codec := UEContextModificationResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeUEContextModificationResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextModificationResponseIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s23.UEContextModificationResponseIEValueERABIEContainerListValueCodec {
		sealed := s23.UEContextModificationResponseIEValueERABIEContainerListValueCodec{}
		*s23.BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationResponseIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.UEContextModificationResponseIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.UEContextModificationResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgeUEContextModificationResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextModificationResponseIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationResponseIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextModificationResponseIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s23.BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UEContextModificationResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUEContextModificationResponseIEContainerValueCodecFieldEncode(&codec))(s23.UEContextModificationResponseIEContainer(value), fresh, budget)
		}
		*s23.BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationResponseIEValueERABIEContainerList, options aper.DecodeState) (s23.UEContextModificationResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s23.BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
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

// UEContextReleaseCommandIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEContextReleaseCommand-IEs}} codec of TS 36.413.
func UEContextReleaseCommandIEValueERABIEContainerListCodec(table s00.UEContextReleaseCommandIEValueIETable) UEContextReleaseCommandIEValueERABIEContainerListValueCodec {
	codec := UEContextReleaseCommandIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return UEContextReleaseCommandIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return UEContextReleaseCommandIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (UEContextReleaseCommandIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEContextReleaseCommandIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEContextReleaseCommandIEField
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
			return nil, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEContextReleaseCommandIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value UEContextReleaseCommandIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEContextReleaseCommandIEContainer(value), fresh, budget)
	}, capture: func(v UEContextReleaseCommandIEValueERABIEContainerList, options aper.DecodeState) (UEContextReleaseCommandIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextReleaseCommandIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v UEContextReleaseCommandIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEContextReleaseCommandIEValueCompareS1APERABIEContainerList(&v, &s)
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

// UEContextResumeFailureIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEContextResumeFailureIEs}} codec of TS 36.413.
func UEContextResumeFailureIEValueERABIEContainerListCodec(table s00.UEContextResumeFailureIEValueIETable) s24.UEContextResumeFailureIEValueERABIEContainerListValueCodec {
	codec := UEContextResumeFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s24.BridgeUEContextResumeFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UEContextResumeFailureIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s24.UEContextResumeFailureIEValueERABIEContainerListValueCodec {
		sealed := s24.UEContextResumeFailureIEValueERABIEContainerListValueCodec{}
		*s24.BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UEContextResumeFailureIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UEContextResumeFailureIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UEContextResumeFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUEContextResumeFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextResumeFailureIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextResumeFailureIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextResumeFailureIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s24.BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UEContextResumeFailureIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeUEContextResumeFailureIEContainerValueCodecFieldEncode(&codec))(s24.UEContextResumeFailureIEContainer(value), fresh, budget)
		}
		*s24.BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UEContextResumeFailureIEValueERABIEContainerList, options aper.DecodeState) (s24.UEContextResumeFailureIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s24.BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UEContextResumeFailureIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextSuspendResponseIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEContextSuspendResponseIEs}} codec of TS 36.413.
func UEContextSuspendResponseIEValueERABIEContainerListCodec(table s00.UEContextSuspendResponseIEValueIETable) s29.UEContextSuspendResponseIEValueERABIEContainerListValueCodec {
	codec := UEContextSuspendResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s29.BridgeUEContextSuspendResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s29.UEContextSuspendResponseIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s29.UEContextSuspendResponseIEValueERABIEContainerListValueCodec {
		sealed := s29.UEContextSuspendResponseIEValueERABIEContainerListValueCodec{}
		*s29.BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.UEContextSuspendResponseIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s29.UEContextSuspendResponseIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s29.UEContextSuspendResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s29.BridgeUEContextSuspendResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextSuspendResponseIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextSuspendResponseIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextSuspendResponseIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s29.BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s29.UEContextSuspendResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s29.BridgeUEContextSuspendResponseIEContainerValueCodecFieldEncode(&codec))(s29.UEContextSuspendResponseIEContainer(value), fresh, budget)
		}
		*s29.BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s29.UEContextSuspendResponseIEValueERABIEContainerList, options aper.DecodeState) (s29.UEContextSuspendResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s29.BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s29.UEContextSuspendResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEInformationTransferIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEInformationTransferIEs}} codec of TS 36.413.
func UEInformationTransferIEValueERABIEContainerListCodec(table s00.UEInformationTransferIEValueIETable) s31.UEInformationTransferIEValueERABIEContainerListValueCodec {
	codec := UEInformationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s31.BridgeUEInformationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s31.UEInformationTransferIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s31.UEInformationTransferIEValueERABIEContainerListValueCodec {
		sealed := s31.UEInformationTransferIEValueERABIEContainerListValueCodec{}
		*s31.BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.UEInformationTransferIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s31.UEInformationTransferIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s31.UEInformationTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s31.BridgeUEInformationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEInformationTransferIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEInformationTransferIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEInformationTransferIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s31.BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s31.UEInformationTransferIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s31.BridgeUEInformationTransferIEContainerValueCodecFieldEncode(&codec))(s31.UEInformationTransferIEContainer(value), fresh, budget)
		}
		*s31.BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s31.UEInformationTransferIEValueERABIEContainerList, options aper.DecodeState) (s31.UEInformationTransferIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s31.BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s31.UEInformationTransferIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
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

// UERadioCapabilityIDMappingRequestIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UERadioCapabilityIDMappingRequestIEs}} codec of TS 36.413.
func UERadioCapabilityIDMappingRequestIEValueERABIEContainerListCodec(table s00.UERadioCapabilityIDMappingRequestIEValueIETable) s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodec {
	codec := UERadioCapabilityIDMappingRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodec {
		sealed := s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodec{}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UERadioCapabilityIDMappingRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeUERadioCapabilityIDMappingRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingRequestIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityIDMappingRequestIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingRequestIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldEncode(&codec))(s12.UERadioCapabilityIDMappingRequestIEContainer(value), fresh, budget)
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList, options aper.DecodeState) (s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
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

// UERadioCapabilityIDMappingResponseIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UERadioCapabilityIDMappingResponseIEs}} codec of TS 36.413.
func UERadioCapabilityIDMappingResponseIEValueERABIEContainerListCodec(table s00.UERadioCapabilityIDMappingResponseIEValueIETable) s24.UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec {
	codec := UERadioCapabilityIDMappingResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s24.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s24.UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec {
		sealed := s24.UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec{}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UERadioCapabilityIDMappingResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponseIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityIDMappingResponseIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponseIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldEncode(&codec))(s24.UERadioCapabilityIDMappingResponseIEContainer(value), fresh, budget)
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, options aper.DecodeState) (s24.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityMatchRequestIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UERadioCapabilityMatchRequestIEs}} codec of TS 36.413.
func UERadioCapabilityMatchRequestIEValueERABIEContainerListCodec(table s00.UERadioCapabilityMatchRequestIEValueIETable) s12.UERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodec {
	codec := UERadioCapabilityMatchRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s12.UERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodec {
		sealed := s12.UERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodec{}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UERadioCapabilityMatchRequestIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UERadioCapabilityMatchRequestIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UERadioCapabilityMatchRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeUERadioCapabilityMatchRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityMatchRequestIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityMatchRequestIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityMatchRequestIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s12.UERadioCapabilityMatchRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s12.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldEncode(&codec))(s12.UERadioCapabilityMatchRequestIEContainer(value), fresh, budget)
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s12.UERadioCapabilityMatchRequestIEValueERABIEContainerList, options aper.DecodeState) (s12.UERadioCapabilityMatchRequestIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UERadioCapabilityMatchRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
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

// UERadioCapabilityMatchResponseIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UERadioCapabilityMatchResponseIEs}} codec of TS 36.413.
func UERadioCapabilityMatchResponseIEValueERABIEContainerListCodec(table s00.UERadioCapabilityMatchResponseIEValueIETable) s24.UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec {
	codec := UERadioCapabilityMatchResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s24.UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec {
		sealed := s24.UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec{}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UERadioCapabilityMatchResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUERadioCapabilityMatchResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponseIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityMatchResponseIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponseIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldEncode(&codec))(s24.UERadioCapabilityMatchResponseIEContainer(value), fresh, budget)
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
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

// UES1APIDPairExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{UE-S1AP-ID-pair-ExtIEs}} codec of TS 36.413.
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
				return field, runtime.WrapDecodePath(err, "UES1APIDPairExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UES1APIDPairExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UES1APIDPairExtIEsExtField")
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
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeUES1APIDPairExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.UES1APIDPairExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUES1APIDPairExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
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

// UESecurityCapabilitiesExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{UESecurityCapabilities-ExtIEs}} codec of TS 36.413.
func UESecurityCapabilitiesExtIEsValueExtensionFieldTableCodec(table s00.UESecurityCapabilitiesExtIEsValueExtensionTable) s12.UESecurityCapabilitiesExtIEsExtFieldValueCodec {
	if !*s00.BridgeUESecurityCapabilitiesExtIEsValueExtensionTableFieldBound(&table) {
		return s12.UESecurityCapabilitiesExtIEsExtFieldValueCodec{}
	}
	return func() s12.UESecurityCapabilitiesExtIEsExtFieldValueCodec {
		sealed := s12.UESecurityCapabilitiesExtIEsExtFieldValueCodec{}
		*s12.BridgeUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UESecurityCapabilitiesExtIEsExtField, error) {
			var field s12.UESecurityCapabilitiesExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeUESecurityCapabilitiesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UESecurityCapabilitiesExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UESecurityCapabilitiesExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UESecurityCapabilitiesExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgeUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.UESecurityCapabilitiesExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeUESecurityCapabilitiesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.UESecurityCapabilitiesExtIEsExtField, options aper.DecodeState) (s12.UESecurityCapabilitiesExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.UESecurityCapabilitiesExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUESecurityCapabilitiesExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UESidelinkAggregateMaximumBitratesExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{UE-Sidelink-Aggregate-MaximumBitrates-ExtIEs}} codec of TS 36.413.
func UESidelinkAggregateMaximumBitratesExtIEsValueExtensionFieldTableCodec(table s00.UESidelinkAggregateMaximumBitratesExtIEsValueExtensionTable) s12.UESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodec {
	if !*s00.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueExtensionTableFieldBound(&table) {
		return s12.UESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodec{}
	}
	return func() s12.UESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodec {
		sealed := s12.UESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodec{}
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UESidelinkAggregateMaximumBitratesExtIEsExtField, error) {
			var field s12.UESidelinkAggregateMaximumBitratesExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitratesExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UESidelinkAggregateMaximumBitratesExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitratesExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.UESidelinkAggregateMaximumBitratesExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.UESidelinkAggregateMaximumBitratesExtIEsExtField, options aper.DecodeState) (s12.UESidelinkAggregateMaximumBitratesExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.UESidelinkAggregateMaximumBitratesExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UES1APIDPairExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{UE-S1AP-ID-pair-ExtIEs}} codec of TS 36.413.
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
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeUES1APIDPairExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UES1APIDPairExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UES1APIDPairExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UES1APIDPairExtIEsExtContainer")
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
			f := s.Begin()
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

// UESecurityCapabilitiesExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{UESecurityCapabilities-ExtIEs}} codec of TS 36.413.
func UESecurityCapabilitiesExtIEsValueExtensionTableCodec(table s00.UESecurityCapabilitiesExtIEsValueExtensionTable, bounds aper.ListBounds) s12.UESecurityCapabilitiesExtIEsExtContainerValueCodec {
	if !*s00.BridgeUESecurityCapabilitiesExtIEsValueExtensionTableFieldBound(&table) {
		return s12.UESecurityCapabilitiesExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s12.UESecurityCapabilitiesExtIEsExtContainerValueCodec {
		sealed := s12.UESecurityCapabilitiesExtIEsExtContainerValueCodec{}
		*s12.BridgeUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UESecurityCapabilitiesExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UESecurityCapabilitiesExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UESecurityCapabilitiesExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeUESecurityCapabilitiesExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UESecurityCapabilitiesExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UESecurityCapabilitiesExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UESecurityCapabilitiesExtIEsExtContainer")
			}
			return fields, nil
		}
		*s12.BridgeUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s12.UESecurityCapabilitiesExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s12.BridgeUESecurityCapabilitiesExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s12.BridgeUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s12.UESecurityCapabilitiesExtIEsExtContainer, options aper.DecodeState) (s12.UESecurityCapabilitiesExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s12.BridgeUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s12.UESecurityCapabilitiesExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeUESecurityCapabilitiesExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationIndicationIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEContextModificationIndicationIEs}} codec of TS 36.413.
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
				return field, runtime.WrapDecodePath(err, "UEContextModificationIndicationIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationIndicationIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextModificationIndicationIEField")
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
			BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
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

// UEContextModificationResponseIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEContextModificationResponseIEs}} codec of TS 36.413.
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
				return field, runtime.WrapDecodePath(err, "UEContextModificationResponseIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationResponseIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextModificationResponseIEField")
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
			BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
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

// UEContextReleaseCommandIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEContextReleaseCommand-IEs}} codec of TS 36.413.
func UEContextReleaseCommandIEValueIEFieldTableCodec(table s00.UEContextReleaseCommandIEValueIETable) UEContextReleaseCommandIEFieldValueCodec {
	if !*s00.BridgeUEContextReleaseCommandIEValueIETableFieldBound(&table) {
		return UEContextReleaseCommandIEFieldValueCodec{}
	}
	return UEContextReleaseCommandIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (UEContextReleaseCommandIEField, error) {
		var field UEContextReleaseCommandIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEContextReleaseCommandIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEField")
		}
		return field, nil
	}, encode: func(field UEContextReleaseCommandIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v UEContextReleaseCommandIEField, options aper.DecodeState) (UEContextReleaseCommandIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v UEContextReleaseCommandIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEField(&v, &s)
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

// UEContextResumeFailureIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEContextResumeFailureIEs}} codec of TS 36.413.
func UEContextResumeFailureIEValueIEFieldTableCodec(table s00.UEContextResumeFailureIEValueIETable) s24.UEContextResumeFailureIEFieldValueCodec {
	if !*s00.BridgeUEContextResumeFailureIEValueIETableFieldBound(&table) {
		return s24.UEContextResumeFailureIEFieldValueCodec{}
	}
	return func() s24.UEContextResumeFailureIEFieldValueCodec {
		sealed := s24.UEContextResumeFailureIEFieldValueCodec{}
		*s24.BridgeUEContextResumeFailureIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UEContextResumeFailureIEField, error) {
			var field s24.UEContextResumeFailureIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s24.BridgeUEContextResumeFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextResumeFailureIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextResumeFailureIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextResumeFailureIEField")
			}
			return field, nil
		}
		*s24.BridgeUEContextResumeFailureIEFieldValueCodecFieldEncode(&sealed) = func(field s24.UEContextResumeFailureIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s24.BridgeUEContextResumeFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s24.BridgeUEContextResumeFailureIEFieldValueCodecFieldCapture(&sealed) = func(v s24.UEContextResumeFailureIEField, options aper.DecodeState) (s24.UEContextResumeFailureIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgeUEContextResumeFailureIEFieldValueCodecFieldCompare(&sealed) = func(v s24.UEContextResumeFailureIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUEContextResumeFailureIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextSuspendResponseIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEContextSuspendResponseIEs}} codec of TS 36.413.
func UEContextSuspendResponseIEValueIEFieldTableCodec(table s00.UEContextSuspendResponseIEValueIETable) s29.UEContextSuspendResponseIEFieldValueCodec {
	if !*s00.BridgeUEContextSuspendResponseIEValueIETableFieldBound(&table) {
		return s29.UEContextSuspendResponseIEFieldValueCodec{}
	}
	return func() s29.UEContextSuspendResponseIEFieldValueCodec {
		sealed := s29.UEContextSuspendResponseIEFieldValueCodec{}
		*s29.BridgeUEContextSuspendResponseIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.UEContextSuspendResponseIEField, error) {
			var field s29.UEContextSuspendResponseIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s29.BridgeUEContextSuspendResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextSuspendResponseIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextSuspendResponseIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextSuspendResponseIEField")
			}
			return field, nil
		}
		*s29.BridgeUEContextSuspendResponseIEFieldValueCodecFieldEncode(&sealed) = func(field s29.UEContextSuspendResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s29.BridgeUEContextSuspendResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s29.BridgeUEContextSuspendResponseIEFieldValueCodecFieldCapture(&sealed) = func(v s29.UEContextSuspendResponseIEField, options aper.DecodeState) (s29.UEContextSuspendResponseIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s29.BridgeUEContextSuspendResponseIEFieldValueCodecFieldCompare(&sealed) = func(v s29.UEContextSuspendResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeUEContextSuspendResponseIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEInformationTransferIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEInformationTransferIEs}} codec of TS 36.413.
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
				return field, runtime.WrapDecodePath(err, "UEInformationTransferIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEInformationTransferIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UEInformationTransferIEField")
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
			BridgeUEInformationTransferIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
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

// UERadioCapabilityIDMappingRequestIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UERadioCapabilityIDMappingRequestIEs}} codec of TS 36.413.
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
				return field, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingRequestIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityIDMappingRequestIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingRequestIEField")
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
			BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
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

// UERadioCapabilityIDMappingResponseIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UERadioCapabilityIDMappingResponseIEs}} codec of TS 36.413.
func UERadioCapabilityIDMappingResponseIEValueIEFieldTableCodec(table s00.UERadioCapabilityIDMappingResponseIEValueIETable) s24.UERadioCapabilityIDMappingResponseIEFieldValueCodec {
	if !*s00.BridgeUERadioCapabilityIDMappingResponseIEValueIETableFieldBound(&table) {
		return s24.UERadioCapabilityIDMappingResponseIEFieldValueCodec{}
	}
	return func() s24.UERadioCapabilityIDMappingResponseIEFieldValueCodec {
		sealed := s24.UERadioCapabilityIDMappingResponseIEFieldValueCodec{}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UERadioCapabilityIDMappingResponseIEField, error) {
			var field s24.UERadioCapabilityIDMappingResponseIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s24.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponseIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityIDMappingResponseIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponseIEField")
			}
			return field, nil
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldEncode(&sealed) = func(field s24.UERadioCapabilityIDMappingResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s24.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldCapture(&sealed) = func(v s24.UERadioCapabilityIDMappingResponseIEField, options aper.DecodeState) (s24.UERadioCapabilityIDMappingResponseIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldCompare(&sealed) = func(v s24.UERadioCapabilityIDMappingResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityMatchRequestIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UERadioCapabilityMatchRequestIEs}} codec of TS 36.413.
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
				return field, runtime.WrapDecodePath(err, "UERadioCapabilityMatchRequestIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityMatchRequestIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UERadioCapabilityMatchRequestIEField")
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
			BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
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

// UERadioCapabilityMatchResponseIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UERadioCapabilityMatchResponseIEs}} codec of TS 36.413.
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
				return field, runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponseIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityMatchResponseIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponseIEField")
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
			BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
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

// UEContextModificationIndicationIEValueIETableCodec constructs the ProtocolIE-Container {{UEContextModificationIndicationIEs}} codec of TS 36.413.
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
					mark := bb.EnterIndex(int64(len(fields)))
					err := s21.BridgeUEContextModificationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextModificationIndicationIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationIndicationIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextModificationIndicationIEContainer")
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
			s.End(f, &root,

				false)
			return v, root
		}
		*s21.BridgeUEContextModificationIndicationIEContainerValueCodecFieldCompare(&sealed) = func(v s21.UEContextModificationIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
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

// UEContextModificationResponseIEValueIETableCodec constructs the ProtocolIE-Container {{UEContextModificationResponseIEs}} codec of TS 36.413.
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
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgeUEContextModificationResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextModificationResponseIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationResponseIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextModificationResponseIEContainer")
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
			s.End(f, &root,

				false)
			return v, root
		}
		*s23.BridgeUEContextModificationResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
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

// UEContextReleaseCommandIEValueIETableCodec constructs the ProtocolIE-Container {{UEContextReleaseCommand-IEs}} codec of TS 36.413.
func UEContextReleaseCommandIEValueIETableCodec(table s00.UEContextReleaseCommandIEValueIETable, bounds aper.ListBounds) UEContextReleaseCommandIEContainerValueCodec {
	if !*s00.BridgeUEContextReleaseCommandIEValueIETableFieldBound(&table) {
		return UEContextReleaseCommandIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return UEContextReleaseCommandIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (UEContextReleaseCommandIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEContextReleaseCommandIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEContextReleaseCommandIEField
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
			return nil, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEContextReleaseCommandIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEContainer")
		}
		return fields, nil
	},
		encode: func(fields UEContextReleaseCommandIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		}, capture: func(v UEContextReleaseCommandIEContainer, options aper.DecodeState) (UEContextReleaseCommandIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v UEContextReleaseCommandIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEContainer(&v, &s)
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

// UEContextResumeFailureIEValueIETableCodec constructs the ProtocolIE-Container {{UEContextResumeFailureIEs}} codec of TS 36.413.
func UEContextResumeFailureIEValueIETableCodec(table s00.UEContextResumeFailureIEValueIETable, bounds aper.ListBounds) s24.UEContextResumeFailureIEContainerValueCodec {
	if !*s00.BridgeUEContextResumeFailureIEValueIETableFieldBound(&table) {
		return s24.UEContextResumeFailureIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s24.UEContextResumeFailureIEContainerValueCodec {
		sealed := s24.UEContextResumeFailureIEContainerValueCodec{}
		*s24.BridgeUEContextResumeFailureIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UEContextResumeFailureIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UEContextResumeFailureIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UEContextResumeFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUEContextResumeFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextResumeFailureIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextResumeFailureIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextResumeFailureIEContainer")
			}
			return fields, nil
		}
		*s24.BridgeUEContextResumeFailureIEContainerValueCodecFieldEncode(&sealed) = func(fields s24.UEContextResumeFailureIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s24.BridgeUEContextResumeFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s24.BridgeUEContextResumeFailureIEContainerValueCodecFieldCapture(&sealed) = func(v s24.UEContextResumeFailureIEContainer, options aper.DecodeState) (s24.UEContextResumeFailureIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s24.BridgeUEContextResumeFailureIEContainerValueCodecFieldCompare(&sealed) = func(v s24.UEContextResumeFailureIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUEContextResumeFailureIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextSuspendResponseIEValueIETableCodec constructs the ProtocolIE-Container {{UEContextSuspendResponseIEs}} codec of TS 36.413.
func UEContextSuspendResponseIEValueIETableCodec(table s00.UEContextSuspendResponseIEValueIETable, bounds aper.ListBounds) s29.UEContextSuspendResponseIEContainerValueCodec {
	if !*s00.BridgeUEContextSuspendResponseIEValueIETableFieldBound(&table) {
		return s29.UEContextSuspendResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s29.UEContextSuspendResponseIEContainerValueCodec {
		sealed := s29.UEContextSuspendResponseIEContainerValueCodec{}
		*s29.BridgeUEContextSuspendResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.UEContextSuspendResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s29.UEContextSuspendResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s29.UEContextSuspendResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s29.BridgeUEContextSuspendResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextSuspendResponseIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextSuspendResponseIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextSuspendResponseIEContainer")
			}
			return fields, nil
		}
		*s29.BridgeUEContextSuspendResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s29.UEContextSuspendResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s29.BridgeUEContextSuspendResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s29.BridgeUEContextSuspendResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s29.UEContextSuspendResponseIEContainer, options aper.DecodeState) (s29.UEContextSuspendResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s29.BridgeUEContextSuspendResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s29.UEContextSuspendResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeUEContextSuspendResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEInformationTransferIEValueIETableCodec constructs the ProtocolIE-Container {{UEInformationTransferIEs}} codec of TS 36.413.
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
					mark := bb.EnterIndex(int64(len(fields)))
					err := s31.BridgeUEInformationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEInformationTransferIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEInformationTransferIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEInformationTransferIEContainer")
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
			s.End(f, &root,

				false)
			return v, root
		}
		*s31.BridgeUEInformationTransferIEContainerValueCodecFieldCompare(&sealed) = func(v s31.UEInformationTransferIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
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

// UERadioCapabilityIDMappingRequestIEValueIETableCodec constructs the ProtocolIE-Container {{UERadioCapabilityIDMappingRequestIEs}} codec of TS 36.413.
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
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeUERadioCapabilityIDMappingRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingRequestIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityIDMappingRequestIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingRequestIEContainer")
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
			s.End(f, &root,

				false)
			return v, root
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldCompare(&sealed) = func(v s12.UERadioCapabilityIDMappingRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
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

// UERadioCapabilityIDMappingResponseIEValueIETableCodec constructs the ProtocolIE-Container {{UERadioCapabilityIDMappingResponseIEs}} codec of TS 36.413.
func UERadioCapabilityIDMappingResponseIEValueIETableCodec(table s00.UERadioCapabilityIDMappingResponseIEValueIETable, bounds aper.ListBounds) s24.UERadioCapabilityIDMappingResponseIEContainerValueCodec {
	if !*s00.BridgeUERadioCapabilityIDMappingResponseIEValueIETableFieldBound(&table) {
		return s24.UERadioCapabilityIDMappingResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s24.UERadioCapabilityIDMappingResponseIEContainerValueCodec {
		sealed := s24.UERadioCapabilityIDMappingResponseIEContainerValueCodec{}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UERadioCapabilityIDMappingResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UERadioCapabilityIDMappingResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UERadioCapabilityIDMappingResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponseIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityIDMappingResponseIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponseIEContainer")
			}
			return fields, nil
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s24.UERadioCapabilityIDMappingResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s24.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s24.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s24.UERadioCapabilityIDMappingResponseIEContainer, options aper.DecodeState) (s24.UERadioCapabilityIDMappingResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s24.UERadioCapabilityIDMappingResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityMatchRequestIEValueIETableCodec constructs the ProtocolIE-Container {{UERadioCapabilityMatchRequestIEs}} codec of TS 36.413.
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
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeUERadioCapabilityMatchRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityMatchRequestIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityMatchRequestIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityMatchRequestIEContainer")
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
			s.End(f, &root,

				false)
			return v, root
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldCompare(&sealed) = func(v s12.UERadioCapabilityMatchRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
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

// UERadioCapabilityMatchResponseIEValueIETableCodec constructs the ProtocolIE-Container {{UERadioCapabilityMatchResponseIEs}} codec of TS 36.413.
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
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUERadioCapabilityMatchResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponseIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityMatchResponseIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponseIEContainer")
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
			s.End(f, &root,

				false)
			return v, root
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
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

// UEContextModificationFailureIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEContextModificationFailureIEs}} codec of TS 36.413.
func UEContextModificationFailureIEValueProtocolErrorIEContainerListCodec(table s00.UEContextModificationFailureIEValueIETable) s23.UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec {
	codec := s36.UEContextModificationFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s23.UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s23.UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec{}
		*s23.BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationFailureIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.UEContextModificationFailureIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.UEContextModificationFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgeUEContextModificationFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextModificationFailureIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationFailureIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextModificationFailureIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s23.BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UEContextModificationFailureIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldEncode(&codec))(s23.UEContextModificationFailureIEContainer(value), fresh, budget)
		}
		*s23.BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationFailureIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s23.UEContextModificationFailureIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeUEContextModificationFailureIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s23.BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationFailureIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s36.BridgeUEContextModificationFailureIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
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

// UEContextModificationIndicationIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEContextModificationIndicationIEs}} codec of TS 36.413.
func UEContextModificationIndicationIEValueProtocolErrorIEContainerListCodec(table s00.UEContextModificationIndicationIEValueIETable) s21.UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextModificationIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s21.BridgeUEContextModificationIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s21.UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s21.UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s21.UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec{}
		*s21.BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.UEContextModificationIndicationIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s21.UEContextModificationIndicationIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s21.UEContextModificationIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s21.BridgeUEContextModificationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextModificationIndicationIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationIndicationIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextModificationIndicationIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
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
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
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

// UEContextModificationResponseIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEContextModificationResponseIEs}} codec of TS 36.413.
func UEContextModificationResponseIEValueProtocolErrorIEContainerListCodec(table s00.UEContextModificationResponseIEValueIETable) s23.UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextModificationResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s23.BridgeUEContextModificationResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s23.UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s23.UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s23.BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationResponseIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.UEContextModificationResponseIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.UEContextModificationResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgeUEContextModificationResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextModificationResponseIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationResponseIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextModificationResponseIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
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
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
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

// UEContextReleaseCommandIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEContextReleaseCommand-IEs}} codec of TS 36.413.
func UEContextReleaseCommandIEValueProtocolErrorIEContainerListCodec(table s00.UEContextReleaseCommandIEValueIETable) UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextReleaseCommandIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (UEContextReleaseCommandIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEContextReleaseCommandIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEContextReleaseCommandIEField
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
			return nil, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEContextReleaseCommandIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value UEContextReleaseCommandIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEContextReleaseCommandIEContainer(value), fresh, budget)
	}, capture: func(v UEContextReleaseCommandIEValueProtocolErrorIEContainerList, options aper.DecodeState) (UEContextReleaseCommandIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v UEContextReleaseCommandIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeUEContextReleaseCommandIEValueCompareS1APProtocolErrorIEContainerList(
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

// UEContextResumeFailureIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEContextResumeFailureIEs}} codec of TS 36.413.
func UEContextResumeFailureIEValueProtocolErrorIEContainerListCodec(table s00.UEContextResumeFailureIEValueIETable) s24.UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextResumeFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s24.BridgeUEContextResumeFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s24.UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s24.UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec{}
		*s24.BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UEContextResumeFailureIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UEContextResumeFailureIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UEContextResumeFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUEContextResumeFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextResumeFailureIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextResumeFailureIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextResumeFailureIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s24.BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UEContextResumeFailureIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeUEContextResumeFailureIEContainerValueCodecFieldEncode(&codec))(s24.UEContextResumeFailureIEContainer(value), fresh, budget)
		}
		*s24.BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UEContextResumeFailureIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s24.UEContextResumeFailureIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UEContextResumeFailureIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextSuspendResponseIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEContextSuspendResponseIEs}} codec of TS 36.413.
func UEContextSuspendResponseIEValueProtocolErrorIEContainerListCodec(table s00.UEContextSuspendResponseIEValueIETable) s29.UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextSuspendResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s29.BridgeUEContextSuspendResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s29.UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s29.UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s29.UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s29.BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s29.UEContextSuspendResponseIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s29.UEContextSuspendResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s29.BridgeUEContextSuspendResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextSuspendResponseIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextSuspendResponseIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextSuspendResponseIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s29.BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s29.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s29.BridgeUEContextSuspendResponseIEContainerValueCodecFieldEncode(&codec))(s29.UEContextSuspendResponseIEContainer(value), fresh, budget)
		}
		*s29.BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s29.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s29.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s29.BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s29.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEInformationTransferIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEInformationTransferIEs}} codec of TS 36.413.
func UEInformationTransferIEValueProtocolErrorIEContainerListCodec(table s00.UEInformationTransferIEValueIETable) s31.UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEInformationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s31.BridgeUEInformationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s31.UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s31.UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s31.UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec{}
		*s31.BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.UEInformationTransferIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s31.UEInformationTransferIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s31.UEInformationTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s31.BridgeUEInformationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEInformationTransferIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEInformationTransferIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEInformationTransferIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
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
			f := s.Begin()
			BridgeUEInformationTransferIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
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

// UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UERadioCapabilityIDMappingRequestIEs}} codec of TS 36.413.
func UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListCodec(table s00.UERadioCapabilityIDMappingRequestIEValueIETable) s12.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := UERadioCapabilityIDMappingRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s12.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s12.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodec{}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UERadioCapabilityIDMappingRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeUERadioCapabilityIDMappingRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
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
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
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

// UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UERadioCapabilityIDMappingResponseIEs}} codec of TS 36.413.
func UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListCodec(table s00.UERadioCapabilityIDMappingResponseIEValueIETable) s24.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := UERadioCapabilityIDMappingResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s24.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s24.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s24.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UERadioCapabilityIDMappingResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldEncode(&codec))(s24.UERadioCapabilityIDMappingResponseIEContainer(value), fresh, budget)
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s24.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
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

// UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UERadioCapabilityMatchRequestIEs}} codec of TS 36.413.
func UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListCodec(table s00.UERadioCapabilityMatchRequestIEValueIETable) s12.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := UERadioCapabilityMatchRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s12.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s12.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s12.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodec{}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UERadioCapabilityMatchRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeUERadioCapabilityMatchRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
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
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
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

// UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UERadioCapabilityMatchResponseIEs}} codec of TS 36.413.
func UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListCodec(table s00.UERadioCapabilityMatchResponseIEValueIETable) s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := UERadioCapabilityMatchResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UERadioCapabilityMatchResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUERadioCapabilityMatchResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
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
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
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

// UEContextModificationFailureIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextModificationFailureIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextModificationFailureIEValueProtocolIEContainerListCodec(table s00.UEContextModificationFailureIEValueIETable, bounds aper.ListBounds) s23.UEContextModificationFailureIEValueProtocolIEContainerListValueCodec {
	codec := s36.UEContextModificationFailureIEValueIETableCodec(table, bounds)
	if *s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextModificationFailureIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s23.UEContextModificationFailureIEValueProtocolIEContainerListValueCodec {
		sealed := s23.UEContextModificationFailureIEValueProtocolIEContainerListValueCodec{}
		*s23.BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationFailureIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.UEContextModificationFailureIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.UEContextModificationFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgeUEContextModificationFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextModificationFailureIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationFailureIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextModificationFailureIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s23.BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s23.UEContextModificationFailureIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s23.BridgeUEContextModificationFailureIEContainerValueCodecFieldEncode(&codec))(s23.UEContextModificationFailureIEContainer(value), fresh, budget)
		}
		*s23.BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s23.UEContextModificationFailureIEValueProtocolIEContainerList, options aper.DecodeState) (s23.UEContextModificationFailureIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s23.BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationFailureIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
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

// UEContextModificationIndicationIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextModificationIndicationIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextModificationIndicationIEValueProtocolIEContainerListCodec(table s00.UEContextModificationIndicationIEValueIETable, bounds aper.ListBounds) s21.UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec {
	codec := UEContextModificationIndicationIEValueIETableCodec(table, bounds)
	if *s21.BridgeUEContextModificationIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s21.UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s21.UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec {
		sealed := s21.UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec{}
		*s21.BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s21.UEContextModificationIndicationIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s21.UEContextModificationIndicationIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s21.UEContextModificationIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s21.BridgeUEContextModificationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextModificationIndicationIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationIndicationIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextModificationIndicationIEValueProtocolIEContainerList")
			}
			return fields, nil
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
			s.
				End(f, &root, false)
			return v, root
		}
		*s21.BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s21.UEContextModificationIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
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

// UEContextModificationResponseIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextModificationResponseIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextModificationResponseIEValueProtocolIEContainerListCodec(table s00.UEContextModificationResponseIEValueIETable, bounds aper.ListBounds) s23.UEContextModificationResponseIEValueProtocolIEContainerListValueCodec {
	codec := UEContextModificationResponseIEValueIETableCodec(table, bounds)
	if *s23.BridgeUEContextModificationResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s23.UEContextModificationResponseIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s23.UEContextModificationResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s23.UEContextModificationResponseIEValueProtocolIEContainerListValueCodec{}
		*s23.BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s23.UEContextModificationResponseIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s23.UEContextModificationResponseIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s23.UEContextModificationResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s23.BridgeUEContextModificationResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextModificationResponseIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationResponseIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextModificationResponseIEValueProtocolIEContainerList")
			}
			return fields, nil
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
			s.
				End(f, &root, false)
			return v, root
		}
		*s23.BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s23.UEContextModificationResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUEContextModificationResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
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

// UEContextReleaseCommandIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextReleaseCommand-IEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextReleaseCommandIEValueProtocolIEContainerListCodec(table s00.UEContextReleaseCommandIEValueIETable, bounds aper.ListBounds) UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec {
	codec := UEContextReleaseCommandIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (UEContextReleaseCommandIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields UEContextReleaseCommandIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field UEContextReleaseCommandIEField
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
			return nil, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "UEContextReleaseCommandIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "UEContextReleaseCommandIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value UEContextReleaseCommandIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(UEContextReleaseCommandIEContainer(value), fresh, budget)
	}, capture: func(v UEContextReleaseCommandIEValueProtocolIEContainerList, options aper.DecodeState) (UEContextReleaseCommandIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v UEContextReleaseCommandIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEContainerList(&v, &s)
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

// UEContextResumeFailureIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextResumeFailureIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextResumeFailureIEValueProtocolIEContainerListCodec(table s00.UEContextResumeFailureIEValueIETable, bounds aper.ListBounds) s24.UEContextResumeFailureIEValueProtocolIEContainerListValueCodec {
	codec := UEContextResumeFailureIEValueIETableCodec(table, bounds)
	if *s24.BridgeUEContextResumeFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UEContextResumeFailureIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s24.UEContextResumeFailureIEValueProtocolIEContainerListValueCodec {
		sealed := s24.UEContextResumeFailureIEValueProtocolIEContainerListValueCodec{}
		*s24.BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UEContextResumeFailureIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UEContextResumeFailureIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UEContextResumeFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUEContextResumeFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextResumeFailureIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextResumeFailureIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextResumeFailureIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s24.BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UEContextResumeFailureIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeUEContextResumeFailureIEContainerValueCodecFieldEncode(&codec))(s24.UEContextResumeFailureIEContainer(value), fresh, budget)
		}
		*s24.BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UEContextResumeFailureIEValueProtocolIEContainerList, options aper.DecodeState) (s24.UEContextResumeFailureIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s24.BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UEContextResumeFailureIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextSuspendResponseIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextSuspendResponseIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextSuspendResponseIEValueProtocolIEContainerListCodec(table s00.UEContextSuspendResponseIEValueIETable, bounds aper.ListBounds) s29.UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec {
	codec := UEContextSuspendResponseIEValueIETableCodec(table, bounds)
	if *s29.BridgeUEContextSuspendResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s29.UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s29.UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s29.UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec{}
		*s29.BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.UEContextSuspendResponseIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s29.UEContextSuspendResponseIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s29.UEContextSuspendResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s29.BridgeUEContextSuspendResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextSuspendResponseIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextSuspendResponseIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextSuspendResponseIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s29.BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s29.UEContextSuspendResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s29.BridgeUEContextSuspendResponseIEContainerValueCodecFieldEncode(&codec))(s29.UEContextSuspendResponseIEContainer(value), fresh, budget)
		}
		*s29.BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s29.UEContextSuspendResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s29.UEContextSuspendResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s29.BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s29.UEContextSuspendResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s29.BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEInformationTransferIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEInformationTransferIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEInformationTransferIEValueProtocolIEContainerListCodec(table s00.UEInformationTransferIEValueIETable, bounds aper.ListBounds) s31.UEInformationTransferIEValueProtocolIEContainerListValueCodec {
	codec := UEInformationTransferIEValueIETableCodec(table, bounds)
	if *s31.BridgeUEInformationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s31.UEInformationTransferIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s31.UEInformationTransferIEValueProtocolIEContainerListValueCodec {
		sealed := s31.UEInformationTransferIEValueProtocolIEContainerListValueCodec{}
		*s31.BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.UEInformationTransferIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s31.UEInformationTransferIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s31.UEInformationTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s31.BridgeUEInformationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEInformationTransferIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEInformationTransferIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEInformationTransferIEValueProtocolIEContainerList")
			}
			return fields, nil
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
			s.
				End(f, &root, false)
			return v, root
		}
		*s31.BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s31.UEInformationTransferIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUEInformationTransferIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
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

// UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UERadioCapabilityIDMappingRequestIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListCodec(table s00.UERadioCapabilityIDMappingRequestIEValueIETable, bounds aper.ListBounds) s12.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodec {
	codec := UERadioCapabilityIDMappingRequestIEValueIETableCodec(table, bounds)
	if *s12.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s12.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodec {
		sealed := s12.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodec{}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UERadioCapabilityIDMappingRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeUERadioCapabilityIDMappingRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList")
			}
			return fields, nil
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
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
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

// UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UERadioCapabilityIDMappingResponseIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListCodec(table s00.UERadioCapabilityIDMappingResponseIEValueIETable, bounds aper.ListBounds) s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec {
	codec := UERadioCapabilityIDMappingResponseIEValueIETableCodec(table, bounds)
	if *s24.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec{}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UERadioCapabilityIDMappingResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldEncode(&codec))(s24.UERadioCapabilityIDMappingResponseIEContainer(value), fresh, budget)
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s24.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
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

// UERadioCapabilityMatchRequestIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UERadioCapabilityMatchRequestIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UERadioCapabilityMatchRequestIEValueProtocolIEContainerListCodec(table s00.UERadioCapabilityMatchRequestIEValueIETable, bounds aper.ListBounds) s12.UERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodec {
	codec := UERadioCapabilityMatchRequestIEValueIETableCodec(table, bounds)
	if *s12.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s12.UERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s12.UERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodec {
		sealed := s12.UERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodec{}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.UERadioCapabilityMatchRequestIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s12.UERadioCapabilityMatchRequestIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s12.UERadioCapabilityMatchRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s12.BridgeUERadioCapabilityMatchRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityMatchRequestIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityMatchRequestIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityMatchRequestIEValueProtocolIEContainerList")
			}
			return fields, nil
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
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeUERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s12.UERadioCapabilityMatchRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
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

// UERadioCapabilityMatchResponseIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UERadioCapabilityMatchResponseIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UERadioCapabilityMatchResponseIEValueProtocolIEContainerListCodec(table s00.UERadioCapabilityMatchResponseIEValueIETable, bounds aper.ListBounds) s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec {
	codec := UERadioCapabilityMatchResponseIEValueIETableCodec(table, bounds)
	if *s24.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec{}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UERadioCapabilityMatchResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUERadioCapabilityMatchResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponseIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityMatchResponseIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponseIEValueProtocolIEContainerList")
			}
			return fields, nil
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
			s.
				End(f, &root, false)
			return v, root
		}
		*s24.BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
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

// uEContextReleaseCommandIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextReleaseCommandIEValue].
type UEContextReleaseCommandIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) UEContextReleaseCommandIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (UEContextReleaseCommandIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEField(v *UEContextReleaseCommandIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEField(v *UEContextReleaseCommandIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// uEContextResumeFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextResumeFailureIEValue].
type UEContextResumeFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s24.UEContextResumeFailureIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s24.UEContextResumeFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEField(v *s24.UEContextResumeFailureIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s24.BridgeUEContextResumeFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s24.BridgeUEContextResumeFailureIEFieldFieldReplay(v), *s24.BridgeUEContextResumeFailureIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEField(v *s24.UEContextResumeFailureIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s24.BridgeUEContextResumeFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s24.BridgeUEContextResumeFailureIEFieldFieldReplay(v), *s24.BridgeUEContextResumeFailureIEFieldFieldWithoutReplay(v))
}

// uEContextSuspendResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextSuspendResponseIEValue].
type UEContextSuspendResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s29.UEContextSuspendResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s29.UEContextSuspendResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEField(v *s29.UEContextSuspendResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s29.BridgeUEContextSuspendResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s29.BridgeUEContextSuspendResponseIEFieldFieldReplay(v), *s29.BridgeUEContextSuspendResponseIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEField(v *s29.UEContextSuspendResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s29.BridgeUEContextSuspendResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s29.BridgeUEContextSuspendResponseIEFieldFieldReplay(v), *s29.BridgeUEContextSuspendResponseIEFieldFieldWithoutReplay(v))
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
	captureSemantics(aper.SemanticCapture) s24.UERadioCapabilityIDMappingResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s24.UERadioCapabilityIDMappingResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEField(v *s24.UERadioCapabilityIDMappingResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s24.BridgeUERadioCapabilityIDMappingResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s24.BridgeUERadioCapabilityIDMappingResponseIEFieldFieldReplay(v), *s24.BridgeUERadioCapabilityIDMappingResponseIEFieldFieldWithoutReplay(v))
}
func BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEField(v *s24.UERadioCapabilityIDMappingResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s24.BridgeUERadioCapabilityIDMappingResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s24.BridgeUERadioCapabilityIDMappingResponseIEFieldFieldReplay(v), *s24.BridgeUERadioCapabilityIDMappingResponseIEFieldFieldWithoutReplay(v))
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

// uES1APIDPairExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[UES1APIDPairExtIEsValue].
type UES1APIDPairExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.UES1APIDPairExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.UES1APIDPairExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
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

// uESecurityCapabilitiesExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[UESecurityCapabilitiesExtIEsValue].
type UESecurityCapabilitiesExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.UESecurityCapabilitiesExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.UESecurityCapabilitiesExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionField(v *s12.UESecurityCapabilitiesExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeUESecurityCapabilitiesExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeUESecurityCapabilitiesExtIEsExtFieldFieldReplay(v), *s12.BridgeUESecurityCapabilitiesExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionField(v *s12.UESecurityCapabilitiesExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeUESecurityCapabilitiesExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeUESecurityCapabilitiesExtIEsExtFieldFieldReplay(v), *s12.BridgeUESecurityCapabilitiesExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCaptureS1APProtocolExtensionField(v *s12.UESidelinkAggregateMaximumBitratesExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldFieldReplay(v), *s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeUESidelinkAggregateMaximumBitratesExtIEsValueCompareS1APProtocolExtensionField(v *s12.UESidelinkAggregateMaximumBitratesExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeUESidelinkAggregateMaximumBitratesExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldFieldReplay(v), *s12.BridgeUESidelinkAggregateMaximumBitratesExtIEsExtFieldFieldWithoutReplay(v))
}

// UESecurityCapabilitiesAPERValue is the concrete APERValue[UESecurityCapabilities].
type UESecurityCapabilitiesAPERValue struct {
	context s00.BridgeCodecContext
	Value   UESecurityCapabilities

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UESecurityCapabilitiesAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UESecurityCapabilitiesAPERValue) WithoutReplay() UESecurityCapabilitiesAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UES1APIDsAPERValue is the concrete APERValue[UES1APIDs].
type UES1APIDsAPERValue struct {
	context s00.BridgeCodecContext
	Value   UES1APIDs

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UES1APIDsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UES1APIDsAPERValue) WithoutReplay() UES1APIDsAPERValue {
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

// UEContextReleaseCommandAPERValue is the concrete APERValue[UEContextReleaseCommand].
type UEContextReleaseCommandAPERValue struct {
	context s00.BridgeCodecContext
	Value   UEContextReleaseCommand

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCommandAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCommandAPERValue) WithoutReplay() UEContextReleaseCommandAPERValue {
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

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeUES1APIDPairExtIEsValueValidateS1APIEContainer(fields s12.UES1APIDPairExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeUES1APIDPairExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeUES1APIDPairExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeUES1APIDPairExtIEsValueMethodRule(field.Value).Assignment
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
func BridgeUESecurityCapabilitiesExtIEsValueValidateS1APIEContainer(fields s12.UESecurityCapabilitiesExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeUESecurityCapabilitiesExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeUESecurityCapabilitiesExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeUESecurityCapabilitiesExtIEsValueMethodRule(field.Value).Assignment
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

// UEContextReleaseCommandIEValueERABIEContainerListValueCodec is the concrete ValueCodec[UEContextReleaseCommandIEValueERABIEContainerList].
type UEContextReleaseCommandIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseCommandIEValueERABIEContainerList, error)
	encode  func(UEContextReleaseCommandIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseCommandIEValueERABIEContainerList, aper.DecodeState) (UEContextReleaseCommandIEValueERABIEContainerList, aper.Snapshot)
	compare func(UEContextReleaseCommandIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCommandIEValueERABIEContainerListValueCodec) New(value UEContextReleaseCommandIEValueERABIEContainerList) (UEContextReleaseCommandIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCommandIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCommandIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCommandIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCommandIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCommandIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCommandIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCommandIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCommandIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCommandIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCommandIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCommandIEValueERABIEContainerListValueCodec) EncodeAPER(value UEContextReleaseCommandIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextReleaseCommandIEValueERABIEContainerListValueCodec) encodeBudgetValue(value UEContextReleaseCommandIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCommandIEValueERABIEContainerListValueCodec) encodeChanged(value UEContextReleaseCommandIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCommandIEValueERABIEContainerList is E-RAB-IE-ContainerList {{UEContextReleaseCommand-IEs}} of TS 36.413: a list of information element fields.
type UEContextReleaseCommandIEValueERABIEContainerList []UEContextReleaseCommandIEValueProtocolIESingleContainer

func BridgeUEContextReleaseCommandIEValueCaptureS1APERABIEContainerList(v *UEContextReleaseCommandIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCommandIEValueCompareS1APERABIEContainerList(v *UEContextReleaseCommandIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextResumeFailureIEValueCaptureS1APERABIEContainerList(v *s24.UEContextResumeFailureIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
func BridgeUEContextResumeFailureIEValueCompareS1APERABIEContainerList(v *s24.UEContextResumeFailureIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
func BridgeUEContextSuspendResponseIEValueCaptureS1APERABIEContainerList(v *s29.UEContextSuspendResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
func BridgeUEContextSuspendResponseIEValueCompareS1APERABIEContainerList(v *s29.UEContextSuspendResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
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
func BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APERABIEContainerList(v *s24.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
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
func BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APERABIEContainerList(v *s24.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
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

// UEContextReleaseCommandIEFieldValueCodec is the concrete ValueCodec[UEContextReleaseCommandIEField].
type UEContextReleaseCommandIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseCommandIEField, error)
	encode  func(UEContextReleaseCommandIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseCommandIEField, aper.DecodeState) (UEContextReleaseCommandIEField, aper.Snapshot)
	compare func(UEContextReleaseCommandIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCommandIEFieldValueCodec) New(value UEContextReleaseCommandIEField) (UEContextReleaseCommandIEFieldAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCommandIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCommandIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCommandIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCommandIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCommandIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCommandIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCommandIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCommandIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCommandIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCommandIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCommandIEFieldValueCodec) EncodeAPER(value UEContextReleaseCommandIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextReleaseCommandIEFieldValueCodec) encodeBudgetValue(value UEContextReleaseCommandIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCommandIEFieldValueCodec) encodeChanged(value UEContextReleaseCommandIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCommandIEContainerValueCodec is the concrete ValueCodec[UEContextReleaseCommandIEContainer].
type UEContextReleaseCommandIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseCommandIEContainer, error)
	encode  func(UEContextReleaseCommandIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseCommandIEContainer, aper.DecodeState) (UEContextReleaseCommandIEContainer, aper.Snapshot)
	compare func(UEContextReleaseCommandIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCommandIEContainerValueCodec) New(value UEContextReleaseCommandIEContainer) (UEContextReleaseCommandIEContainerAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCommandIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCommandIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCommandIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCommandIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCommandIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCommandIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCommandIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCommandIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCommandIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCommandIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCommandIEContainerValueCodec) EncodeAPER(value UEContextReleaseCommandIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextReleaseCommandIEContainerValueCodec) encodeBudgetValue(value UEContextReleaseCommandIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCommandIEContainerValueCodec) encodeChanged(value UEContextReleaseCommandIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
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

// UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[UEContextReleaseCommandIEValueProtocolErrorIEContainerList].
type UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseCommandIEValueProtocolErrorIEContainerList, error)
	encode  func(UEContextReleaseCommandIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseCommandIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextReleaseCommandIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(UEContextReleaseCommandIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) New(value UEContextReleaseCommandIEValueProtocolErrorIEContainerList) (UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value UEContextReleaseCommandIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value UEContextReleaseCommandIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCommandIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{UEContextReleaseCommand-IEs}} of TS 36.413: a list of information element fields.
type UEContextReleaseCommandIEValueProtocolErrorIEContainerList []UEContextReleaseCommandIEValueProtocolIESingleContainer

func BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolErrorIEContainerList(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCommandIEValueCompareS1APProtocolErrorIEContainerList(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextResumeFailureIEValueCaptureS1APProtocolErrorIEContainerList(v *s24.UEContextResumeFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
func BridgeUEContextResumeFailureIEValueCompareS1APProtocolErrorIEContainerList(v *s24.UEContextResumeFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
func BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *s29.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
func BridgeUEContextSuspendResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s29.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
func BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *s24.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
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
func BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s24.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
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
			s36.BridgeUEContextModificationFailureIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
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

// UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[UEContextReleaseCommandIEValueProtocolIEContainerList].
type UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (UEContextReleaseCommandIEValueProtocolIEContainerList, error)
	encode  func(UEContextReleaseCommandIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(UEContextReleaseCommandIEValueProtocolIEContainerList, aper.DecodeState) (UEContextReleaseCommandIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(UEContextReleaseCommandIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) New(value UEContextReleaseCommandIEValueProtocolIEContainerList) (UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) EncodeAPER(value UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value UEContextReleaseCommandIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) encodeChanged(value UEContextReleaseCommandIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEContextReleaseCommandIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {UEContextReleaseCommand-IEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type UEContextReleaseCommandIEValueProtocolIEContainerList []UEContextReleaseCommandIEValueProtocolIESingleContainer

func BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEContainerList(v *UEContextReleaseCommandIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
			BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEContainerList(v *UEContextReleaseCommandIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
			BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEContainerList(v *s24.UEContextResumeFailureIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
func BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEContainerList(v *s24.UEContextResumeFailureIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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
func BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEContainerList(v *s29.UEContextSuspendResponseIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
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
func BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEContainerList(v *s29.UEContextSuspendResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
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

// UEContextReleaseCommandIEValueERABIEContainerListAPERValue is the concrete APERValue[UEContextReleaseCommandIEValueERABIEContainerList].
type UEContextReleaseCommandIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseCommandIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCommandIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCommandIEValueERABIEContainerListAPERValue) WithoutReplay() UEContextReleaseCommandIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseCommandIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{UEContextReleaseCommand-IEs}} of TS 36.413: a single information element field.
type UEContextReleaseCommandIEValueProtocolIESingleContainer = UEContextReleaseCommandIEField

func BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIESingleContainer(v *UEContextReleaseCommandIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIESingleContainer(v *UEContextReleaseCommandIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIESingleContainer(v *s24.UEContextResumeFailureIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextResumeFailureIEValueCompareS1APProtocolIESingleContainer(v *s24.UEContextResumeFailureIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIESingleContainer(v *s29.UEContextSuspendResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIESingleContainer(v *s29.UEContextSuspendResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
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
func BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIESingleContainer(v *s24.UERadioCapabilityIDMappingResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIESingleContainer(v *s24.UERadioCapabilityIDMappingResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
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

// UEContextReleaseCommandIEFieldAPERValue is the concrete APERValue[UEContextReleaseCommandIEField].
type UEContextReleaseCommandIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseCommandIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCommandIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCommandIEFieldAPERValue) WithoutReplay() UEContextReleaseCommandIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseCommandIEContainerAPERValue is the concrete APERValue[UEContextReleaseCommandIEContainer].
type UEContextReleaseCommandIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseCommandIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCommandIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCommandIEContainerAPERValue) WithoutReplay() UEContextReleaseCommandIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[UEContextReleaseCommandIEValueProtocolErrorIEContainerList].
type UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseCommandIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue is the concrete APERValue[UEContextReleaseCommandIEValueProtocolIEContainerList].
type UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         UEContextReleaseCommandIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue) WithoutReplay() UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue {
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
	bodyS1SetupFailure                *s27.S1SetupFailure
	bodyUEContextModificationFailure  *s36.UEContextModificationFailure
	bodyENBConfigurationUpdateFailure *s24.ENBConfigurationUpdateFailure
	bodyMMEConfigurationUpdateFailure *s26.MMEConfigurationUpdateFailure
	bodyUEContextResumeFailure        *UEContextResumeFailure
	bodyS1RemovalFailure              *s27.S1RemovalFailure
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
func (v *UnsuccessfulValue) AsS1SetupFailure() (*s27.S1SetupFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(17) || v.bodyS1SetupFailure == nil {
		return nil, false
	}
	return v.bodyS1SetupFailure, true
}

// AsUEContextModificationFailure returns the selected UEContextModificationFailure value of UnsuccessfulValue and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsUEContextModificationFailure() (*s36.UEContextModificationFailure, bool) {
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
func (v *UnsuccessfulValue) AsMMEConfigurationUpdateFailure() (*s26.MMEConfigurationUpdateFailure, bool) {
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
func (v *UnsuccessfulValue) AsS1RemovalFailure() (*s27.S1RemovalFailure, bool) {
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
		var body s27.S1SetupFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s27.BridgeS1SetupFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.S1SetupFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "S1SetupFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s27.BridgeS1SetupFailureFieldPerPadding(&body) = padding
		*s27.BridgeS1SetupFailureFieldReceived(&body) = true
		raw.RetainContents(s27.BridgeS1SetupFailureFieldReceivedBytes(&body))
		*s27.BridgeS1SetupFailureFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyS1SetupFailure = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(21):
		var body s36.UEContextModificationFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s36.BridgeUEContextModificationFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.UEContextModificationFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextModificationFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s36.BridgeUEContextModificationFailureFieldPerPadding(&body) = padding
		*s36.BridgeUEContextModificationFailureFieldReceived(&body) = true
		raw.RetainContents(s36.BridgeUEContextModificationFailureFieldReceivedBytes(&body))
		*s36.BridgeUEContextModificationFailureFieldReceivedLocation(&body) = raw.ContentLocation()
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
		var body s26.MMEConfigurationUpdateFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s26.BridgeMMEConfigurationUpdateFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.MMEConfigurationUpdateFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "MMEConfigurationUpdateFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s26.BridgeMMEConfigurationUpdateFailureFieldPerPadding(&body) = padding
		*s26.BridgeMMEConfigurationUpdateFailureFieldReceived(&body) = true
		raw.RetainContents(s26.BridgeMMEConfigurationUpdateFailureFieldReceivedBytes(&body))
		*s26.BridgeMMEConfigurationUpdateFailureFieldReceivedLocation(&body) = raw.ContentLocation()
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
		var body s27.S1RemovalFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s27.BridgeS1RemovalFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.S1RemovalFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "S1RemovalFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s27.BridgeS1RemovalFailureFieldPerPadding(&body) = padding
		*s27.BridgeS1RemovalFailureFieldReceived(&body) = true
		raw.RetainContents(s27.BridgeS1RemovalFailureFieldReceivedBytes(&body))
		*s27.BridgeS1RemovalFailureFieldReceivedLocation(&body) = raw.ContentLocation()
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
		return s27.BridgeS1SetupFailureMethodMarshalAPERBudget(v.bodyS1SetupFailure, budget, fresh)
	case s00.ProcedureCode(21):
		if v.bodyUEContextModificationFailure == nil {
			return nil, fmt.Errorf("%s value: missing UEContextModificationFailure", "Unsuccessful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s36.BridgeUEContextModificationFailureMethodMarshalAPERBudget(v.bodyUEContextModificationFailure, budget, fresh)
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
		return s26.BridgeMMEConfigurationUpdateFailureMethodMarshalAPERBudget(v.bodyMMEConfigurationUpdateFailure, budget, fresh)
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
		return s27.BridgeS1RemovalFailureMethodMarshalAPERBudget(v.bodyS1RemovalFailure, budget, fresh)
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
func BridgeCaptureS1APUEContextReleaseCommand(v *UEContextReleaseCommand, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseCommandIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUEContextReleaseCommand(v *UEContextReleaseCommand, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextReleaseCommandIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUEContextReleaseCommandIEValue(v *UEContextReleaseCommandIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(99):
			{
				f := s.Begin()
				s.Bool(v.rowUES1APIDs == nil)
				if v.rowUES1APIDs != nil {
					BridgeCaptureS1APUES1APIDs(v.rowUES1APIDs, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCaptureS1APCause(v.rowCause, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextReleaseCommandIEValue) captureSemantics(s aper.SemanticCapture) UEContextReleaseCommandIEValue {
	BridgeCaptureS1APUEContextReleaseCommandIEValue(&v, &s)
	return v
}
func BridgeCompareS1APUEContextReleaseCommandIEValue(v *UEContextReleaseCommandIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(99):
			{
				f := s.Begin()
				s.Bool(v.rowUES1APIDs == nil)
				if v.rowUES1APIDs != nil {
					BridgeCompareS1APUES1APIDs(v.rowUES1APIDs, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s14.BridgeCompareS1APCause(v.rowCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v UEContextReleaseCommandIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APUEContextReleaseCommandIEValue(&v, &s)
	return s
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
func BridgeCaptureS1APUES1APIDs(v *UES1APIDs, s *aper.SemanticCapture) {
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
	case s00.UES1APIDsChoiceUES1APIDPair:
		{
			f := s.Begin()
			s.Bool(v.UES1APIDPair == nil)
			if v.UES1APIDPair != nil {
				BridgeCaptureS1APUES1APIDPair(v.UES1APIDPair, s)
			}
			s.End(f, nil, false)
		}
	case s00.UES1APIDsChoiceMMEUES1APID:
		{
			f := s.Begin()
			s.Bool(v.MMEUES1APID == nil)
			if v.MMEUES1APID != nil {
				s00.BridgeCaptureS1APMMEUES1APID(v.MMEUES1APID, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUES1APIDs(v *UES1APIDs, s *aper.SemanticComparison) {
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
	case s00.UES1APIDsChoiceUES1APIDPair:
		{
			f := s.Begin()
			s.Bool(v.UES1APIDPair == nil)
			if v.UES1APIDPair != nil {
				BridgeCompareS1APUES1APIDPair(v.UES1APIDPair, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.UES1APIDsChoiceMMEUES1APID:
		{
			f := s.Begin()
			s.Bool(v.MMEUES1APID == nil)
			if v.MMEUES1APID != nil {
				s02.BridgeCompareS1APMMEUES1APID(v.MMEUES1APID, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APUESecurityCapabilities(v *UESecurityCapabilities, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APEncryptionAlgorithms(&v.EncryptionAlgorithms, s)
	s00.BridgeCaptureS1APIntegrityProtectionAlgorithms(&v.IntegrityProtectionAlgorithms, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUESecurityCapabilitiesExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APUESecurityCapabilities(v *UESecurityCapabilities, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APEncryptionAlgorithms(&v.EncryptionAlgorithms, s)
	s02.BridgeCompareS1APIntegrityProtectionAlgorithms(&v.IntegrityProtectionAlgorithms, s)
	s.Bool(v.IEExtensions == nil)
	BridgeUESecurityCapabilitiesExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
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
					s27.BridgeCaptureS1APS1SetupFailure(v.bodyS1SetupFailure, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(21):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationFailure == nil)
				if v.bodyUEContextModificationFailure != nil {
					s36.BridgeCaptureS1APUEContextModificationFailure(v.bodyUEContextModificationFailure, s)
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
					s26.BridgeCaptureS1APMMEConfigurationUpdateFailure(v.bodyMMEConfigurationUpdateFailure, s)
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
					s27.BridgeCaptureS1APS1RemovalFailure(v.bodyS1RemovalFailure, s)
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
					s27.BridgeCompareS1APS1SetupFailure(v.bodyS1SetupFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(21):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationFailure == nil)
				if v.bodyUEContextModificationFailure != nil {
					s36.BridgeCompareS1APUEContextModificationFailure(v.bodyUEContextModificationFailure, s)
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
					s26.BridgeCompareS1APMMEConfigurationUpdateFailure(v.bodyMMEConfigurationUpdateFailure, s)
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
					s27.BridgeCompareS1APS1RemovalFailure(v.bodyS1RemovalFailure, s)
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

// UES1APIDs represents the ASN.1 CHOICE type UE-S1AP-IDs.
type UES1APIDs struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	received           bool
	withoutReplay      bool
	receivedAbsolute   bool
	receivedBytes      aper.WireSpan
	receivedLocation   aper.Location
	Choice             int
	perPadding         aper.CompletePadding  `json:"-"`
	perOpenTypePadding aper.CompletePadding  `json:"-"`
	UnknownExtension   *aper.ChoiceExtension `json:"UnknownExtension,omitempty"`
	UES1APIDPair       *UES1APIDPair         `json:"UES1APIDPair,omitempty"`
	MMEUES1APID        *s00.MMEUES1APID      `json:"MMEUES1APID,omitempty"`
}

// NewUES1APIDsUES1APIDPair creates a UES1APIDs with the uE-S1AP-ID-pair alternative.
func BridgeNewUES1APIDsUES1APIDPairLegacy(v UES1APIDPair) UES1APIDs {
	return UES1APIDs{
		Choice:       s00.UES1APIDsChoiceUES1APIDPair,
		UES1APIDPair: &v,
	}
}

// NewUES1APIDsMMEUES1APID creates a UES1APIDs with the mME-UE-S1AP-ID alternative.
func BridgeNewUES1APIDsMMEUES1APIDLegacy(v s00.MMEUES1APID) UES1APIDs {
	return UES1APIDs{
		Choice:      s00.UES1APIDsChoiceMMEUES1APID,
		MMEUES1APID: &v,
	}
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

// UESecurityCapabilities represents the ASN.1 type UESecurityCapabilities (SEQUENCE).
type UESecurityCapabilities struct {
	replay                        aper.Snapshot
	stream                        aper.WireSpan
	received                      bool
	withoutReplay                 bool
	receivedAbsolute              bool
	receivedBytes                 aper.WireSpan
	receivedLocation              aper.Location
	EncryptionAlgorithms          s00.EncryptionAlgorithms                     `asn1:"tag:0,context,implicit"`
	IntegrityProtectionAlgorithms s00.IntegrityProtectionAlgorithms            `asn1:"tag:1,context,implicit"`
	IEExtensions                  s12.UESecurityCapabilitiesExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef             bool                                         `asn1:"-" json:"-"`
	extCount                      int64                                        `asn1:"-" json:"-"`
	extPresent                    []bool                                       `asn1:"-" json:"-"`
	extData                       [][]byte                                     `asn1:"-" json:"-"`
	perPadding                    aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding                 []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin                     []aper.OpaqueOrigin
	extWire                       []aper.WireSpan
}

// MarshalAPER encodes UES1APIDs to APER format.
func (v *UES1APIDs) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *UES1APIDs) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "UES1APIDs:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "UES1APIDs:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "UES1APIDs:", v.Choice)
	}
	isExtension := v.Choice > 2
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "UES1APIDs:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.UES1APIDsChoiceUES1APIDPair:
		if v.UES1APIDPair == nil {
			return fmt.Errorf("choice alternative uE-S1AP-ID-pair is nil")
		}
		if err := v.UES1APIDPair.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding uE-S1AP-ID-pair: %w", err)
		}
	case s00.UES1APIDsChoiceMMEUES1APID:
		if v.MMEUES1APID == nil {
			return fmt.Errorf("choice alternative mME-UE-S1AP-ID is nil")
		}
		if err := aper.EncodeIntegerAligned(bb, int64(*v.MMEUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
			return fmt.Errorf("encoding mME-UE-S1AP-ID: %w", err)
		}
	default:
		return fmt.Errorf("unknown UES1APIDs choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes UES1APIDs from APER format.
func (v *UES1APIDs) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UES1APIDs with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UES1APIDs) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UES1APIDs")
	}
	bb.EnterComponent("UES1APIDs")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UES1APIDs")
	}
	padding, err := aper.CaptureFinalBits(bb, "UES1APIDs")
	if err != nil {
		return runtime.WrapDecodePath(err, "UES1APIDs")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *UES1APIDs) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UES1APIDs{}
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
		if err := openExtension.ObserveUnknown(bb); err != nil {
			return err
		}
		v.UnknownExtension = &openExtension
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
	case s00.UES1APIDsChoiceUES1APIDPair:
		toleranceMark_ues1apidpair := bb.EnterComponent("UES1APIDPair")
		var dec_ues1apidpair UES1APIDPair
		if err := dec_ues1apidpair.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "UES1APIDPair")
		}
		if err := aper.ChargeValue(bb, dec_ues1apidpair); err != nil {
			return err
		}
		v.UES1APIDPair = &dec_ues1apidpair
		bb.LeaveComponent(toleranceMark_ues1apidpair)
	case s00.UES1APIDsChoiceMMEUES1APID:
		val_mmeues1apid, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "MMEUES1APID")
		}
		tmp_mmeues1apid := s00.MMEUES1APID(val_mmeues1apid)
		if err := aper.ChargeValue(bb, tmp_mmeues1apid); err != nil {
			return err
		}
		v.MMEUES1APID = (*s00.MMEUES1APID)(bb.OwnInt64(int64(tmp_mmeues1apid)))

	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
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

// MarshalAPER encodes UESecurityCapabilities to APER format.
func (v *UESecurityCapabilities) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UESecurityCapabilities) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBitStringAlignedExt(bb, v.EncryptionAlgorithms.Bytes, v.EncryptionAlgorithms.BitLength, 16, 16, true, true); err != nil {
		return fmt.Errorf("encoding encryptionAlgorithms: %w", err)
	}
	if err := aper.EncodeBitStringAlignedExt(bb, v.IntegrityProtectionAlgorithms.Bytes, v.IntegrityProtectionAlgorithms.BitLength, 16, 16, true, true); err != nil {
		return fmt.Errorf("encoding integrityProtectionAlgorithms: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s12.BridgeUESecurityCapabilitiesExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UESecurityCapabilities from APER format.
func (v *UESecurityCapabilities) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UESecurityCapabilities with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UESecurityCapabilities) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UESecurityCapabilities")
	}
	bb.EnterComponent("UESecurityCapabilities")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UESecurityCapabilities")
	}
	padding, err := aper.CaptureFinalBits(bb, "UESecurityCapabilities")
	if err != nil {
		return runtime.WrapDecodePath(err, "UESecurityCapabilities")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UESecurityCapabilities) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UESecurityCapabilities{}
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
	bsBytes_encryptionalgorithms, bsBitLen_encryptionalgorithms, err := aper.DecodeBitStringAlignedExt(bb, 16, 16, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EncryptionAlgorithms")
	}
	v.EncryptionAlgorithms = runtime.BitString{Bytes: bsBytes_encryptionalgorithms, BitLength: bsBitLen_encryptionalgorithms}
	bsBytes_integrityprotectionalgorithms, bsBitLen_integrityprotectionalgorithms, err := aper.DecodeBitStringAlignedExt(bb, 16, 16, true, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "IntegrityProtectionAlgorithms")
	}
	v.IntegrityProtectionAlgorithms = runtime.BitString{Bytes: bsBytes_integrityprotectionalgorithms, BitLength: bsBitLen_integrityprotectionalgorithms}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s12.UESecurityCapabilitiesExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.UESecurityCapabilitiesExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgeUESecurityCapabilitiesExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UES1APIDs) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UES1APIDs", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UES1APIDs", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UES1APIDs) WithoutReplay() UES1APIDs {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UES1APIDs
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UESecurityCapabilities) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UESecurityCapabilities", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UESecurityCapabilities", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UESecurityCapabilities) WithoutReplay() UESecurityCapabilities {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UESecurityCapabilities
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

// Extensions returns owned unknown sequence additions.
func (v *UESecurityCapabilities) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UESecurityCapabilities) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UESecurityCapabilities.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UESecurityCapabilities.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UESecurityCapabilities) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UESecurityCapabilities.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UESecurityCapabilities.Extensions[%d]", index))
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

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *UES1APIDs) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UES1APIDs")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UES1APIDs) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UES1APIDs")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUES1APIDs(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UES1APIDs")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UES1APIDs")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UES1APIDs) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UES1APIDs")
}
func (v *UES1APIDs) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UES1APIDs")
}
func (v *UES1APIDs) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUES1APIDs(v, &s)
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
func (v *UES1APIDs) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UES1APIDs) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UESecurityCapabilities) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UESecurityCapabilities")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UESecurityCapabilities) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UESecurityCapabilities")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUESecurityCapabilities(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UESecurityCapabilities")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UESecurityCapabilities")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UESecurityCapabilities) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UESecurityCapabilities")
}
func (v *UESecurityCapabilities) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UESecurityCapabilities")
}
func (v *UESecurityCapabilities) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUESecurityCapabilities(v, &s)
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
func (v *UESecurityCapabilities) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UESecurityCapabilities) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UES1APIDs) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UES1APIDs")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UES1APIDs
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUES1APIDs(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UES1APIDs{}
		return report, aper.OperationError(err, "UES1APIDs")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UES1APIDs")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *UESecurityCapabilities) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UESecurityCapabilities")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UESecurityCapabilities
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUESecurityCapabilities(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UESecurityCapabilities{}
		return report, aper.OperationError(err, "UESecurityCapabilities")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UESecurityCapabilities")
}

// NewUES1APIDsUES1APIDPair constructs a checked complete value.
func NewUES1APIDsUES1APIDPair(v UES1APIDPair, options ...aper.BuildOption) (UES1APIDs, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsUES1APIDPair")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsUES1APIDPair")
	}
	value := BridgeNewUES1APIDsUES1APIDPairLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsUES1APIDPair")
	}
	return value, aper.OperationError(nil, "UES1APIDsUES1APIDPair")
}

// NewUES1APIDsMMEUES1APID constructs a checked complete value.
func NewUES1APIDsMMEUES1APID(v s00.MMEUES1APID, options ...aper.BuildOption) (UES1APIDs, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsMMEUES1APID")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), v); err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsMMEUES1APID")
	}
	value := BridgeNewUES1APIDsMMEUES1APIDLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsMMEUES1APID")
	}
	return value, aper.OperationError(nil, "UES1APIDsMMEUES1APID")
}

// NewUES1APIDsUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewUES1APIDsUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (UES1APIDs, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsUnknownExtension")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), aper.ChoiceExtension{}); err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsUnknownExtension")
	}
	value := UES1APIDs{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return UES1APIDs{}, aper.OperationError(err, "UES1APIDsUnknownExtension")
	}
	return value, aper.OperationError(nil, "UES1APIDsUnknownExtension")
}

// UEContextReleaseCommand represents the ASN.1 type UEContextReleaseCommand (SEQUENCE).
type UEContextReleaseCommand struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      UEContextReleaseCommandIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                               `asn1:"-" json:"-"`
	extCount         int64                              `asn1:"-" json:"-"`
	extPresent       []bool                             `asn1:"-" json:"-"`
	extData          [][]byte                           `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                  `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding             `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
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

// UEContextSuspendResponse represents the ASN.1 type UEContextSuspendResponse (SEQUENCE).
type UEContextSuspendResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s29.UEContextSuspendResponseIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s24.UEContextResumeFailureIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s24.UERadioCapabilityIDMappingResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                              `asn1:"-" json:"-"`
	extCount         int64                                             `asn1:"-" json:"-"`
	extPresent       []bool                                            `asn1:"-" json:"-"`
	extData          [][]byte                                          `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                 `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                            `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes UEContextReleaseCommand to APER format.
func (v *UEContextReleaseCommand) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UEContextReleaseCommand) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes UEContextReleaseCommand from APER format.
func (v *UEContextReleaseCommand) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UEContextReleaseCommand with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UEContextReleaseCommand) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseCommand")
	}
	bb.EnterComponent("UEContextReleaseCommand")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseCommand")
	}
	padding, err := aper.CaptureFinalBits(bb, "UEContextReleaseCommand")
	if err != nil {
		return runtime.WrapDecodePath(err, "UEContextReleaseCommand")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UEContextReleaseCommand) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextReleaseCommand{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(UEContextReleaseCommandIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem UEContextReleaseCommandIEField
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
			if err := s29.BridgeUEContextSuspendResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	v.ProtocolIEs = make(s29.UEContextSuspendResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s29.UEContextSuspendResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s29.BridgeUEContextSuspendResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s24.BridgeUEContextResumeFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	v.ProtocolIEs = make(s24.UEContextResumeFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s24.UEContextResumeFailureIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s24.BridgeUEContextResumeFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s24.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	v.ProtocolIEs = make(s24.UERadioCapabilityIDMappingResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s24.UERadioCapabilityIDMappingResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s24.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *UEContextReleaseCommand) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextReleaseCommand", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "UEContextReleaseCommand", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UEContextReleaseCommand) WithoutReplay() UEContextReleaseCommand {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero UEContextReleaseCommand
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
func (v *UEContextReleaseCommand) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UEContextReleaseCommand) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextReleaseCommand.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextReleaseCommand.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UEContextReleaseCommand) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("UEContextReleaseCommand.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("UEContextReleaseCommand.Extensions[%d]", index))
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
func (v *UEContextReleaseCommand) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "UEContextReleaseCommand")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *UEContextReleaseCommand) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "UEContextReleaseCommand")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APUEContextReleaseCommand(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "UEContextReleaseCommand")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "UEContextReleaseCommand")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *UEContextReleaseCommand) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "UEContextReleaseCommand")
}
func (v *UEContextReleaseCommand) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "UEContextReleaseCommand")
}
func (v *UEContextReleaseCommand) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APUEContextReleaseCommand(v, &s)
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
func (v *UEContextReleaseCommand) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *UEContextReleaseCommand) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
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
func (v *UEContextReleaseCommand) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "UEContextReleaseCommand")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded UEContextReleaseCommand
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APUEContextReleaseCommand(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = UEContextReleaseCommand{}
		return report, aper.OperationError(err, "UEContextReleaseCommand")
	}
	*v = decoded
	return report, aper.OperationError(nil, "UEContextReleaseCommand")
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

type UEContextReleaseCommandIEValue struct {
	id           s00.ProtocolIEID
	received     aper.WireSpan
	replay       aper.Snapshot
	opaque       aper.OpaqueOpenType
	isOpaque     bool
	rowUES1APIDs *UES1APIDs
	rowCause     *s14.Cause
}

func (v UEContextReleaseCommandIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(99):
		return v.rowUES1APIDs != nil
	case s00.ProtocolIEID(2):
		return v.rowCause != nil
	}
	return false
}

// Opaque returns the retained opaque open value of UEContextReleaseCommandIEValue and reports whether the opaque alternative is selected.
func (v *UEContextReleaseCommandIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (UEContextReleaseCommandIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseCommand-IEs"}}
}
func (UEContextReleaseCommandIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(99):
		return aper.UnknownSelector
	case s00.ProtocolIEID(2):
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

// AsUES1APIDs returns the selected UES1APIDs value of UEContextReleaseCommandIEValue and reports whether that alternative is active.
func (v *UEContextReleaseCommandIEValue) AsUES1APIDs() (*UES1APIDs, bool) {
	if v == nil || v.id != s00.ProtocolIEID(99) || v.rowUES1APIDs == nil {
		return nil, false
	}
	return v.rowUES1APIDs, true
}

// AsCause returns the selected Cause value of UEContextReleaseCommandIEValue and reports whether that alternative is active.
func (v *UEContextReleaseCommandIEValue) AsCause() (*s14.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v UEContextReleaseCommandIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UEContextReleaseCommandIEValue, error) {
	out := UEContextReleaseCommandIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(99):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value UES1APIDs
		child := scope
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "UES1APIDs:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UES1APIDs")
		if err != nil {
			return out, err
		}
		value.perPadding = padding.Padding()
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		value.receivedLocation = raw.ContentLocation()
		out.rowUES1APIDs = &value
		raw.RetainContents(&out.received)
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
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v UEContextReleaseCommandIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v UEContextReleaseCommandIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(99):
		if v.rowUES1APIDs == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextReleaseCommand-IEs.id-UE-S1AP-IDs:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := v.rowUES1APIDs.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(2):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "UEContextReleaseCommand-IEs.id-Cause:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s14.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UEContextReleaseCommandIEValue:", v.id)
	}
}

type UEContextReleaseCommandIETable struct{}

func UEContextReleaseCommandIEs() UEContextReleaseCommandIETable {
	return UEContextReleaseCommandIETable{}
}

// ID returns the ASN.1 object-set identity of UEContextReleaseCommandIETable.
func (UEContextReleaseCommandIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseCommand-IEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by UEContextReleaseCommandIETable.
func (UEContextReleaseCommandIETable) Table() s00.UEContextReleaseCommandIEValueIETable {
	return func() s00.UEContextReleaseCommandIEValueIETable {
		sealed := s00.UEContextReleaseCommandIEValueIETable{}
		*s00.BridgeUEContextReleaseCommandIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (UEContextReleaseCommandIETable) infoUES1APIDs() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCommandIEs().ID(), ID: s00.ProtocolIEID(99), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UE-S1AP-IDs"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseCommand-IEs", Row: "id-UE-S1AP-IDs"}}}
}

// UES1APIDs returns the typed binding for the UES1APIDs row of UEContextReleaseCommandIETable.
func (t UEContextReleaseCommandIETable) UES1APIDs() UEContextReleaseCommandUES1APIDsIEBinding {
	return UEContextReleaseCommandUES1APIDsIEBinding{info: t.infoUES1APIDs(), codec: UES1APIDsValueCodec{path: "UES1APIDs",
		decode: func(data []byte, options aper.DecodeState) (UES1APIDs, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty UES1APIDs
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UES1APIDs")
			var zero UEContextReleaseCommandIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(99), raw)
			if err != nil {
				var empty UES1APIDs
				return empty, runtime.WrapDecodePath(err, "UES1APIDs")
			}
			value, ok := decoded.AsUES1APIDs()
			if !ok {
				var empty UES1APIDs
				return empty, fmt.Errorf("binding UEContextReleaseCommand-IEs.id-UE-S1AP-IDs: no selected value")
			}
			return *value, nil
		},
		encode: func(value UES1APIDs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextReleaseCommandIEValue{id: s00.ProtocolIEID(99), rowUES1APIDs: &value}).encodeFresh(fresh, budget)
		}, capture: func(v UES1APIDs, options aper.DecodeState) (UES1APIDs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			BridgeCaptureS1APUES1APIDs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v UES1APIDs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APUES1APIDs(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UES1APIDs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value UES1APIDs) UEContextReleaseCommandIEValue {
		return UEContextReleaseCommandIEValue{id: s00.ProtocolIEID(99), rowUES1APIDs: &value}
	}, get: func(value *UEContextReleaseCommandIEValue) (*UES1APIDs, bool) { return value.AsUES1APIDs() }}
}
func (UEContextReleaseCommandIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: UEContextReleaseCommandIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "UEContextReleaseCommand-IEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of UEContextReleaseCommandIETable.
func (t UEContextReleaseCommandIETable) Cause() UEContextReleaseCommandCauseIEBinding {
	return UEContextReleaseCommandCauseIEBinding{info: t.infoCause(), codec: func() s14.CauseValueCodec {
		sealed := s14.CauseValueCodec{}
		*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.Cause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cause")
			var zero UEContextReleaseCommandIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s14.Cause
				return empty, runtime.WrapDecodePath(err, "Cause")
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s14.Cause
				return empty, fmt.Errorf("binding UEContextReleaseCommand-IEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextReleaseCommandIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s14.Cause) UEContextReleaseCommandIEValue {
			return UEContextReleaseCommandIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *UEContextReleaseCommandIEValue) (*s14.Cause, bool) { return value.AsCause() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in UEContextReleaseCommandIETable.
func (t UEContextReleaseCommandIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UEContextReleaseCommandIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UEContextReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(99):
		return UEContextReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-UE-S1AP-IDs requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(2):
		return UEContextReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UEContextReleaseCommandIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UEContextReleaseCommandIEField{}, aper.OperationError(err, "Opaque")
		}
		return UEContextReleaseCommandIEField{Id: id, Criticality: criticality, Value: UEContextReleaseCommandIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// UES1APIDPairCodec binds the complete source value type.
func UES1APIDPairCodec() UES1APIDPairValueCodec {
	return UES1APIDPairValueCodec{path: "UES1APIDPair", decode: func(data []byte, options aper.DecodeState) (UES1APIDPair, error) {
		var value UES1APIDPair
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return UES1APIDPair{}, err
		}
		value.received = true
		value.receivedAbsolute = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value UES1APIDPair, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v UES1APIDPair, options aper.DecodeState) (UES1APIDPair, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureS1APUES1APIDPair(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v UES1APIDPair, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeCompareS1APUES1APIDPair(&v, &s)
		s.End(f, root, false)
		return s.Plan(),
			s.
				BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UES1APIDPair"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// UES1APIDsCodec binds the complete APER value type.
func UES1APIDsCodec() UES1APIDsValueCodec { return UEContextReleaseCommandIEs().UES1APIDs().Codec() }

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
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldCapture(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *func(s26.MMEConfigurationUpdateFailure, aper.DecodeState) (s26.MMEConfigurationUpdateFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldCompare(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *func(s26.MMEConfigurationUpdateFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldContext(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldDecode(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s26.MMEConfigurationUpdateFailure, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldEncode(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *func(*s26.MMEConfigurationUpdateFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldInfo(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldInject(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *func(s26.MMEConfigurationUpdateFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldValidate(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *func(*s26.MMEConfigurationUpdateFailure, *aper.DecodeBudget) (s21.ValidationReport, error) {
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
func BridgeS1RemovalFailureUnsuccessfulBindingFieldCapture(v *S1RemovalFailureUnsuccessfulBinding) *func(s27.S1RemovalFailure, aper.DecodeState) (s27.S1RemovalFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldCompare(v *S1RemovalFailureUnsuccessfulBinding) *func(s27.S1RemovalFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldContext(v *S1RemovalFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldDecode(v *S1RemovalFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s27.S1RemovalFailure, error) {
	return &v.decode
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldEncode(v *S1RemovalFailureUnsuccessfulBinding) *func(*s27.S1RemovalFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldInfo(v *S1RemovalFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldInject(v *S1RemovalFailureUnsuccessfulBinding) *func(s27.S1RemovalFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldValidate(v *S1RemovalFailureUnsuccessfulBinding) *func(*s27.S1RemovalFailure, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldCapture(v *S1SetupFailureUnsuccessfulBinding) *func(s27.S1SetupFailure, aper.DecodeState) (s27.S1SetupFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldCompare(v *S1SetupFailureUnsuccessfulBinding) *func(s27.S1SetupFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldContext(v *S1SetupFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldDecode(v *S1SetupFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s27.S1SetupFailure, error) {
	return &v.decode
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldEncode(v *S1SetupFailureUnsuccessfulBinding) *func(*s27.S1SetupFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldInfo(v *S1SetupFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldInject(v *S1SetupFailureUnsuccessfulBinding) *func(s27.S1SetupFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldValidate(v *S1SetupFailureUnsuccessfulBinding) *func(*s27.S1SetupFailure, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldCapture(v *UEContextModificationFailureUnsuccessfulBinding) *func(s36.UEContextModificationFailure, aper.DecodeState) (s36.UEContextModificationFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldCompare(v *UEContextModificationFailureUnsuccessfulBinding) *func(s36.UEContextModificationFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldContext(v *UEContextModificationFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldDecode(v *UEContextModificationFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s36.UEContextModificationFailure, error) {
	return &v.decode
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldEncode(v *UEContextModificationFailureUnsuccessfulBinding) *func(*s36.UEContextModificationFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldInfo(v *UEContextModificationFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldInject(v *UEContextModificationFailureUnsuccessfulBinding) *func(s36.UEContextModificationFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldValidate(v *UEContextModificationFailureUnsuccessfulBinding) *func(*s36.UEContextModificationFailure, *aper.DecodeBudget) (s21.ValidationReport, error) {
	return &v.validate
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
func BridgeUEContextReleaseCommandAPERValueFieldContext(v *UEContextReleaseCommandAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandAPERValueFieldReceived(v *UEContextReleaseCommandAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCommandAPERValueFieldReplay(v *UEContextReleaseCommandAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCommandAPERValueFieldWithoutReplay(v *UEContextReleaseCommandAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCommandCauseIEBindingFieldCodec(v *UEContextReleaseCommandCauseIEBinding) *s14.CauseValueCodec {
	return &v.codec
}
func BridgeUEContextReleaseCommandCauseIEBindingFieldGet(v *UEContextReleaseCommandCauseIEBinding) *func(*UEContextReleaseCommandIEValue) (*s14.Cause, bool) {
	return &v.get
}
func BridgeUEContextReleaseCommandCauseIEBindingFieldInfo(v *UEContextReleaseCommandCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextReleaseCommandCauseIEBindingFieldInject(v *UEContextReleaseCommandCauseIEBinding) *func(s14.Cause) UEContextReleaseCommandIEValue {
	return &v.inject
}
func BridgeUEContextReleaseCommandFieldExtCount(v *UEContextReleaseCommand) *int64 {
	return &v.extCount
}
func BridgeUEContextReleaseCommandFieldExtData(v *UEContextReleaseCommand) *[][]byte {
	return &v.extData
}
func BridgeUEContextReleaseCommandFieldExtOrigin(v *UEContextReleaseCommand) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUEContextReleaseCommandFieldExtPresent(v *UEContextReleaseCommand) *[]bool {
	return &v.extPresent
}
func BridgeUEContextReleaseCommandFieldExtWire(v *UEContextReleaseCommand) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUEContextReleaseCommandFieldPerExtPadding(v *UEContextReleaseCommand) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUEContextReleaseCommandFieldPerPadding(v *UEContextReleaseCommand) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUEContextReleaseCommandFieldProtocolIEsIndef(v *UEContextReleaseCommand) *bool {
	return &v.protocolIEsIndef
}
func BridgeUEContextReleaseCommandFieldReceived(v *UEContextReleaseCommand) *bool { return &v.received }
func BridgeUEContextReleaseCommandFieldReceivedAbsolute(v *UEContextReleaseCommand) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextReleaseCommandFieldReceivedBytes(v *UEContextReleaseCommand) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextReleaseCommandFieldReceivedLocation(v *UEContextReleaseCommand) *aper.Location {
	return &v.receivedLocation
}
func BridgeUEContextReleaseCommandFieldReplay(v *UEContextReleaseCommand) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCommandFieldStream(v *UEContextReleaseCommand) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextReleaseCommandFieldWithoutReplay(v *UEContextReleaseCommand) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCommandIEContainerAPERValueFieldContext(v *UEContextReleaseCommandIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEContainerAPERValueFieldReceived(v *UEContextReleaseCommandIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCommandIEContainerAPERValueFieldReplay(v *UEContextReleaseCommandIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCommandIEContainerAPERValueFieldWithoutReplay(v *UEContextReleaseCommandIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCommandIEContainerValueCodecFieldCapture(v *UEContextReleaseCommandIEContainerValueCodec) *func(UEContextReleaseCommandIEContainer, aper.DecodeState) (UEContextReleaseCommandIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCommandIEContainerValueCodecFieldCompare(v *UEContextReleaseCommandIEContainerValueCodec) *func(UEContextReleaseCommandIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCommandIEContainerValueCodecFieldContext(v *UEContextReleaseCommandIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEContainerValueCodecFieldDecode(v *UEContextReleaseCommandIEContainerValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseCommandIEContainer, error) {
	return &v.decode
}
func BridgeUEContextReleaseCommandIEContainerValueCodecFieldEncode(v *UEContextReleaseCommandIEContainerValueCodec) *func(UEContextReleaseCommandIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCommandIEContainerValueCodecFieldPath(v *UEContextReleaseCommandIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseCommandIEContainerValueCodecMethodEncodeBudgetValue(v UEContextReleaseCommandIEContainerValueCodec, a0 UEContextReleaseCommandIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseCommandIEContainerValueCodecMethodEncodeChanged(v UEContextReleaseCommandIEContainerValueCodec, a0 UEContextReleaseCommandIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseCommandIEFieldAPERValueFieldContext(v *UEContextReleaseCommandIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEFieldAPERValueFieldReceived(v *UEContextReleaseCommandIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCommandIEFieldAPERValueFieldReplay(v *UEContextReleaseCommandIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCommandIEFieldAPERValueFieldWithoutReplay(v *UEContextReleaseCommandIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCommandIEFieldFieldReceived(v *UEContextReleaseCommandIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUEContextReleaseCommandIEFieldFieldReplay(v *UEContextReleaseCommandIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCommandIEFieldFieldStream(v *UEContextReleaseCommandIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUEContextReleaseCommandIEFieldFieldWithoutReplay(v *UEContextReleaseCommandIEField) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCommandIEFieldMethodMarshalAPERTo(v *UEContextReleaseCommandIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextReleaseCommandIEFieldMethodUnmarshalAPERFrom(v *UEContextReleaseCommandIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextReleaseCommandIEFieldValueCodecFieldCapture(v *UEContextReleaseCommandIEFieldValueCodec) *func(UEContextReleaseCommandIEField, aper.DecodeState) (UEContextReleaseCommandIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCommandIEFieldValueCodecFieldCompare(v *UEContextReleaseCommandIEFieldValueCodec) *func(UEContextReleaseCommandIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCommandIEFieldValueCodecFieldContext(v *UEContextReleaseCommandIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEFieldValueCodecFieldDecode(v *UEContextReleaseCommandIEFieldValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseCommandIEField, error) {
	return &v.decode
}
func BridgeUEContextReleaseCommandIEFieldValueCodecFieldEncode(v *UEContextReleaseCommandIEFieldValueCodec) *func(UEContextReleaseCommandIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCommandIEFieldValueCodecFieldPath(v *UEContextReleaseCommandIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseCommandIEFieldValueCodecMethodEncodeBudgetValue(v UEContextReleaseCommandIEFieldValueCodec, a0 UEContextReleaseCommandIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseCommandIEFieldValueCodecMethodEncodeChanged(v UEContextReleaseCommandIEFieldValueCodec, a0 UEContextReleaseCommandIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseCommandIETableMethodInfoCause(v UEContextReleaseCommandIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeUEContextReleaseCommandIETableMethodInfoUES1APIDs(v UEContextReleaseCommandIETable) s00.FieldInfo {
	return v.infoUES1APIDs()
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListAPERValueFieldContext(v *UEContextReleaseCommandIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListAPERValueFieldReceived(v *UEContextReleaseCommandIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListAPERValueFieldReplay(v *UEContextReleaseCommandIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *UEContextReleaseCommandIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecFieldCapture(v *UEContextReleaseCommandIEValueERABIEContainerListValueCodec) *func(UEContextReleaseCommandIEValueERABIEContainerList, aper.DecodeState) (UEContextReleaseCommandIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecFieldCompare(v *UEContextReleaseCommandIEValueERABIEContainerListValueCodec) *func(UEContextReleaseCommandIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecFieldContext(v *UEContextReleaseCommandIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecFieldDecode(v *UEContextReleaseCommandIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseCommandIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecFieldEncode(v *UEContextReleaseCommandIEValueERABIEContainerListValueCodec) *func(UEContextReleaseCommandIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecFieldPath(v *UEContextReleaseCommandIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextReleaseCommandIEValueERABIEContainerListValueCodec, a0 UEContextReleaseCommandIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseCommandIEValueERABIEContainerListValueCodecMethodEncodeChanged(v UEContextReleaseCommandIEValueERABIEContainerListValueCodec, a0 UEContextReleaseCommandIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseCommandIEValueFieldId(v *UEContextReleaseCommandIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEContextReleaseCommandIEValueFieldIsOpaque(v *UEContextReleaseCommandIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEContextReleaseCommandIEValueFieldOpaque(v *UEContextReleaseCommandIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEContextReleaseCommandIEValueFieldReceived(v *UEContextReleaseCommandIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCommandIEValueFieldReplay(v *UEContextReleaseCommandIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCommandIEValueFieldRowCause(v *UEContextReleaseCommandIEValue) **s14.Cause {
	return &v.rowCause
}
func BridgeUEContextReleaseCommandIEValueFieldRowUES1APIDs(v *UEContextReleaseCommandIEValue) **UES1APIDs {
	return &v.rowUES1APIDs
}
func BridgeUEContextReleaseCommandIEValueMethodCaptureSemantics(v UEContextReleaseCommandIEValue, a0 aper.SemanticCapture) UEContextReleaseCommandIEValue {
	return v.captureSemantics(a0)
}
func BridgeUEContextReleaseCommandIEValueMethodCompareSemantics(v UEContextReleaseCommandIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEContextReleaseCommandIEValueMethodDecode(v UEContextReleaseCommandIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UEContextReleaseCommandIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUEContextReleaseCommandIEValueMethodEncode(v UEContextReleaseCommandIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUEContextReleaseCommandIEValueMethodEncodeFresh(v UEContextReleaseCommandIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUEContextReleaseCommandIEValueMethodMatchesID(v UEContextReleaseCommandIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEContextReleaseCommandIEValueMethodReason(v UEContextReleaseCommandIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUEContextReleaseCommandIEValueMethodRule(v UEContextReleaseCommandIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextReleaseCommandIEValueProtocolErrorIEContainerList, aper.DecodeState) (UEContextReleaseCommandIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextReleaseCommandIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseCommandIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) *func(UEContextReleaseCommandIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextReleaseCommandIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v UEContextReleaseCommandIEValueProtocolErrorIEContainerListValueCodec, a0 UEContextReleaseCommandIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListAPERValueFieldContext(v *UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListAPERValueFieldReceived(v *UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListAPERValueFieldReplay(v *UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *UEContextReleaseCommandIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecFieldCapture(v *UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) *func(UEContextReleaseCommandIEValueProtocolIEContainerList, aper.DecodeState) (UEContextReleaseCommandIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecFieldCompare(v *UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) *func(UEContextReleaseCommandIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecFieldContext(v *UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecFieldDecode(v *UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseCommandIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecFieldEncode(v *UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) *func(UEContextReleaseCommandIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecFieldPath(v *UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec, a0 UEContextReleaseCommandIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseCommandIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v UEContextReleaseCommandIEValueProtocolIEContainerListValueCodec, a0 UEContextReleaseCommandIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEContextReleaseCommandMethodMarshalAPERBudget(v *UEContextReleaseCommand, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextReleaseCommandMethodMarshalAPERBudgetValue(v *UEContextReleaseCommand, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUEContextReleaseCommandMethodMarshalAPERChanged(v *UEContextReleaseCommand, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUEContextReleaseCommandMethodMarshalAPERChangedValue(v *UEContextReleaseCommand, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUEContextReleaseCommandMethodMarshalAPERLegacy(v *UEContextReleaseCommand) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUEContextReleaseCommandMethodMarshalAPERNewValue(v *UEContextReleaseCommand, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUEContextReleaseCommandMethodMarshalAPERPlanned(v *UEContextReleaseCommand, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUEContextReleaseCommandMethodMarshalAPERTo(v *UEContextReleaseCommand, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUEContextReleaseCommandMethodUnmarshalAPERFrom(v *UEContextReleaseCommand, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUEContextReleaseCommandMethodUnmarshalAPERLegacy(v *UEContextReleaseCommand, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUEContextReleaseCommandMethodUnmarshalAPERWithOptions(v *UEContextReleaseCommand, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUEContextReleaseCommandUES1APIDsIEBindingFieldCodec(v *UEContextReleaseCommandUES1APIDsIEBinding) *UES1APIDsValueCodec {
	return &v.codec
}
func BridgeUEContextReleaseCommandUES1APIDsIEBindingFieldGet(v *UEContextReleaseCommandUES1APIDsIEBinding) *func(*UEContextReleaseCommandIEValue) (*UES1APIDs, bool) {
	return &v.get
}
func BridgeUEContextReleaseCommandUES1APIDsIEBindingFieldInfo(v *UEContextReleaseCommandUES1APIDsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUEContextReleaseCommandUES1APIDsIEBindingFieldInject(v *UEContextReleaseCommandUES1APIDsIEBinding) *func(UES1APIDs) UEContextReleaseCommandIEValue {
	return &v.inject
}
func BridgeUEContextReleaseCommandValueCodecFieldCapture(v *UEContextReleaseCommandValueCodec) *func(UEContextReleaseCommand, aper.DecodeState) (UEContextReleaseCommand, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextReleaseCommandValueCodecFieldCompare(v *UEContextReleaseCommandValueCodec) *func(UEContextReleaseCommand, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextReleaseCommandValueCodecFieldContext(v *UEContextReleaseCommandValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextReleaseCommandValueCodecFieldDecode(v *UEContextReleaseCommandValueCodec) *func([]byte, aper.DecodeState) (UEContextReleaseCommand, error) {
	return &v.decode
}
func BridgeUEContextReleaseCommandValueCodecFieldEncode(v *UEContextReleaseCommandValueCodec) *func(UEContextReleaseCommand, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextReleaseCommandValueCodecFieldPath(v *UEContextReleaseCommandValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEContextReleaseCommandValueCodecMethodEncodeBudgetValue(v UEContextReleaseCommandValueCodec, a0 UEContextReleaseCommand, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEContextReleaseCommandValueCodecMethodEncodeChanged(v UEContextReleaseCommandValueCodec, a0 UEContextReleaseCommand, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
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
func BridgeUES1APIDPairValueCodecFieldCapture(v *UES1APIDPairValueCodec) *func(UES1APIDPair, aper.DecodeState) (UES1APIDPair, aper.Snapshot) {
	return &v.capture
}
func BridgeUES1APIDPairValueCodecFieldCompare(v *UES1APIDPairValueCodec) *func(UES1APIDPair, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUES1APIDPairValueCodecFieldContext(v *UES1APIDPairValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUES1APIDPairValueCodecFieldDecode(v *UES1APIDPairValueCodec) *func([]byte, aper.DecodeState) (UES1APIDPair, error) {
	return &v.decode
}
func BridgeUES1APIDPairValueCodecFieldEncode(v *UES1APIDPairValueCodec) *func(UES1APIDPair, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUES1APIDPairValueCodecFieldPath(v *UES1APIDPairValueCodec) *aper.Path { return &v.path }
func BridgeUES1APIDPairValueCodecMethodEncodeBudgetValue(v UES1APIDPairValueCodec, a0 UES1APIDPair, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUES1APIDPairValueCodecMethodEncodeChanged(v UES1APIDPairValueCodec, a0 UES1APIDPair, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUES1APIDsAPERValueFieldContext(v *UES1APIDsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUES1APIDsAPERValueFieldReceived(v *UES1APIDsAPERValue) *aper.WireSpan { return &v.received }
func BridgeUES1APIDsAPERValueFieldReplay(v *UES1APIDsAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeUES1APIDsAPERValueFieldWithoutReplay(v *UES1APIDsAPERValue) *bool     { return &v.withoutReplay }
func BridgeUES1APIDsFieldPerOpenTypePadding(v *UES1APIDs) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeUES1APIDsFieldPerPadding(v *UES1APIDs) *aper.CompletePadding { return &v.perPadding }
func BridgeUES1APIDsFieldReceived(v *UES1APIDs) *bool                   { return &v.received }
func BridgeUES1APIDsFieldReceivedAbsolute(v *UES1APIDs) *bool           { return &v.receivedAbsolute }
func BridgeUES1APIDsFieldReceivedBytes(v *UES1APIDs) *aper.WireSpan     { return &v.receivedBytes }
func BridgeUES1APIDsFieldReceivedLocation(v *UES1APIDs) *aper.Location  { return &v.receivedLocation }
func BridgeUES1APIDsFieldReplay(v *UES1APIDs) *aper.Snapshot            { return &v.replay }
func BridgeUES1APIDsFieldStream(v *UES1APIDs) *aper.WireSpan            { return &v.stream }
func BridgeUES1APIDsFieldWithoutReplay(v *UES1APIDs) *bool              { return &v.withoutReplay }
func BridgeUES1APIDsMethodMarshalAPERBudget(v *UES1APIDs, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUES1APIDsMethodMarshalAPERBudgetValue(v *UES1APIDs, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUES1APIDsMethodMarshalAPERChanged(v *UES1APIDs, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUES1APIDsMethodMarshalAPERChangedValue(v *UES1APIDs, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUES1APIDsMethodMarshalAPERLegacy(v *UES1APIDs) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUES1APIDsMethodMarshalAPERNewValue(v *UES1APIDs, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUES1APIDsMethodMarshalAPERPlanned(v *UES1APIDs, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUES1APIDsMethodMarshalAPERTo(v *UES1APIDs, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUES1APIDsMethodUnmarshalAPERFrom(v *UES1APIDs, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUES1APIDsMethodUnmarshalAPERLegacy(v *UES1APIDs, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUES1APIDsMethodUnmarshalAPERWithOptions(v *UES1APIDs, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUES1APIDsValueCodecFieldCapture(v *UES1APIDsValueCodec) *func(UES1APIDs, aper.DecodeState) (UES1APIDs, aper.Snapshot) {
	return &v.capture
}
func BridgeUES1APIDsValueCodecFieldCompare(v *UES1APIDsValueCodec) *func(UES1APIDs, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUES1APIDsValueCodecFieldContext(v *UES1APIDsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUES1APIDsValueCodecFieldDecode(v *UES1APIDsValueCodec) *func([]byte, aper.DecodeState) (UES1APIDs, error) {
	return &v.decode
}
func BridgeUES1APIDsValueCodecFieldEncode(v *UES1APIDsValueCodec) *func(UES1APIDs, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUES1APIDsValueCodecFieldPath(v *UES1APIDsValueCodec) *aper.Path { return &v.path }
func BridgeUES1APIDsValueCodecMethodEncodeBudgetValue(v UES1APIDsValueCodec, a0 UES1APIDs, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUES1APIDsValueCodecMethodEncodeChanged(v UES1APIDsValueCodec, a0 UES1APIDs, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUESecurityCapabilitiesAPERValueFieldContext(v *UESecurityCapabilitiesAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUESecurityCapabilitiesAPERValueFieldReceived(v *UESecurityCapabilitiesAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUESecurityCapabilitiesAPERValueFieldReplay(v *UESecurityCapabilitiesAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUESecurityCapabilitiesAPERValueFieldWithoutReplay(v *UESecurityCapabilitiesAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUESecurityCapabilitiesFieldExtCount(v *UESecurityCapabilities) *int64   { return &v.extCount }
func BridgeUESecurityCapabilitiesFieldExtData(v *UESecurityCapabilities) *[][]byte { return &v.extData }
func BridgeUESecurityCapabilitiesFieldExtOrigin(v *UESecurityCapabilities) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUESecurityCapabilitiesFieldExtPresent(v *UESecurityCapabilities) *[]bool {
	return &v.extPresent
}
func BridgeUESecurityCapabilitiesFieldExtWire(v *UESecurityCapabilities) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeUESecurityCapabilitiesFieldIEExtensionsIndef(v *UESecurityCapabilities) *bool {
	return &v.iEExtensionsIndef
}
func BridgeUESecurityCapabilitiesFieldPerExtPadding(v *UESecurityCapabilities) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeUESecurityCapabilitiesFieldPerPadding(v *UESecurityCapabilities) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeUESecurityCapabilitiesFieldReceived(v *UESecurityCapabilities) *bool { return &v.received }
func BridgeUESecurityCapabilitiesFieldReceivedAbsolute(v *UESecurityCapabilities) *bool {
	return &v.receivedAbsolute
}
func BridgeUESecurityCapabilitiesFieldReceivedBytes(v *UESecurityCapabilities) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUESecurityCapabilitiesFieldReceivedLocation(v *UESecurityCapabilities) *aper.Location {
	return &v.receivedLocation
}
func BridgeUESecurityCapabilitiesFieldReplay(v *UESecurityCapabilities) *aper.Snapshot {
	return &v.replay
}
func BridgeUESecurityCapabilitiesFieldStream(v *UESecurityCapabilities) *aper.WireSpan {
	return &v.stream
}
func BridgeUESecurityCapabilitiesFieldWithoutReplay(v *UESecurityCapabilities) *bool {
	return &v.withoutReplay
}
func BridgeUESecurityCapabilitiesMethodMarshalAPERBudget(v *UESecurityCapabilities, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUESecurityCapabilitiesMethodMarshalAPERBudgetValue(v *UESecurityCapabilities, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeUESecurityCapabilitiesMethodMarshalAPERChanged(v *UESecurityCapabilities, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUESecurityCapabilitiesMethodMarshalAPERChangedValue(v *UESecurityCapabilities, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUESecurityCapabilitiesMethodMarshalAPERLegacy(v *UESecurityCapabilities) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUESecurityCapabilitiesMethodMarshalAPERNewValue(v *UESecurityCapabilities, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeUESecurityCapabilitiesMethodMarshalAPERPlanned(v *UESecurityCapabilities, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeUESecurityCapabilitiesMethodMarshalAPERTo(v *UESecurityCapabilities, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUESecurityCapabilitiesMethodUnmarshalAPERFrom(v *UESecurityCapabilities, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUESecurityCapabilitiesMethodUnmarshalAPERLegacy(v *UESecurityCapabilities, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUESecurityCapabilitiesMethodUnmarshalAPERWithOptions(v *UESecurityCapabilities, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUESecurityCapabilitiesValueCodecFieldCapture(v *UESecurityCapabilitiesValueCodec) *func(UESecurityCapabilities, aper.DecodeState) (UESecurityCapabilities, aper.Snapshot) {
	return &v.capture
}
func BridgeUESecurityCapabilitiesValueCodecFieldCompare(v *UESecurityCapabilitiesValueCodec) *func(UESecurityCapabilities, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUESecurityCapabilitiesValueCodecFieldContext(v *UESecurityCapabilitiesValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUESecurityCapabilitiesValueCodecFieldDecode(v *UESecurityCapabilitiesValueCodec) *func([]byte, aper.DecodeState) (UESecurityCapabilities, error) {
	return &v.decode
}
func BridgeUESecurityCapabilitiesValueCodecFieldEncode(v *UESecurityCapabilitiesValueCodec) *func(UESecurityCapabilities, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUESecurityCapabilitiesValueCodecFieldPath(v *UESecurityCapabilitiesValueCodec) *aper.Path {
	return &v.path
}
func BridgeUESecurityCapabilitiesValueCodecMethodEncodeBudgetValue(v UESecurityCapabilitiesValueCodec, a0 UESecurityCapabilities, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUESecurityCapabilitiesValueCodecMethodEncodeChanged(v UESecurityCapabilitiesValueCodec, a0 UESecurityCapabilities, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
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
func BridgeUnsuccessfulValueFieldBodyMMEConfigurationUpdateFailure(v *UnsuccessfulValue) **s26.MMEConfigurationUpdateFailure {
	return &v.bodyMMEConfigurationUpdateFailure
}
func BridgeUnsuccessfulValueFieldBodyPathSwitchRequestFailure(v *UnsuccessfulValue) **s26.PathSwitchRequestFailure {
	return &v.bodyPathSwitchRequestFailure
}
func BridgeUnsuccessfulValueFieldBodyS1RemovalFailure(v *UnsuccessfulValue) **s27.S1RemovalFailure {
	return &v.bodyS1RemovalFailure
}
func BridgeUnsuccessfulValueFieldBodyS1SetupFailure(v *UnsuccessfulValue) **s27.S1SetupFailure {
	return &v.bodyS1SetupFailure
}
func BridgeUnsuccessfulValueFieldBodyUEContextModificationFailure(v *UnsuccessfulValue) **s36.UEContextModificationFailure {
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

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *UEContextReleaseCommandIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 99:
		if value, ok := v.AsUES1APIDs(); ok {
			return value, true
		}
	case 2:
		if value, ok := v.AsCause(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *UnsuccessfulValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.code {
	case 0:
		if value, ok := v.AsHandoverPreparationFailure(); ok {
			return value, true
		}
	case 1:
		if value, ok := v.AsHandoverFailure(); ok {
			return value, true
		}
	case 3:
		if value, ok := v.AsPathSwitchRequestFailure(); ok {
			return value, true
		}
	case 9:
		if value, ok := v.AsInitialContextSetupFailure(); ok {
			return value, true
		}
	case 17:
		if value, ok := v.AsS1SetupFailure(); ok {
			return value, true
		}
	case 21:
		if value, ok := v.AsUEContextModificationFailure(); ok {
			return value, true
		}
	case 29:
		if value, ok := v.AsENBConfigurationUpdateFailure(); ok {
			return value, true
		}
	case 30:
		if value, ok := v.AsMMEConfigurationUpdateFailure(); ok {
			return value, true
		}
	case 56:
		if value, ok := v.AsUEContextResumeFailure(); ok {
			return value, true
		}
	case 67:
		if value, ok := v.AsS1RemovalFailure(); ok {
			return value, true
		}
	}
	return nil, false
}
