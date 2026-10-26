// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s46 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s46

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s03 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s03"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s08 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s08"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s16 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s17"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s25 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s25"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s28 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s28"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s39 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s39"
	s45 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s45"
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
	capture func(s29.HandoverPreparationFailure, aper.DecodeState,

	) (s29.HandoverPreparationFailure, aper.Snapshot,

	)
	compare func(s29.HandoverPreparationFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s29.HandoverPreparationFailure,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s29.HandoverPreparationFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s29.HandoverPreparationFailure,

		error)
	inject func(s29.HandoverPreparationFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b HandoverPreparationFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverPreparationFailureUnsuccessfulBinding) Codec() s29.HandoverPreparationFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s29.HandoverPreparationFailureValueCodec{}
	}
	return func() s29.HandoverPreparationFailureValueCodec {
		sealed := s29.HandoverPreparationFailureValueCodec{}
		*s29.BridgeHandoverPreparationFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s29.BridgeHandoverPreparationFailureValueCodecFieldDecode(&sealed) = b.decode
		*s29.BridgeHandoverPreparationFailureValueCodecFieldEncode(&sealed) = func(value s29.HandoverPreparationFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s29.BridgeHandoverPreparationFailureValueCodecFieldCapture(&sealed) = b.capture
		*s29.BridgeHandoverPreparationFailureValueCodecFieldCompare(&sealed) = b.compare
		*s29.BridgeHandoverPreparationFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b HandoverPreparationFailureUnsuccessfulBinding) Build(body s29.HandoverPreparationFailure,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s29.HandoverFailure, aper.DecodeState,

	) (s29.HandoverFailure, aper.Snapshot,

	)
	compare func(s29.HandoverFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s29.HandoverFailure,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s29.HandoverFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s29.HandoverFailure,

		error)
	inject func(s29.HandoverFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b HandoverFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverFailureUnsuccessfulBinding) Codec() s29.HandoverFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s29.HandoverFailureValueCodec{}
	}
	return func() s29.HandoverFailureValueCodec {
		sealed := s29.HandoverFailureValueCodec{}
		*s29.BridgeHandoverFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s29.BridgeHandoverFailureValueCodecFieldDecode(&sealed) = b.decode
		*s29.BridgeHandoverFailureValueCodecFieldEncode(&sealed) = func(value s29.HandoverFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s29.BridgeHandoverFailureValueCodecFieldCapture(&sealed) = b.capture
		*s29.BridgeHandoverFailureValueCodecFieldCompare(&sealed) = b.compare
		*s29.BridgeHandoverFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b HandoverFailureUnsuccessfulBinding) Build(body s29.HandoverFailure,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s30.PathSwitchRequestFailure, aper.DecodeState,

	) (s30.PathSwitchRequestFailure, aper.Snapshot,

	)
	compare func(s30.PathSwitchRequestFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s30.PathSwitchRequestFailure,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s30.PathSwitchRequestFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s30.PathSwitchRequestFailure,

		error)
	inject func(s30.PathSwitchRequestFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b PathSwitchRequestFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b PathSwitchRequestFailureUnsuccessfulBinding) Codec() s30.PathSwitchRequestFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s30.PathSwitchRequestFailureValueCodec{}
	}
	return func() s30.PathSwitchRequestFailureValueCodec {
		sealed := s30.PathSwitchRequestFailureValueCodec{}
		*s30.BridgePathSwitchRequestFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s30.BridgePathSwitchRequestFailureValueCodecFieldDecode(&sealed) = b.decode
		*s30.BridgePathSwitchRequestFailureValueCodecFieldEncode(&sealed) = func(value s30.PathSwitchRequestFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s30.BridgePathSwitchRequestFailureValueCodecFieldCapture(&sealed) = b.capture
		*s30.BridgePathSwitchRequestFailureValueCodecFieldCompare(&sealed) = b.compare
		*s30.BridgePathSwitchRequestFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b PathSwitchRequestFailureUnsuccessfulBinding) Build(body s30.PathSwitchRequestFailure,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s30.InitialContextSetupFailure, aper.DecodeState,

	) (s30.InitialContextSetupFailure, aper.Snapshot,

	)
	compare func(s30.InitialContextSetupFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s30.InitialContextSetupFailure,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s30.InitialContextSetupFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s30.InitialContextSetupFailure,

		error)
	inject func(s30.InitialContextSetupFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupFailureUnsuccessfulBinding) Codec() s30.InitialContextSetupFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s30.InitialContextSetupFailureValueCodec{}
	}
	return func() s30.InitialContextSetupFailureValueCodec {
		sealed := s30.InitialContextSetupFailureValueCodec{}
		*s30.BridgeInitialContextSetupFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s30.BridgeInitialContextSetupFailureValueCodecFieldDecode(&sealed) = b.decode
		*s30.BridgeInitialContextSetupFailureValueCodecFieldEncode(&sealed) = func(value s30.InitialContextSetupFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s30.BridgeInitialContextSetupFailureValueCodecFieldCapture(&sealed) = b.capture
		*s30.BridgeInitialContextSetupFailureValueCodecFieldCompare(&sealed) = b.compare
		*s30.BridgeInitialContextSetupFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b InitialContextSetupFailureUnsuccessfulBinding) Build(body s30.InitialContextSetupFailure,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s31.S1SetupFailure, aper.DecodeState,

	) (s31.S1SetupFailure, aper.Snapshot,

	)
	compare func(s31.S1SetupFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s31.S1SetupFailure,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s31.S1SetupFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s31.S1SetupFailure,

		error)
	inject func(s31.S1SetupFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b S1SetupFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1SetupFailureUnsuccessfulBinding) Codec() s31.S1SetupFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s31.S1SetupFailureValueCodec{}
	}
	return func() s31.S1SetupFailureValueCodec {
		sealed := s31.S1SetupFailureValueCodec{}
		*s31.BridgeS1SetupFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s31.BridgeS1SetupFailureValueCodecFieldDecode(&sealed) = b.decode
		*s31.BridgeS1SetupFailureValueCodecFieldEncode(&sealed) = func(value s31.S1SetupFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s31.BridgeS1SetupFailureValueCodecFieldCapture(&sealed) = b.capture
		*s31.BridgeS1SetupFailureValueCodecFieldCompare(&sealed) = b.compare
		*s31.BridgeS1SetupFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b S1SetupFailureUnsuccessfulBinding) Build(body s31.S1SetupFailure,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s45.UEContextModificationFailure, aper.DecodeState,

	) (s45.UEContextModificationFailure, aper.Snapshot,

	)
	compare func(s45.UEContextModificationFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s45.UEContextModificationFailure,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s45.UEContextModificationFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s45.UEContextModificationFailure,

		error)
	inject func(s45.UEContextModificationFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b UEContextModificationFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextModificationFailureUnsuccessfulBinding) Codec() UEContextModificationFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return UEContextModificationFailureValueCodec{}
	}
	return UEContextModificationFailureValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value s45.UEContextModificationFailure,

		fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates a body and constructs its bound procedure message.
func (b UEContextModificationFailureUnsuccessfulBinding) Build(body s45.UEContextModificationFailure,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s28.ENBConfigurationUpdateFailure, aper.DecodeState,

	) (s28.ENBConfigurationUpdateFailure, aper.Snapshot,

	)
	compare func(s28.ENBConfigurationUpdateFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s28.ENBConfigurationUpdateFailure,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s28.ENBConfigurationUpdateFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s28.ENBConfigurationUpdateFailure,

		error)
	inject func(s28.ENBConfigurationUpdateFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b ENBConfigurationUpdateFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b ENBConfigurationUpdateFailureUnsuccessfulBinding) Codec() s28.ENBConfigurationUpdateFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s28.ENBConfigurationUpdateFailureValueCodec{}
	}
	return func() s28.ENBConfigurationUpdateFailureValueCodec {
		sealed := s28.ENBConfigurationUpdateFailureValueCodec{}
		*s28.BridgeENBConfigurationUpdateFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s28.BridgeENBConfigurationUpdateFailureValueCodecFieldDecode(&sealed) = b.decode
		*s28.BridgeENBConfigurationUpdateFailureValueCodecFieldEncode(&sealed) = func(value s28.ENBConfigurationUpdateFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s28.BridgeENBConfigurationUpdateFailureValueCodecFieldCapture(&sealed) = b.capture
		*s28.BridgeENBConfigurationUpdateFailureValueCodecFieldCompare(&sealed) = b.compare
		*s28.BridgeENBConfigurationUpdateFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b ENBConfigurationUpdateFailureUnsuccessfulBinding) Build(body s28.ENBConfigurationUpdateFailure,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s30.MMEConfigurationUpdateFailure, aper.DecodeState,

	) (s30.MMEConfigurationUpdateFailure, aper.Snapshot,

	)
	compare func(s30.MMEConfigurationUpdateFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s30.MMEConfigurationUpdateFailure,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s30.MMEConfigurationUpdateFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s30.MMEConfigurationUpdateFailure,

		error)
	inject func(s30.MMEConfigurationUpdateFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b MMEConfigurationUpdateFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b MMEConfigurationUpdateFailureUnsuccessfulBinding) Codec() s30.MMEConfigurationUpdateFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s30.MMEConfigurationUpdateFailureValueCodec{}
	}
	return func() s30.MMEConfigurationUpdateFailureValueCodec {
		sealed := s30.MMEConfigurationUpdateFailureValueCodec{}
		*s30.BridgeMMEConfigurationUpdateFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s30.BridgeMMEConfigurationUpdateFailureValueCodecFieldDecode(&sealed) = b.decode
		*s30.BridgeMMEConfigurationUpdateFailureValueCodecFieldEncode(&sealed) = func(value s30.MMEConfigurationUpdateFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s30.BridgeMMEConfigurationUpdateFailureValueCodecFieldCapture(&sealed) = b.capture
		*s30.BridgeMMEConfigurationUpdateFailureValueCodecFieldCompare(&sealed) = b.compare
		*s30.BridgeMMEConfigurationUpdateFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b MMEConfigurationUpdateFailureUnsuccessfulBinding) Build(body s30.MMEConfigurationUpdateFailure,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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

		*aper.DecodeBudget) (s25.ValidationReport, error)
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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
	capture func(s31.S1RemovalFailure, aper.DecodeState,

	) (s31.S1RemovalFailure, aper.Snapshot,

	)
	compare func(s31.S1RemovalFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
	info     s00.ProcedureInfo
	validate func(*s31.S1RemovalFailure,

		*aper.DecodeBudget) (s25.ValidationReport, error)
	encode func(*s31.S1RemovalFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s31.S1RemovalFailure,

		error)
	inject func(s31.S1RemovalFailure,

	) UnsuccessfulValue
}

// Info returns the source descriptor for this binding.
func (b S1RemovalFailureUnsuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b S1RemovalFailureUnsuccessfulBinding) Codec() s31.S1RemovalFailureValueCodec {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s31.S1RemovalFailureValueCodec{}
	}
	return func() s31.S1RemovalFailureValueCodec {
		sealed := s31.S1RemovalFailureValueCodec{}
		*s31.BridgeS1RemovalFailureValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s31.BridgeS1RemovalFailureValueCodecFieldDecode(&sealed) = b.decode
		*s31.BridgeS1RemovalFailureValueCodecFieldEncode(&sealed) = func(value s31.S1RemovalFailure,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s31.BridgeS1RemovalFailureValueCodecFieldCapture(&sealed) = b.capture
		*s31.BridgeS1RemovalFailureValueCodecFieldCompare(&sealed) = b.compare
		*s31.BridgeS1RemovalFailureValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates a body and constructs its bound procedure message.
func (b S1RemovalFailureUnsuccessfulBinding) Build(body s31.S1RemovalFailure,

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
	if *s25.BridgeValidationReportFieldErr(&report) != nil {
		return UnsuccessfulOutcome{}, aper.OperationError(*s25.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s25.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return UnsuccessfulOutcome{}, aper.OperationError(&s25.BuildError{Issues: issues}, "Build")
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
func BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIEContainer(v *s24.UEContextModificationIndicationIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIEContainer(v *s24.UEContextModificationIndicationIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIEContainer(v *s27.UEContextModificationResponseIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextModificationResponseIEValueCompareS1APProtocolIEContainer(v *s27.UEContextModificationResponseIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEContainer(v *s27.UEContextResumeFailureIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEContainer(v *s27.UEContextResumeFailureIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEContainer(v *s36.UEContextSuspendResponseIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEContainer(v *s36.UEContextSuspendResponseIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEInformationTransferIEValueCaptureS1APProtocolIEContainer(v *s39.UEInformationTransferIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEInformationTransferIEValueCompareS1APProtocolIEContainer(v *s39.UEInformationTransferIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIEContainer(v *s14.UERadioCapabilityIDMappingRequestIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIEContainer(v *s14.UERadioCapabilityIDMappingRequestIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEContainer(v *s28.UERadioCapabilityIDMappingResponseIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEContainer(v *s28.UERadioCapabilityIDMappingResponseIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIEContainer(v *s14.UERadioCapabilityMatchRequestIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIEContainer(v *s14.UERadioCapabilityMatchRequestIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEContainer(v *s28.UERadioCapabilityMatchResponseIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEContainer(v *s28.UERadioCapabilityMatchResponseIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUES1APIDPairExtIEsValueCaptureS1APProtocolExtensionContainer(v *s14.UES1APIDPairExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUES1APIDPairExtIEsValueCompareS1APProtocolExtensionContainer(v *s14.UES1APIDPairExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
	codec  s17.CauseValueCodec
	inject func(s17.Cause,

	) UEContextReleaseCommandIEValue

	get func(*UEContextReleaseCommandIEValue,

	) (*s17.Cause,

		bool)
}

// Info returns the source descriptor for this binding.
func (b UEContextReleaseCommandCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b UEContextReleaseCommandCauseIEBinding) Codec() s17.CauseValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b UEContextReleaseCommandCauseIEBinding) New(value s17.Cause,

) (UEContextReleaseCommandIEField, error) {
	if b.inject == nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s17.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UEContextReleaseCommandIEField{}, aper.OperationError(err, "Value.New")
	}
	return UEContextReleaseCommandIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b UEContextReleaseCommandCauseIEBinding) Get(field *UEContextReleaseCommandIEField) (*s17.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// UEContextModificationFailureValueCodec is the concrete ValueCodec[UEContextModificationFailure].
type UEContextModificationFailureValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s45.UEContextModificationFailure,

		error)
	encode func(s45.UEContextModificationFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s45.UEContextModificationFailure, aper.DecodeState,

	) (s45.UEContextModificationFailure, aper.Snapshot,

	)
	compare func(s45.UEContextModificationFailure, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEContextModificationFailureValueCodec) New(value s45.UEContextModificationFailure,

) (s45.UEContextModificationFailureAPERValue, error) {
	if c.encode == nil {
		return s45.UEContextModificationFailureAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s45.UEContextModificationFailureAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return s45.UEContextModificationFailureAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return s45.UEContextModificationFailureAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEContextModificationFailureValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (s45.UEContextModificationFailureAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return s45.UEContextModificationFailureAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return s45.UEContextModificationFailureAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return func() s45.UEContextModificationFailureAPERValue {
			sealed := s45.UEContextModificationFailureAPERValue{Value: value}
			*s45.BridgeUEContextModificationFailureAPERValueFieldReceived(&sealed) = aper.OriginalWire(data)
			*s45.BridgeUEContextModificationFailureAPERValueFieldReplay(&sealed) = replay
			*s45.BridgeUEContextModificationFailureAPERValueFieldContext(&sealed) = c.context
			return sealed
		}(), report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return s45.UEContextModificationFailureAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEContextModificationFailureValueCodec) EncodeAPER(value s45.UEContextModificationFailureAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := *s45.BridgeUEContextModificationFailureAPERValueFieldWithoutReplay(&value) || aper.EncodeWithoutReplay(options...)
	if *s45.BridgeUEContextModificationFailureAPERValueFieldContext(&value) == c.context && !fresh && (*s45.BridgeUEContextModificationFailureAPERValueFieldReplay(&value)).Present() {
		plan, next := c.compare(value.Value, *s45.BridgeUEContextModificationFailureAPERValueFieldReplay(&value), budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(*s45.BridgeUEContextModificationFailureAPERValueFieldReplay(&value)) {
			out, err := aper.CopyReplay(*s45.BridgeUEContextModificationFailureAPERValueFieldReceived(&value), &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEContextModificationFailureValueCodec) encodeBudgetValue(value s45.UEContextModificationFailure,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEContextModificationFailureValueCodec) encodeChanged(value s45.UEContextModificationFailure,

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
func BridgeUEContextModificationResponseIEValueValidateS1APIEContainer(fields s27.UEContextModificationResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s27.BridgeUEContextModificationResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s27.BridgeUEContextModificationResponseIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s27.BridgeUEContextModificationResponseIEValueMethodRule(field.Value).Assignment
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
func BridgeUEContextModificationFailureIEValueValidateS1APIEContainer(fields s27.UEContextModificationFailureIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s27.BridgeUEContextModificationFailureIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s27.BridgeUEContextModificationFailureIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s27.BridgeUEContextModificationFailureIEValueMethodRule(field.Value).Assignment
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
func BridgeUERadioCapabilityMatchRequestIEValueValidateS1APIEContainer(fields s14.UERadioCapabilityMatchRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s14.BridgeUERadioCapabilityMatchRequestIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s14.BridgeUERadioCapabilityMatchRequestIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s14.BridgeUERadioCapabilityMatchRequestIEValueMethodRule(field.Value).Assignment
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
func BridgeUERadioCapabilityMatchResponseIEValueValidateS1APIEContainer(fields s28.UERadioCapabilityMatchResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s28.BridgeUERadioCapabilityMatchResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s28.BridgeUERadioCapabilityMatchResponseIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s28.BridgeUERadioCapabilityMatchResponseIEValueMethodRule(field.Value).Assignment
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
func BridgeUEContextModificationIndicationIEValueValidateS1APIEContainer(fields s24.UEContextModificationIndicationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s24.BridgeUEContextModificationIndicationIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s24.BridgeUEContextModificationIndicationIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s24.BridgeUEContextModificationIndicationIEValueMethodRule(field.Value).Assignment
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
func BridgeUEContextSuspendResponseIEValueValidateS1APIEContainer(fields s36.UEContextSuspendResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s36.BridgeUEContextSuspendResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s36.BridgeUEContextSuspendResponseIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s36.BridgeUEContextSuspendResponseIEValueMethodRule(field.Value).Assignment
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
func BridgeUEContextResumeFailureIEValueValidateS1APIEContainer(fields s27.UEContextResumeFailureIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s27.BridgeUEContextResumeFailureIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s27.BridgeUEContextResumeFailureIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s27.BridgeUEContextResumeFailureIEValueMethodRule(field.Value).Assignment
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
func BridgeUEInformationTransferIEValueValidateS1APIEContainer(fields s39.UEInformationTransferIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s39.BridgeUEInformationTransferIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s39.BridgeUEInformationTransferIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s39.BridgeUEInformationTransferIEValueMethodRule(field.Value).Assignment
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
func BridgeUERadioCapabilityIDMappingRequestIEValueValidateS1APIEContainer(fields s14.UERadioCapabilityIDMappingRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s08.BridgeUERadioCapabilityIDMappingRequestIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s08.BridgeUERadioCapabilityIDMappingRequestIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s08.BridgeUERadioCapabilityIDMappingRequestIEValueMethodRule(field.Value).Assignment
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
func BridgeUERadioCapabilityIDMappingResponseIEValueValidateS1APIEContainer(fields s28.UERadioCapabilityIDMappingResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s28.BridgeUERadioCapabilityIDMappingResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s28.BridgeUERadioCapabilityIDMappingResponseIEValueMethodRule(field.Value)
			s25.BridgeValidationReportMethodAddIssue(&report, s25.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s31.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s28.BridgeUERadioCapabilityIDMappingResponseIEValueMethodRule(field.Value).Assignment
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

// UEContextModificationFailureIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEContextModificationFailureIEs}} codec of TS 36.413.
func UEContextModificationFailureIEValueERABIEContainerListCodec(table s00.UEContextModificationFailureIEValueIETable) s27.UEContextModificationFailureIEValueERABIEContainerListValueCodec {
	codec := s45.UEContextModificationFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s27.BridgeUEContextModificationFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s27.UEContextModificationFailureIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s27.UEContextModificationFailureIEValueERABIEContainerListValueCodec {
		sealed := s27.UEContextModificationFailureIEValueERABIEContainerListValueCodec{}
		*s27.BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "UEContextModificationFailureIEValueERABIEContainerList"
		*s27.BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.UEContextModificationFailureIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s27.UEContextModificationFailureIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s27.UEContextModificationFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s27.BridgeUEContextModificationFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
				return nil, runtime.WrapDecodePath(err, "UEContextModificationFailureIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationFailureIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "UEContextModificationFailureIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s27.BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s27.UEContextModificationFailureIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s27.BridgeUEContextModificationFailureIEContainerValueCodecFieldEncode(&codec))(s27.UEContextModificationFailureIEContainer(value), fresh, budget)
		}
		*s27.BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s27.UEContextModificationFailureIEValueERABIEContainerList, options aper.DecodeState) (s27.UEContextModificationFailureIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s45.BridgeUEContextModificationFailureIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s27.BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s27.UEContextModificationFailureIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationFailureIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgeUEContextModificationFailureIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationIndicationIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEContextModificationIndicationIEs}} codec of TS 36.413.
func UEContextModificationIndicationIEValueERABIEContainerListCodec(table s00.UEContextModificationIndicationIEValueIETable) s24.UEContextModificationIndicationIEValueERABIEContainerListValueCodec {
	codec := UEContextModificationIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s24.BridgeUEContextModificationIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UEContextModificationIndicationIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s24.UEContextModificationIndicationIEValueERABIEContainerListValueCodec {
		sealed := s24.UEContextModificationIndicationIEValueERABIEContainerListValueCodec{}
		*s24.BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "UEContextModificationIndicationIEValueERABIEContainerList"
		*s24.BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UEContextModificationIndicationIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UEContextModificationIndicationIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UEContextModificationIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUEContextModificationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s24.BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UEContextModificationIndicationIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeUEContextModificationIndicationIEContainerValueCodecFieldEncode(&codec))(s24.UEContextModificationIndicationIEContainer(value), fresh, budget)
		}
		*s24.BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UEContextModificationIndicationIEValueERABIEContainerList, options aper.DecodeState) (s24.UEContextModificationIndicationIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s24.BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UEContextModificationIndicationIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUEContextModificationIndicationIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationResponseIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEContextModificationResponseIEs}} codec of TS 36.413.
func UEContextModificationResponseIEValueERABIEContainerListCodec(table s00.UEContextModificationResponseIEValueIETable) s27.UEContextModificationResponseIEValueERABIEContainerListValueCodec {
	codec := UEContextModificationResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s27.BridgeUEContextModificationResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s27.UEContextModificationResponseIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s27.UEContextModificationResponseIEValueERABIEContainerListValueCodec {
		sealed := s27.UEContextModificationResponseIEValueERABIEContainerListValueCodec{}
		*s27.BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "UEContextModificationResponseIEValueERABIEContainerList"
		*s27.BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.UEContextModificationResponseIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s27.UEContextModificationResponseIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s27.UEContextModificationResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s27.BridgeUEContextModificationResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s27.BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s27.UEContextModificationResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s27.BridgeUEContextModificationResponseIEContainerValueCodecFieldEncode(&codec))(s27.UEContextModificationResponseIEContainer(value), fresh, budget)
		}
		*s27.BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s27.UEContextModificationResponseIEValueERABIEContainerList, options aper.DecodeState) (s27.UEContextModificationResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s27.BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s27.UEContextModificationResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgeUEContextModificationResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextResumeFailureIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEContextResumeFailureIEs}} codec of TS 36.413.
func UEContextResumeFailureIEValueERABIEContainerListCodec(table s00.UEContextResumeFailureIEValueIETable) s27.UEContextResumeFailureIEValueERABIEContainerListValueCodec {
	codec := UEContextResumeFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s27.BridgeUEContextResumeFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s27.UEContextResumeFailureIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s27.UEContextResumeFailureIEValueERABIEContainerListValueCodec {
		sealed := s27.UEContextResumeFailureIEValueERABIEContainerListValueCodec{}
		*s27.BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "UEContextResumeFailureIEValueERABIEContainerList"
		*s27.BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.UEContextResumeFailureIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s27.UEContextResumeFailureIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s27.UEContextResumeFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s27.BridgeUEContextResumeFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s27.BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s27.UEContextResumeFailureIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s27.BridgeUEContextResumeFailureIEContainerValueCodecFieldEncode(&codec))(s27.UEContextResumeFailureIEContainer(value), fresh, budget)
		}
		*s27.BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s27.UEContextResumeFailureIEValueERABIEContainerList, options aper.DecodeState) (s27.UEContextResumeFailureIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s27.BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s27.UEContextResumeFailureIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgeUEContextResumeFailureIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextSuspendResponseIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEContextSuspendResponseIEs}} codec of TS 36.413.
func UEContextSuspendResponseIEValueERABIEContainerListCodec(table s00.UEContextSuspendResponseIEValueIETable) s36.UEContextSuspendResponseIEValueERABIEContainerListValueCodec {
	codec := UEContextSuspendResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s36.BridgeUEContextSuspendResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s36.UEContextSuspendResponseIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s36.UEContextSuspendResponseIEValueERABIEContainerListValueCodec {
		sealed := s36.UEContextSuspendResponseIEValueERABIEContainerListValueCodec{}
		*s36.BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "UEContextSuspendResponseIEValueERABIEContainerList"
		*s36.BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.UEContextSuspendResponseIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s36.UEContextSuspendResponseIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s36.UEContextSuspendResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s36.BridgeUEContextSuspendResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s36.BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s36.UEContextSuspendResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s36.BridgeUEContextSuspendResponseIEContainerValueCodecFieldEncode(&codec))(s36.UEContextSuspendResponseIEContainer(value), fresh, budget)
		}
		*s36.BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s36.UEContextSuspendResponseIEValueERABIEContainerList, options aper.DecodeState) (s36.UEContextSuspendResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s36.BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s36.UEContextSuspendResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s36.BridgeUEContextSuspendResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEInformationTransferIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UEInformationTransferIEs}} codec of TS 36.413.
func UEInformationTransferIEValueERABIEContainerListCodec(table s00.UEInformationTransferIEValueIETable) s39.UEInformationTransferIEValueERABIEContainerListValueCodec {
	codec := UEInformationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s39.BridgeUEInformationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s39.UEInformationTransferIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s39.UEInformationTransferIEValueERABIEContainerListValueCodec {
		sealed := s39.UEInformationTransferIEValueERABIEContainerListValueCodec{}
		*s39.BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "UEInformationTransferIEValueERABIEContainerList"
		*s39.BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s39.UEInformationTransferIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s39.UEInformationTransferIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s39.UEInformationTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s39.BridgeUEInformationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s39.BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s39.UEInformationTransferIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s39.BridgeUEInformationTransferIEContainerValueCodecFieldEncode(&codec))(s39.UEInformationTransferIEContainer(value), fresh, budget)
		}
		*s39.BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s39.UEInformationTransferIEValueERABIEContainerList, options aper.DecodeState) (s39.UEInformationTransferIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s39.BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s39.UEInformationTransferIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s39.BridgeUEInformationTransferIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityIDMappingRequestIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UERadioCapabilityIDMappingRequestIEs}} codec of TS 36.413.
func UERadioCapabilityIDMappingRequestIEValueERABIEContainerListCodec(table s00.UERadioCapabilityIDMappingRequestIEValueIETable) s14.UERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodec {
	codec := UERadioCapabilityIDMappingRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s14.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s14.UERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s14.UERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodec {
		sealed := s14.UERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodec{}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "UERadioCapabilityIDMappingRequestIEValueERABIEContainerList"
		*s14.BridgeUERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.UERadioCapabilityIDMappingRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeUERadioCapabilityIDMappingRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s14.BridgeUERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s14.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s14.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldEncode(&codec))(s14.UERadioCapabilityIDMappingRequestIEContainer(value), fresh, budget)
		}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s14.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList, options aper.DecodeState) (s14.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s14.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityIDMappingResponseIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UERadioCapabilityIDMappingResponseIEs}} codec of TS 36.413.
func UERadioCapabilityIDMappingResponseIEValueERABIEContainerListCodec(table s00.UERadioCapabilityIDMappingResponseIEValueIETable) s28.UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec {
	codec := UERadioCapabilityIDMappingResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s28.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s28.UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s28.UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec {
		sealed := s28.UERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodec{}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "UERadioCapabilityIDMappingResponseIEValueERABIEContainerList"
		*s28.BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s28.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s28.UERadioCapabilityIDMappingResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s28.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s28.BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s28.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s28.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldEncode(&codec))(s28.UERadioCapabilityIDMappingResponseIEContainer(value), fresh, budget)
		}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s28.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, options aper.DecodeState) (s28.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s28.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityMatchRequestIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UERadioCapabilityMatchRequestIEs}} codec of TS 36.413.
func UERadioCapabilityMatchRequestIEValueERABIEContainerListCodec(table s00.UERadioCapabilityMatchRequestIEValueIETable) s14.UERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodec {
	codec := UERadioCapabilityMatchRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s14.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s14.UERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s14.UERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodec {
		sealed := s14.UERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodec{}
		*s14.BridgeUERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "UERadioCapabilityMatchRequestIEValueERABIEContainerList"
		*s14.BridgeUERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UERadioCapabilityMatchRequestIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.UERadioCapabilityMatchRequestIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.UERadioCapabilityMatchRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeUERadioCapabilityMatchRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s14.BridgeUERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s14.UERadioCapabilityMatchRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s14.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldEncode(&codec))(s14.UERadioCapabilityMatchRequestIEContainer(value), fresh, budget)
		}
		*s14.BridgeUERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s14.UERadioCapabilityMatchRequestIEValueERABIEContainerList, options aper.DecodeState) (s14.UERadioCapabilityMatchRequestIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s14.BridgeUERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s14.UERadioCapabilityMatchRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUERadioCapabilityMatchRequestIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityMatchResponseIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{UERadioCapabilityMatchResponseIEs}} codec of TS 36.413.
func UERadioCapabilityMatchResponseIEValueERABIEContainerListCodec(table s00.UERadioCapabilityMatchResponseIEValueIETable) s28.UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec {
	codec := UERadioCapabilityMatchResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s28.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s28.UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s28.UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec {
		sealed := s28.UERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodec{}
		*s28.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldPath(&sealed) = "UERadioCapabilityMatchResponseIEValueERABIEContainerList"
		*s28.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.UERadioCapabilityMatchResponseIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s28.UERadioCapabilityMatchResponseIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s28.UERadioCapabilityMatchResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s28.BridgeUERadioCapabilityMatchResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s28.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s28.UERadioCapabilityMatchResponseIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s28.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldEncode(&codec))(s28.UERadioCapabilityMatchResponseIEContainer(value), fresh, budget)
		}
		*s28.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s28.UERadioCapabilityMatchResponseIEValueERABIEContainerList, options aper.DecodeState) (s28.UERadioCapabilityMatchResponseIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s28.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s28.UERadioCapabilityMatchResponseIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeUERadioCapabilityMatchResponseIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UES1APIDPairExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{UE-S1AP-ID-pair-ExtIEs}} codec of TS 36.413.
func UES1APIDPairExtIEsValueExtensionFieldTableCodec(table s00.UES1APIDPairExtIEsValueExtensionTable) s14.UES1APIDPairExtIEsExtFieldValueCodec {
	if !*s00.BridgeUES1APIDPairExtIEsValueExtensionTableFieldBound(&table) {
		return s14.UES1APIDPairExtIEsExtFieldValueCodec{}
	}
	return func() s14.UES1APIDPairExtIEsExtFieldValueCodec {
		sealed := s14.UES1APIDPairExtIEsExtFieldValueCodec{}
		*s14.BridgeUES1APIDPairExtIEsExtFieldValueCodecFieldPath(&sealed) = "UES1APIDPairExtIEsExtField"
		*s14.BridgeUES1APIDPairExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UES1APIDPairExtIEsExtField, error) {
			var field s14.UES1APIDPairExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s14.BridgeUES1APIDPairExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UES1APIDPairExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UES1APIDPairExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UES1APIDPairExtIEsExtField")
			}
			return field, nil
		}
		*s14.BridgeUES1APIDPairExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s14.UES1APIDPairExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s14.BridgeUES1APIDPairExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s14.BridgeUES1APIDPairExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s14.UES1APIDPairExtIEsExtField, options aper.DecodeState) (s14.UES1APIDPairExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUES1APIDPairExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s14.BridgeUES1APIDPairExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s14.UES1APIDPairExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUES1APIDPairExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUES1APIDPairExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UES1APIDPairExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{UE-S1AP-ID-pair-ExtIEs}} codec of TS 36.413.
func UES1APIDPairExtIEsValueExtensionTableCodec(table s00.UES1APIDPairExtIEsValueExtensionTable, bounds aper.ListBounds) s14.UES1APIDPairExtIEsExtContainerValueCodec {
	if !*s00.BridgeUES1APIDPairExtIEsValueExtensionTableFieldBound(&table) {
		return s14.UES1APIDPairExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s14.UES1APIDPairExtIEsExtContainerValueCodec {
		sealed := s14.UES1APIDPairExtIEsExtContainerValueCodec{}
		*s14.BridgeUES1APIDPairExtIEsExtContainerValueCodecFieldPath(&sealed) = "UES1APIDPairExtIEsExtContainer"
		*s14.BridgeUES1APIDPairExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UES1APIDPairExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.UES1APIDPairExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.UES1APIDPairExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeUES1APIDPairExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s14.BridgeUES1APIDPairExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s14.UES1APIDPairExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s14.BridgeUES1APIDPairExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s14.BridgeUES1APIDPairExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s14.UES1APIDPairExtIEsExtContainer, options aper.DecodeState) (s14.UES1APIDPairExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUES1APIDPairExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeUES1APIDPairExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s14.UES1APIDPairExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUES1APIDPairExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUES1APIDPairExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationIndicationIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEContextModificationIndicationIEs}} codec of TS 36.413.
func UEContextModificationIndicationIEValueIEFieldTableCodec(table s00.UEContextModificationIndicationIEValueIETable) s24.UEContextModificationIndicationIEFieldValueCodec {
	if !*s00.BridgeUEContextModificationIndicationIEValueIETableFieldBound(&table) {
		return s24.UEContextModificationIndicationIEFieldValueCodec{}
	}
	return func() s24.UEContextModificationIndicationIEFieldValueCodec {
		sealed := s24.UEContextModificationIndicationIEFieldValueCodec{}
		*s24.BridgeUEContextModificationIndicationIEFieldValueCodecFieldPath(&sealed) = "UEContextModificationIndicationIEField"
		*s24.BridgeUEContextModificationIndicationIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UEContextModificationIndicationIEField, error) {
			var field s24.UEContextModificationIndicationIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s24.BridgeUEContextModificationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextModificationIndicationIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationIndicationIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextModificationIndicationIEField")
			}
			return field, nil
		}
		*s24.BridgeUEContextModificationIndicationIEFieldValueCodecFieldEncode(&sealed) = func(field s24.UEContextModificationIndicationIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s24.BridgeUEContextModificationIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s24.BridgeUEContextModificationIndicationIEFieldValueCodecFieldCapture(&sealed) = func(v s24.UEContextModificationIndicationIEField, options aper.DecodeState) (s24.UEContextModificationIndicationIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgeUEContextModificationIndicationIEFieldValueCodecFieldCompare(&sealed) = func(v s24.UEContextModificationIndicationIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUEContextModificationIndicationIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationResponseIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEContextModificationResponseIEs}} codec of TS 36.413.
func UEContextModificationResponseIEValueIEFieldTableCodec(table s00.UEContextModificationResponseIEValueIETable) s27.UEContextModificationResponseIEFieldValueCodec {
	if !*s00.BridgeUEContextModificationResponseIEValueIETableFieldBound(&table) {
		return s27.UEContextModificationResponseIEFieldValueCodec{}
	}
	return func() s27.UEContextModificationResponseIEFieldValueCodec {
		sealed := s27.UEContextModificationResponseIEFieldValueCodec{}
		*s27.BridgeUEContextModificationResponseIEFieldValueCodecFieldPath(&sealed) = "UEContextModificationResponseIEField"
		*s27.BridgeUEContextModificationResponseIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.UEContextModificationResponseIEField, error) {
			var field s27.UEContextModificationResponseIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s27.BridgeUEContextModificationResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextModificationResponseIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextModificationResponseIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextModificationResponseIEField")
			}
			return field, nil
		}
		*s27.BridgeUEContextModificationResponseIEFieldValueCodecFieldEncode(&sealed) = func(field s27.UEContextModificationResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s27.BridgeUEContextModificationResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s27.BridgeUEContextModificationResponseIEFieldValueCodecFieldCapture(&sealed) = func(v s27.UEContextModificationResponseIEField, options aper.DecodeState) (s27.UEContextModificationResponseIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s27.BridgeUEContextModificationResponseIEFieldValueCodecFieldCompare(&sealed) = func(v s27.UEContextModificationResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgeUEContextModificationResponseIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextResumeFailureIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEContextResumeFailureIEs}} codec of TS 36.413.
func UEContextResumeFailureIEValueIEFieldTableCodec(table s00.UEContextResumeFailureIEValueIETable) s27.UEContextResumeFailureIEFieldValueCodec {
	if !*s00.BridgeUEContextResumeFailureIEValueIETableFieldBound(&table) {
		return s27.UEContextResumeFailureIEFieldValueCodec{}
	}
	return func() s27.UEContextResumeFailureIEFieldValueCodec {
		sealed := s27.UEContextResumeFailureIEFieldValueCodec{}
		*s27.BridgeUEContextResumeFailureIEFieldValueCodecFieldPath(&sealed) = "UEContextResumeFailureIEField"
		*s27.BridgeUEContextResumeFailureIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.UEContextResumeFailureIEField, error) {
			var field s27.UEContextResumeFailureIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s27.BridgeUEContextResumeFailureIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextResumeFailureIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextResumeFailureIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextResumeFailureIEField")
			}
			return field, nil
		}
		*s27.BridgeUEContextResumeFailureIEFieldValueCodecFieldEncode(&sealed) = func(field s27.UEContextResumeFailureIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s27.BridgeUEContextResumeFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s27.BridgeUEContextResumeFailureIEFieldValueCodecFieldCapture(&sealed) = func(v s27.UEContextResumeFailureIEField, options aper.DecodeState) (s27.UEContextResumeFailureIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s27.BridgeUEContextResumeFailureIEFieldValueCodecFieldCompare(&sealed) = func(v s27.UEContextResumeFailureIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgeUEContextResumeFailureIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextSuspendResponseIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEContextSuspendResponseIEs}} codec of TS 36.413.
func UEContextSuspendResponseIEValueIEFieldTableCodec(table s00.UEContextSuspendResponseIEValueIETable) s36.UEContextSuspendResponseIEFieldValueCodec {
	if !*s00.BridgeUEContextSuspendResponseIEValueIETableFieldBound(&table) {
		return s36.UEContextSuspendResponseIEFieldValueCodec{}
	}
	return func() s36.UEContextSuspendResponseIEFieldValueCodec {
		sealed := s36.UEContextSuspendResponseIEFieldValueCodec{}
		*s36.BridgeUEContextSuspendResponseIEFieldValueCodecFieldPath(&sealed) = "UEContextSuspendResponseIEField"
		*s36.BridgeUEContextSuspendResponseIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.UEContextSuspendResponseIEField, error) {
			var field s36.UEContextSuspendResponseIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s36.BridgeUEContextSuspendResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextSuspendResponseIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEContextSuspendResponseIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UEContextSuspendResponseIEField")
			}
			return field, nil
		}
		*s36.BridgeUEContextSuspendResponseIEFieldValueCodecFieldEncode(&sealed) = func(field s36.UEContextSuspendResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s36.BridgeUEContextSuspendResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s36.BridgeUEContextSuspendResponseIEFieldValueCodecFieldCapture(&sealed) = func(v s36.UEContextSuspendResponseIEField, options aper.DecodeState) (s36.UEContextSuspendResponseIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s36.BridgeUEContextSuspendResponseIEFieldValueCodecFieldCompare(&sealed) = func(v s36.UEContextSuspendResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s36.BridgeUEContextSuspendResponseIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEInformationTransferIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UEInformationTransferIEs}} codec of TS 36.413.
func UEInformationTransferIEValueIEFieldTableCodec(table s00.UEInformationTransferIEValueIETable) s39.UEInformationTransferIEFieldValueCodec {
	if !*s00.BridgeUEInformationTransferIEValueIETableFieldBound(&table) {
		return s39.UEInformationTransferIEFieldValueCodec{}
	}
	return func() s39.UEInformationTransferIEFieldValueCodec {
		sealed := s39.UEInformationTransferIEFieldValueCodec{}
		*s39.BridgeUEInformationTransferIEFieldValueCodecFieldPath(&sealed) = "UEInformationTransferIEField"
		*s39.BridgeUEInformationTransferIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s39.UEInformationTransferIEField, error) {
			var field s39.UEInformationTransferIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s39.BridgeUEInformationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UEInformationTransferIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UEInformationTransferIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UEInformationTransferIEField")
			}
			return field, nil
		}
		*s39.BridgeUEInformationTransferIEFieldValueCodecFieldEncode(&sealed) = func(field s39.UEInformationTransferIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s39.BridgeUEInformationTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s39.BridgeUEInformationTransferIEFieldValueCodecFieldCapture(&sealed) = func(v s39.UEInformationTransferIEField, options aper.DecodeState) (s39.UEInformationTransferIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s39.BridgeUEInformationTransferIEFieldValueCodecFieldCompare(&sealed) = func(v s39.UEInformationTransferIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s39.BridgeUEInformationTransferIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityIDMappingRequestIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UERadioCapabilityIDMappingRequestIEs}} codec of TS 36.413.
func UERadioCapabilityIDMappingRequestIEValueIEFieldTableCodec(table s00.UERadioCapabilityIDMappingRequestIEValueIETable) s14.UERadioCapabilityIDMappingRequestIEFieldValueCodec {
	if !*s00.BridgeUERadioCapabilityIDMappingRequestIEValueIETableFieldBound(&table) {
		return s14.UERadioCapabilityIDMappingRequestIEFieldValueCodec{}
	}
	return func() s14.UERadioCapabilityIDMappingRequestIEFieldValueCodec {
		sealed := s14.UERadioCapabilityIDMappingRequestIEFieldValueCodec{}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEFieldValueCodecFieldPath(&sealed) = "UERadioCapabilityIDMappingRequestIEField"
		*s14.BridgeUERadioCapabilityIDMappingRequestIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UERadioCapabilityIDMappingRequestIEField, error) {
			var field s14.UERadioCapabilityIDMappingRequestIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s14.BridgeUERadioCapabilityIDMappingRequestIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingRequestIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityIDMappingRequestIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingRequestIEField")
			}
			return field, nil
		}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEFieldValueCodecFieldEncode(&sealed) = func(field s14.UERadioCapabilityIDMappingRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s14.BridgeUERadioCapabilityIDMappingRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEFieldValueCodecFieldCapture(&sealed) = func(v s14.UERadioCapabilityIDMappingRequestIEField, options aper.DecodeState) (s14.UERadioCapabilityIDMappingRequestIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEFieldValueCodecFieldCompare(&sealed) = func(v s14.UERadioCapabilityIDMappingRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityIDMappingResponseIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UERadioCapabilityIDMappingResponseIEs}} codec of TS 36.413.
func UERadioCapabilityIDMappingResponseIEValueIEFieldTableCodec(table s00.UERadioCapabilityIDMappingResponseIEValueIETable) s28.UERadioCapabilityIDMappingResponseIEFieldValueCodec {
	if !*s00.BridgeUERadioCapabilityIDMappingResponseIEValueIETableFieldBound(&table) {
		return s28.UERadioCapabilityIDMappingResponseIEFieldValueCodec{}
	}
	return func() s28.UERadioCapabilityIDMappingResponseIEFieldValueCodec {
		sealed := s28.UERadioCapabilityIDMappingResponseIEFieldValueCodec{}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldPath(&sealed) = "UERadioCapabilityIDMappingResponseIEField"
		*s28.BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.UERadioCapabilityIDMappingResponseIEField, error) {
			var field s28.UERadioCapabilityIDMappingResponseIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s28.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponseIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityIDMappingResponseIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UERadioCapabilityIDMappingResponseIEField")
			}
			return field, nil
		}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldEncode(&sealed) = func(field s28.UERadioCapabilityIDMappingResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s28.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldCapture(&sealed) = func(v s28.UERadioCapabilityIDMappingResponseIEField, options aper.DecodeState) (s28.UERadioCapabilityIDMappingResponseIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldCompare(&sealed) = func(v s28.UERadioCapabilityIDMappingResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityMatchRequestIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UERadioCapabilityMatchRequestIEs}} codec of TS 36.413.
func UERadioCapabilityMatchRequestIEValueIEFieldTableCodec(table s00.UERadioCapabilityMatchRequestIEValueIETable) s14.UERadioCapabilityMatchRequestIEFieldValueCodec {
	if !*s00.BridgeUERadioCapabilityMatchRequestIEValueIETableFieldBound(&table) {
		return s14.UERadioCapabilityMatchRequestIEFieldValueCodec{}
	}
	return func() s14.UERadioCapabilityMatchRequestIEFieldValueCodec {
		sealed := s14.UERadioCapabilityMatchRequestIEFieldValueCodec{}
		*s14.BridgeUERadioCapabilityMatchRequestIEFieldValueCodecFieldPath(&sealed) = "UERadioCapabilityMatchRequestIEField"
		*s14.BridgeUERadioCapabilityMatchRequestIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UERadioCapabilityMatchRequestIEField, error) {
			var field s14.UERadioCapabilityMatchRequestIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s14.BridgeUERadioCapabilityMatchRequestIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UERadioCapabilityMatchRequestIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityMatchRequestIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UERadioCapabilityMatchRequestIEField")
			}
			return field, nil
		}
		*s14.BridgeUERadioCapabilityMatchRequestIEFieldValueCodecFieldEncode(&sealed) = func(field s14.UERadioCapabilityMatchRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s14.BridgeUERadioCapabilityMatchRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s14.BridgeUERadioCapabilityMatchRequestIEFieldValueCodecFieldCapture(&sealed) = func(v s14.UERadioCapabilityMatchRequestIEField, options aper.DecodeState) (s14.UERadioCapabilityMatchRequestIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeUERadioCapabilityMatchRequestIEFieldValueCodecFieldCompare(&sealed) = func(v s14.UERadioCapabilityMatchRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUERadioCapabilityMatchRequestIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityMatchResponseIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{UERadioCapabilityMatchResponseIEs}} codec of TS 36.413.
func UERadioCapabilityMatchResponseIEValueIEFieldTableCodec(table s00.UERadioCapabilityMatchResponseIEValueIETable) s28.UERadioCapabilityMatchResponseIEFieldValueCodec {
	if !*s00.BridgeUERadioCapabilityMatchResponseIEValueIETableFieldBound(&table) {
		return s28.UERadioCapabilityMatchResponseIEFieldValueCodec{}
	}
	return func() s28.UERadioCapabilityMatchResponseIEFieldValueCodec {
		sealed := s28.UERadioCapabilityMatchResponseIEFieldValueCodec{}
		*s28.BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldPath(&sealed) = "UERadioCapabilityMatchResponseIEField"
		*s28.BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.UERadioCapabilityMatchResponseIEField, error) {
			var field s28.UERadioCapabilityMatchResponseIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s28.BridgeUERadioCapabilityMatchResponseIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponseIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "UERadioCapabilityMatchResponseIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "UERadioCapabilityMatchResponseIEField")
			}
			return field, nil
		}
		*s28.BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldEncode(&sealed) = func(field s28.UERadioCapabilityMatchResponseIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s28.BridgeUERadioCapabilityMatchResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s28.BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldCapture(&sealed) = func(v s28.UERadioCapabilityMatchResponseIEField, options aper.DecodeState) (s28.UERadioCapabilityMatchResponseIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldCompare(&sealed) = func(v s28.UERadioCapabilityMatchResponseIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeUERadioCapabilityMatchResponseIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationIndicationIEValueIETableCodec constructs the ProtocolIE-Container {{UEContextModificationIndicationIEs}} codec of TS 36.413.
func UEContextModificationIndicationIEValueIETableCodec(table s00.UEContextModificationIndicationIEValueIETable, bounds aper.ListBounds) s24.UEContextModificationIndicationIEContainerValueCodec {
	if !*s00.BridgeUEContextModificationIndicationIEValueIETableFieldBound(&table) {
		return s24.UEContextModificationIndicationIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s24.UEContextModificationIndicationIEContainerValueCodec {
		sealed := s24.UEContextModificationIndicationIEContainerValueCodec{}
		*s24.BridgeUEContextModificationIndicationIEContainerValueCodecFieldPath(&sealed) = "UEContextModificationIndicationIEContainer"
		*s24.BridgeUEContextModificationIndicationIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UEContextModificationIndicationIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UEContextModificationIndicationIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UEContextModificationIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUEContextModificationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s24.BridgeUEContextModificationIndicationIEContainerValueCodecFieldEncode(&sealed) = func(fields s24.UEContextModificationIndicationIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s24.BridgeUEContextModificationIndicationIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s24.BridgeUEContextModificationIndicationIEContainerValueCodecFieldCapture(&sealed) = func(v s24.UEContextModificationIndicationIEContainer, options aper.DecodeState) (s24.UEContextModificationIndicationIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s24.BridgeUEContextModificationIndicationIEContainerValueCodecFieldCompare(&sealed) = func(v s24.UEContextModificationIndicationIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUEContextModificationIndicationIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationResponseIEValueIETableCodec constructs the ProtocolIE-Container {{UEContextModificationResponseIEs}} codec of TS 36.413.
func UEContextModificationResponseIEValueIETableCodec(table s00.UEContextModificationResponseIEValueIETable, bounds aper.ListBounds) s27.UEContextModificationResponseIEContainerValueCodec {
	if !*s00.BridgeUEContextModificationResponseIEValueIETableFieldBound(&table) {
		return s27.UEContextModificationResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s27.UEContextModificationResponseIEContainerValueCodec {
		sealed := s27.UEContextModificationResponseIEContainerValueCodec{}
		*s27.BridgeUEContextModificationResponseIEContainerValueCodecFieldPath(&sealed) = "UEContextModificationResponseIEContainer"
		*s27.BridgeUEContextModificationResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.UEContextModificationResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s27.UEContextModificationResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s27.UEContextModificationResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s27.BridgeUEContextModificationResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s27.BridgeUEContextModificationResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s27.UEContextModificationResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s27.BridgeUEContextModificationResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s27.BridgeUEContextModificationResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s27.UEContextModificationResponseIEContainer, options aper.DecodeState) (s27.UEContextModificationResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s27.BridgeUEContextModificationResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s27.UEContextModificationResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgeUEContextModificationResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextResumeFailureIEValueIETableCodec constructs the ProtocolIE-Container {{UEContextResumeFailureIEs}} codec of TS 36.413.
func UEContextResumeFailureIEValueIETableCodec(table s00.UEContextResumeFailureIEValueIETable, bounds aper.ListBounds) s27.UEContextResumeFailureIEContainerValueCodec {
	if !*s00.BridgeUEContextResumeFailureIEValueIETableFieldBound(&table) {
		return s27.UEContextResumeFailureIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s27.UEContextResumeFailureIEContainerValueCodec {
		sealed := s27.UEContextResumeFailureIEContainerValueCodec{}
		*s27.BridgeUEContextResumeFailureIEContainerValueCodecFieldPath(&sealed) = "UEContextResumeFailureIEContainer"
		*s27.BridgeUEContextResumeFailureIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.UEContextResumeFailureIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s27.UEContextResumeFailureIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s27.UEContextResumeFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s27.BridgeUEContextResumeFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s27.BridgeUEContextResumeFailureIEContainerValueCodecFieldEncode(&sealed) = func(fields s27.UEContextResumeFailureIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s27.BridgeUEContextResumeFailureIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s27.BridgeUEContextResumeFailureIEContainerValueCodecFieldCapture(&sealed) = func(v s27.UEContextResumeFailureIEContainer, options aper.DecodeState) (s27.UEContextResumeFailureIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s27.BridgeUEContextResumeFailureIEContainerValueCodecFieldCompare(&sealed) = func(v s27.UEContextResumeFailureIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgeUEContextResumeFailureIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextSuspendResponseIEValueIETableCodec constructs the ProtocolIE-Container {{UEContextSuspendResponseIEs}} codec of TS 36.413.
func UEContextSuspendResponseIEValueIETableCodec(table s00.UEContextSuspendResponseIEValueIETable, bounds aper.ListBounds) s36.UEContextSuspendResponseIEContainerValueCodec {
	if !*s00.BridgeUEContextSuspendResponseIEValueIETableFieldBound(&table) {
		return s36.UEContextSuspendResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s36.UEContextSuspendResponseIEContainerValueCodec {
		sealed := s36.UEContextSuspendResponseIEContainerValueCodec{}
		*s36.BridgeUEContextSuspendResponseIEContainerValueCodecFieldPath(&sealed) = "UEContextSuspendResponseIEContainer"
		*s36.BridgeUEContextSuspendResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.UEContextSuspendResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s36.UEContextSuspendResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s36.UEContextSuspendResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s36.BridgeUEContextSuspendResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s36.BridgeUEContextSuspendResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s36.UEContextSuspendResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s36.BridgeUEContextSuspendResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s36.BridgeUEContextSuspendResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s36.UEContextSuspendResponseIEContainer, options aper.DecodeState) (s36.UEContextSuspendResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s36.BridgeUEContextSuspendResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s36.UEContextSuspendResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s36.BridgeUEContextSuspendResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEInformationTransferIEValueIETableCodec constructs the ProtocolIE-Container {{UEInformationTransferIEs}} codec of TS 36.413.
func UEInformationTransferIEValueIETableCodec(table s00.UEInformationTransferIEValueIETable, bounds aper.ListBounds) s39.UEInformationTransferIEContainerValueCodec {
	if !*s00.BridgeUEInformationTransferIEValueIETableFieldBound(&table) {
		return s39.UEInformationTransferIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s39.UEInformationTransferIEContainerValueCodec {
		sealed := s39.UEInformationTransferIEContainerValueCodec{}
		*s39.BridgeUEInformationTransferIEContainerValueCodecFieldPath(&sealed) = "UEInformationTransferIEContainer"
		*s39.BridgeUEInformationTransferIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s39.UEInformationTransferIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s39.UEInformationTransferIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s39.UEInformationTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s39.BridgeUEInformationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s39.BridgeUEInformationTransferIEContainerValueCodecFieldEncode(&sealed) = func(fields s39.UEInformationTransferIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s39.BridgeUEInformationTransferIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s39.BridgeUEInformationTransferIEContainerValueCodecFieldCapture(&sealed) = func(v s39.UEInformationTransferIEContainer, options aper.DecodeState) (s39.UEInformationTransferIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s39.BridgeUEInformationTransferIEContainerValueCodecFieldCompare(&sealed) = func(v s39.UEInformationTransferIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s39.BridgeUEInformationTransferIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityIDMappingRequestIEValueIETableCodec constructs the ProtocolIE-Container {{UERadioCapabilityIDMappingRequestIEs}} codec of TS 36.413.
func UERadioCapabilityIDMappingRequestIEValueIETableCodec(table s00.UERadioCapabilityIDMappingRequestIEValueIETable, bounds aper.ListBounds) s14.UERadioCapabilityIDMappingRequestIEContainerValueCodec {
	if !*s00.BridgeUERadioCapabilityIDMappingRequestIEValueIETableFieldBound(&table) {
		return s14.UERadioCapabilityIDMappingRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s14.UERadioCapabilityIDMappingRequestIEContainerValueCodec {
		sealed := s14.UERadioCapabilityIDMappingRequestIEContainerValueCodec{}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldPath(&sealed) = "UERadioCapabilityIDMappingRequestIEContainer"
		*s14.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UERadioCapabilityIDMappingRequestIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.UERadioCapabilityIDMappingRequestIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.UERadioCapabilityIDMappingRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeUERadioCapabilityIDMappingRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s14.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldEncode(&sealed) = func(fields s14.UERadioCapabilityIDMappingRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s14.BridgeUERadioCapabilityIDMappingRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s14.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldCapture(&sealed) = func(v s14.UERadioCapabilityIDMappingRequestIEContainer, options aper.DecodeState) (s14.UERadioCapabilityIDMappingRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldCompare(&sealed) = func(v s14.UERadioCapabilityIDMappingRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityIDMappingResponseIEValueIETableCodec constructs the ProtocolIE-Container {{UERadioCapabilityIDMappingResponseIEs}} codec of TS 36.413.
func UERadioCapabilityIDMappingResponseIEValueIETableCodec(table s00.UERadioCapabilityIDMappingResponseIEValueIETable, bounds aper.ListBounds) s28.UERadioCapabilityIDMappingResponseIEContainerValueCodec {
	if !*s00.BridgeUERadioCapabilityIDMappingResponseIEValueIETableFieldBound(&table) {
		return s28.UERadioCapabilityIDMappingResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s28.UERadioCapabilityIDMappingResponseIEContainerValueCodec {
		sealed := s28.UERadioCapabilityIDMappingResponseIEContainerValueCodec{}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldPath(&sealed) = "UERadioCapabilityIDMappingResponseIEContainer"
		*s28.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.UERadioCapabilityIDMappingResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s28.UERadioCapabilityIDMappingResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s28.UERadioCapabilityIDMappingResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s28.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s28.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s28.UERadioCapabilityIDMappingResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s28.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s28.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s28.UERadioCapabilityIDMappingResponseIEContainer, options aper.DecodeState) (s28.UERadioCapabilityIDMappingResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s28.UERadioCapabilityIDMappingResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityMatchRequestIEValueIETableCodec constructs the ProtocolIE-Container {{UERadioCapabilityMatchRequestIEs}} codec of TS 36.413.
func UERadioCapabilityMatchRequestIEValueIETableCodec(table s00.UERadioCapabilityMatchRequestIEValueIETable, bounds aper.ListBounds) s14.UERadioCapabilityMatchRequestIEContainerValueCodec {
	if !*s00.BridgeUERadioCapabilityMatchRequestIEValueIETableFieldBound(&table) {
		return s14.UERadioCapabilityMatchRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s14.UERadioCapabilityMatchRequestIEContainerValueCodec {
		sealed := s14.UERadioCapabilityMatchRequestIEContainerValueCodec{}
		*s14.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldPath(&sealed) = "UERadioCapabilityMatchRequestIEContainer"
		*s14.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UERadioCapabilityMatchRequestIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.UERadioCapabilityMatchRequestIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.UERadioCapabilityMatchRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeUERadioCapabilityMatchRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s14.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldEncode(&sealed) = func(fields s14.UERadioCapabilityMatchRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s14.BridgeUERadioCapabilityMatchRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s14.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldCapture(&sealed) = func(v s14.UERadioCapabilityMatchRequestIEContainer, options aper.DecodeState) (s14.UERadioCapabilityMatchRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s14.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldCompare(&sealed) = func(v s14.UERadioCapabilityMatchRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityMatchResponseIEValueIETableCodec constructs the ProtocolIE-Container {{UERadioCapabilityMatchResponseIEs}} codec of TS 36.413.
func UERadioCapabilityMatchResponseIEValueIETableCodec(table s00.UERadioCapabilityMatchResponseIEValueIETable, bounds aper.ListBounds) s28.UERadioCapabilityMatchResponseIEContainerValueCodec {
	if !*s00.BridgeUERadioCapabilityMatchResponseIEValueIETableFieldBound(&table) {
		return s28.UERadioCapabilityMatchResponseIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s28.UERadioCapabilityMatchResponseIEContainerValueCodec {
		sealed := s28.UERadioCapabilityMatchResponseIEContainerValueCodec{}
		*s28.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldPath(&sealed) = "UERadioCapabilityMatchResponseIEContainer"
		*s28.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.UERadioCapabilityMatchResponseIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s28.UERadioCapabilityMatchResponseIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s28.UERadioCapabilityMatchResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s28.BridgeUERadioCapabilityMatchResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s28.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldEncode(&sealed) = func(fields s28.UERadioCapabilityMatchResponseIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s28.BridgeUERadioCapabilityMatchResponseIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
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
		*s28.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldCapture(&sealed) = func(v s28.UERadioCapabilityMatchResponseIEContainer, options aper.DecodeState) (s28.UERadioCapabilityMatchResponseIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s28.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldCompare(&sealed) = func(v s28.UERadioCapabilityMatchResponseIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationFailureIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEContextModificationFailureIEs}} codec of TS 36.413.
func UEContextModificationFailureIEValueProtocolErrorIEContainerListCodec(table s00.UEContextModificationFailureIEValueIETable) s27.UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec {
	codec := s45.UEContextModificationFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s27.BridgeUEContextModificationFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s27.UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s27.UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s27.UEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodec{}
		*s27.BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "UEContextModificationFailureIEValueProtocolErrorIEContainerList"
		*s27.BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.UEContextModificationFailureIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s27.UEContextModificationFailureIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s27.UEContextModificationFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s27.BridgeUEContextModificationFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s27.BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s27.UEContextModificationFailureIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s27.BridgeUEContextModificationFailureIEContainerValueCodecFieldEncode(&codec))(s27.UEContextModificationFailureIEContainer(value), fresh, budget)
		}
		*s27.BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s27.UEContextModificationFailureIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s27.UEContextModificationFailureIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s45.BridgeUEContextModificationFailureIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s27.BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s27.UEContextModificationFailureIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationFailureIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgeUEContextModificationFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationIndicationIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEContextModificationIndicationIEs}} codec of TS 36.413.
func UEContextModificationIndicationIEValueProtocolErrorIEContainerListCodec(table s00.UEContextModificationIndicationIEValueIETable) s24.UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextModificationIndicationIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s24.BridgeUEContextModificationIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s24.UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s24.UEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodec{}
		*s24.BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "UEContextModificationIndicationIEValueProtocolErrorIEContainerList"
		*s24.BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UEContextModificationIndicationIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UEContextModificationIndicationIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UEContextModificationIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUEContextModificationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s24.BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UEContextModificationIndicationIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeUEContextModificationIndicationIEContainerValueCodecFieldEncode(&codec))(s24.UEContextModificationIndicationIEContainer(value), fresh, budget)
		}
		*s24.BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UEContextModificationIndicationIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s24.UEContextModificationIndicationIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UEContextModificationIndicationIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUEContextModificationIndicationIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationResponseIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEContextModificationResponseIEs}} codec of TS 36.413.
func UEContextModificationResponseIEValueProtocolErrorIEContainerListCodec(table s00.UEContextModificationResponseIEValueIETable) s27.UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextModificationResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s27.BridgeUEContextModificationResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s27.UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s27.UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s27.UEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s27.BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "UEContextModificationResponseIEValueProtocolErrorIEContainerList"
		*s27.BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.UEContextModificationResponseIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s27.UEContextModificationResponseIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s27.UEContextModificationResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s27.BridgeUEContextModificationResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s27.BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s27.UEContextModificationResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s27.BridgeUEContextModificationResponseIEContainerValueCodecFieldEncode(&codec))(s27.UEContextModificationResponseIEContainer(value), fresh, budget)
		}
		*s27.BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s27.UEContextModificationResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s27.UEContextModificationResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s27.BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s27.UEContextModificationResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgeUEContextModificationResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextResumeFailureIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEContextResumeFailureIEs}} codec of TS 36.413.
func UEContextResumeFailureIEValueProtocolErrorIEContainerListCodec(table s00.UEContextResumeFailureIEValueIETable) s27.UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextResumeFailureIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s27.BridgeUEContextResumeFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s27.UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s27.UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s27.UEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodec{}
		*s27.BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "UEContextResumeFailureIEValueProtocolErrorIEContainerList"
		*s27.BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.UEContextResumeFailureIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s27.UEContextResumeFailureIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s27.UEContextResumeFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s27.BridgeUEContextResumeFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s27.BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s27.UEContextResumeFailureIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s27.BridgeUEContextResumeFailureIEContainerValueCodecFieldEncode(&codec))(s27.UEContextResumeFailureIEContainer(value), fresh, budget)
		}
		*s27.BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s27.UEContextResumeFailureIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s27.UEContextResumeFailureIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s27.BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s27.UEContextResumeFailureIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgeUEContextResumeFailureIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextSuspendResponseIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEContextSuspendResponseIEs}} codec of TS 36.413.
func UEContextSuspendResponseIEValueProtocolErrorIEContainerListCodec(table s00.UEContextSuspendResponseIEValueIETable) s36.UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEContextSuspendResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s36.BridgeUEContextSuspendResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s36.UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s36.UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s36.UEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s36.BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "UEContextSuspendResponseIEValueProtocolErrorIEContainerList"
		*s36.BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s36.UEContextSuspendResponseIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s36.UEContextSuspendResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s36.BridgeUEContextSuspendResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s36.BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s36.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s36.BridgeUEContextSuspendResponseIEContainerValueCodecFieldEncode(&codec))(s36.UEContextSuspendResponseIEContainer(value), fresh, budget)
		}
		*s36.BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s36.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s36.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s36.BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s36.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s36.BridgeUEContextSuspendResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEInformationTransferIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UEInformationTransferIEs}} codec of TS 36.413.
func UEInformationTransferIEValueProtocolErrorIEContainerListCodec(table s00.UEInformationTransferIEValueIETable) s39.UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec {
	codec := UEInformationTransferIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s39.BridgeUEInformationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s39.UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s39.UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s39.UEInformationTransferIEValueProtocolErrorIEContainerListValueCodec{}
		*s39.BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "UEInformationTransferIEValueProtocolErrorIEContainerList"
		*s39.BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s39.UEInformationTransferIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s39.UEInformationTransferIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s39.UEInformationTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s39.BridgeUEInformationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s39.BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s39.UEInformationTransferIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s39.BridgeUEInformationTransferIEContainerValueCodecFieldEncode(&codec))(s39.UEInformationTransferIEContainer(value), fresh, budget)
		}
		*s39.BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s39.UEInformationTransferIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s39.UEInformationTransferIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s39.BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s39.UEInformationTransferIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s39.BridgeUEInformationTransferIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UERadioCapabilityIDMappingRequestIEs}} codec of TS 36.413.
func UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListCodec(table s00.UERadioCapabilityIDMappingRequestIEValueIETable) s14.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := UERadioCapabilityIDMappingRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s14.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s14.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s14.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s14.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodec{}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList"
		*s14.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.UERadioCapabilityIDMappingRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeUERadioCapabilityIDMappingRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s14.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s14.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s14.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldEncode(&codec))(s14.UERadioCapabilityIDMappingRequestIEContainer(value), fresh, budget)
		}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s14.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s14.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s14.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UERadioCapabilityIDMappingResponseIEs}} codec of TS 36.413.
func UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListCodec(table s00.UERadioCapabilityIDMappingResponseIEValueIETable) s28.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := UERadioCapabilityIDMappingResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s28.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s28.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s28.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s28.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList"
		*s28.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s28.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s28.UERadioCapabilityIDMappingResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s28.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s28.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s28.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s28.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldEncode(&codec))(s28.UERadioCapabilityIDMappingResponseIEContainer(value), fresh, budget)
		}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s28.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s28.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s28.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UERadioCapabilityMatchRequestIEs}} codec of TS 36.413.
func UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListCodec(table s00.UERadioCapabilityMatchRequestIEValueIETable) s14.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := UERadioCapabilityMatchRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s14.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s14.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s14.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s14.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodec{}
		*s14.BridgeUERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList"
		*s14.BridgeUERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.UERadioCapabilityMatchRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeUERadioCapabilityMatchRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s14.BridgeUERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s14.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s14.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldEncode(&codec))(s14.UERadioCapabilityMatchRequestIEContainer(value), fresh, budget)
		}
		*s14.BridgeUERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s14.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s14.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeUERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s14.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{UERadioCapabilityMatchResponseIEs}} codec of TS 36.413.
func UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListCodec(table s00.UERadioCapabilityMatchResponseIEValueIETable) s28.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec {
	codec := UERadioCapabilityMatchResponseIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s28.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s28.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s28.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s28.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodec{}
		*s28.BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldPath(&sealed) = "UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList"
		*s28.BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s28.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s28.UERadioCapabilityMatchResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s28.BridgeUERadioCapabilityMatchResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s28.BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s28.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s28.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldEncode(&codec))(s28.UERadioCapabilityMatchResponseIEContainer(value), fresh, budget)
		}
		*s28.BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s28.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s28.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s28.BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s28.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeUERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationFailureIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextModificationFailureIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextModificationFailureIEValueProtocolIEContainerListCodec(table s00.UEContextModificationFailureIEValueIETable, bounds aper.ListBounds) s27.UEContextModificationFailureIEValueProtocolIEContainerListValueCodec {
	codec := s45.UEContextModificationFailureIEValueIETableCodec(table, bounds)
	if *s27.BridgeUEContextModificationFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s27.UEContextModificationFailureIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s27.UEContextModificationFailureIEValueProtocolIEContainerListValueCodec {
		sealed := s27.UEContextModificationFailureIEValueProtocolIEContainerListValueCodec{}
		*s27.BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "UEContextModificationFailureIEValueProtocolIEContainerList"
		*s27.BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.UEContextModificationFailureIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s27.UEContextModificationFailureIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s27.UEContextModificationFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s27.BridgeUEContextModificationFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s27.BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s27.UEContextModificationFailureIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s27.BridgeUEContextModificationFailureIEContainerValueCodecFieldEncode(&codec))(s27.UEContextModificationFailureIEContainer(value), fresh, budget)
		}
		*s27.BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s27.UEContextModificationFailureIEValueProtocolIEContainerList, options aper.DecodeState) (s27.UEContextModificationFailureIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s45.BridgeUEContextModificationFailureIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s27.BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s27.UEContextModificationFailureIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgeUEContextModificationFailureIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationIndicationIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextModificationIndicationIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextModificationIndicationIEValueProtocolIEContainerListCodec(table s00.UEContextModificationIndicationIEValueIETable, bounds aper.ListBounds) s24.UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec {
	codec := UEContextModificationIndicationIEValueIETableCodec(table, bounds)
	if *s24.BridgeUEContextModificationIndicationIEContainerValueCodecFieldDecode(&codec) == nil {
		return s24.UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s24.UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec {
		sealed := s24.UEContextModificationIndicationIEValueProtocolIEContainerListValueCodec{}
		*s24.BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "UEContextModificationIndicationIEValueProtocolIEContainerList"
		*s24.BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.UEContextModificationIndicationIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s24.UEContextModificationIndicationIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s24.UEContextModificationIndicationIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s24.BridgeUEContextModificationIndicationIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s24.BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s24.UEContextModificationIndicationIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s24.BridgeUEContextModificationIndicationIEContainerValueCodecFieldEncode(&codec))(s24.UEContextModificationIndicationIEContainer(value), fresh, budget)
		}
		*s24.BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s24.UEContextModificationIndicationIEValueProtocolIEContainerList, options aper.DecodeState) (s24.UEContextModificationIndicationIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s24.BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s24.UEContextModificationIndicationIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s24.BridgeUEContextModificationIndicationIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextModificationResponseIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextModificationResponseIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextModificationResponseIEValueProtocolIEContainerListCodec(table s00.UEContextModificationResponseIEValueIETable, bounds aper.ListBounds) s27.UEContextModificationResponseIEValueProtocolIEContainerListValueCodec {
	codec := UEContextModificationResponseIEValueIETableCodec(table, bounds)
	if *s27.BridgeUEContextModificationResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s27.UEContextModificationResponseIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s27.UEContextModificationResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s27.UEContextModificationResponseIEValueProtocolIEContainerListValueCodec{}
		*s27.BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "UEContextModificationResponseIEValueProtocolIEContainerList"
		*s27.BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.UEContextModificationResponseIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s27.UEContextModificationResponseIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s27.UEContextModificationResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s27.BridgeUEContextModificationResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s27.BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s27.UEContextModificationResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s27.BridgeUEContextModificationResponseIEContainerValueCodecFieldEncode(&codec))(s27.UEContextModificationResponseIEContainer(value), fresh, budget)
		}
		*s27.BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s27.UEContextModificationResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s27.UEContextModificationResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s27.BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s27.UEContextModificationResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUEContextModificationResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s27.BridgeUEContextModificationResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextResumeFailureIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextResumeFailureIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextResumeFailureIEValueProtocolIEContainerListCodec(table s00.UEContextResumeFailureIEValueIETable, bounds aper.ListBounds) s28.UEContextResumeFailureIEValueProtocolIEContainerListValueCodec {
	codec := UEContextResumeFailureIEValueIETableCodec(table, bounds)
	if *s27.BridgeUEContextResumeFailureIEContainerValueCodecFieldDecode(&codec) == nil {
		return s28.UEContextResumeFailureIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s28.UEContextResumeFailureIEValueProtocolIEContainerListValueCodec {
		sealed := s28.UEContextResumeFailureIEValueProtocolIEContainerListValueCodec{}
		*s28.BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "UEContextResumeFailureIEValueProtocolIEContainerList"
		*s28.BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s27.UEContextResumeFailureIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s27.UEContextResumeFailureIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s27.UEContextResumeFailureIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s27.BridgeUEContextResumeFailureIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s28.BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s27.UEContextResumeFailureIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s27.BridgeUEContextResumeFailureIEContainerValueCodecFieldEncode(&codec))(s27.UEContextResumeFailureIEContainer(value), fresh, budget)
		}
		*s28.BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s27.UEContextResumeFailureIEValueProtocolIEContainerList, options aper.DecodeState) (s27.UEContextResumeFailureIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s28.BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s27.UEContextResumeFailureIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeUEContextResumeFailureIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEContextSuspendResponseIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEContextSuspendResponseIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEContextSuspendResponseIEValueProtocolIEContainerListCodec(table s00.UEContextSuspendResponseIEValueIETable, bounds aper.ListBounds) s36.UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec {
	codec := UEContextSuspendResponseIEValueIETableCodec(table, bounds)
	if *s36.BridgeUEContextSuspendResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s36.UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s36.UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s36.UEContextSuspendResponseIEValueProtocolIEContainerListValueCodec{}
		*s36.BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "UEContextSuspendResponseIEValueProtocolIEContainerList"
		*s36.BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.UEContextSuspendResponseIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s36.UEContextSuspendResponseIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s36.UEContextSuspendResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s36.BridgeUEContextSuspendResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s36.BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s36.UEContextSuspendResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s36.BridgeUEContextSuspendResponseIEContainerValueCodecFieldEncode(&codec))(s36.UEContextSuspendResponseIEContainer(value), fresh, budget)
		}
		*s36.BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s36.UEContextSuspendResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s36.UEContextSuspendResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s36.BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s36.UEContextSuspendResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s36.BridgeUEContextSuspendResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UEInformationTransferIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UEInformationTransferIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UEInformationTransferIEValueProtocolIEContainerListCodec(table s00.UEInformationTransferIEValueIETable, bounds aper.ListBounds) s39.UEInformationTransferIEValueProtocolIEContainerListValueCodec {
	codec := UEInformationTransferIEValueIETableCodec(table, bounds)
	if *s39.BridgeUEInformationTransferIEContainerValueCodecFieldDecode(&codec) == nil {
		return s39.UEInformationTransferIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s39.UEInformationTransferIEValueProtocolIEContainerListValueCodec {
		sealed := s39.UEInformationTransferIEValueProtocolIEContainerListValueCodec{}
		*s39.BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "UEInformationTransferIEValueProtocolIEContainerList"
		*s39.BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s39.UEInformationTransferIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s39.UEInformationTransferIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s39.UEInformationTransferIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s39.BridgeUEInformationTransferIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s39.BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s39.UEInformationTransferIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s39.BridgeUEInformationTransferIEContainerValueCodecFieldEncode(&codec))(s39.UEInformationTransferIEContainer(value), fresh, budget)
		}
		*s39.BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s39.UEInformationTransferIEValueProtocolIEContainerList, options aper.DecodeState) (s39.UEInformationTransferIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUEInformationTransferIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s39.BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s39.UEInformationTransferIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUEInformationTransferIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s39.BridgeUEInformationTransferIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UERadioCapabilityIDMappingRequestIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListCodec(table s00.UERadioCapabilityIDMappingRequestIEValueIETable, bounds aper.ListBounds) s14.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodec {
	codec := UERadioCapabilityIDMappingRequestIEValueIETableCodec(table, bounds)
	if *s14.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s14.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s14.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodec {
		sealed := s14.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodec{}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList"
		*s14.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.UERadioCapabilityIDMappingRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeUERadioCapabilityIDMappingRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s14.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s14.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s14.BridgeUERadioCapabilityIDMappingRequestIEContainerValueCodecFieldEncode(&codec))(s14.UERadioCapabilityIDMappingRequestIEContainer(value), fresh, budget)
		}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s14.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList, options aper.DecodeState) (s14.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s14.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUERadioCapabilityIDMappingRequestIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UERadioCapabilityIDMappingResponseIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListCodec(table s00.UERadioCapabilityIDMappingResponseIEValueIETable, bounds aper.ListBounds) s28.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec {
	codec := UERadioCapabilityIDMappingResponseIEValueIETableCodec(table, bounds)
	if *s28.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s28.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s28.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s28.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodec{}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList"
		*s28.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s28.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s28.UERadioCapabilityIDMappingResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s28.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s28.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s28.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s28.BridgeUERadioCapabilityIDMappingResponseIEContainerValueCodecFieldEncode(&codec))(s28.UERadioCapabilityIDMappingResponseIEContainer(value), fresh, budget)
		}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s28.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s28.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s28.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeUERadioCapabilityIDMappingResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityMatchRequestIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UERadioCapabilityMatchRequestIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UERadioCapabilityMatchRequestIEValueProtocolIEContainerListCodec(table s00.UERadioCapabilityMatchRequestIEValueIETable, bounds aper.ListBounds) s14.UERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodec {
	codec := UERadioCapabilityMatchRequestIEValueIETableCodec(table, bounds)
	if *s14.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s14.UERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s14.UERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodec {
		sealed := s14.UERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodec{}
		*s14.BridgeUERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "UERadioCapabilityMatchRequestIEValueProtocolIEContainerList"
		*s14.BridgeUERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.UERadioCapabilityMatchRequestIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s14.UERadioCapabilityMatchRequestIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s14.UERadioCapabilityMatchRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s14.BridgeUERadioCapabilityMatchRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s14.BridgeUERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s14.UERadioCapabilityMatchRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s14.BridgeUERadioCapabilityMatchRequestIEContainerValueCodecFieldEncode(&codec))(s14.UERadioCapabilityMatchRequestIEContainer(value), fresh, budget)
		}
		*s14.BridgeUERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s14.UERadioCapabilityMatchRequestIEValueProtocolIEContainerList, options aper.DecodeState) (s14.UERadioCapabilityMatchRequestIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s14.BridgeUERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s14.UERadioCapabilityMatchRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s14.BridgeUERadioCapabilityMatchRequestIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// UERadioCapabilityMatchResponseIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {UERadioCapabilityMatchResponseIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func UERadioCapabilityMatchResponseIEValueProtocolIEContainerListCodec(table s00.UERadioCapabilityMatchResponseIEValueIETable, bounds aper.ListBounds) s28.UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec {
	codec := UERadioCapabilityMatchResponseIEValueIETableCodec(table, bounds)
	if *s28.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldDecode(&codec) == nil {
		return s28.UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s28.UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec {
		sealed := s28.UERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodec{}
		*s28.BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldPath(&sealed) = "UERadioCapabilityMatchResponseIEValueProtocolIEContainerList"
		*s28.BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s28.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s28.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s28.UERadioCapabilityMatchResponseIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s28.BridgeUERadioCapabilityMatchResponseIEFieldMethodUnmarshalAPERFrom(&field, bb)
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
		*s28.BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s28.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s28.BridgeUERadioCapabilityMatchResponseIEContainerValueCodecFieldEncode(&codec))(s28.UERadioCapabilityMatchResponseIEContainer(value), fresh, budget)
		}
		*s28.BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s28.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, options aper.DecodeState) (s28.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s28.BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s28.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s28.BridgeUERadioCapabilityMatchResponseIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
	captureSemantics(aper.SemanticCapture) s27.UEContextModificationFailureIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s27.UEContextModificationFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// uEContextModificationIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextModificationIndicationIEValue].
type UEContextModificationIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s24.UEContextModificationIndicationIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s24.UEContextModificationIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIEField(v *s24.UEContextModificationIndicationIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s24.BridgeUEContextModificationIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s24.BridgeUEContextModificationIndicationIEFieldFieldReplay(v), *s24.BridgeUEContextModificationIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIEField(v *s24.UEContextModificationIndicationIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s24.BridgeUEContextModificationIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s24.BridgeUEContextModificationIndicationIEFieldFieldReplay(v), *s24.BridgeUEContextModificationIndicationIEFieldFieldWithoutReplay(v))
}

// uEContextModificationResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextModificationResponseIEValue].
type UEContextModificationResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s27.UEContextModificationResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s27.UEContextModificationResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIEField(v *s27.UEContextModificationResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s27.BridgeUEContextModificationResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s27.BridgeUEContextModificationResponseIEFieldFieldReplay(v), *s27.BridgeUEContextModificationResponseIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextModificationResponseIEValueCompareS1APProtocolIEField(v *s27.UEContextModificationResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s27.BridgeUEContextModificationResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s27.BridgeUEContextModificationResponseIEFieldFieldReplay(v), *s27.BridgeUEContextModificationResponseIEFieldFieldWithoutReplay(v))
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

// uEContextResumeFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextResumeFailureIEValue].
type UEContextResumeFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s27.UEContextResumeFailureIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s27.UEContextResumeFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEField(v *s27.UEContextResumeFailureIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s27.BridgeUEContextResumeFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s27.BridgeUEContextResumeFailureIEFieldFieldReplay(v), *s27.BridgeUEContextResumeFailureIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEField(v *s27.UEContextResumeFailureIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s27.BridgeUEContextResumeFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s27.BridgeUEContextResumeFailureIEFieldFieldReplay(v), *s27.BridgeUEContextResumeFailureIEFieldFieldWithoutReplay(v))
}

// uEContextSuspendResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[UEContextSuspendResponseIEValue].
type UEContextSuspendResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s36.UEContextSuspendResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s36.UEContextSuspendResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEField(v *s36.UEContextSuspendResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s36.BridgeUEContextSuspendResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s36.BridgeUEContextSuspendResponseIEFieldFieldReplay(v), *s36.BridgeUEContextSuspendResponseIEFieldFieldWithoutReplay(v))
}
func BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEField(v *s36.UEContextSuspendResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s36.BridgeUEContextSuspendResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s36.BridgeUEContextSuspendResponseIEFieldFieldReplay(v), *s36.BridgeUEContextSuspendResponseIEFieldFieldWithoutReplay(v))
}

// uEInformationTransferIEValueProtocolOpenValue is the concrete protocolOpenValue[UEInformationTransferIEValue].
type UEInformationTransferIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s39.UEInformationTransferIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s39.UEInformationTransferIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUEInformationTransferIEValueCaptureS1APProtocolIEField(v *s39.UEInformationTransferIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s39.BridgeUEInformationTransferIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s39.BridgeUEInformationTransferIEFieldFieldReplay(v), *s39.BridgeUEInformationTransferIEFieldFieldWithoutReplay(v))
}
func BridgeUEInformationTransferIEValueCompareS1APProtocolIEField(v *s39.UEInformationTransferIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s39.BridgeUEInformationTransferIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s39.BridgeUEInformationTransferIEFieldFieldReplay(v), *s39.BridgeUEInformationTransferIEFieldFieldWithoutReplay(v))
}

// uERadioCapabilityIDMappingRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[UERadioCapabilityIDMappingRequestIEValue].
type UERadioCapabilityIDMappingRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s08.UERadioCapabilityIDMappingRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s08.UERadioCapabilityIDMappingRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIEField(v *s14.UERadioCapabilityIDMappingRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s08.BridgeUERadioCapabilityIDMappingRequestIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s14.BridgeUERadioCapabilityIDMappingRequestIEFieldFieldReplay(v), *s14.BridgeUERadioCapabilityIDMappingRequestIEFieldFieldWithoutReplay(v))
}
func BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIEField(v *s14.UERadioCapabilityIDMappingRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s08.BridgeUERadioCapabilityIDMappingRequestIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s14.BridgeUERadioCapabilityIDMappingRequestIEFieldFieldReplay(v), *s14.BridgeUERadioCapabilityIDMappingRequestIEFieldFieldWithoutReplay(v))
}

// uERadioCapabilityIDMappingResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[UERadioCapabilityIDMappingResponseIEValue].
type UERadioCapabilityIDMappingResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s28.UERadioCapabilityIDMappingResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s28.UERadioCapabilityIDMappingResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEField(v *s28.UERadioCapabilityIDMappingResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s28.BridgeUERadioCapabilityIDMappingResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s28.BridgeUERadioCapabilityIDMappingResponseIEFieldFieldReplay(v), *s28.BridgeUERadioCapabilityIDMappingResponseIEFieldFieldWithoutReplay(v))
}
func BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEField(v *s28.UERadioCapabilityIDMappingResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s28.BridgeUERadioCapabilityIDMappingResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s28.BridgeUERadioCapabilityIDMappingResponseIEFieldFieldReplay(v), *s28.BridgeUERadioCapabilityIDMappingResponseIEFieldFieldWithoutReplay(v))
}

// uERadioCapabilityMatchRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[UERadioCapabilityMatchRequestIEValue].
type UERadioCapabilityMatchRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s14.UERadioCapabilityMatchRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s14.UERadioCapabilityMatchRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIEField(v *s14.UERadioCapabilityMatchRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s14.BridgeUERadioCapabilityMatchRequestIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s14.BridgeUERadioCapabilityMatchRequestIEFieldFieldReplay(v), *s14.BridgeUERadioCapabilityMatchRequestIEFieldFieldWithoutReplay(v))
}
func BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIEField(v *s14.UERadioCapabilityMatchRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s14.BridgeUERadioCapabilityMatchRequestIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s14.BridgeUERadioCapabilityMatchRequestIEFieldFieldReplay(v), *s14.BridgeUERadioCapabilityMatchRequestIEFieldFieldWithoutReplay(v))
}

// uERadioCapabilityMatchResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[UERadioCapabilityMatchResponseIEValue].
type UERadioCapabilityMatchResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s28.UERadioCapabilityMatchResponseIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s28.UERadioCapabilityMatchResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEField(v *s28.UERadioCapabilityMatchResponseIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s28.BridgeUERadioCapabilityMatchResponseIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s28.BridgeUERadioCapabilityMatchResponseIEFieldFieldReplay(v), *s28.BridgeUERadioCapabilityMatchResponseIEFieldFieldWithoutReplay(v))
}
func BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEField(v *s28.UERadioCapabilityMatchResponseIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s28.BridgeUERadioCapabilityMatchResponseIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s28.BridgeUERadioCapabilityMatchResponseIEFieldFieldReplay(v), *s28.BridgeUERadioCapabilityMatchResponseIEFieldFieldWithoutReplay(v))
}
func BridgeUES1APIDPairExtIEsValueCaptureS1APProtocolExtensionField(v *s14.UES1APIDPairExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s07.BridgeUES1APIDPairExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s14.BridgeUES1APIDPairExtIEsExtFieldFieldReplay(v), *s14.BridgeUES1APIDPairExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeUES1APIDPairExtIEsValueCompareS1APProtocolExtensionField(v *s14.UES1APIDPairExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s03.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s07.BridgeUES1APIDPairExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s14.BridgeUES1APIDPairExtIEsExtFieldFieldReplay(v), *s14.BridgeUES1APIDPairExtIEsExtFieldFieldWithoutReplay(v))
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
func BridgeUEContextModificationFailureIEValueCompareS1APERABIEContainerList(v *s27.UEContextModificationFailureIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextModificationIndicationIEValueCaptureS1APERABIEContainerList(v *s24.UEContextModificationIndicationIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextModificationIndicationIEValueCompareS1APERABIEContainerList(v *s24.UEContextModificationIndicationIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextModificationResponseIEValueCaptureS1APERABIEContainerList(v *s27.UEContextModificationResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextModificationResponseIEValueCompareS1APERABIEContainerList(v *s27.UEContextModificationResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

func BridgeUEContextResumeFailureIEValueCaptureS1APERABIEContainerList(v *s27.UEContextResumeFailureIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextResumeFailureIEValueCompareS1APERABIEContainerList(v *s27.UEContextResumeFailureIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextSuspendResponseIEValueCaptureS1APERABIEContainerList(v *s36.UEContextSuspendResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextSuspendResponseIEValueCompareS1APERABIEContainerList(v *s36.UEContextSuspendResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEInformationTransferIEValueCaptureS1APERABIEContainerList(v *s39.UEInformationTransferIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEInformationTransferIEValueCompareS1APERABIEContainerList(v *s39.UEInformationTransferIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APERABIEContainerList(v *s14.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APERABIEContainerList(v *s14.UERadioCapabilityIDMappingRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APERABIEContainerList(v *s28.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APERABIEContainerList(v *s28.UERadioCapabilityIDMappingResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APERABIEContainerList(v *s14.UERadioCapabilityMatchRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityMatchRequestIEValueCompareS1APERABIEContainerList(v *s14.UERadioCapabilityMatchRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APERABIEContainerList(v *s28.UERadioCapabilityMatchResponseIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityMatchResponseIEValueCompareS1APERABIEContainerList(v *s28.UERadioCapabilityMatchResponseIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextModificationFailureIEValueCompareS1APProtocolErrorIEContainerList(v *s27.UEContextModificationFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolErrorIEContainerList(v *s24.UEContextModificationIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextModificationIndicationIEValueCompareS1APProtocolErrorIEContainerList(v *s24.UEContextModificationIndicationIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextModificationResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *s27.UEContextModificationResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextModificationResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s27.UEContextModificationResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

func BridgeUEContextResumeFailureIEValueCaptureS1APProtocolErrorIEContainerList(v *s27.UEContextResumeFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextResumeFailureIEValueCompareS1APProtocolErrorIEContainerList(v *s27.UEContextResumeFailureIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *s36.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextSuspendResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s36.UEContextSuspendResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEInformationTransferIEValueCaptureS1APProtocolErrorIEContainerList(v *s39.UEInformationTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEInformationTransferIEValueCompareS1APProtocolErrorIEContainerList(v *s39.UEInformationTransferIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *s14.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolErrorIEContainerList(v *s14.UERadioCapabilityIDMappingRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *s28.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s28.UERadioCapabilityIDMappingResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *s14.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolErrorIEContainerList(v *s14.UERadioCapabilityMatchRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolErrorIEContainerList(v *s28.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolErrorIEContainerList(v *s28.UERadioCapabilityMatchResponseIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEContainerList(v *s27.UEContextModificationFailureIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIEContainerList(v *s24.UEContextModificationIndicationIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIEContainerList(v *s24.UEContextModificationIndicationIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIEContainerList(v *s27.UEContextModificationResponseIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextModificationResponseIEValueCompareS1APProtocolIEContainerList(v *s27.UEContextModificationResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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

func BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEContainerList(v *s27.UEContextResumeFailureIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEContainerList(v *s27.UEContextResumeFailureIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEContainerList(v *s36.UEContextSuspendResponseIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEContainerList(v *s36.UEContextSuspendResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEInformationTransferIEValueCaptureS1APProtocolIEContainerList(v *s39.UEInformationTransferIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEInformationTransferIEValueCompareS1APProtocolIEContainerList(v *s39.UEInformationTransferIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIEContainerList(v *s14.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIEContainerList(v *s14.UERadioCapabilityIDMappingRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEContainerList(v *s28.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEContainerList(v *s28.UERadioCapabilityIDMappingResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIEContainerList(v *s14.UERadioCapabilityMatchRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIEContainerList(v *s14.UERadioCapabilityMatchRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEContainerList(v *s28.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
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
func BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIEContainerList(v *s28.UERadioCapabilityMatchResponseIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
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
func BridgeUEContextModificationFailureIEValueCompareS1APProtocolIESingleContainer(v *s27.UEContextModificationFailureIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s45.BridgeUEContextModificationFailureIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIESingleContainer(v *s24.UEContextModificationIndicationIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationIndicationIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIESingleContainer(v *s24.UEContextModificationIndicationIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationIndicationIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIESingleContainer(v *s27.UEContextModificationResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextModificationResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextModificationResponseIEValueCompareS1APProtocolIESingleContainer(v *s27.UEContextModificationResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
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
func BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIESingleContainer(v *s27.UEContextResumeFailureIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextResumeFailureIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextResumeFailureIEValueCompareS1APProtocolIESingleContainer(v *s27.UEContextResumeFailureIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextResumeFailureIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIESingleContainer(v *s36.UEContextSuspendResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextSuspendResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIESingleContainer(v *s36.UEContextSuspendResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEContextSuspendResponseIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUEInformationTransferIEValueCaptureS1APProtocolIESingleContainer(v *s39.UEInformationTransferIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEInformationTransferIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUEInformationTransferIEValueCompareS1APProtocolIESingleContainer(v *s39.UEInformationTransferIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUEInformationTransferIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIESingleContainer(v *s14.UERadioCapabilityIDMappingRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityIDMappingRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIESingleContainer(v *s14.UERadioCapabilityIDMappingRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityIDMappingRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIESingleContainer(v *s28.UERadioCapabilityIDMappingResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityIDMappingResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIESingleContainer(v *s28.UERadioCapabilityIDMappingResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityIDMappingResponseIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIESingleContainer(v *s14.UERadioCapabilityMatchRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityMatchRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIESingleContainer(v *s14.UERadioCapabilityMatchRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityMatchRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIESingleContainer(v *s28.UERadioCapabilityMatchResponseIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeUERadioCapabilityMatchResponseIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeUERadioCapabilityMatchResponseIEValueCompareS1APProtocolIESingleContainer(v *s28.UERadioCapabilityMatchResponseIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
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
	bodyHandoverPreparationFailure    *s29.HandoverPreparationFailure
	bodyHandoverFailure               *s29.HandoverFailure
	bodyPathSwitchRequestFailure      *s30.PathSwitchRequestFailure
	bodyInitialContextSetupFailure    *s30.InitialContextSetupFailure
	bodyS1SetupFailure                *s31.S1SetupFailure
	bodyUEContextModificationFailure  *s45.UEContextModificationFailure
	bodyENBConfigurationUpdateFailure *s28.ENBConfigurationUpdateFailure
	bodyMMEConfigurationUpdateFailure *s30.MMEConfigurationUpdateFailure
	bodyUEContextResumeFailure        *UEContextResumeFailure
	bodyS1RemovalFailure              *s31.S1RemovalFailure
}

// Opaque returns the retained opaque open value of UnsuccessfulValue and reports whether the opaque alternative is selected.
func (v *UnsuccessfulValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}

// AsHandoverPreparationFailure returns the selected HandoverPreparationFailure value of UnsuccessfulValue and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsHandoverPreparationFailure() (*s29.HandoverPreparationFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(0) || v.bodyHandoverPreparationFailure == nil {
		return nil, false
	}
	return v.bodyHandoverPreparationFailure, true
}

// AsHandoverFailure returns the selected HandoverFailure value of UnsuccessfulValue and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsHandoverFailure() (*s29.HandoverFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(1) || v.bodyHandoverFailure == nil {
		return nil, false
	}
	return v.bodyHandoverFailure, true
}

// AsPathSwitchRequestFailure returns the selected PathSwitchRequestFailure value of UnsuccessfulValue and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsPathSwitchRequestFailure() (*s30.PathSwitchRequestFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(3) || v.bodyPathSwitchRequestFailure == nil {
		return nil, false
	}
	return v.bodyPathSwitchRequestFailure, true
}

// AsInitialContextSetupFailure returns the selected InitialContextSetupFailure value of UnsuccessfulValue and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsInitialContextSetupFailure() (*s30.InitialContextSetupFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(9) || v.bodyInitialContextSetupFailure == nil {
		return nil, false
	}
	return v.bodyInitialContextSetupFailure, true
}

// AsS1SetupFailure returns the selected S1SetupFailure value of UnsuccessfulValue and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsS1SetupFailure() (*s31.S1SetupFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(17) || v.bodyS1SetupFailure == nil {
		return nil, false
	}
	return v.bodyS1SetupFailure, true
}

// AsUEContextModificationFailure returns the selected UEContextModificationFailure value of UnsuccessfulValue and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsUEContextModificationFailure() (*s45.UEContextModificationFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(21) || v.bodyUEContextModificationFailure == nil {
		return nil, false
	}
	return v.bodyUEContextModificationFailure, true
}

// AsENBConfigurationUpdateFailure returns the selected ENBConfigurationUpdateFailure value of UnsuccessfulValue and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsENBConfigurationUpdateFailure() (*s28.ENBConfigurationUpdateFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(29) || v.bodyENBConfigurationUpdateFailure == nil {
		return nil, false
	}
	return v.bodyENBConfigurationUpdateFailure, true
}

// AsMMEConfigurationUpdateFailure returns the selected MMEConfigurationUpdateFailure value of UnsuccessfulValue and reports whether that alternative is active.
func (v *UnsuccessfulValue) AsMMEConfigurationUpdateFailure() (*s30.MMEConfigurationUpdateFailure, bool) {
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
func (v *UnsuccessfulValue) AsS1RemovalFailure() (*s31.S1RemovalFailure, bool) {
	if v == nil || v.code != s00.ProcedureCode(67) || v.bodyS1RemovalFailure == nil {
		return nil, false
	}
	return v.bodyS1RemovalFailure, true
}
func BridgeDecodeUnsuccessfulValue(code s00.ProcedureCode, raw aper.OpaqueOpenType) (UnsuccessfulValue, error) {
	v := UnsuccessfulValue{code: code}
	switch code {
	case s00.ProcedureCode(0):
		var body s29.HandoverPreparationFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s29.BridgeHandoverPreparationFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.HandoverPreparationFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverPreparationFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s29.BridgeHandoverPreparationFailureFieldPerPadding(&body) = padding
		*s29.BridgeHandoverPreparationFailureFieldReceived(&body) = true
		raw.RetainContents(s29.BridgeHandoverPreparationFailureFieldReceivedBytes(&body))
		*s29.BridgeHandoverPreparationFailureFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyHandoverPreparationFailure = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(1):
		var body s29.HandoverFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s29.BridgeHandoverFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.HandoverFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s29.BridgeHandoverFailureFieldPerPadding(&body) = padding
		*s29.BridgeHandoverFailureFieldReceived(&body) = true
		raw.RetainContents(s29.BridgeHandoverFailureFieldReceivedBytes(&body))
		*s29.BridgeHandoverFailureFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyHandoverFailure = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(3):
		var body s30.PathSwitchRequestFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s30.BridgePathSwitchRequestFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.PathSwitchRequestFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PathSwitchRequestFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s30.BridgePathSwitchRequestFailureFieldPerPadding(&body) = padding
		*s30.BridgePathSwitchRequestFailureFieldReceived(&body) = true
		raw.RetainContents(s30.BridgePathSwitchRequestFailureFieldReceivedBytes(&body))
		*s30.BridgePathSwitchRequestFailureFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyPathSwitchRequestFailure = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(9):
		var body s30.InitialContextSetupFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s30.BridgeInitialContextSetupFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.InitialContextSetupFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "InitialContextSetupFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s30.BridgeInitialContextSetupFailureFieldPerPadding(&body) = padding
		*s30.BridgeInitialContextSetupFailureFieldReceived(&body) = true
		raw.RetainContents(s30.BridgeInitialContextSetupFailureFieldReceivedBytes(&body))
		*s30.BridgeInitialContextSetupFailureFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyInitialContextSetupFailure = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(17):
		var body s31.S1SetupFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s31.BridgeS1SetupFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.S1SetupFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "S1SetupFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s31.BridgeS1SetupFailureFieldPerPadding(&body) = padding
		*s31.BridgeS1SetupFailureFieldReceived(&body) = true
		raw.RetainContents(s31.BridgeS1SetupFailureFieldReceivedBytes(&body))
		*s31.BridgeS1SetupFailureFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyS1SetupFailure = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(21):
		var body s45.UEContextModificationFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s45.BridgeUEContextModificationFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.UEContextModificationFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEContextModificationFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s45.BridgeUEContextModificationFailureFieldPerPadding(&body) = padding
		*s45.BridgeUEContextModificationFailureFieldReceived(&body) = true
		raw.RetainContents(s45.BridgeUEContextModificationFailureFieldReceivedBytes(&body))
		*s45.BridgeUEContextModificationFailureFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyUEContextModificationFailure = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(29):
		var body s28.ENBConfigurationUpdateFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s28.BridgeENBConfigurationUpdateFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.ENBConfigurationUpdateFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ENBConfigurationUpdateFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s28.BridgeENBConfigurationUpdateFailureFieldPerPadding(&body) = padding
		*s28.BridgeENBConfigurationUpdateFailureFieldReceived(&body) = true
		raw.RetainContents(s28.BridgeENBConfigurationUpdateFailureFieldReceivedBytes(&body))
		*s28.BridgeENBConfigurationUpdateFailureFieldReceivedLocation(&body) = raw.ContentLocation()
		v.bodyENBConfigurationUpdateFailure = &body
		raw.RetainContents(&v.received)
	case s00.ProcedureCode(30):
		var body s30.MMEConfigurationUpdateFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s30.BridgeMMEConfigurationUpdateFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.MMEConfigurationUpdateFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "MMEConfigurationUpdateFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s30.BridgeMMEConfigurationUpdateFailureFieldPerPadding(&body) = padding
		*s30.BridgeMMEConfigurationUpdateFailureFieldReceived(&body) = true
		raw.RetainContents(s30.BridgeMMEConfigurationUpdateFailureFieldReceivedBytes(&body))
		*s30.BridgeMMEConfigurationUpdateFailureFieldReceivedLocation(&body) = raw.ContentLocation()
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
		var body s31.S1RemovalFailure
		child := raw.ChildDecodeBuffer()
		if err := child.EnterOpenType(); err != nil {
			return UnsuccessfulValue{}, err
		}
		defer child.LeaveOpenType()
		if err := s31.BridgeS1RemovalFailureMethodUnmarshalAPERFrom(&body, child); err != nil {
			return UnsuccessfulValue{}, fmt.Errorf("%s %w", "UnsuccessfulMessage.value.S1RemovalFailure:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "S1RemovalFailure")
		if err != nil {
			return UnsuccessfulValue{}, err
		}
		*s31.BridgeS1RemovalFailureFieldPerPadding(&body) = padding
		*s31.BridgeS1RemovalFailureFieldReceived(&body) = true
		raw.RetainContents(s31.BridgeS1RemovalFailureFieldReceivedBytes(&body))
		*s31.BridgeS1RemovalFailureFieldReceivedLocation(&body) = raw.ContentLocation()
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
		return s29.BridgeHandoverPreparationFailureMethodMarshalAPERBudget(v.bodyHandoverPreparationFailure, budget, fresh)
	case s00.ProcedureCode(1):
		if v.bodyHandoverFailure == nil {
			return nil, fmt.Errorf("%s value: missing HandoverFailure", "Unsuccessful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s29.BridgeHandoverFailureMethodMarshalAPERBudget(v.bodyHandoverFailure, budget, fresh)
	case s00.ProcedureCode(3):
		if v.bodyPathSwitchRequestFailure == nil {
			return nil, fmt.Errorf("%s value: missing PathSwitchRequestFailure", "Unsuccessful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s30.BridgePathSwitchRequestFailureMethodMarshalAPERBudget(v.bodyPathSwitchRequestFailure, budget, fresh)
	case s00.ProcedureCode(9):
		if v.bodyInitialContextSetupFailure == nil {
			return nil, fmt.Errorf("%s value: missing InitialContextSetupFailure", "Unsuccessful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s30.BridgeInitialContextSetupFailureMethodMarshalAPERBudget(v.bodyInitialContextSetupFailure, budget, fresh)
	case s00.ProcedureCode(17):
		if v.bodyS1SetupFailure == nil {
			return nil, fmt.Errorf("%s value: missing S1SetupFailure", "Unsuccessful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s31.BridgeS1SetupFailureMethodMarshalAPERBudget(v.bodyS1SetupFailure, budget, fresh)
	case s00.ProcedureCode(21):
		if v.bodyUEContextModificationFailure == nil {
			return nil, fmt.Errorf("%s value: missing UEContextModificationFailure", "Unsuccessful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s45.BridgeUEContextModificationFailureMethodMarshalAPERBudget(v.bodyUEContextModificationFailure, budget, fresh)
	case s00.ProcedureCode(29):
		if v.bodyENBConfigurationUpdateFailure == nil {
			return nil, fmt.Errorf("%s value: missing ENBConfigurationUpdateFailure", "Unsuccessful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s28.BridgeENBConfigurationUpdateFailureMethodMarshalAPERBudget(v.bodyENBConfigurationUpdateFailure, budget, fresh)
	case s00.ProcedureCode(30):
		if v.bodyMMEConfigurationUpdateFailure == nil {
			return nil, fmt.Errorf("%s value: missing MMEConfigurationUpdateFailure", "Unsuccessful")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		return s30.BridgeMMEConfigurationUpdateFailureMethodMarshalAPERBudget(v.bodyMMEConfigurationUpdateFailure, budget, fresh)
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
		return s31.BridgeS1RemovalFailureMethodMarshalAPERBudget(v.bodyS1RemovalFailure, budget, fresh)
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
					s17.BridgeCaptureS1APCause(v.rowCause, s)
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
	s03.BridgeCompareS1APProtocolIEID(&v.id, s)
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
					s17.BridgeCompareS1APCause(v.rowCause, s)
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
	s03.BridgeCompareS1APProcedureCode(&v.ProcedureCode, s)
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
					s29.BridgeCaptureS1APHandoverPreparationFailure(v.bodyHandoverPreparationFailure, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(1):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverFailure == nil)
				if v.bodyHandoverFailure != nil {
					s29.BridgeCaptureS1APHandoverFailure(v.bodyHandoverFailure, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(3):
			{
				f := s.Begin()
				s.Bool(v.bodyPathSwitchRequestFailure == nil)
				if v.bodyPathSwitchRequestFailure != nil {
					s30.BridgeCaptureS1APPathSwitchRequestFailure(v.bodyPathSwitchRequestFailure, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(9):
			{
				f := s.Begin()
				s.Bool(v.bodyInitialContextSetupFailure == nil)
				if v.bodyInitialContextSetupFailure != nil {
					s30.BridgeCaptureS1APInitialContextSetupFailure(v.bodyInitialContextSetupFailure, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(17):
			{
				f := s.Begin()
				s.Bool(v.bodyS1SetupFailure == nil)
				if v.bodyS1SetupFailure != nil {
					s31.BridgeCaptureS1APS1SetupFailure(v.bodyS1SetupFailure, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(21):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationFailure == nil)
				if v.bodyUEContextModificationFailure != nil {
					s45.BridgeCaptureS1APUEContextModificationFailure(v.bodyUEContextModificationFailure, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(29):
			{
				f := s.Begin()
				s.Bool(v.bodyENBConfigurationUpdateFailure == nil)
				if v.bodyENBConfigurationUpdateFailure != nil {
					s28.BridgeCaptureS1APENBConfigurationUpdateFailure(v.bodyENBConfigurationUpdateFailure, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(30):
			{
				f := s.Begin()
				s.Bool(v.bodyMMEConfigurationUpdateFailure == nil)
				if v.bodyMMEConfigurationUpdateFailure != nil {
					s30.BridgeCaptureS1APMMEConfigurationUpdateFailure(v.bodyMMEConfigurationUpdateFailure, s)
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
					s31.BridgeCaptureS1APS1RemovalFailure(v.bodyS1RemovalFailure, s)
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
				s.Bool(v.bodyHandoverPreparationFailure == nil)
				if v.bodyHandoverPreparationFailure != nil {
					s29.BridgeCompareS1APHandoverPreparationFailure(v.bodyHandoverPreparationFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(1):
			{
				f := s.Begin()
				s.Bool(v.bodyHandoverFailure == nil)
				if v.bodyHandoverFailure != nil {
					s29.BridgeCompareS1APHandoverFailure(v.bodyHandoverFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(3):
			{
				f := s.Begin()
				s.Bool(v.bodyPathSwitchRequestFailure == nil)
				if v.bodyPathSwitchRequestFailure != nil {
					s30.BridgeCompareS1APPathSwitchRequestFailure(v.bodyPathSwitchRequestFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(9):
			{
				f := s.Begin()
				s.Bool(v.bodyInitialContextSetupFailure == nil)
				if v.bodyInitialContextSetupFailure != nil {
					s30.BridgeCompareS1APInitialContextSetupFailure(v.bodyInitialContextSetupFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(17):
			{
				f := s.Begin()
				s.Bool(v.bodyS1SetupFailure == nil)
				if v.bodyS1SetupFailure != nil {
					s31.BridgeCompareS1APS1SetupFailure(v.bodyS1SetupFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(21):
			{
				f := s.Begin()
				s.Bool(v.bodyUEContextModificationFailure == nil)
				if v.bodyUEContextModificationFailure != nil {
					s45.BridgeCompareS1APUEContextModificationFailure(v.bodyUEContextModificationFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(29):
			{
				f := s.Begin()
				s.Bool(v.bodyENBConfigurationUpdateFailure == nil)
				if v.bodyENBConfigurationUpdateFailure != nil {
					s28.BridgeCompareS1APENBConfigurationUpdateFailure(v.bodyENBConfigurationUpdateFailure, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(30):
			{
				f := s.Begin()
				s.Bool(v.bodyMMEConfigurationUpdateFailure == nil)
				if v.bodyMMEConfigurationUpdateFailure != nil {
					s30.BridgeCompareS1APMMEConfigurationUpdateFailure(v.bodyMMEConfigurationUpdateFailure, s)
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
					s31.BridgeCompareS1APS1RemovalFailure(v.bodyS1RemovalFailure, s)
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
	IEExtensions      s14.UES1APIDPairExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                               `asn1:"-" json:"-"`
	extCount          int64                              `asn1:"-" json:"-"`
	extPresent        []bool                             `asn1:"-" json:"-"`
	extData           [][]byte                           `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                  `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding             `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
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
		if err := aper.EncodeIntegerAligned(bb, int64(*v.MMEUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false); err != nil {
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
		val_mmeues1apid, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false)
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
	if err := aper.EncodeIntegerAligned(bb, int64(v.MMEUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false); err != nil {
		return fmt.Errorf("encoding mME-UE-S1AP-ID: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.ENBUES1APID), s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false); err != nil {
		return fmt.Errorf("encoding eNB-UE-S1AP-ID: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s14.BridgeUES1APIDPairExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UES1APIDPair from APER format.
func (v *UES1APIDPair) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *UES1APIDPair) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UES1APIDPair{}
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
	val_mmeues1apid, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(4294967295), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "MMEUES1APID")
	}
	v.MMEUES1APID = s00.MMEUES1APID(val_mmeues1apid)
	val_enbues1apid, err := aper.DecodeIntegerAligned(bb, s08.BridgeInt64Ptr(0), s08.BridgeInt64Ptr(16777215), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "ENBUES1APID")
	}
	v.ENBUES1APID = s00.ENBUES1APID(val_enbues1apid)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s14.UES1APIDPairExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s14.UES1APIDPairExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s14.BridgeUES1APIDPairExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *UES1APIDPair) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UES1APIDPair", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UES1APIDs", v.receivedLocation, v.perPadding)
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

// UEContextModificationResponse represents the ASN.1 type UEContextModificationResponse (SEQUENCE).
type UEContextModificationResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s27.UEContextModificationResponseIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s14.UERadioCapabilityMatchRequestIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s28.UERadioCapabilityMatchResponseIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s24.UEContextModificationIndicationIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s36.UEContextSuspendResponseIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s27.UEContextResumeFailureIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s39.UEInformationTransferIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s14.UERadioCapabilityIDMappingRequestIEContainer `asn1:"tag:0,context,implicit"`
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
	ProtocolIEs      s28.UERadioCapabilityIDMappingResponseIEContainer `asn1:"tag:0,context,implicit"`
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
			if err := s27.BridgeUEContextModificationResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEContextModificationResponse from APER format.
func (v *UEContextModificationResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *UEContextModificationResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextModificationResponse{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s27.UEContextModificationResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s27.UEContextModificationResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s27.BridgeUEContextModificationResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s14.BridgeUERadioCapabilityMatchRequestIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UERadioCapabilityMatchRequest from APER format.
func (v *UERadioCapabilityMatchRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *UERadioCapabilityMatchRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UERadioCapabilityMatchRequest{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s14.UERadioCapabilityMatchRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s14.UERadioCapabilityMatchRequestIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s14.BridgeUERadioCapabilityMatchRequestIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s28.BridgeUERadioCapabilityMatchResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UERadioCapabilityMatchResponse from APER format.
func (v *UERadioCapabilityMatchResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *UERadioCapabilityMatchResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UERadioCapabilityMatchResponse{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s28.UERadioCapabilityMatchResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s28.UERadioCapabilityMatchResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s28.BridgeUERadioCapabilityMatchResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s24.BridgeUEContextModificationIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEContextModificationIndication from APER format.
func (v *UEContextModificationIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *UEContextModificationIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextModificationIndication{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s24.UEContextModificationIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s24.UEContextModificationIndicationIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s24.BridgeUEContextModificationIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s36.BridgeUEContextSuspendResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEContextSuspendResponse from APER format.
func (v *UEContextSuspendResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *UEContextSuspendResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextSuspendResponse{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s36.UEContextSuspendResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s36.UEContextSuspendResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s36.BridgeUEContextSuspendResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s27.BridgeUEContextResumeFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEContextResumeFailure from APER format.
func (v *UEContextResumeFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *UEContextResumeFailure) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEContextResumeFailure{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s27.UEContextResumeFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s27.UEContextResumeFailureIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s27.BridgeUEContextResumeFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s39.BridgeUEInformationTransferIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UEInformationTransfer from APER format.
func (v *UEInformationTransfer) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *UEInformationTransfer) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UEInformationTransfer{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s39.UEInformationTransferIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s39.UEInformationTransferIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s39.BridgeUEInformationTransferIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s14.BridgeUERadioCapabilityIDMappingRequestIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UERadioCapabilityIDMappingRequest from APER format.
func (v *UERadioCapabilityIDMappingRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *UERadioCapabilityIDMappingRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UERadioCapabilityIDMappingRequest{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s14.UERadioCapabilityIDMappingRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s14.UERadioCapabilityIDMappingRequestIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s14.BridgeUERadioCapabilityIDMappingRequestIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
			if err := s28.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes UERadioCapabilityIDMappingResponse from APER format.
func (v *UERadioCapabilityIDMappingResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
	v.perPadding = padding
	return nil
}
func (v *UERadioCapabilityIDMappingResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UERadioCapabilityIDMappingResponse{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s28.UERadioCapabilityIDMappingResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1127
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s28.UERadioCapabilityIDMappingResponseIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s28.BridgeUERadioCapabilityIDMappingResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *UEContextModificationIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextModificationIndication", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextModificationResponse", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextResumeFailure", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEContextSuspendResponse", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UEInformationTransfer", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UERadioCapabilityIDMappingRequest", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UERadioCapabilityIDMappingResponse", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UERadioCapabilityMatchRequest", v.receivedLocation, v.perPadding)
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UERadioCapabilityMatchResponse", v.receivedLocation, v.perPadding)
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

// UnmarshalAPER decodes UnsuccessfulOutcome from APER format.
func (v *UnsuccessfulOutcome) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
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
		return s16.BridgeReceivedFormAt(v.received, v.receivedBytes, "UnsuccessfulOutcome", v.receivedLocation, v.perPadding)
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
	rowCause     *s17.Cause
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
func (v *UEContextReleaseCommandIEValue) AsCause() (*s17.Cause, bool) {
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
		var value s17.Cause
		child := scope
		if err := s17.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "Cause:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*s17.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*s17.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(s17.BridgeCauseFieldReceivedBytes(&value))
		*s17.BridgeCauseFieldReceivedLocation(&value) = raw.ContentLocation()
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
		candidate, err := s17.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
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
	return UEContextReleaseCommandCauseIEBinding{info: t.infoCause(), codec: func() s17.CauseValueCodec {
		sealed := s17.CauseValueCodec{}
		*s17.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s17.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s17.Cause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cause")
			var zero UEContextReleaseCommandIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s17.Cause
				return empty, runtime.WrapDecodePath(err, "Cause")
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s17.Cause
				return empty, fmt.Errorf("binding UEContextReleaseCommand-IEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s17.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s17.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UEContextReleaseCommandIEValue{id: s00.ProtocolIEID(2), rowCause: &value}).encodeFresh(fresh, budget)
		}
		*s17.BridgeCauseValueCodecFieldCapture(&sealed) = func(v s17.Cause, options aper.DecodeState) (s17.Cause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s17.BridgeCaptureS1APCause(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s17.BridgeCauseValueCodecFieldCompare(&sealed) = func(v s17.Cause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s17.BridgeCompareS1APCause(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s17.BridgeCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s17.Cause) UEContextReleaseCommandIEValue {
			return UEContextReleaseCommandIEValue{id: s00.ProtocolIEID(2), rowCause: &value}
		}, get: func(value *UEContextReleaseCommandIEValue) (*s17.Cause, bool) { return value.AsCause() }}
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
func BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldCapture(v *ENBConfigurationUpdateFailureUnsuccessfulBinding) *func(s28.ENBConfigurationUpdateFailure, aper.DecodeState) (s28.ENBConfigurationUpdateFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldCompare(v *ENBConfigurationUpdateFailureUnsuccessfulBinding) *func(s28.ENBConfigurationUpdateFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldContext(v *ENBConfigurationUpdateFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldDecode(v *ENBConfigurationUpdateFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s28.ENBConfigurationUpdateFailure, error) {
	return &v.decode
}
func BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldEncode(v *ENBConfigurationUpdateFailureUnsuccessfulBinding) *func(*s28.ENBConfigurationUpdateFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldInfo(v *ENBConfigurationUpdateFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldInject(v *ENBConfigurationUpdateFailureUnsuccessfulBinding) *func(s28.ENBConfigurationUpdateFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeENBConfigurationUpdateFailureUnsuccessfulBindingFieldValidate(v *ENBConfigurationUpdateFailureUnsuccessfulBinding) *func(*s28.ENBConfigurationUpdateFailure, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeHandoverFailureUnsuccessfulBindingFieldCapture(v *HandoverFailureUnsuccessfulBinding) *func(s29.HandoverFailure, aper.DecodeState) (s29.HandoverFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverFailureUnsuccessfulBindingFieldCompare(v *HandoverFailureUnsuccessfulBinding) *func(s29.HandoverFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverFailureUnsuccessfulBindingFieldContext(v *HandoverFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverFailureUnsuccessfulBindingFieldDecode(v *HandoverFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s29.HandoverFailure, error) {
	return &v.decode
}
func BridgeHandoverFailureUnsuccessfulBindingFieldEncode(v *HandoverFailureUnsuccessfulBinding) *func(*s29.HandoverFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverFailureUnsuccessfulBindingFieldInfo(v *HandoverFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeHandoverFailureUnsuccessfulBindingFieldInject(v *HandoverFailureUnsuccessfulBinding) *func(s29.HandoverFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeHandoverFailureUnsuccessfulBindingFieldValidate(v *HandoverFailureUnsuccessfulBinding) *func(*s29.HandoverFailure, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeHandoverPreparationFailureUnsuccessfulBindingFieldCapture(v *HandoverPreparationFailureUnsuccessfulBinding) *func(s29.HandoverPreparationFailure, aper.DecodeState) (s29.HandoverPreparationFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverPreparationFailureUnsuccessfulBindingFieldCompare(v *HandoverPreparationFailureUnsuccessfulBinding) *func(s29.HandoverPreparationFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverPreparationFailureUnsuccessfulBindingFieldContext(v *HandoverPreparationFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverPreparationFailureUnsuccessfulBindingFieldDecode(v *HandoverPreparationFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s29.HandoverPreparationFailure, error) {
	return &v.decode
}
func BridgeHandoverPreparationFailureUnsuccessfulBindingFieldEncode(v *HandoverPreparationFailureUnsuccessfulBinding) *func(*s29.HandoverPreparationFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverPreparationFailureUnsuccessfulBindingFieldInfo(v *HandoverPreparationFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeHandoverPreparationFailureUnsuccessfulBindingFieldInject(v *HandoverPreparationFailureUnsuccessfulBinding) *func(s29.HandoverPreparationFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeHandoverPreparationFailureUnsuccessfulBindingFieldValidate(v *HandoverPreparationFailureUnsuccessfulBinding) *func(*s29.HandoverPreparationFailure, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeInitialContextSetupFailureUnsuccessfulBindingFieldCapture(v *InitialContextSetupFailureUnsuccessfulBinding) *func(s30.InitialContextSetupFailure, aper.DecodeState) (s30.InitialContextSetupFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupFailureUnsuccessfulBindingFieldCompare(v *InitialContextSetupFailureUnsuccessfulBinding) *func(s30.InitialContextSetupFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupFailureUnsuccessfulBindingFieldContext(v *InitialContextSetupFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupFailureUnsuccessfulBindingFieldDecode(v *InitialContextSetupFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s30.InitialContextSetupFailure, error) {
	return &v.decode
}
func BridgeInitialContextSetupFailureUnsuccessfulBindingFieldEncode(v *InitialContextSetupFailureUnsuccessfulBinding) *func(*s30.InitialContextSetupFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupFailureUnsuccessfulBindingFieldInfo(v *InitialContextSetupFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeInitialContextSetupFailureUnsuccessfulBindingFieldInject(v *InitialContextSetupFailureUnsuccessfulBinding) *func(s30.InitialContextSetupFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeInitialContextSetupFailureUnsuccessfulBindingFieldValidate(v *InitialContextSetupFailureUnsuccessfulBinding) *func(*s30.InitialContextSetupFailure, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldCapture(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *func(s30.MMEConfigurationUpdateFailure, aper.DecodeState) (s30.MMEConfigurationUpdateFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldCompare(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *func(s30.MMEConfigurationUpdateFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldContext(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldDecode(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s30.MMEConfigurationUpdateFailure, error) {
	return &v.decode
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldEncode(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *func(*s30.MMEConfigurationUpdateFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldInfo(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldInject(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *func(s30.MMEConfigurationUpdateFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeMMEConfigurationUpdateFailureUnsuccessfulBindingFieldValidate(v *MMEConfigurationUpdateFailureUnsuccessfulBinding) *func(*s30.MMEConfigurationUpdateFailure, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgePathSwitchRequestFailureUnsuccessfulBindingFieldCapture(v *PathSwitchRequestFailureUnsuccessfulBinding) *func(s30.PathSwitchRequestFailure, aper.DecodeState) (s30.PathSwitchRequestFailure, aper.Snapshot) {
	return &v.capture
}
func BridgePathSwitchRequestFailureUnsuccessfulBindingFieldCompare(v *PathSwitchRequestFailureUnsuccessfulBinding) *func(s30.PathSwitchRequestFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePathSwitchRequestFailureUnsuccessfulBindingFieldContext(v *PathSwitchRequestFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePathSwitchRequestFailureUnsuccessfulBindingFieldDecode(v *PathSwitchRequestFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s30.PathSwitchRequestFailure, error) {
	return &v.decode
}
func BridgePathSwitchRequestFailureUnsuccessfulBindingFieldEncode(v *PathSwitchRequestFailureUnsuccessfulBinding) *func(*s30.PathSwitchRequestFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePathSwitchRequestFailureUnsuccessfulBindingFieldInfo(v *PathSwitchRequestFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgePathSwitchRequestFailureUnsuccessfulBindingFieldInject(v *PathSwitchRequestFailureUnsuccessfulBinding) *func(s30.PathSwitchRequestFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgePathSwitchRequestFailureUnsuccessfulBindingFieldValidate(v *PathSwitchRequestFailureUnsuccessfulBinding) *func(*s30.PathSwitchRequestFailure, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldCapture(v *S1RemovalFailureUnsuccessfulBinding) *func(s31.S1RemovalFailure, aper.DecodeState) (s31.S1RemovalFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldCompare(v *S1RemovalFailureUnsuccessfulBinding) *func(s31.S1RemovalFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldContext(v *S1RemovalFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldDecode(v *S1RemovalFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s31.S1RemovalFailure, error) {
	return &v.decode
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldEncode(v *S1RemovalFailureUnsuccessfulBinding) *func(*s31.S1RemovalFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldInfo(v *S1RemovalFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldInject(v *S1RemovalFailureUnsuccessfulBinding) *func(s31.S1RemovalFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeS1RemovalFailureUnsuccessfulBindingFieldValidate(v *S1RemovalFailureUnsuccessfulBinding) *func(*s31.S1RemovalFailure, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldCapture(v *S1SetupFailureUnsuccessfulBinding) *func(s31.S1SetupFailure, aper.DecodeState) (s31.S1SetupFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldCompare(v *S1SetupFailureUnsuccessfulBinding) *func(s31.S1SetupFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldContext(v *S1SetupFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldDecode(v *S1SetupFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s31.S1SetupFailure, error) {
	return &v.decode
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldEncode(v *S1SetupFailureUnsuccessfulBinding) *func(*s31.S1SetupFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldInfo(v *S1SetupFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldInject(v *S1SetupFailureUnsuccessfulBinding) *func(s31.S1SetupFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeS1SetupFailureUnsuccessfulBindingFieldValidate(v *S1SetupFailureUnsuccessfulBinding) *func(*s31.S1SetupFailure, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldCapture(v *UEContextModificationFailureUnsuccessfulBinding) *func(s45.UEContextModificationFailure, aper.DecodeState) (s45.UEContextModificationFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldCompare(v *UEContextModificationFailureUnsuccessfulBinding) *func(s45.UEContextModificationFailure, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldContext(v *UEContextModificationFailureUnsuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldDecode(v *UEContextModificationFailureUnsuccessfulBinding) *func([]byte, aper.DecodeState) (s45.UEContextModificationFailure, error) {
	return &v.decode
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldEncode(v *UEContextModificationFailureUnsuccessfulBinding) *func(*s45.UEContextModificationFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldInfo(v *UEContextModificationFailureUnsuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldInject(v *UEContextModificationFailureUnsuccessfulBinding) *func(s45.UEContextModificationFailure) UnsuccessfulValue {
	return &v.inject
}
func BridgeUEContextModificationFailureUnsuccessfulBindingFieldValidate(v *UEContextModificationFailureUnsuccessfulBinding) *func(*s45.UEContextModificationFailure, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextModificationIndicationFieldPerPadding(v *UEContextModificationIndication) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeUEContextModificationIndicationMethodMarshalAPERBudget(v *UEContextModificationIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextModificationIndicationMethodUnmarshalAPERFrom(v *UEContextModificationIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeUEContextModificationResponseFieldPerPadding(v *UEContextModificationResponse) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeUEContextModificationResponseMethodMarshalAPERBudget(v *UEContextModificationResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextModificationResponseMethodUnmarshalAPERFrom(v *UEContextModificationResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeUEContextReleaseCommandIEFieldFieldReplay(v *UEContextReleaseCommandIEField) *aper.Snapshot {
	return &v.replay
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
func BridgeUEContextReleaseCommandIEValueFieldId(v *UEContextReleaseCommandIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUEContextReleaseCommandIEValueFieldIsOpaque(v *UEContextReleaseCommandIEValue) *bool {
	return &v.isOpaque
}
func BridgeUEContextReleaseCommandIEValueFieldOpaque(v *UEContextReleaseCommandIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUEContextReleaseCommandIEValueFieldRowCause(v *UEContextReleaseCommandIEValue) **s17.Cause {
	return &v.rowCause
}
func BridgeUEContextReleaseCommandIEValueFieldRowUES1APIDs(v *UEContextReleaseCommandIEValue) **UES1APIDs {
	return &v.rowUES1APIDs
}
func BridgeUEContextReleaseCommandIEValueMethodCompareSemantics(v UEContextReleaseCommandIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUEContextReleaseCommandIEValueMethodMatchesID(v UEContextReleaseCommandIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeUEContextReleaseCommandIEValueMethodRule(v UEContextReleaseCommandIEValue) aper.SourceRule {
	return v.rule()
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
func BridgeUEContextResumeFailureFieldReceived(v *UEContextResumeFailure) *bool { return &v.received }
func BridgeUEContextResumeFailureFieldReceivedAbsolute(v *UEContextResumeFailure) *bool {
	return &v.receivedAbsolute
}
func BridgeUEContextResumeFailureFieldReceivedBytes(v *UEContextResumeFailure) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeUEContextResumeFailureMethodMarshalAPERBudget(v *UEContextResumeFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
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
func BridgeUEContextResumeFailureUnsuccessfulBindingFieldValidate(v *UEContextResumeFailureUnsuccessfulBinding) *func(*UEContextResumeFailure, *aper.DecodeBudget) (s25.ValidationReport, error) {
	return &v.validate
}
func BridgeUEContextSuspendResponseFieldPerPadding(v *UEContextSuspendResponse) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeUEContextSuspendResponseMethodMarshalAPERBudget(v *UEContextSuspendResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEContextSuspendResponseMethodUnmarshalAPERFrom(v *UEContextSuspendResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeUEInformationTransferFieldPerPadding(v *UEInformationTransfer) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeUEInformationTransferMethodMarshalAPERBudget(v *UEInformationTransfer, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUEInformationTransferMethodUnmarshalAPERFrom(v *UEInformationTransfer, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeUERadioCapabilityIDMappingRequestFieldPerPadding(v *UERadioCapabilityIDMappingRequest) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeUERadioCapabilityIDMappingRequestMethodMarshalAPERBudget(v *UERadioCapabilityIDMappingRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUERadioCapabilityIDMappingRequestMethodUnmarshalAPERFrom(v *UERadioCapabilityIDMappingRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeUERadioCapabilityIDMappingResponseFieldPerPadding(v *UERadioCapabilityIDMappingResponse) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeUERadioCapabilityIDMappingResponseMethodMarshalAPERBudget(v *UERadioCapabilityIDMappingResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUERadioCapabilityIDMappingResponseMethodUnmarshalAPERFrom(v *UERadioCapabilityIDMappingResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeUERadioCapabilityMatchRequestFieldPerPadding(v *UERadioCapabilityMatchRequest) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeUERadioCapabilityMatchRequestMethodMarshalAPERBudget(v *UERadioCapabilityMatchRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUERadioCapabilityMatchRequestMethodUnmarshalAPERFrom(v *UERadioCapabilityMatchRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeUERadioCapabilityMatchResponseFieldPerPadding(v *UERadioCapabilityMatchResponse) *aper.FinalPadding {
	return &v.perPadding
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
func BridgeUERadioCapabilityMatchResponseMethodMarshalAPERBudget(v *UERadioCapabilityMatchResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUERadioCapabilityMatchResponseMethodUnmarshalAPERFrom(v *UERadioCapabilityMatchResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
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
func BridgeUnsuccessfulOutcomeMethodMarshalAPERTo(v *UnsuccessfulOutcome, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUnsuccessfulOutcomeMethodUnmarshalAPERFrom(v *UnsuccessfulOutcome, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUnsuccessfulValueFieldBodyENBConfigurationUpdateFailure(v *UnsuccessfulValue) **s28.ENBConfigurationUpdateFailure {
	return &v.bodyENBConfigurationUpdateFailure
}
func BridgeUnsuccessfulValueFieldBodyHandoverFailure(v *UnsuccessfulValue) **s29.HandoverFailure {
	return &v.bodyHandoverFailure
}
func BridgeUnsuccessfulValueFieldBodyHandoverPreparationFailure(v *UnsuccessfulValue) **s29.HandoverPreparationFailure {
	return &v.bodyHandoverPreparationFailure
}
func BridgeUnsuccessfulValueFieldBodyInitialContextSetupFailure(v *UnsuccessfulValue) **s30.InitialContextSetupFailure {
	return &v.bodyInitialContextSetupFailure
}
func BridgeUnsuccessfulValueFieldBodyMMEConfigurationUpdateFailure(v *UnsuccessfulValue) **s30.MMEConfigurationUpdateFailure {
	return &v.bodyMMEConfigurationUpdateFailure
}
func BridgeUnsuccessfulValueFieldBodyPathSwitchRequestFailure(v *UnsuccessfulValue) **s30.PathSwitchRequestFailure {
	return &v.bodyPathSwitchRequestFailure
}
func BridgeUnsuccessfulValueFieldBodyS1RemovalFailure(v *UnsuccessfulValue) **s31.S1RemovalFailure {
	return &v.bodyS1RemovalFailure
}
func BridgeUnsuccessfulValueFieldBodyS1SetupFailure(v *UnsuccessfulValue) **s31.S1SetupFailure {
	return &v.bodyS1SetupFailure
}
func BridgeUnsuccessfulValueFieldBodyUEContextModificationFailure(v *UnsuccessfulValue) **s45.UEContextModificationFailure {
	return &v.bodyUEContextModificationFailure
}
func BridgeUnsuccessfulValueFieldBodyUEContextResumeFailure(v *UnsuccessfulValue) **UEContextResumeFailure {
	return &v.bodyUEContextResumeFailure
}
func BridgeUnsuccessfulValueFieldCode(v *UnsuccessfulValue) *s00.ProcedureCode     { return &v.code }
func BridgeUnsuccessfulValueFieldIsOpaque(v *UnsuccessfulValue) *bool              { return &v.isOpaque }
func BridgeUnsuccessfulValueFieldOpaque(v *UnsuccessfulValue) *aper.OpaqueOpenType { return &v.opaque }

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
