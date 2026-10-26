// Code generated from the locked X2AP source closure. DO NOT EDIT.

// Package s20 implements the x2ap root package.
package s20

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s00"
	s05 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s05"
	s06 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s07"
	s11 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s11"
	s12 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s14"
	s16 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s16"
	s17 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s17"
	s18 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/x2ap/internal/model/s19"
	runtime "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/x2ap/runtime/aper"
)

// APERValue carries a source value and private replay state.
type APERValue[T any] struct {
	context       s00.X2apInternalCodecContext
	Value         T
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire representation, if present.
func (v APERValue[T]) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that encodes without received replay state.
func (v APERValue[T]) WithoutReplay() APERValue[T] {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ValueCodec binds one source value type to its complete APER encoding.
type ValueCodec[T any] struct {
	context s00.X2apInternalCodecContext
	capture func(T, aper.DecodeState) (T, aper.Snapshot)
	compare func(T, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (T, error)
	encode  func(T, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates the source value and constructs a value without received replay state.
func (c ValueCodec[T]) New(value T) (APERValue[T], error) {
	if c.encode == nil {
		return APERValue[T]{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return APERValue[T]{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return APERValue[T]{}, aper.OperationError(err, "Value.New")
	}
	return APERValue[T]{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes one complete APER value and retains its received representation.
func (c ValueCodec[T]) DecodeAPER(data []byte, options ...aper.DecodeOption) (APERValue[T], aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return APERValue[T]{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
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
				return APERValue[T]{}, report, aper.OperationError(err, c.path)
			}
			return APERValue[T]{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
		}
	}
	report, err := aper.FinishDecode(settings, aper.OperationError(err, c.path))
	return APERValue[T]{}, report, aper.OperationError(err, c.path)
}

// EncodeAPER encodes the value, preserving unchanged received contents unless replay is disabled.
func (c ValueCodec[T]) EncodeAPER(value APERValue[T], options ...aper.EncodeOption) ([]byte, error) {
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
		return c.encodeChanged(value.Value, fresh, plan)
	}
	return c.encodeUnplanned(value.Value, fresh, budget)
}
func (c ValueCodec[T]) encodeUnplanned(value T, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ValueCodec[T]) encodeChanged(value T, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	aper.NewBudgetBuffer(&budget).SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

type IEBinding[T any, V X2apInternalProtocolOpenValue[V]] struct {
	info   s06.FieldInfo
	codec  ValueCodec[T]
	inject func(T) V
	get    func(*V) (*T, bool)
}

// Info returns the source metadata for this binding.
func (b IEBinding[T, V]) Info() s06.FieldInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b IEBinding[T, V]) Codec() ValueCodec[T] { return b.codec }

// New validates the source value and constructs a value without received replay state.
func (b IEBinding[T, V]) New(value T) (ProtocolIEField[V], error) {
	if b.inject == nil {
		return ProtocolIEField[V]{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ProtocolIEField[V]{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ProtocolIEField[V]{}, aper.OperationError(fmt.Errorf("IE %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ProtocolIEField[V]{}, aper.OperationError(err, "Value.New")
	}
	return ProtocolIEField[V]{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected value when the field matches this binding.
func (b IEBinding[T, V]) Get(field *ProtocolIEField[V]) (*T, bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

type ExtensionBinding[T any, V X2apInternalProtocolOpenValue[V]] struct {
	info   s06.FieldInfo
	codec  ValueCodec[T]
	inject func(T) V
	get    func(*V) (*T, bool)
}

// Info returns the source metadata for this binding.
func (b ExtensionBinding[T, V]) Info() s06.FieldInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b ExtensionBinding[T, V]) Codec() ValueCodec[T] { return b.codec }

// New validates the source value and constructs a value without received replay state.
func (b ExtensionBinding[T, V]) New(value T) (ProtocolExtensionField[V], error) {
	if b.inject == nil {
		return ProtocolExtensionField[V]{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ProtocolExtensionField[V]{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ProtocolExtensionField[V]{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ProtocolExtensionField[V]{}, aper.OperationError(err, "Value.New")
	}
	return ProtocolExtensionField[V]{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected value when the field matches this binding.
func (b ExtensionBinding[T, V]) Get(field *ProtocolExtensionField[V]) (*T, bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

type InitiatingBinding[T any] struct {
	context  s00.X2apInternalCodecContext
	capture  func(T, aper.DecodeState) (T, aper.Snapshot)
	compare  func(T, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*T, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*T, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (T, error)
	inject   func(T) s19.InitiatingValue
}

// Info returns the source metadata for this binding.
func (b InitiatingBinding[T]) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b InitiatingBinding[T]) Codec() ValueCodec[T] {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return ValueCodec[T]{}
	}
	return ValueCodec[T]{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value T, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b InitiatingBinding[T]) Build(body T, options ...aper.BuildOption) (s19.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s19.InitiatingMessage{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s19.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s19.InitiatingMessage{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s19.InitiatingMessage{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s19.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s19.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s19.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

type SuccessfulBinding[T any] struct {
	context  s00.X2apInternalCodecContext
	capture  func(T, aper.DecodeState) (T, aper.Snapshot)
	compare  func(T, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*T, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*T, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (T, error)
	inject   func(T) s18.SuccessfulValue
}

// Info returns the source metadata for this binding.
func (b SuccessfulBinding[T]) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b SuccessfulBinding[T]) Codec() ValueCodec[T] {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return ValueCodec[T]{}
	}
	return ValueCodec[T]{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value T, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b SuccessfulBinding[T]) Build(body T, options ...aper.BuildOption) (s18.SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s18.SuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s18.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s18.SuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s18.SuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s18.SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s18.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return s18.SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

type UnsuccessfulBinding[T any] struct {
	context  s00.X2apInternalCodecContext
	capture  func(T, aper.DecodeState) (T, aper.Snapshot)
	compare  func(T, aper.Snapshot, aper.DecodeBudget) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*T, *aper.DecodeBudget) (s12.ValidationReport, error)
	encode   func(*T, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (T, error)
	inject   func(T) s14.UnsuccessfulValue
}

// Info returns the source metadata for this binding.
func (b UnsuccessfulBinding[T]) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for the bound source value.
func (b UnsuccessfulBinding[T]) Codec() ValueCodec[T] {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return ValueCodec[T]{}
	}
	return ValueCodec[T]{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value T, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs the bound procedure message.
func (b UnsuccessfulBinding[T]) Build(body T, options ...aper.BuildOption) (s14.UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.decode == nil || b.inject == nil {
		return s14.UnsuccessfulOutcome{}, aper.OperationError(aper.ErrInvalidValue, "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s14.UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s14.UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s14.UnsuccessfulOutcome{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "Build")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s14.UnsuccessfulOutcome{}, aper.OperationError(&s12.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s14.UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s14.UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return s14.UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}
func NewUEContextRelease(fields s12.UEContextReleaseIEContainer, options ...aper.BuildOption) (s19.UEContextRelease, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.UEContextRelease{}, aper.OperationError(err, "UEContextRelease")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.UEContextReleaseIEField](bb, uint64(len(fields))); err != nil {
		return s19.UEContextRelease{}, aper.OperationError(err, "UEContextRelease")
	}
	v := s19.UEContextRelease{ProtocolIEs: make(s12.UEContextReleaseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := X2apInternalValidateUEContextReleaseBudget(&v, budget)
	if err != nil {
		return s19.UEContextRelease{}, aper.OperationError(err, "UEContextRelease")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s19.UEContextRelease{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "UEContextRelease")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s19.UEContextRelease{}, aper.OperationError(&s12.BuildError{Issues: issues}, "UEContextRelease")
	}
	if _, err := s19.X2apInternalUEContextReleaseMarshalAPERBudget(&v, budget, false); err != nil {
		return s19.UEContextRelease{}, aper.OperationError(fmt.Errorf("UEContextRelease.protocolIEs: %w", err), "UEContextRelease")
	}
	return v, aper.OperationError(nil, "UEContextRelease")
}
func NewX2SetupRequest(fields s17.X2SetupRequestIEContainer, options ...aper.BuildOption) (s19.X2SetupRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.X2SetupRequest{}, aper.OperationError(err, "X2SetupRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s17.X2SetupRequestIEField](bb, uint64(len(fields))); err != nil {
		return s19.X2SetupRequest{}, aper.OperationError(err, "X2SetupRequest")
	}
	v := s19.X2SetupRequest{ProtocolIEs: make(s17.X2SetupRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := X2apInternalValidateX2SetupRequestBudget(&v, budget)
	if err != nil {
		return s19.X2SetupRequest{}, aper.OperationError(err, "X2SetupRequest")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s19.X2SetupRequest{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "X2SetupRequest")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s19.X2SetupRequest{}, aper.OperationError(&s12.BuildError{Issues: issues}, "X2SetupRequest")
	}
	if _, err := s19.X2apInternalX2SetupRequestMarshalAPERBudget(&v, budget, false); err != nil {
		return s19.X2SetupRequest{}, aper.OperationError(fmt.Errorf("X2SetupRequest.protocolIEs: %w", err), "X2SetupRequest")
	}
	return v, aper.OperationError(nil, "X2SetupRequest")
}
func NewX2SetupResponse(fields s17.X2SetupResponseIEContainer, options ...aper.BuildOption) (s18.X2SetupResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.X2SetupResponse{}, aper.OperationError(err, "X2SetupResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s17.X2SetupResponseIEField](bb, uint64(len(fields))); err != nil {
		return s18.X2SetupResponse{}, aper.OperationError(err, "X2SetupResponse")
	}
	v := s18.X2SetupResponse{ProtocolIEs: make(s17.X2SetupResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := X2apInternalValidateX2SetupResponseBudget(&v, budget)
	if err != nil {
		return s18.X2SetupResponse{}, aper.OperationError(err, "X2SetupResponse")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s18.X2SetupResponse{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "X2SetupResponse")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s18.X2SetupResponse{}, aper.OperationError(&s12.BuildError{Issues: issues}, "X2SetupResponse")
	}
	if _, err := s18.X2apInternalX2SetupResponseMarshalAPERBudget(&v, budget, false); err != nil {
		return s18.X2SetupResponse{}, aper.OperationError(fmt.Errorf("X2SetupResponse.protocolIEs: %w", err), "X2SetupResponse")
	}
	return v, aper.OperationError(nil, "X2SetupResponse")
}
func NewX2Release(fields s07.X2ReleaseIEContainer, options ...aper.BuildOption) (s19.X2Release, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.X2Release{}, aper.OperationError(err, "X2Release")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s07.X2ReleaseIEField](bb, uint64(len(fields))); err != nil {
		return s19.X2Release{}, aper.OperationError(err, "X2Release")
	}
	v := s19.X2Release{ProtocolIEs: make(s07.X2ReleaseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := X2apInternalValidateX2ReleaseBudget(&v, budget)
	if err != nil {
		return s19.X2Release{}, aper.OperationError(err, "X2Release")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s19.X2Release{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "X2Release")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s19.X2Release{}, aper.OperationError(&s12.BuildError{Issues: issues}, "X2Release")
	}
	if _, err := s19.X2apInternalX2ReleaseMarshalAPERBudget(&v, budget, false); err != nil {
		return s19.X2Release{}, aper.OperationError(fmt.Errorf("X2Release.protocolIEs: %w", err), "X2Release")
	}
	return v, aper.OperationError(nil, "X2Release")
}
func NewX2APMessageTransfer(fields s13.X2APMessageTransferIEContainer, options ...aper.BuildOption) (s19.X2APMessageTransfer, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.X2APMessageTransfer{}, aper.OperationError(err, "X2APMessageTransfer")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s13.X2APMessageTransferIEField](bb, uint64(len(fields))); err != nil {
		return s19.X2APMessageTransfer{}, aper.OperationError(err, "X2APMessageTransfer")
	}
	v := s19.X2APMessageTransfer{ProtocolIEs: make(s13.X2APMessageTransferIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := X2apInternalValidateX2APMessageTransferBudget(&v, budget)
	if err != nil {
		return s19.X2APMessageTransfer{}, aper.OperationError(err, "X2APMessageTransfer")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s19.X2APMessageTransfer{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "X2APMessageTransfer")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s19.X2APMessageTransfer{}, aper.OperationError(&s12.BuildError{Issues: issues}, "X2APMessageTransfer")
	}
	if _, err := s19.X2apInternalX2APMessageTransferMarshalAPERBudget(&v, budget, false); err != nil {
		return s19.X2APMessageTransfer{}, aper.OperationError(fmt.Errorf("X2APMessageTransfer.protocolIEs: %w", err), "X2APMessageTransfer")
	}
	return v, aper.OperationError(nil, "X2APMessageTransfer")
}
func NewX2RemovalRequest(fields s13.X2RemovalRequestIEContainer, options ...aper.BuildOption) (s19.X2RemovalRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.X2RemovalRequest{}, aper.OperationError(err, "X2RemovalRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s13.X2RemovalRequestIEField](bb, uint64(len(fields))); err != nil {
		return s19.X2RemovalRequest{}, aper.OperationError(err, "X2RemovalRequest")
	}
	v := s19.X2RemovalRequest{ProtocolIEs: make(s13.X2RemovalRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := X2apInternalValidateX2RemovalRequestBudget(&v, budget)
	if err != nil {
		return s19.X2RemovalRequest{}, aper.OperationError(err, "X2RemovalRequest")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s19.X2RemovalRequest{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "X2RemovalRequest")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s19.X2RemovalRequest{}, aper.OperationError(&s12.BuildError{Issues: issues}, "X2RemovalRequest")
	}
	if _, err := s19.X2apInternalX2RemovalRequestMarshalAPERBudget(&v, budget, false); err != nil {
		return s19.X2RemovalRequest{}, aper.OperationError(fmt.Errorf("X2RemovalRequest.protocolIEs: %w", err), "X2RemovalRequest")
	}
	return v, aper.OperationError(nil, "X2RemovalRequest")
}
func NewX2RemovalResponse(fields s07.X2RemovalResponseIEContainer, options ...aper.BuildOption) (s18.X2RemovalResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.X2RemovalResponse{}, aper.OperationError(err, "X2RemovalResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s07.X2RemovalResponseIEField](bb, uint64(len(fields))); err != nil {
		return s18.X2RemovalResponse{}, aper.OperationError(err, "X2RemovalResponse")
	}
	v := s18.X2RemovalResponse{ProtocolIEs: make(s07.X2RemovalResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := X2apInternalValidateX2RemovalResponseBudget(&v, budget)
	if err != nil {
		return s18.X2RemovalResponse{}, aper.OperationError(err, "X2RemovalResponse")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s18.X2RemovalResponse{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "X2RemovalResponse")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s18.X2RemovalResponse{}, aper.OperationError(&s12.BuildError{Issues: issues}, "X2RemovalResponse")
	}
	if _, err := s18.X2apInternalX2RemovalResponseMarshalAPERBudget(&v, budget, false); err != nil {
		return s18.X2RemovalResponse{}, aper.OperationError(fmt.Errorf("X2RemovalResponse.protocolIEs: %w", err), "X2RemovalResponse")
	}
	return v, aper.OperationError(nil, "X2RemovalResponse")
}
func NewSgNBReleaseRequestAcknowledge(fields s17.SgNBReleaseRequestAcknowledgeIEContainer, options ...aper.BuildOption) (s18.SgNBReleaseRequestAcknowledge, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.SgNBReleaseRequestAcknowledge{}, aper.OperationError(err, "SgNBReleaseRequestAcknowledge")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s17.SgNBReleaseRequestAcknowledgeIEField](bb, uint64(len(fields))); err != nil {
		return s18.SgNBReleaseRequestAcknowledge{}, aper.OperationError(err, "SgNBReleaseRequestAcknowledge")
	}
	v := s18.SgNBReleaseRequestAcknowledge{ProtocolIEs: make(s17.SgNBReleaseRequestAcknowledgeIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := s19.X2apInternalValidateSgNBReleaseRequestAcknowledgeBudget(&v, budget)
	if err != nil {
		return s18.SgNBReleaseRequestAcknowledge{}, aper.OperationError(err, "SgNBReleaseRequestAcknowledge")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s18.SgNBReleaseRequestAcknowledge{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "SgNBReleaseRequestAcknowledge")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s18.SgNBReleaseRequestAcknowledge{}, aper.OperationError(&s12.BuildError{Issues: issues}, "SgNBReleaseRequestAcknowledge")
	}
	if _, err := s18.X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERBudget(&v, budget, false); err != nil {
		return s18.SgNBReleaseRequestAcknowledge{}, aper.OperationError(fmt.Errorf("SgNBReleaseRequestAcknowledge.protocolIEs: %w", err), "SgNBReleaseRequestAcknowledge")
	}
	return v, aper.OperationError(nil, "SgNBReleaseRequestAcknowledge")
}
func NewSgNBReleaseRequired(fields s17.SgNBReleaseRequiredIEContainer, options ...aper.BuildOption) (s19.SgNBReleaseRequired, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.SgNBReleaseRequired{}, aper.OperationError(err, "SgNBReleaseRequired")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s17.SgNBReleaseRequiredIEField](bb, uint64(len(fields))); err != nil {
		return s19.SgNBReleaseRequired{}, aper.OperationError(err, "SgNBReleaseRequired")
	}
	v := s19.SgNBReleaseRequired{ProtocolIEs: make(s17.SgNBReleaseRequiredIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := X2apInternalValidateSgNBReleaseRequiredBudget(&v, budget)
	if err != nil {
		return s19.SgNBReleaseRequired{}, aper.OperationError(err, "SgNBReleaseRequired")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s19.SgNBReleaseRequired{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "SgNBReleaseRequired")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s19.SgNBReleaseRequired{}, aper.OperationError(&s12.BuildError{Issues: issues}, "SgNBReleaseRequired")
	}
	if _, err := s19.X2apInternalSgNBReleaseRequiredMarshalAPERBudget(&v, budget, false); err != nil {
		return s19.SgNBReleaseRequired{}, aper.OperationError(fmt.Errorf("SgNBReleaseRequired.protocolIEs: %w", err), "SgNBReleaseRequired")
	}
	return v, aper.OperationError(nil, "SgNBReleaseRequired")
}
func NewTraceStart(fields s16.TraceStartIEContainer, options ...aper.BuildOption) (s19.TraceStart, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.TraceStart{}, aper.OperationError(err, "TraceStart")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s16.TraceStartIEField](bb, uint64(len(fields))); err != nil {
		return s19.TraceStart{}, aper.OperationError(err, "TraceStart")
	}
	v := s19.TraceStart{ProtocolIEs: make(s16.TraceStartIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := X2apInternalValidateTraceStartBudget(&v, budget)
	if err != nil {
		return s19.TraceStart{}, aper.OperationError(err, "TraceStart")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s19.TraceStart{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "TraceStart")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s19.TraceStart{}, aper.OperationError(&s12.BuildError{Issues: issues}, "TraceStart")
	}
	if _, err := s19.X2apInternalTraceStartMarshalAPERBudget(&v, budget, false); err != nil {
		return s19.TraceStart{}, aper.OperationError(fmt.Errorf("TraceStart.protocolIEs: %w", err), "TraceStart")
	}
	return v, aper.OperationError(nil, "TraceStart")
}
func NewUERadioCapabilityIDMappingRequest(fields s11.UERadioCapabilityIDMappingRequestIEContainer, options ...aper.BuildOption) (s19.UERadioCapabilityIDMappingRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.UERadioCapabilityIDMappingRequest{}, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.UERadioCapabilityIDMappingRequestIEField](bb, uint64(len(fields))); err != nil {
		return s19.UERadioCapabilityIDMappingRequest{}, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
	}
	v := s19.UERadioCapabilityIDMappingRequest{ProtocolIEs: make(s11.UERadioCapabilityIDMappingRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := X2apInternalValidateUERadioCapabilityIDMappingRequestBudget(&v, budget)
	if err != nil {
		return s19.UERadioCapabilityIDMappingRequest{}, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s19.UERadioCapabilityIDMappingRequest{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "UERadioCapabilityIDMappingRequest")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s19.UERadioCapabilityIDMappingRequest{}, aper.OperationError(&s12.BuildError{Issues: issues}, "UERadioCapabilityIDMappingRequest")
	}
	if _, err := s19.X2apInternalUERadioCapabilityIDMappingRequestMarshalAPERBudget(&v, budget, false); err != nil {
		return s19.UERadioCapabilityIDMappingRequest{}, aper.OperationError(fmt.Errorf("UERadioCapabilityIDMappingRequest.protocolIEs: %w", err), "UERadioCapabilityIDMappingRequest")
	}
	return v, aper.OperationError(nil, "UERadioCapabilityIDMappingRequest")
}
func NewUERadioCapabilityIDMappingResponse(fields s11.UERadioCapabilityIDMappingResponseIEContainer, options ...aper.BuildOption) (s18.UERadioCapabilityIDMappingResponse, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.UERadioCapabilityIDMappingResponse{}, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s11.UERadioCapabilityIDMappingResponseIEField](bb, uint64(len(fields))); err != nil {
		return s18.UERadioCapabilityIDMappingResponse{}, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	v := s18.UERadioCapabilityIDMappingResponse{ProtocolIEs: make(s11.UERadioCapabilityIDMappingResponseIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := X2apInternalValidateUERadioCapabilityIDMappingResponseBudget(&v, budget)
	if err != nil {
		return s18.UERadioCapabilityIDMappingResponse{}, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s18.UERadioCapabilityIDMappingResponse{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "UERadioCapabilityIDMappingResponse")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s18.UERadioCapabilityIDMappingResponse{}, aper.OperationError(&s12.BuildError{Issues: issues}, "UERadioCapabilityIDMappingResponse")
	}
	if _, err := s18.X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERBudget(&v, budget, false); err != nil {
		return s18.UERadioCapabilityIDMappingResponse{}, aper.OperationError(fmt.Errorf("UERadioCapabilityIDMappingResponse.protocolIEs: %w", err), "UERadioCapabilityIDMappingResponse")
	}
	return v, aper.OperationError(nil, "UERadioCapabilityIDMappingResponse")
}

// Initiating returns the typed binding for the initiating message of UEContextReleaseDescriptor.
func (UEContextReleaseDescriptor) Initiating() s19.UEContextReleaseInitiatingBinding {
	return s19.X2apInternalConstructT33UEContextReleaseInitiatingBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(UEContextReleaseProcedure().Info(), func(v *s19.UEContextRelease, budget *aper.DecodeBudget) (s12.ValidationReport, error) {
		return X2apInternalValidateUEContextReleaseBudget(v, budget)
	}, func(v *s19.UEContextRelease, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s19.X2apInternalUEContextReleaseMarshalAPERBudget(v, budget, fresh)
	}, func(data []byte, options aper.DecodeState) (s19.UEContextRelease, error) {
		var v s19.UEContextRelease
		err := s19.X2apInternalUEContextReleaseUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s19.UEContextRelease{}, err
		}
		*s19.X2apInternalUEContextReleaseFieldReceived(&v) = true
		*s19.X2apInternalUEContextReleaseFieldReceivedAbsolute(&v) = true
		*s19.X2apInternalUEContextReleaseFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, func(v s19.UEContextRelease) s19.InitiatingValue {
		return s19.X2apInternalConstructT15InitiatingValueF4codeF20bodyUEContextRelease(s00.ProcedureCode(5), &v)
	}, func(v s19.UEContextRelease, options aper.DecodeState) (s19.UEContextRelease, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s19.X2apInternalCaptureX2APUEContextRelease(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, func(v s19.UEContextRelease, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root,
			budget)
		f := s.Begin()
		s19.X2apInternalCompareX2APUEContextRelease(&v, &s)
		s.
			End(f, root, false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:UEContextRelease"))

}

// Initiating returns the typed binding for the initiating message of X2SetupDescriptor.
func (X2SetupDescriptor) Initiating() s19.X2SetupRequestInitiatingBinding {
	return s19.X2apInternalConstructT31X2SetupRequestInitiatingBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(X2SetupProcedure().Info(), func(v *s19.X2SetupRequest, budget *aper.DecodeBudget) (s12.ValidationReport, error) {
		return X2apInternalValidateX2SetupRequestBudget(v, budget)
	}, func(v *s19.X2SetupRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s19.X2apInternalX2SetupRequestMarshalAPERBudget(v, budget, fresh)
	}, func(data []byte, options aper.DecodeState) (s19.X2SetupRequest, error) {
		var v s19.X2SetupRequest
		err := s19.X2apInternalX2SetupRequestUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s19.X2SetupRequest{}, err
		}
		*s19.X2apInternalX2SetupRequestFieldReceived(&v) = true
		*s19.X2apInternalX2SetupRequestFieldReceivedAbsolute(&v) = true
		*s19.X2apInternalX2SetupRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, func(v s19.X2SetupRequest) s19.InitiatingValue {
		return s19.X2apInternalConstructT15InitiatingValueF4codeF18bodyX2SetupRequest(s00.ProcedureCode(6), &v)
	}, func(v s19.X2SetupRequest, options aper.DecodeState) (s19.X2SetupRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.
			Begin()
		s19.X2apInternalCaptureX2APX2SetupRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, func(v s19.X2SetupRequest, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s19.X2apInternalCompareX2APX2SetupRequest(&v, &s)
		s.End(
			f,
			root,
			false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:X2SetupRequest"))

}

// Successful returns the typed binding for the successful outcome of X2SetupDescriptor.
func (X2SetupDescriptor) Successful() s18.X2SetupResponseSuccessfulBinding {
	return s18.X2apInternalConstructT32X2SetupResponseSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(X2SetupProcedure().Info(), func(v *s18.X2SetupResponse, budget *aper.DecodeBudget) (s12.ValidationReport, error) {
		return X2apInternalValidateX2SetupResponseBudget(v, budget)
	}, func(v *s18.X2SetupResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s18.X2apInternalX2SetupResponseMarshalAPERBudget(v, budget, fresh)
	}, func(data []byte, options aper.DecodeState) (s18.X2SetupResponse, error) {
		var v s18.X2SetupResponse
		err := s18.X2apInternalX2SetupResponseUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s18.X2SetupResponse{}, err
		}
		*s18.X2apInternalX2SetupResponseFieldReceived(&v) = true
		*s18.X2apInternalX2SetupResponseFieldReceivedAbsolute(&v) = true
		*s18.X2apInternalX2SetupResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, func(v s18.X2SetupResponse) s18.SuccessfulValue {
		return s18.X2apInternalConstructT15SuccessfulValueF4codeF19bodyX2SetupResponse(s00.ProcedureCode(6), &v)
	}, func(v s18.X2SetupResponse, options aper.DecodeState) (s18.X2SetupResponse, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f :=
			s.Begin()
		s18.X2apInternalCaptureX2APX2SetupResponse(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, func(v s18.X2SetupResponse, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root,
			budget)
		f := s.Begin()
		s18.X2apInternalCompareX2APX2SetupResponse(&v, &s)
		s.End(
			f,
			root, false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:X2SetupResponse"))

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of X2SetupDescriptor.
func (X2SetupDescriptor) Unsuccessful() s14.X2SetupFailureUnsuccessfulBinding {
	return s14.X2apInternalConstructT33X2SetupFailureUnsuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(X2SetupProcedure().Info(), func(v *s14.X2SetupFailure, budget *aper.DecodeBudget) (s12.ValidationReport, error) {
		return s14.X2apInternalValidateX2SetupFailureBudget(v, budget)
	}, func(v *s14.X2SetupFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s14.X2apInternalX2SetupFailureMarshalAPERBudget(v, budget, fresh)
	}, func(data []byte, options aper.DecodeState) (s14.X2SetupFailure, error) {
		var v s14.X2SetupFailure
		err := s14.X2apInternalX2SetupFailureUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s14.X2SetupFailure{}, err
		}
		*s14.X2apInternalX2SetupFailureFieldReceived(&v) = true
		*s14.X2apInternalX2SetupFailureFieldReceivedAbsolute(&v) = true
		*s14.X2apInternalX2SetupFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, func(v s14.X2SetupFailure) s14.UnsuccessfulValue {
		return s14.X2apInternalConstructT17UnsuccessfulValueF4codeF18bodyX2SetupFailure(s00.ProcedureCode(6), &v)
	}, func(v s14.X2SetupFailure, options aper.DecodeState) (s14.X2SetupFailure, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.
			Begin()
		s14.X2apInternalCaptureX2APX2SetupFailure(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, func(v s14.X2SetupFailure, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s14.X2apInternalCompareX2APX2SetupFailure(&v, &s)
		s.End(
			f,
			root,
			false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:X2SetupFailure"))

}

// Initiating returns the typed binding for the initiating message of X2ReleaseDescriptor.
func (X2ReleaseDescriptor) Initiating() s19.X2ReleaseInitiatingBinding {
	return s19.X2apInternalConstructT26X2ReleaseInitiatingBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(X2ReleaseProcedure().Info(), func(v *s19.X2Release, budget *aper.DecodeBudget) (s12.ValidationReport, error) {
		return X2apInternalValidateX2ReleaseBudget(v, budget)
	}, func(v *s19.X2Release, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s19.X2apInternalX2ReleaseMarshalAPERBudget(v, budget, fresh)
	}, func(data []byte, options aper.DecodeState) (s19.X2Release, error) {
		var v s19.X2Release
		err := s19.X2apInternalX2ReleaseUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s19.X2Release{}, err
		}
		*s19.X2apInternalX2ReleaseFieldReceived(&v) = true
		*s19.X2apInternalX2ReleaseFieldReceivedAbsolute(&v) = true
		*s19.X2apInternalX2ReleaseFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, func(v s19.X2Release) s19.InitiatingValue {
		return s19.X2apInternalConstructT15InitiatingValueF4codeF13bodyX2Release(s00.ProcedureCode(16), &v)
	}, func(v s19.X2Release, options aper.DecodeState) (s19.X2Release, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s19.X2apInternalCaptureX2APX2Release(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, func(v s19.X2Release, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root,
			budget,
		)
		f := s.Begin()
		s19.X2apInternalCompareX2APX2Release(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:X2Release"))

}

// Initiating returns the typed binding for the initiating message of X2APMessageTransferDescriptor.
func (X2APMessageTransferDescriptor) Initiating() s19.X2APMessageTransferInitiatingBinding {
	return s19.X2apInternalConstructT36X2APMessageTransferInitiatingBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(X2APMessageTransferProcedure().Info(), func(v *s19.X2APMessageTransfer, budget *aper.DecodeBudget) (s12.ValidationReport, error) {
		return X2apInternalValidateX2APMessageTransferBudget(v, budget)
	}, func(v *s19.X2APMessageTransfer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s19.X2apInternalX2APMessageTransferMarshalAPERBudget(v, budget, fresh)
	}, func(data []byte, options aper.DecodeState) (s19.X2APMessageTransfer, error) {
		var v s19.X2APMessageTransfer
		err := s19.X2apInternalX2APMessageTransferUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s19.X2APMessageTransfer{}, err
		}
		*s19.X2apInternalX2APMessageTransferFieldReceived(&v) = true
		*s19.X2apInternalX2APMessageTransferFieldReceivedAbsolute(&v) = true
		*s19.X2apInternalX2APMessageTransferFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, func(v s19.X2APMessageTransfer) s19.InitiatingValue {
		return s19.X2apInternalConstructT15InitiatingValueF4codeF23bodyX2APMessageTransfer(s00.ProcedureCode(17), &v)
	}, func(v s19.X2APMessageTransfer, options aper.DecodeState) (s19.X2APMessageTransfer, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s19.X2apInternalCaptureX2APX2APMessageTransfer(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root

	}, func(v s19.X2APMessageTransfer, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root,
			budget)
		f := s.Begin()
		s19.X2apInternalCompareX2APX2APMessageTransfer(&v,
			&s,
		)
		s.End(f, root, false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:X2APMessageTransfer"))

}

// Initiating returns the typed binding for the initiating message of X2RemovalDescriptor.
func (X2RemovalDescriptor) Initiating() s19.X2RemovalRequestInitiatingBinding {
	return s19.X2apInternalConstructT33X2RemovalRequestInitiatingBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(X2RemovalProcedure().Info(), func(v *s19.X2RemovalRequest, budget *aper.DecodeBudget) (s12.ValidationReport, error) {
		return X2apInternalValidateX2RemovalRequestBudget(v, budget)
	}, func(v *s19.X2RemovalRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s19.X2apInternalX2RemovalRequestMarshalAPERBudget(v, budget, fresh)
	}, func(data []byte, options aper.DecodeState) (s19.X2RemovalRequest, error) {
		var v s19.X2RemovalRequest
		err := s19.X2apInternalX2RemovalRequestUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s19.X2RemovalRequest{}, err
		}
		*s19.X2apInternalX2RemovalRequestFieldReceived(&v) = true
		*s19.X2apInternalX2RemovalRequestFieldReceivedAbsolute(&v) = true
		*s19.X2apInternalX2RemovalRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, func(v s19.X2RemovalRequest) s19.InitiatingValue {
		return s19.X2apInternalConstructT15InitiatingValueF4codeF20bodyX2RemovalRequest(s00.ProcedureCode(18), &v)
	}, func(v s19.X2RemovalRequest, options aper.DecodeState) (s19.X2RemovalRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s19.X2apInternalCaptureX2APX2RemovalRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, func(v s19.X2RemovalRequest, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root,
			budget)
		f := s.Begin()
		s19.X2apInternalCompareX2APX2RemovalRequest(&v, &s)
		s.
			End(f, root, false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:X2RemovalRequest"))

}

// Successful returns the typed binding for the successful outcome of X2RemovalDescriptor.
func (X2RemovalDescriptor) Successful() s18.X2RemovalResponseSuccessfulBinding {
	return s18.X2apInternalConstructT34X2RemovalResponseSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(X2RemovalProcedure().Info(), func(v *s18.X2RemovalResponse, budget *aper.DecodeBudget) (s12.ValidationReport, error) {
		return X2apInternalValidateX2RemovalResponseBudget(v, budget)
	}, func(v *s18.X2RemovalResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s18.X2apInternalX2RemovalResponseMarshalAPERBudget(v, budget, fresh)
	}, func(data []byte, options aper.DecodeState) (s18.X2RemovalResponse, error) {
		var v s18.X2RemovalResponse
		err := s18.X2apInternalX2RemovalResponseUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s18.X2RemovalResponse{}, err
		}
		*s18.X2apInternalX2RemovalResponseFieldReceived(&v) = true
		*s18.X2apInternalX2RemovalResponseFieldReceivedAbsolute(&v) = true
		*s18.X2apInternalX2RemovalResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, func(v s18.X2RemovalResponse) s18.SuccessfulValue {
		return s18.X2apInternalConstructT15SuccessfulValueF4codeF21bodyX2RemovalResponse(s00.ProcedureCode(18), &v)
	}, func(v s18.X2RemovalResponse, options aper.DecodeState) (s18.X2RemovalResponse, aper.Snapshot) {
		s := aper.SemanticCaptureFor(
			options,
		)
		f := s.Begin()
		s18.X2apInternalCaptureX2APX2RemovalResponse(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, func(v s18.X2RemovalResponse, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root,
			budget)
		f := s.Begin()
		s18.X2apInternalCompareX2APX2RemovalResponse(&v, &s)
		s.
			End(f, root, false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:X2RemovalResponse"))

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of X2RemovalDescriptor.
func (X2RemovalDescriptor) Unsuccessful() s14.X2RemovalFailureUnsuccessfulBinding {
	return s14.X2apInternalConstructT35X2RemovalFailureUnsuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(X2RemovalProcedure().Info(), func(v *s14.X2RemovalFailure, budget *aper.DecodeBudget) (s12.ValidationReport, error) {
		return s14.X2apInternalValidateX2RemovalFailureBudget(v, budget)
	}, func(v *s14.X2RemovalFailure, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s14.X2apInternalX2RemovalFailureMarshalAPERBudget(v, budget, fresh)
	}, func(data []byte, options aper.DecodeState) (s14.X2RemovalFailure, error) {
		var v s14.X2RemovalFailure
		err := s14.X2apInternalX2RemovalFailureUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s14.X2RemovalFailure{}, err
		}
		*s14.X2apInternalX2RemovalFailureFieldReceived(&v) = true
		*s14.X2apInternalX2RemovalFailureFieldReceivedAbsolute(&v) = true
		*s14.X2apInternalX2RemovalFailureFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, func(v s14.X2RemovalFailure) s14.UnsuccessfulValue {
		return s14.X2apInternalConstructT17UnsuccessfulValueF4codeF20bodyX2RemovalFailure(s00.ProcedureCode(18), &v)
	}, func(v s14.X2RemovalFailure, options aper.DecodeState) (s14.X2RemovalFailure, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s14.X2apInternalCaptureX2APX2RemovalFailure(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, func(v s14.X2RemovalFailure, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root,
			budget)
		f := s.Begin()
		s14.X2apInternalCompareX2APX2RemovalFailure(&v, &s)
		s.
			End(f, root, false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:X2RemovalFailure"))

}

// Initiating returns the typed binding for the initiating message of MeNBinitiatedSgNBReleaseDescriptor.
func (MeNBinitiatedSgNBReleaseDescriptor) Initiating() s19.SgNBReleaseRequestInitiatingBinding {
	return s19.X2apInternalConstructT35SgNBReleaseRequestInitiatingBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(MeNBinitiatedSgNBReleaseProcedure().Info(), func(v *s19.SgNBReleaseRequest, budget *aper.DecodeBudget) (s12.ValidationReport, error) {
		return s19.X2apInternalValidateSgNBReleaseRequestBudget(v, budget)
	}, func(v *s19.SgNBReleaseRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s19.X2apInternalSgNBReleaseRequestMarshalAPERBudget(v, budget, fresh)
	}, func(data []byte, options aper.DecodeState) (s19.SgNBReleaseRequest, error) {
		var v s19.SgNBReleaseRequest
		err := s19.X2apInternalSgNBReleaseRequestUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s19.SgNBReleaseRequest{}, err
		}
		*s19.X2apInternalSgNBReleaseRequestFieldReceived(&v) = true
		*s19.X2apInternalSgNBReleaseRequestFieldReceivedAbsolute(&v) = true
		*s19.X2apInternalSgNBReleaseRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, func(v s19.SgNBReleaseRequest) s19.InitiatingValue {
		return s19.X2apInternalConstructT15InitiatingValueF4codeF22bodySgNBReleaseRequest(s00.ProcedureCode(31), &v)
	}, func(v s19.SgNBReleaseRequest, options aper.DecodeState) (s19.SgNBReleaseRequest, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s19.X2apInternalCaptureX2APSgNBReleaseRequest(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, func(v s19.SgNBReleaseRequest, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root,
			budget)
		f := s.Begin()
		s19.X2apInternalCompareX2APSgNBReleaseRequest(&v, &s)
		s.
			End(f, root, false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:SgNBReleaseRequest"))

}

// Successful returns the typed binding for the successful outcome of MeNBinitiatedSgNBReleaseDescriptor.
func (MeNBinitiatedSgNBReleaseDescriptor) Successful() s18.SgNBReleaseRequestAcknowledgeSuccessfulBinding {
	return s18.X2apInternalConstructT46SgNBReleaseRequestAcknowledgeSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(MeNBinitiatedSgNBReleaseProcedure().Info(), func(v *s18.SgNBReleaseRequestAcknowledge, budget *aper.DecodeBudget) (s12.ValidationReport, error) {
		return s19.X2apInternalValidateSgNBReleaseRequestAcknowledgeBudget(v, budget)
	}, func(v *s18.SgNBReleaseRequestAcknowledge, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s18.X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERBudget(v, budget, fresh)
	}, func(data []byte, options aper.DecodeState) (s18.SgNBReleaseRequestAcknowledge, error) {
		var v s18.SgNBReleaseRequestAcknowledge
		err := s18.X2apInternalSgNBReleaseRequestAcknowledgeUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s18.SgNBReleaseRequestAcknowledge{}, err
		}
		*s18.X2apInternalSgNBReleaseRequestAcknowledgeFieldReceived(&v) = true
		*s18.X2apInternalSgNBReleaseRequestAcknowledgeFieldReceivedAbsolute(&v) = true
		*s18.X2apInternalSgNBReleaseRequestAcknowledgeFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, func(v s18.SgNBReleaseRequestAcknowledge) s18.SuccessfulValue {
		return s18.X2apInternalConstructT15SuccessfulValueF4codeF33bodySgNBReleaseRequestAcknowledge(s00.ProcedureCode(31), &v)
	}, func(v s18.SgNBReleaseRequestAcknowledge, options aper.DecodeState) (s18.SgNBReleaseRequestAcknowledge, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s18.X2apInternalCaptureX2APSgNBReleaseRequestAcknowledge(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, func(v s18.SgNBReleaseRequestAcknowledge, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s18.X2apInternalCompareX2APSgNBReleaseRequestAcknowledge(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:SgNBReleaseRequestAcknowledge"))

}

// Unsuccessful returns the typed binding for the unsuccessful outcome of MeNBinitiatedSgNBReleaseDescriptor.
func (MeNBinitiatedSgNBReleaseDescriptor) Unsuccessful() s14.SgNBReleaseRequestRejectUnsuccessfulBinding {
	return s14.X2apInternalConstructT43SgNBReleaseRequestRejectUnsuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(MeNBinitiatedSgNBReleaseProcedure().Info(), func(v *s14.SgNBReleaseRequestReject, budget *aper.DecodeBudget) (s12.ValidationReport, error) {
		return s14.X2apInternalValidateSgNBReleaseRequestRejectBudget(v, budget)
	}, func(v *s14.SgNBReleaseRequestReject, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s14.X2apInternalSgNBReleaseRequestRejectMarshalAPERBudget(v, budget, fresh)
	}, func(data []byte, options aper.DecodeState) (s14.SgNBReleaseRequestReject, error) {
		var v s14.SgNBReleaseRequestReject
		err := s14.X2apInternalSgNBReleaseRequestRejectUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s14.SgNBReleaseRequestReject{}, err
		}
		*s14.X2apInternalSgNBReleaseRequestRejectFieldReceived(&v) = true
		*s14.X2apInternalSgNBReleaseRequestRejectFieldReceivedAbsolute(&v) = true
		*s14.X2apInternalSgNBReleaseRequestRejectFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, func(v s14.SgNBReleaseRequestReject) s14.UnsuccessfulValue {
		return s14.X2apInternalConstructT17UnsuccessfulValueF4codeF28bodySgNBReleaseRequestReject(s00.ProcedureCode(31), &v)
	}, func(v s14.SgNBReleaseRequestReject, options aper.DecodeState) (s14.SgNBReleaseRequestReject, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s14.X2apInternalCaptureX2APSgNBReleaseRequestReject(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, func(v s14.SgNBReleaseRequestReject, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s14.X2apInternalCompareX2APSgNBReleaseRequestReject(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:SgNBReleaseRequestReject"))

}

// Initiating returns the typed binding for the initiating message of SgNBinitiatedSgNBReleaseDescriptor.
func (SgNBinitiatedSgNBReleaseDescriptor) Initiating() s19.SgNBReleaseRequiredInitiatingBinding {
	return s19.X2apInternalConstructT36SgNBReleaseRequiredInitiatingBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(SgNBinitiatedSgNBReleaseProcedure().Info(), func(v *s19.SgNBReleaseRequired, budget *aper.DecodeBudget) (s12.ValidationReport, error) {
		return X2apInternalValidateSgNBReleaseRequiredBudget(v, budget)
	}, func(v *s19.SgNBReleaseRequired, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s19.X2apInternalSgNBReleaseRequiredMarshalAPERBudget(v, budget, fresh)
	}, func(data []byte, options aper.DecodeState) (s19.SgNBReleaseRequired, error) {
		var v s19.SgNBReleaseRequired
		err := s19.X2apInternalSgNBReleaseRequiredUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s19.SgNBReleaseRequired{}, err
		}
		*s19.X2apInternalSgNBReleaseRequiredFieldReceived(&v) = true
		*s19.X2apInternalSgNBReleaseRequiredFieldReceivedAbsolute(&v) = true
		*s19.X2apInternalSgNBReleaseRequiredFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, func(v s19.SgNBReleaseRequired) s19.InitiatingValue {
		return s19.X2apInternalConstructT15InitiatingValueF4codeF23bodySgNBReleaseRequired(s00.ProcedureCode(32), &v)
	}, func(v s19.SgNBReleaseRequired, options aper.DecodeState) (s19.SgNBReleaseRequired, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s19.X2apInternalCaptureX2APSgNBReleaseRequired(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root

	}, func(v s19.SgNBReleaseRequired, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root,
			budget)
		f := s.Begin()
		s19.X2apInternalCompareX2APSgNBReleaseRequired(&v,
			&s,
		)
		s.End(f, root, false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:SgNBReleaseRequired"))

}

// Successful returns the typed binding for the successful outcome of SgNBinitiatedSgNBReleaseDescriptor.
func (SgNBinitiatedSgNBReleaseDescriptor) Successful() s18.SgNBReleaseConfirmSuccessfulBinding {
	return s18.X2apInternalConstructT35SgNBReleaseConfirmSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(SgNBinitiatedSgNBReleaseProcedure().Info(), func(v *s18.SgNBReleaseConfirm, budget *aper.DecodeBudget) (s12.ValidationReport, error) {
		return s19.X2apInternalValidateSgNBReleaseConfirmBudget(v, budget)
	}, func(v *s18.SgNBReleaseConfirm, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s18.X2apInternalSgNBReleaseConfirmMarshalAPERBudget(v, budget, fresh)
	}, func(data []byte, options aper.DecodeState) (s18.SgNBReleaseConfirm, error) {
		var v s18.SgNBReleaseConfirm
		err := s18.X2apInternalSgNBReleaseConfirmUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s18.SgNBReleaseConfirm{}, err
		}
		*s18.X2apInternalSgNBReleaseConfirmFieldReceived(&v) = true
		*s18.X2apInternalSgNBReleaseConfirmFieldReceivedAbsolute(&v) = true
		*s18.X2apInternalSgNBReleaseConfirmFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, func(v s18.SgNBReleaseConfirm) s18.SuccessfulValue {
		return s18.X2apInternalConstructT15SuccessfulValueF4codeF22bodySgNBReleaseConfirm(s00.ProcedureCode(32), &v)
	}, func(v s18.SgNBReleaseConfirm, options aper.DecodeState) (s18.SgNBReleaseConfirm, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s18.X2apInternalCaptureX2APSgNBReleaseConfirm(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, func(v s18.SgNBReleaseConfirm, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root,
			budget)
		f := s.Begin()
		s18.X2apInternalCompareX2APSgNBReleaseConfirm(&v, &s)
		s.
			End(f, root, false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:SgNBReleaseConfirm"))

}

// Initiating returns the typed binding for the initiating message of TraceStartDescriptor.
func (TraceStartDescriptor) Initiating() s19.TraceStartInitiatingBinding {
	return s19.X2apInternalConstructT27TraceStartInitiatingBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(TraceStartProcedure().Info(), func(v *s19.TraceStart, budget *aper.DecodeBudget) (s12.ValidationReport, error) {
		return X2apInternalValidateTraceStartBudget(v, budget)
	}, func(v *s19.TraceStart, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s19.X2apInternalTraceStartMarshalAPERBudget(v, budget, fresh)
	}, func(data []byte, options aper.DecodeState) (s19.TraceStart, error) {
		var v s19.TraceStart
		err := s19.X2apInternalTraceStartUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s19.TraceStart{}, err
		}
		*s19.X2apInternalTraceStartFieldReceived(&v) = true
		*s19.X2apInternalTraceStartFieldReceivedAbsolute(&v) = true
		*s19.X2apInternalTraceStartFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, func(v s19.TraceStart) s19.InitiatingValue {
		return s19.X2apInternalConstructT15InitiatingValueF4codeF14bodyTraceStart(s00.ProcedureCode(47), &v)
	}, func(v s19.TraceStart, options aper.DecodeState) (s19.TraceStart, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.
			Begin()
		s19.X2apInternalCaptureX2APTraceStart(&v, &s)
		var root aper.Snapshot
		s.End(
			f,
			&root, false)
		return v, root
	}, func(v s19.TraceStart, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root,
			budget,
		)
		f := s.Begin()
		s19.X2apInternalCompareX2APTraceStart(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:TraceStart"))

}

// Initiating returns the typed binding for the initiating message of UERadioCapabilityIDMappingDescriptor.
func (UERadioCapabilityIDMappingDescriptor) Initiating() s19.UERadioCapabilityIDMappingRequestInitiatingBinding {
	return s19.X2apInternalConstructT50UERadioCapabilityIDMappingRequestInitiatingBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(UERadioCapabilityIDMappingProcedure().Info(), func(v *s19.UERadioCapabilityIDMappingRequest, budget *aper.DecodeBudget) (s12.ValidationReport, error) {
		return X2apInternalValidateUERadioCapabilityIDMappingRequestBudget(v, budget)
	}, func(v *s19.UERadioCapabilityIDMappingRequest, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s19.X2apInternalUERadioCapabilityIDMappingRequestMarshalAPERBudget(v, budget, fresh)
	}, func(data []byte, options aper.DecodeState) (s19.UERadioCapabilityIDMappingRequest, error) {
		var v s19.UERadioCapabilityIDMappingRequest
		err := s19.X2apInternalUERadioCapabilityIDMappingRequestUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s19.UERadioCapabilityIDMappingRequest{}, err
		}
		*s19.X2apInternalUERadioCapabilityIDMappingRequestFieldReceived(&v) = true
		*s19.X2apInternalUERadioCapabilityIDMappingRequestFieldReceivedAbsolute(&v) = true
		*s19.X2apInternalUERadioCapabilityIDMappingRequestFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, func(v s19.UERadioCapabilityIDMappingRequest) s19.InitiatingValue {
		return s19.X2apInternalConstructT15InitiatingValueF4codeF37bodyUERadioCapabilityIDMappingRequest(s00.ProcedureCode(56), &v)
	}, func(v s19.UERadioCapabilityIDMappingRequest, options aper.DecodeState) (s19.UERadioCapabilityIDMappingRequest, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s19.X2apInternalCaptureX2APUERadioCapabilityIDMappingRequest(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, func(v s19.UERadioCapabilityIDMappingRequest, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s19.X2apInternalCompareX2APUERadioCapabilityIDMappingRequest(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:UERadioCapabilityIDMappingRequest"))

}

// Successful returns the typed binding for the successful outcome of UERadioCapabilityIDMappingDescriptor.
func (UERadioCapabilityIDMappingDescriptor) Successful() s18.UERadioCapabilityIDMappingResponseSuccessfulBinding {
	return s18.X2apInternalConstructT51UERadioCapabilityIDMappingResponseSuccessfulBindingF4infoF8validateF6encodeF6decodeF6injectF7captureF7compareF7context(UERadioCapabilityIDMappingProcedure().Info(), func(v *s18.UERadioCapabilityIDMappingResponse, budget *aper.DecodeBudget) (s12.ValidationReport, error) {
		return X2apInternalValidateUERadioCapabilityIDMappingResponseBudget(v, budget)
	}, func(v *s18.UERadioCapabilityIDMappingResponse, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s18.X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERBudget(v, budget, fresh)
	}, func(data []byte, options aper.DecodeState) (s18.UERadioCapabilityIDMappingResponse, error) {
		var v s18.UERadioCapabilityIDMappingResponse
		err := s18.X2apInternalUERadioCapabilityIDMappingResponseUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s18.UERadioCapabilityIDMappingResponse{}, err
		}
		*s18.X2apInternalUERadioCapabilityIDMappingResponseFieldReceived(&v) = true
		*s18.X2apInternalUERadioCapabilityIDMappingResponseFieldReceivedAbsolute(&v) = true
		*s18.X2apInternalUERadioCapabilityIDMappingResponseFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, func(v s18.UERadioCapabilityIDMappingResponse) s18.SuccessfulValue {
		return s18.X2apInternalConstructT15SuccessfulValueF4codeF38bodyUERadioCapabilityIDMappingResponse(s00.ProcedureCode(56), &v)
	}, func(v s18.UERadioCapabilityIDMappingResponse, options aper.DecodeState) (s18.UERadioCapabilityIDMappingResponse, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s18.X2apInternalCaptureX2APUERadioCapabilityIDMappingResponse(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, func(v s18.UERadioCapabilityIDMappingResponse, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s18.X2apInternalCompareX2APUERadioCapabilityIDMappingResponse(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:UERadioCapabilityIDMappingResponse"))

}
func X2apInternalCaptureX2APPrivateIEContainer[V X2apInternalProtocolPrivateValue[V]](v *PrivateIEContainer[V], s *aper.SemanticCapture) {
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
			X2apInternalCaptureX2APPrivateIEField[V](&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func X2apInternalCompareX2APPrivateIEContainer[V X2apInternalProtocolPrivateValue[V]](v *PrivateIEContainer[V], s *aper.SemanticComparison) {
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
			X2apInternalCompareX2APPrivateIEField[V](&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func X2apInternalCaptureX2APPrivateIEField[V X2apInternalProtocolPrivateValue[V]](v *PrivateIEField[V], s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s00.X2apInternalCaptureX2APPrivateIEID(&v.Id, s)
	s00.X2apInternalCaptureX2APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APPrivateIEField[V X2apInternalProtocolPrivateValue[V]](v *PrivateIEField[V], s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s00.X2apInternalCompareX2APPrivateIEID(&v.Id, s)
	s00.X2apInternalCompareX2APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APProtocolExtensionContainer[V X2apInternalProtocolOpenValue[V]](v *ProtocolExtensionContainer[V], s *aper.SemanticCapture) {
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
			X2apInternalCaptureX2APProtocolExtensionField[V](&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func X2apInternalCompareX2APProtocolExtensionContainer[V X2apInternalProtocolOpenValue[V]](v *ProtocolExtensionContainer[V], s *aper.SemanticComparison) {
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
			X2apInternalCompareX2APProtocolExtensionField[V](&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func X2apInternalCaptureX2APProtocolExtensionField[V X2apInternalProtocolOpenValue[V]](v *ProtocolExtensionField[V], s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s00.X2apInternalCaptureX2APProtocolIEID(&v.Id, s)
	s00.X2apInternalCaptureX2APCriticality(&v.Criticality, s)
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APProtocolExtensionField[V X2apInternalProtocolOpenValue[V]](v *ProtocolExtensionField[V], s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s00.X2apInternalCompareX2APProtocolIEID(&v.Id, s)
	s00.X2apInternalCompareX2APCriticality(&v.Criticality, s)
	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APProtocolIEContainer[V X2apInternalProtocolOpenValue[V]](v *ProtocolIEContainer[V], s *aper.SemanticCapture) {
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
			X2apInternalCaptureX2APProtocolIEField[V](&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func X2apInternalCompareX2APProtocolIEContainer[V X2apInternalProtocolOpenValue[V]](v *ProtocolIEContainer[V], s *aper.SemanticComparison) {
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
			X2apInternalCompareX2APProtocolIEField[V](&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func X2apInternalCaptureX2APProtocolIEField[V X2apInternalProtocolOpenValue[V]](v *ProtocolIEField[V], s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s00.X2apInternalCaptureX2APProtocolIEID(&v.Id, s)
	s00.X2apInternalCaptureX2APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APProtocolIEField[V X2apInternalProtocolOpenValue[V]](v *ProtocolIEField[V], s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s00.X2apInternalCompareX2APProtocolIEID(&v.Id, s)
	s00.X2apInternalCompareX2APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APProtocolIESingleContainer[V X2apInternalProtocolOpenValue[V]](v *ProtocolIESingleContainer[V], s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	X2apInternalCaptureX2APProtocolIEField[V](v, s)
	s.End(f, nil, false)
}
func X2apInternalCompareX2APProtocolIESingleContainer[V X2apInternalProtocolOpenValue[V]](v *ProtocolIESingleContainer[V], s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	X2apInternalCompareX2APProtocolIEField[V](v, s)
	s.End(f, aper.Snapshot{}, false)
}
func X2apInternalCaptureX2APULHighInterferenceIndicationInfoComplete(v *ULHighInterferenceIndicationInfoComplete, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s12.X2apInternalCaptureX2APULHighInterferenceIndicationInfo(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APULHighInterferenceIndicationInfoComplete(v *ULHighInterferenceIndicationInfoComplete, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s12.X2apInternalCompareX2APULHighInterferenceIndicationInfo(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APULInterferenceOverloadIndicationComplete(v *ULInterferenceOverloadIndicationComplete, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s12.X2apInternalCaptureX2APULInterferenceOverloadIndication(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APULInterferenceOverloadIndicationComplete(v *ULInterferenceOverloadIndicationComplete, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s12.X2apInternalCompareX2APULInterferenceOverloadIndication(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func X2apInternalCaptureX2APWLANMeasConfigNameListComplete(v *WLANMeasConfigNameListComplete, s *aper.SemanticCapture) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s13.X2apInternalCaptureX2APWLANMeasConfigNameList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func X2apInternalCompareX2APWLANMeasConfigNameListComplete(v *WLANMeasConfigNameListComplete, s *aper.SemanticComparison) {
	f := s.Begin()
	if s.Failed() {
		return
	}
	s.EnterValue()
	defer s.LeaveValue()
	s13.X2apInternalCompareX2APWLANMeasConfigNameList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}

type X2apInternalProtocolOpenValue[V any] interface {
	captureSemantics(aper.SemanticCapture) V
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (V, error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}
type ProtocolIEField[V X2apInternalProtocolOpenValue[V]] struct {
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         V
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
}
type ProtocolIEContainer[V X2apInternalProtocolOpenValue[V]] []ProtocolIEField[V]
type ProtocolIEContainerList[V X2apInternalProtocolOpenValue[V]] []ProtocolIEContainer[V]

// WithoutReplay returns a copy that encodes without received replay state.
func (v ProtocolIEField[V]) WithoutReplay() ProtocolIEField[V] {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire representation, if present.
func (v *ProtocolIEField[V]) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	location := v.stream.ContentLocation()
	location.Path = "ProtocolIEField"
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, location, nil)
}

// MarshalAPERTo encodes the field into the enclosing APER buffer.
func (v *ProtocolIEField[V]) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	// TS 36.423 V19.1.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return err
	}
	if err := bb.ChargeWork(uint64(len(data))); err != nil {
		return err
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s00.X2apInternalInt64Ptr(0), s00.X2apInternalInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the enclosing APER buffer.
func (v *ProtocolIEField[V]) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ProtocolIEField[V]{}
	id, err := aper.DecodeIntegerAligned(bb, s00.X2apInternalInt64Ptr(0), s00.X2apInternalInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero V
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

type ProtocolExtensionField[V X2apInternalProtocolOpenValue[V]] struct {
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue V
	replay         aper.Snapshot
	stream         aper.WireSpan
	withoutReplay  bool
}
type ProtocolExtensionContainer[V X2apInternalProtocolOpenValue[V]] []ProtocolExtensionField[V]

// WithoutReplay returns a copy that encodes without received replay state.
func (v ProtocolExtensionField[V]) WithoutReplay() ProtocolExtensionField[V] {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire representation, if present.
func (v *ProtocolExtensionField[V]) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	location := v.stream.ContentLocation()
	location.Path = "ProtocolExtensionField"
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, location, nil)
}

// MarshalAPERTo encodes the field into the enclosing APER buffer.
func (v *ProtocolExtensionField[V]) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	// TS 36.423 V19.1.0 §9.3.8 binds the table-selected value to @id.
	if !v.ExtensionValue.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	data, err := v.ExtensionValue.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return err
	}
	if err := bb.ChargeWork(uint64(len(data))); err != nil {
		return err
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s00.X2apInternalInt64Ptr(0), s00.X2apInternalInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the enclosing APER buffer.
func (v *ProtocolExtensionField[V]) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ProtocolExtensionField[V]{}
	id, err := aper.DecodeIntegerAligned(bb, s00.X2apInternalInt64Ptr(0), s00.X2apInternalInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero V
	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := zero.decode(v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

type X2apInternalProtocolPrivateValue[V any] interface {
	captureSemantics(aper.SemanticCapture) V
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	matchesID(s00.PrivateIEID, *aper.DecodeBudget) bool
	decode(s00.PrivateIEID, aper.OpaqueOpenType) (V, error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	rule() aper.SourceRule
}
type PrivateIEField[V X2apInternalProtocolPrivateValue[V]] struct {
	Id            s00.PrivateIEID
	Criticality   s00.Criticality
	Value         V
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
}
type PrivateIEContainer[V X2apInternalProtocolPrivateValue[V]] []PrivateIEField[V]

// WithoutReplay returns a copy that encodes without received replay state.
func (v PrivateIEField[V]) WithoutReplay() PrivateIEField[V] {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire representation, if present.
func (v *PrivateIEField[V]) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	location := v.stream.ContentLocation()
	location.Path = "PrivateIEField"
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, location, nil)
}

// MarshalAPERTo encodes the field into the enclosing APER buffer.
func (v *PrivateIEField[V]) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		return fmt.Errorf("nil PrivateIEField")
	}
	// TS 36.423 V19.1.0 §9.3.8 binds the private value to @id, too.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: private field id does not match its value selector", aper.ErrInvalidValue), "PrivateIEField.Id")
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return err
	}
	if err := bb.ChargeWork(uint64(len(data))); err != nil {
		return err
	}
	if err := s00.X2apInternalPrivateIEIDMarshalAPERTo(&v.Id, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	return aper.EncodeOpenTypeAligned(bb, data)
}

// UnmarshalAPERFrom decodes the field from the enclosing APER buffer.
func (v *PrivateIEField[V]) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil PrivateIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PrivateIEField[V]{}
	if err := s00.X2apInternalPrivateIEIDUnmarshalAPERFrom(&v.Id, bb); err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero V
	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("PrivateIEField.Value")
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

type ProtocolIEFieldPair[A X2apInternalProtocolOpenValue[A], B X2apInternalProtocolOpenValue[B]] struct {
	Id                s00.ProtocolIEID
	FirstCriticality  s00.Criticality
	FirstValue        A
	SecondCriticality s00.Criticality
	SecondValue       B
}
type ProtocolIEContainerPair[A X2apInternalProtocolOpenValue[A], B X2apInternalProtocolOpenValue[B]] []ProtocolIEFieldPair[A, B]
type ProtocolIEContainerPairList[A X2apInternalProtocolOpenValue[A], B X2apInternalProtocolOpenValue[B]] []ProtocolIEContainerPair[A, B]
type ProtocolIESingleContainer[V X2apInternalProtocolOpenValue[V]] = ProtocolIEField[V]
type UEContextReleaseDescriptor struct{}

func UEContextReleaseProcedure() UEContextReleaseDescriptor { return UEContextReleaseDescriptor{} }

// Info returns the source-derived procedure metadata for UEContextReleaseDescriptor.
func (UEContextReleaseDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(5), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "X2AP-PDU-Descriptions", Assignment: "id-uEContextRelease"}}}
}

type X2SetupDescriptor struct{}

func X2SetupProcedure() X2SetupDescriptor { return X2SetupDescriptor{} }

// Info returns the source-derived procedure metadata for X2SetupDescriptor.
func (X2SetupDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(6), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: true, Rule: aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "X2AP-PDU-Descriptions", Assignment: "id-x2Setup"}}}
}

type X2ReleaseDescriptor struct{}

func X2ReleaseProcedure() X2ReleaseDescriptor { return X2ReleaseDescriptor{} }

// Info returns the source-derived procedure metadata for X2ReleaseDescriptor.
func (X2ReleaseDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(16), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "X2AP-PDU-Descriptions", Assignment: "id-x2Release"}}}
}

type X2APMessageTransferDescriptor struct{}

func X2APMessageTransferProcedure() X2APMessageTransferDescriptor {
	return X2APMessageTransferDescriptor{}
}

// Info returns the source-derived procedure metadata for X2APMessageTransferDescriptor.
func (X2APMessageTransferDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(17), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "X2AP-PDU-Descriptions", Assignment: "id-x2APMessageTransfer"}}}
}

type X2RemovalDescriptor struct{}

func X2RemovalProcedure() X2RemovalDescriptor { return X2RemovalDescriptor{} }

// Info returns the source-derived procedure metadata for X2RemovalDescriptor.
func (X2RemovalDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(18), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: true, Rule: aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "X2AP-PDU-Descriptions", Assignment: "id-x2Removal"}}}
}

type MeNBinitiatedSgNBReleaseDescriptor struct{}

func MeNBinitiatedSgNBReleaseProcedure() MeNBinitiatedSgNBReleaseDescriptor {
	return MeNBinitiatedSgNBReleaseDescriptor{}
}

// Info returns the source-derived procedure metadata for MeNBinitiatedSgNBReleaseDescriptor.
func (MeNBinitiatedSgNBReleaseDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(31), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: true, Rule: aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "X2AP-PDU-Descriptions", Assignment: "id-meNBinitiatedSgNBRelease"}}}
}

type SgNBinitiatedSgNBReleaseDescriptor struct{}

func SgNBinitiatedSgNBReleaseProcedure() SgNBinitiatedSgNBReleaseDescriptor {
	return SgNBinitiatedSgNBReleaseDescriptor{}
}

// Info returns the source-derived procedure metadata for SgNBinitiatedSgNBReleaseDescriptor.
func (SgNBinitiatedSgNBReleaseDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(32), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "X2AP-PDU-Descriptions", Assignment: "id-sgNBinitiatedSgNBRelease"}}}
}

type TraceStartDescriptor struct{}

func TraceStartProcedure() TraceStartDescriptor { return TraceStartDescriptor{} }

// Info returns the source-derived procedure metadata for TraceStartDescriptor.
func (TraceStartDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(47), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "X2AP-PDU-Descriptions", Assignment: "id-traceStart"}}}
}

type UERadioCapabilityIDMappingDescriptor struct{}

func UERadioCapabilityIDMappingProcedure() UERadioCapabilityIDMappingDescriptor {
	return UERadioCapabilityIDMappingDescriptor{}
}

// Info returns the source-derived procedure metadata for UERadioCapabilityIDMappingDescriptor.
func (UERadioCapabilityIDMappingDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(56), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: true, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "X2AP-PDU-Descriptions", Assignment: "id-UERadioCapabilityIDMapping"}}}
}

// SgNBReleaseConfirmCodec binds the complete APER value type.
func SgNBReleaseConfirmCodec() s18.SgNBReleaseConfirmValueCodec {
	return SgNBinitiatedSgNBReleaseProcedure().Successful().Codec()
}

// SgNBReleaseRequestAcknowledgeCodec binds the complete APER value type.
func SgNBReleaseRequestAcknowledgeCodec() s18.SgNBReleaseRequestAcknowledgeValueCodec {
	return MeNBinitiatedSgNBReleaseProcedure().Successful().Codec()
}

// SgNBReleaseRequestCodec binds the complete APER value type.
func SgNBReleaseRequestCodec() s19.SgNBReleaseRequestValueCodec {
	return MeNBinitiatedSgNBReleaseProcedure().Initiating().Codec()
}

// SgNBReleaseRequestRejectCodec binds the complete APER value type.
func SgNBReleaseRequestRejectCodec() s14.SgNBReleaseRequestRejectValueCodec {
	return MeNBinitiatedSgNBReleaseProcedure().Unsuccessful().Codec()
}

// SgNBReleaseRequiredCodec binds the complete APER value type.
func SgNBReleaseRequiredCodec() s19.SgNBReleaseRequiredValueCodec {
	return SgNBinitiatedSgNBReleaseProcedure().Initiating().Codec()
}

// TraceStartCodec binds the complete APER value type.
func TraceStartCodec() s19.TraceStartValueCodec { return TraceStartProcedure().Initiating().Codec() }

// UEContextReleaseCodec binds the complete APER value type.
func UEContextReleaseCodec() s19.UEContextReleaseValueCodec {
	return UEContextReleaseProcedure().Initiating().Codec()
}

// UERadioCapabilityIDMappingRequestCodec binds the complete APER value type.
func UERadioCapabilityIDMappingRequestCodec() s19.UERadioCapabilityIDMappingRequestValueCodec {
	return UERadioCapabilityIDMappingProcedure().Initiating().Codec()
}

// UERadioCapabilityIDMappingResponseCodec binds the complete APER value type.
func UERadioCapabilityIDMappingResponseCodec() s18.UERadioCapabilityIDMappingResponseValueCodec {
	return UERadioCapabilityIDMappingProcedure().Successful().Codec()
}

// ULHighInterferenceIndicationInfoCodec binds the complete source value type.
func ULHighInterferenceIndicationInfoCodec() s12.ULHighInterferenceIndicationInfoValueCodec {
	return s12.X2apInternalConstructT42ULHighInterferenceIndicationInfoValueCodecF4pathF6decodeF6encodeF7captureF7compareF7context("ULHighInterferenceIndicationInfo", func(data []byte, options aper.DecodeState) (s12.ULHighInterferenceIndicationInfo, error) {
		var complete ULHighInterferenceIndicationInfoComplete
		if err := X2apInternalULHighInterferenceIndicationInfoCompleteUnmarshalAPERWithOptions(&complete, data, options); err != nil {
			var zero s12.ULHighInterferenceIndicationInfo
			return zero, err
		}
		return complete.Value, nil
	}, func(value s12.ULHighInterferenceIndicationInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		complete := ULHighInterferenceIndicationInfoComplete{Value: value}
		return X2apInternalULHighInterferenceIndicationInfoCompleteMarshalAPERBudget(&complete, budget, fresh)
	}, func(v s12.ULHighInterferenceIndicationInfo, options aper.DecodeState) (s12.ULHighInterferenceIndicationInfo, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s12.X2apInternalCaptureX2APULHighInterferenceIndicationInfo(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, func(v s12.ULHighInterferenceIndicationInfo, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s12.X2apInternalCompareX2APULHighInterferenceIndicationInfo(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:ULHighInterferenceIndicationInfo"))

}

// ULInterferenceOverloadIndicationCodec binds the complete source value type.
func ULInterferenceOverloadIndicationCodec() s12.ULInterferenceOverloadIndicationValueCodec {
	return s12.X2apInternalConstructT42ULInterferenceOverloadIndicationValueCodecF4pathF6decodeF6encodeF7captureF7compareF7context("ULInterferenceOverloadIndication", func(data []byte, options aper.DecodeState) (s12.ULInterferenceOverloadIndication, error) {
		var complete ULInterferenceOverloadIndicationComplete
		if err := X2apInternalULInterferenceOverloadIndicationCompleteUnmarshalAPERWithOptions(&complete, data, options); err != nil {
			var zero s12.ULInterferenceOverloadIndication
			return zero, err
		}
		return complete.Value, nil
	}, func(value s12.ULInterferenceOverloadIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		complete := ULInterferenceOverloadIndicationComplete{Value: value}
		return X2apInternalULInterferenceOverloadIndicationCompleteMarshalAPERBudget(&complete, budget, fresh)
	}, func(v s12.ULInterferenceOverloadIndication, options aper.DecodeState) (s12.ULInterferenceOverloadIndication, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s12.X2apInternalCaptureX2APULInterferenceOverloadIndication(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, func(v s12.ULInterferenceOverloadIndication, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s12.X2apInternalCompareX2APULInterferenceOverloadIndication(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:ULInterferenceOverloadIndication"))

}

// WLANMeasConfigNameListCodec binds the complete source value type.
func WLANMeasConfigNameListCodec() s13.WLANMeasConfigNameListValueCodec {
	return s13.X2apInternalConstructT32WLANMeasConfigNameListValueCodecF4pathF6decodeF6encodeF7captureF7compareF7context("WLANMeasConfigNameList", func(data []byte, options aper.DecodeState) (s13.WLANMeasConfigNameList, error) {
		var complete WLANMeasConfigNameListComplete
		if err := X2apInternalWLANMeasConfigNameListCompleteUnmarshalAPERWithOptions(&complete, data, options); err != nil {
			var zero s13.WLANMeasConfigNameList
			return zero, err
		}
		return complete.Value, nil
	}, func(value s13.WLANMeasConfigNameList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		complete := WLANMeasConfigNameListComplete{Value: value}
		return X2apInternalWLANMeasConfigNameListCompleteMarshalAPERBudget(&complete, budget, fresh)
	}, func(v s13.WLANMeasConfigNameList, options aper.DecodeState) (s13.WLANMeasConfigNameList, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s13.X2apInternalCaptureX2APWLANMeasConfigNameList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, func(v s13.WLANMeasConfigNameList, root aper.Snapshot, budget aper.DecodeBudget) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		s13.X2apInternalCompareX2APWLANMeasConfigNameList(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, s00.X2apInternalConstructT12codecContextF6source("source-value:WLANMeasConfigNameList"))

}

// X2APMessageTransferCodec binds the complete APER value type.
func X2APMessageTransferCodec() s19.X2APMessageTransferValueCodec {
	return X2APMessageTransferProcedure().Initiating().Codec()
}

// X2ReleaseCodec binds the complete APER value type.
func X2ReleaseCodec() s19.X2ReleaseValueCodec { return X2ReleaseProcedure().Initiating().Codec() }

// X2RemovalFailureCodec binds the complete APER value type.
func X2RemovalFailureCodec() s14.X2RemovalFailureValueCodec {
	return X2RemovalProcedure().Unsuccessful().Codec()
}

// X2RemovalRequestCodec binds the complete APER value type.
func X2RemovalRequestCodec() s19.X2RemovalRequestValueCodec {
	return X2RemovalProcedure().Initiating().Codec()
}

// X2RemovalResponseCodec binds the complete APER value type.
func X2RemovalResponseCodec() s18.X2RemovalResponseValueCodec {
	return X2RemovalProcedure().Successful().Codec()
}

// X2SetupFailureCodec binds the complete APER value type.
func X2SetupFailureCodec() s14.X2SetupFailureValueCodec {
	return X2SetupProcedure().Unsuccessful().Codec()
}

// X2SetupRequestCodec binds the complete APER value type.
func X2SetupRequestCodec() s19.X2SetupRequestValueCodec {
	return X2SetupProcedure().Initiating().Codec()
}

// X2SetupResponseCodec binds the complete APER value type.
func X2SetupResponseCodec() s18.X2SetupResponseValueCodec {
	return X2SetupProcedure().Successful().Codec()
}

// TS 36.423 V19.1.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func X2apInternalValidateX2APIEContainer[V X2apInternalProtocolOpenValue[V]](fields ProtocolIEContainer[V], rows []s06.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: s00.X2apInternalConstructT7TableIDF6source(rule.Assignment), IEID: field.Id, HasIEID: true, Rule: s00.X2apInternalX2apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := s00.X2apInternalConstructT7TableIDF6source(field.Value.rule().Assignment)
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
func X2apInternalValidateUEContextReleaseBudget(v *s19.UEContextRelease, budget *aper.DecodeBudget,

) (s12.ValidationReport, error) {
	if v == nil {
		return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("nil UEContextRelease")
	}
	rows := []s06.FieldInfo{s12.UEContextReleaseIEs().OldENBUEX2APID().Info(), s12.UEContextReleaseIEs().NewENBUEX2APID().Info(), s12.UEContextReleaseIEs().OldENBUEX2APIDExtension().Info(), s12.UEContextReleaseIEs().NewENBUEX2APIDExtension().Info(), s12.UEContextReleaseIEs().SIPTOBearerDeactivationIndication().Info(), s12.UEContextReleaseIEs().SgNBUEX2APID().Info()}
	report := s13.X2apInternalUEContextReleaseIEValuevalidateX2APIEContainer(v.ProtocolIEs, rows, "UEContextRelease.protocolIEs", budget)
	X2apInternalWalkValidationUEContextRelease(v, &report, "UEContextRelease", true)
	return report, nil
}
func X2apInternalValidateX2SetupRequestBudget(v *s19.X2SetupRequest, budget *aper.DecodeBudget,

) (s12.ValidationReport, error) {
	if v == nil {
		return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("nil X2SetupRequest")
	}
	rows := []s06.FieldInfo{s17.X2SetupRequestIEs().GlobalENBID().Info(), s17.X2SetupRequestIEs().ServedCells().Info(), s17.X2SetupRequestIEs().GUGroupIDList().Info(), s17.X2SetupRequestIEs().LHNID().Info()}
	report := s17.X2apInternalX2SetupRequestIEValuevalidateX2APIEContainer(v.ProtocolIEs, rows, "X2SetupRequest.protocolIEs", budget)
	X2apInternalWalkValidationX2SetupRequest(v, &report, "X2SetupRequest", true)
	return report, nil
}
func X2apInternalValidateX2SetupResponseBudget(v *s18.X2SetupResponse, budget *aper.DecodeBudget,

) (s12.ValidationReport, error) {
	if v == nil {
		return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("nil X2SetupResponse")
	}
	rows := []s06.FieldInfo{s17.X2SetupResponseIEs().GlobalENBID().Info(), s17.X2SetupResponseIEs().ServedCells().Info(), s17.X2SetupResponseIEs().GUGroupIDList().Info(), s17.X2SetupResponseIEs().CriticalityDiagnostics().Info(), s17.X2SetupResponseIEs().LHNID().Info()}
	report := s17.X2apInternalX2SetupResponseIEValuevalidateX2APIEContainer(v.ProtocolIEs, rows, "X2SetupResponse.protocolIEs", budget)
	X2apInternalWalkValidationX2SetupResponse(v, &report, "X2SetupResponse", true)
	return report, nil
}
func X2apInternalValidateX2ReleaseBudget(v *s19.X2Release, budget *aper.DecodeBudget,

) (s12.ValidationReport, error) {
	if v == nil {
		return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("nil X2Release")
	}
	rows := []s06.FieldInfo{s07.X2ReleaseIEs().GlobalENBID().Info()}
	report := s13.X2apInternalX2ReleaseIEValuevalidateX2APIEContainer(v.ProtocolIEs, rows, "X2Release.protocolIEs", budget)
	X2apInternalWalkValidationX2Release(v, &report, "X2Release", true)
	return report, nil
}
func X2apInternalValidateX2APMessageTransferBudget(v *s19.X2APMessageTransfer, budget *aper.DecodeBudget,

) (s12.ValidationReport, error) {
	if v == nil {
		return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("nil X2APMessageTransfer")
	}
	rows := []s06.FieldInfo{s13.X2APMessageTransferIEs().RNLHeader().Info(), s13.X2APMessageTransferIEs().X2APMessage().Info()}
	report := s13.X2apInternalX2APMessageTransferIEValuevalidateX2APIEContainer(v.ProtocolIEs, rows, "X2APMessageTransfer.protocolIEs", budget)
	X2apInternalWalkValidationX2APMessageTransfer(v, &report, "X2APMessageTransfer", true)
	return report, nil
}
func X2apInternalValidateX2RemovalRequestBudget(v *s19.X2RemovalRequest, budget *aper.DecodeBudget,

) (s12.ValidationReport, error) {
	if v == nil {
		return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("nil X2RemovalRequest")
	}
	rows := []s06.FieldInfo{s13.X2RemovalRequestIEs().GlobalENBID().Info(), s13.X2RemovalRequestIEs().X2RemovalThreshold().Info()}
	report := s13.X2apInternalX2RemovalRequestIEValuevalidateX2APIEContainer(v.ProtocolIEs, rows, "X2RemovalRequest.protocolIEs", budget)
	X2apInternalWalkValidationX2RemovalRequest(v, &report, "X2RemovalRequest", true)
	return report, nil
}
func X2apInternalValidateX2RemovalResponseBudget(v *s18.X2RemovalResponse, budget *aper.DecodeBudget,

) (s12.ValidationReport, error) {
	if v == nil {
		return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("nil X2RemovalResponse")
	}
	rows := []s06.FieldInfo{s07.X2RemovalResponseIEs().GlobalENBID().Info(), s07.X2RemovalResponseIEs().CriticalityDiagnostics().Info()}
	report := s13.X2apInternalX2RemovalResponseIEValuevalidateX2APIEContainer(v.ProtocolIEs, rows, "X2RemovalResponse.protocolIEs", budget)
	X2apInternalWalkValidationX2RemovalResponse(v, &report, "X2RemovalResponse", true)
	return report, nil
}
func X2apInternalValidateSgNBReleaseRequiredBudget(v *s19.SgNBReleaseRequired, budget *aper.DecodeBudget,

) (s12.ValidationReport, error) {
	if v == nil {
		return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("nil SgNBReleaseRequired")
	}
	rows := []s06.FieldInfo{s17.SgNBReleaseRequiredIEs().MeNBUEX2APID().Info(), s17.SgNBReleaseRequiredIEs().SgNBUEX2APID().Info(), s17.SgNBReleaseRequiredIEs().Cause().Info(), s17.SgNBReleaseRequiredIEs().MeNBUEX2APIDExtension().Info(), s17.SgNBReleaseRequiredIEs().ERABsToBeReleasedSgNBRelReqdList().Info(), s17.SgNBReleaseRequiredIEs().SgNBtoMeNBContainer().Info(), s17.SgNBReleaseRequiredIEs().SCGUEHistoryInformation().Info()}
	report := s17.X2apInternalSgNBReleaseRequiredIEValuevalidateX2APIEContainer(v.ProtocolIEs, rows, "SgNBReleaseRequired.protocolIEs", budget)
	X2apInternalWalkValidationSgNBReleaseRequired(v, &report, "SgNBReleaseRequired", true)
	return report, nil
}
func X2apInternalValidateTraceStartBudget(v *s19.TraceStart, budget *aper.DecodeBudget,

) (s12.ValidationReport, error) {
	if v == nil {
		return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("nil TraceStart")
	}
	rows := []s06.FieldInfo{s16.TraceStartIEs().MeNBUEX2APID().Info(), s16.TraceStartIEs().SgNBUEX2APID().Info(), s16.TraceStartIEs().TraceActivation().Info(), s16.TraceStartIEs().MeNBUEX2APIDExtension().Info()}
	report := s16.X2apInternalTraceStartIEValuevalidateX2APIEContainer(v.ProtocolIEs, rows, "TraceStart.protocolIEs", budget)
	X2apInternalWalkValidationTraceStart(v, &report, "TraceStart", true)
	return report, nil
}
func X2apInternalValidateUERadioCapabilityIDMappingRequestBudget(v *s19.UERadioCapabilityIDMappingRequest, budget *aper.DecodeBudget,

) (s12.ValidationReport, error) {
	if v == nil {
		return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("nil UERadioCapabilityIDMappingRequest")
	}
	rows := []s06.FieldInfo{s11.UERadioCapabilityIDMappingRequestIEs().UERadioCapabilityID().Info()}
	report := s13.X2apInternalUERadioCapabilityIDMappingRequestIEValuevalidateX2APIEContainer(v.ProtocolIEs, rows, "UERadioCapabilityIDMappingRequest.protocolIEs", budget)
	X2apInternalWalkValidationUERadioCapabilityIDMappingRequest(v, &report, "UERadioCapabilityIDMappingRequest", true)
	return report, nil
}
func X2apInternalValidateUERadioCapabilityIDMappingResponseBudget(v *s18.UERadioCapabilityIDMappingResponse, budget *aper.DecodeBudget,

) (s12.ValidationReport, error) {
	if v == nil {
		return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("nil UERadioCapabilityIDMappingResponse")
	}
	rows := []s06.FieldInfo{s11.UERadioCapabilityIDMappingResponseIEs().UERadioCapabilityID().Info(), s11.UERadioCapabilityIDMappingResponseIEs().UERadioCapability().Info(), s11.UERadioCapabilityIDMappingResponseIEs().CriticalityDiagnostics().Info()}
	report := s13.X2apInternalUERadioCapabilityIDMappingResponseIEValuevalidateX2APIEContainer(v.ProtocolIEs, rows, "UERadioCapabilityIDMappingResponse.protocolIEs", budget)
	X2apInternalWalkValidationUERadioCapabilityIDMappingResponse(v, &report, "UERadioCapabilityIDMappingResponse", true)
	return report, nil
}
func X2apInternalValidateInitiatingMessage(v *s19.InitiatingMessage, budget *aper.DecodeBudget,

) (s12.ValidationReport, error) {
	if v == nil {
		return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("nil InitiatingMessage")
	}
	if *s19.X2apInternalInitiatingValueFieldCode(&v.Value) != v.ProcedureCode {
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "X2AP-PDU-Descriptions", Assignment: "InitiatingMessage"}}}})
			return report
		}(), nil
	}
	switch v.ProcedureCode {
	case 0:
		body, ok := v.Value.AsHandoverRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing HandoverRequest")
		}
		report, err := s19.X2apInternalValidateHandoverRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.HandoverPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 1:
		body, ok := v.Value.AsHandoverCancel()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing HandoverCancel")
		}
		report, err := s19.X2apInternalValidateHandoverCancelBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.HandoverCancelProcedure().Info().Rule}})
		}
		return report, nil
	case 2:
		body, ok := v.Value.AsLoadInformation()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing LoadInformation")
		}
		report, err := s19.X2apInternalValidateLoadInformationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.LoadIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 3:
		body, ok := v.Value.AsErrorIndication()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing ErrorIndication")
		}
		report, err := s19.X2apInternalValidateErrorIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.ErrorIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 4:
		body, ok := v.Value.AsSNStatusTransfer()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SNStatusTransfer")
		}
		report, err := s19.X2apInternalValidateSNStatusTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SnStatusTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 5:
		body, ok := v.Value.AsUEContextRelease()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing UEContextRelease")
		}
		report, err := X2apInternalValidateUEContextReleaseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UEContextReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 6:
		body, ok := v.Value.AsX2SetupRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing X2SetupRequest")
		}
		report, err := X2apInternalValidateX2SetupRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{X2SetupProcedure().Info().Rule}})
		}
		return report, nil
	case 7:
		body, ok := v.Value.AsResetRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing ResetRequest")
		}
		report, err := s19.X2apInternalValidateResetRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.ResetProcedure().Info().Rule}})
		}
		return report, nil
	case 8:
		body, ok := v.Value.AsENBConfigurationUpdate()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing ENBConfigurationUpdate")
		}
		report, err := s19.X2apInternalValidateENBConfigurationUpdateBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.ENBConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 9:
		body, ok := v.Value.AsResourceStatusRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing ResourceStatusRequest")
		}
		report, err := s19.X2apInternalValidateResourceStatusRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.ResourceStatusReportingInitiationProcedure().Info().Rule}})
		}
		return report, nil
	case 10:
		body, ok := v.Value.AsResourceStatusUpdate()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing ResourceStatusUpdate")
		}
		report, err := s19.X2apInternalValidateResourceStatusUpdateBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.ResourceStatusReportingProcedure().Info().Rule}})
		}
		return report, nil
	case 11:
		body, ok := v.Value.AsPrivateMessage()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing PrivateMessage")
		}
		report, err := s19.X2apInternalValidatePrivateMessageBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.PrivateMessageProcedure().Info().Rule}})
		}
		return report, nil
	case 12:
		body, ok := v.Value.AsMobilityChangeRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing MobilityChangeRequest")
		}
		report, err := s19.X2apInternalValidateMobilityChangeRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.MobilitySettingsChangeProcedure().Info().Rule}})
		}
		return report, nil
	case 13:
		body, ok := v.Value.AsRLFIndication()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing RLFIndication")
		}
		report, err := s19.X2apInternalValidateRLFIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.RLFIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 14:
		body, ok := v.Value.AsHandoverReport()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing HandoverReport")
		}
		report, err := s19.X2apInternalValidateHandoverReportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.HandoverReportProcedure().Info().Rule}})
		}
		return report, nil
	case 15:
		body, ok := v.Value.AsCellActivationRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing CellActivationRequest")
		}
		report, err := s19.X2apInternalValidateCellActivationRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.CellActivationProcedure().Info().Rule}})
		}
		return report, nil
	case 16:
		body, ok := v.Value.AsX2Release()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing X2Release")
		}
		report, err := X2apInternalValidateX2ReleaseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{X2ReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 17:
		body, ok := v.Value.AsX2APMessageTransfer()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing X2APMessageTransfer")
		}
		report, err := X2apInternalValidateX2APMessageTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{X2APMessageTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 18:
		body, ok := v.Value.AsX2RemovalRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing X2RemovalRequest")
		}
		report, err := X2apInternalValidateX2RemovalRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{X2RemovalProcedure().Info().Rule}})
		}
		return report, nil
	case 19:
		body, ok := v.Value.AsSeNBAdditionRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SeNBAdditionRequest")
		}
		report, err := s19.X2apInternalValidateSeNBAdditionRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SeNBAdditionPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 20:
		body, ok := v.Value.AsSeNBReconfigurationComplete()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SeNBReconfigurationComplete")
		}
		report, err := s19.X2apInternalValidateSeNBReconfigurationCompleteBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SeNBReconfigurationCompletionProcedure().Info().Rule}})
		}
		return report, nil
	case 21:
		body, ok := v.Value.AsSeNBModificationRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SeNBModificationRequest")
		}
		report, err := s19.X2apInternalValidateSeNBModificationRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.MeNBinitiatedSeNBModificationPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 22:
		body, ok := v.Value.AsSeNBModificationRequired()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SeNBModificationRequired")
		}
		report, err := s19.X2apInternalValidateSeNBModificationRequiredBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SeNBinitiatedSeNBModificationProcedure().Info().Rule}})
		}
		return report, nil
	case 23:
		body, ok := v.Value.AsSeNBReleaseRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SeNBReleaseRequest")
		}
		report, err := s19.X2apInternalValidateSeNBReleaseRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.MeNBinitiatedSeNBReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 24:
		body, ok := v.Value.AsSeNBReleaseRequired()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SeNBReleaseRequired")
		}
		report, err := s19.X2apInternalValidateSeNBReleaseRequiredBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SeNBinitiatedSeNBReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 25:
		body, ok := v.Value.AsSeNBCounterCheckRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SeNBCounterCheckRequest")
		}
		report, err := s19.X2apInternalValidateSeNBCounterCheckRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SeNBCounterCheckProcedure().Info().Rule}})
		}
		return report, nil
	case 26:
		body, ok := v.Value.AsRetrieveUEContextRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing RetrieveUEContextRequest")
		}
		report, err := s19.X2apInternalValidateRetrieveUEContextRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.RetrieveUEContextProcedure().Info().Rule}})
		}
		return report, nil
	case 27:
		body, ok := v.Value.AsSgNBAdditionRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SgNBAdditionRequest")
		}
		report, err := s19.X2apInternalValidateSgNBAdditionRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SgNBAdditionPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 28:
		body, ok := v.Value.AsSgNBReconfigurationComplete()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SgNBReconfigurationComplete")
		}
		report, err := s19.X2apInternalValidateSgNBReconfigurationCompleteBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SgNBReconfigurationCompletionProcedure().Info().Rule}})
		}
		return report, nil
	case 29:
		body, ok := v.Value.AsSgNBModificationRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SgNBModificationRequest")
		}
		report, err := s19.X2apInternalValidateSgNBModificationRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.MeNBinitiatedSgNBModificationPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 30:
		body, ok := v.Value.AsSgNBModificationRequired()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SgNBModificationRequired")
		}
		report, err := s19.X2apInternalValidateSgNBModificationRequiredBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SgNBinitiatedSgNBModificationProcedure().Info().Rule}})
		}
		return report, nil
	case 31:
		body, ok := v.Value.AsSgNBReleaseRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SgNBReleaseRequest")
		}
		report, err := s19.X2apInternalValidateSgNBReleaseRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{MeNBinitiatedSgNBReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 32:
		body, ok := v.Value.AsSgNBReleaseRequired()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SgNBReleaseRequired")
		}
		report, err := X2apInternalValidateSgNBReleaseRequiredBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{SgNBinitiatedSgNBReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 33:
		body, ok := v.Value.AsSgNBCounterCheckRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SgNBCounterCheckRequest")
		}
		report, err := s19.X2apInternalValidateSgNBCounterCheckRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SgNBCounterCheckProcedure().Info().Rule}})
		}
		return report, nil
	case 34:
		body, ok := v.Value.AsSgNBChangeRequired()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SgNBChangeRequired")
		}
		report, err := s19.X2apInternalValidateSgNBChangeRequiredBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SgNBChangeProcedure().Info().Rule}})
		}
		return report, nil
	case 35:
		body, ok := v.Value.AsRRCTransfer()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing RRCTransfer")
		}
		report, err := s19.X2apInternalValidateRRCTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.RRCTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 36:
		body, ok := v.Value.AsENDCX2SetupRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing ENDCX2SetupRequest")
		}
		report, err := s19.X2apInternalValidateENDCX2SetupRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EndcX2SetupProcedure().Info().Rule}})
		}
		return report, nil
	case 37:
		body, ok := v.Value.AsENDCConfigurationUpdate()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing ENDCConfigurationUpdate")
		}
		report, err := s19.X2apInternalValidateENDCConfigurationUpdateBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EndcConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 38:
		body, ok := v.Value.AsSecondaryRATDataUsageReport()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SecondaryRATDataUsageReport")
		}
		report, err := s19.X2apInternalValidateSecondaryRATDataUsageReportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SecondaryRATDataUsageReportProcedure().Info().Rule}})
		}
		return report, nil
	case 39:
		body, ok := v.Value.AsENDCCellActivationRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing ENDCCellActivationRequest")
		}
		report, err := s19.X2apInternalValidateENDCCellActivationRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EndcCellActivationProcedure().Info().Rule}})
		}
		return report, nil
	case 40:
		body, ok := v.Value.AsENDCPartialResetRequired()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing ENDCPartialResetRequired")
		}
		report, err := s19.X2apInternalValidateENDCPartialResetRequiredBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EndcPartialResetProcedure().Info().Rule}})
		}
		return report, nil
	case 41:
		body, ok := v.Value.AsEUTRANRCellResourceCoordinationRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing EUTRANRCellResourceCoordinationRequest")
		}
		report, err := s19.X2apInternalValidateEUTRANRCellResourceCoordinationRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EUTRANRCellResourceCoordinationProcedure().Info().Rule}})
		}
		return report, nil
	case 42:
		body, ok := v.Value.AsSgNBActivityNotification()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SgNBActivityNotification")
		}
		report, err := s19.X2apInternalValidateSgNBActivityNotificationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SgNBActivityNotificationProcedure().Info().Rule}})
		}
		return report, nil
	case 43:
		body, ok := v.Value.AsENDCX2RemovalRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing ENDCX2RemovalRequest")
		}
		report, err := s19.X2apInternalValidateENDCX2RemovalRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EndcX2RemovalProcedure().Info().Rule}})
		}
		return report, nil
	case 44:
		body, ok := v.Value.AsDataForwardingAddressIndication()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing DataForwardingAddressIndication")
		}
		report, err := s19.X2apInternalValidateDataForwardingAddressIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.DataForwardingAddressIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 45:
		body, ok := v.Value.AsGNBStatusIndication()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing GNBStatusIndication")
		}
		report, err := s19.X2apInternalValidateGNBStatusIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.GNBStatusIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 46:
		body, ok := v.Value.AsDeactivateTrace()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing DeactivateTrace")
		}
		report, err := s19.X2apInternalValidateDeactivateTraceBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.DeactivateTraceProcedure().Info().Rule}})
		}
		return report, nil
	case 47:
		body, ok := v.Value.AsTraceStart()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing TraceStart")
		}
		report, err := X2apInternalValidateTraceStartBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{TraceStartProcedure().Info().Rule}})
		}
		return report, nil
	case 48:
		body, ok := v.Value.AsENDCConfigurationTransfer()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing ENDCConfigurationTransfer")
		}
		report, err := s19.X2apInternalValidateENDCConfigurationTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EndcConfigurationTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 49:
		body, ok := v.Value.AsHandoverSuccess()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing HandoverSuccess")
		}
		report, err := s19.X2apInternalValidateHandoverSuccessBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.HandoverSuccessProcedure().Info().Rule}})
		}
		return report, nil
	case 50:
		body, ok := v.Value.AsConditionalHandoverCancel()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing ConditionalHandoverCancel")
		}
		report, err := s19.X2apInternalValidateConditionalHandoverCancelBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.ConditionalHandoverCancelProcedure().Info().Rule}})
		}
		return report, nil
	case 51:
		body, ok := v.Value.AsEarlyStatusTransfer()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing EarlyStatusTransfer")
		}
		report, err := s19.X2apInternalValidateEarlyStatusTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EarlyStatusTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 52:
		body, ok := v.Value.AsCellTrafficTrace()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing CellTrafficTrace")
		}
		report, err := s19.X2apInternalValidateCellTrafficTraceBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.CellTrafficTraceProcedure().Info().Rule}})
		}
		return report, nil
	case 53:
		body, ok := v.Value.AsENDCResourceStatusUpdate()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing ENDCResourceStatusUpdate")
		}
		report, err := s19.X2apInternalValidateENDCResourceStatusUpdateBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EndcresourceStatusReportingProcedure().Info().Rule}})
		}
		return report, nil
	case 54:
		body, ok := v.Value.AsENDCResourceStatusRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing ENDCResourceStatusRequest")
		}
		report, err := s19.X2apInternalValidateENDCResourceStatusRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EndcresourceStatusReportingInitiationProcedure().Info().Rule}})
		}
		return report, nil
	case 55:
		body, ok := v.Value.AsF1CTrafficTransfer()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing F1CTrafficTransfer")
		}
		report, err := s19.X2apInternalValidateF1CTrafficTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.F1CTrafficTransferProcedure().Info().Rule}})
		}
		return report, nil
	case 56:
		body, ok := v.Value.AsUERadioCapabilityIDMappingRequest()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing UERadioCapabilityIDMappingRequest")
		}
		report, err := X2apInternalValidateUERadioCapabilityIDMappingRequestBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UERadioCapabilityIDMappingProcedure().Info().Rule}})
		}
		return report, nil
	case 57:
		body, ok := v.Value.AsAccessAndMobilityIndication()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing AccessAndMobilityIndication")
		}
		report, err := s19.X2apInternalValidateAccessAndMobilityIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.AccessAndMobilityIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 59:
		body, ok := v.Value.AsCPCCancel()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing CPCCancel")
		}
		report, err := s19.X2apInternalValidateCPCCancelBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.CPCCancelProcedure().Info().Rule}})
		}
		return report, nil
	case 60:
		body, ok := v.Value.AsRachIndication()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing RachIndication")
		}
		report, err := s19.X2apInternalValidateRachIndicationBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.RachIndicationProcedure().Info().Rule}})
		}
		return report, nil
	case 61:
		body, ok := v.Value.AsSCGFailureInformationReport()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SCGFailureInformationReport")
		}
		report, err := s19.X2apInternalValidateSCGFailureInformationReportBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.ScgFailureInformationReportProcedure().Info().Rule}})
		}
		return report, nil
	case 62:
		body, ok := v.Value.AsSCGFailureTransfer()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("InitiatingMessage.value: missing SCGFailureTransfer")
		}
		report, err := s19.X2apInternalValidateSCGFailureTransferBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "InitiatingMessage.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.ScgFailureTransferProcedure().Info().Rule}})
		}
		return report, nil
	default:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnknownProcedure, Severity: s00.ValidationSeverityUnrecognized, Location: aper.Location{Path: "InitiatingMessage.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnknownProcedure)})
			s12.X2apInternalValidationReportAddUnchecked(&report, aper.Location{Path: "InitiatingMessage.value"})
			return report
		}(), nil
	}
}
func X2apInternalValidateSuccessfulOutcome(v *s18.SuccessfulOutcome, budget *aper.DecodeBudget,

) (s12.ValidationReport, error) {
	if v == nil {
		return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("nil SuccessfulOutcome")
	}
	if *s18.X2apInternalSuccessfulValueFieldCode(&v.Value) != v.ProcedureCode {
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "X2AP-PDU-Descriptions", Assignment: "SuccessfulOutcome"}}}})
			return report
		}(), nil
	}
	switch v.ProcedureCode {
	case 0:
		body, ok := v.Value.AsHandoverRequestAcknowledge()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing HandoverRequestAcknowledge")
		}
		report, err := s19.X2apInternalValidateHandoverRequestAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.HandoverPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 1:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 2:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 3:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 4:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 5:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 6:
		body, ok := v.Value.AsX2SetupResponse()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing X2SetupResponse")
		}
		report, err := X2apInternalValidateX2SetupResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{X2SetupProcedure().Info().Rule}})
		}
		return report, nil
	case 7:
		body, ok := v.Value.AsResetResponse()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing ResetResponse")
		}
		report, err := s19.X2apInternalValidateResetResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.ResetProcedure().Info().Rule}})
		}
		return report, nil
	case 8:
		body, ok := v.Value.AsENBConfigurationUpdateAcknowledge()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing ENBConfigurationUpdateAcknowledge")
		}
		report, err := s19.X2apInternalValidateENBConfigurationUpdateAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.ENBConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 9:
		body, ok := v.Value.AsResourceStatusResponse()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing ResourceStatusResponse")
		}
		report, err := s19.X2apInternalValidateResourceStatusResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.ResourceStatusReportingInitiationProcedure().Info().Rule}})
		}
		return report, nil
	case 10:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 11:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 12:
		body, ok := v.Value.AsMobilityChangeAcknowledge()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing MobilityChangeAcknowledge")
		}
		report, err := s19.X2apInternalValidateMobilityChangeAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.MobilitySettingsChangeProcedure().Info().Rule}})
		}
		return report, nil
	case 13:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 14:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 15:
		body, ok := v.Value.AsCellActivationResponse()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing CellActivationResponse")
		}
		report, err := s19.X2apInternalValidateCellActivationResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.CellActivationProcedure().Info().Rule}})
		}
		return report, nil
	case 16:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 17:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 18:
		body, ok := v.Value.AsX2RemovalResponse()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing X2RemovalResponse")
		}
		report, err := X2apInternalValidateX2RemovalResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{X2RemovalProcedure().Info().Rule}})
		}
		return report, nil
	case 19:
		body, ok := v.Value.AsSeNBAdditionRequestAcknowledge()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing SeNBAdditionRequestAcknowledge")
		}
		report, err := s19.X2apInternalValidateSeNBAdditionRequestAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SeNBAdditionPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 20:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 21:
		body, ok := v.Value.AsSeNBModificationRequestAcknowledge()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing SeNBModificationRequestAcknowledge")
		}
		report, err := s19.X2apInternalValidateSeNBModificationRequestAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.MeNBinitiatedSeNBModificationPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 22:
		body, ok := v.Value.AsSeNBModificationConfirm()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing SeNBModificationConfirm")
		}
		report, err := s19.X2apInternalValidateSeNBModificationConfirmBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SeNBinitiatedSeNBModificationProcedure().Info().Rule}})
		}
		return report, nil
	case 23:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 24:
		body, ok := v.Value.AsSeNBReleaseConfirm()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing SeNBReleaseConfirm")
		}
		report, err := s19.X2apInternalValidateSeNBReleaseConfirmBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SeNBinitiatedSeNBReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 25:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 26:
		body, ok := v.Value.AsRetrieveUEContextResponse()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing RetrieveUEContextResponse")
		}
		report, err := s19.X2apInternalValidateRetrieveUEContextResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.RetrieveUEContextProcedure().Info().Rule}})
		}
		return report, nil
	case 27:
		body, ok := v.Value.AsSgNBAdditionRequestAcknowledge()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing SgNBAdditionRequestAcknowledge")
		}
		report, err := s19.X2apInternalValidateSgNBAdditionRequestAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SgNBAdditionPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 28:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 29:
		body, ok := v.Value.AsSgNBModificationRequestAcknowledge()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing SgNBModificationRequestAcknowledge")
		}
		report, err := s19.X2apInternalValidateSgNBModificationRequestAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.MeNBinitiatedSgNBModificationPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 30:
		body, ok := v.Value.AsSgNBModificationConfirm()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing SgNBModificationConfirm")
		}
		report, err := s19.X2apInternalValidateSgNBModificationConfirmBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SgNBinitiatedSgNBModificationProcedure().Info().Rule}})
		}
		return report, nil
	case 31:
		body, ok := v.Value.AsSgNBReleaseRequestAcknowledge()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing SgNBReleaseRequestAcknowledge")
		}
		report, err := s19.X2apInternalValidateSgNBReleaseRequestAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{MeNBinitiatedSgNBReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 32:
		body, ok := v.Value.AsSgNBReleaseConfirm()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing SgNBReleaseConfirm")
		}
		report, err := s19.X2apInternalValidateSgNBReleaseConfirmBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{SgNBinitiatedSgNBReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 33:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 34:
		body, ok := v.Value.AsSgNBChangeConfirm()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing SgNBChangeConfirm")
		}
		report, err := s19.X2apInternalValidateSgNBChangeConfirmBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SgNBChangeProcedure().Info().Rule}})
		}
		return report, nil
	case 35:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 36:
		body, ok := v.Value.AsENDCX2SetupResponse()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing ENDCX2SetupResponse")
		}
		report, err := s19.X2apInternalValidateENDCX2SetupResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EndcX2SetupProcedure().Info().Rule}})
		}
		return report, nil
	case 37:
		body, ok := v.Value.AsENDCConfigurationUpdateAcknowledge()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing ENDCConfigurationUpdateAcknowledge")
		}
		report, err := s19.X2apInternalValidateENDCConfigurationUpdateAcknowledgeBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EndcConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 38:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 39:
		body, ok := v.Value.AsENDCCellActivationResponse()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing ENDCCellActivationResponse")
		}
		report, err := s19.X2apInternalValidateENDCCellActivationResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EndcCellActivationProcedure().Info().Rule}})
		}
		return report, nil
	case 40:
		body, ok := v.Value.AsENDCPartialResetConfirm()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing ENDCPartialResetConfirm")
		}
		report, err := s19.X2apInternalValidateENDCPartialResetConfirmBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EndcPartialResetProcedure().Info().Rule}})
		}
		return report, nil
	case 41:
		body, ok := v.Value.AsEUTRANRCellResourceCoordinationResponse()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing EUTRANRCellResourceCoordinationResponse")
		}
		report, err := s19.X2apInternalValidateEUTRANRCellResourceCoordinationResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EUTRANRCellResourceCoordinationProcedure().Info().Rule}})
		}
		return report, nil
	case 42:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 43:
		body, ok := v.Value.AsENDCX2RemovalResponse()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing ENDCX2RemovalResponse")
		}
		report, err := s19.X2apInternalValidateENDCX2RemovalResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EndcX2RemovalProcedure().Info().Rule}})
		}
		return report, nil
	case 44:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 45:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 46:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 47:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 48:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 49:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 50:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 51:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 52:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 53:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 54:
		body, ok := v.Value.AsENDCResourceStatusResponse()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing ENDCResourceStatusResponse")
		}
		report, err := s19.X2apInternalValidateENDCResourceStatusResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EndcresourceStatusReportingInitiationProcedure().Info().Rule}})
		}
		return report, nil
	case 55:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 56:
		body, ok := v.Value.AsUERadioCapabilityIDMappingResponse()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("SuccessfulOutcome.value: missing UERadioCapabilityIDMappingResponse")
		}
		report, err := X2apInternalValidateUERadioCapabilityIDMappingResponseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{UERadioCapabilityIDMappingProcedure().Info().Rule}})
		}
		return report, nil
	case 57:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 59:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 60:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 61:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 62:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	default:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnknownProcedure, Severity: s00.ValidationSeverityUnrecognized, Location: aper.Location{Path: "SuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnknownProcedure)})
			s12.X2apInternalValidationReportAddUnchecked(&report, aper.Location{Path: "SuccessfulOutcome.value"})
			return report
		}(), nil
	}
}
func X2apInternalValidateUnsuccessfulOutcome(v *s14.UnsuccessfulOutcome, budget *aper.DecodeBudget,

) (s12.ValidationReport, error) {
	if v == nil {
		return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("nil UnsuccessfulOutcome")
	}
	if *s14.X2apInternalUnsuccessfulValueFieldCode(&v.Value) != v.ProcedureCode {
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{{Document: "3GPP TS 36.423", Edition: "V19.1.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "X2AP-PDU-Descriptions", Assignment: "UnsuccessfulOutcome"}}}})
			return report
		}(), nil
	}
	switch v.ProcedureCode {
	case 0:
		body, ok := v.Value.AsHandoverPreparationFailure()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing HandoverPreparationFailure")
		}
		report, err := s14.X2apInternalValidateHandoverPreparationFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.HandoverPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 1:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 2:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 3:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 4:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 5:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 6:
		body, ok := v.Value.AsX2SetupFailure()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing X2SetupFailure")
		}
		report, err := s14.X2apInternalValidateX2SetupFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{X2SetupProcedure().Info().Rule}})
		}
		return report, nil
	case 7:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 8:
		body, ok := v.Value.AsENBConfigurationUpdateFailure()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing ENBConfigurationUpdateFailure")
		}
		report, err := s14.X2apInternalValidateENBConfigurationUpdateFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.ENBConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 9:
		body, ok := v.Value.AsResourceStatusFailure()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing ResourceStatusFailure")
		}
		report, err := s14.X2apInternalValidateResourceStatusFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.ResourceStatusReportingInitiationProcedure().Info().Rule}})
		}
		return report, nil
	case 10:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 11:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 12:
		body, ok := v.Value.AsMobilityChangeFailure()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing MobilityChangeFailure")
		}
		report, err := s14.X2apInternalValidateMobilityChangeFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.MobilitySettingsChangeProcedure().Info().Rule}})
		}
		return report, nil
	case 13:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 14:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 15:
		body, ok := v.Value.AsCellActivationFailure()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing CellActivationFailure")
		}
		report, err := s14.X2apInternalValidateCellActivationFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.CellActivationProcedure().Info().Rule}})
		}
		return report, nil
	case 16:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 17:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 18:
		body, ok := v.Value.AsX2RemovalFailure()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing X2RemovalFailure")
		}
		report, err := s14.X2apInternalValidateX2RemovalFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{X2RemovalProcedure().Info().Rule}})
		}
		return report, nil
	case 19:
		body, ok := v.Value.AsSeNBAdditionRequestReject()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing SeNBAdditionRequestReject")
		}
		report, err := s14.X2apInternalValidateSeNBAdditionRequestRejectBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SeNBAdditionPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 20:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 21:
		body, ok := v.Value.AsSeNBModificationRequestReject()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing SeNBModificationRequestReject")
		}
		report, err := s14.X2apInternalValidateSeNBModificationRequestRejectBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.MeNBinitiatedSeNBModificationPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 22:
		body, ok := v.Value.AsSeNBModificationRefuse()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing SeNBModificationRefuse")
		}
		report, err := s14.X2apInternalValidateSeNBModificationRefuseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SeNBinitiatedSeNBModificationProcedure().Info().Rule}})
		}
		return report, nil
	case 23:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 24:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 25:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 26:
		body, ok := v.Value.AsRetrieveUEContextFailure()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing RetrieveUEContextFailure")
		}
		report, err := s14.X2apInternalValidateRetrieveUEContextFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.RetrieveUEContextProcedure().Info().Rule}})
		}
		return report, nil
	case 27:
		body, ok := v.Value.AsSgNBAdditionRequestReject()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing SgNBAdditionRequestReject")
		}
		report, err := s14.X2apInternalValidateSgNBAdditionRequestRejectBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SgNBAdditionPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 28:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 29:
		body, ok := v.Value.AsSgNBModificationRequestReject()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing SgNBModificationRequestReject")
		}
		report, err := s14.X2apInternalValidateSgNBModificationRequestRejectBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.MeNBinitiatedSgNBModificationPreparationProcedure().Info().Rule}})
		}
		return report, nil
	case 30:
		body, ok := v.Value.AsSgNBModificationRefuse()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing SgNBModificationRefuse")
		}
		report, err := s14.X2apInternalValidateSgNBModificationRefuseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SgNBinitiatedSgNBModificationProcedure().Info().Rule}})
		}
		return report, nil
	case 31:
		body, ok := v.Value.AsSgNBReleaseRequestReject()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing SgNBReleaseRequestReject")
		}
		report, err := s14.X2apInternalValidateSgNBReleaseRequestRejectBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityIgnore {
			expected, received := s00.CriticalityIgnore, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{MeNBinitiatedSgNBReleaseProcedure().Info().Rule}})
		}
		return report, nil
	case 32:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 33:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 34:
		body, ok := v.Value.AsSgNBChangeRefuse()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing SgNBChangeRefuse")
		}
		report, err := s14.X2apInternalValidateSgNBChangeRefuseBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.SgNBChangeProcedure().Info().Rule}})
		}
		return report, nil
	case 35:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 36:
		body, ok := v.Value.AsENDCX2SetupFailure()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing ENDCX2SetupFailure")
		}
		report, err := s14.X2apInternalValidateENDCX2SetupFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EndcX2SetupProcedure().Info().Rule}})
		}
		return report, nil
	case 37:
		body, ok := v.Value.AsENDCConfigurationUpdateFailure()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing ENDCConfigurationUpdateFailure")
		}
		report, err := s14.X2apInternalValidateENDCConfigurationUpdateFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EndcConfigurationUpdateProcedure().Info().Rule}})
		}
		return report, nil
	case 38:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 39:
		body, ok := v.Value.AsENDCCellActivationFailure()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing ENDCCellActivationFailure")
		}
		report, err := s14.X2apInternalValidateENDCCellActivationFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EndcCellActivationProcedure().Info().Rule}})
		}
		return report, nil
	case 40:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 41:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 42:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 43:
		body, ok := v.Value.AsENDCX2RemovalFailure()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing ENDCX2RemovalFailure")
		}
		report, err := s14.X2apInternalValidateENDCX2RemovalFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EndcX2RemovalProcedure().Info().Rule}})
		}
		return report, nil
	case 44:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 45:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 46:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 47:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 48:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 49:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 50:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 51:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 52:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 53:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 54:
		body, ok := v.Value.AsENDCResourceStatusFailure()
		if !ok {
			return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("UnsuccessfulOutcome.value: missing ENDCResourceStatusFailure")
		}
		report, err := s14.X2apInternalValidateENDCResourceStatusFailureBudget(body, budget)
		if err != nil {
			return report, err
		}
		if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
			return report, *s12.X2apInternalValidationReportFieldErr(&report)
		}
		if v.Criticality != s00.CriticalityReject {
			expected, received := s00.CriticalityReject, v.Criticality
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.criticality"}, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s00.X2apInternalX2apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s19.EndcresourceStatusReportingInitiationProcedure().Info().Rule}})
		}
		return report, nil
	case 55:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 56:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 57:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 59:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 60:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 61:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	case 62:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnavailableOutcome, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnavailableOutcome), RelatedRules: s00.X2apInternalX2apHandlingRules(s00.UnavailableOutcome)})
			return report
		}(), nil
	default:
		return func() s12.ValidationReport {
			report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
			s12.X2apInternalValidationReportAddIssue(&report, s12.ValidationIssue{Code: s00.UnknownProcedure, Severity: s00.ValidationSeverityUnrecognized, Location: aper.Location{Path: "UnsuccessfulOutcome.procedureCode"}, Rule: s00.X2apInternalX2apValidationRule(s00.UnknownProcedure)})
			s12.X2apInternalValidationReportAddUnchecked(&report, aper.Location{Path: "UnsuccessfulOutcome.value"})
			return report
		}(), nil
	}
}
func X2apInternalValidateMessageBudget(v *s19.X2APPDU, budget *aper.DecodeBudget,

) (s12.ValidationReport, error) {
	if v == nil {
		return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("nil X2APPDU")
	}
	if v.UnknownExtension != nil && v.Choice != 0 {
		return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("X2APPDU: known choice %d and unknown extension are both selected", v.Choice)
	}
	switch v.Choice {
	case s00.X2APPDUChoiceInitiatingMessage:
		return X2apInternalValidateInitiatingMessage(v.InitiatingMessage, budget)
	case s00.X2APPDUChoiceSuccessfulOutcome:
		return X2apInternalValidateSuccessfulOutcome(v.SuccessfulOutcome, budget)
	case s00.X2APPDUChoiceUnsuccessfulOutcome:
		return X2apInternalValidateUnsuccessfulOutcome(v.UnsuccessfulOutcome, budget)
	default:
		if v.UnknownExtension != nil {
			if len(v.UnknownExtension.Contents()) == 0 {
				return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("X2APPDU: unknown extension has empty complete encoding")
			}
			return func() s12.ValidationReport {
				report := s12.X2apInternalConstructT16ValidationReportF8CompleteF6budget(false, budget)
				s12.X2apInternalValidationReportAddUnchecked(&report, aper.Location{Path: "X2APPDU.unknownExtension"})
				return report
			}(), nil
		}
		return s12.X2apInternalConstructT16ValidationReportF6budget(budget), fmt.Errorf("X2APPDU: invalid choice %d", v.Choice)
	}
}
func ValidateUEContextRelease(v *s19.UEContextRelease, options ...aper.ValidationOption) (s12.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s12.ValidationReport{}, aper.OperationError(err, "UEContextRelease")
	}
	report, err := X2apInternalValidateUEContextReleaseBudget(v, budget)
	if err == nil && !s13.X2apInternalValidationHasValueMismatch(report) {
		_, err = s19.X2apInternalUEContextReleaseMarshalAPERBudget(v, budget, false)
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		err = *s12.X2apInternalValidationReportFieldErr(&report)
	}
	*s12.X2apInternalValidationReportFieldBudget(&report) = nil
	*s12.X2apInternalValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UEContextRelease")
}
func ValidateX2SetupRequest(v *s19.X2SetupRequest, options ...aper.ValidationOption) (s12.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s12.ValidationReport{}, aper.OperationError(err, "X2SetupRequest")
	}
	report, err := X2apInternalValidateX2SetupRequestBudget(v, budget)
	if err == nil && !s13.X2apInternalValidationHasValueMismatch(report) {
		_, err = s19.X2apInternalX2SetupRequestMarshalAPERBudget(v, budget, false)
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		err = *s12.X2apInternalValidationReportFieldErr(&report)
	}
	*s12.X2apInternalValidationReportFieldBudget(&report) = nil
	*s12.X2apInternalValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "X2SetupRequest")
}
func ValidateX2SetupResponse(v *s18.X2SetupResponse, options ...aper.ValidationOption) (s12.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s12.ValidationReport{}, aper.OperationError(err, "X2SetupResponse")
	}
	report, err := X2apInternalValidateX2SetupResponseBudget(v, budget)
	if err == nil && !s13.X2apInternalValidationHasValueMismatch(report) {
		_, err = s18.X2apInternalX2SetupResponseMarshalAPERBudget(v, budget, false)
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		err = *s12.X2apInternalValidationReportFieldErr(&report)
	}
	*s12.X2apInternalValidationReportFieldBudget(&report) = nil
	*s12.X2apInternalValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "X2SetupResponse")
}
func ValidateX2Release(v *s19.X2Release, options ...aper.ValidationOption) (s12.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s12.ValidationReport{}, aper.OperationError(err, "X2Release")
	}
	report, err := X2apInternalValidateX2ReleaseBudget(v, budget)
	if err == nil && !s13.X2apInternalValidationHasValueMismatch(report) {
		_, err = s19.X2apInternalX2ReleaseMarshalAPERBudget(v, budget, false)
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		err = *s12.X2apInternalValidationReportFieldErr(&report)
	}
	*s12.X2apInternalValidationReportFieldBudget(&report) = nil
	*s12.X2apInternalValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "X2Release")
}
func ValidateX2APMessageTransfer(v *s19.X2APMessageTransfer, options ...aper.ValidationOption) (s12.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s12.ValidationReport{}, aper.OperationError(err, "X2APMessageTransfer")
	}
	report, err := X2apInternalValidateX2APMessageTransferBudget(v, budget)
	if err == nil && !s13.X2apInternalValidationHasValueMismatch(report) {
		_, err = s19.X2apInternalX2APMessageTransferMarshalAPERBudget(v, budget, false)
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		err = *s12.X2apInternalValidationReportFieldErr(&report)
	}
	*s12.X2apInternalValidationReportFieldBudget(&report) = nil
	*s12.X2apInternalValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "X2APMessageTransfer")
}
func ValidateX2RemovalRequest(v *s19.X2RemovalRequest, options ...aper.ValidationOption) (s12.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s12.ValidationReport{}, aper.OperationError(err, "X2RemovalRequest")
	}
	report, err := X2apInternalValidateX2RemovalRequestBudget(v, budget)
	if err == nil && !s13.X2apInternalValidationHasValueMismatch(report) {
		_, err = s19.X2apInternalX2RemovalRequestMarshalAPERBudget(v, budget, false)
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		err = *s12.X2apInternalValidationReportFieldErr(&report)
	}
	*s12.X2apInternalValidationReportFieldBudget(&report) = nil
	*s12.X2apInternalValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "X2RemovalRequest")
}
func ValidateX2RemovalResponse(v *s18.X2RemovalResponse, options ...aper.ValidationOption) (s12.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s12.ValidationReport{}, aper.OperationError(err, "X2RemovalResponse")
	}
	report, err := X2apInternalValidateX2RemovalResponseBudget(v, budget)
	if err == nil && !s13.X2apInternalValidationHasValueMismatch(report) {
		_, err = s18.X2apInternalX2RemovalResponseMarshalAPERBudget(v, budget, false)
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		err = *s12.X2apInternalValidationReportFieldErr(&report)
	}
	*s12.X2apInternalValidationReportFieldBudget(&report) = nil
	*s12.X2apInternalValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "X2RemovalResponse")
}
func ValidateSgNBReleaseRequestAcknowledge(v *s18.SgNBReleaseRequestAcknowledge, options ...aper.ValidationOption) (s12.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s12.ValidationReport{}, aper.OperationError(err, "SgNBReleaseRequestAcknowledge")
	}
	report, err := s19.X2apInternalValidateSgNBReleaseRequestAcknowledgeBudget(v, budget)
	if err == nil && !s13.X2apInternalValidationHasValueMismatch(report) {
		_, err = s18.X2apInternalSgNBReleaseRequestAcknowledgeMarshalAPERBudget(v, budget, false)
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		err = *s12.X2apInternalValidationReportFieldErr(&report)
	}
	*s12.X2apInternalValidationReportFieldBudget(&report) = nil
	*s12.X2apInternalValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "SgNBReleaseRequestAcknowledge")
}
func ValidateSgNBReleaseRequired(v *s19.SgNBReleaseRequired, options ...aper.ValidationOption) (s12.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s12.ValidationReport{}, aper.OperationError(err, "SgNBReleaseRequired")
	}
	report, err := X2apInternalValidateSgNBReleaseRequiredBudget(v, budget)
	if err == nil && !s13.X2apInternalValidationHasValueMismatch(report) {
		_, err = s19.X2apInternalSgNBReleaseRequiredMarshalAPERBudget(v, budget, false)
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		err = *s12.X2apInternalValidationReportFieldErr(&report)
	}
	*s12.X2apInternalValidationReportFieldBudget(&report) = nil
	*s12.X2apInternalValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "SgNBReleaseRequired")
}
func ValidateTraceStart(v *s19.TraceStart, options ...aper.ValidationOption) (s12.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s12.ValidationReport{}, aper.OperationError(err, "TraceStart")
	}
	report, err := X2apInternalValidateTraceStartBudget(v, budget)
	if err == nil && !s13.X2apInternalValidationHasValueMismatch(report) {
		_, err = s19.X2apInternalTraceStartMarshalAPERBudget(v, budget, false)
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		err = *s12.X2apInternalValidationReportFieldErr(&report)
	}
	*s12.X2apInternalValidationReportFieldBudget(&report) = nil
	*s12.X2apInternalValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "TraceStart")
}
func ValidateUERadioCapabilityIDMappingRequest(v *s19.UERadioCapabilityIDMappingRequest, options ...aper.ValidationOption) (s12.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s12.ValidationReport{}, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
	}
	report, err := X2apInternalValidateUERadioCapabilityIDMappingRequestBudget(v, budget)
	if err == nil && !s13.X2apInternalValidationHasValueMismatch(report) {
		_, err = s19.X2apInternalUERadioCapabilityIDMappingRequestMarshalAPERBudget(v, budget, false)
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		err = *s12.X2apInternalValidationReportFieldErr(&report)
	}
	*s12.X2apInternalValidationReportFieldBudget(&report) = nil
	*s12.X2apInternalValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UERadioCapabilityIDMappingRequest")
}
func ValidateUERadioCapabilityIDMappingResponse(v *s18.UERadioCapabilityIDMappingResponse, options ...aper.ValidationOption) (s12.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s12.ValidationReport{}, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
	}
	report, err := X2apInternalValidateUERadioCapabilityIDMappingResponseBudget(v, budget)
	if err == nil && !s13.X2apInternalValidationHasValueMismatch(report) {
		_, err = s18.X2apInternalUERadioCapabilityIDMappingResponseMarshalAPERBudget(v, budget, false)
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		err = *s12.X2apInternalValidationReportFieldErr(&report)
	}
	*s12.X2apInternalValidationReportFieldBudget(&report) = nil
	*s12.X2apInternalValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "UERadioCapabilityIDMappingResponse")
}
func ValidateMessage(v *s19.X2APPDU, options ...aper.ValidationOption) (s12.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s12.ValidationReport{}, aper.OperationError(err, "Message")
	}
	report, err := X2apInternalValidateMessageBudget(v, budget)
	if err == nil && !s13.X2apInternalValidationHasValueMismatch(report) {
		_, err = s19.X2apInternalX2APPDUMarshalAPERBudget(v, budget, false)
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		err = *s12.X2apInternalValidationReportFieldErr(&report)
	}
	*s12.X2apInternalValidationReportFieldBudget(&report) = nil
	*s12.X2apInternalValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "Message")
}
func X2apInternalValidateX2APExtensionContainer[V X2apInternalProtocolOpenValue[V]](fields ProtocolExtensionContainer[V], rows []s06.FieldInfo, path string, budget *aper.DecodeBudget) s12.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[ProtocolIEField[V]](bb, uint64(len(fields))); err != nil {
		return s12.X2apInternalConstructT16ValidationReportF3errF6budget(err, budget)
	}
	asIE := make(ProtocolIEContainer[V], len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return X2apInternalValidateX2APIEContainer(asIE, rows, path, budget)
}
func X2apInternalWalkValidationSgNBReleaseRequired(v *s19.SgNBReleaseRequired, report *s12.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s12.X2apInternalValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s12.X2apInternalValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s06.FieldInfo{s17.SgNBReleaseRequiredIEs().MeNBUEX2APID().Info(), s17.SgNBReleaseRequiredIEs().SgNBUEX2APID().Info(), s17.SgNBReleaseRequiredIEs().Cause().Info(), s17.SgNBReleaseRequiredIEs().MeNBUEX2APIDExtension().Info(), s17.SgNBReleaseRequiredIEs().ERABsToBeReleasedSgNBRelReqdList().Info(), s17.SgNBReleaseRequiredIEs().SgNBtoMeNBContainer().Info(), s17.SgNBReleaseRequiredIEs().SCGUEHistoryInformation().Info()}
			s13.X2apInternalMergeNestedValidation(report, s17.X2apInternalSgNBReleaseRequiredIEValuevalidateX2APIEContainer(fields, rows, nestedPath, *s12.X2apInternalValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s12.X2apInternalValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(5):
				if value, ok := fields[i].Value.AsCause(); ok {
					s13.X2apInternalWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=5}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(320):
				if value, ok := fields[i].Value.AsERABsToBeReleasedSgNBRelReqdList(); ok {
					s13.X2apInternalWalkValidationERABsToBeReleasedSgNBRelReqdList(value, report, fmt.Sprintf("%s[%d]{id=320}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(415):
				if value, ok := fields[i].Value.AsSCGUEHistoryInformation(); ok {
					s13.X2apInternalWalkValidationSCGUEHistoryInformation(value, report, fmt.Sprintf("%s[%d]{id=415}", nestedPath, i), false)
				}
			}
		}
	}
	if *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
}
func X2apInternalWalkValidationSuccessfulOutcome(v *s18.SuccessfulOutcome, report *s12.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s12.X2apInternalValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s12.X2apInternalValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
	if *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
	if *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
}
func X2apInternalWalkValidationTraceStart(v *s19.TraceStart, report *s12.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s12.X2apInternalValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s12.X2apInternalValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s06.FieldInfo{s16.TraceStartIEs().MeNBUEX2APID().Info(), s16.TraceStartIEs().SgNBUEX2APID().Info(), s16.TraceStartIEs().TraceActivation().Info(), s16.TraceStartIEs().MeNBUEX2APIDExtension().Info()}
			s13.X2apInternalMergeNestedValidation(report, s16.X2apInternalTraceStartIEValuevalidateX2APIEContainer(fields, rows, nestedPath, *s12.X2apInternalValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s12.X2apInternalValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(13):
				if value, ok := fields[i].Value.AsTraceActivation(); ok {
					s16.X2apInternalWalkValidationTraceActivation(value, report, fmt.Sprintf("%s[%d]{id=13}", nestedPath, i), false)
				}
			}
		}
	}
	if *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
}
func X2apInternalWalkValidationUEContextRelease(v *s19.UEContextRelease, report *s12.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s12.X2apInternalValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s12.X2apInternalValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s06.FieldInfo{s12.UEContextReleaseIEs().OldENBUEX2APID().Info(), s12.UEContextReleaseIEs().NewENBUEX2APID().Info(), s12.UEContextReleaseIEs().OldENBUEX2APIDExtension().Info(), s12.UEContextReleaseIEs().NewENBUEX2APIDExtension().Info(), s12.UEContextReleaseIEs().SIPTOBearerDeactivationIndication().Info(), s12.UEContextReleaseIEs().SgNBUEX2APID().Info()}
			s13.X2apInternalMergeNestedValidation(report, s13.X2apInternalUEContextReleaseIEValuevalidateX2APIEContainer(fields, rows, nestedPath, *s12.X2apInternalValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s12.X2apInternalValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
}
func X2apInternalWalkValidationUERadioCapabilityIDMappingRequest(v *s19.UERadioCapabilityIDMappingRequest, report *s12.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s12.X2apInternalValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s12.X2apInternalValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s06.FieldInfo{s11.UERadioCapabilityIDMappingRequestIEs().UERadioCapabilityID().Info()}
			s13.X2apInternalMergeNestedValidation(report, s13.X2apInternalUERadioCapabilityIDMappingRequestIEValuevalidateX2APIEContainer(fields, rows, nestedPath, *s12.X2apInternalValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s12.X2apInternalValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
}
func X2apInternalWalkValidationUERadioCapabilityIDMappingResponse(v *s18.UERadioCapabilityIDMappingResponse, report *s12.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s12.X2apInternalValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s12.X2apInternalValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s06.FieldInfo{s11.UERadioCapabilityIDMappingResponseIEs().UERadioCapabilityID().Info(), s11.UERadioCapabilityIDMappingResponseIEs().UERadioCapability().Info(), s11.UERadioCapabilityIDMappingResponseIEs().CriticalityDiagnostics().Info()}
			s13.X2apInternalMergeNestedValidation(report, s13.X2apInternalUERadioCapabilityIDMappingResponseIEValuevalidateX2APIEContainer(fields, rows, nestedPath, *s12.X2apInternalValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s12.X2apInternalValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(17):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s13.X2apInternalWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=17}", nestedPath, i), false)
				}
			}
		}
	}
	if *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
}
func X2apInternalWalkValidationX2APMessageTransfer(v *s19.X2APMessageTransfer, report *s12.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s12.X2apInternalValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s12.X2apInternalValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s06.FieldInfo{s13.X2APMessageTransferIEs().RNLHeader().Info(), s13.X2APMessageTransferIEs().X2APMessage().Info()}
			s13.X2apInternalMergeNestedValidation(report, s13.X2apInternalX2APMessageTransferIEValuevalidateX2APIEContainer(fields, rows, nestedPath, *s12.X2apInternalValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s12.X2apInternalValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(101):
				if value, ok := fields[i].Value.AsRNLHeader(); ok {
					s13.X2apInternalWalkValidationRNLHeader(value, report, fmt.Sprintf("%s[%d]{id=101}", nestedPath, i), false)
				}
			}
		}
	}
	if *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
}
func X2apInternalWalkValidationX2APPDU(v *s19.X2APPDU, report *s12.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s12.X2apInternalValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s12.X2apInternalValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.X2APPDUChoiceInitiatingMessage && v.InitiatingMessage != nil {
		s19.X2apInternalWalkValidationInitiatingMessage(v.InitiatingMessage, report, path+".initiatingMessage", false)
	}
	if v.Choice == s00.X2APPDUChoiceSuccessfulOutcome && v.SuccessfulOutcome != nil {
		X2apInternalWalkValidationSuccessfulOutcome(v.SuccessfulOutcome, report, path+".successfulOutcome", false)
	}
	if v.Choice == s00.X2APPDUChoiceUnsuccessfulOutcome && v.UnsuccessfulOutcome != nil {
		s14.X2apInternalWalkValidationUnsuccessfulOutcome(v.UnsuccessfulOutcome, report, path+".unsuccessfulOutcome", false)
	}
}
func X2apInternalWalkValidationX2Release(v *s19.X2Release, report *s12.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s12.X2apInternalValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s12.X2apInternalValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s06.FieldInfo{s07.X2ReleaseIEs().GlobalENBID().Info()}
			s13.X2apInternalMergeNestedValidation(report, s13.X2apInternalX2ReleaseIEValuevalidateX2APIEContainer(fields, rows, nestedPath, *s12.X2apInternalValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s12.X2apInternalValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(21):
				if value, ok := fields[i].Value.AsGlobalENBID(); ok {
					s13.X2apInternalWalkValidationGlobalENBID(value, report, fmt.Sprintf("%s[%d]{id=21}", nestedPath, i), false)
				}
			}
		}
	}
	if *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
}
func X2apInternalWalkValidationX2RemovalRequest(v *s19.X2RemovalRequest, report *s12.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s12.X2apInternalValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s12.X2apInternalValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s06.FieldInfo{s13.X2RemovalRequestIEs().GlobalENBID().Info(), s13.X2RemovalRequestIEs().X2RemovalThreshold().Info()}
			s13.X2apInternalMergeNestedValidation(report, s13.X2apInternalX2RemovalRequestIEValuevalidateX2APIEContainer(fields, rows, nestedPath, *s12.X2apInternalValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s12.X2apInternalValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(21):
				if value, ok := fields[i].Value.AsGlobalENBID(); ok {
					s13.X2apInternalWalkValidationGlobalENBID(value, report, fmt.Sprintf("%s[%d]{id=21}", nestedPath, i), false)
				}
			}
		}
	}
	if *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
}
func X2apInternalWalkValidationX2RemovalResponse(v *s18.X2RemovalResponse, report *s12.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s12.X2apInternalValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s12.X2apInternalValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s06.FieldInfo{s07.X2RemovalResponseIEs().GlobalENBID().Info(), s07.X2RemovalResponseIEs().CriticalityDiagnostics().Info()}
			s13.X2apInternalMergeNestedValidation(report, s13.X2apInternalX2RemovalResponseIEValuevalidateX2APIEContainer(fields, rows, nestedPath, *s12.X2apInternalValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s12.X2apInternalValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(21):
				if value, ok := fields[i].Value.AsGlobalENBID(); ok {
					s13.X2apInternalWalkValidationGlobalENBID(value, report, fmt.Sprintf("%s[%d]{id=21}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(17):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s13.X2apInternalWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=17}", nestedPath, i), false)
				}
			}
		}
	}
	if *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
}
func X2apInternalWalkValidationX2SetupRequest(v *s19.X2SetupRequest, report *s12.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s12.X2apInternalValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s12.X2apInternalValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s06.FieldInfo{s17.X2SetupRequestIEs().GlobalENBID().Info(), s17.X2SetupRequestIEs().ServedCells().Info(), s17.X2SetupRequestIEs().GUGroupIDList().Info(), s17.X2SetupRequestIEs().LHNID().Info()}
			s13.X2apInternalMergeNestedValidation(report, s17.X2apInternalX2SetupRequestIEValuevalidateX2APIEContainer(fields, rows, nestedPath, *s12.X2apInternalValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s12.X2apInternalValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(21):
				if value, ok := fields[i].Value.AsGlobalENBID(); ok {
					s13.X2apInternalWalkValidationGlobalENBID(value, report, fmt.Sprintf("%s[%d]{id=21}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(20):
				if value, ok := fields[i].Value.AsServedCells(); ok {
					s17.X2apInternalWalkValidationServedCells(value, report, fmt.Sprintf("%s[%d]{id=20}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(24):
				if value, ok := fields[i].Value.AsGUGroupIDList(); ok {
					s13.X2apInternalWalkValidationGUGroupIDList(value, report, fmt.Sprintf("%s[%d]{id=24}", nestedPath, i), false)
				}
			}
		}
	}
	if *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
}
func X2apInternalWalkValidationX2SetupResponse(v *s18.X2SetupResponse, report *s12.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s12.X2apInternalValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s12.X2apInternalValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s06.FieldInfo{s17.X2SetupResponseIEs().GlobalENBID().Info(), s17.X2SetupResponseIEs().ServedCells().Info(), s17.X2SetupResponseIEs().GUGroupIDList().Info(), s17.X2SetupResponseIEs().CriticalityDiagnostics().Info(), s17.X2SetupResponseIEs().LHNID().Info()}
			s13.X2apInternalMergeNestedValidation(report, s17.X2apInternalX2SetupResponseIEValuevalidateX2APIEContainer(fields, rows, nestedPath, *s12.X2apInternalValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s12.X2apInternalValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(21):
				if value, ok := fields[i].Value.AsGlobalENBID(); ok {
					s13.X2apInternalWalkValidationGlobalENBID(value, report, fmt.Sprintf("%s[%d]{id=21}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(20):
				if value, ok := fields[i].Value.AsServedCells(); ok {
					s17.X2apInternalWalkValidationServedCells(value, report, fmt.Sprintf("%s[%d]{id=20}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(24):
				if value, ok := fields[i].Value.AsGUGroupIDList(); ok {
					s13.X2apInternalWalkValidationGUGroupIDList(value, report, fmt.Sprintf("%s[%d]{id=24}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(17):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					s13.X2apInternalWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=17}", nestedPath, i), false)
				}
			}
		}
	}
	if *s12.X2apInternalValidationReportFieldErr(report) != nil {
		return
	}
}

type X2apInternalAsn1cAPERULHighInterferenceIndicationInfoListValue struct {
	Value s12.ULHighInterferenceIndicationInfo
}

// ULHighInterferenceIndicationInfoComplete carries a complete ULHighInterferenceIndicationInfo encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.4 require new encodings to pad with zero bits.
type ULHighInterferenceIndicationInfoComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s12.ULHighInterferenceIndicationInfo
	perPadding       aper.CompletePadding `json:"-"`
}

func X2apInternalULHighInterferenceIndicationInfoCompleteMarshalAPERLegacy(v *ULHighInterferenceIndicationInfoComplete) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalMarshalAPERULHighInterferenceIndicationInfoTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ULHighInterferenceIndicationInfo from APER format.
func X2apInternalULHighInterferenceIndicationInfoCompleteUnmarshalAPERLegacy(v *ULHighInterferenceIndicationInfoComplete, data []byte) error {
	return X2apInternalULHighInterferenceIndicationInfoCompleteUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}
func X2apInternalULHighInterferenceIndicationInfoCompleteUnmarshalAPERWithOptions(v *ULHighInterferenceIndicationInfoComplete, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ULHighInterferenceIndicationInfo")
	}
	bb.EnterComponent("ULHighInterferenceIndicationInfo")
	value, err := X2apInternalUnmarshalAPERULHighInterferenceIndicationInfoFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ULHighInterferenceIndicationInfo")
	}
	padding, err := aper.CaptureFinalBits(bb, "ULHighInterferenceIndicationInfo")
	if err != nil {
		return runtime.WrapDecodePath(err, "ULHighInterferenceIndicationInfo")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERULHighInterferenceIndicationInfo encodes a ULHighInterferenceIndicationInfo list to APER.
func X2apInternalMarshalAPERULHighInterferenceIndicationInfo(list ULHighInterferenceIndicationInfoComplete) ([]byte, error) {
	return X2apInternalULHighInterferenceIndicationInfoCompleteMarshalAPERLegacy(&list)
}

// MarshalAPERULHighInterferenceIndicationInfoTo appends a ULHighInterferenceIndicationInfo list to bb.
func X2apInternalMarshalAPERULHighInterferenceIndicationInfoTo(list s12.ULHighInterferenceIndicationInfo, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := X2apInternalAsn1cAPERULHighInterferenceIndicationInfoListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s12.X2apInternalULHighInterferenceIndicationInfoItemMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERULHighInterferenceIndicationInfo decodes a ULHighInterferenceIndicationInfo list from APER.
func X2apInternalUnmarshalAPERULHighInterferenceIndicationInfo(data []byte) (ULHighInterferenceIndicationInfoComplete, error) {
	var value ULHighInterferenceIndicationInfoComplete
	if err := X2apInternalULHighInterferenceIndicationInfoCompleteUnmarshalAPERLegacy(&value, data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERULHighInterferenceIndicationInfoFrom decodes a ULHighInterferenceIndicationInfo list from bb.
func X2apInternalUnmarshalAPERULHighInterferenceIndicationInfoFrom(bb *aper.BitBuffer) (s12.ULHighInterferenceIndicationInfo, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v X2apInternalAsn1cAPERULHighInterferenceIndicationInfoListValue
	if err := X2apInternalUnmarshalAPERULHighInterferenceIndicationInfoInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func X2apInternalUnmarshalAPERULHighInterferenceIndicationInfoInto(v *X2apInternalAsn1cAPERULHighInterferenceIndicationInfoListValue, bb *aper.BitBuffer) error {
	v.Value = make(s12.ULHighInterferenceIndicationInfo, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s12.ULHighInterferenceIndicationInfoItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s12.X2apInternalULHighInterferenceIndicationInfoItemUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return errCollection_value
	}
	return nil
}

type X2apInternalAsn1cAPERULInterferenceOverloadIndicationListValue struct {
	Value s12.ULInterferenceOverloadIndication
}

// ULInterferenceOverloadIndicationComplete carries a complete ULInterferenceOverloadIndication encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.4 require new encodings to pad with zero bits.
type ULInterferenceOverloadIndicationComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s12.ULInterferenceOverloadIndication
	perPadding       aper.CompletePadding `json:"-"`
}

func X2apInternalULInterferenceOverloadIndicationCompleteMarshalAPERLegacy(v *ULInterferenceOverloadIndicationComplete) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalMarshalAPERULInterferenceOverloadIndicationTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ULInterferenceOverloadIndication from APER format.
func X2apInternalULInterferenceOverloadIndicationCompleteUnmarshalAPERLegacy(v *ULInterferenceOverloadIndicationComplete, data []byte) error {
	return X2apInternalULInterferenceOverloadIndicationCompleteUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}
func X2apInternalULInterferenceOverloadIndicationCompleteUnmarshalAPERWithOptions(v *ULInterferenceOverloadIndicationComplete, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ULInterferenceOverloadIndication")
	}
	bb.EnterComponent("ULInterferenceOverloadIndication")
	value, err := X2apInternalUnmarshalAPERULInterferenceOverloadIndicationFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ULInterferenceOverloadIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "ULInterferenceOverloadIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "ULInterferenceOverloadIndication")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERULInterferenceOverloadIndication encodes a ULInterferenceOverloadIndication list to APER.
func X2apInternalMarshalAPERULInterferenceOverloadIndication(list ULInterferenceOverloadIndicationComplete) ([]byte, error) {
	return X2apInternalULInterferenceOverloadIndicationCompleteMarshalAPERLegacy(&list)
}

// MarshalAPERULInterferenceOverloadIndicationTo appends a ULInterferenceOverloadIndication list to bb.
func X2apInternalMarshalAPERULInterferenceOverloadIndicationTo(list s12.ULInterferenceOverloadIndication, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := X2apInternalAsn1cAPERULInterferenceOverloadIndicationListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 110, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeEnumeratedAligned(bb, int64(elem), 3, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERULInterferenceOverloadIndication decodes a ULInterferenceOverloadIndication list from APER.
func X2apInternalUnmarshalAPERULInterferenceOverloadIndication(data []byte) (ULInterferenceOverloadIndicationComplete, error) {
	var value ULInterferenceOverloadIndicationComplete
	if err := X2apInternalULInterferenceOverloadIndicationCompleteUnmarshalAPERLegacy(&value, data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERULInterferenceOverloadIndicationFrom decodes a ULInterferenceOverloadIndication list from bb.
func X2apInternalUnmarshalAPERULInterferenceOverloadIndicationFrom(bb *aper.BitBuffer) (s12.ULInterferenceOverloadIndication, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v X2apInternalAsn1cAPERULInterferenceOverloadIndicationListValue
	if err := X2apInternalUnmarshalAPERULInterferenceOverloadIndicationInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func X2apInternalUnmarshalAPERULInterferenceOverloadIndicationInto(v *X2apInternalAsn1cAPERULInterferenceOverloadIndicationListValue, bb *aper.BitBuffer) error {
	v.Value = make(s12.ULInterferenceOverloadIndication, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 110, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_2: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1143
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
			}
			if next, err := aper.AppendValues(bb, v.Value, s00.ULInterferenceOverloadIndicationItem(val)); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return errCollection_value
	}
	return nil
}

type X2apInternalAsn1cAPERWLANMeasConfigNameListListValue struct{ Value s13.WLANMeasConfigNameList }

// WLANMeasConfigNameListComplete carries a complete WLANMeasConfigNameList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.4 require new encodings to pad with zero bits.
type WLANMeasConfigNameListComplete struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	Value            s13.WLANMeasConfigNameList
	perPadding       aper.CompletePadding `json:"-"`
}

func X2apInternalWLANMeasConfigNameListCompleteMarshalAPERLegacy(v *WLANMeasConfigNameListComplete) ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := X2apInternalMarshalAPERWLANMeasConfigNameListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes WLANMeasConfigNameList from APER format.
func X2apInternalWLANMeasConfigNameListCompleteUnmarshalAPERLegacy(v *WLANMeasConfigNameListComplete, data []byte) error {
	return X2apInternalWLANMeasConfigNameListCompleteUnmarshalAPERWithOptions(v, data, aper.DecodeState{})
}
func X2apInternalWLANMeasConfigNameListCompleteUnmarshalAPERWithOptions(v *WLANMeasConfigNameListComplete, data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasConfigNameList")
	}
	bb.EnterComponent("WLANMeasConfigNameList")
	value, err := X2apInternalUnmarshalAPERWLANMeasConfigNameListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasConfigNameList")
	}
	padding, err := aper.CaptureFinalBits(bb, "WLANMeasConfigNameList")
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasConfigNameList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERWLANMeasConfigNameList encodes a WLANMeasConfigNameList list to APER.
func X2apInternalMarshalAPERWLANMeasConfigNameList(list WLANMeasConfigNameListComplete) ([]byte, error) {
	return X2apInternalWLANMeasConfigNameListCompleteMarshalAPERLegacy(&list)
}

// MarshalAPERWLANMeasConfigNameListTo appends a WLANMeasConfigNameList list to bb.
func X2apInternalMarshalAPERWLANMeasConfigNameListTo(list s13.WLANMeasConfigNameList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := X2apInternalAsn1cAPERWLANMeasConfigNameListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := aper.EncodeOctetStringAligned(bb, []byte(elem), 1, 32, true); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERWLANMeasConfigNameList decodes a WLANMeasConfigNameList list from APER.
func X2apInternalUnmarshalAPERWLANMeasConfigNameList(data []byte) (WLANMeasConfigNameListComplete, error) {
	var value WLANMeasConfigNameListComplete
	if err := X2apInternalWLANMeasConfigNameListCompleteUnmarshalAPERLegacy(&value, data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERWLANMeasConfigNameListFrom decodes a WLANMeasConfigNameList list from bb.
func X2apInternalUnmarshalAPERWLANMeasConfigNameListFrom(bb *aper.BitBuffer) (s13.WLANMeasConfigNameList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v X2apInternalAsn1cAPERWLANMeasConfigNameListListValue
	if err := X2apInternalUnmarshalAPERWLANMeasConfigNameListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func X2apInternalUnmarshalAPERWLANMeasConfigNameListInto(v *X2apInternalAsn1cAPERWLANMeasConfigNameListListValue, bb *aper.BitBuffer) error {
	v.Value = make(s13.WLANMeasConfigNameList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 4, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_5: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1176
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := aper.DecodeOctetStringAligned(bb, 1, 32, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
			}
			if next, err := aper.AppendValues(bb, v.Value, val); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return errCollection_value
	}
	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ULHighInterferenceIndicationInfoComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "ULHighInterferenceIndicationInfoComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ULHighInterferenceIndicationInfoComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ULHighInterferenceIndicationInfoComplete) WithoutReplay() ULHighInterferenceIndicationInfoComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ULHighInterferenceIndicationInfoComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ULInterferenceOverloadIndicationComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "ULInterferenceOverloadIndicationComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "ULInterferenceOverloadIndicationComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ULInterferenceOverloadIndicationComplete) WithoutReplay() ULInterferenceOverloadIndicationComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero ULInterferenceOverloadIndicationComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WLANMeasConfigNameListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s00.X2apInternalReceivedFormAt(v.received, v.receivedBytes, "WLANMeasConfigNameListComplete", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "WLANMeasConfigNameListComplete", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WLANMeasConfigNameListComplete) WithoutReplay() WLANMeasConfigNameListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero WLANMeasConfigNameListComplete
	v.perPadding = zero.perPadding
	return v
}

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *ULHighInterferenceIndicationInfoComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ULHighInterferenceIndicationInfoComplete")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ULHighInterferenceIndicationInfoComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APULHighInterferenceIndicationInfoComplete(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "ULHighInterferenceIndicationInfoComplete")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "ULHighInterferenceIndicationInfoComplete")
		}
		return X2apInternalULHighInterferenceIndicationInfoCompleteMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalULHighInterferenceIndicationInfoCompleteMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalULHighInterferenceIndicationInfoCompleteMarshalAPERWithPlan(v *ULHighInterferenceIndicationInfoComplete, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalULHighInterferenceIndicationInfoCompleteMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ULHighInterferenceIndicationInfoComplete")
}
func X2apInternalULHighInterferenceIndicationInfoCompleteMarshalAPERUnplanned(v *ULHighInterferenceIndicationInfoComplete, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalULHighInterferenceIndicationInfoCompleteMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ULHighInterferenceIndicationInfoComplete")
}
func X2apInternalULHighInterferenceIndicationInfoCompleteMarshalAPERBudget(v *ULHighInterferenceIndicationInfoComplete, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APULHighInterferenceIndicationInfoComplete(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalULHighInterferenceIndicationInfoCompleteMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalULHighInterferenceIndicationInfoCompleteMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalULHighInterferenceIndicationInfoCompleteMarshalAPERChanged(v *ULHighInterferenceIndicationInfoComplete, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalULHighInterferenceIndicationInfoCompleteMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalULHighInterferenceIndicationInfoCompleteMarshalAPERPlanned(v *ULHighInterferenceIndicationInfoComplete, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalMarshalAPERULHighInterferenceIndicationInfoTo(value.Value, bb, fresh); err != nil {
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

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *ULInterferenceOverloadIndicationComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ULInterferenceOverloadIndicationComplete")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "ULInterferenceOverloadIndicationComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APULInterferenceOverloadIndicationComplete(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "ULInterferenceOverloadIndicationComplete")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "ULInterferenceOverloadIndicationComplete")
		}
		return X2apInternalULInterferenceOverloadIndicationCompleteMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalULInterferenceOverloadIndicationCompleteMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalULInterferenceOverloadIndicationCompleteMarshalAPERWithPlan(v *ULInterferenceOverloadIndicationComplete, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalULInterferenceOverloadIndicationCompleteMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ULInterferenceOverloadIndicationComplete")
}
func X2apInternalULInterferenceOverloadIndicationCompleteMarshalAPERUnplanned(v *ULInterferenceOverloadIndicationComplete, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalULInterferenceOverloadIndicationCompleteMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "ULInterferenceOverloadIndicationComplete")
}
func X2apInternalULInterferenceOverloadIndicationCompleteMarshalAPERBudget(v *ULInterferenceOverloadIndicationComplete, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APULInterferenceOverloadIndicationComplete(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalULInterferenceOverloadIndicationCompleteMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalULInterferenceOverloadIndicationCompleteMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalULInterferenceOverloadIndicationCompleteMarshalAPERChanged(v *ULInterferenceOverloadIndicationComplete, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalULInterferenceOverloadIndicationCompleteMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalULInterferenceOverloadIndicationCompleteMarshalAPERPlanned(v *ULInterferenceOverloadIndicationComplete, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalMarshalAPERULInterferenceOverloadIndicationTo(value.Value, bb, fresh); err != nil {
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

// MarshalAPER encodes a complete value using one per-call semantic plan.
func (v *WLANMeasConfigNameListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "WLANMeasConfigNameListComplete")
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "WLANMeasConfigNameListComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		X2apInternalCompareX2APWLANMeasConfigNameListComplete(v, &s)
		plan := s.Plan()
		if err := plan.Error(); err != nil {
			return nil, aper.OperationError(err, "WLANMeasConfigNameListComplete")
		}
		if plan.Unchanged(v.replay) && v.received {
			out, err := v.receivedBytes.EncodePlanBytes(plan)
			return out, aper.OperationError(err, "WLANMeasConfigNameListComplete")
		}
		return X2apInternalWLANMeasConfigNameListCompleteMarshalAPERWithPlan(v, fresh, plan)
	}
	return X2apInternalWLANMeasConfigNameListCompleteMarshalAPERUnplanned(v, fresh, budget)
}
func X2apInternalWLANMeasConfigNameListCompleteMarshalAPERWithPlan(v *WLANMeasConfigNameListComplete, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	budget := plan.EncodingBudget()
	bb := aper.NewBudgetBuffer(&budget)
	bb.SetReplayPlan(&plan)
	out, err := X2apInternalWLANMeasConfigNameListCompleteMarshalAPERPlanned(v, &budget, fresh)
	if failure := bb.CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "WLANMeasConfigNameListComplete")
}
func X2apInternalWLANMeasConfigNameListCompleteMarshalAPERUnplanned(v *WLANMeasConfigNameListComplete, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := X2apInternalWLANMeasConfigNameListCompleteMarshalAPERPlanned(v, &budget, fresh)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(uint64(len(out))); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, "WLANMeasConfigNameListComplete")
}
func X2apInternalWLANMeasConfigNameListCompleteMarshalAPERBudget(v *WLANMeasConfigNameListComplete, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		X2apInternalCompareX2APWLANMeasConfigNameListComplete(v, &s)
		decisions := s.Plan()
		if err := decisions.CommitBudget(budget); err != nil {
			return nil, err
		}
		if decisions.Unchanged(v.replay) && v.received {
			return v.receivedBytes.EncodeBytes(budget)
		}
		return X2apInternalWLANMeasConfigNameListCompleteMarshalAPERChanged(v, budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return v.receivedBytes.EncodeBytes(budget)
	}
	return X2apInternalWLANMeasConfigNameListCompleteMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalWLANMeasConfigNameListCompleteMarshalAPERChanged(v *WLANMeasConfigNameListComplete, budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	previous := bb.ReplayPlan()
	bb.SetReplayPlan(&plan)
	defer bb.SetReplayPlan(previous)
	return X2apInternalWLANMeasConfigNameListCompleteMarshalAPERPlanned(v, budget, fresh)
}
func X2apInternalWLANMeasConfigNameListCompleteMarshalAPERPlanned(v *WLANMeasConfigNameListComplete, budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := X2apInternalMarshalAPERWLANMeasConfigNameListTo(value.Value, bb, fresh); err != nil {
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
func (v *ULHighInterferenceIndicationInfoComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ULHighInterferenceIndicationInfoComplete")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded ULHighInterferenceIndicationInfoComplete
	err := X2apInternalULHighInterferenceIndicationInfoCompleteUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APULHighInterferenceIndicationInfoComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ULHighInterferenceIndicationInfoComplete{}
		return report, aper.OperationError(err, "ULHighInterferenceIndicationInfoComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ULHighInterferenceIndicationInfoComplete")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *ULInterferenceOverloadIndicationComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ULInterferenceOverloadIndicationComplete")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded ULInterferenceOverloadIndicationComplete
	err := X2apInternalULInterferenceOverloadIndicationCompleteUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APULInterferenceOverloadIndicationComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ULInterferenceOverloadIndicationComplete{}
		return report, aper.OperationError(err, "ULInterferenceOverloadIndicationComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ULInterferenceOverloadIndicationComplete")
}

// UnmarshalAPER decodes atomically into one immutable wire owner.
func (v *WLANMeasConfigNameListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "WLANMeasConfigNameListComplete")
	}
	data, settings := aper.OwnDecodeOptions(data, options...)
	var decoded WLANMeasConfigNameListComplete
	err := X2apInternalWLANMeasConfigNameListCompleteUnmarshalAPERWithOptions(&decoded, data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		X2apInternalCaptureX2APWLANMeasConfigNameListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = WLANMeasConfigNameListComplete{}
		return report, aper.OperationError(err, "WLANMeasConfigNameListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "WLANMeasConfigNameListComplete")
}

// MarshalAPERULHighInterferenceIndicationInfo encodes a complete named list.
func MarshalAPERULHighInterferenceIndicationInfo(v ULHighInterferenceIndicationInfoComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERULInterferenceOverloadIndication encodes a complete named list.
func MarshalAPERULInterferenceOverloadIndication(v ULInterferenceOverloadIndicationComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERWLANMeasConfigNameList encodes a complete named list.
func MarshalAPERWLANMeasConfigNameList(v WLANMeasConfigNameListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERULHighInterferenceIndicationInfo decodes a complete named list.
func UnmarshalAPERULHighInterferenceIndicationInfo(data []byte, options ...aper.DecodeOption) (ULHighInterferenceIndicationInfoComplete, aper.DecodeReport, error) {
	var v ULHighInterferenceIndicationInfoComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERULInterferenceOverloadIndication decodes a complete named list.
func UnmarshalAPERULInterferenceOverloadIndication(data []byte, options ...aper.DecodeOption) (ULInterferenceOverloadIndicationComplete, aper.DecodeReport, error) {
	var v ULInterferenceOverloadIndicationComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERWLANMeasConfigNameList decodes a complete named list.
func UnmarshalAPERWLANMeasConfigNameList(data []byte, options ...aper.DecodeOption) (WLANMeasConfigNameListComplete, aper.DecodeReport, error) {
	var v WLANMeasConfigNameListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// NewX2APPDUInitiatingMessage constructs and validates a complete X2AP message.
func NewX2APPDUInitiatingMessage(v s19.InitiatingMessage, options ...aper.BuildOption) (s19.X2APPDU, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.X2APPDU{}, aper.OperationError(err, "X2APPDUInitiatingMessage")
	}
	value := s19.X2apInternalNewX2APPDUInitiatingMessageLegacy(v)
	report, err := X2apInternalValidateMessageBudget(&value, budget)
	if err != nil {
		return s19.X2APPDU{}, aper.OperationError(err, "X2APPDUInitiatingMessage")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s19.X2APPDU{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "X2APPDUInitiatingMessage")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s19.X2APPDU{}, aper.OperationError(&s12.BuildError{Issues: issues}, "X2APPDUInitiatingMessage")
	}
	if _, err := s19.X2apInternalX2APPDUMarshalAPERBudget((&value), budget, false); err != nil {
		return s19.X2APPDU{}, aper.OperationError(err, "X2APPDUInitiatingMessage")
	}
	return value, aper.OperationError(nil, "X2APPDUInitiatingMessage")
}

// NewX2APPDUSuccessfulOutcome constructs and validates a complete X2AP message.
func NewX2APPDUSuccessfulOutcome(v s18.SuccessfulOutcome, options ...aper.BuildOption) (s19.X2APPDU, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.X2APPDU{}, aper.OperationError(err, "X2APPDUSuccessfulOutcome")
	}
	value := s19.X2apInternalNewX2APPDUSuccessfulOutcomeLegacy(v)
	report, err := X2apInternalValidateMessageBudget(&value, budget)
	if err != nil {
		return s19.X2APPDU{}, aper.OperationError(err, "X2APPDUSuccessfulOutcome")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s19.X2APPDU{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "X2APPDUSuccessfulOutcome")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s19.X2APPDU{}, aper.OperationError(&s12.BuildError{Issues: issues}, "X2APPDUSuccessfulOutcome")
	}
	if _, err := s19.X2apInternalX2APPDUMarshalAPERBudget((&value), budget, false); err != nil {
		return s19.X2APPDU{}, aper.OperationError(err, "X2APPDUSuccessfulOutcome")
	}
	return value, aper.OperationError(nil, "X2APPDUSuccessfulOutcome")
}

// NewX2APPDUUnsuccessfulOutcome constructs and validates a complete X2AP message.
func NewX2APPDUUnsuccessfulOutcome(v s14.UnsuccessfulOutcome, options ...aper.BuildOption) (s19.X2APPDU, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s19.X2APPDU{}, aper.OperationError(err, "X2APPDUUnsuccessfulOutcome")
	}
	value := s19.X2apInternalNewX2APPDUUnsuccessfulOutcomeLegacy(v)
	report, err := X2apInternalValidateMessageBudget(&value, budget)
	if err != nil {
		return s19.X2APPDU{}, aper.OperationError(err, "X2APPDUUnsuccessfulOutcome")
	}
	if *s12.X2apInternalValidationReportFieldErr(&report) != nil {
		return s19.X2APPDU{}, aper.OperationError(*s12.X2apInternalValidationReportFieldErr(&report), "X2APPDUUnsuccessfulOutcome")
	}
	if issues := s12.X2apInternalBuildBlockingIssues(report); len(issues) != 0 {
		return s19.X2APPDU{}, aper.OperationError(&s12.BuildError{Issues: issues}, "X2APPDUUnsuccessfulOutcome")
	}
	if _, err := s19.X2apInternalX2APPDUMarshalAPERBudget((&value), budget, false); err != nil {
		return s19.X2APPDU{}, aper.OperationError(err, "X2APPDUUnsuccessfulOutcome")
	}
	return value, aper.OperationError(nil, "X2APPDUUnsuccessfulOutcome")
}
