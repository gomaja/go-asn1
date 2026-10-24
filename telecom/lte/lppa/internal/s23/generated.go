// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s23 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s23

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s12"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s13"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s14"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s16"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s17"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s18"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s19"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s20"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s22"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

type APERValue[T any] struct {
	context       s00.BridgeCodecContext
	Value         T
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v APERValue[T]) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v APERValue[T]) WithoutReplay() APERValue[T] {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ValueCodec binds one source value type to its complete APER encoding.
type ValueCodec[T any] struct {
	context s00.BridgeCodecContext
	capture func(T, aper.DecodeState) (T, aper.Snapshot)
	compare func(T, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan
	path    aper.Path
	decode  func([]byte, aper.DecodeState) (T, error)
	encode  func(T, bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
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

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ValueCodec[T]) DecodeAPER(data []byte, options ...aper.DecodeOption) (APERValue[T], aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return APERValue[T]{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return APERValue[T]{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return APERValue[T]{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return APERValue[T]{}, report, aper.OperationError(err, c.path)
	}
	return APERValue[T]{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ValueCodec[T]) EncodeAPER(value APERValue[T], options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, aper.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, aper.OperationError(err, c.path)
}
func (c ValueCodec[T]) encodeBudget(value T, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ValueCodec[T]) encodeChanged(value T, fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

type IEBinding[T any, V ProtocolOpenValueConstraint[V]] struct {
	info   s00.FieldInfo
	codec  ValueCodec[T]
	inject func(T) V
	get    func(*V) (*T, bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b IEBinding[T, V]) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b IEBinding[T, V]) Codec() ValueCodec[T] { return b.codec }

// New validates value and constructs a field with this binding's identifier and criticality.
func (b IEBinding[T, V]) New(value T) (ProtocolIEField[V], error) {
	if b.inject == nil {
		return ProtocolIEField[V]{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ProtocolIEField[V]{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ProtocolIEField[V]{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ProtocolIEField[V]{}, aper.OperationError(err, "Value.New")
	}
	return ProtocolIEField[V]{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b IEBinding[T, V]) Get(field *ProtocolIEField[V]) (*T, bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

type ExtensionBinding[T any, V ProtocolOpenValueConstraint[V]] struct {
	info   s00.FieldInfo
	codec  ValueCodec[T]
	inject func(T) V
	get    func(*V) (*T, bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ExtensionBinding[T, V]) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ExtensionBinding[T, V]) Codec() ValueCodec[T] { return b.codec }

// New validates value and constructs a field with this binding's identifier and criticality.
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

// Get returns the selected typed value when the field belongs to this binding.
func (b ExtensionBinding[T, V]) Get(field *ProtocolExtensionField[V]) (*T, bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

type InitiatingBinding[T any] struct {
	context  s00.BridgeCodecContext
	capture  func(T, aper.DecodeState) (T, aper.Snapshot)
	compare  func(T, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*T, *aper.DecodeBudget) (s09.ValidationReport, error)
	encode   func(*T, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (T, error)
	inject   func(T) s21.InitiatingValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b InitiatingBinding[T]) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b InitiatingBinding[T]) Codec() ValueCodec[T] {
	return ValueCodec[T]{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value T, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b InitiatingBinding[T]) Build(body T, transactionID s00.LPPATransactionID, options ...aper.BuildOption) (s21.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return s21.InitiatingMessage{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s21.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return s21.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s21.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s21.InitiatingMessage{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s21.InitiatingMessage{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s21.InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s21.InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return s21.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

type SuccessfulBinding[T any] struct {
	context  s00.BridgeCodecContext
	capture  func(T, aper.DecodeState) (T, aper.Snapshot)
	compare  func(T, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*T, *aper.DecodeBudget) (s09.ValidationReport, error)
	encode   func(*T, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (T, error)
	inject   func(T) s22.SuccessfulValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b SuccessfulBinding[T]) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b SuccessfulBinding[T]) Codec() ValueCodec[T] {
	return ValueCodec[T]{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value T, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b SuccessfulBinding[T]) Build(body T, transactionID s00.LPPATransactionID, options ...aper.BuildOption) (s22.SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s22.SuccessfulOutcome{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return s22.SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

type UnsuccessfulBinding[T any] struct {
	context  s00.BridgeCodecContext
	capture  func(T, aper.DecodeState) (T, aper.Snapshot)
	compare  func(T, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*T, *aper.DecodeBudget) (s09.ValidationReport, error)
	encode   func(*T, bool, *aper.DecodeBudget) ([]byte, error)
	decode   func([]byte, aper.DecodeState) (T, error)
	inject   func(T) s16.UnsuccessfulValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b UnsuccessfulBinding[T]) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b UnsuccessfulBinding[T]) Codec() ValueCodec[T] {
	return ValueCodec[T]{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value T, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b UnsuccessfulBinding[T]) Build(body T, transactionID s00.LPPATransactionID, options ...aper.BuildOption) (s16.UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return s16.UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s16.UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return s16.UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s16.UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s16.UnsuccessfulOutcome{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s16.UnsuccessfulOutcome{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s16.UnsuccessfulOutcome{}, aper.OperationError(fmt.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s16.UnsuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return s16.UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}
func NewErrorIndication(fields s10.ErrorIndicationIEContainer, options ...aper.BuildOption) (s11.ErrorIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s11.ErrorIndication{}, aper.OperationError(err, "ErrorIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s10.ErrorIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s11.ErrorIndication{}, aper.OperationError(err, "ErrorIndication")
	}
	v := s11.ErrorIndication{ProtocolIEs: make(s10.ErrorIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateErrorIndicationBudget(&v, budget)
	if err != nil {
		return s11.ErrorIndication{}, aper.OperationError(err, "ErrorIndication")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s11.ErrorIndication{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "ErrorIndication")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s11.ErrorIndication{}, aper.OperationError(&s09.BuildError{Issues: issues}, "ErrorIndication")
	}
	if _, err := s11.BridgeErrorIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s11.ErrorIndication{}, aper.OperationError(fmt.Errorf("%s %w", "ErrorIndication.protocolIEs:", err), "ErrorIndication")
	}
	return v, aper.OperationError(nil, "ErrorIndication")
}
func NewECIDMeasurementInitiationFailure(fields s09.ECIDMeasurementInitiationFailureIEContainer, options ...aper.BuildOption) (s11.ECIDMeasurementInitiationFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s11.ECIDMeasurementInitiationFailure{}, aper.OperationError(err, "ECIDMeasurementInitiationFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s09.ECIDMeasurementInitiationFailureIEField](bb, uint64(len(fields))); err != nil {
		return s11.ECIDMeasurementInitiationFailure{}, aper.OperationError(err, "ECIDMeasurementInitiationFailure")
	}
	v := s11.ECIDMeasurementInitiationFailure{ProtocolIEs: make(s09.ECIDMeasurementInitiationFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateECIDMeasurementInitiationFailureBudget(&v, budget)
	if err != nil {
		return s11.ECIDMeasurementInitiationFailure{}, aper.OperationError(err, "ECIDMeasurementInitiationFailure")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s11.ECIDMeasurementInitiationFailure{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "ECIDMeasurementInitiationFailure")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s11.ECIDMeasurementInitiationFailure{}, aper.OperationError(&s09.BuildError{Issues: issues}, "ECIDMeasurementInitiationFailure")
	}
	if _, err := s11.BridgeECIDMeasurementInitiationFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s11.ECIDMeasurementInitiationFailure{}, aper.OperationError(fmt.Errorf("%s %w", "ECIDMeasurementInitiationFailure.protocolIEs:", err), "ECIDMeasurementInitiationFailure")
	}
	return v, aper.OperationError(nil, "ECIDMeasurementInitiationFailure")
}
func NewECIDMeasurementFailureIndication(fields s06.ECIDMeasurementFailureIndicationIEContainer, options ...aper.BuildOption) (s11.ECIDMeasurementFailureIndication, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s11.ECIDMeasurementFailureIndication{}, aper.OperationError(err, "ECIDMeasurementFailureIndication")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s06.ECIDMeasurementFailureIndicationIEField](bb, uint64(len(fields))); err != nil {
		return s11.ECIDMeasurementFailureIndication{}, aper.OperationError(err, "ECIDMeasurementFailureIndication")
	}
	v := s11.ECIDMeasurementFailureIndication{ProtocolIEs: make(s06.ECIDMeasurementFailureIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateECIDMeasurementFailureIndicationBudget(&v, budget)
	if err != nil {
		return s11.ECIDMeasurementFailureIndication{}, aper.OperationError(err, "ECIDMeasurementFailureIndication")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s11.ECIDMeasurementFailureIndication{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "ECIDMeasurementFailureIndication")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s11.ECIDMeasurementFailureIndication{}, aper.OperationError(&s09.BuildError{Issues: issues}, "ECIDMeasurementFailureIndication")
	}
	if _, err := s11.BridgeECIDMeasurementFailureIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s11.ECIDMeasurementFailureIndication{}, aper.OperationError(fmt.Errorf("%s %w", "ECIDMeasurementFailureIndication.protocolIEs:", err), "ECIDMeasurementFailureIndication")
	}
	return v, aper.OperationError(nil, "ECIDMeasurementFailureIndication")
}
func NewECIDMeasurementReport(fields s13.ECIDMeasurementReportIEContainer, options ...aper.BuildOption) (s13.ECIDMeasurementReport, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s13.ECIDMeasurementReport{}, aper.OperationError(err, "ECIDMeasurementReport")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s13.ECIDMeasurementReportIEField](bb, uint64(len(fields))); err != nil {
		return s13.ECIDMeasurementReport{}, aper.OperationError(err, "ECIDMeasurementReport")
	}
	v := s13.ECIDMeasurementReport{ProtocolIEs: make(s13.ECIDMeasurementReportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateECIDMeasurementReportBudget(&v, budget)
	if err != nil {
		return s13.ECIDMeasurementReport{}, aper.OperationError(err, "ECIDMeasurementReport")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s13.ECIDMeasurementReport{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "ECIDMeasurementReport")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s13.ECIDMeasurementReport{}, aper.OperationError(&s09.BuildError{Issues: issues}, "ECIDMeasurementReport")
	}
	if _, err := s13.BridgeECIDMeasurementReportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s13.ECIDMeasurementReport{}, aper.OperationError(fmt.Errorf("%s %w", "ECIDMeasurementReport.protocolIEs:", err), "ECIDMeasurementReport")
	}
	return v, aper.OperationError(nil, "ECIDMeasurementReport")
}
func NewECIDMeasurementTerminationCommand(fields s03.ECIDMeasurementTerminationCommandIEContainer, options ...aper.BuildOption) (s06.ECIDMeasurementTerminationCommand, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s06.ECIDMeasurementTerminationCommand{}, aper.OperationError(err, "ECIDMeasurementTerminationCommand")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s03.ECIDMeasurementTerminationCommandIEField](bb, uint64(len(fields))); err != nil {
		return s06.ECIDMeasurementTerminationCommand{}, aper.OperationError(err, "ECIDMeasurementTerminationCommand")
	}
	v := s06.ECIDMeasurementTerminationCommand{ProtocolIEs: make(s03.ECIDMeasurementTerminationCommandIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateECIDMeasurementTerminationCommandBudget(&v, budget)
	if err != nil {
		return s06.ECIDMeasurementTerminationCommand{}, aper.OperationError(err, "ECIDMeasurementTerminationCommand")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s06.ECIDMeasurementTerminationCommand{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "ECIDMeasurementTerminationCommand")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s06.ECIDMeasurementTerminationCommand{}, aper.OperationError(&s09.BuildError{Issues: issues}, "ECIDMeasurementTerminationCommand")
	}
	if _, err := s06.BridgeECIDMeasurementTerminationCommandMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s06.ECIDMeasurementTerminationCommand{}, aper.OperationError(fmt.Errorf("%s %w", "ECIDMeasurementTerminationCommand.protocolIEs:", err), "ECIDMeasurementTerminationCommand")
	}
	return v, aper.OperationError(nil, "ECIDMeasurementTerminationCommand")
}
func NewOTDOAInformationRequest(fields s18.OTDOAInformationRequestIEContainer, options ...aper.BuildOption) (s18.OTDOAInformationRequest, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s18.OTDOAInformationRequest{}, aper.OperationError(err, "OTDOAInformationRequest")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s18.OTDOAInformationRequestIEField](bb, uint64(len(fields))); err != nil {
		return s18.OTDOAInformationRequest{}, aper.OperationError(err, "OTDOAInformationRequest")
	}
	v := s18.OTDOAInformationRequest{ProtocolIEs: make(s18.OTDOAInformationRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateOTDOAInformationRequestBudget(&v, budget)
	if err != nil {
		return s18.OTDOAInformationRequest{}, aper.OperationError(err, "OTDOAInformationRequest")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s18.OTDOAInformationRequest{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "OTDOAInformationRequest")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s18.OTDOAInformationRequest{}, aper.OperationError(&s09.BuildError{Issues: issues}, "OTDOAInformationRequest")
	}
	if _, err := s18.BridgeOTDOAInformationRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s18.OTDOAInformationRequest{}, aper.OperationError(fmt.Errorf("%s %w", "OTDOAInformationRequest.protocolIEs:", err), "OTDOAInformationRequest")
	}
	return v, aper.OperationError(nil, "OTDOAInformationRequest")
}
func NewOTDOAInformationFailure(fields s10.OTDOAInformationFailureIEContainer, options ...aper.BuildOption) (s12.OTDOAInformationFailure, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s12.OTDOAInformationFailure{}, aper.OperationError(err, "OTDOAInformationFailure")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s10.OTDOAInformationFailureIEField](bb, uint64(len(fields))); err != nil {
		return s12.OTDOAInformationFailure{}, aper.OperationError(err, "OTDOAInformationFailure")
	}
	v := s12.OTDOAInformationFailure{ProtocolIEs: make(s10.OTDOAInformationFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateOTDOAInformationFailureBudget(&v, budget)
	if err != nil {
		return s12.OTDOAInformationFailure{}, aper.OperationError(err, "OTDOAInformationFailure")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s12.OTDOAInformationFailure{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "OTDOAInformationFailure")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s12.OTDOAInformationFailure{}, aper.OperationError(&s09.BuildError{Issues: issues}, "OTDOAInformationFailure")
	}
	if _, err := s12.BridgeOTDOAInformationFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s12.OTDOAInformationFailure{}, aper.OperationError(fmt.Errorf("%s %w", "OTDOAInformationFailure.protocolIEs:", err), "OTDOAInformationFailure")
	}
	return v, aper.OperationError(nil, "OTDOAInformationFailure")
}
func NewAssistanceInformationFeedback(fields s17.AssistanceInformationFeedbackIEContainer, options ...aper.BuildOption) (s17.AssistanceInformationFeedback, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s17.AssistanceInformationFeedback{}, aper.OperationError(err, "AssistanceInformationFeedback")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s17.AssistanceInformationFeedbackIEField](bb, uint64(len(fields))); err != nil {
		return s17.AssistanceInformationFeedback{}, aper.OperationError(err, "AssistanceInformationFeedback")
	}
	v := s17.AssistanceInformationFeedback{ProtocolIEs: make(s17.AssistanceInformationFeedbackIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateAssistanceInformationFeedbackBudget(&v, budget)
	if err != nil {
		return s17.AssistanceInformationFeedback{}, aper.OperationError(err, "AssistanceInformationFeedback")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s17.AssistanceInformationFeedback{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "AssistanceInformationFeedback")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s17.AssistanceInformationFeedback{}, aper.OperationError(&s09.BuildError{Issues: issues}, "AssistanceInformationFeedback")
	}
	if _, err := s17.BridgeAssistanceInformationFeedbackMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s17.AssistanceInformationFeedback{}, aper.OperationError(fmt.Errorf("%s %w", "AssistanceInformationFeedback.protocolIEs:", err), "AssistanceInformationFeedback")
	}
	return v, aper.OperationError(nil, "AssistanceInformationFeedback")
}

// Initiating returns the binding for this procedure's initiating message.
func (ErrorIndicationDescriptor) Initiating() s21.ErrorIndicationInitiatingBinding {
	return func() s21.ErrorIndicationInitiatingBinding {
		sealed := s21.ErrorIndicationInitiatingBinding{}
		*s21.BridgeErrorIndicationInitiatingBindingFieldInfo(&sealed) = ErrorIndicationProcedure().Info()
		*s21.BridgeErrorIndicationInitiatingBindingFieldValidate(&sealed) = func(v *s11.ErrorIndication, budget *aper.DecodeBudget) (s09.ValidationReport, error) {
			return BridgeValidateErrorIndicationBudget(v, budget)
		}
		*s21.BridgeErrorIndicationInitiatingBindingFieldEncode(&sealed) = func(v *s11.ErrorIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s11.BridgeErrorIndicationMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s21.BridgeErrorIndicationInitiatingBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.ErrorIndication, error) {
			var v s11.ErrorIndication
			err := s11.BridgeErrorIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s11.ErrorIndication{}, err
			}
			*s11.BridgeErrorIndicationFieldReceived(&v) = true
			*s11.BridgeErrorIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s21.BridgeErrorIndicationInitiatingBindingFieldInject(&sealed) = func(v s11.ErrorIndication) s21.InitiatingValue {
			return func() s21.InitiatingValue {
				sealed := s21.InitiatingValue{}
				*s21.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(0)
				*s21.BridgeInitiatingValueFieldBodyErrorIndication(&sealed) = &v
				return sealed
			}()
		}
		*s21.BridgeErrorIndicationInitiatingBindingFieldCapture(&sealed) = func(v s11.ErrorIndication, options aper.DecodeState) (s11.ErrorIndication, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s11.BridgeCaptureLPPaErrorIndication(&v, &s)
			var root aper.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeErrorIndicationInitiatingBindingFieldCompare(&sealed) = func(v s11.ErrorIndication, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			s11.BridgeCompareLPPaErrorIndication(&v, &s)
			s.
				End(f, root, false)
			return s.Plan()
		}
		*s21.BridgeErrorIndicationInitiatingBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ErrorIndication"
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the binding for this procedure's initiating message.
func (ECIDMeasurementFailureIndicationDescriptor) Initiating() s21.ECIDMeasurementFailureIndicationInitiatingBinding {
	return func() s21.ECIDMeasurementFailureIndicationInitiatingBinding {
		sealed := s21.ECIDMeasurementFailureIndicationInitiatingBinding{}
		*s21.BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldInfo(&sealed) = ECIDMeasurementFailureIndicationProcedure().Info()
		*s21.BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldValidate(&sealed) = func(v *s11.ECIDMeasurementFailureIndication, budget *aper.DecodeBudget) (s09.ValidationReport, error) {
			return BridgeValidateECIDMeasurementFailureIndicationBudget(v, budget)
		}
		*s21.BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldEncode(&sealed) = func(v *s11.ECIDMeasurementFailureIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s11.BridgeECIDMeasurementFailureIndicationMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s21.BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s11.ECIDMeasurementFailureIndication, error) {
			var v s11.ECIDMeasurementFailureIndication
			err := s11.BridgeECIDMeasurementFailureIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s11.ECIDMeasurementFailureIndication{}, err
			}
			*s11.BridgeECIDMeasurementFailureIndicationFieldReceived(&v) = true
			*s11.BridgeECIDMeasurementFailureIndicationFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s21.BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldInject(&sealed) = func(v s11.ECIDMeasurementFailureIndication) s21.InitiatingValue {
			return func() s21.InitiatingValue {
				sealed := s21.InitiatingValue{}
				*s21.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(3)
				*s21.BridgeInitiatingValueFieldBodyECIDMeasurementFailureIndication(&sealed) = &v
				return sealed
			}()
		}
		*s21.BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldCapture(&sealed) = func(v s11.ECIDMeasurementFailureIndication, options aper.DecodeState) (s11.ECIDMeasurementFailureIndication, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s11.BridgeCaptureLPPaECIDMeasurementFailureIndication(&v, &s)
			var root aper.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldCompare(&sealed) = func(v s11.ECIDMeasurementFailureIndication, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s11.BridgeCompareLPPaECIDMeasurementFailureIndication(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s21.BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ECIDMeasurementFailureIndication"
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the binding for this procedure's initiating message.
func (ECIDMeasurementReportDescriptor) Initiating() s21.ECIDMeasurementReportInitiatingBinding {
	return func() s21.ECIDMeasurementReportInitiatingBinding {
		sealed := s21.ECIDMeasurementReportInitiatingBinding{}
		*s21.BridgeECIDMeasurementReportInitiatingBindingFieldInfo(&sealed) = ECIDMeasurementReportProcedure().Info()
		*s21.BridgeECIDMeasurementReportInitiatingBindingFieldValidate(&sealed) = func(v *s13.ECIDMeasurementReport, budget *aper.DecodeBudget) (s09.ValidationReport, error) {
			return BridgeValidateECIDMeasurementReportBudget(v, budget)
		}
		*s21.BridgeECIDMeasurementReportInitiatingBindingFieldEncode(&sealed) = func(v *s13.ECIDMeasurementReport, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s13.BridgeECIDMeasurementReportMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s21.BridgeECIDMeasurementReportInitiatingBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.ECIDMeasurementReport, error) {
			var v s13.ECIDMeasurementReport
			err := s13.BridgeECIDMeasurementReportMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s13.ECIDMeasurementReport{}, err
			}
			*s13.BridgeECIDMeasurementReportFieldReceived(&v) = true
			*s13.BridgeECIDMeasurementReportFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s21.BridgeECIDMeasurementReportInitiatingBindingFieldInject(&sealed) = func(v s13.ECIDMeasurementReport) s21.InitiatingValue {
			return func() s21.InitiatingValue {
				sealed := s21.InitiatingValue{}
				*s21.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(4)
				*s21.BridgeInitiatingValueFieldBodyECIDMeasurementReport(&sealed) = &v
				return sealed
			}()
		}
		*s21.BridgeECIDMeasurementReportInitiatingBindingFieldCapture(&sealed) = func(v s13.ECIDMeasurementReport, options aper.DecodeState) (s13.ECIDMeasurementReport, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s13.BridgeCaptureLPPaECIDMeasurementReport(&v,
				&s,
			)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f,

				&root, false)
			return v, root
		}
		*s21.BridgeECIDMeasurementReportInitiatingBindingFieldCompare(&sealed) = func(v s13.ECIDMeasurementReport, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s13.BridgeCompareLPPaECIDMeasurementReport(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s21.BridgeECIDMeasurementReportInitiatingBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ECIDMeasurementReport"
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the binding for this procedure's initiating message.
func (ECIDMeasurementTerminationDescriptor) Initiating() s21.ECIDMeasurementTerminationCommandInitiatingBinding {
	return func() s21.ECIDMeasurementTerminationCommandInitiatingBinding {
		sealed := s21.ECIDMeasurementTerminationCommandInitiatingBinding{}
		*s21.BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldInfo(&sealed) = ECIDMeasurementTerminationProcedure().Info()
		*s21.BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldValidate(&sealed) = func(v *s06.ECIDMeasurementTerminationCommand, budget *aper.DecodeBudget) (s09.ValidationReport, error) {
			return BridgeValidateECIDMeasurementTerminationCommandBudget(v, budget)
		}
		*s21.BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldEncode(&sealed) = func(v *s06.ECIDMeasurementTerminationCommand, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s06.BridgeECIDMeasurementTerminationCommandMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s21.BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s06.ECIDMeasurementTerminationCommand, error) {
			var v s06.ECIDMeasurementTerminationCommand
			err := s06.BridgeECIDMeasurementTerminationCommandMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s06.ECIDMeasurementTerminationCommand{}, err
			}
			*s06.BridgeECIDMeasurementTerminationCommandFieldReceived(&v) = true
			*s06.BridgeECIDMeasurementTerminationCommandFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s21.BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldInject(&sealed) = func(v s06.ECIDMeasurementTerminationCommand) s21.InitiatingValue {
			return func() s21.InitiatingValue {
				sealed := s21.InitiatingValue{}
				*s21.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(5)
				*s21.BridgeInitiatingValueFieldBodyECIDMeasurementTerminationCommand(&sealed) = &v
				return sealed
			}()
		}
		*s21.BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldCapture(&sealed) = func(v s06.ECIDMeasurementTerminationCommand, options aper.DecodeState) (s06.ECIDMeasurementTerminationCommand, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s06.BridgeCaptureLPPaECIDMeasurementTerminationCommand(&v, &s)
			var root aper.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldCompare(&sealed) = func(v s06.ECIDMeasurementTerminationCommand, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s06.BridgeCompareLPPaECIDMeasurementTerminationCommand(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s21.BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ECIDMeasurementTerminationCommand"
			return sealed
		}()
		return sealed
	}()

}

// Initiating returns the binding for this procedure's initiating message.
func (AssistanceInformationFeedbackDescriptor) Initiating() s21.AssistanceInformationFeedbackInitiatingBinding {
	return func() s21.AssistanceInformationFeedbackInitiatingBinding {
		sealed := s21.AssistanceInformationFeedbackInitiatingBinding{}
		*s21.BridgeAssistanceInformationFeedbackInitiatingBindingFieldInfo(&sealed) = AssistanceInformationFeedbackProcedure().Info()
		*s21.BridgeAssistanceInformationFeedbackInitiatingBindingFieldValidate(&sealed) = func(v *s17.AssistanceInformationFeedback, budget *aper.DecodeBudget) (s09.ValidationReport, error) {
			return BridgeValidateAssistanceInformationFeedbackBudget(v, budget)
		}
		*s21.BridgeAssistanceInformationFeedbackInitiatingBindingFieldEncode(&sealed) = func(v *s17.AssistanceInformationFeedback, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s17.BridgeAssistanceInformationFeedbackMethodMarshalAPERBudget(v, budget, fresh)
		}
		*s21.BridgeAssistanceInformationFeedbackInitiatingBindingFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s17.AssistanceInformationFeedback, error) {
			var v s17.AssistanceInformationFeedback
			err := s17.BridgeAssistanceInformationFeedbackMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return s17.AssistanceInformationFeedback{}, err
			}
			*s17.BridgeAssistanceInformationFeedbackFieldReceived(&v) = true
			*s17.BridgeAssistanceInformationFeedbackFieldReceivedBytes(&v) = aper.OriginalWire(data)
			return v, nil
		}
		*s21.BridgeAssistanceInformationFeedbackInitiatingBindingFieldInject(&sealed) = func(v s17.AssistanceInformationFeedback) s21.InitiatingValue {
			return func() s21.InitiatingValue {
				sealed := s21.InitiatingValue{}
				*s21.BridgeInitiatingValueFieldCode(&sealed) = s00.ProcedureCode(10)
				*s21.BridgeInitiatingValueFieldBodyAssistanceInformationFeedback(&sealed) = &v
				return sealed
			}()
		}
		*s21.BridgeAssistanceInformationFeedbackInitiatingBindingFieldCapture(&sealed) = func(v s17.AssistanceInformationFeedback, options aper.DecodeState) (s17.AssistanceInformationFeedback, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s17.BridgeCaptureLPPaAssistanceInformationFeedback(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s21.BridgeAssistanceInformationFeedbackInitiatingBindingFieldCompare(&sealed) = func(v s17.AssistanceInformationFeedback, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s17.BridgeCompareLPPaAssistanceInformationFeedback(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s21.BridgeAssistanceInformationFeedbackInitiatingBindingFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AssistanceInformationFeedback"
			return sealed
		}()
		return sealed
	}()

}

// ECIDMeasurementInitiationResponseSuccessfulBinding is the concrete SuccessfulBinding[ECIDMeasurementInitiationResponse].
type ECIDMeasurementInitiationResponseSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s22.ECIDMeasurementInitiationResponse, aper.DecodeState,

	) (s22.ECIDMeasurementInitiationResponse, aper.Snapshot,

	)
	compare func(s22.ECIDMeasurementInitiationResponse, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*s22.ECIDMeasurementInitiationResponse,

		*aper.DecodeBudget) (s09.ValidationReport, error)
	encode func(*s22.ECIDMeasurementInitiationResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s22.ECIDMeasurementInitiationResponse,

		error)
	inject func(s22.ECIDMeasurementInitiationResponse,

	) s22.SuccessfulValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementInitiationResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementInitiationResponseSuccessfulBinding) Codec() s22.ECIDMeasurementInitiationResponseValueCodec {
	return func() s22.ECIDMeasurementInitiationResponseValueCodec {
		sealed := s22.ECIDMeasurementInitiationResponseValueCodec{}
		*s22.BridgeECIDMeasurementInitiationResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s22.BridgeECIDMeasurementInitiationResponseValueCodecFieldDecode(&sealed) = b.decode
		*s22.BridgeECIDMeasurementInitiationResponseValueCodecFieldEncode(&sealed) = func(value s22.ECIDMeasurementInitiationResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s22.BridgeECIDMeasurementInitiationResponseValueCodecFieldCapture(&sealed) = b.capture
		*s22.BridgeECIDMeasurementInitiationResponseValueCodecFieldCompare(&sealed) = b.compare
		*s22.BridgeECIDMeasurementInitiationResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b ECIDMeasurementInitiationResponseSuccessfulBinding) Build(body s22.ECIDMeasurementInitiationResponse,

	transactionID s00.LPPATransactionID, options ...aper.BuildOption) (s22.SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s22.SuccessfulOutcome{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return s22.SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// OTDOAInformationResponseSuccessfulBinding is the concrete SuccessfulBinding[OTDOAInformationResponse].
type OTDOAInformationResponseSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s18.OTDOAInformationResponse, aper.DecodeState,

	) (s18.OTDOAInformationResponse, aper.Snapshot,

	)
	compare func(s18.OTDOAInformationResponse, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*s18.OTDOAInformationResponse,

		*aper.DecodeBudget) (s09.ValidationReport, error)
	encode func(*s18.OTDOAInformationResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s18.OTDOAInformationResponse,

		error)
	inject func(s18.OTDOAInformationResponse,

	) s22.SuccessfulValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b OTDOAInformationResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b OTDOAInformationResponseSuccessfulBinding) Codec() s18.OTDOAInformationResponseValueCodec {
	return func() s18.OTDOAInformationResponseValueCodec {
		sealed := s18.OTDOAInformationResponseValueCodec{}
		*s18.BridgeOTDOAInformationResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s18.BridgeOTDOAInformationResponseValueCodecFieldDecode(&sealed) = b.decode
		*s18.BridgeOTDOAInformationResponseValueCodecFieldEncode(&sealed) = func(value s18.OTDOAInformationResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s18.BridgeOTDOAInformationResponseValueCodecFieldCapture(&sealed) = b.capture
		*s18.BridgeOTDOAInformationResponseValueCodecFieldCompare(&sealed) = b.compare
		*s18.BridgeOTDOAInformationResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b OTDOAInformationResponseSuccessfulBinding) Build(body s18.OTDOAInformationResponse,

	transactionID s00.LPPATransactionID, options ...aper.BuildOption) (s22.SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s22.SuccessfulOutcome{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return s22.SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UTDOAInformationResponseSuccessfulBinding is the concrete SuccessfulBinding[UTDOAInformationResponse].
type UTDOAInformationResponseSuccessfulBinding struct {
	context s00.BridgeCodecContext
	capture func(s17.UTDOAInformationResponse, aper.DecodeState,

	) (s17.UTDOAInformationResponse, aper.Snapshot,

	)
	compare func(s17.UTDOAInformationResponse, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*s17.UTDOAInformationResponse,

		*aper.DecodeBudget) (s09.ValidationReport, error)
	encode func(*s17.UTDOAInformationResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s17.UTDOAInformationResponse,

		error)
	inject func(s17.UTDOAInformationResponse,

	) s22.SuccessfulValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b UTDOAInformationResponseSuccessfulBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b UTDOAInformationResponseSuccessfulBinding) Codec() s17.UTDOAInformationResponseValueCodec {
	return func() s17.UTDOAInformationResponseValueCodec {
		sealed := s17.UTDOAInformationResponseValueCodec{}
		*s17.BridgeUTDOAInformationResponseValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s17.BridgeUTDOAInformationResponseValueCodecFieldDecode(&sealed) = b.decode
		*s17.BridgeUTDOAInformationResponseValueCodecFieldEncode(&sealed) = func(value s17.UTDOAInformationResponse,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s17.BridgeUTDOAInformationResponseValueCodecFieldCapture(&sealed) = b.capture
		*s17.BridgeUTDOAInformationResponseValueCodecFieldCompare(&sealed) = b.compare
		*s17.BridgeUTDOAInformationResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b UTDOAInformationResponseSuccessfulBinding) Build(body s17.UTDOAInformationResponse,

	transactionID s00.LPPATransactionID, options ...aper.BuildOption) (s22.SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s22.SuccessfulOutcome{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "Build")
	}
	return s22.SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// LPPAPDUValueCodec is the concrete ValueCodec[LPPAPDU].
type LPPAPDUValueCodec struct {
	context s00.BridgeCodecContext
	capture func(LPPAPDU, aper.DecodeState,

	) (LPPAPDU, aper.Snapshot,

	)
	compare func(LPPAPDU, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (LPPAPDU,

		error)
	encode func(LPPAPDU,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c LPPAPDUValueCodec) New(value LPPAPDU,

) (LPPAPDUAPERValue, error) {
	if c.encode == nil {
		return LPPAPDUAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LPPAPDUAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LPPAPDUAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return LPPAPDUAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c LPPAPDUValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LPPAPDUAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return LPPAPDUAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return LPPAPDUAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return LPPAPDUAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return LPPAPDUAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return LPPAPDUAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c LPPAPDUValueCodec) EncodeAPER(value LPPAPDUAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, aper.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, aper.OperationError(err, c.path)
}
func (c LPPAPDUValueCodec) encodeBudget(value LPPAPDU,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c LPPAPDUValueCodec) encodeChanged(value LPPAPDU,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// SuccessfulOutcomeValueCodec is the concrete ValueCodec[SuccessfulOutcome].
type SuccessfulOutcomeValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s22.SuccessfulOutcome, aper.DecodeState,

	) (s22.SuccessfulOutcome, aper.Snapshot,

	)
	compare func(s22.SuccessfulOutcome, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s22.SuccessfulOutcome,

		error)
	encode func(s22.SuccessfulOutcome,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c SuccessfulOutcomeValueCodec) New(value s22.SuccessfulOutcome,

) (SuccessfulOutcomeAPERValue, error) {
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

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c SuccessfulOutcomeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SuccessfulOutcomeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SuccessfulOutcomeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return SuccessfulOutcomeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SuccessfulOutcomeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return SuccessfulOutcomeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return SuccessfulOutcomeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c SuccessfulOutcomeValueCodec) EncodeAPER(value SuccessfulOutcomeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, aper.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, aper.OperationError(err, c.path)
}
func (c SuccessfulOutcomeValueCodec) encodeBudget(value s22.SuccessfulOutcome,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SuccessfulOutcomeValueCodec) encodeChanged(value s22.SuccessfulOutcome,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeECIDMeasurementInitiationResponseIEValueValidateLPPaIEContainer(fields s22.ECIDMeasurementInitiationResponseIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s09.ValidationReport {
	report := func() s09.ValidationReport {
		sealed := s09.ValidationReport{Complete: true}
		*s09.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s09.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s09.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !s22.BridgeECIDMeasurementInitiationResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s22.BridgeECIDMeasurementInitiationResponseIEValueMethodRule(field.Value)
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s04.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		aper.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row s00.FieldInfo
			related := []aper.SourceRule{s04.BridgeLppaAdoptedRule(s00.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s04.BridgeLppaValidationRule(s00.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s04.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: s04.BridgeLppaValidationRule(s00.NotAllowed), RelatedRules: s04.BridgeLppaHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s04.BridgeLppaAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s04.BridgeLppaValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s04.BridgeLppaAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s04.BridgeLppaValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s04.BridgeLppaAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s09.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s09.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeWLANMeasurementResultItemExtIEsValueValidateLPPaExtensionContainer(fields s04.WLANMeasurementResultItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s04.WLANMeasurementResultItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s04.WLANMeasurementResultItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeWLANMeasurementResultItemExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// eCIDMeasurementInitiationResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s22.ECIDMeasurementInitiationResponseIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s22.ECIDMeasurementInitiationResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// wLANMeasurementResultItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[WLANMeasurementResultItemExtIEsValue].
type WLANMeasurementResultItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.WLANMeasurementResultItemExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.WLANMeasurementResultItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// LPPAPDUAPERValue is the concrete APERValue[LPPAPDU].
type LPPAPDUAPERValue struct {
	context s00.BridgeCodecContext
	Value   LPPAPDU

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v LPPAPDUAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v LPPAPDUAPERValue) WithoutReplay() LPPAPDUAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SuccessfulOutcomeAPERValue is the concrete APERValue[SuccessfulOutcome].
type SuccessfulOutcomeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s22.SuccessfulOutcome

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v SuccessfulOutcomeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v SuccessfulOutcomeAPERValue) WithoutReplay() SuccessfulOutcomeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeWLANMeasurementResultItemExtIEsValueValidateLPPaIEContainer(fields s04.WLANMeasurementResultItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s09.ValidationReport {
	report := func() s09.ValidationReport {
		sealed := s09.ValidationReport{Complete: true}
		*s09.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s09.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s09.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !s03.BridgeWLANMeasurementResultItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s03.BridgeWLANMeasurementResultItemExtIEsValueMethodRule(field.Value)
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s04.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		aper.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row s00.FieldInfo
			related := []aper.SourceRule{s04.BridgeLppaAdoptedRule(s00.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s04.BridgeLppaValidationRule(s00.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s04.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: s04.BridgeLppaValidationRule(s00.NotAllowed), RelatedRules: s04.BridgeLppaHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s04.BridgeLppaAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s04.BridgeLppaValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s04.BridgeLppaAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s04.BridgeLppaValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s04.BridgeLppaAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s09.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s09.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// MarshalAPERWLANMeasurementResult encodes a WLANMeasurementResult list to APER.
func BridgeMarshalAPERWLANMeasurementResult(list s22.WLANMeasurementResultComplete) ([]byte, error) {
	return s22.BridgeWLANMeasurementResultCompleteMethodMarshalAPERLegacy(&list)
}

// UnmarshalAPERWLANMeasurementResult decodes a WLANMeasurementResult list from APER.
func BridgeUnmarshalAPERWLANMeasurementResult(data []byte) (s22.WLANMeasurementResultComplete, error) {
	var value s22.WLANMeasurementResultComplete
	if err := s22.BridgeWLANMeasurementResultCompleteMethodUnmarshalAPERLegacy(&value, data); err != nil {
		return value, err
	}
	return value, nil
}

// LPPAPDU represents the ASN.1 CHOICE type LPPA-PDU.
type LPPAPDU struct {
	knownOpenBytes      uint64
	replay              aper.Snapshot
	stream              aper.WireSpan
	withoutReplay       bool
	received            bool
	receivedBytes       aper.WireSpan
	Choice              int
	perPadding          aper.CompletePadding     `json:"-"`
	perOpenTypePadding  aper.CompletePadding     `json:"-"`
	UnknownExtension    *aper.ChoiceExtension    `json:"UnknownExtension,omitempty"`
	InitiatingMessage   *s21.InitiatingMessage   `json:"InitiatingMessage,omitempty"`
	SuccessfulOutcome   *s22.SuccessfulOutcome   `json:"SuccessfulOutcome,omitempty"`
	UnsuccessfulOutcome *s16.UnsuccessfulOutcome `json:"UnsuccessfulOutcome,omitempty"`
}

// NewLPPAPDUInitiatingMessage creates a LPPAPDU with the initiatingMessage alternative.
func BridgeNewLPPAPDUInitiatingMessageLegacy(v s21.InitiatingMessage) LPPAPDU {
	return LPPAPDU{
		Choice:            s00.LPPAPDUChoiceInitiatingMessage,
		InitiatingMessage: &v,
	}
}

// NewLPPAPDUSuccessfulOutcome creates a LPPAPDU with the successfulOutcome alternative.
func BridgeNewLPPAPDUSuccessfulOutcomeLegacy(v s22.SuccessfulOutcome) LPPAPDU {
	return LPPAPDU{
		Choice:            s00.LPPAPDUChoiceSuccessfulOutcome,
		SuccessfulOutcome: &v,
	}
}

// NewLPPAPDUUnsuccessfulOutcome creates a LPPAPDU with the unsuccessfulOutcome alternative.
func BridgeNewLPPAPDUUnsuccessfulOutcomeLegacy(v s16.UnsuccessfulOutcome) LPPAPDU {
	return LPPAPDU{
		Choice:              s00.LPPAPDUChoiceUnsuccessfulOutcome,
		UnsuccessfulOutcome: &v,
	}
}

// MarshalAPER encodes LPPAPDU to APER format.
func (v *LPPAPDU) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *LPPAPDU) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.
			ReplayTo(v.stream, bb); ok || err !=
			nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "LPPAPDU:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "LPPAPDU:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "LPPAPDU:", v.Choice)
	}
	isExtension := v.Choice > 3
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "LPPAPDU:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case s00.LPPAPDUChoiceInitiatingMessage:
		if v.InitiatingMessage == nil {
			return fmt.Errorf("choice alternative initiatingMessage is nil")
		}
		if err := s21.BridgeInitiatingMessageMethodMarshalAPERTo(v.InitiatingMessage, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding initiatingMessage: %w", err)
		}
	case s00.LPPAPDUChoiceSuccessfulOutcome:
		if v.SuccessfulOutcome == nil {
			return fmt.Errorf("choice alternative successfulOutcome is nil")
		}
		if err := s22.BridgeSuccessfulOutcomeMethodMarshalAPERTo(v.SuccessfulOutcome, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding successfulOutcome: %w", err)
		}
	case s00.LPPAPDUChoiceUnsuccessfulOutcome:
		if v.UnsuccessfulOutcome == nil {
			return fmt.Errorf("choice alternative unsuccessfulOutcome is nil")
		}
		if err := s16.BridgeUnsuccessfulOutcomeMethodMarshalAPERTo(v.UnsuccessfulOutcome, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding unsuccessfulOutcome: %w", err)
		}
	default:
		return fmt.Errorf("unknown LPPAPDU choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes LPPAPDU from APER format.
func (v *LPPAPDU) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes LPPAPDU with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *LPPAPDU) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "LPPAPDU")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "LPPAPDU")
	}
	padding, err := aper.CaptureFinalBits(bb, "LPPAPDU")
	if err != nil {
		return runtime.WrapDecodePath(err, "LPPAPDU")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *LPPAPDU) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LPPAPDU{}
	isExtension, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := aper.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := aper.DecodeChoiceExtensionAligned(bb, extIdx, 0)
		if extIdx < 0 {
			v.knownOpenBytes = max(v.knownOpenBytes, openExtension.ContentLength())
		}
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		v.UnknownExtension = &openExtension
		v.stream = bb.CaptureWireSpan(replayStart)
		v.stream.RecordUsage(replayUsage,

			bb)

		return nil
	}
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 2)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.LPPAPDUChoiceInitiatingMessage:
		toleranceMark_initiatingmessage := bb.EnterComponent("InitiatingMessage")
		var dec_initiatingmessage s21.InitiatingMessage
		if err := s21.BridgeInitiatingMessageMethodUnmarshalAPERFrom(&dec_initiatingmessage, bb); err != nil {
			return runtime.WrapDecodePath(err, "InitiatingMessage")
		}
		if err := aper.ChargeValue(bb, dec_initiatingmessage); err != nil {
			return err
		}
		v.InitiatingMessage = &dec_initiatingmessage
		bb.LeaveComponent(toleranceMark_initiatingmessage)
	case s00.LPPAPDUChoiceSuccessfulOutcome:
		toleranceMark_successfuloutcome := bb.EnterComponent("SuccessfulOutcome")
		var dec_successfuloutcome s22.SuccessfulOutcome
		if err := s22.BridgeSuccessfulOutcomeMethodUnmarshalAPERFrom(&dec_successfuloutcome, bb); err != nil {
			return runtime.WrapDecodePath(err, "SuccessfulOutcome")
		}
		if err := aper.ChargeValue(bb, dec_successfuloutcome); err != nil {
			return err
		}
		v.SuccessfulOutcome = &dec_successfuloutcome
		bb.LeaveComponent(toleranceMark_successfuloutcome)
	case s00.LPPAPDUChoiceUnsuccessfulOutcome:
		toleranceMark_unsuccessfuloutcome := bb.EnterComponent("UnsuccessfulOutcome")
		var dec_unsuccessfuloutcome s16.UnsuccessfulOutcome
		if err := s16.BridgeUnsuccessfulOutcomeMethodUnmarshalAPERFrom(&dec_unsuccessfuloutcome, bb); err != nil {
			return runtime.WrapDecodePath(err, "UnsuccessfulOutcome")
		}
		if err := aper.ChargeValue(bb, dec_unsuccessfuloutcome); err != nil {
			return err
		}
		v.UnsuccessfulOutcome = &dec_unsuccessfuloutcome
		bb.LeaveComponent(toleranceMark_unsuccessfuloutcome)
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *LPPAPDU) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "LPPAPDU", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v LPPAPDU) WithoutReplay() LPPAPDU {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero LPPAPDU
	v.perPadding = zero.perPadding
	return v
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *LPPAPDU) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "LPPAPDU")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "LPPAPDU")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaLPPAPDU(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "LPPAPDU")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "LPPAPDU")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "LPPAPDU")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "LPPAPDU")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "LPPAPDU")
}
func (v *LPPAPDU) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *LPPAPDU) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *LPPAPDU) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaLPPAPDU(v, &s)
		if err := s.ChargeComparison(budget); err != nil {
			return nil, err
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.receivedBytes.ReplayBytes(budget)
		}
		return v.marshalAPERChanged(budget, fresh, s.Plan())
	}
	if !fresh && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && v.received {
		if err := v.replay.ApplyReplay(budget); err != nil {
			return nil, err
		}
		return v.receivedBytes.ReplayBytes(budget)
	}
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *LPPAPDU) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *LPPAPDU) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := value.marshalAPERTo(bb, fresh); err != nil {
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

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *LPPAPDU) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "LPPAPDU")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded LPPAPDU
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaLPPAPDU(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = LPPAPDU{}
		return report, aper.OperationError(err, "LPPAPDU")
	}
	*v = decoded
	return report, aper.OperationError(nil, "LPPAPDU")
}

// NewLPPAPDUUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewLPPAPDUUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (LPPAPDU, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return LPPAPDU{}, aper.OperationError(err, "LPPAPDUUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return LPPAPDU{}, aper.OperationError(err, "LPPAPDUUnknownExtension")
	}
	value := LPPAPDU{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return LPPAPDU{}, aper.OperationError(err, "LPPAPDUUnknownExtension")
	}
	return value, aper.OperationError(nil, "LPPAPDUUnknownExtension")
}

// PayloadCodec owns a typed foreign decoder and encoder. The callbacks must
// enforce the foreign schema and consume a complete value.
type PayloadCodec[T any] struct {
	decode func([]byte, s00.PayloadLimits) (T, s00.PayloadReport, error)
	encode func(T, s00.PayloadLimits) ([]byte, error)
}
type NewPayloadCodec[T any] struct{}

// Call invokes the payload operation for the caller-selected value type.
func (NewPayloadCodec[T]) Call(
	decode func([]byte, s00.PayloadLimits) (T, s00.PayloadReport, error),
	encode func(T, s00.PayloadLimits) ([]byte, error),
) (PayloadCodec[T], error) {
	if decode == nil || encode == nil {
		return PayloadCodec[T]{}, aper.OperationError(aper.OperationError(fmt.Errorf("%w: payload binding: nil callback", aper.ErrInvalidValue), "Payload.binding"), "PayloadCodec")
	}
	return PayloadCodec[T]{decode: decode, encode: encode}, aper.OperationError(nil, "PayloadCodec")
}

type DecodePayload[T any] struct{}

// Call invokes the payload operation for the caller-selected value type.
func (DecodePayload[T]) Call(data []byte, codec PayloadCodec[T], limits s00.PayloadLimits) (T, s00.PayloadReport, error) {
	var zero T
	if codec.decode == nil || codec.encode == nil {
		return zero, s00.PayloadReport{}, aper.OperationError(fmt.Errorf("%w: payload binding: zero codec", aper.ErrInvalidValue), "Payload.binding")
	}
	limits = s03.BridgeEffectivePayloadLimits(limits)
	if uint64(len(data)) > limits.MaxInputBytes {
		return zero, s00.PayloadReport{}, aper.OperationError(fmt.Errorf("%w: payload input: %d bytes exceed limit %d", aper.ErrLimit, len(data), limits.MaxInputBytes), "Payload.input")
	}
	if uint64(len(data)) > limits.MaxAllocatedBytes {
		return zero, s00.PayloadReport{}, aper.OperationError(fmt.Errorf("%w: payload input copy: %d bytes exceed allocation limit %d", aper.ErrLimit, len(data), limits.MaxAllocatedBytes), "Payload.input")
	}
	if uint64(len(data)) > limits.MaxWork {
		return zero, s00.PayloadReport{}, aper.OperationError(fmt.Errorf("%w: payload input copy work", aper.ErrLimit), "Payload.input")
	}
	owned := append([]byte(nil), data...)
	value, report, err := codec.decode(owned, limits)
	if err != nil {
		return zero, report, fmt.Errorf("payload decode: %w", err)
	}
	if uint64(len(report.Deviations)) > limits.MaxReports {
		return zero, s00.PayloadReport{}, aper.OperationError(fmt.Errorf("%w: payload report: %d deviations exceed limit %d", aper.ErrLimit, len(report.Deviations), limits.MaxReports), "Payload.report")
	}
	return value, report, nil
}

type EncodePayload[T any] struct{}

// Call invokes the payload operation for the caller-selected value type.
func (EncodePayload[T]) Call(value T, codec PayloadCodec[T], limits s00.PayloadLimits) ([]byte, error) {
	if codec.decode == nil || codec.encode == nil {
		return nil, aper.OperationError(fmt.Errorf("%w: payload binding: zero codec", aper.ErrInvalidValue), "Payload.binding")
	}
	limits = s03.BridgeEffectivePayloadLimits(limits)
	wire, err := codec.encode(value, limits)
	if err != nil {
		return nil, fmt.Errorf("payload encode: %w", err)
	}
	if uint64(len(wire)) > limits.MaxOutputBytes {
		return nil, aper.OperationError(fmt.Errorf("%w: payload output: %d bytes exceed limit %d", aper.ErrLimit, len(wire), limits.MaxOutputBytes), "Payload.output")
	}
	if uint64(len(wire)) > limits.MaxAllocatedBytes {
		return nil, aper.OperationError(fmt.Errorf("%w: payload output copy: %d bytes exceed allocation limit %d", aper.ErrLimit, len(wire), limits.MaxAllocatedBytes), "Payload.output")
	}
	if uint64(len(wire)) > limits.MaxWork {
		return nil, aper.OperationError(fmt.Errorf("%w: payload output copy work", aper.ErrLimit), "Payload.output")
	}
	return append([]byte(nil), wire...), nil
}
func NewOpaqueSuccessfulOutcome(code s00.ProcedureCode, criticality s00.Criticality, transactionID s00.LPPATransactionID, data []byte) (s22.SuccessfulOutcome, error) {
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "OpaqueSuccessfulOutcome")
	}
	switch code {
	case s00.ProcedureCode(2):
		return s22.SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-e-CIDMeasurementInitiation requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(6):
		return s22.SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-oTDOAInformationExchange requires its typed binding"), "OpaqueSuccessfulOutcome")
	case s00.ProcedureCode(7):
		return s22.SuccessfulOutcome{}, aper.OperationError(fmt.Errorf("known Successful procedure id-uTDOAInformationExchange requires its typed binding"), "OpaqueSuccessfulOutcome")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "OpaqueSuccessfulOutcome")
	}
	opaque, err := aper.BuildOpaqueOpenType(data, budget)
	if err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "OpaqueSuccessfulOutcome")
	}
	retained, err := opaque.Retained(budget)
	if err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "OpaqueSuccessfulOutcome")
	}
	message := s22.SuccessfulOutcome{ProcedureCode: code, Criticality: criticality, LppatransactionID: transactionID, Value: func() s22.SuccessfulValue {
		sealed := s22.SuccessfulValue{}
		*s22.BridgeSuccessfulValueFieldCode(&sealed) = code
		*s22.BridgeSuccessfulValueFieldOpaque(&sealed) = retained
		*s22.BridgeSuccessfulValueFieldIsOpaque(&sealed) = true
		return sealed
	}()}
	if _, err := s22.BridgeSuccessfulOutcomeMethodMarshalAPERBudget(&message, budget, false); err != nil {
		return s22.SuccessfulOutcome{}, aper.OperationError(err, "OpaqueSuccessfulOutcome")
	}
	return message, aper.OperationError(nil, "OpaqueSuccessfulOutcome")
}
func BridgeCaptureLPPaLPPAPDU(v *LPPAPDU, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.OpenBytes(v.knownOpenBytes)
	s.Stream(v.stream)
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
	case s00.LPPAPDUChoiceInitiatingMessage:
		{
			f := s.Begin()
			s.Bool(v.InitiatingMessage == nil)
			if v.InitiatingMessage != nil {
				s21.BridgeCaptureLPPaInitiatingMessage(v.InitiatingMessage, s)
			}
			s.End(f, nil, false)
		}
	case s00.LPPAPDUChoiceSuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.SuccessfulOutcome == nil)
			if v.SuccessfulOutcome != nil {
				s22.BridgeCaptureLPPaSuccessfulOutcome(v.SuccessfulOutcome, s)
			}
			s.End(f, nil, false)
		}
	case s00.LPPAPDUChoiceUnsuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.UnsuccessfulOutcome == nil)
			if v.UnsuccessfulOutcome != nil {
				s16.BridgeCaptureLPPaUnsuccessfulOutcome(v.UnsuccessfulOutcome, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaLPPAPDU(v *LPPAPDU, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

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
	case s00.LPPAPDUChoiceInitiatingMessage:
		{
			f := s.Begin()
			s.Bool(v.InitiatingMessage == nil)
			if v.InitiatingMessage != nil {
				s21.BridgeCompareLPPaInitiatingMessage(v.InitiatingMessage, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.LPPAPDUChoiceSuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.SuccessfulOutcome == nil)
			if v.SuccessfulOutcome != nil {
				s22.BridgeCompareLPPaSuccessfulOutcome(v.SuccessfulOutcome, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.LPPAPDUChoiceUnsuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.UnsuccessfulOutcome == nil)
			if v.UnsuccessfulOutcome != nil {
				s16.BridgeCompareLPPaUnsuccessfulOutcome(v.UnsuccessfulOutcome, s)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaPrivateIEContainer[V ProtocolPrivateValueConstraint[V]](v *PrivateIEContainer[V], s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeCaptureLPPaPrivateIEField[V](&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeCompareLPPaPrivateIEContainer[V ProtocolPrivateValueConstraint[V]](v *PrivateIEContainer[V], s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeCompareLPPaPrivateIEField[V](&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCaptureLPPaPrivateIEField[V ProtocolPrivateValueConstraint[V]](v *PrivateIEField[V], s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s08.BridgeCaptureLPPaPrivateIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(v.Value.captureFraming())
	v.Value = v.Value.captureSemantics(*s)
	s.Child(v.Value.captureSnapshot())
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaPrivateIEField[V ProtocolPrivateValueConstraint[V]](v *PrivateIEField[V], s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s08.BridgeCompareLPPaPrivateIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaProtocolExtensionContainer[V ProtocolOpenValueConstraint[V]](v *ProtocolExtensionContainer[V], s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeCaptureLPPaProtocolExtensionField[V](&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeCompareLPPaProtocolExtensionContainer[V ProtocolOpenValueConstraint[V]](v *ProtocolExtensionContainer[V], s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeCompareLPPaProtocolExtensionField[V](&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCaptureLPPaProtocolExtensionField[V ProtocolOpenValueConstraint[V]](v *ProtocolExtensionField[V], s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(v.ExtensionValue.captureFraming())
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.Child(v.ExtensionValue.captureSnapshot())
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaProtocolExtensionField[V ProtocolOpenValueConstraint[V]](v *ProtocolExtensionField[V], s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaProtocolIEContainer[V ProtocolOpenValueConstraint[V]](v *ProtocolIEContainer[V], s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeCaptureLPPaProtocolIEField[V](&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeCompareLPPaProtocolIEContainer[V ProtocolOpenValueConstraint[V]](v *ProtocolIEContainer[V], s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeCompareLPPaProtocolIEField[V](&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCaptureLPPaProtocolIEField[V ProtocolOpenValueConstraint[V]](v *ProtocolIEField[V], s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(v.Value.captureFraming())
	v.Value = v.Value.captureSemantics(*s)
	s.Child(v.Value.captureSnapshot())
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaProtocolIEField[V ProtocolOpenValueConstraint[V]](v *ProtocolIEField[V], s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaProtocolIESingleContainer[V ProtocolOpenValueConstraint[V]](v *ProtocolIESingleContainer[V], s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	BridgeCaptureLPPaProtocolIEField[V](v, s)
}
func BridgeCompareLPPaProtocolIESingleContainer[V ProtocolOpenValueConstraint[V]](v *ProtocolIESingleContainer[V], s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	BridgeCompareLPPaProtocolIEField[V](v, s)
}

type ProtocolOpenValueConstraint[V any] interface {
	captureSemantics(aper.SemanticCapture) V
	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (V, error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}
type ProtocolIEField[V ProtocolOpenValueConstraint[V]] struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         V
	received      aper.CompletePadding
}
type ProtocolIEContainer[V ProtocolOpenValueConstraint[V]] []ProtocolIEField[V]
type ProtocolIEContainerList[V ProtocolOpenValueConstraint[V]] []ProtocolIEContainer[V]

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ProtocolIEField[V]) WithoutReplay() ProtocolIEField[V] {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ProtocolIEField[V]) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ProtocolIEField[V]) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ProtocolIEField[V]{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
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
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

type ProtocolExtensionField[V ProtocolOpenValueConstraint[V]] struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue V
	received       aper.CompletePadding
}
type ProtocolExtensionContainer[V ProtocolOpenValueConstraint[V]] []ProtocolExtensionField[V]

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ProtocolExtensionField[V]) WithoutReplay() ProtocolExtensionField[V] {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ProtocolExtensionField[V]) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.ExtensionValue.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.ExtensionValue.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *ProtocolExtensionField[V]) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ProtocolExtensionField[V]{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
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
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

type ProtocolPrivateValueConstraint[V any] interface {
	captureSemantics(aper.SemanticCapture) V
	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	matchesID(s08.PrivateIEID, *aper.DecodeBudget) bool
	decode(s08.PrivateIEID, aper.OpaqueOpenType) (V, error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	rule() aper.SourceRule
}
type PrivateIEField[V ProtocolPrivateValueConstraint[V]] struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s08.PrivateIEID
	Criticality   s00.Criticality
	Value         V
	received      aper.CompletePadding
}
type PrivateIEContainer[V ProtocolPrivateValueConstraint[V]] []PrivateIEField[V]

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PrivateIEField[V]) WithoutReplay() PrivateIEField[V] {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *PrivateIEField[V]) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
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
		if ok, err := v.replay.ReplayTo(v.stream,
			bb); ok || err !=
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
	// TS 36.455 V19.0.0 §9.3.8 binds the private value to @id, too.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: private field id does not match its value selector", aper.ErrInvalidValue), "PrivateIEField.Id")
	}
	if err := s08.BridgePrivateIEIDMethodMarshalAPERTo(&v.Id, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return aper.EncodeOpenTypeAligned(bb, data)
}
func (v *PrivateIEField[V]) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil PrivateIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PrivateIEField[V]{}
	if err := s08.BridgePrivateIEIDMethodUnmarshalAPERFrom(&v.Id, bb); err != nil {
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
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

type ProtocolIEFieldPair[A ProtocolOpenValueConstraint[A], B ProtocolOpenValueConstraint[B]] struct {
	Id                s00.ProtocolIEID
	FirstCriticality  s00.Criticality
	FirstValue        A
	SecondCriticality s00.Criticality
	SecondValue       B
}
type ProtocolIEContainerPair[A ProtocolOpenValueConstraint[A], B ProtocolOpenValueConstraint[B]] []ProtocolIEFieldPair[A, B]
type ProtocolIEContainerPairList[A ProtocolOpenValueConstraint[A], B ProtocolOpenValueConstraint[B]] []ProtocolIEContainerPair[A, B]
type ProtocolIESingleContainer[V ProtocolOpenValueConstraint[V]] = ProtocolIEField[V]
type ErrorIndicationDescriptor struct{}

func ErrorIndicationProcedure() ErrorIndicationDescriptor { return ErrorIndicationDescriptor{} }

// Info returns the source-derived metadata for this descriptor or binding.
func (ErrorIndicationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(0), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-errorIndication"}}}
}

type ECIDMeasurementFailureIndicationDescriptor struct{}

func ECIDMeasurementFailureIndicationProcedure() ECIDMeasurementFailureIndicationDescriptor {
	return ECIDMeasurementFailureIndicationDescriptor{}
}

// Info returns the source-derived metadata for this descriptor or binding.
func (ECIDMeasurementFailureIndicationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(3), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-e-CIDMeasurementFailureIndication"}}}
}

type ECIDMeasurementReportDescriptor struct{}

func ECIDMeasurementReportProcedure() ECIDMeasurementReportDescriptor {
	return ECIDMeasurementReportDescriptor{}
}

// Info returns the source-derived metadata for this descriptor or binding.
func (ECIDMeasurementReportDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(4), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-e-CIDMeasurementReport"}}}
}

type ECIDMeasurementTerminationDescriptor struct{}

func ECIDMeasurementTerminationProcedure() ECIDMeasurementTerminationDescriptor {
	return ECIDMeasurementTerminationDescriptor{}
}

// Info returns the source-derived metadata for this descriptor or binding.
func (ECIDMeasurementTerminationDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(5), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-e-CIDMeasurementTermination"}}}
}

type AssistanceInformationFeedbackDescriptor struct{}

func AssistanceInformationFeedbackProcedure() AssistanceInformationFeedbackDescriptor {
	return AssistanceInformationFeedbackDescriptor{}
}

// Info returns the source-derived metadata for this descriptor or binding.
func (AssistanceInformationFeedbackDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(10), Criticality: s00.CriticalityReject, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-assistanceInformationFeedback"}}}
}

// AssistanceInformationFeedbackCodec binds the complete APER value type.
func AssistanceInformationFeedbackCodec() s17.AssistanceInformationFeedbackValueCodec {
	return AssistanceInformationFeedbackProcedure().Initiating().Codec()
}

// ECIDMeasurementFailureIndicationCodec binds the complete APER value type.
func ECIDMeasurementFailureIndicationCodec() s11.ECIDMeasurementFailureIndicationValueCodec {
	return ECIDMeasurementFailureIndicationProcedure().Initiating().Codec()
}

// ECIDMeasurementReportCodec binds the complete APER value type.
func ECIDMeasurementReportCodec() s13.ECIDMeasurementReportValueCodec {
	return ECIDMeasurementReportProcedure().Initiating().Codec()
}

// ECIDMeasurementTerminationCommandCodec binds the complete APER value type.
func ECIDMeasurementTerminationCommandCodec() s06.ECIDMeasurementTerminationCommandValueCodec {
	return ECIDMeasurementTerminationProcedure().Initiating().Codec()
}

// ErrorIndicationCodec binds the complete APER value type.
func ErrorIndicationCodec() s11.ErrorIndicationValueCodec {
	return ErrorIndicationProcedure().Initiating().Codec()
}

// LPPAPDUCodec binds the complete source value type.
func LPPAPDUCodec() LPPAPDUValueCodec {
	return LPPAPDUValueCodec{path: "LPPAPDU", decode: func(data []byte, options aper.DecodeState) (LPPAPDU, error) {
		var value LPPAPDU
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return LPPAPDU{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value LPPAPDU, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v LPPAPDU, options aper.DecodeState) (LPPAPDU, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f :=
			s.Begin()
		BridgeCaptureLPPaLPPAPDU(&v, &s)
		var root aper.Snapshot
		s.
			OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v LPPAPDU, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(
			root, limits)
		f := s.Begin()
		BridgeCompareLPPaLPPAPDU(&v, &s)
		s.
			End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LPPAPDU"
		return sealed
	}(),
	}
}

// SuccessfulOutcomeCodec binds the complete source value type.
func SuccessfulOutcomeCodec() SuccessfulOutcomeValueCodec {
	return SuccessfulOutcomeValueCodec{path: "SuccessfulOutcome", decode: func(data []byte, options aper.DecodeState) (s22.SuccessfulOutcome, error) {
		var value s22.SuccessfulOutcome
		if err := s22.BridgeSuccessfulOutcomeMethodUnmarshalAPERWithOptions(&value, data, options); err != nil {
			return s22.SuccessfulOutcome{}, err
		}
		*s22.BridgeSuccessfulOutcomeFieldReceived(&value) = true
		*s22.BridgeSuccessfulOutcomeFieldReceivedBytes(&value) = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value s22.SuccessfulOutcome, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s22.BridgeSuccessfulOutcomeMethodMarshalAPERBudget((&value), budget, fresh)
	}, capture: func(v s22.SuccessfulOutcome, options aper.DecodeState) (s22.SuccessfulOutcome, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		s22.BridgeCaptureLPPaSuccessfulOutcome(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v s22.SuccessfulOutcome, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		s22.BridgeCompareLPPaSuccessfulOutcome(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SuccessfulOutcome"
		return sealed
	}(),
	}
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeValidateLPPaIEContainer[V ProtocolOpenValueConstraint[V]](fields ProtocolIEContainer[V], rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s09.ValidationReport {
	report := func() s09.ValidationReport {
		sealed := s09.ValidationReport{Complete: true}
		*s09.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s09.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s09.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s04.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		aper.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row s00.FieldInfo
			related := []aper.SourceRule{s04.BridgeLppaAdoptedRule(s00.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s04.BridgeLppaValidationRule(s00.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s04.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: s04.BridgeLppaValidationRule(s00.NotAllowed), RelatedRules: s04.BridgeLppaHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s04.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s04.BridgeLppaAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s04.BridgeLppaValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s04.BridgeLppaAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s04.BridgeLppaValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s04.BridgeLppaAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s09.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s09.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeValidateErrorIndicationBudget(v *s11.ErrorIndication, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ErrorIndication")
	}
	rows := []s00.FieldInfo{s10.ErrorIndicationIEs().Cause().Info(), s10.ErrorIndicationIEs().CriticalityDiagnostics().Info()}
	report := s11.BridgeErrorIndicationIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "ErrorIndication.protocolIEs", budget)
	BridgeWalkValidationErrorIndication(v, &report, "ErrorIndication", true)
	return report, nil
}
func BridgeValidateECIDMeasurementInitiationFailureBudget(v *s11.ECIDMeasurementInitiationFailure, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ECIDMeasurementInitiationFailure")
	}
	rows := []s00.FieldInfo{s10.ECIDMeasurementInitiationFailureIEs().ESMLCUEMeasurementID().Info(), s10.ECIDMeasurementInitiationFailureIEs().Cause().Info(), s10.ECIDMeasurementInitiationFailureIEs().CriticalityDiagnostics().Info()}
	report := s11.BridgeECIDMeasurementInitiationFailureIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "ECIDMeasurementInitiationFailure.protocolIEs", budget)
	BridgeWalkValidationECIDMeasurementInitiationFailure(v, &report, "ECIDMeasurementInitiationFailure", true)
	return report, nil
}
func BridgeValidateECIDMeasurementFailureIndicationBudget(v *s11.ECIDMeasurementFailureIndication, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ECIDMeasurementFailureIndication")
	}
	rows := []s00.FieldInfo{s06.ECIDMeasurementFailureIndicationIEs().ESMLCUEMeasurementID().Info(), s06.ECIDMeasurementFailureIndicationIEs().ENBUEMeasurementID().Info(), s06.ECIDMeasurementFailureIndicationIEs().Cause().Info()}
	report := s11.BridgeECIDMeasurementFailureIndicationIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "ECIDMeasurementFailureIndication.protocolIEs", budget)
	BridgeWalkValidationECIDMeasurementFailureIndication(v, &report, "ECIDMeasurementFailureIndication", true)
	return report, nil
}
func BridgeValidateECIDMeasurementReportBudget(v *s13.ECIDMeasurementReport, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ECIDMeasurementReport")
	}
	rows := []s00.FieldInfo{s13.ECIDMeasurementReportIEs().ESMLCUEMeasurementID().Info(), s13.ECIDMeasurementReportIEs().ENBUEMeasurementID().Info(), s13.ECIDMeasurementReportIEs().ECIDMeasurementResult().Info(), s13.ECIDMeasurementReportIEs().CellPortionID().Info()}
	report := s13.BridgeECIDMeasurementReportIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "ECIDMeasurementReport.protocolIEs", budget)
	BridgeWalkValidationECIDMeasurementReport(v, &report, "ECIDMeasurementReport", true)
	return report, nil
}
func BridgeValidateECIDMeasurementTerminationCommandBudget(v *s06.ECIDMeasurementTerminationCommand, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil ECIDMeasurementTerminationCommand")
	}
	rows := []s00.FieldInfo{s03.ECIDMeasurementTerminationCommandIEs().ESMLCUEMeasurementID().Info(), s03.ECIDMeasurementTerminationCommandIEs().ENBUEMeasurementID().Info()}
	report := s11.BridgeECIDMeasurementTerminationCommandIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "ECIDMeasurementTerminationCommand.protocolIEs", budget)
	BridgeWalkValidationECIDMeasurementTerminationCommand(v, &report, "ECIDMeasurementTerminationCommand", true)
	return report, nil
}
func BridgeValidateOTDOAInformationRequestBudget(v *s18.OTDOAInformationRequest, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil OTDOAInformationRequest")
	}
	rows := []s00.FieldInfo{s18.OTDOAInformationRequestIEs().OTDOAInformationTypeGroup().Info()}
	report := s18.BridgeOTDOAInformationRequestIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "OTDOAInformationRequest.protocolIEs", budget)
	BridgeWalkValidationOTDOAInformationRequest(v, &report, "OTDOAInformationRequest", true)
	return report, nil
}
func BridgeValidateOTDOAInformationFailureBudget(v *s12.OTDOAInformationFailure, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil OTDOAInformationFailure")
	}
	rows := []s00.FieldInfo{s10.OTDOAInformationFailureIEs().Cause().Info(), s10.OTDOAInformationFailureIEs().CriticalityDiagnostics().Info()}
	report := s12.BridgeOTDOAInformationFailureIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "OTDOAInformationFailure.protocolIEs", budget)
	BridgeWalkValidationOTDOAInformationFailure(v, &report, "OTDOAInformationFailure", true)
	return report, nil
}
func BridgeValidateAssistanceInformationFeedbackBudget(v *s17.AssistanceInformationFeedback, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil AssistanceInformationFeedback")
	}
	rows := []s00.FieldInfo{s17.AssistanceInformationFeedbackIEs().AssistanceInformationFailureList().Info(), s17.AssistanceInformationFeedbackIEs().CriticalityDiagnostics().Info()}
	report := s17.BridgeAssistanceInformationFeedbackIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "AssistanceInformationFeedback.protocolIEs", budget)
	BridgeWalkValidationAssistanceInformationFeedback(v, &report, "AssistanceInformationFeedback", true)
	return report, nil
}
func ValidateErrorIndication(v *s11.ErrorIndication, options ...aper.ValidationOption) (s09.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s09.ValidationReport{}, aper.OperationError(err, "ErrorIndication")
	}
	report, err := BridgeValidateErrorIndicationBudget(v, budget)
	if err == nil && !s20.BridgeValidationHasValueMismatch(report) {
		_, err = s11.BridgeErrorIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		err = *s09.BridgeValidationReportFieldErr(&report)
	}
	*s09.BridgeValidationReportFieldBudget(&report) = nil
	*s09.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ErrorIndication")
}
func ValidateECIDMeasurementInitiationFailure(v *s11.ECIDMeasurementInitiationFailure, options ...aper.ValidationOption) (s09.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s09.ValidationReport{}, aper.OperationError(err, "ECIDMeasurementInitiationFailure")
	}
	report, err := BridgeValidateECIDMeasurementInitiationFailureBudget(v, budget)
	if err == nil && !s20.BridgeValidationHasValueMismatch(report) {
		_, err = s11.BridgeECIDMeasurementInitiationFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		err = *s09.BridgeValidationReportFieldErr(&report)
	}
	*s09.BridgeValidationReportFieldBudget(&report) = nil
	*s09.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ECIDMeasurementInitiationFailure")
}
func ValidateECIDMeasurementFailureIndication(v *s11.ECIDMeasurementFailureIndication, options ...aper.ValidationOption) (s09.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s09.ValidationReport{}, aper.OperationError(err, "ECIDMeasurementFailureIndication")
	}
	report, err := BridgeValidateECIDMeasurementFailureIndicationBudget(v, budget)
	if err == nil && !s20.BridgeValidationHasValueMismatch(report) {
		_, err = s11.BridgeECIDMeasurementFailureIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		err = *s09.BridgeValidationReportFieldErr(&report)
	}
	*s09.BridgeValidationReportFieldBudget(&report) = nil
	*s09.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ECIDMeasurementFailureIndication")
}
func ValidateECIDMeasurementReport(v *s13.ECIDMeasurementReport, options ...aper.ValidationOption) (s09.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s09.ValidationReport{}, aper.OperationError(err, "ECIDMeasurementReport")
	}
	report, err := BridgeValidateECIDMeasurementReportBudget(v, budget)
	if err == nil && !s20.BridgeValidationHasValueMismatch(report) {
		_, err = s13.BridgeECIDMeasurementReportMethodMarshalAPERBudget(v, budget, false)
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		err = *s09.BridgeValidationReportFieldErr(&report)
	}
	*s09.BridgeValidationReportFieldBudget(&report) = nil
	*s09.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ECIDMeasurementReport")
}
func ValidateECIDMeasurementTerminationCommand(v *s06.ECIDMeasurementTerminationCommand, options ...aper.ValidationOption) (s09.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s09.ValidationReport{}, aper.OperationError(err, "ECIDMeasurementTerminationCommand")
	}
	report, err := BridgeValidateECIDMeasurementTerminationCommandBudget(v, budget)
	if err == nil && !s20.BridgeValidationHasValueMismatch(report) {
		_, err = s06.BridgeECIDMeasurementTerminationCommandMethodMarshalAPERBudget(v, budget, false)
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		err = *s09.BridgeValidationReportFieldErr(&report)
	}
	*s09.BridgeValidationReportFieldBudget(&report) = nil
	*s09.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "ECIDMeasurementTerminationCommand")
}
func ValidateOTDOAInformationRequest(v *s18.OTDOAInformationRequest, options ...aper.ValidationOption) (s09.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s09.ValidationReport{}, aper.OperationError(err, "OTDOAInformationRequest")
	}
	report, err := BridgeValidateOTDOAInformationRequestBudget(v, budget)
	if err == nil && !s20.BridgeValidationHasValueMismatch(report) {
		_, err = s18.BridgeOTDOAInformationRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		err = *s09.BridgeValidationReportFieldErr(&report)
	}
	*s09.BridgeValidationReportFieldBudget(&report) = nil
	*s09.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "OTDOAInformationRequest")
}
func ValidateOTDOAInformationFailure(v *s12.OTDOAInformationFailure, options ...aper.ValidationOption) (s09.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s09.ValidationReport{}, aper.OperationError(err, "OTDOAInformationFailure")
	}
	report, err := BridgeValidateOTDOAInformationFailureBudget(v, budget)
	if err == nil && !s20.BridgeValidationHasValueMismatch(report) {
		_, err = s12.BridgeOTDOAInformationFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		err = *s09.BridgeValidationReportFieldErr(&report)
	}
	*s09.BridgeValidationReportFieldBudget(&report) = nil
	*s09.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "OTDOAInformationFailure")
}
func ValidateAssistanceInformationFeedback(v *s17.AssistanceInformationFeedback, options ...aper.ValidationOption) (s09.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s09.ValidationReport{}, aper.OperationError(err, "AssistanceInformationFeedback")
	}
	report, err := BridgeValidateAssistanceInformationFeedbackBudget(v, budget)
	if err == nil && !s20.BridgeValidationHasValueMismatch(report) {
		_, err = s17.BridgeAssistanceInformationFeedbackMethodMarshalAPERBudget(v, budget, false)
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		err = *s09.BridgeValidationReportFieldErr(&report)
	}
	*s09.BridgeValidationReportFieldBudget(&report) = nil
	*s09.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "AssistanceInformationFeedback")
}
func BridgeValidateLPPaExtensionContainer[V ProtocolOpenValueConstraint[V]](fields ProtocolExtensionContainer[V], rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[ProtocolIEField[V]](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(ProtocolIEContainer[V], len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeWalkValidationAssistanceInformationFailureList(v *s05.AssistanceInformationFailureList, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationAssistanceInformationFailureListElem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationAssistanceInformationFailureListElem(v *s05.AssistanceInformationFailureListElem, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s09.BridgeAssistanceInformationFailureListExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationAssistanceInformationFeedback(v *s17.AssistanceInformationFeedback, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s17.AssistanceInformationFeedbackIEs().AssistanceInformationFailureList().Info(), s17.AssistanceInformationFeedbackIEs().CriticalityDiagnostics().Info()}
			s11.BridgeMergeNestedValidation(report, s17.BridgeAssistanceInformationFeedbackIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(24):
				if value, ok := fields[i].Value.AsAssistanceInformationFailureList(); ok {
					BridgeWalkValidationAssistanceInformationFailureList(value, report, fmt.Sprintf("%s[%d]{id=24}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(1):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=1}", nestedPath, i), false)
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationAssistanceInformationMetaData(v *s05.AssistanceInformationMetaData, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s09.BridgeAssistanceInformationMetaDataExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationBitmapsforNPRS(v *s05.BitmapsforNPRS, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationCause(v *s05.Cause, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationCriticalityDiagnostics(v *s09.CriticalityDiagnostics, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEsCriticalityDiagnostics != nil {
		BridgeWalkValidationCriticalityDiagnosticsIEList(&v.IEsCriticalityDiagnostics, report, path+".iEsCriticalityDiagnostics", false)
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s11.BridgeCriticalityDiagnosticsExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCriticalityDiagnosticsIEList(v *s05.CriticalityDiagnosticsIEList, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationCriticalityDiagnosticsIEListElem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCriticalityDiagnosticsIEListElem(v *s05.CriticalityDiagnosticsIEListElem, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s11.BridgeCriticalityDiagnosticsIEListExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationECGI(v *s05.ECGI, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s11.BridgeECGIExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationECIDMeasurementFailureIndication(v *s11.ECIDMeasurementFailureIndication, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s06.ECIDMeasurementFailureIndicationIEs().ESMLCUEMeasurementID().Info(), s06.ECIDMeasurementFailureIndicationIEs().ENBUEMeasurementID().Info(), s06.ECIDMeasurementFailureIndicationIEs().Cause().Info()}
			s11.BridgeMergeNestedValidation(report, s11.BridgeECIDMeasurementFailureIndicationIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(0):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=0}", nestedPath, i), false)
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationECIDMeasurementInitiationFailure(v *s11.ECIDMeasurementInitiationFailure, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s10.ECIDMeasurementInitiationFailureIEs().ESMLCUEMeasurementID().Info(), s10.ECIDMeasurementInitiationFailureIEs().Cause().Info(), s10.ECIDMeasurementInitiationFailureIEs().CriticalityDiagnostics().Info()}
			s11.BridgeMergeNestedValidation(report, s11.BridgeECIDMeasurementInitiationFailureIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(0):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=0}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(1):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=1}", nestedPath, i), false)
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationECIDMeasurementReport(v *s13.ECIDMeasurementReport, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s13.ECIDMeasurementReportIEs().ESMLCUEMeasurementID().Info(), s13.ECIDMeasurementReportIEs().ENBUEMeasurementID().Info(), s13.ECIDMeasurementReportIEs().ECIDMeasurementResult().Info(), s13.ECIDMeasurementReportIEs().CellPortionID().Info()}
			s11.BridgeMergeNestedValidation(report, s13.BridgeECIDMeasurementReportIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(7):
				if value, ok := fields[i].Value.AsECIDMeasurementResult(); ok {
					BridgeWalkValidationECIDMeasurementResult(value, report, fmt.Sprintf("%s[%d]{id=7}", nestedPath, i), false)
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationECIDMeasurementResult(v *s13.ECIDMeasurementResult, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationECGI(&v.ServingCellID, report, path+".servingCell-ID", false)
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.EUTRANAccessPointPosition != nil {
		BridgeWalkValidationEUTRANAccessPointPosition(v.EUTRANAccessPointPosition, report, path+".e-UTRANAccessPointPosition", false)
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.MeasuredResults != nil {
		BridgeWalkValidationMeasuredResults(&v.MeasuredResults, report, path+".measuredResults", false)
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationECIDMeasurementTerminationCommand(v *s06.ECIDMeasurementTerminationCommand, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s03.ECIDMeasurementTerminationCommandIEs().ESMLCUEMeasurementID().Info(), s03.ECIDMeasurementTerminationCommandIEs().ENBUEMeasurementID().Info()}
			s11.BridgeMergeNestedValidation(report, s11.BridgeECIDMeasurementTerminationCommandIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationEUTRANAccessPointPosition(v *s06.EUTRANAccessPointPosition, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationErrorIndication(v *s11.ErrorIndication, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s10.ErrorIndicationIEs().Cause().Info(), s10.ErrorIndicationIEs().CriticalityDiagnostics().Info()}
			s11.BridgeMergeNestedValidation(report, s11.BridgeErrorIndicationIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(0):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=0}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(1):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=1}", nestedPath, i), false)
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInitiatingMessage(v *s21.InitiatingMessage, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInterRATMeasuredResultsValue(v *s19.InterRATMeasuredResultsValue, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.InterRATMeasuredResultsValueChoiceResultGERAN {
		if v.ResultGERAN != nil {
			BridgeWalkValidationResultGERAN(&v.ResultGERAN, report, path+".resultGERAN", false)
		}
	}
	if v.Choice == s00.InterRATMeasuredResultsValueChoiceResultUTRAN {
		if v.ResultUTRAN != nil {
			BridgeWalkValidationResultUTRAN(&v.ResultUTRAN, report, path+".resultUTRAN", false)
		}
	}
	if v.Choice == s00.InterRATMeasuredResultsValueChoiceResultNR {
		if v.ResultNR != nil {
			BridgeWalkValidationResultNR(&v.ResultNR, report, path+".resultNR", false)
		}
	}
}
func BridgeWalkValidationInterRATMeasurementQuantities(v *s06.InterRATMeasurementQuantities, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s06.InterRATMeasurementQuantitiesItemIEs().InterRATMeasurementQuantitiesItem().Info()}
		s11.BridgeMergeNestedValidation(report, s11.BridgeInterRATMeasurementQuantitiesItemIEValueValidateLPPaIEContainer(s06.InterRATMeasurementQuantitiesItemIEContainer{field}, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		fields := s06.InterRATMeasurementQuantitiesItemIEContainer{field}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(16):
				if value, ok := fields[i].Value.AsInterRATMeasurementQuantitiesItem(); ok {
					BridgeWalkValidationInterRATMeasurementQuantitiesItem(value, report, fmt.Sprintf("%s[%d]{id=16}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationInterRATMeasurementQuantitiesItem(v *s06.InterRATMeasurementQuantitiesItem, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s11.BridgeInterRATMeasurementQuantitiesValueExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInterRATMeasurementResult(v *s20.InterRATMeasurementResult, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationInterRATMeasuredResultsValue(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationMeasuredResults(v *s13.MeasuredResults, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationMeasuredResultsValue(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationMeasuredResultsValue(v *s13.MeasuredResultsValue, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == s00.MeasuredResultsValueChoiceResultRSRP {
		if v.ResultRSRP != nil {
			BridgeWalkValidationResultRSRP(&v.ResultRSRP, report, path+".resultRSRP", false)
		}
	}
	if v.Choice == s00.MeasuredResultsValueChoiceResultRSRQ {
		if v.ResultRSRQ != nil {
			BridgeWalkValidationResultRSRQ(&v.ResultRSRQ, report, path+".resultRSRQ", false)
		}
	}
}
func BridgeWalkValidationMeasurementQuantities(v *s06.MeasurementQuantities, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s07.MeasurementQuantitiesItemIEs().MeasurementQuantitiesItem().Info()}
		s11.BridgeMergeNestedValidation(report, s11.BridgeMeasurementQuantitiesItemIEValueValidateLPPaIEContainer(s06.MeasurementQuantitiesItemIEContainer{field}, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		fields := s06.MeasurementQuantitiesItemIEContainer{field}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(11):
				if value, ok := fields[i].Value.AsMeasurementQuantitiesItem(); ok {
					BridgeWalkValidationMeasurementQuantitiesItem(value, report, fmt.Sprintf("%s[%d]{id=11}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationMeasurementQuantitiesItem(v *s06.MeasurementQuantitiesItem, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s11.BridgeMeasurementQuantitiesValueExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationNPRSConfiguration(v *s07.NPRSConfiguration, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.NPRSSubframePartA != nil {
		BridgeWalkValidationNPRSSubframePartA(v.NPRSSubframePartA, report, path+".nPRSSubframePartA", false)
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.NPRSSubframePartB != nil {
		BridgeWalkValidationNPRSSubframePartB(v.NPRSSubframePartB, report, path+".nPRSSubframePartB", false)
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationNPRSMutingConfiguration(v *s07.NPRSMutingConfiguration, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationNPRSSubframePartA(v *s07.NPRSSubframePartA, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationBitmapsforNPRS(&v.BitmapsforNPRS, report, path+".bitmapsforNPRS", false)
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.NPRSMutingConfiguration != nil {
		BridgeWalkValidationNPRSMutingConfiguration(v.NPRSMutingConfiguration, report, path+".nPRSMutingConfiguration", false)
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationNPRSSubframePartB(v *s07.NPRSSubframePartB, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.NPRSMutingConfiguration != nil {
		BridgeWalkValidationNPRSMutingConfiguration(v.NPRSMutingConfiguration, report, path+".nPRSMutingConfiguration", false)
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationNRCGI(v *s07.NRCGI, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s11.BridgeNRCGIExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationOTDOAInformationFailure(v *s12.OTDOAInformationFailure, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s10.OTDOAInformationFailureIEs().Cause().Info(), s10.OTDOAInformationFailureIEs().CriticalityDiagnostics().Info()}
			s11.BridgeMergeNestedValidation(report, s12.BridgeOTDOAInformationFailureIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(0):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, fmt.Sprintf("%s[%d]{id=0}", nestedPath, i), false)
				}
			case s00.ProtocolIEID(1):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, fmt.Sprintf("%s[%d]{id=1}", nestedPath, i), false)
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationOTDOAInformationRequest(v *s18.OTDOAInformationRequest, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []s00.FieldInfo{s18.OTDOAInformationRequestIEs().OTDOAInformationTypeGroup().Info()}
			s11.BridgeMergeNestedValidation(report, s18.BridgeOTDOAInformationRequestIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(9):
				if value, ok := fields[i].Value.AsOTDOAInformationTypeGroup(); ok {
					BridgeWalkValidationOTDOAInformationType(value, report, fmt.Sprintf("%s[%d]{id=9}", nestedPath, i), false)
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationOTDOAInformationType(v *s07.OTDOAInformationType, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := fmt.Sprintf("%s[%d]", path, i)
		rows := []s00.FieldInfo{s07.OTDOAInformationTypeIEs().OTDOAInformationTypeItem().Info()}
		s11.BridgeMergeNestedValidation(report, s12.BridgeOTDOAInformationTypeIEValueValidateLPPaIEContainer(s07.OTDOAInformationTypeIEContainer{field}, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
		fields := s07.OTDOAInformationTypeIEContainer{field}
		for i := range fields {
			if *s09.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case s00.ProtocolIEID(10):
				if value, ok := fields[i].Value.AsOTDOAInformationTypeItem(); ok {
					BridgeWalkValidationOTDOAInformationTypeItem(value, report, fmt.Sprintf("%s[%d]{id=10}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationOTDOAInformationTypeItem(v *s07.OTDOAInformationTypeItem, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s12.BridgeOTDOAInformationTypeItemExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPRSFrequencyHoppingConfiguration(v *s08.PRSFrequencyHoppingConfiguration, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationPRSFrequencyHoppingConfigurationBandPositions(&v.BandPositions, report, path+".bandPositions", false)
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s12.BridgePRSFrequencyHoppingConfigurationItemIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPRSFrequencyHoppingConfigurationBandPositions(v *s00.PRSFrequencyHoppingConfigurationBandPositions, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationPRSMutingConfiguration(v *s08.PRSMutingConfiguration, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationPosSIBSegments(v *s08.PosSIBSegments, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationPosSIBSegmentsElem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationPosSIBSegmentsElem(v *s08.PosSIBSegmentsElem, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s12.BridgePosSIBSegmentsExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPosSIBs(v *s10.PosSIBs, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationPosSIBsElem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationPosSIBsElem(v *s10.PosSIBsElem, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationPosSIBSegments(&v.PosSIBSegments, report, path+".posSIB-Segments", false)
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.AssistanceInformationMetaData != nil {
		BridgeWalkValidationAssistanceInformationMetaData(v.AssistanceInformationMetaData, report, path+".assistanceInformationMetaData", false)
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s12.BridgePosSIBsExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPrivateIEID(v *s08.PrivateIEID, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationPrivateMessage(v *s12.PrivateMessage, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationRequestedSRSTransmissionCharacteristics(v *s08.RequestedSRSTransmissionCharacteristics, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationResultGERAN(v *s12.ResultGERAN, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationResultGERANItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationResultGERANItem(v *s12.ResultGERANItem, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s12.BridgeResultGERANItemExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationResultNR(v *s19.ResultNR, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationResultNRItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationResultNRItem(v *s19.ResultNRItem, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{s19.ResultNRItemExtIEs().ResultsPerSSBIndexList().Info(), s19.ResultNRItemExtIEs().NRCGI().Info()}
				s11.BridgeMergeNestedValidation(report, s20.BridgeResultNRItemExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case s00.ProtocolIEID(25):
					if value, ok := fields[i].ExtensionValue.AsResultsPerSSBIndexList(); ok {
						BridgeWalkValidationResultsPerSSBIndexList(value, report, fmt.Sprintf("%s[%d]{id=25}", nestedPath, i), false)
					}
				case s00.ProtocolIEID(27):
					if value, ok := fields[i].ExtensionValue.AsNRCGI(); ok {
						BridgeWalkValidationNRCGI(value, report, fmt.Sprintf("%s[%d]{id=27}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationResultRSRP(v *s12.ResultRSRP, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationResultRSRPItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationResultRSRPItem(v *s12.ResultRSRPItem, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.ECGI != nil {
		BridgeWalkValidationECGI(v.ECGI, report, path+".eCGI", false)
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s12.BridgeResultRSRPItemExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationResultRSRQ(v *s13.ResultRSRQ, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationResultRSRQItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationResultRSRQItem(v *s13.ResultRSRQItem, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.ECGI != nil {
		BridgeWalkValidationECGI(v.ECGI, report, path+".eCGI", false)
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s13.BridgeResultRSRQItemExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationResultUTRAN(v *s14.ResultUTRAN, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationResultUTRANItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationResultUTRANItem(v *s14.ResultUTRANItem, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationResultUTRANItemPhysCellIDUTRAN(&v.PhysCellIDUTRAN, report, path+".physCellIDUTRAN", false)
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s14.BridgeResultUTRANItemExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationResultUTRANItemPhysCellIDUTRAN(v *s08.ResultUTRANItemPhysCellIDUTRAN, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationResultsPerSSBIndexItem(v *s14.ResultsPerSSBIndexItem, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []s00.FieldInfo{}
				s11.BridgeMergeNestedValidation(report, s14.BridgeResultsPerSSBIndexItemExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *s09.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *s09.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationResultsPerSSBIndexList(v *s14.ResultsPerSSBIndexList, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationResultsPerSSBIndexItem(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationSRSConfigurationForAllCells(v *s09.SRSConfigurationForAllCells, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *s09.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationSRSConfigurationForOneCell(&(*v)[i], report, fmt.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationSRSConfigurationForOneCell(v *s09.SRSConfigurationForOneCell, report *s09.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*s09.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldCapture(v *ECIDMeasurementInitiationResponseSuccessfulBinding) *func(s22.ECIDMeasurementInitiationResponse, aper.DecodeState) (s22.ECIDMeasurementInitiationResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldCompare(v *ECIDMeasurementInitiationResponseSuccessfulBinding) *func(s22.ECIDMeasurementInitiationResponse, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldContext(v *ECIDMeasurementInitiationResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldDecode(v *ECIDMeasurementInitiationResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s22.ECIDMeasurementInitiationResponse, error) {
	return &v.decode
}
func BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldEncode(v *ECIDMeasurementInitiationResponseSuccessfulBinding) *func(*s22.ECIDMeasurementInitiationResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldInfo(v *ECIDMeasurementInitiationResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldInject(v *ECIDMeasurementInitiationResponseSuccessfulBinding) *func(s22.ECIDMeasurementInitiationResponse) s22.SuccessfulValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldValidate(v *ECIDMeasurementInitiationResponseSuccessfulBinding) *func(*s22.ECIDMeasurementInitiationResponse, *aper.DecodeBudget) (s09.ValidationReport, error) {
	return &v.validate
}
func BridgeLPPAPDUAPERValueFieldContext(v *LPPAPDUAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLPPAPDUAPERValueFieldReceived(v *LPPAPDUAPERValue) *aper.WireSpan { return &v.received }
func BridgeLPPAPDUAPERValueFieldReplay(v *LPPAPDUAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeLPPAPDUAPERValueFieldWithoutReplay(v *LPPAPDUAPERValue) *bool     { return &v.withoutReplay }
func BridgeLPPAPDUFieldKnownOpenBytes(v *LPPAPDU) *uint64                    { return &v.knownOpenBytes }
func BridgeLPPAPDUFieldPerOpenTypePadding(v *LPPAPDU) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeLPPAPDUFieldPerPadding(v *LPPAPDU) *aper.CompletePadding { return &v.perPadding }
func BridgeLPPAPDUFieldReceived(v *LPPAPDU) *bool                   { return &v.received }
func BridgeLPPAPDUFieldReceivedBytes(v *LPPAPDU) *aper.WireSpan     { return &v.receivedBytes }
func BridgeLPPAPDUFieldReplay(v *LPPAPDU) *aper.Snapshot            { return &v.replay }
func BridgeLPPAPDUFieldStream(v *LPPAPDU) *aper.WireSpan            { return &v.stream }
func BridgeLPPAPDUFieldWithoutReplay(v *LPPAPDU) *bool              { return &v.withoutReplay }
func BridgeLPPAPDUMethodMarshalAPERBudget(v *LPPAPDU, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLPPAPDUMethodMarshalAPERChanged(v *LPPAPDU, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeLPPAPDUMethodMarshalAPERChangedValue(v *LPPAPDU, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeLPPAPDUMethodMarshalAPERFreshValue(v *LPPAPDU, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeLPPAPDUMethodMarshalAPERLegacy(v *LPPAPDU) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeLPPAPDUMethodMarshalAPERPlanned(v *LPPAPDU, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeLPPAPDUMethodMarshalAPERTo(v *LPPAPDU, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLPPAPDUMethodUnmarshalAPERFrom(v *LPPAPDU, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLPPAPDUMethodUnmarshalAPERLegacy(v *LPPAPDU, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeLPPAPDUMethodUnmarshalAPERWithOptions(v *LPPAPDU, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeLPPAPDUValueCodecFieldCapture(v *LPPAPDUValueCodec) *func(LPPAPDU, aper.DecodeState) (LPPAPDU, aper.Snapshot) {
	return &v.capture
}
func BridgeLPPAPDUValueCodecFieldCompare(v *LPPAPDUValueCodec) *func(LPPAPDU, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeLPPAPDUValueCodecFieldContext(v *LPPAPDUValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLPPAPDUValueCodecFieldDecode(v *LPPAPDUValueCodec) *func([]byte, aper.DecodeState) (LPPAPDU, error) {
	return &v.decode
}
func BridgeLPPAPDUValueCodecFieldEncode(v *LPPAPDUValueCodec) *func(LPPAPDU, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLPPAPDUValueCodecFieldPath(v *LPPAPDUValueCodec) *aper.Path { return &v.path }
func BridgeLPPAPDUValueCodecMethodEncodeBudget(v LPPAPDUValueCodec, a0 LPPAPDU, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeLPPAPDUValueCodecMethodEncodeChanged(v LPPAPDUValueCodec, a0 LPPAPDU, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOAInformationResponseSuccessfulBindingFieldCapture(v *OTDOAInformationResponseSuccessfulBinding) *func(s18.OTDOAInformationResponse, aper.DecodeState) (s18.OTDOAInformationResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeOTDOAInformationResponseSuccessfulBindingFieldCompare(v *OTDOAInformationResponseSuccessfulBinding) *func(s18.OTDOAInformationResponse, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeOTDOAInformationResponseSuccessfulBindingFieldContext(v *OTDOAInformationResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationResponseSuccessfulBindingFieldDecode(v *OTDOAInformationResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s18.OTDOAInformationResponse, error) {
	return &v.decode
}
func BridgeOTDOAInformationResponseSuccessfulBindingFieldEncode(v *OTDOAInformationResponseSuccessfulBinding) *func(*s18.OTDOAInformationResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOAInformationResponseSuccessfulBindingFieldInfo(v *OTDOAInformationResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeOTDOAInformationResponseSuccessfulBindingFieldInject(v *OTDOAInformationResponseSuccessfulBinding) *func(s18.OTDOAInformationResponse) s22.SuccessfulValue {
	return &v.inject
}
func BridgeOTDOAInformationResponseSuccessfulBindingFieldValidate(v *OTDOAInformationResponseSuccessfulBinding) *func(*s18.OTDOAInformationResponse, *aper.DecodeBudget) (s09.ValidationReport, error) {
	return &v.validate
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
func BridgeSuccessfulOutcomeValueCodecFieldCapture(v *SuccessfulOutcomeValueCodec) *func(s22.SuccessfulOutcome, aper.DecodeState) (s22.SuccessfulOutcome, aper.Snapshot) {
	return &v.capture
}
func BridgeSuccessfulOutcomeValueCodecFieldCompare(v *SuccessfulOutcomeValueCodec) *func(s22.SuccessfulOutcome, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeSuccessfulOutcomeValueCodecFieldContext(v *SuccessfulOutcomeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSuccessfulOutcomeValueCodecFieldDecode(v *SuccessfulOutcomeValueCodec) *func([]byte, aper.DecodeState) (s22.SuccessfulOutcome, error) {
	return &v.decode
}
func BridgeSuccessfulOutcomeValueCodecFieldEncode(v *SuccessfulOutcomeValueCodec) *func(s22.SuccessfulOutcome, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSuccessfulOutcomeValueCodecFieldPath(v *SuccessfulOutcomeValueCodec) *aper.Path {
	return &v.path
}
func BridgeSuccessfulOutcomeValueCodecMethodEncodeBudget(v SuccessfulOutcomeValueCodec, a0 s22.SuccessfulOutcome, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSuccessfulOutcomeValueCodecMethodEncodeChanged(v SuccessfulOutcomeValueCodec, a0 s22.SuccessfulOutcome, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUTDOAInformationResponseSuccessfulBindingFieldCapture(v *UTDOAInformationResponseSuccessfulBinding) *func(s17.UTDOAInformationResponse, aper.DecodeState) (s17.UTDOAInformationResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeUTDOAInformationResponseSuccessfulBindingFieldCompare(v *UTDOAInformationResponseSuccessfulBinding) *func(s17.UTDOAInformationResponse, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeUTDOAInformationResponseSuccessfulBindingFieldContext(v *UTDOAInformationResponseSuccessfulBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationResponseSuccessfulBindingFieldDecode(v *UTDOAInformationResponseSuccessfulBinding) *func([]byte, aper.DecodeState) (s17.UTDOAInformationResponse, error) {
	return &v.decode
}
func BridgeUTDOAInformationResponseSuccessfulBindingFieldEncode(v *UTDOAInformationResponseSuccessfulBinding) *func(*s17.UTDOAInformationResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTDOAInformationResponseSuccessfulBindingFieldInfo(v *UTDOAInformationResponseSuccessfulBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUTDOAInformationResponseSuccessfulBindingFieldInject(v *UTDOAInformationResponseSuccessfulBinding) *func(s17.UTDOAInformationResponse) s22.SuccessfulValue {
	return &v.inject
}
func BridgeUTDOAInformationResponseSuccessfulBindingFieldValidate(v *UTDOAInformationResponseSuccessfulBinding) *func(*s17.UTDOAInformationResponse, *aper.DecodeBudget) (s09.ValidationReport, error) {
	return &v.validate
}
