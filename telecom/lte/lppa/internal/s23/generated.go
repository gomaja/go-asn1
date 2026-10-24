// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s23 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s23

import (
	q6 "fmt"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q23 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q15 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q19 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q21 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	q13 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	q26 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	q22 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	q7 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	q11 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	q17 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s12"
	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s13"
	q27 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s14"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s16"
	q18 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s17"
	q16 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s18"
	q25 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s19"
	q24 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s20"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s22"
	q20 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

type APERValue[T any] struct {
	context       q4.BridgeCodecContext
	Value         T
	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v APERValue[T]) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v APERValue[T]) WithoutReplay() APERValue[T] {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// ValueCodec binds one source value type to its complete APER encoding.
type ValueCodec[T any] struct {
	context q4.BridgeCodecContext
	capture func(T, q5.DecodeState) (T, q5.Snapshot)
	compare func(T, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan
	path    q5.Path
	decode  func([]byte, q5.DecodeState) (T, error)
	encode  func(T, bool, *q5.DecodeBudget) ([]byte, error)
}

func (c ValueCodec[T]) New(value T) (APERValue[T], error) {
	if c.encode == nil {
		return APERValue[T]{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return APERValue[T]{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return APERValue[T]{}, q5.OperationError(err, "Value.New")
	}
	return APERValue[T]{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c ValueCodec[T]) DecodeAPER(data []byte, options ...q5.DecodeOption) (APERValue[T], q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return APERValue[T]{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return APERValue[T]{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return APERValue[T]{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return APERValue[T]{}, report, q5.OperationError(err, c.path)
	}
	return APERValue[T]{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ValueCodec[T]) EncodeAPER(value APERValue[T], options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q5.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q5.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q5.OperationError(err, c.path)
}
func (c ValueCodec[T]) encodeBudget(value T, fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ValueCodec[T]) encodeChanged(value T, fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

type IEBinding[T any, V ProtocolOpenValueConstraint[V]] struct {
	info   q4.FieldInfo
	codec  ValueCodec[T]
	inject func(T) V
	get    func(*V) (*T, bool)
}

func (b IEBinding[T, V]) Info() q4.FieldInfo   { return b.info }
func (b IEBinding[T, V]) Codec() ValueCodec[T] { return b.codec }
func (b IEBinding[T, V]) New(value T) (ProtocolIEField[V], error) {
	if b.inject == nil {
		return ProtocolIEField[V]{}, q5.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return ProtocolIEField[V]{}, q5.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ProtocolIEField[V]{}, q5.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), value); err != nil {
		return ProtocolIEField[V]{}, q5.OperationError(err, "Value.New")
	}
	return ProtocolIEField[V]{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q5.OperationError(nil, "Value.New")
}
func (b IEBinding[T, V]) Get(field *ProtocolIEField[V]) (*T, bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

type ExtensionBinding[T any, V ProtocolOpenValueConstraint[V]] struct {
	info   q4.FieldInfo
	codec  ValueCodec[T]
	inject func(T) V
	get    func(*V) (*T, bool)
}

func (b ExtensionBinding[T, V]) Info() q4.FieldInfo   { return b.info }
func (b ExtensionBinding[T, V]) Codec() ValueCodec[T] { return b.codec }
func (b ExtensionBinding[T, V]) New(value T) (ProtocolExtensionField[V], error) {
	if b.inject == nil {
		return ProtocolExtensionField[V]{}, q5.OperationError(q6.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return ProtocolExtensionField[V]{}, q5.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ProtocolExtensionField[V]{}, q5.OperationError(q6.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), value); err != nil {
		return ProtocolExtensionField[V]{}, q5.OperationError(err, "Value.New")
	}
	return ProtocolExtensionField[V]{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, q5.OperationError(nil, "Value.New")
}
func (b ExtensionBinding[T, V]) Get(field *ProtocolExtensionField[V]) (*T, bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

type InitiatingBinding[T any] struct {
	context  q4.BridgeCodecContext
	capture  func(T, q5.DecodeState) (T, q5.Snapshot)
	compare  func(T, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan
	info     q4.ProcedureInfo
	validate func(*T, *q5.DecodeBudget) (q7.ValidationReport, error)
	encode   func(*T, bool, *q5.DecodeBudget) ([]byte, error)
	decode   func([]byte, q5.DecodeState) (T, error)
	inject   func(T) q8.InitiatingValue
}

func (b InitiatingBinding[T]) Info() q4.ProcedureInfo { return b.info }
func (b InitiatingBinding[T]) Codec() ValueCodec[T] {
	return ValueCodec[T]{path: q5.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value T, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}
func (b InitiatingBinding[T]) Build(body T, transactionID q4.LPPATransactionID, options ...q5.BuildOption) (q8.InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return q8.InitiatingMessage{}, q5.OperationError(q6.Errorf("%w: unbound procedure binding", q5.ErrInvalidValue), "Build")
	}
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q8.InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if err := q4.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return q8.InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return q8.InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		return q8.InitiatingMessage{}, q5.OperationError(*q7.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q7.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q8.InitiatingMessage{}, q5.OperationError(&q7.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return q8.InitiatingMessage{}, q5.OperationError(q6.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), body); err != nil {
		return q8.InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	return q8.InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q5.OperationError(nil, "Build")
}

type SuccessfulBinding[T any] struct {
	context  q4.BridgeCodecContext
	capture  func(T, q5.DecodeState) (T, q5.Snapshot)
	compare  func(T, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan
	info     q4.ProcedureInfo
	validate func(*T, *q5.DecodeBudget) (q7.ValidationReport, error)
	encode   func(*T, bool, *q5.DecodeBudget) ([]byte, error)
	decode   func([]byte, q5.DecodeState) (T, error)
	inject   func(T) q9.SuccessfulValue
}

func (b SuccessfulBinding[T]) Info() q4.ProcedureInfo { return b.info }
func (b SuccessfulBinding[T]) Codec() ValueCodec[T] {
	return ValueCodec[T]{path: q5.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value T, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}
func (b SuccessfulBinding[T]) Build(body T, transactionID q4.LPPATransactionID, options ...q5.BuildOption) (q9.SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(q6.Errorf("%w: unbound procedure binding", q5.ErrInvalidValue), "Build")
	}
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	if err := q4.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(*q7.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q7.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q9.SuccessfulOutcome{}, q5.OperationError(&q7.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(q6.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), body); err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	return q9.SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q5.OperationError(nil, "Build")
}

type UnsuccessfulBinding[T any] struct {
	context  q4.BridgeCodecContext
	capture  func(T, q5.DecodeState) (T, q5.Snapshot)
	compare  func(T, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan
	info     q4.ProcedureInfo
	validate func(*T, *q5.DecodeBudget) (q7.ValidationReport, error)
	encode   func(*T, bool, *q5.DecodeBudget) ([]byte, error)
	decode   func([]byte, q5.DecodeState) (T, error)
	inject   func(T) q10.UnsuccessfulValue
}

func (b UnsuccessfulBinding[T]) Info() q4.ProcedureInfo { return b.info }
func (b UnsuccessfulBinding[T]) Codec() ValueCodec[T] {
	return ValueCodec[T]{path: q5.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value T, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}
func (b UnsuccessfulBinding[T]) Build(body T, transactionID q4.LPPATransactionID, options ...q5.BuildOption) (q10.UnsuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return q10.UnsuccessfulOutcome{}, q5.OperationError(q6.Errorf("%w: unbound procedure binding", q5.ErrInvalidValue), "Build")
	}
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q10.UnsuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	if err := q4.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return q10.UnsuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return q10.UnsuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		return q10.UnsuccessfulOutcome{}, q5.OperationError(*q7.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q7.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q10.UnsuccessfulOutcome{}, q5.OperationError(&q7.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return q10.UnsuccessfulOutcome{}, q5.OperationError(q6.Errorf("unsuccessfulOutcome.value: %w", err), "Build")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), body); err != nil {
		return q10.UnsuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	return q10.UnsuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q5.OperationError(nil, "Build")
}
func NewErrorIndication(fields q11.ErrorIndicationIEContainer, options ...q5.BuildOption) (q12.ErrorIndication, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q12.ErrorIndication{}, q5.OperationError(err, "ErrorIndication")
	}
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q11.ErrorIndicationIEField](bb, uint64(len(fields))); err != nil {
		return q12.ErrorIndication{}, q5.OperationError(err, "ErrorIndication")
	}
	v := q12.ErrorIndication{ProtocolIEs: make(q11.ErrorIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateErrorIndicationBudget(&v, budget)
	if err != nil {
		return q12.ErrorIndication{}, q5.OperationError(err, "ErrorIndication")
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		return q12.ErrorIndication{}, q5.OperationError(*q7.BridgeValidationReportFieldErr(&report), "ErrorIndication")
	}
	if issues := q7.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q12.ErrorIndication{}, q5.OperationError(&q7.BuildError{Issues: issues}, "ErrorIndication")
	}
	if _, err := q12.BridgeErrorIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return q12.ErrorIndication{}, q5.OperationError(q6.Errorf("%s %w", "ErrorIndication.protocolIEs:", err), "ErrorIndication")
	}
	return v, q5.OperationError(nil, "ErrorIndication")
}
func NewECIDMeasurementInitiationFailure(fields q7.ECIDMeasurementInitiationFailureIEContainer, options ...q5.BuildOption) (q12.ECIDMeasurementInitiationFailure, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q12.ECIDMeasurementInitiationFailure{}, q5.OperationError(err, "ECIDMeasurementInitiationFailure")
	}
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q7.ECIDMeasurementInitiationFailureIEField](bb, uint64(len(fields))); err != nil {
		return q12.ECIDMeasurementInitiationFailure{}, q5.OperationError(err, "ECIDMeasurementInitiationFailure")
	}
	v := q12.ECIDMeasurementInitiationFailure{ProtocolIEs: make(q7.ECIDMeasurementInitiationFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateECIDMeasurementInitiationFailureBudget(&v, budget)
	if err != nil {
		return q12.ECIDMeasurementInitiationFailure{}, q5.OperationError(err, "ECIDMeasurementInitiationFailure")
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		return q12.ECIDMeasurementInitiationFailure{}, q5.OperationError(*q7.BridgeValidationReportFieldErr(&report), "ECIDMeasurementInitiationFailure")
	}
	if issues := q7.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q12.ECIDMeasurementInitiationFailure{}, q5.OperationError(&q7.BuildError{Issues: issues}, "ECIDMeasurementInitiationFailure")
	}
	if _, err := q12.BridgeECIDMeasurementInitiationFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return q12.ECIDMeasurementInitiationFailure{}, q5.OperationError(q6.Errorf("%s %w", "ECIDMeasurementInitiationFailure.protocolIEs:", err), "ECIDMeasurementInitiationFailure")
	}
	return v, q5.OperationError(nil, "ECIDMeasurementInitiationFailure")
}
func NewECIDMeasurementFailureIndication(fields q13.ECIDMeasurementFailureIndicationIEContainer, options ...q5.BuildOption) (q12.ECIDMeasurementFailureIndication, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q12.ECIDMeasurementFailureIndication{}, q5.OperationError(err, "ECIDMeasurementFailureIndication")
	}
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q13.ECIDMeasurementFailureIndicationIEField](bb, uint64(len(fields))); err != nil {
		return q12.ECIDMeasurementFailureIndication{}, q5.OperationError(err, "ECIDMeasurementFailureIndication")
	}
	v := q12.ECIDMeasurementFailureIndication{ProtocolIEs: make(q13.ECIDMeasurementFailureIndicationIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateECIDMeasurementFailureIndicationBudget(&v, budget)
	if err != nil {
		return q12.ECIDMeasurementFailureIndication{}, q5.OperationError(err, "ECIDMeasurementFailureIndication")
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		return q12.ECIDMeasurementFailureIndication{}, q5.OperationError(*q7.BridgeValidationReportFieldErr(&report), "ECIDMeasurementFailureIndication")
	}
	if issues := q7.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q12.ECIDMeasurementFailureIndication{}, q5.OperationError(&q7.BuildError{Issues: issues}, "ECIDMeasurementFailureIndication")
	}
	if _, err := q12.BridgeECIDMeasurementFailureIndicationMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return q12.ECIDMeasurementFailureIndication{}, q5.OperationError(q6.Errorf("%s %w", "ECIDMeasurementFailureIndication.protocolIEs:", err), "ECIDMeasurementFailureIndication")
	}
	return v, q5.OperationError(nil, "ECIDMeasurementFailureIndication")
}
func NewECIDMeasurementReport(fields q14.ECIDMeasurementReportIEContainer, options ...q5.BuildOption) (q14.ECIDMeasurementReport, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q14.ECIDMeasurementReport{}, q5.OperationError(err, "ECIDMeasurementReport")
	}
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q14.ECIDMeasurementReportIEField](bb, uint64(len(fields))); err != nil {
		return q14.ECIDMeasurementReport{}, q5.OperationError(err, "ECIDMeasurementReport")
	}
	v := q14.ECIDMeasurementReport{ProtocolIEs: make(q14.ECIDMeasurementReportIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateECIDMeasurementReportBudget(&v, budget)
	if err != nil {
		return q14.ECIDMeasurementReport{}, q5.OperationError(err, "ECIDMeasurementReport")
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		return q14.ECIDMeasurementReport{}, q5.OperationError(*q7.BridgeValidationReportFieldErr(&report), "ECIDMeasurementReport")
	}
	if issues := q7.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q14.ECIDMeasurementReport{}, q5.OperationError(&q7.BuildError{Issues: issues}, "ECIDMeasurementReport")
	}
	if _, err := q14.BridgeECIDMeasurementReportMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return q14.ECIDMeasurementReport{}, q5.OperationError(q6.Errorf("%s %w", "ECIDMeasurementReport.protocolIEs:", err), "ECIDMeasurementReport")
	}
	return v, q5.OperationError(nil, "ECIDMeasurementReport")
}
func NewECIDMeasurementTerminationCommand(fields q15.ECIDMeasurementTerminationCommandIEContainer, options ...q5.BuildOption) (q13.ECIDMeasurementTerminationCommand, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q13.ECIDMeasurementTerminationCommand{}, q5.OperationError(err, "ECIDMeasurementTerminationCommand")
	}
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q15.ECIDMeasurementTerminationCommandIEField](bb, uint64(len(fields))); err != nil {
		return q13.ECIDMeasurementTerminationCommand{}, q5.OperationError(err, "ECIDMeasurementTerminationCommand")
	}
	v := q13.ECIDMeasurementTerminationCommand{ProtocolIEs: make(q15.ECIDMeasurementTerminationCommandIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateECIDMeasurementTerminationCommandBudget(&v, budget)
	if err != nil {
		return q13.ECIDMeasurementTerminationCommand{}, q5.OperationError(err, "ECIDMeasurementTerminationCommand")
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		return q13.ECIDMeasurementTerminationCommand{}, q5.OperationError(*q7.BridgeValidationReportFieldErr(&report), "ECIDMeasurementTerminationCommand")
	}
	if issues := q7.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q13.ECIDMeasurementTerminationCommand{}, q5.OperationError(&q7.BuildError{Issues: issues}, "ECIDMeasurementTerminationCommand")
	}
	if _, err := q13.BridgeECIDMeasurementTerminationCommandMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return q13.ECIDMeasurementTerminationCommand{}, q5.OperationError(q6.Errorf("%s %w", "ECIDMeasurementTerminationCommand.protocolIEs:", err), "ECIDMeasurementTerminationCommand")
	}
	return v, q5.OperationError(nil, "ECIDMeasurementTerminationCommand")
}
func NewOTDOAInformationRequest(fields q16.OTDOAInformationRequestIEContainer, options ...q5.BuildOption) (q16.OTDOAInformationRequest, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q16.OTDOAInformationRequest{}, q5.OperationError(err, "OTDOAInformationRequest")
	}
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q16.OTDOAInformationRequestIEField](bb, uint64(len(fields))); err != nil {
		return q16.OTDOAInformationRequest{}, q5.OperationError(err, "OTDOAInformationRequest")
	}
	v := q16.OTDOAInformationRequest{ProtocolIEs: make(q16.OTDOAInformationRequestIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateOTDOAInformationRequestBudget(&v, budget)
	if err != nil {
		return q16.OTDOAInformationRequest{}, q5.OperationError(err, "OTDOAInformationRequest")
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		return q16.OTDOAInformationRequest{}, q5.OperationError(*q7.BridgeValidationReportFieldErr(&report), "OTDOAInformationRequest")
	}
	if issues := q7.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q16.OTDOAInformationRequest{}, q5.OperationError(&q7.BuildError{Issues: issues}, "OTDOAInformationRequest")
	}
	if _, err := q16.BridgeOTDOAInformationRequestMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return q16.OTDOAInformationRequest{}, q5.OperationError(q6.Errorf("%s %w", "OTDOAInformationRequest.protocolIEs:", err), "OTDOAInformationRequest")
	}
	return v, q5.OperationError(nil, "OTDOAInformationRequest")
}
func NewOTDOAInformationFailure(fields q11.OTDOAInformationFailureIEContainer, options ...q5.BuildOption) (q17.OTDOAInformationFailure, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q17.OTDOAInformationFailure{}, q5.OperationError(err, "OTDOAInformationFailure")
	}
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q11.OTDOAInformationFailureIEField](bb, uint64(len(fields))); err != nil {
		return q17.OTDOAInformationFailure{}, q5.OperationError(err, "OTDOAInformationFailure")
	}
	v := q17.OTDOAInformationFailure{ProtocolIEs: make(q11.OTDOAInformationFailureIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateOTDOAInformationFailureBudget(&v, budget)
	if err != nil {
		return q17.OTDOAInformationFailure{}, q5.OperationError(err, "OTDOAInformationFailure")
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		return q17.OTDOAInformationFailure{}, q5.OperationError(*q7.BridgeValidationReportFieldErr(&report), "OTDOAInformationFailure")
	}
	if issues := q7.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q17.OTDOAInformationFailure{}, q5.OperationError(&q7.BuildError{Issues: issues}, "OTDOAInformationFailure")
	}
	if _, err := q17.BridgeOTDOAInformationFailureMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return q17.OTDOAInformationFailure{}, q5.OperationError(q6.Errorf("%s %w", "OTDOAInformationFailure.protocolIEs:", err), "OTDOAInformationFailure")
	}
	return v, q5.OperationError(nil, "OTDOAInformationFailure")
}
func NewAssistanceInformationFeedback(fields q18.AssistanceInformationFeedbackIEContainer, options ...q5.BuildOption) (q18.AssistanceInformationFeedback, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q18.AssistanceInformationFeedback{}, q5.OperationError(err, "AssistanceInformationFeedback")
	}
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q18.AssistanceInformationFeedbackIEField](bb, uint64(len(fields))); err != nil {
		return q18.AssistanceInformationFeedback{}, q5.OperationError(err, "AssistanceInformationFeedback")
	}
	v := q18.AssistanceInformationFeedback{ProtocolIEs: make(q18.AssistanceInformationFeedbackIEContainer, len(fields))}
	copy(v.ProtocolIEs, fields)
	report, err := BridgeValidateAssistanceInformationFeedbackBudget(&v, budget)
	if err != nil {
		return q18.AssistanceInformationFeedback{}, q5.OperationError(err, "AssistanceInformationFeedback")
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		return q18.AssistanceInformationFeedback{}, q5.OperationError(*q7.BridgeValidationReportFieldErr(&report), "AssistanceInformationFeedback")
	}
	if issues := q7.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q18.AssistanceInformationFeedback{}, q5.OperationError(&q7.BuildError{Issues: issues}, "AssistanceInformationFeedback")
	}
	if _, err := q18.BridgeAssistanceInformationFeedbackMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return q18.AssistanceInformationFeedback{}, q5.OperationError(q6.Errorf("%s %w", "AssistanceInformationFeedback.protocolIEs:", err), "AssistanceInformationFeedback")
	}
	return v, q5.OperationError(nil, "AssistanceInformationFeedback")
}
func (ErrorIndicationDescriptor) Initiating() q8.ErrorIndicationInitiatingBinding {
	return func() q8.ErrorIndicationInitiatingBinding {
		sealed := q8.ErrorIndicationInitiatingBinding{}
		*q8.BridgeErrorIndicationInitiatingBindingFieldInfo(&sealed) = ErrorIndicationProcedure().Info()
		*q8.BridgeErrorIndicationInitiatingBindingFieldValidate(&sealed) = func(v *q12.ErrorIndication, budget *q5.DecodeBudget) (q7.ValidationReport, error) {
			return BridgeValidateErrorIndicationBudget(v, budget)
		}
		*q8.BridgeErrorIndicationInitiatingBindingFieldEncode(&sealed) = func(v *q12.ErrorIndication, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q12.BridgeErrorIndicationMethodMarshalAPERBudget(v, budget, fresh)
		}
		*q8.BridgeErrorIndicationInitiatingBindingFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q12.ErrorIndication, error) {
			var v q12.ErrorIndication
			err := q12.BridgeErrorIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return q12.ErrorIndication{}, err
			}
			*q12.BridgeErrorIndicationFieldReceived(&v) = true
			*q12.BridgeErrorIndicationFieldReceivedBytes(&v) = q5.OriginalWire(data)
			return v, nil
		}
		*q8.BridgeErrorIndicationInitiatingBindingFieldInject(&sealed) = func(v q12.ErrorIndication) q8.InitiatingValue {
			return func() q8.InitiatingValue {
				sealed := q8.InitiatingValue{}
				*q8.BridgeInitiatingValueFieldCode(&sealed) = q4.ProcedureCode(0)
				*q8.BridgeInitiatingValueFieldBodyErrorIndication(&sealed) = &v
				return sealed
			}()
		}
		*q8.BridgeErrorIndicationInitiatingBindingFieldCapture(&sealed) = func(v q12.ErrorIndication, options q5.DecodeState) (q12.ErrorIndication, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f :=
				s.Begin()
			q12.BridgeCaptureLPPaErrorIndication(&v, &s)
			var root q5.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q8.BridgeErrorIndicationInitiatingBindingFieldCompare(&sealed) = func(v q12.ErrorIndication, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			q12.BridgeCompareLPPaErrorIndication(&v, &s)
			s.
				End(f, root, false)
			return s.Plan()
		}
		*q8.BridgeErrorIndicationInitiatingBindingFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:ErrorIndication"
			return sealed
		}()
		return sealed
	}()

}
func (ECIDMeasurementFailureIndicationDescriptor) Initiating() q8.ECIDMeasurementFailureIndicationInitiatingBinding {
	return func() q8.ECIDMeasurementFailureIndicationInitiatingBinding {
		sealed := q8.ECIDMeasurementFailureIndicationInitiatingBinding{}
		*q8.BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldInfo(&sealed) = ECIDMeasurementFailureIndicationProcedure().Info()
		*q8.BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldValidate(&sealed) = func(v *q12.ECIDMeasurementFailureIndication, budget *q5.DecodeBudget) (q7.ValidationReport, error) {
			return BridgeValidateECIDMeasurementFailureIndicationBudget(v, budget)
		}
		*q8.BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldEncode(&sealed) = func(v *q12.ECIDMeasurementFailureIndication, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q12.BridgeECIDMeasurementFailureIndicationMethodMarshalAPERBudget(v, budget, fresh)
		}
		*q8.BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q12.ECIDMeasurementFailureIndication, error) {
			var v q12.ECIDMeasurementFailureIndication
			err := q12.BridgeECIDMeasurementFailureIndicationMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return q12.ECIDMeasurementFailureIndication{}, err
			}
			*q12.BridgeECIDMeasurementFailureIndicationFieldReceived(&v) = true
			*q12.BridgeECIDMeasurementFailureIndicationFieldReceivedBytes(&v) = q5.OriginalWire(data)
			return v, nil
		}
		*q8.BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldInject(&sealed) = func(v q12.ECIDMeasurementFailureIndication) q8.InitiatingValue {
			return func() q8.InitiatingValue {
				sealed := q8.InitiatingValue{}
				*q8.BridgeInitiatingValueFieldCode(&sealed) = q4.ProcedureCode(3)
				*q8.BridgeInitiatingValueFieldBodyECIDMeasurementFailureIndication(&sealed) = &v
				return sealed
			}()
		}
		*q8.BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldCapture(&sealed) = func(v q12.ECIDMeasurementFailureIndication, options q5.DecodeState) (q12.ECIDMeasurementFailureIndication, q5.Snapshot,
		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q12.BridgeCaptureLPPaECIDMeasurementFailureIndication(&v, &s)
			var root q5.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q8.BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldCompare(&sealed) = func(v q12.ECIDMeasurementFailureIndication, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q12.BridgeCompareLPPaECIDMeasurementFailureIndication(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q8.BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:ECIDMeasurementFailureIndication"
			return sealed
		}()
		return sealed
	}()

}
func (ECIDMeasurementReportDescriptor) Initiating() q8.ECIDMeasurementReportInitiatingBinding {
	return func() q8.ECIDMeasurementReportInitiatingBinding {
		sealed := q8.ECIDMeasurementReportInitiatingBinding{}
		*q8.BridgeECIDMeasurementReportInitiatingBindingFieldInfo(&sealed) = ECIDMeasurementReportProcedure().Info()
		*q8.BridgeECIDMeasurementReportInitiatingBindingFieldValidate(&sealed) = func(v *q14.ECIDMeasurementReport, budget *q5.DecodeBudget) (q7.ValidationReport, error) {
			return BridgeValidateECIDMeasurementReportBudget(v, budget)
		}
		*q8.BridgeECIDMeasurementReportInitiatingBindingFieldEncode(&sealed) = func(v *q14.ECIDMeasurementReport, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q14.BridgeECIDMeasurementReportMethodMarshalAPERBudget(v, budget, fresh)
		}
		*q8.BridgeECIDMeasurementReportInitiatingBindingFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q14.ECIDMeasurementReport, error) {
			var v q14.ECIDMeasurementReport
			err := q14.BridgeECIDMeasurementReportMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return q14.ECIDMeasurementReport{}, err
			}
			*q14.BridgeECIDMeasurementReportFieldReceived(&v) = true
			*q14.BridgeECIDMeasurementReportFieldReceivedBytes(&v) = q5.OriginalWire(data)
			return v, nil
		}
		*q8.BridgeECIDMeasurementReportInitiatingBindingFieldInject(&sealed) = func(v q14.ECIDMeasurementReport) q8.InitiatingValue {
			return func() q8.InitiatingValue {
				sealed := q8.InitiatingValue{}
				*q8.BridgeInitiatingValueFieldCode(&sealed) = q4.ProcedureCode(4)
				*q8.BridgeInitiatingValueFieldBodyECIDMeasurementReport(&sealed) = &v
				return sealed
			}()
		}
		*q8.BridgeECIDMeasurementReportInitiatingBindingFieldCapture(&sealed) = func(v q14.ECIDMeasurementReport, options q5.DecodeState) (q14.ECIDMeasurementReport, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q14.BridgeCaptureLPPaECIDMeasurementReport(&v,
				&s,
			)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f,

				&root, false)
			return v, root
		}
		*q8.BridgeECIDMeasurementReportInitiatingBindingFieldCompare(&sealed) = func(v q14.ECIDMeasurementReport, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q14.BridgeCompareLPPaECIDMeasurementReport(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q8.BridgeECIDMeasurementReportInitiatingBindingFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:ECIDMeasurementReport"
			return sealed
		}()
		return sealed
	}()

}
func (ECIDMeasurementTerminationDescriptor) Initiating() q8.ECIDMeasurementTerminationCommandInitiatingBinding {
	return func() q8.ECIDMeasurementTerminationCommandInitiatingBinding {
		sealed := q8.ECIDMeasurementTerminationCommandInitiatingBinding{}
		*q8.BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldInfo(&sealed) = ECIDMeasurementTerminationProcedure().Info()
		*q8.BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldValidate(&sealed) = func(v *q13.ECIDMeasurementTerminationCommand, budget *q5.DecodeBudget) (q7.ValidationReport, error) {
			return BridgeValidateECIDMeasurementTerminationCommandBudget(v, budget)
		}
		*q8.BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldEncode(&sealed) = func(v *q13.ECIDMeasurementTerminationCommand, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q13.BridgeECIDMeasurementTerminationCommandMethodMarshalAPERBudget(v, budget, fresh)
		}
		*q8.BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q13.ECIDMeasurementTerminationCommand, error) {
			var v q13.ECIDMeasurementTerminationCommand
			err := q13.BridgeECIDMeasurementTerminationCommandMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return q13.ECIDMeasurementTerminationCommand{}, err
			}
			*q13.BridgeECIDMeasurementTerminationCommandFieldReceived(&v) = true
			*q13.BridgeECIDMeasurementTerminationCommandFieldReceivedBytes(&v) = q5.OriginalWire(data)
			return v, nil
		}
		*q8.BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldInject(&sealed) = func(v q13.ECIDMeasurementTerminationCommand) q8.InitiatingValue {
			return func() q8.InitiatingValue {
				sealed := q8.InitiatingValue{}
				*q8.BridgeInitiatingValueFieldCode(&sealed) = q4.ProcedureCode(5)
				*q8.BridgeInitiatingValueFieldBodyECIDMeasurementTerminationCommand(&sealed) = &v
				return sealed
			}()
		}
		*q8.BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldCapture(&sealed) = func(v q13.ECIDMeasurementTerminationCommand, options q5.DecodeState) (q13.ECIDMeasurementTerminationCommand, q5.Snapshot,

		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q13.BridgeCaptureLPPaECIDMeasurementTerminationCommand(&v, &s)
			var root q5.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q8.BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldCompare(&sealed) = func(v q13.ECIDMeasurementTerminationCommand, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q13.BridgeCompareLPPaECIDMeasurementTerminationCommand(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q8.BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:ECIDMeasurementTerminationCommand"
			return sealed
		}()
		return sealed
	}()

}
func (AssistanceInformationFeedbackDescriptor) Initiating() q8.AssistanceInformationFeedbackInitiatingBinding {
	return func() q8.AssistanceInformationFeedbackInitiatingBinding {
		sealed := q8.AssistanceInformationFeedbackInitiatingBinding{}
		*q8.BridgeAssistanceInformationFeedbackInitiatingBindingFieldInfo(&sealed) = AssistanceInformationFeedbackProcedure().Info()
		*q8.BridgeAssistanceInformationFeedbackInitiatingBindingFieldValidate(&sealed) = func(v *q18.AssistanceInformationFeedback, budget *q5.DecodeBudget) (q7.ValidationReport, error) {
			return BridgeValidateAssistanceInformationFeedbackBudget(v, budget)
		}
		*q8.BridgeAssistanceInformationFeedbackInitiatingBindingFieldEncode(&sealed) = func(v *q18.AssistanceInformationFeedback, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q18.BridgeAssistanceInformationFeedbackMethodMarshalAPERBudget(v, budget, fresh)
		}
		*q8.BridgeAssistanceInformationFeedbackInitiatingBindingFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q18.AssistanceInformationFeedback, error) {
			var v q18.AssistanceInformationFeedback
			err := q18.BridgeAssistanceInformationFeedbackMethodUnmarshalAPERWithOptions(&v, data, options)
			if err != nil {
				return q18.AssistanceInformationFeedback{}, err
			}
			*q18.BridgeAssistanceInformationFeedbackFieldReceived(&v) = true
			*q18.BridgeAssistanceInformationFeedbackFieldReceivedBytes(&v) = q5.OriginalWire(data)
			return v, nil
		}
		*q8.BridgeAssistanceInformationFeedbackInitiatingBindingFieldInject(&sealed) = func(v q18.AssistanceInformationFeedback) q8.InitiatingValue {
			return func() q8.InitiatingValue {
				sealed := q8.InitiatingValue{}
				*q8.BridgeInitiatingValueFieldCode(&sealed) = q4.ProcedureCode(10)
				*q8.BridgeInitiatingValueFieldBodyAssistanceInformationFeedback(&sealed) = &v
				return sealed
			}()
		}
		*q8.BridgeAssistanceInformationFeedbackInitiatingBindingFieldCapture(&sealed) = func(v q18.AssistanceInformationFeedback, options q5.DecodeState) (q18.AssistanceInformationFeedback, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q18.BridgeCaptureLPPaAssistanceInformationFeedback(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q8.BridgeAssistanceInformationFeedbackInitiatingBindingFieldCompare(&sealed) = func(v q18.AssistanceInformationFeedback, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q18.BridgeCompareLPPaAssistanceInformationFeedback(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q8.BridgeAssistanceInformationFeedbackInitiatingBindingFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:AssistanceInformationFeedback"
			return sealed
		}()
		return sealed
	}()

}

// ECIDMeasurementInitiationResponseSuccessfulBinding is the concrete SuccessfulBinding[ECIDMeasurementInitiationResponse].
type ECIDMeasurementInitiationResponseSuccessfulBinding struct {
	context q4.BridgeCodecContext
	capture func(q9.ECIDMeasurementInitiationResponse, q5.DecodeState,

	) (q9.ECIDMeasurementInitiationResponse, q5.Snapshot,

	)
	compare func(q9.ECIDMeasurementInitiationResponse, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	info     q4.ProcedureInfo
	validate func(*q9.ECIDMeasurementInitiationResponse,

		*q5.DecodeBudget) (q7.ValidationReport, error)
	encode func(*q9.ECIDMeasurementInitiationResponse,

		bool, *q5.DecodeBudget) ([]byte, error)
	decode func([]byte, q5.DecodeState) (q9.ECIDMeasurementInitiationResponse,

		error)
	inject func(q9.ECIDMeasurementInitiationResponse,

	) q9.SuccessfulValue
}

func (b ECIDMeasurementInitiationResponseSuccessfulBinding) Info() q4.ProcedureInfo { return b.info }
func (b ECIDMeasurementInitiationResponseSuccessfulBinding) Codec() q9.ECIDMeasurementInitiationResponseValueCodec {
	return func() q9.ECIDMeasurementInitiationResponseValueCodec {
		sealed := q9.ECIDMeasurementInitiationResponseValueCodec{}
		*q9.BridgeECIDMeasurementInitiationResponseValueCodecFieldPath(&sealed) = q5.Path(b.info.Rule.Assignment.Assignment)
		*q9.BridgeECIDMeasurementInitiationResponseValueCodecFieldDecode(&sealed) = b.decode
		*q9.BridgeECIDMeasurementInitiationResponseValueCodecFieldEncode(&sealed) = func(value q9.ECIDMeasurementInitiationResponse,

			fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*q9.BridgeECIDMeasurementInitiationResponseValueCodecFieldCapture(&sealed) = b.capture
		*q9.BridgeECIDMeasurementInitiationResponseValueCodecFieldCompare(&sealed) = b.compare
		*q9.BridgeECIDMeasurementInitiationResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}
func (b ECIDMeasurementInitiationResponseSuccessfulBinding) Build(body q9.ECIDMeasurementInitiationResponse,

	transactionID q4.LPPATransactionID, options ...q5.BuildOption) (q9.SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(q6.Errorf("%w: unbound procedure binding", q5.ErrInvalidValue), "Build")
	}
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	if err := q4.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(*q7.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q7.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q9.SuccessfulOutcome{}, q5.OperationError(&q7.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(q6.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), body); err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	return q9.SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q5.OperationError(nil, "Build")
}

// OTDOAInformationResponseSuccessfulBinding is the concrete SuccessfulBinding[OTDOAInformationResponse].
type OTDOAInformationResponseSuccessfulBinding struct {
	context q4.BridgeCodecContext
	capture func(q16.OTDOAInformationResponse, q5.DecodeState,

	) (q16.OTDOAInformationResponse, q5.Snapshot,

	)
	compare func(q16.OTDOAInformationResponse, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	info     q4.ProcedureInfo
	validate func(*q16.OTDOAInformationResponse,

		*q5.DecodeBudget) (q7.ValidationReport, error)
	encode func(*q16.OTDOAInformationResponse,

		bool, *q5.DecodeBudget) ([]byte, error)
	decode func([]byte, q5.DecodeState) (q16.OTDOAInformationResponse,

		error)
	inject func(q16.OTDOAInformationResponse,

	) q9.SuccessfulValue
}

func (b OTDOAInformationResponseSuccessfulBinding) Info() q4.ProcedureInfo { return b.info }
func (b OTDOAInformationResponseSuccessfulBinding) Codec() q16.OTDOAInformationResponseValueCodec {
	return func() q16.OTDOAInformationResponseValueCodec {
		sealed := q16.OTDOAInformationResponseValueCodec{}
		*q16.BridgeOTDOAInformationResponseValueCodecFieldPath(&sealed) = q5.Path(b.info.Rule.Assignment.Assignment)
		*q16.BridgeOTDOAInformationResponseValueCodecFieldDecode(&sealed) = b.decode
		*q16.BridgeOTDOAInformationResponseValueCodecFieldEncode(&sealed) = func(value q16.OTDOAInformationResponse,

			fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*q16.BridgeOTDOAInformationResponseValueCodecFieldCapture(&sealed) = b.capture
		*q16.BridgeOTDOAInformationResponseValueCodecFieldCompare(&sealed) = b.compare
		*q16.BridgeOTDOAInformationResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}
func (b OTDOAInformationResponseSuccessfulBinding) Build(body q16.OTDOAInformationResponse,

	transactionID q4.LPPATransactionID, options ...q5.BuildOption) (q9.SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(q6.Errorf("%w: unbound procedure binding", q5.ErrInvalidValue), "Build")
	}
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	if err := q4.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(*q7.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q7.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q9.SuccessfulOutcome{}, q5.OperationError(&q7.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(q6.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), body); err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	return q9.SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q5.OperationError(nil, "Build")
}

// UTDOAInformationResponseSuccessfulBinding is the concrete SuccessfulBinding[UTDOAInformationResponse].
type UTDOAInformationResponseSuccessfulBinding struct {
	context q4.BridgeCodecContext
	capture func(q18.UTDOAInformationResponse, q5.DecodeState,

	) (q18.UTDOAInformationResponse, q5.Snapshot,

	)
	compare func(q18.UTDOAInformationResponse, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	info     q4.ProcedureInfo
	validate func(*q18.UTDOAInformationResponse,

		*q5.DecodeBudget) (q7.ValidationReport, error)
	encode func(*q18.UTDOAInformationResponse,

		bool, *q5.DecodeBudget) ([]byte, error)
	decode func([]byte, q5.DecodeState) (q18.UTDOAInformationResponse,

		error)
	inject func(q18.UTDOAInformationResponse,

	) q9.SuccessfulValue
}

func (b UTDOAInformationResponseSuccessfulBinding) Info() q4.ProcedureInfo { return b.info }
func (b UTDOAInformationResponseSuccessfulBinding) Codec() q18.UTDOAInformationResponseValueCodec {
	return func() q18.UTDOAInformationResponseValueCodec {
		sealed := q18.UTDOAInformationResponseValueCodec{}
		*q18.BridgeUTDOAInformationResponseValueCodecFieldPath(&sealed) = q5.Path(b.info.Rule.Assignment.Assignment)
		*q18.BridgeUTDOAInformationResponseValueCodecFieldDecode(&sealed) = b.decode
		*q18.BridgeUTDOAInformationResponseValueCodecFieldEncode(&sealed) = func(value q18.UTDOAInformationResponse,

			fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*q18.BridgeUTDOAInformationResponseValueCodecFieldCapture(&sealed) = b.capture
		*q18.BridgeUTDOAInformationResponseValueCodecFieldCompare(&sealed) = b.compare
		*q18.BridgeUTDOAInformationResponseValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}
func (b UTDOAInformationResponseSuccessfulBinding) Build(body q18.UTDOAInformationResponse,

	transactionID q4.LPPATransactionID, options ...q5.BuildOption) (q9.SuccessfulOutcome, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(q6.Errorf("%w: unbound procedure binding", q5.ErrInvalidValue), "Build")
	}
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	if err := q4.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(*q7.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q7.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q9.SuccessfulOutcome{}, q5.OperationError(&q7.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(q6.Errorf("successfulOutcome.value: %w", err), "Build")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), body); err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "Build")
	}
	return q9.SuccessfulOutcome{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q5.OperationError(nil, "Build")
}

// LPPAPDUValueCodec is the concrete ValueCodec[LPPAPDU].
type LPPAPDUValueCodec struct {
	context q4.BridgeCodecContext
	capture func(LPPAPDU, q5.DecodeState,

	) (LPPAPDU, q5.Snapshot,

	)
	compare func(LPPAPDU, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (LPPAPDU,

		error)
	encode func(LPPAPDU,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c LPPAPDUValueCodec) New(value LPPAPDU,

) (LPPAPDUAPERValue, error) {
	if c.encode == nil {
		return LPPAPDUAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return LPPAPDUAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LPPAPDUAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return LPPAPDUAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c LPPAPDUValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (LPPAPDUAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return LPPAPDUAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return LPPAPDUAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return LPPAPDUAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return LPPAPDUAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return LPPAPDUAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c LPPAPDUValueCodec) EncodeAPER(value LPPAPDUAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q5.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q5.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q5.OperationError(err, c.path)
}
func (c LPPAPDUValueCodec) encodeBudget(value LPPAPDU,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c LPPAPDUValueCodec) encodeChanged(value LPPAPDU,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// SuccessfulOutcomeValueCodec is the concrete ValueCodec[SuccessfulOutcome].
type SuccessfulOutcomeValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q9.SuccessfulOutcome, q5.DecodeState,

	) (q9.SuccessfulOutcome, q5.Snapshot,

	)
	compare func(q9.SuccessfulOutcome, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q9.SuccessfulOutcome,

		error)
	encode func(q9.SuccessfulOutcome,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c SuccessfulOutcomeValueCodec) New(value q9.SuccessfulOutcome,

) (SuccessfulOutcomeAPERValue, error) {
	if c.encode == nil {
		return SuccessfulOutcomeAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return SuccessfulOutcomeAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SuccessfulOutcomeAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return SuccessfulOutcomeAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c SuccessfulOutcomeValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (SuccessfulOutcomeAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SuccessfulOutcomeAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return SuccessfulOutcomeAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SuccessfulOutcomeAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return SuccessfulOutcomeAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return SuccessfulOutcomeAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c SuccessfulOutcomeValueCodec) EncodeAPER(value SuccessfulOutcomeAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q5.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q5.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q5.OperationError(err, c.path)
}
func (c SuccessfulOutcomeValueCodec) encodeBudget(value q9.SuccessfulOutcome,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SuccessfulOutcomeValueCodec) encodeChanged(value q9.SuccessfulOutcome,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeECIDMeasurementInitiationResponseIEValueValidateLPPaIEContainer(fields q9.ECIDMeasurementInitiationResponseIEContainer, rows []q4.FieldInfo, path string, budget *q5.DecodeBudget,

) q7.ValidationReport {
	report := func() q7.ValidationReport {
		sealed := q7.ValidationReport{Complete: true}
		*q7.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q5.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q7.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q4.ProtocolIEID]int, len(rows))
	counts := make(map[q4.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q7.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q7.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q5.Location{Path: q5.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q9.BridgeECIDMeasurementInitiationResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q9.BridgeECIDMeasurementInitiationResponseIEValueMethodRule(field.Value)
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.ValueIDMismatch, Severity: q4.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q4.TableID {
				sealed := q4.TableID{}
				*q4.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q4.ValueIDMismatch), RelatedRules: []q5.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q5.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q4.FieldInfo
			related := []q5.SourceRule{q19.BridgeLppaAdoptedRule(q4.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.RepeatedIE, Severity: q4.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q4.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q4.ValidationSeverityUnrecognized
			if _, globallyKnown := q19.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q4.ValidationSeverityError
			}
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q4.NotAllowed), RelatedRules: q19.BridgeLppaHandlingRules(q4.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.WrongCriticality, Severity: q4.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q4.WrongCriticality), RelatedRules: []q5.SourceRule{q19.BridgeLppaAdoptedRule(q4.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.WrongOrder, Severity: q4.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q4.WrongOrder), RelatedRules: []q5.SourceRule{q19.BridgeLppaAdoptedRule(q4.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q4.PresenceMandatory && counts[row.ID] == 0 {
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.MissingMandatory, Severity: q4.ValidationSeverityError, Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q4.MissingMandatory), RelatedRules: []q5.SourceRule{q19.BridgeLppaAdoptedRule(q4.MissingMandatory), row.Rule}})
		}
		if row.Presence == q4.PresenceConditional {
			q7.BridgeValidationReportMethodAddDeferred(&report, q4.DeferredCondition{Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q7.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeWLANMeasurementResultItemExtIEsValueValidateLPPaExtensionContainer(fields q19.WLANMeasurementResultItemExtIEsExtContainer, rows []q4.FieldInfo, path string, budget *q5.DecodeBudget) q7.ValidationReport {
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q19.WLANMeasurementResultItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q7.ValidationReport {
			sealed := q7.ValidationReport{}
			*q7.BridgeValidationReportFieldErr(&sealed) = err
			*q7.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q19.WLANMeasurementResultItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeWLANMeasurementResultItemExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// eCIDMeasurementInitiationResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q9.ECIDMeasurementInitiationResponseIEValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q4.ProtocolIEID, q5.OpaqueOpenType) (q9.ECIDMeasurementInitiationResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q4.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q4.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}

// wLANMeasurementResultItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[WLANMeasurementResultItemExtIEsValue].
type WLANMeasurementResultItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q15.WLANMeasurementResultItemExtIEsValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q4.ProtocolIEID, q5.OpaqueOpenType) (q15.WLANMeasurementResultItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q4.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q4.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}

// LPPAPDUAPERValue is the concrete APERValue[LPPAPDU].
type LPPAPDUAPERValue struct {
	context q4.BridgeCodecContext
	Value   LPPAPDU

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v LPPAPDUAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v LPPAPDUAPERValue) WithoutReplay() LPPAPDUAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// SuccessfulOutcomeAPERValue is the concrete APERValue[SuccessfulOutcome].
type SuccessfulOutcomeAPERValue struct {
	context q4.BridgeCodecContext
	Value   q9.SuccessfulOutcome

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v SuccessfulOutcomeAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v SuccessfulOutcomeAPERValue) WithoutReplay() SuccessfulOutcomeAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeWLANMeasurementResultItemExtIEsValueValidateLPPaIEContainer(fields q19.WLANMeasurementResultItemExtIEsIEContainer, rows []q4.FieldInfo, path string, budget *q5.DecodeBudget,

) q7.ValidationReport {
	report := func() q7.ValidationReport {
		sealed := q7.ValidationReport{Complete: true}
		*q7.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q5.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q7.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q4.ProtocolIEID]int, len(rows))
	counts := make(map[q4.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q7.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q7.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q5.Location{Path: q5.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q15.BridgeWLANMeasurementResultItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q15.BridgeWLANMeasurementResultItemExtIEsValueMethodRule(field.Value)
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.ValueIDMismatch, Severity: q4.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q4.TableID {
				sealed := q4.TableID{}
				*q4.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q4.ValueIDMismatch), RelatedRules: []q5.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q5.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q4.FieldInfo
			related := []q5.SourceRule{q19.BridgeLppaAdoptedRule(q4.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.RepeatedIE, Severity: q4.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q4.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q4.ValidationSeverityUnrecognized
			if _, globallyKnown := q19.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q4.ValidationSeverityError
			}
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q4.NotAllowed), RelatedRules: q19.BridgeLppaHandlingRules(q4.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.WrongCriticality, Severity: q4.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q4.WrongCriticality), RelatedRules: []q5.SourceRule{q19.BridgeLppaAdoptedRule(q4.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.WrongOrder, Severity: q4.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q4.WrongOrder), RelatedRules: []q5.SourceRule{q19.BridgeLppaAdoptedRule(q4.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q4.PresenceMandatory && counts[row.ID] == 0 {
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.MissingMandatory, Severity: q4.ValidationSeverityError, Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q4.MissingMandatory), RelatedRules: []q5.SourceRule{q19.BridgeLppaAdoptedRule(q4.MissingMandatory), row.Rule}})
		}
		if row.Presence == q4.PresenceConditional {
			q7.BridgeValidationReportMethodAddDeferred(&report, q4.DeferredCondition{Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q7.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// MarshalAPERWLANMeasurementResult encodes a WLANMeasurementResult list to APER.
func BridgeMarshalAPERWLANMeasurementResult(list q9.WLANMeasurementResultComplete) ([]byte, error) {
	return q9.BridgeWLANMeasurementResultCompleteMethodMarshalAPERLegacy(&list)
}

// UnmarshalAPERWLANMeasurementResult decodes a WLANMeasurementResult list from APER.
func BridgeUnmarshalAPERWLANMeasurementResult(data []byte) (q9.WLANMeasurementResultComplete, error) {
	var value q9.WLANMeasurementResultComplete
	if err := q9.BridgeWLANMeasurementResultCompleteMethodUnmarshalAPERLegacy(&value, data); err != nil {
		return value, err
	}
	return value, nil
}

// LPPAPDU represents the ASN.1 CHOICE type LPPA-PDU.
type LPPAPDU struct {
	knownOpenBytes      uint64
	replay              q5.Snapshot
	stream              q5.WireSpan
	withoutReplay       bool
	received            bool
	receivedBytes       q5.WireSpan
	Choice              int
	perPadding          q5.CompletePadding       `json:"-"`
	perOpenTypePadding  q5.CompletePadding       `json:"-"`
	UnknownExtension    *q5.ChoiceExtension      `json:"UnknownExtension,omitempty"`
	InitiatingMessage   *q8.InitiatingMessage    `json:"InitiatingMessage,omitempty"`
	SuccessfulOutcome   *q9.SuccessfulOutcome    `json:"SuccessfulOutcome,omitempty"`
	UnsuccessfulOutcome *q10.UnsuccessfulOutcome `json:"UnsuccessfulOutcome,omitempty"`
}

// NewLPPAPDUInitiatingMessage creates a LPPAPDU with the initiatingMessage alternative.
func BridgeNewLPPAPDUInitiatingMessageLegacy(v q8.InitiatingMessage) LPPAPDU {
	return LPPAPDU{
		Choice:            q4.LPPAPDUChoiceInitiatingMessage,
		InitiatingMessage: &v,
	}
}

// NewLPPAPDUSuccessfulOutcome creates a LPPAPDU with the successfulOutcome alternative.
func BridgeNewLPPAPDUSuccessfulOutcomeLegacy(v q9.SuccessfulOutcome) LPPAPDU {
	return LPPAPDU{
		Choice:            q4.LPPAPDUChoiceSuccessfulOutcome,
		SuccessfulOutcome: &v,
	}
}

// NewLPPAPDUUnsuccessfulOutcome creates a LPPAPDU with the unsuccessfulOutcome alternative.
func BridgeNewLPPAPDUUnsuccessfulOutcomeLegacy(v q10.UnsuccessfulOutcome) LPPAPDU {
	return LPPAPDU{
		Choice:              q4.LPPAPDUChoiceUnsuccessfulOutcome,
		UnsuccessfulOutcome: &v,
	}
}

// MarshalAPER encodes LPPAPDU to APER format.
func (v *LPPAPDU) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *LPPAPDU) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
			return q6.Errorf("%s known choice %d and unknown extension are both selected", "LPPAPDU:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return q6.Errorf("%s extension index %d must be non-negative", "LPPAPDU:", v.UnknownExtension.Index())
		}
		if err := q5.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := q5.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index()); err != nil {
			return err
		}
		return v.UnknownExtension.EncodeTo(bb)
	}
	if v.Choice < 1 {
		return q6.Errorf("%s choice %d must be positive", "LPPAPDU:", v.Choice)
	}
	isExtension := v.Choice > 3
	if err := q5.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return q6.Errorf("%s extension choice %d not supported", "LPPAPDU:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return q6.Errorf("choice index outside root")
	}
	if err := q5.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 2); err != nil {
		return err
	}
	switch v.Choice {
	case q4.LPPAPDUChoiceInitiatingMessage:
		if v.InitiatingMessage == nil {
			return q6.Errorf("choice alternative initiatingMessage is nil")
		}
		if err := q8.BridgeInitiatingMessageMethodMarshalAPERTo(v.InitiatingMessage, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return q6.Errorf("encoding initiatingMessage: %w", err)
		}
	case q4.LPPAPDUChoiceSuccessfulOutcome:
		if v.SuccessfulOutcome == nil {
			return q6.Errorf("choice alternative successfulOutcome is nil")
		}
		if err := q9.BridgeSuccessfulOutcomeMethodMarshalAPERTo(v.SuccessfulOutcome, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return q6.Errorf("encoding successfulOutcome: %w", err)
		}
	case q4.LPPAPDUChoiceUnsuccessfulOutcome:
		if v.UnsuccessfulOutcome == nil {
			return q6.Errorf("choice alternative unsuccessfulOutcome is nil")
		}
		if err := q10.BridgeUnsuccessfulOutcomeMethodMarshalAPERTo(v.UnsuccessfulOutcome, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return q6.Errorf("encoding unsuccessfulOutcome: %w", err)
		}
	default:
		return q6.Errorf("unknown LPPAPDU choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes LPPAPDU from APER format.
func (v *LPPAPDU) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes LPPAPDU with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *LPPAPDU) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q20.WrapDecodePath(err, "LPPAPDU")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q20.WrapDecodePath(err, "LPPAPDU")
	}
	padding, err := q5.CaptureFinalBits(bb, "LPPAPDU")
	if err != nil {
		return q20.WrapDecodePath(err, "LPPAPDU")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *LPPAPDU) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = LPPAPDU{}
	isExtension, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := q5.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return q20.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := q5.DecodeChoiceExtensionAligned(bb, extIdx, 0)
		if extIdx < 0 {
			v.knownOpenBytes = max(v.knownOpenBytes, openExtension.ContentLength())
		}
		if err != nil {
			return q20.WrapDecodePath(err, "UnknownExtension")
		}
		v.UnknownExtension = &openExtension
		v.stream = bb.CaptureWireSpan(replayStart)
		v.stream.RecordUsage(replayUsage,

			bb)

		return nil
	}
	idx, err := q5.DecodeConstrainedWholeNumberAligned(bb, 0, 2)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return q6.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case q4.LPPAPDUChoiceInitiatingMessage:
		toleranceMark_initiatingmessage := bb.EnterComponent("InitiatingMessage")
		var dec_initiatingmessage q8.InitiatingMessage
		if err := q8.BridgeInitiatingMessageMethodUnmarshalAPERFrom(&dec_initiatingmessage, bb); err != nil {
			return q20.WrapDecodePath(err, "InitiatingMessage")
		}
		if err := q5.ChargeValue(bb, dec_initiatingmessage); err != nil {
			return err
		}
		v.InitiatingMessage = &dec_initiatingmessage
		bb.LeaveComponent(toleranceMark_initiatingmessage)
	case q4.LPPAPDUChoiceSuccessfulOutcome:
		toleranceMark_successfuloutcome := bb.EnterComponent("SuccessfulOutcome")
		var dec_successfuloutcome q9.SuccessfulOutcome
		if err := q9.BridgeSuccessfulOutcomeMethodUnmarshalAPERFrom(&dec_successfuloutcome, bb); err != nil {
			return q20.WrapDecodePath(err, "SuccessfulOutcome")
		}
		if err := q5.ChargeValue(bb, dec_successfuloutcome); err != nil {
			return err
		}
		v.SuccessfulOutcome = &dec_successfuloutcome
		bb.LeaveComponent(toleranceMark_successfuloutcome)
	case q4.LPPAPDUChoiceUnsuccessfulOutcome:
		toleranceMark_unsuccessfuloutcome := bb.EnterComponent("UnsuccessfulOutcome")
		var dec_unsuccessfuloutcome q10.UnsuccessfulOutcome
		if err := q10.BridgeUnsuccessfulOutcomeMethodUnmarshalAPERFrom(&dec_unsuccessfuloutcome, bb); err != nil {
			return q20.WrapDecodePath(err, "UnsuccessfulOutcome")
		}
		if err := q5.ChargeValue(bb, dec_unsuccessfuloutcome); err != nil {
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
func (v *LPPAPDU) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q21.BridgeReceivedFormAt(v.received, v.receivedBytes, "LPPAPDU", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v LPPAPDU) WithoutReplay() LPPAPDU {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero LPPAPDU
	v.perPadding = zero.perPadding
	return v
}
func (v *LPPAPDU) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "LPPAPDU")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "LPPAPDU")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaLPPAPDU(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "LPPAPDU")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "LPPAPDU")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "LPPAPDU")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "LPPAPDU")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "LPPAPDU")
}
func (v *LPPAPDU) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *LPPAPDU) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *LPPAPDU) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
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
func (v *LPPAPDU) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *LPPAPDU) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q5.NewBudgetBuffer(budget)
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
func (v *LPPAPDU) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "LPPAPDU")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded LPPAPDU
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaLPPAPDU(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = LPPAPDU{}
		return report, q5.OperationError(err, "LPPAPDU")
	}
	*v = decoded
	return report, q5.OperationError(nil, "LPPAPDU")
}

// NewLPPAPDUUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewLPPAPDUUnknownExtension(index uint64, contents []byte, options ...q5.BuildOption) (LPPAPDU, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return LPPAPDU{}, q5.OperationError(err, "LPPAPDUUnknownExtension")
	}
	extension, err := q5.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return LPPAPDU{}, q5.OperationError(err, "LPPAPDUUnknownExtension")
	}
	value := LPPAPDU{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return LPPAPDU{}, q5.OperationError(err, "LPPAPDUUnknownExtension")
	}
	return value, q5.OperationError(nil, "LPPAPDUUnknownExtension")
}

// PayloadCodec owns a typed foreign decoder and encoder. The callbacks must
// enforce the foreign schema and consume a complete value.
type PayloadCodec[T any] struct {
	decode func([]byte, q4.PayloadLimits) (T, q4.PayloadReport, error)
	encode func(T, q4.PayloadLimits) ([]byte, error)
}
type NewPayloadCodec[T any] struct{}

func (NewPayloadCodec[T]) Call(
	decode func([]byte, q4.PayloadLimits) (T, q4.PayloadReport, error),
	encode func(T, q4.PayloadLimits) ([]byte, error),
) (PayloadCodec[T], error) {
	if decode == nil || encode == nil {
		return PayloadCodec[T]{}, q5.OperationError(q5.OperationError(q6.Errorf("%w: payload binding: nil callback", q5.ErrInvalidValue), "Payload.binding"), "PayloadCodec")
	}
	return PayloadCodec[T]{decode: decode, encode: encode}, q5.OperationError(nil, "PayloadCodec")
}

type DecodePayload[T any] struct{}

func (DecodePayload[T]) Call(data []byte, codec PayloadCodec[T], limits q4.PayloadLimits) (T, q4.PayloadReport, error) {
	var zero T
	if codec.decode == nil || codec.encode == nil {
		return zero, q4.PayloadReport{}, q5.OperationError(q6.Errorf("%w: payload binding: zero codec", q5.ErrInvalidValue), "Payload.binding")
	}
	limits = q15.BridgeEffectivePayloadLimits(limits)
	if uint64(len(data)) > limits.MaxInputBytes {
		return zero, q4.PayloadReport{}, q5.OperationError(q6.Errorf("%w: payload input: %d bytes exceed limit %d", q5.ErrLimit, len(data), limits.MaxInputBytes), "Payload.input")
	}
	if uint64(len(data)) > limits.MaxAllocatedBytes {
		return zero, q4.PayloadReport{}, q5.OperationError(q6.Errorf("%w: payload input copy: %d bytes exceed allocation limit %d", q5.ErrLimit, len(data), limits.MaxAllocatedBytes), "Payload.input")
	}
	if uint64(len(data)) > limits.MaxWork {
		return zero, q4.PayloadReport{}, q5.OperationError(q6.Errorf("%w: payload input copy work", q5.ErrLimit), "Payload.input")
	}
	owned := append([]byte(nil), data...)
	value, report, err := codec.decode(owned, limits)
	if err != nil {
		return zero, report, q6.Errorf("payload decode: %w", err)
	}
	if uint64(len(report.Deviations)) > limits.MaxReports {
		return zero, q4.PayloadReport{}, q5.OperationError(q6.Errorf("%w: payload report: %d deviations exceed limit %d", q5.ErrLimit, len(report.Deviations), limits.MaxReports), "Payload.report")
	}
	return value, report, nil
}

type EncodePayload[T any] struct{}

func (EncodePayload[T]) Call(value T, codec PayloadCodec[T], limits q4.PayloadLimits) ([]byte, error) {
	if codec.decode == nil || codec.encode == nil {
		return nil, q5.OperationError(q6.Errorf("%w: payload binding: zero codec", q5.ErrInvalidValue), "Payload.binding")
	}
	limits = q15.BridgeEffectivePayloadLimits(limits)
	wire, err := codec.encode(value, limits)
	if err != nil {
		return nil, q6.Errorf("payload encode: %w", err)
	}
	if uint64(len(wire)) > limits.MaxOutputBytes {
		return nil, q5.OperationError(q6.Errorf("%w: payload output: %d bytes exceed limit %d", q5.ErrLimit, len(wire), limits.MaxOutputBytes), "Payload.output")
	}
	if uint64(len(wire)) > limits.MaxAllocatedBytes {
		return nil, q5.OperationError(q6.Errorf("%w: payload output copy: %d bytes exceed allocation limit %d", q5.ErrLimit, len(wire), limits.MaxAllocatedBytes), "Payload.output")
	}
	if uint64(len(wire)) > limits.MaxWork {
		return nil, q5.OperationError(q6.Errorf("%w: payload output copy work", q5.ErrLimit), "Payload.output")
	}
	return append([]byte(nil), wire...), nil
}
func NewOpaqueSuccessfulOutcome(code q4.ProcedureCode, criticality q4.Criticality, transactionID q4.LPPATransactionID, data []byte) (q9.SuccessfulOutcome, error) {
	if err := q4.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "OpaqueSuccessfulOutcome")
	}
	switch code {
	case q4.ProcedureCode(2):
		return q9.SuccessfulOutcome{}, q5.OperationError(q6.Errorf("known Successful procedure id-e-CIDMeasurementInitiation requires its typed binding"), "OpaqueSuccessfulOutcome")
	case q4.ProcedureCode(6):
		return q9.SuccessfulOutcome{}, q5.OperationError(q6.Errorf("known Successful procedure id-oTDOAInformationExchange requires its typed binding"), "OpaqueSuccessfulOutcome")
	case q4.ProcedureCode(7):
		return q9.SuccessfulOutcome{}, q5.OperationError(q6.Errorf("known Successful procedure id-uTDOAInformationExchange requires its typed binding"), "OpaqueSuccessfulOutcome")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "OpaqueSuccessfulOutcome")
	}
	opaque, err := q5.BuildOpaqueOpenType(data, budget)
	if err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "OpaqueSuccessfulOutcome")
	}
	retained, err := opaque.Retained(budget)
	if err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "OpaqueSuccessfulOutcome")
	}
	message := q9.SuccessfulOutcome{ProcedureCode: code, Criticality: criticality, LppatransactionID: transactionID, Value: func() q9.SuccessfulValue {
		sealed := q9.SuccessfulValue{}
		*q9.BridgeSuccessfulValueFieldCode(&sealed) = code
		*q9.BridgeSuccessfulValueFieldOpaque(&sealed) = retained
		*q9.BridgeSuccessfulValueFieldIsOpaque(&sealed) = true
		return sealed
	}()}
	if _, err := q9.BridgeSuccessfulOutcomeMethodMarshalAPERBudget(&message, budget, false); err != nil {
		return q9.SuccessfulOutcome{}, q5.OperationError(err, "OpaqueSuccessfulOutcome")
	}
	return message, q5.OperationError(nil, "OpaqueSuccessfulOutcome")
}
func BridgeCaptureLPPaLPPAPDU(v *LPPAPDU, s *q5.SemanticCapture) {
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
	case q4.LPPAPDUChoiceInitiatingMessage:
		{
			f := s.Begin()
			s.Bool(v.InitiatingMessage == nil)
			if v.InitiatingMessage != nil {
				q8.BridgeCaptureLPPaInitiatingMessage(v.InitiatingMessage, s)
			}
			s.End(f, nil, false)
		}
	case q4.LPPAPDUChoiceSuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.SuccessfulOutcome == nil)
			if v.SuccessfulOutcome != nil {
				q9.BridgeCaptureLPPaSuccessfulOutcome(v.SuccessfulOutcome, s)
			}
			s.End(f, nil, false)
		}
	case q4.LPPAPDUChoiceUnsuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.UnsuccessfulOutcome == nil)
			if v.UnsuccessfulOutcome != nil {
				q10.BridgeCaptureLPPaUnsuccessfulOutcome(v.UnsuccessfulOutcome, s)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaLPPAPDU(v *LPPAPDU, s *q5.SemanticComparison) {
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
		s.End(f, q5.Snapshot{}, false)
	}
	switch v.Choice {
	case q4.LPPAPDUChoiceInitiatingMessage:
		{
			f := s.Begin()
			s.Bool(v.InitiatingMessage == nil)
			if v.InitiatingMessage != nil {
				q8.BridgeCompareLPPaInitiatingMessage(v.InitiatingMessage, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q4.LPPAPDUChoiceSuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.SuccessfulOutcome == nil)
			if v.SuccessfulOutcome != nil {
				q9.BridgeCompareLPPaSuccessfulOutcome(v.SuccessfulOutcome, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q4.LPPAPDUChoiceUnsuccessfulOutcome:
		{
			f := s.Begin()
			s.Bool(v.UnsuccessfulOutcome == nil)
			if v.UnsuccessfulOutcome != nil {
				q10.BridgeCompareLPPaUnsuccessfulOutcome(v.UnsuccessfulOutcome, s)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaPrivateIEContainer[V ProtocolPrivateValueConstraint[V]](v *PrivateIEContainer[V], s *q5.SemanticCapture) {
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
func BridgeCompareLPPaPrivateIEContainer[V ProtocolPrivateValueConstraint[V]](v *PrivateIEContainer[V], s *q5.SemanticComparison) {
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
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeCaptureLPPaPrivateIEField[V ProtocolPrivateValueConstraint[V]](v *PrivateIEField[V], s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q22.BridgeCaptureLPPaPrivateIEID(&v.Id, s)
	q4.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(v.Value.captureFraming())
	v.Value = v.Value.captureSemantics(*s)
	s.Child(v.Value.captureSnapshot())
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaPrivateIEField[V ProtocolPrivateValueConstraint[V]](v *PrivateIEField[V], s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q22.BridgeCompareLPPaPrivateIEID(&v.Id, s)
	q23.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaProtocolExtensionContainer[V ProtocolOpenValueConstraint[V]](v *ProtocolExtensionContainer[V], s *q5.SemanticCapture) {
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
func BridgeCompareLPPaProtocolExtensionContainer[V ProtocolOpenValueConstraint[V]](v *ProtocolExtensionContainer[V], s *q5.SemanticComparison) {
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
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeCaptureLPPaProtocolExtensionField[V ProtocolOpenValueConstraint[V]](v *ProtocolExtensionField[V], s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q4.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q4.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(v.ExtensionValue.captureFraming())
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.Child(v.ExtensionValue.captureSnapshot())
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaProtocolExtensionField[V ProtocolOpenValueConstraint[V]](v *ProtocolExtensionField[V], s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q23.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q23.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaProtocolIEContainer[V ProtocolOpenValueConstraint[V]](v *ProtocolIEContainer[V], s *q5.SemanticCapture) {
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
func BridgeCompareLPPaProtocolIEContainer[V ProtocolOpenValueConstraint[V]](v *ProtocolIEContainer[V], s *q5.SemanticComparison) {
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
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeCaptureLPPaProtocolIEField[V ProtocolOpenValueConstraint[V]](v *ProtocolIEField[V], s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q4.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q4.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(v.Value.captureFraming())
	v.Value = v.Value.captureSemantics(*s)
	s.Child(v.Value.captureSnapshot())
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaProtocolIEField[V ProtocolOpenValueConstraint[V]](v *ProtocolIEField[V], s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q23.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q23.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaProtocolIESingleContainer[V ProtocolOpenValueConstraint[V]](v *ProtocolIESingleContainer[V], s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	BridgeCaptureLPPaProtocolIEField[V](v, s)
}
func BridgeCompareLPPaProtocolIESingleContainer[V ProtocolOpenValueConstraint[V]](v *ProtocolIESingleContainer[V], s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	BridgeCompareLPPaProtocolIEField[V](v, s)
}

type ProtocolOpenValueConstraint[V any] interface {
	captureSemantics(q5.SemanticCapture) V
	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q4.ProtocolIEID, q5.OpaqueOpenType) (V, error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q4.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q4.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}
type ProtocolIEField[V ProtocolOpenValueConstraint[V]] struct {
	withoutReplay bool
	replay        q5.Snapshot
	stream        q5.WireSpan
	Id            q4.ProtocolIEID
	Criticality   q4.Criticality
	Value         V
	received      q5.CompletePadding
}
type ProtocolIEContainer[V ProtocolOpenValueConstraint[V]] []ProtocolIEField[V]
type ProtocolIEContainerList[V ProtocolOpenValueConstraint[V]] []ProtocolIEContainer[V]

func (v ProtocolIEField[V]) WithoutReplay() ProtocolIEField[V] {
	v.withoutReplay = true
	v.stream = q5.WireSpan{}
	return v
}
func (v *ProtocolIEField[V]) ReceivedForm() q5.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q5.ReceivedForm{}
	}
	return q5.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ProtocolIEField[V]) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
		return q6.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return q20.WrapDecodePath(q6.Errorf("%w: field id %d does not match its value selector", q5.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q5.EncodeIntegerAligned(bb, int64(v.Id), q15.BridgeInt64Ptr(0), q15.BridgeInt64Ptr(65535), false); err != nil {
		return q6.Errorf("encoding id: %w", err)
	}
	if err := q5.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q6.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	if err := q5.EncodeOpenTypeAligned(bb, data); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ProtocolIEField[V]) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ProtocolIEField[V]{}
	id, err := q5.DecodeIntegerAligned(bb, q15.BridgeInt64Ptr(0), q15.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q20.WrapDecodePath(err, "Id")
	}
	v.Id = q4.ProtocolIEID(id)
	criticality, err := q5.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q20.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q4.Criticality(criticality)
	var zero V
	raw, err := q5.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return q20.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return q20.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

type ProtocolExtensionField[V ProtocolOpenValueConstraint[V]] struct {
	withoutReplay  bool
	replay         q5.Snapshot
	stream         q5.WireSpan
	Id             q4.ProtocolIEID
	Criticality    q4.Criticality
	ExtensionValue V
	received       q5.CompletePadding
}
type ProtocolExtensionContainer[V ProtocolOpenValueConstraint[V]] []ProtocolExtensionField[V]

func (v ProtocolExtensionField[V]) WithoutReplay() ProtocolExtensionField[V] {
	v.withoutReplay = true
	v.stream = q5.WireSpan{}
	return v
}
func (v *ProtocolExtensionField[V]) ReceivedForm() q5.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q5.ReceivedForm{}
	}
	return q5.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ProtocolExtensionField[V]) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
		return q6.Errorf("nil ProtocolExtensionField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.ExtensionValue.matchesID(v.Id, bb.Budget()) {
		return q20.WrapDecodePath(q6.Errorf("%w: field id %d does not match its value selector", q5.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q5.EncodeIntegerAligned(bb, int64(v.Id), q15.BridgeInt64Ptr(0), q15.BridgeInt64Ptr(65535), false); err != nil {
		return q6.Errorf("encoding id: %w", err)
	}
	if err := q5.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q6.Errorf("encoding criticality: %w", err)
	}
	data, err := v.ExtensionValue.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q6.Errorf("encoding extensionValue: %w", err)
	}
	if err := q5.EncodeOpenTypeAligned(bb, data); err != nil {
		return q6.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *ProtocolExtensionField[V]) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ProtocolExtensionField[V]{}
	id, err := q5.DecodeIntegerAligned(bb, q15.BridgeInt64Ptr(0), q15.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q20.WrapDecodePath(err, "Id")
	}
	v.Id = q4.ProtocolIEID(id)
	criticality, err := q5.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q20.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q4.Criticality(criticality)
	var zero V
	raw, err := q5.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return q20.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return q20.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

type ProtocolPrivateValueConstraint[V any] interface {
	captureSemantics(q5.SemanticCapture) V
	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	matchesID(q22.PrivateIEID, *q5.DecodeBudget) bool
	decode(q22.PrivateIEID, q5.OpaqueOpenType) (V, error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	rule() q5.SourceRule
}
type PrivateIEField[V ProtocolPrivateValueConstraint[V]] struct {
	withoutReplay bool
	replay        q5.Snapshot
	stream        q5.WireSpan
	Id            q22.PrivateIEID
	Criticality   q4.Criticality
	Value         V
	received      q5.CompletePadding
}
type PrivateIEContainer[V ProtocolPrivateValueConstraint[V]] []PrivateIEField[V]

func (v PrivateIEField[V]) WithoutReplay() PrivateIEField[V] {
	v.withoutReplay = true
	v.stream = q5.WireSpan{}
	return v
}
func (v *PrivateIEField[V]) ReceivedForm() q5.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q5.ReceivedForm{}
	}
	return q5.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *PrivateIEField[V]) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
		return q6.Errorf("nil PrivateIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the private value to @id, too.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return q20.WrapDecodePath(q6.Errorf("%w: private field id does not match its value selector", q5.ErrInvalidValue), "PrivateIEField.Id")
	}
	if err := q22.BridgePrivateIEIDMethodMarshalAPERTo(&v.Id, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return q6.Errorf("encoding id: %w", err)
	}
	if err := q5.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q6.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return q5.EncodeOpenTypeAligned(bb, data)
}
func (v *PrivateIEField[V]) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil PrivateIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PrivateIEField[V]{}
	if err := q22.BridgePrivateIEIDMethodUnmarshalAPERFrom(&v.Id, bb); err != nil {
		return q20.WrapDecodePath(err, "Id")
	}
	criticality, err := q5.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q20.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q4.Criticality(criticality)
	var zero V
	raw, err := q5.DecodeOpaqueOpenTypeAligned(bb, q5.UnknownSelector, zero.rule())
	if err != nil {
		return q20.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("PrivateIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return q20.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

type ProtocolIEFieldPair[A ProtocolOpenValueConstraint[A], B ProtocolOpenValueConstraint[B]] struct {
	Id                q4.ProtocolIEID
	FirstCriticality  q4.Criticality
	FirstValue        A
	SecondCriticality q4.Criticality
	SecondValue       B
}
type ProtocolIEContainerPair[A ProtocolOpenValueConstraint[A], B ProtocolOpenValueConstraint[B]] []ProtocolIEFieldPair[A, B]
type ProtocolIEContainerPairList[A ProtocolOpenValueConstraint[A], B ProtocolOpenValueConstraint[B]] []ProtocolIEContainerPair[A, B]
type ProtocolIESingleContainer[V ProtocolOpenValueConstraint[V]] = ProtocolIEField[V]
type ErrorIndicationDescriptor struct{}

func ErrorIndicationProcedure() ErrorIndicationDescriptor { return ErrorIndicationDescriptor{} }
func (ErrorIndicationDescriptor) Info() q4.ProcedureInfo {
	return q4.ProcedureInfo{Code: q4.ProcedureCode(0), Criticality: q4.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-errorIndication"}}}
}

type ECIDMeasurementFailureIndicationDescriptor struct{}

func ECIDMeasurementFailureIndicationProcedure() ECIDMeasurementFailureIndicationDescriptor {
	return ECIDMeasurementFailureIndicationDescriptor{}
}
func (ECIDMeasurementFailureIndicationDescriptor) Info() q4.ProcedureInfo {
	return q4.ProcedureInfo{Code: q4.ProcedureCode(3), Criticality: q4.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-e-CIDMeasurementFailureIndication"}}}
}

type ECIDMeasurementReportDescriptor struct{}

func ECIDMeasurementReportProcedure() ECIDMeasurementReportDescriptor {
	return ECIDMeasurementReportDescriptor{}
}
func (ECIDMeasurementReportDescriptor) Info() q4.ProcedureInfo {
	return q4.ProcedureInfo{Code: q4.ProcedureCode(4), Criticality: q4.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-e-CIDMeasurementReport"}}}
}

type ECIDMeasurementTerminationDescriptor struct{}

func ECIDMeasurementTerminationProcedure() ECIDMeasurementTerminationDescriptor {
	return ECIDMeasurementTerminationDescriptor{}
}
func (ECIDMeasurementTerminationDescriptor) Info() q4.ProcedureInfo {
	return q4.ProcedureInfo{Code: q4.ProcedureCode(5), Criticality: q4.CriticalityReject, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-e-CIDMeasurementTermination"}}}
}

type AssistanceInformationFeedbackDescriptor struct{}

func AssistanceInformationFeedbackProcedure() AssistanceInformationFeedbackDescriptor {
	return AssistanceInformationFeedbackDescriptor{}
}
func (AssistanceInformationFeedbackDescriptor) Info() q4.ProcedureInfo {
	return q4.ProcedureInfo{Code: q4.ProcedureCode(10), Criticality: q4.CriticalityReject, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-assistanceInformationFeedback"}}}
}

// AssistanceInformationFeedbackCodec binds the complete APER value type.
func AssistanceInformationFeedbackCodec() q18.AssistanceInformationFeedbackValueCodec {
	return AssistanceInformationFeedbackProcedure().Initiating().Codec()
}

// ECIDMeasurementFailureIndicationCodec binds the complete APER value type.
func ECIDMeasurementFailureIndicationCodec() q12.ECIDMeasurementFailureIndicationValueCodec {
	return ECIDMeasurementFailureIndicationProcedure().Initiating().Codec()
}

// ECIDMeasurementReportCodec binds the complete APER value type.
func ECIDMeasurementReportCodec() q14.ECIDMeasurementReportValueCodec {
	return ECIDMeasurementReportProcedure().Initiating().Codec()
}

// ECIDMeasurementTerminationCommandCodec binds the complete APER value type.
func ECIDMeasurementTerminationCommandCodec() q13.ECIDMeasurementTerminationCommandValueCodec {
	return ECIDMeasurementTerminationProcedure().Initiating().Codec()
}

// ErrorIndicationCodec binds the complete APER value type.
func ErrorIndicationCodec() q12.ErrorIndicationValueCodec {
	return ErrorIndicationProcedure().Initiating().Codec()
}

// LPPAPDUCodec binds the complete source value type.
func LPPAPDUCodec() LPPAPDUValueCodec {
	return LPPAPDUValueCodec{path: "LPPAPDU", decode: func(data []byte, options q5.DecodeState) (LPPAPDU, error) {
		var value LPPAPDU
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return LPPAPDU{}, err
		}
		value.received = true
		value.receivedBytes = q5.OriginalWire(data)
		return value, nil
	}, encode: func(value LPPAPDU, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v LPPAPDU, options q5.DecodeState) (LPPAPDU, q5.Snapshot) {
		s := q5.SemanticCaptureFor(options)
		f :=
			s.Begin()
		BridgeCaptureLPPaLPPAPDU(&v, &s)
		var root q5.Snapshot
		s.
			OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v LPPAPDU, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
		s := q5.NewSemanticComparison(
			root, limits)
		f := s.Begin()
		BridgeCompareLPPaLPPAPDU(&v, &s)
		s.
			End(f, root, false)
		return s.Plan()
	}, context: func() q4.BridgeCodecContext {
		sealed := q4.BridgeCodecContext{}
		*q4.BridgecodecContextFieldSource(&sealed) = "source-value:LPPAPDU"
		return sealed
	}(),
	}
}

// SuccessfulOutcomeCodec binds the complete source value type.
func SuccessfulOutcomeCodec() SuccessfulOutcomeValueCodec {
	return SuccessfulOutcomeValueCodec{path: "SuccessfulOutcome", decode: func(data []byte, options q5.DecodeState) (q9.SuccessfulOutcome, error) {
		var value q9.SuccessfulOutcome
		if err := q9.BridgeSuccessfulOutcomeMethodUnmarshalAPERWithOptions(&value, data, options); err != nil {
			return q9.SuccessfulOutcome{}, err
		}
		*q9.BridgeSuccessfulOutcomeFieldReceived(&value) = true
		*q9.BridgeSuccessfulOutcomeFieldReceivedBytes(&value) = q5.OriginalWire(data)
		return value, nil
	}, encode: func(value q9.SuccessfulOutcome, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return q9.BridgeSuccessfulOutcomeMethodMarshalAPERBudget((&value), budget, fresh)
	}, capture: func(v q9.SuccessfulOutcome, options q5.DecodeState) (q9.SuccessfulOutcome, q5.Snapshot) {
		s := q5.SemanticCaptureFor(options)
		f := s.Begin()
		q9.BridgeCaptureLPPaSuccessfulOutcome(&v, &s)
		var root q5.Snapshot
		s.OperationCounts()
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v q9.SuccessfulOutcome, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
		s := q5.NewSemanticComparison(root, limits)
		f := s.Begin()
		q9.BridgeCompareLPPaSuccessfulOutcome(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q4.BridgeCodecContext {
		sealed := q4.BridgeCodecContext{}
		*q4.BridgecodecContextFieldSource(&sealed) = "source-value:SuccessfulOutcome"
		return sealed
	}(),
	}
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeValidateLPPaIEContainer[V ProtocolOpenValueConstraint[V]](fields ProtocolIEContainer[V], rows []q4.FieldInfo, path string, budget *q5.DecodeBudget,

) q7.ValidationReport {
	report := func() q7.ValidationReport {
		sealed := q7.ValidationReport{Complete: true}
		*q7.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q5.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q7.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q4.ProtocolIEID]int, len(rows))
	counts := make(map[q4.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q7.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q7.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q5.Location{Path: q5.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.ValueIDMismatch, Severity: q4.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q4.TableID {
				sealed := q4.TableID{}
				*q4.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q4.ValueIDMismatch), RelatedRules: []q5.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q5.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q4.FieldInfo
			related := []q5.SourceRule{q19.BridgeLppaAdoptedRule(q4.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.RepeatedIE, Severity: q4.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q4.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q4.ValidationSeverityUnrecognized
			if _, globallyKnown := q19.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q4.ValidationSeverityError
			}
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q4.NotAllowed), RelatedRules: q19.BridgeLppaHandlingRules(q4.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.WrongCriticality, Severity: q4.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q4.WrongCriticality), RelatedRules: []q5.SourceRule{q19.BridgeLppaAdoptedRule(q4.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.WrongOrder, Severity: q4.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q4.WrongOrder), RelatedRules: []q5.SourceRule{q19.BridgeLppaAdoptedRule(q4.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q4.PresenceMandatory && counts[row.ID] == 0 {
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q4.MissingMandatory, Severity: q4.ValidationSeverityError, Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q4.MissingMandatory), RelatedRules: []q5.SourceRule{q19.BridgeLppaAdoptedRule(q4.MissingMandatory), row.Rule}})
		}
		if row.Presence == q4.PresenceConditional {
			q7.BridgeValidationReportMethodAddDeferred(&report, q4.DeferredCondition{Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q7.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeValidateErrorIndicationBudget(v *q12.ErrorIndication, budget *q5.DecodeBudget,

) (q7.ValidationReport, error) {
	if v == nil {
		return func() q7.ValidationReport {
			sealed := q7.ValidationReport{}
			*q7.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q6.Errorf("nil ErrorIndication")
	}
	rows := []q4.FieldInfo{q11.ErrorIndicationIEs().Cause().Info(), q11.ErrorIndicationIEs().CriticalityDiagnostics().Info()}
	report := q12.BridgeErrorIndicationIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "ErrorIndication.protocolIEs", budget)
	BridgeWalkValidationErrorIndication(v, &report, "ErrorIndication", true)
	return report, nil
}
func BridgeValidateECIDMeasurementInitiationFailureBudget(v *q12.ECIDMeasurementInitiationFailure, budget *q5.DecodeBudget,

) (q7.ValidationReport, error) {
	if v == nil {
		return func() q7.ValidationReport {
			sealed := q7.ValidationReport{}
			*q7.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q6.Errorf("nil ECIDMeasurementInitiationFailure")
	}
	rows := []q4.FieldInfo{q11.ECIDMeasurementInitiationFailureIEs().ESMLCUEMeasurementID().Info(), q11.ECIDMeasurementInitiationFailureIEs().Cause().Info(), q11.ECIDMeasurementInitiationFailureIEs().CriticalityDiagnostics().Info()}
	report := q12.BridgeECIDMeasurementInitiationFailureIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "ECIDMeasurementInitiationFailure.protocolIEs", budget)
	BridgeWalkValidationECIDMeasurementInitiationFailure(v, &report, "ECIDMeasurementInitiationFailure", true)
	return report, nil
}
func BridgeValidateECIDMeasurementFailureIndicationBudget(v *q12.ECIDMeasurementFailureIndication, budget *q5.DecodeBudget,

) (q7.ValidationReport, error) {
	if v == nil {
		return func() q7.ValidationReport {
			sealed := q7.ValidationReport{}
			*q7.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q6.Errorf("nil ECIDMeasurementFailureIndication")
	}
	rows := []q4.FieldInfo{q13.ECIDMeasurementFailureIndicationIEs().ESMLCUEMeasurementID().Info(), q13.ECIDMeasurementFailureIndicationIEs().ENBUEMeasurementID().Info(), q13.ECIDMeasurementFailureIndicationIEs().Cause().Info()}
	report := q12.BridgeECIDMeasurementFailureIndicationIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "ECIDMeasurementFailureIndication.protocolIEs", budget)
	BridgeWalkValidationECIDMeasurementFailureIndication(v, &report, "ECIDMeasurementFailureIndication", true)
	return report, nil
}
func BridgeValidateECIDMeasurementReportBudget(v *q14.ECIDMeasurementReport, budget *q5.DecodeBudget,

) (q7.ValidationReport, error) {
	if v == nil {
		return func() q7.ValidationReport {
			sealed := q7.ValidationReport{}
			*q7.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q6.Errorf("nil ECIDMeasurementReport")
	}
	rows := []q4.FieldInfo{q14.ECIDMeasurementReportIEs().ESMLCUEMeasurementID().Info(), q14.ECIDMeasurementReportIEs().ENBUEMeasurementID().Info(), q14.ECIDMeasurementReportIEs().ECIDMeasurementResult().Info(), q14.ECIDMeasurementReportIEs().CellPortionID().Info()}
	report := q14.BridgeECIDMeasurementReportIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "ECIDMeasurementReport.protocolIEs", budget)
	BridgeWalkValidationECIDMeasurementReport(v, &report, "ECIDMeasurementReport", true)
	return report, nil
}
func BridgeValidateECIDMeasurementTerminationCommandBudget(v *q13.ECIDMeasurementTerminationCommand, budget *q5.DecodeBudget,

) (q7.ValidationReport, error) {
	if v == nil {
		return func() q7.ValidationReport {
			sealed := q7.ValidationReport{}
			*q7.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q6.Errorf("nil ECIDMeasurementTerminationCommand")
	}
	rows := []q4.FieldInfo{q15.ECIDMeasurementTerminationCommandIEs().ESMLCUEMeasurementID().Info(), q15.ECIDMeasurementTerminationCommandIEs().ENBUEMeasurementID().Info()}
	report := q12.BridgeECIDMeasurementTerminationCommandIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "ECIDMeasurementTerminationCommand.protocolIEs", budget)
	BridgeWalkValidationECIDMeasurementTerminationCommand(v, &report, "ECIDMeasurementTerminationCommand", true)
	return report, nil
}
func BridgeValidateOTDOAInformationRequestBudget(v *q16.OTDOAInformationRequest, budget *q5.DecodeBudget,

) (q7.ValidationReport, error) {
	if v == nil {
		return func() q7.ValidationReport {
			sealed := q7.ValidationReport{}
			*q7.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q6.Errorf("nil OTDOAInformationRequest")
	}
	rows := []q4.FieldInfo{q16.OTDOAInformationRequestIEs().OTDOAInformationTypeGroup().Info()}
	report := q16.BridgeOTDOAInformationRequestIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "OTDOAInformationRequest.protocolIEs", budget)
	BridgeWalkValidationOTDOAInformationRequest(v, &report, "OTDOAInformationRequest", true)
	return report, nil
}
func BridgeValidateOTDOAInformationFailureBudget(v *q17.OTDOAInformationFailure, budget *q5.DecodeBudget,

) (q7.ValidationReport, error) {
	if v == nil {
		return func() q7.ValidationReport {
			sealed := q7.ValidationReport{}
			*q7.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q6.Errorf("nil OTDOAInformationFailure")
	}
	rows := []q4.FieldInfo{q11.OTDOAInformationFailureIEs().Cause().Info(), q11.OTDOAInformationFailureIEs().CriticalityDiagnostics().Info()}
	report := q17.BridgeOTDOAInformationFailureIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "OTDOAInformationFailure.protocolIEs", budget)
	BridgeWalkValidationOTDOAInformationFailure(v, &report, "OTDOAInformationFailure", true)
	return report, nil
}
func BridgeValidateAssistanceInformationFeedbackBudget(v *q18.AssistanceInformationFeedback, budget *q5.DecodeBudget,

) (q7.ValidationReport, error) {
	if v == nil {
		return func() q7.ValidationReport {
			sealed := q7.ValidationReport{}
			*q7.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q6.Errorf("nil AssistanceInformationFeedback")
	}
	rows := []q4.FieldInfo{q18.AssistanceInformationFeedbackIEs().AssistanceInformationFailureList().Info(), q18.AssistanceInformationFeedbackIEs().CriticalityDiagnostics().Info()}
	report := q18.BridgeAssistanceInformationFeedbackIEValueValidateLPPaIEContainer(v.ProtocolIEs, rows, "AssistanceInformationFeedback.protocolIEs", budget)
	BridgeWalkValidationAssistanceInformationFeedback(v, &report, "AssistanceInformationFeedback", true)
	return report, nil
}
func ValidateErrorIndication(v *q12.ErrorIndication, options ...q5.ValidationOption) (q7.ValidationReport, error) {
	budget, err := q5.ValidationBudget(options...)
	if err != nil {
		return q7.ValidationReport{}, q5.OperationError(err, "ErrorIndication")
	}
	report, err := BridgeValidateErrorIndicationBudget(v, budget)
	if err == nil && !q24.BridgeValidationHasValueMismatch(report) {
		_, err = q12.BridgeErrorIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		err = *q7.BridgeValidationReportFieldErr(&report)
	}
	*q7.BridgeValidationReportFieldBudget(&report) = nil
	*q7.BridgeValidationReportFieldErr(&report) = nil
	return report, q5.OperationError(err, "ErrorIndication")
}
func ValidateECIDMeasurementInitiationFailure(v *q12.ECIDMeasurementInitiationFailure, options ...q5.ValidationOption) (q7.ValidationReport, error) {
	budget, err := q5.ValidationBudget(options...)
	if err != nil {
		return q7.ValidationReport{}, q5.OperationError(err, "ECIDMeasurementInitiationFailure")
	}
	report, err := BridgeValidateECIDMeasurementInitiationFailureBudget(v, budget)
	if err == nil && !q24.BridgeValidationHasValueMismatch(report) {
		_, err = q12.BridgeECIDMeasurementInitiationFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		err = *q7.BridgeValidationReportFieldErr(&report)
	}
	*q7.BridgeValidationReportFieldBudget(&report) = nil
	*q7.BridgeValidationReportFieldErr(&report) = nil
	return report, q5.OperationError(err, "ECIDMeasurementInitiationFailure")
}
func ValidateECIDMeasurementFailureIndication(v *q12.ECIDMeasurementFailureIndication, options ...q5.ValidationOption) (q7.ValidationReport, error) {
	budget, err := q5.ValidationBudget(options...)
	if err != nil {
		return q7.ValidationReport{}, q5.OperationError(err, "ECIDMeasurementFailureIndication")
	}
	report, err := BridgeValidateECIDMeasurementFailureIndicationBudget(v, budget)
	if err == nil && !q24.BridgeValidationHasValueMismatch(report) {
		_, err = q12.BridgeECIDMeasurementFailureIndicationMethodMarshalAPERBudget(v, budget, false)
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		err = *q7.BridgeValidationReportFieldErr(&report)
	}
	*q7.BridgeValidationReportFieldBudget(&report) = nil
	*q7.BridgeValidationReportFieldErr(&report) = nil
	return report, q5.OperationError(err, "ECIDMeasurementFailureIndication")
}
func ValidateECIDMeasurementReport(v *q14.ECIDMeasurementReport, options ...q5.ValidationOption) (q7.ValidationReport, error) {
	budget, err := q5.ValidationBudget(options...)
	if err != nil {
		return q7.ValidationReport{}, q5.OperationError(err, "ECIDMeasurementReport")
	}
	report, err := BridgeValidateECIDMeasurementReportBudget(v, budget)
	if err == nil && !q24.BridgeValidationHasValueMismatch(report) {
		_, err = q14.BridgeECIDMeasurementReportMethodMarshalAPERBudget(v, budget, false)
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		err = *q7.BridgeValidationReportFieldErr(&report)
	}
	*q7.BridgeValidationReportFieldBudget(&report) = nil
	*q7.BridgeValidationReportFieldErr(&report) = nil
	return report, q5.OperationError(err, "ECIDMeasurementReport")
}
func ValidateECIDMeasurementTerminationCommand(v *q13.ECIDMeasurementTerminationCommand, options ...q5.ValidationOption) (q7.ValidationReport, error) {
	budget, err := q5.ValidationBudget(options...)
	if err != nil {
		return q7.ValidationReport{}, q5.OperationError(err, "ECIDMeasurementTerminationCommand")
	}
	report, err := BridgeValidateECIDMeasurementTerminationCommandBudget(v, budget)
	if err == nil && !q24.BridgeValidationHasValueMismatch(report) {
		_, err = q13.BridgeECIDMeasurementTerminationCommandMethodMarshalAPERBudget(v, budget, false)
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		err = *q7.BridgeValidationReportFieldErr(&report)
	}
	*q7.BridgeValidationReportFieldBudget(&report) = nil
	*q7.BridgeValidationReportFieldErr(&report) = nil
	return report, q5.OperationError(err, "ECIDMeasurementTerminationCommand")
}
func ValidateOTDOAInformationRequest(v *q16.OTDOAInformationRequest, options ...q5.ValidationOption) (q7.ValidationReport, error) {
	budget, err := q5.ValidationBudget(options...)
	if err != nil {
		return q7.ValidationReport{}, q5.OperationError(err, "OTDOAInformationRequest")
	}
	report, err := BridgeValidateOTDOAInformationRequestBudget(v, budget)
	if err == nil && !q24.BridgeValidationHasValueMismatch(report) {
		_, err = q16.BridgeOTDOAInformationRequestMethodMarshalAPERBudget(v, budget, false)
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		err = *q7.BridgeValidationReportFieldErr(&report)
	}
	*q7.BridgeValidationReportFieldBudget(&report) = nil
	*q7.BridgeValidationReportFieldErr(&report) = nil
	return report, q5.OperationError(err, "OTDOAInformationRequest")
}
func ValidateOTDOAInformationFailure(v *q17.OTDOAInformationFailure, options ...q5.ValidationOption) (q7.ValidationReport, error) {
	budget, err := q5.ValidationBudget(options...)
	if err != nil {
		return q7.ValidationReport{}, q5.OperationError(err, "OTDOAInformationFailure")
	}
	report, err := BridgeValidateOTDOAInformationFailureBudget(v, budget)
	if err == nil && !q24.BridgeValidationHasValueMismatch(report) {
		_, err = q17.BridgeOTDOAInformationFailureMethodMarshalAPERBudget(v, budget, false)
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		err = *q7.BridgeValidationReportFieldErr(&report)
	}
	*q7.BridgeValidationReportFieldBudget(&report) = nil
	*q7.BridgeValidationReportFieldErr(&report) = nil
	return report, q5.OperationError(err, "OTDOAInformationFailure")
}
func ValidateAssistanceInformationFeedback(v *q18.AssistanceInformationFeedback, options ...q5.ValidationOption) (q7.ValidationReport, error) {
	budget, err := q5.ValidationBudget(options...)
	if err != nil {
		return q7.ValidationReport{}, q5.OperationError(err, "AssistanceInformationFeedback")
	}
	report, err := BridgeValidateAssistanceInformationFeedbackBudget(v, budget)
	if err == nil && !q24.BridgeValidationHasValueMismatch(report) {
		_, err = q18.BridgeAssistanceInformationFeedbackMethodMarshalAPERBudget(v, budget, false)
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		err = *q7.BridgeValidationReportFieldErr(&report)
	}
	*q7.BridgeValidationReportFieldBudget(&report) = nil
	*q7.BridgeValidationReportFieldErr(&report) = nil
	return report, q5.OperationError(err, "AssistanceInformationFeedback")
}
func BridgeValidateLPPaExtensionContainer[V ProtocolOpenValueConstraint[V]](fields ProtocolExtensionContainer[V], rows []q4.FieldInfo, path string, budget *q5.DecodeBudget) q7.ValidationReport {
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[ProtocolIEField[V]](bb, uint64(len(fields))); err != nil {
		return func() q7.ValidationReport {
			sealed := q7.ValidationReport{}
			*q7.BridgeValidationReportFieldErr(&sealed) = err
			*q7.BridgeValidationReportFieldBudget(&sealed) = budget
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
func BridgeWalkValidationAssistanceInformationFailureList(v *q21.AssistanceInformationFailureList, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q7.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationAssistanceInformationFailureListElem(&(*v)[i], report, q6.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationAssistanceInformationFailureListElem(v *q21.AssistanceInformationFailureListElem, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q4.FieldInfo{}
				q12.BridgeMergeNestedValidation(report, q7.BridgeAssistanceInformationFailureListExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q7.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationAssistanceInformationFeedback(v *q18.AssistanceInformationFeedback, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []q4.FieldInfo{q18.AssistanceInformationFeedbackIEs().AssistanceInformationFailureList().Info(), q18.AssistanceInformationFeedbackIEs().CriticalityDiagnostics().Info()}
			q12.BridgeMergeNestedValidation(report, q18.BridgeAssistanceInformationFeedbackIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *q7.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case q4.ProtocolIEID(24):
				if value, ok := fields[i].Value.AsAssistanceInformationFailureList(); ok {
					BridgeWalkValidationAssistanceInformationFailureList(value, report, q6.Sprintf("%s[%d]{id=24}", nestedPath, i), false)
				}
			case q4.ProtocolIEID(1):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, q6.Sprintf("%s[%d]{id=1}", nestedPath, i), false)
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationAssistanceInformationMetaData(v *q21.AssistanceInformationMetaData, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q4.FieldInfo{}
				q12.BridgeMergeNestedValidation(report, q7.BridgeAssistanceInformationMetaDataExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q7.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationBitmapsforNPRS(v *q21.BitmapsforNPRS, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationCause(v *q21.Cause, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationCriticalityDiagnostics(v *q7.CriticalityDiagnostics, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEsCriticalityDiagnostics != nil {
		BridgeWalkValidationCriticalityDiagnosticsIEList(&v.IEsCriticalityDiagnostics, report, path+".iEsCriticalityDiagnostics", false)
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q4.FieldInfo{}
				q12.BridgeMergeNestedValidation(report, q12.BridgeCriticalityDiagnosticsExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q7.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationCriticalityDiagnosticsIEList(v *q21.CriticalityDiagnosticsIEList, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q7.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationCriticalityDiagnosticsIEListElem(&(*v)[i], report, q6.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationCriticalityDiagnosticsIEListElem(v *q21.CriticalityDiagnosticsIEListElem, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q4.FieldInfo{}
				q12.BridgeMergeNestedValidation(report, q12.BridgeCriticalityDiagnosticsIEListExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q7.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationECGI(v *q21.ECGI, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q4.FieldInfo{}
				q12.BridgeMergeNestedValidation(report, q12.BridgeECGIExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q7.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationECIDMeasurementFailureIndication(v *q12.ECIDMeasurementFailureIndication, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []q4.FieldInfo{q13.ECIDMeasurementFailureIndicationIEs().ESMLCUEMeasurementID().Info(), q13.ECIDMeasurementFailureIndicationIEs().ENBUEMeasurementID().Info(), q13.ECIDMeasurementFailureIndicationIEs().Cause().Info()}
			q12.BridgeMergeNestedValidation(report, q12.BridgeECIDMeasurementFailureIndicationIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *q7.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case q4.ProtocolIEID(0):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, q6.Sprintf("%s[%d]{id=0}", nestedPath, i), false)
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationECIDMeasurementInitiationFailure(v *q12.ECIDMeasurementInitiationFailure, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []q4.FieldInfo{q11.ECIDMeasurementInitiationFailureIEs().ESMLCUEMeasurementID().Info(), q11.ECIDMeasurementInitiationFailureIEs().Cause().Info(), q11.ECIDMeasurementInitiationFailureIEs().CriticalityDiagnostics().Info()}
			q12.BridgeMergeNestedValidation(report, q12.BridgeECIDMeasurementInitiationFailureIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *q7.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case q4.ProtocolIEID(0):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, q6.Sprintf("%s[%d]{id=0}", nestedPath, i), false)
				}
			case q4.ProtocolIEID(1):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, q6.Sprintf("%s[%d]{id=1}", nestedPath, i), false)
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationECIDMeasurementReport(v *q14.ECIDMeasurementReport, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []q4.FieldInfo{q14.ECIDMeasurementReportIEs().ESMLCUEMeasurementID().Info(), q14.ECIDMeasurementReportIEs().ENBUEMeasurementID().Info(), q14.ECIDMeasurementReportIEs().ECIDMeasurementResult().Info(), q14.ECIDMeasurementReportIEs().CellPortionID().Info()}
			q12.BridgeMergeNestedValidation(report, q14.BridgeECIDMeasurementReportIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *q7.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case q4.ProtocolIEID(7):
				if value, ok := fields[i].Value.AsECIDMeasurementResult(); ok {
					BridgeWalkValidationECIDMeasurementResult(value, report, q6.Sprintf("%s[%d]{id=7}", nestedPath, i), false)
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationECIDMeasurementResult(v *q14.ECIDMeasurementResult, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationECGI(&v.ServingCellID, report, path+".servingCell-ID", false)
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.EUTRANAccessPointPosition != nil {
		BridgeWalkValidationEUTRANAccessPointPosition(v.EUTRANAccessPointPosition, report, path+".e-UTRANAccessPointPosition", false)
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.MeasuredResults != nil {
		BridgeWalkValidationMeasuredResults(&v.MeasuredResults, report, path+".measuredResults", false)
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationECIDMeasurementTerminationCommand(v *q13.ECIDMeasurementTerminationCommand, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []q4.FieldInfo{q15.ECIDMeasurementTerminationCommandIEs().ESMLCUEMeasurementID().Info(), q15.ECIDMeasurementTerminationCommandIEs().ENBUEMeasurementID().Info()}
			q12.BridgeMergeNestedValidation(report, q12.BridgeECIDMeasurementTerminationCommandIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *q7.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationEUTRANAccessPointPosition(v *q13.EUTRANAccessPointPosition, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationErrorIndication(v *q12.ErrorIndication, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []q4.FieldInfo{q11.ErrorIndicationIEs().Cause().Info(), q11.ErrorIndicationIEs().CriticalityDiagnostics().Info()}
			q12.BridgeMergeNestedValidation(report, q12.BridgeErrorIndicationIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *q7.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case q4.ProtocolIEID(0):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, q6.Sprintf("%s[%d]{id=0}", nestedPath, i), false)
				}
			case q4.ProtocolIEID(1):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, q6.Sprintf("%s[%d]{id=1}", nestedPath, i), false)
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInitiatingMessage(v *q8.InitiatingMessage, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInterRATMeasuredResultsValue(v *q25.InterRATMeasuredResultsValue, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == q4.InterRATMeasuredResultsValueChoiceResultGERAN {
		if v.ResultGERAN != nil {
			BridgeWalkValidationResultGERAN(&v.ResultGERAN, report, path+".resultGERAN", false)
		}
	}
	if v.Choice == q4.InterRATMeasuredResultsValueChoiceResultUTRAN {
		if v.ResultUTRAN != nil {
			BridgeWalkValidationResultUTRAN(&v.ResultUTRAN, report, path+".resultUTRAN", false)
		}
	}
	if v.Choice == q4.InterRATMeasuredResultsValueChoiceResultNR {
		if v.ResultNR != nil {
			BridgeWalkValidationResultNR(&v.ResultNR, report, path+".resultNR", false)
		}
	}
}
func BridgeWalkValidationInterRATMeasurementQuantities(v *q13.InterRATMeasurementQuantities, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q7.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := q6.Sprintf("%s[%d]", path, i)
		rows := []q4.FieldInfo{q13.InterRATMeasurementQuantitiesItemIEs().InterRATMeasurementQuantitiesItem().Info()}
		q12.BridgeMergeNestedValidation(report, q12.BridgeInterRATMeasurementQuantitiesItemIEValueValidateLPPaIEContainer(q13.InterRATMeasurementQuantitiesItemIEContainer{field}, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
		fields := q13.InterRATMeasurementQuantitiesItemIEContainer{field}
		for i := range fields {
			if *q7.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case q4.ProtocolIEID(16):
				if value, ok := fields[i].Value.AsInterRATMeasurementQuantitiesItem(); ok {
					BridgeWalkValidationInterRATMeasurementQuantitiesItem(value, report, q6.Sprintf("%s[%d]{id=16}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationInterRATMeasurementQuantitiesItem(v *q13.InterRATMeasurementQuantitiesItem, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q4.FieldInfo{}
				q12.BridgeMergeNestedValidation(report, q12.BridgeInterRATMeasurementQuantitiesValueExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q7.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationInterRATMeasurementResult(v *q24.InterRATMeasurementResult, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q7.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationInterRATMeasuredResultsValue(&(*v)[i], report, q6.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationMeasuredResults(v *q14.MeasuredResults, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q7.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationMeasuredResultsValue(&(*v)[i], report, q6.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationMeasuredResultsValue(v *q14.MeasuredResultsValue, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.Choice == q4.MeasuredResultsValueChoiceResultRSRP {
		if v.ResultRSRP != nil {
			BridgeWalkValidationResultRSRP(&v.ResultRSRP, report, path+".resultRSRP", false)
		}
	}
	if v.Choice == q4.MeasuredResultsValueChoiceResultRSRQ {
		if v.ResultRSRQ != nil {
			BridgeWalkValidationResultRSRQ(&v.ResultRSRQ, report, path+".resultRSRQ", false)
		}
	}
}
func BridgeWalkValidationMeasurementQuantities(v *q13.MeasurementQuantities, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q7.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := q6.Sprintf("%s[%d]", path, i)
		rows := []q4.FieldInfo{q26.MeasurementQuantitiesItemIEs().MeasurementQuantitiesItem().Info()}
		q12.BridgeMergeNestedValidation(report, q12.BridgeMeasurementQuantitiesItemIEValueValidateLPPaIEContainer(q13.MeasurementQuantitiesItemIEContainer{field}, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
		fields := q13.MeasurementQuantitiesItemIEContainer{field}
		for i := range fields {
			if *q7.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case q4.ProtocolIEID(11):
				if value, ok := fields[i].Value.AsMeasurementQuantitiesItem(); ok {
					BridgeWalkValidationMeasurementQuantitiesItem(value, report, q6.Sprintf("%s[%d]{id=11}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationMeasurementQuantitiesItem(v *q13.MeasurementQuantitiesItem, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q4.FieldInfo{}
				q12.BridgeMergeNestedValidation(report, q12.BridgeMeasurementQuantitiesValueExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q7.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationNPRSConfiguration(v *q26.NPRSConfiguration, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if v.NPRSSubframePartA != nil {
		BridgeWalkValidationNPRSSubframePartA(v.NPRSSubframePartA, report, path+".nPRSSubframePartA", false)
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.NPRSSubframePartB != nil {
		BridgeWalkValidationNPRSSubframePartB(v.NPRSSubframePartB, report, path+".nPRSSubframePartB", false)
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationNPRSMutingConfiguration(v *q26.NPRSMutingConfiguration, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationNPRSSubframePartA(v *q26.NPRSSubframePartA, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	BridgeWalkValidationBitmapsforNPRS(&v.BitmapsforNPRS, report, path+".bitmapsforNPRS", false)
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.NPRSMutingConfiguration != nil {
		BridgeWalkValidationNPRSMutingConfiguration(v.NPRSMutingConfiguration, report, path+".nPRSMutingConfiguration", false)
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationNPRSSubframePartB(v *q26.NPRSSubframePartB, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.NPRSMutingConfiguration != nil {
		BridgeWalkValidationNPRSMutingConfiguration(v.NPRSMutingConfiguration, report, path+".nPRSMutingConfiguration", false)
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationNRCGI(v *q26.NRCGI, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q4.FieldInfo{}
				q12.BridgeMergeNestedValidation(report, q12.BridgeNRCGIExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q7.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationOTDOAInformationFailure(v *q17.OTDOAInformationFailure, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []q4.FieldInfo{q11.OTDOAInformationFailureIEs().Cause().Info(), q11.OTDOAInformationFailureIEs().CriticalityDiagnostics().Info()}
			q12.BridgeMergeNestedValidation(report, q17.BridgeOTDOAInformationFailureIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *q7.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case q4.ProtocolIEID(0):
				if value, ok := fields[i].Value.AsCause(); ok {
					BridgeWalkValidationCause(value, report, q6.Sprintf("%s[%d]{id=0}", nestedPath, i), false)
				}
			case q4.ProtocolIEID(1):
				if value, ok := fields[i].Value.AsCriticalityDiagnostics(); ok {
					BridgeWalkValidationCriticalityDiagnostics(value, report, q6.Sprintf("%s[%d]{id=1}", nestedPath, i), false)
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationOTDOAInformationRequest(v *q16.OTDOAInformationRequest, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	{
		fields := v.ProtocolIEs
		nestedPath := path + ".ProtocolIEs"
		if !skipRoot {
			rows := []q4.FieldInfo{q16.OTDOAInformationRequestIEs().OTDOAInformationTypeGroup().Info()}
			q12.BridgeMergeNestedValidation(report, q16.BridgeOTDOAInformationRequestIEValueValidateLPPaIEContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
		}
		for i := range fields {
			if *q7.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case q4.ProtocolIEID(9):
				if value, ok := fields[i].Value.AsOTDOAInformationTypeGroup(); ok {
					BridgeWalkValidationOTDOAInformationType(value, report, q6.Sprintf("%s[%d]{id=9}", nestedPath, i), false)
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationOTDOAInformationType(v *q26.OTDOAInformationType, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q7.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		field := (*v)[i]
		nestedPath := q6.Sprintf("%s[%d]", path, i)
		rows := []q4.FieldInfo{q26.OTDOAInformationTypeIEs().OTDOAInformationTypeItem().Info()}
		q12.BridgeMergeNestedValidation(report, q17.BridgeOTDOAInformationTypeIEValueValidateLPPaIEContainer(q26.OTDOAInformationTypeIEContainer{field}, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
		fields := q26.OTDOAInformationTypeIEContainer{field}
		for i := range fields {
			if *q7.BridgeValidationReportFieldErr(report) != nil {
				return
			}
			switch fields[i].Id {
			case q4.ProtocolIEID(10):
				if value, ok := fields[i].Value.AsOTDOAInformationTypeItem(); ok {
					BridgeWalkValidationOTDOAInformationTypeItem(value, report, q6.Sprintf("%s[%d]{id=10}", nestedPath, i), false)
				}
			}
		}
	}
}
func BridgeWalkValidationOTDOAInformationTypeItem(v *q26.OTDOAInformationTypeItem, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q4.FieldInfo{}
				q12.BridgeMergeNestedValidation(report, q17.BridgeOTDOAInformationTypeItemExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q7.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPRSFrequencyHoppingConfiguration(v *q22.PRSFrequencyHoppingConfiguration, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationPRSFrequencyHoppingConfigurationBandPositions(&v.BandPositions, report, path+".bandPositions", false)
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q4.FieldInfo{}
				q12.BridgeMergeNestedValidation(report, q17.BridgePRSFrequencyHoppingConfigurationItemIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q7.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPRSFrequencyHoppingConfigurationBandPositions(v *q4.PRSFrequencyHoppingConfigurationBandPositions, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationPRSMutingConfiguration(v *q22.PRSMutingConfiguration, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationPosSIBSegments(v *q22.PosSIBSegments, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q7.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationPosSIBSegmentsElem(&(*v)[i], report, q6.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationPosSIBSegmentsElem(v *q22.PosSIBSegmentsElem, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q4.FieldInfo{}
				q12.BridgeMergeNestedValidation(report, q17.BridgePosSIBSegmentsExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q7.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPosSIBs(v *q11.PosSIBs, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q7.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationPosSIBsElem(&(*v)[i], report, q6.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationPosSIBsElem(v *q11.PosSIBsElem, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationPosSIBSegments(&v.PosSIBSegments, report, path+".posSIB-Segments", false)
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.AssistanceInformationMetaData != nil {
		BridgeWalkValidationAssistanceInformationMetaData(v.AssistanceInformationMetaData, report, path+".assistanceInformationMetaData", false)
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q4.FieldInfo{}
				q12.BridgeMergeNestedValidation(report, q17.BridgePosSIBsExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q7.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationPrivateIEID(v *q22.PrivateIEID, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationPrivateMessage(v *q17.PrivateMessage, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationRequestedSRSTransmissionCharacteristics(v *q22.RequestedSRSTransmissionCharacteristics, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationResultGERAN(v *q17.ResultGERAN, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q7.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationResultGERANItem(&(*v)[i], report, q6.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationResultGERANItem(v *q17.ResultGERANItem, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q4.FieldInfo{}
				q12.BridgeMergeNestedValidation(report, q17.BridgeResultGERANItemExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q7.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationResultNR(v *q25.ResultNR, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q7.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationResultNRItem(&(*v)[i], report, q6.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationResultNRItem(v *q25.ResultNRItem, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q4.FieldInfo{q25.ResultNRItemExtIEs().ResultsPerSSBIndexList().Info(), q25.ResultNRItemExtIEs().NRCGI().Info()}
				q12.BridgeMergeNestedValidation(report, q24.BridgeResultNRItemExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q7.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				case q4.ProtocolIEID(25):
					if value, ok := fields[i].ExtensionValue.AsResultsPerSSBIndexList(); ok {
						BridgeWalkValidationResultsPerSSBIndexList(value, report, q6.Sprintf("%s[%d]{id=25}", nestedPath, i), false)
					}
				case q4.ProtocolIEID(27):
					if value, ok := fields[i].ExtensionValue.AsNRCGI(); ok {
						BridgeWalkValidationNRCGI(value, report, q6.Sprintf("%s[%d]{id=27}", nestedPath, i), false)
					}
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationResultRSRP(v *q17.ResultRSRP, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q7.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationResultRSRPItem(&(*v)[i], report, q6.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationResultRSRPItem(v *q17.ResultRSRPItem, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.ECGI != nil {
		BridgeWalkValidationECGI(v.ECGI, report, path+".eCGI", false)
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q4.FieldInfo{}
				q12.BridgeMergeNestedValidation(report, q17.BridgeResultRSRPItemExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q7.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationResultRSRQ(v *q14.ResultRSRQ, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q7.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationResultRSRQItem(&(*v)[i], report, q6.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationResultRSRQItem(v *q14.ResultRSRQItem, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.ECGI != nil {
		BridgeWalkValidationECGI(v.ECGI, report, path+".eCGI", false)
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q4.FieldInfo{}
				q12.BridgeMergeNestedValidation(report, q14.BridgeResultRSRQItemExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q7.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationResultUTRAN(v *q27.ResultUTRAN, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q7.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationResultUTRANItem(&(*v)[i], report, q6.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationResultUTRANItem(v *q27.ResultUTRANItem, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	BridgeWalkValidationResultUTRANItemPhysCellIDUTRAN(&v.PhysCellIDUTRAN, report, path+".physCellIDUTRAN", false)
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q4.FieldInfo{}
				q12.BridgeMergeNestedValidation(report, q27.BridgeResultUTRANItemExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q7.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationResultUTRANItemPhysCellIDUTRAN(v *q22.ResultUTRANItemPhysCellIDUTRAN, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
}
func BridgeWalkValidationResultsPerSSBIndexItem(v *q27.ResultsPerSSBIndexItem, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if v.IEExtensions != nil {
		{
			fields := v.IEExtensions
			nestedPath := path + ".IEExtensions"
			if !skipRoot {
				rows := []q4.FieldInfo{}
				q12.BridgeMergeNestedValidation(report, q27.BridgeResultsPerSSBIndexItemExtIEsValueValidateLPPaExtensionContainer(fields, rows, nestedPath, *q7.BridgeValidationReportFieldBudget(report)))
			}
			for i := range fields {
				if *q7.BridgeValidationReportFieldErr(report) != nil {
					return
				}
				switch fields[i].Id {
				}
			}
		}
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeWalkValidationResultsPerSSBIndexList(v *q27.ResultsPerSSBIndexList, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q7.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationResultsPerSSBIndexItem(&(*v)[i], report, q6.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationSRSConfigurationForAllCells(v *q7.SRSConfigurationForAllCells, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	for i := range *v {
		if *q7.BridgeValidationReportFieldErr(report) != nil {
			return
		}
		BridgeWalkValidationSRSConfigurationForOneCell(&(*v)[i], report, q6.Sprintf("%s[%d]", path, i), false)
	}
}
func BridgeWalkValidationSRSConfigurationForOneCell(v *q7.SRSConfigurationForOneCell, report *q7.ValidationReport, path string, skipRoot bool) {
	if v == nil || report == nil || *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	bb := q5.NewBudgetBuffer(*q7.BridgeValidationReportFieldBudget(report))
	if err := bb.EnterDecodeValue(); err != nil {
		*q7.BridgeValidationReportFieldErr(report) = err
		return
	}
	defer bb.LeaveDecodeValue()
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
	if *q7.BridgeValidationReportFieldErr(report) != nil {
		return
	}
}
func BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldCapture(v *ECIDMeasurementInitiationResponseSuccessfulBinding) *func(q9.ECIDMeasurementInitiationResponse, q5.DecodeState) (q9.ECIDMeasurementInitiationResponse, q5.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldCompare(v *ECIDMeasurementInitiationResponseSuccessfulBinding) *func(q9.ECIDMeasurementInitiationResponse, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldContext(v *ECIDMeasurementInitiationResponseSuccessfulBinding) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldDecode(v *ECIDMeasurementInitiationResponseSuccessfulBinding) *func([]byte, q5.DecodeState) (q9.ECIDMeasurementInitiationResponse, error) {
	return &v.decode
}
func BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldEncode(v *ECIDMeasurementInitiationResponseSuccessfulBinding) *func(*q9.ECIDMeasurementInitiationResponse, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldInfo(v *ECIDMeasurementInitiationResponseSuccessfulBinding) *q4.ProcedureInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldInject(v *ECIDMeasurementInitiationResponseSuccessfulBinding) *func(q9.ECIDMeasurementInitiationResponse) q9.SuccessfulValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationResponseSuccessfulBindingFieldValidate(v *ECIDMeasurementInitiationResponseSuccessfulBinding) *func(*q9.ECIDMeasurementInitiationResponse, *q5.DecodeBudget) (q7.ValidationReport, error) {
	return &v.validate
}
func BridgeLPPAPDUAPERValueFieldContext(v *LPPAPDUAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeLPPAPDUAPERValueFieldReceived(v *LPPAPDUAPERValue) *q5.WireSpan { return &v.received }
func BridgeLPPAPDUAPERValueFieldReplay(v *LPPAPDUAPERValue) *q5.Snapshot   { return &v.replay }
func BridgeLPPAPDUAPERValueFieldWithoutReplay(v *LPPAPDUAPERValue) *bool   { return &v.withoutReplay }
func BridgeLPPAPDUFieldKnownOpenBytes(v *LPPAPDU) *uint64                  { return &v.knownOpenBytes }
func BridgeLPPAPDUFieldPerOpenTypePadding(v *LPPAPDU) *q5.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeLPPAPDUFieldPerPadding(v *LPPAPDU) *q5.CompletePadding { return &v.perPadding }
func BridgeLPPAPDUFieldReceived(v *LPPAPDU) *bool                 { return &v.received }
func BridgeLPPAPDUFieldReceivedBytes(v *LPPAPDU) *q5.WireSpan     { return &v.receivedBytes }
func BridgeLPPAPDUFieldReplay(v *LPPAPDU) *q5.Snapshot            { return &v.replay }
func BridgeLPPAPDUFieldStream(v *LPPAPDU) *q5.WireSpan            { return &v.stream }
func BridgeLPPAPDUFieldWithoutReplay(v *LPPAPDU) *bool            { return &v.withoutReplay }
func BridgeLPPAPDUMethodMarshalAPERBudget(v *LPPAPDU, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeLPPAPDUMethodMarshalAPERChanged(v *LPPAPDU, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeLPPAPDUMethodMarshalAPERChangedValue(v *LPPAPDU, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeLPPAPDUMethodMarshalAPERFreshValue(v *LPPAPDU, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeLPPAPDUMethodMarshalAPERLegacy(v *LPPAPDU) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeLPPAPDUMethodMarshalAPERPlanned(v *LPPAPDU, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeLPPAPDUMethodMarshalAPERTo(v *LPPAPDU, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeLPPAPDUMethodUnmarshalAPERFrom(v *LPPAPDU, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeLPPAPDUMethodUnmarshalAPERLegacy(v *LPPAPDU, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeLPPAPDUMethodUnmarshalAPERWithOptions(v *LPPAPDU, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeLPPAPDUValueCodecFieldCapture(v *LPPAPDUValueCodec) *func(LPPAPDU, q5.DecodeState) (LPPAPDU, q5.Snapshot) {
	return &v.capture
}
func BridgeLPPAPDUValueCodecFieldCompare(v *LPPAPDUValueCodec) *func(LPPAPDU, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeLPPAPDUValueCodecFieldContext(v *LPPAPDUValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeLPPAPDUValueCodecFieldDecode(v *LPPAPDUValueCodec) *func([]byte, q5.DecodeState) (LPPAPDU, error) {
	return &v.decode
}
func BridgeLPPAPDUValueCodecFieldEncode(v *LPPAPDUValueCodec) *func(LPPAPDU, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLPPAPDUValueCodecFieldPath(v *LPPAPDUValueCodec) *q5.Path { return &v.path }
func BridgeLPPAPDUValueCodecMethodEncodeBudget(v LPPAPDUValueCodec, a0 LPPAPDU, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeLPPAPDUValueCodecMethodEncodeChanged(v LPPAPDUValueCodec, a0 LPPAPDU, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOAInformationResponseSuccessfulBindingFieldCapture(v *OTDOAInformationResponseSuccessfulBinding) *func(q16.OTDOAInformationResponse, q5.DecodeState) (q16.OTDOAInformationResponse, q5.Snapshot) {
	return &v.capture
}
func BridgeOTDOAInformationResponseSuccessfulBindingFieldCompare(v *OTDOAInformationResponseSuccessfulBinding) *func(q16.OTDOAInformationResponse, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeOTDOAInformationResponseSuccessfulBindingFieldContext(v *OTDOAInformationResponseSuccessfulBinding) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationResponseSuccessfulBindingFieldDecode(v *OTDOAInformationResponseSuccessfulBinding) *func([]byte, q5.DecodeState) (q16.OTDOAInformationResponse, error) {
	return &v.decode
}
func BridgeOTDOAInformationResponseSuccessfulBindingFieldEncode(v *OTDOAInformationResponseSuccessfulBinding) *func(*q16.OTDOAInformationResponse, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOAInformationResponseSuccessfulBindingFieldInfo(v *OTDOAInformationResponseSuccessfulBinding) *q4.ProcedureInfo {
	return &v.info
}
func BridgeOTDOAInformationResponseSuccessfulBindingFieldInject(v *OTDOAInformationResponseSuccessfulBinding) *func(q16.OTDOAInformationResponse) q9.SuccessfulValue {
	return &v.inject
}
func BridgeOTDOAInformationResponseSuccessfulBindingFieldValidate(v *OTDOAInformationResponseSuccessfulBinding) *func(*q16.OTDOAInformationResponse, *q5.DecodeBudget) (q7.ValidationReport, error) {
	return &v.validate
}
func BridgeSuccessfulOutcomeAPERValueFieldContext(v *SuccessfulOutcomeAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeSuccessfulOutcomeAPERValueFieldReceived(v *SuccessfulOutcomeAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeSuccessfulOutcomeAPERValueFieldReplay(v *SuccessfulOutcomeAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeSuccessfulOutcomeAPERValueFieldWithoutReplay(v *SuccessfulOutcomeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSuccessfulOutcomeValueCodecFieldCapture(v *SuccessfulOutcomeValueCodec) *func(q9.SuccessfulOutcome, q5.DecodeState) (q9.SuccessfulOutcome, q5.Snapshot) {
	return &v.capture
}
func BridgeSuccessfulOutcomeValueCodecFieldCompare(v *SuccessfulOutcomeValueCodec) *func(q9.SuccessfulOutcome, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeSuccessfulOutcomeValueCodecFieldContext(v *SuccessfulOutcomeValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeSuccessfulOutcomeValueCodecFieldDecode(v *SuccessfulOutcomeValueCodec) *func([]byte, q5.DecodeState) (q9.SuccessfulOutcome, error) {
	return &v.decode
}
func BridgeSuccessfulOutcomeValueCodecFieldEncode(v *SuccessfulOutcomeValueCodec) *func(q9.SuccessfulOutcome, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSuccessfulOutcomeValueCodecFieldPath(v *SuccessfulOutcomeValueCodec) *q5.Path {
	return &v.path
}
func BridgeSuccessfulOutcomeValueCodecMethodEncodeBudget(v SuccessfulOutcomeValueCodec, a0 q9.SuccessfulOutcome, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSuccessfulOutcomeValueCodecMethodEncodeChanged(v SuccessfulOutcomeValueCodec, a0 q9.SuccessfulOutcome, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUTDOAInformationResponseSuccessfulBindingFieldCapture(v *UTDOAInformationResponseSuccessfulBinding) *func(q18.UTDOAInformationResponse, q5.DecodeState) (q18.UTDOAInformationResponse, q5.Snapshot) {
	return &v.capture
}
func BridgeUTDOAInformationResponseSuccessfulBindingFieldCompare(v *UTDOAInformationResponseSuccessfulBinding) *func(q18.UTDOAInformationResponse, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeUTDOAInformationResponseSuccessfulBindingFieldContext(v *UTDOAInformationResponseSuccessfulBinding) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationResponseSuccessfulBindingFieldDecode(v *UTDOAInformationResponseSuccessfulBinding) *func([]byte, q5.DecodeState) (q18.UTDOAInformationResponse, error) {
	return &v.decode
}
func BridgeUTDOAInformationResponseSuccessfulBindingFieldEncode(v *UTDOAInformationResponseSuccessfulBinding) *func(*q18.UTDOAInformationResponse, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTDOAInformationResponseSuccessfulBindingFieldInfo(v *UTDOAInformationResponseSuccessfulBinding) *q4.ProcedureInfo {
	return &v.info
}
func BridgeUTDOAInformationResponseSuccessfulBindingFieldInject(v *UTDOAInformationResponseSuccessfulBinding) *func(q18.UTDOAInformationResponse) q9.SuccessfulValue {
	return &v.inject
}
func BridgeUTDOAInformationResponseSuccessfulBindingFieldValidate(v *UTDOAInformationResponseSuccessfulBinding) *func(*q18.UTDOAInformationResponse, *q5.DecodeBudget) (q7.ValidationReport, error) {
	return &v.validate
}
