// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s21 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s21

import (
	q9 "fmt"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q20 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"
	q21 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q11 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q19 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q22 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	q6 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s12"
	q13 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s13"
	q18 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s15"
	q16 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s16"
	q17 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s17"
	q15 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s18"
	q7 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s20"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

func (PrivateMessageDescriptor) Initiating() PrivateMessageInitiatingBinding {
	return PrivateMessageInitiatingBinding{info: PrivateMessageProcedure().Info(), validate: func(v *q4.PrivateMessage, budget *q5.DecodeBudget) (q6.ValidationReport, error) {
		return q7.BridgeValidatePrivateMessageBudget(v, budget)
	}, encode: func(v *q4.PrivateMessage, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return q4.BridgePrivateMessageMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options q5.DecodeState) (q4.PrivateMessage, error) {
		var v q4.PrivateMessage
		err := q4.BridgePrivateMessageMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return q4.PrivateMessage{}, err
		}
		*q4.BridgePrivateMessageFieldReceived(&v) = true
		*q4.BridgePrivateMessageFieldReceivedBytes(&v) = q5.OriginalWire(data)
		return v, nil
	}, inject: func(v q4.PrivateMessage) InitiatingValue {
		return InitiatingValue{code: q8.ProcedureCode(1), bodyPrivateMessage: &v}
	}, capture: func(v q4.PrivateMessage, options q5.DecodeState) (q4.PrivateMessage, q5.Snapshot) {
		s := q5.SemanticCaptureFor(options)
		f := s.
			Begin()
		q4.BridgeCaptureLPPaPrivateMessage(&v, &s)
		var root q5.Snapshot

		s.OperationCounts()
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v q4.PrivateMessage, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
		s := q5.NewSemanticComparison(root,
			limits)
		f := s.Begin()
		q4.BridgeCompareLPPaPrivateMessage(&v, &s)
		s.
			End(f, root, false)
		return s.Plan()
	}, context: func() q8.BridgeCodecContext {
		sealed := q8.BridgeCodecContext{}
		*q8.BridgecodecContextFieldSource(&sealed) = "source-value:PrivateMessage"
		return sealed
	}(),
	}
}

// ECIDMeasurementInitiationRequestIEContainer is the concrete ProtocolIEContainer[ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestIEContainer []ECIDMeasurementInitiationRequestIEField

// ECIDMeasurementInitiationRequestIEField is the concrete ProtocolIEField[ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestIEField struct {
	withoutReplay bool
	replay        q5.Snapshot
	stream        q5.WireSpan
	Id            q8.ProtocolIEID
	Criticality   q8.Criticality
	Value         q7.ECIDMeasurementInitiationRequestIEValue

	received q5.CompletePadding
}

func (v ECIDMeasurementInitiationRequestIEField) WithoutReplay() ECIDMeasurementInitiationRequestIEField {
	v.withoutReplay = true
	v.stream = q5.WireSpan{}
	return v
}
func (v *ECIDMeasurementInitiationRequestIEField) ReceivedForm() q5.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q5.ReceivedForm{}
	}
	return q5.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ECIDMeasurementInitiationRequestIEField) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
		return q9.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !q7.BridgeECIDMeasurementInitiationRequestIEValueMethodMatchesID(v.Value, v.Id, bb.Budget()) {
		return q10.WrapDecodePath(q9.Errorf("%w: field id %d does not match its value selector", q5.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q5.EncodeIntegerAligned(bb, int64(v.Id), q11.BridgeInt64Ptr(0), q11.BridgeInt64Ptr(65535), false); err != nil {
		return q9.Errorf("encoding id: %w", err)
	}
	if err := q5.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q9.Errorf("encoding criticality: %w", err)
	}
	data, err := q7.BridgeECIDMeasurementInitiationRequestIEValueMethodEncodeFresh(v.Value, len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q9.Errorf("encoding value: %w", err)
	}
	if err := q5.EncodeOpenTypeAligned(bb, data); err != nil {
		return q9.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ECIDMeasurementInitiationRequestIEField) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q9.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementInitiationRequestIEField{}
	id, err := q5.DecodeIntegerAligned(bb, q11.BridgeInt64Ptr(0), q11.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q10.WrapDecodePath(err, "Id")
	}
	v.Id = q8.ProtocolIEID(id)
	criticality, err := q5.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q10.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q8.Criticality(criticality)
	var zero q7.ECIDMeasurementInitiationRequestIEValue

	raw, err := q5.DecodeOpaqueOpenTypeAligned(bb, q7.BridgeECIDMeasurementInitiationRequestIEValueMethodReason(zero, v.Id), q7.BridgeECIDMeasurementInitiationRequestIEValueMethodRule(zero))
	if err != nil {
		return q10.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := q7.BridgeECIDMeasurementInitiationRequestIEValueMethodDecode(zero, v.Id, raw)
	if err != nil {
		return q10.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ErrorIndicationInitiatingBinding is the concrete InitiatingBinding[ErrorIndication].
type ErrorIndicationInitiatingBinding struct {
	context q8.BridgeCodecContext
	capture func(q12.ErrorIndication, q5.DecodeState,

	) (q12.ErrorIndication, q5.Snapshot,

	)
	compare func(q12.ErrorIndication, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	info     q8.ProcedureInfo
	validate func(*q12.ErrorIndication,

		*q5.DecodeBudget) (q6.ValidationReport, error)
	encode func(*q12.ErrorIndication,

		bool, *q5.DecodeBudget) ([]byte, error)
	decode func([]byte, q5.DecodeState) (q12.ErrorIndication,

		error)
	inject func(q12.ErrorIndication,

	) InitiatingValue
}

func (b ErrorIndicationInitiatingBinding) Info() q8.ProcedureInfo { return b.info }
func (b ErrorIndicationInitiatingBinding) Codec() q12.ErrorIndicationValueCodec {
	return func() q12.ErrorIndicationValueCodec {
		sealed := q12.ErrorIndicationValueCodec{}
		*q12.BridgeErrorIndicationValueCodecFieldPath(&sealed) = q5.Path(b.info.Rule.Assignment.Assignment)
		*q12.BridgeErrorIndicationValueCodecFieldDecode(&sealed) = b.decode
		*q12.BridgeErrorIndicationValueCodecFieldEncode(&sealed) = func(value q12.ErrorIndication,

			fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*q12.BridgeErrorIndicationValueCodecFieldCapture(&sealed) = b.capture
		*q12.BridgeErrorIndicationValueCodecFieldCompare(&sealed) = b.compare
		*q12.BridgeErrorIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}
func (b ErrorIndicationInitiatingBinding) Build(body q12.ErrorIndication,

	transactionID q8.LPPATransactionID, options ...q5.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("%w: unbound procedure binding", q5.ErrInvalidValue), "Build")
	}
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if err := q8.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, q5.OperationError(&q6.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q5.OperationError(nil, "Build")
}

// PrivateMessageInitiatingBinding is the concrete InitiatingBinding[PrivateMessage].
type PrivateMessageInitiatingBinding struct {
	context q8.BridgeCodecContext
	capture func(q4.PrivateMessage, q5.DecodeState,

	) (q4.PrivateMessage, q5.Snapshot,

	)
	compare func(q4.PrivateMessage, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	info     q8.ProcedureInfo
	validate func(*q4.PrivateMessage,

		*q5.DecodeBudget) (q6.ValidationReport, error)
	encode func(*q4.PrivateMessage,

		bool, *q5.DecodeBudget) ([]byte, error)
	decode func([]byte, q5.DecodeState) (q4.PrivateMessage,

		error)
	inject func(q4.PrivateMessage,

	) InitiatingValue
}

func (b PrivateMessageInitiatingBinding) Info() q8.ProcedureInfo { return b.info }
func (b PrivateMessageInitiatingBinding) Codec() q4.PrivateMessageValueCodec {
	return func() q4.PrivateMessageValueCodec {
		sealed := q4.PrivateMessageValueCodec{}
		*q4.BridgePrivateMessageValueCodecFieldPath(&sealed) = q5.Path(b.info.Rule.Assignment.Assignment)
		*q4.BridgePrivateMessageValueCodecFieldDecode(&sealed) = b.decode
		*q4.BridgePrivateMessageValueCodecFieldEncode(&sealed) = func(value q4.PrivateMessage,

			fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*q4.BridgePrivateMessageValueCodecFieldCapture(&sealed) = b.capture
		*q4.BridgePrivateMessageValueCodecFieldCompare(&sealed) = b.compare
		*q4.BridgePrivateMessageValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}
func (b PrivateMessageInitiatingBinding) Build(body q4.PrivateMessage,

	transactionID q8.LPPATransactionID, options ...q5.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("%w: unbound procedure binding", q5.ErrInvalidValue), "Build")
	}
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if err := q8.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, q5.OperationError(&q6.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q5.OperationError(nil, "Build")
}

// ECIDMeasurementInitiationRequestInitiatingBinding is the concrete InitiatingBinding[ECIDMeasurementInitiationRequest].
type ECIDMeasurementInitiationRequestInitiatingBinding struct {
	context q8.BridgeCodecContext
	capture func(ECIDMeasurementInitiationRequest, q5.DecodeState,

	) (ECIDMeasurementInitiationRequest, q5.Snapshot,

	)
	compare func(ECIDMeasurementInitiationRequest, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	info     q8.ProcedureInfo
	validate func(*ECIDMeasurementInitiationRequest,

		*q5.DecodeBudget) (q6.ValidationReport, error)
	encode func(*ECIDMeasurementInitiationRequest,

		bool, *q5.DecodeBudget) ([]byte, error)
	decode func([]byte, q5.DecodeState) (ECIDMeasurementInitiationRequest,

		error)
	inject func(ECIDMeasurementInitiationRequest,

	) InitiatingValue
}

func (b ECIDMeasurementInitiationRequestInitiatingBinding) Info() q8.ProcedureInfo { return b.info }
func (b ECIDMeasurementInitiationRequestInitiatingBinding) Codec() ECIDMeasurementInitiationRequestValueCodec {
	return ECIDMeasurementInitiationRequestValueCodec{path: q5.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value ECIDMeasurementInitiationRequest,

		fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}
func (b ECIDMeasurementInitiationRequestInitiatingBinding) Build(body ECIDMeasurementInitiationRequest,

	transactionID q8.LPPATransactionID, options ...q5.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("%w: unbound procedure binding", q5.ErrInvalidValue), "Build")
	}
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if err := q8.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, q5.OperationError(&q6.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q5.OperationError(nil, "Build")
}

// ECIDMeasurementFailureIndicationInitiatingBinding is the concrete InitiatingBinding[ECIDMeasurementFailureIndication].
type ECIDMeasurementFailureIndicationInitiatingBinding struct {
	context q8.BridgeCodecContext
	capture func(q12.ECIDMeasurementFailureIndication, q5.DecodeState,

	) (q12.ECIDMeasurementFailureIndication, q5.Snapshot,

	)
	compare func(q12.ECIDMeasurementFailureIndication, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	info     q8.ProcedureInfo
	validate func(*q12.ECIDMeasurementFailureIndication,

		*q5.DecodeBudget) (q6.ValidationReport, error)
	encode func(*q12.ECIDMeasurementFailureIndication,

		bool, *q5.DecodeBudget) ([]byte, error)
	decode func([]byte, q5.DecodeState) (q12.ECIDMeasurementFailureIndication,

		error)
	inject func(q12.ECIDMeasurementFailureIndication,

	) InitiatingValue
}

func (b ECIDMeasurementFailureIndicationInitiatingBinding) Info() q8.ProcedureInfo { return b.info }
func (b ECIDMeasurementFailureIndicationInitiatingBinding) Codec() q12.ECIDMeasurementFailureIndicationValueCodec {
	return func() q12.ECIDMeasurementFailureIndicationValueCodec {
		sealed := q12.ECIDMeasurementFailureIndicationValueCodec{}
		*q12.BridgeECIDMeasurementFailureIndicationValueCodecFieldPath(&sealed) = q5.Path(b.info.Rule.Assignment.Assignment)
		*q12.BridgeECIDMeasurementFailureIndicationValueCodecFieldDecode(&sealed) = b.decode
		*q12.BridgeECIDMeasurementFailureIndicationValueCodecFieldEncode(&sealed) = func(value q12.ECIDMeasurementFailureIndication,

			fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*q12.BridgeECIDMeasurementFailureIndicationValueCodecFieldCapture(&sealed) = b.capture
		*q12.BridgeECIDMeasurementFailureIndicationValueCodecFieldCompare(&sealed) = b.compare
		*q12.BridgeECIDMeasurementFailureIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}
func (b ECIDMeasurementFailureIndicationInitiatingBinding) Build(body q12.ECIDMeasurementFailureIndication,

	transactionID q8.LPPATransactionID, options ...q5.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("%w: unbound procedure binding", q5.ErrInvalidValue), "Build")
	}
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if err := q8.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, q5.OperationError(&q6.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q5.OperationError(nil, "Build")
}

// ECIDMeasurementReportInitiatingBinding is the concrete InitiatingBinding[ECIDMeasurementReport].
type ECIDMeasurementReportInitiatingBinding struct {
	context q8.BridgeCodecContext
	capture func(q13.ECIDMeasurementReport, q5.DecodeState,

	) (q13.ECIDMeasurementReport, q5.Snapshot,

	)
	compare func(q13.ECIDMeasurementReport, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	info     q8.ProcedureInfo
	validate func(*q13.ECIDMeasurementReport,

		*q5.DecodeBudget) (q6.ValidationReport, error)
	encode func(*q13.ECIDMeasurementReport,

		bool, *q5.DecodeBudget) ([]byte, error)
	decode func([]byte, q5.DecodeState) (q13.ECIDMeasurementReport,

		error)
	inject func(q13.ECIDMeasurementReport,

	) InitiatingValue
}

func (b ECIDMeasurementReportInitiatingBinding) Info() q8.ProcedureInfo { return b.info }
func (b ECIDMeasurementReportInitiatingBinding) Codec() q13.ECIDMeasurementReportValueCodec {
	return func() q13.ECIDMeasurementReportValueCodec {
		sealed := q13.ECIDMeasurementReportValueCodec{}
		*q13.BridgeECIDMeasurementReportValueCodecFieldPath(&sealed) = q5.Path(b.info.Rule.Assignment.Assignment)
		*q13.BridgeECIDMeasurementReportValueCodecFieldDecode(&sealed) = b.decode
		*q13.BridgeECIDMeasurementReportValueCodecFieldEncode(&sealed) = func(value q13.ECIDMeasurementReport,

			fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*q13.BridgeECIDMeasurementReportValueCodecFieldCapture(&sealed) = b.capture
		*q13.BridgeECIDMeasurementReportValueCodecFieldCompare(&sealed) = b.compare
		*q13.BridgeECIDMeasurementReportValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}
func (b ECIDMeasurementReportInitiatingBinding) Build(body q13.ECIDMeasurementReport,

	transactionID q8.LPPATransactionID, options ...q5.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("%w: unbound procedure binding", q5.ErrInvalidValue), "Build")
	}
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if err := q8.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, q5.OperationError(&q6.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q5.OperationError(nil, "Build")
}

// ECIDMeasurementTerminationCommandInitiatingBinding is the concrete InitiatingBinding[ECIDMeasurementTerminationCommand].
type ECIDMeasurementTerminationCommandInitiatingBinding struct {
	context q8.BridgeCodecContext
	capture func(q14.ECIDMeasurementTerminationCommand, q5.DecodeState,

	) (q14.ECIDMeasurementTerminationCommand, q5.Snapshot,

	)
	compare func(q14.ECIDMeasurementTerminationCommand, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	info     q8.ProcedureInfo
	validate func(*q14.ECIDMeasurementTerminationCommand,

		*q5.DecodeBudget) (q6.ValidationReport, error)
	encode func(*q14.ECIDMeasurementTerminationCommand,

		bool, *q5.DecodeBudget) ([]byte, error)
	decode func([]byte, q5.DecodeState) (q14.ECIDMeasurementTerminationCommand,

		error)
	inject func(q14.ECIDMeasurementTerminationCommand,

	) InitiatingValue
}

func (b ECIDMeasurementTerminationCommandInitiatingBinding) Info() q8.ProcedureInfo { return b.info }
func (b ECIDMeasurementTerminationCommandInitiatingBinding) Codec() q14.ECIDMeasurementTerminationCommandValueCodec {
	return func() q14.ECIDMeasurementTerminationCommandValueCodec {
		sealed := q14.ECIDMeasurementTerminationCommandValueCodec{}
		*q14.BridgeECIDMeasurementTerminationCommandValueCodecFieldPath(&sealed) = q5.Path(b.info.Rule.Assignment.Assignment)
		*q14.BridgeECIDMeasurementTerminationCommandValueCodecFieldDecode(&sealed) = b.decode
		*q14.BridgeECIDMeasurementTerminationCommandValueCodecFieldEncode(&sealed) = func(value q14.ECIDMeasurementTerminationCommand,

			fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*q14.BridgeECIDMeasurementTerminationCommandValueCodecFieldCapture(&sealed) = b.capture
		*q14.BridgeECIDMeasurementTerminationCommandValueCodecFieldCompare(&sealed) = b.compare
		*q14.BridgeECIDMeasurementTerminationCommandValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}
func (b ECIDMeasurementTerminationCommandInitiatingBinding) Build(body q14.ECIDMeasurementTerminationCommand,

	transactionID q8.LPPATransactionID, options ...q5.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("%w: unbound procedure binding", q5.ErrInvalidValue), "Build")
	}
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if err := q8.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, q5.OperationError(&q6.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q5.OperationError(nil, "Build")
}

// OTDOAInformationRequestInitiatingBinding is the concrete InitiatingBinding[OTDOAInformationRequest].
type OTDOAInformationRequestInitiatingBinding struct {
	context q8.BridgeCodecContext
	capture func(q15.OTDOAInformationRequest, q5.DecodeState,

	) (q15.OTDOAInformationRequest, q5.Snapshot,

	)
	compare func(q15.OTDOAInformationRequest, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	info     q8.ProcedureInfo
	validate func(*q15.OTDOAInformationRequest,

		*q5.DecodeBudget) (q6.ValidationReport, error)
	encode func(*q15.OTDOAInformationRequest,

		bool, *q5.DecodeBudget) ([]byte, error)
	decode func([]byte, q5.DecodeState) (q15.OTDOAInformationRequest,

		error)
	inject func(q15.OTDOAInformationRequest,

	) InitiatingValue
}

func (b OTDOAInformationRequestInitiatingBinding) Info() q8.ProcedureInfo { return b.info }
func (b OTDOAInformationRequestInitiatingBinding) Codec() q15.OTDOAInformationRequestValueCodec {
	return func() q15.OTDOAInformationRequestValueCodec {
		sealed := q15.OTDOAInformationRequestValueCodec{}
		*q15.BridgeOTDOAInformationRequestValueCodecFieldPath(&sealed) = q5.Path(b.info.Rule.Assignment.Assignment)
		*q15.BridgeOTDOAInformationRequestValueCodecFieldDecode(&sealed) = b.decode
		*q15.BridgeOTDOAInformationRequestValueCodecFieldEncode(&sealed) = func(value q15.OTDOAInformationRequest,

			fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*q15.BridgeOTDOAInformationRequestValueCodecFieldCapture(&sealed) = b.capture
		*q15.BridgeOTDOAInformationRequestValueCodecFieldCompare(&sealed) = b.compare
		*q15.BridgeOTDOAInformationRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}
func (b OTDOAInformationRequestInitiatingBinding) Build(body q15.OTDOAInformationRequest,

	transactionID q8.LPPATransactionID, options ...q5.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("%w: unbound procedure binding", q5.ErrInvalidValue), "Build")
	}
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if err := q8.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, q5.OperationError(&q6.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q5.OperationError(nil, "Build")
}

// UTDOAInformationRequestInitiatingBinding is the concrete InitiatingBinding[UTDOAInformationRequest].
type UTDOAInformationRequestInitiatingBinding struct {
	context q8.BridgeCodecContext
	capture func(q16.UTDOAInformationRequest, q5.DecodeState,

	) (q16.UTDOAInformationRequest, q5.Snapshot,

	)
	compare func(q16.UTDOAInformationRequest, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	info     q8.ProcedureInfo
	validate func(*q16.UTDOAInformationRequest,

		*q5.DecodeBudget) (q6.ValidationReport, error)
	encode func(*q16.UTDOAInformationRequest,

		bool, *q5.DecodeBudget) ([]byte, error)
	decode func([]byte, q5.DecodeState) (q16.UTDOAInformationRequest,

		error)
	inject func(q16.UTDOAInformationRequest,

	) InitiatingValue
}

func (b UTDOAInformationRequestInitiatingBinding) Info() q8.ProcedureInfo { return b.info }
func (b UTDOAInformationRequestInitiatingBinding) Codec() q16.UTDOAInformationRequestValueCodec {
	return func() q16.UTDOAInformationRequestValueCodec {
		sealed := q16.UTDOAInformationRequestValueCodec{}
		*q16.BridgeUTDOAInformationRequestValueCodecFieldPath(&sealed) = q5.Path(b.info.Rule.Assignment.Assignment)
		*q16.BridgeUTDOAInformationRequestValueCodecFieldDecode(&sealed) = b.decode
		*q16.BridgeUTDOAInformationRequestValueCodecFieldEncode(&sealed) = func(value q16.UTDOAInformationRequest,

			fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*q16.BridgeUTDOAInformationRequestValueCodecFieldCapture(&sealed) = b.capture
		*q16.BridgeUTDOAInformationRequestValueCodecFieldCompare(&sealed) = b.compare
		*q16.BridgeUTDOAInformationRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}
func (b UTDOAInformationRequestInitiatingBinding) Build(body q16.UTDOAInformationRequest,

	transactionID q8.LPPATransactionID, options ...q5.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("%w: unbound procedure binding", q5.ErrInvalidValue), "Build")
	}
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if err := q8.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, q5.OperationError(&q6.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q5.OperationError(nil, "Build")
}

// UTDOAInformationUpdateInitiatingBinding is the concrete InitiatingBinding[UTDOAInformationUpdate].
type UTDOAInformationUpdateInitiatingBinding struct {
	context q8.BridgeCodecContext
	capture func(q17.UTDOAInformationUpdate, q5.DecodeState,

	) (q17.UTDOAInformationUpdate, q5.Snapshot,

	)
	compare func(q17.UTDOAInformationUpdate, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	info     q8.ProcedureInfo
	validate func(*q17.UTDOAInformationUpdate,

		*q5.DecodeBudget) (q6.ValidationReport, error)
	encode func(*q17.UTDOAInformationUpdate,

		bool, *q5.DecodeBudget) ([]byte, error)
	decode func([]byte, q5.DecodeState) (q17.UTDOAInformationUpdate,

		error)
	inject func(q17.UTDOAInformationUpdate,

	) InitiatingValue
}

func (b UTDOAInformationUpdateInitiatingBinding) Info() q8.ProcedureInfo { return b.info }
func (b UTDOAInformationUpdateInitiatingBinding) Codec() q17.UTDOAInformationUpdateValueCodec {
	return func() q17.UTDOAInformationUpdateValueCodec {
		sealed := q17.UTDOAInformationUpdateValueCodec{}
		*q17.BridgeUTDOAInformationUpdateValueCodecFieldPath(&sealed) = q5.Path(b.info.Rule.Assignment.Assignment)
		*q17.BridgeUTDOAInformationUpdateValueCodecFieldDecode(&sealed) = b.decode
		*q17.BridgeUTDOAInformationUpdateValueCodecFieldEncode(&sealed) = func(value q17.UTDOAInformationUpdate,

			fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*q17.BridgeUTDOAInformationUpdateValueCodecFieldCapture(&sealed) = b.capture
		*q17.BridgeUTDOAInformationUpdateValueCodecFieldCompare(&sealed) = b.compare
		*q17.BridgeUTDOAInformationUpdateValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}
func (b UTDOAInformationUpdateInitiatingBinding) Build(body q17.UTDOAInformationUpdate,

	transactionID q8.LPPATransactionID, options ...q5.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("%w: unbound procedure binding", q5.ErrInvalidValue), "Build")
	}
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if err := q8.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, q5.OperationError(&q6.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q5.OperationError(nil, "Build")
}

// AssistanceInformationControlInitiatingBinding is the concrete InitiatingBinding[AssistanceInformationControl].
type AssistanceInformationControlInitiatingBinding struct {
	context q8.BridgeCodecContext
	capture func(q18.AssistanceInformationControl, q5.DecodeState,

	) (q18.AssistanceInformationControl, q5.Snapshot,

	)
	compare func(q18.AssistanceInformationControl, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	info     q8.ProcedureInfo
	validate func(*q18.AssistanceInformationControl,

		*q5.DecodeBudget) (q6.ValidationReport, error)
	encode func(*q18.AssistanceInformationControl,

		bool, *q5.DecodeBudget) ([]byte, error)
	decode func([]byte, q5.DecodeState) (q18.AssistanceInformationControl,

		error)
	inject func(q18.AssistanceInformationControl,

	) InitiatingValue
}

func (b AssistanceInformationControlInitiatingBinding) Info() q8.ProcedureInfo { return b.info }
func (b AssistanceInformationControlInitiatingBinding) Codec() q18.AssistanceInformationControlValueCodec {
	return func() q18.AssistanceInformationControlValueCodec {
		sealed := q18.AssistanceInformationControlValueCodec{}
		*q18.BridgeAssistanceInformationControlValueCodecFieldPath(&sealed) = q5.Path(b.info.Rule.Assignment.Assignment)
		*q18.BridgeAssistanceInformationControlValueCodecFieldDecode(&sealed) = b.decode
		*q18.BridgeAssistanceInformationControlValueCodecFieldEncode(&sealed) = func(value q18.AssistanceInformationControl,

			fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*q18.BridgeAssistanceInformationControlValueCodecFieldCapture(&sealed) = b.capture
		*q18.BridgeAssistanceInformationControlValueCodecFieldCompare(&sealed) = b.compare
		*q18.BridgeAssistanceInformationControlValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}
func (b AssistanceInformationControlInitiatingBinding) Build(body q18.AssistanceInformationControl,

	transactionID q8.LPPATransactionID, options ...q5.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("%w: unbound procedure binding", q5.ErrInvalidValue), "Build")
	}
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if err := q8.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, q5.OperationError(&q6.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q5.OperationError(nil, "Build")
}

// AssistanceInformationFeedbackInitiatingBinding is the concrete InitiatingBinding[AssistanceInformationFeedback].
type AssistanceInformationFeedbackInitiatingBinding struct {
	context q8.BridgeCodecContext
	capture func(q17.AssistanceInformationFeedback, q5.DecodeState,

	) (q17.AssistanceInformationFeedback, q5.Snapshot,

	)
	compare func(q17.AssistanceInformationFeedback, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	info     q8.ProcedureInfo
	validate func(*q17.AssistanceInformationFeedback,

		*q5.DecodeBudget) (q6.ValidationReport, error)
	encode func(*q17.AssistanceInformationFeedback,

		bool, *q5.DecodeBudget) ([]byte, error)
	decode func([]byte, q5.DecodeState) (q17.AssistanceInformationFeedback,

		error)
	inject func(q17.AssistanceInformationFeedback,

	) InitiatingValue
}

func (b AssistanceInformationFeedbackInitiatingBinding) Info() q8.ProcedureInfo { return b.info }
func (b AssistanceInformationFeedbackInitiatingBinding) Codec() q17.AssistanceInformationFeedbackValueCodec {
	return func() q17.AssistanceInformationFeedbackValueCodec {
		sealed := q17.AssistanceInformationFeedbackValueCodec{}
		*q17.BridgeAssistanceInformationFeedbackValueCodecFieldPath(&sealed) = q5.Path(b.info.Rule.Assignment.Assignment)
		*q17.BridgeAssistanceInformationFeedbackValueCodecFieldDecode(&sealed) = b.decode
		*q17.BridgeAssistanceInformationFeedbackValueCodecFieldEncode(&sealed) = func(value q17.AssistanceInformationFeedback,

			fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*q17.BridgeAssistanceInformationFeedbackValueCodecFieldCapture(&sealed) = b.capture
		*q17.BridgeAssistanceInformationFeedbackValueCodecFieldCompare(&sealed) = b.compare
		*q17.BridgeAssistanceInformationFeedbackValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}
func (b AssistanceInformationFeedbackInitiatingBinding) Build(body q17.AssistanceInformationFeedback,

	transactionID q8.LPPATransactionID, options ...q5.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("%w: unbound procedure binding", q5.ErrInvalidValue), "Build")
	}
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if err := q8.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	if *q6.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, q5.OperationError(*q6.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := q6.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, q5.OperationError(&q6.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, q5.OperationError(nil, "Build")
}
func BridgeECIDMeasurementInitiationRequestIEValueCaptureLPPaProtocolIEContainer(v *ECIDMeasurementInitiationRequestIEContainer, s *q5.SemanticCapture) {
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
			BridgeECIDMeasurementInitiationRequestIEValueCaptureLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeECIDMeasurementInitiationRequestIEValueCompareLPPaProtocolIEContainer(v *ECIDMeasurementInitiationRequestIEContainer, s *q5.SemanticComparison) {
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
			BridgeECIDMeasurementInitiationRequestIEValueCompareLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeWLANMeasurementResultItemExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q19.WLANMeasurementResultItemExtIEsExtContainer, s *q5.SemanticCapture) {
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
			BridgeWLANMeasurementResultItemExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeWLANMeasurementResultItemExtIEsValueCompareLPPaProtocolExtensionContainer(v *q19.WLANMeasurementResultItemExtIEsExtContainer, s *q5.SemanticComparison) {
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
			BridgeWLANMeasurementResultItemExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
}

// ECIDMeasurementInitiationRequestMeasurementIDIEBinding is the concrete IEBinding[MeasurementID, ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestMeasurementIDIEBinding struct {
	info   q8.FieldInfo
	codec  q8.MeasurementIDValueCodec
	inject func(q8.MeasurementID,

	) q7.ECIDMeasurementInitiationRequestIEValue

	get func(*q7.ECIDMeasurementInitiationRequestIEValue,

	) (*q8.MeasurementID,

		bool)
}

func (b ECIDMeasurementInitiationRequestMeasurementIDIEBinding) Info() q8.FieldInfo { return b.info }
func (b ECIDMeasurementInitiationRequestMeasurementIDIEBinding) Codec() q8.MeasurementIDValueCodec {
	return b.codec
}
func (b ECIDMeasurementInitiationRequestMeasurementIDIEBinding) New(value q8.MeasurementID,

) (ECIDMeasurementInitiationRequestIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(q9.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(err, "Value.New")
	}
	if _, err := (*q8.BridgeMeasurementIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(q9.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q5.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementInitiationRequestMeasurementIDIEBinding) Get(field *ECIDMeasurementInitiationRequestIEField) (*q8.MeasurementID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding is the concrete IEBinding[ReportCharacteristics, ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding struct {
	info   q8.FieldInfo
	codec  q20.ReportCharacteristicsValueCodec
	inject func(q8.ReportCharacteristics,

	) q7.ECIDMeasurementInitiationRequestIEValue

	get func(*q7.ECIDMeasurementInitiationRequestIEValue,

	) (*q8.ReportCharacteristics,

		bool)
}

func (b ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding) Info() q8.FieldInfo {
	return b.info
}
func (b ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding) Codec() q20.ReportCharacteristicsValueCodec {
	return b.codec
}
func (b ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding) New(value q8.ReportCharacteristics,

) (ECIDMeasurementInitiationRequestIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(q9.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(err, "Value.New")
	}
	if _, err := (*q20.BridgeReportCharacteristicsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(q9.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q5.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding) Get(field *ECIDMeasurementInitiationRequestIEField) (*q8.ReportCharacteristics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding is the concrete IEBinding[MeasurementPeriodicity, ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding struct {
	info   q8.FieldInfo
	codec  q8.MeasurementPeriodicityValueCodec
	inject func(q8.MeasurementPeriodicity,

	) q7.ECIDMeasurementInitiationRequestIEValue

	get func(*q7.ECIDMeasurementInitiationRequestIEValue,

	) (*q8.MeasurementPeriodicity,

		bool)
}

func (b ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding) Info() q8.FieldInfo {
	return b.info
}
func (b ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding) Codec() q8.MeasurementPeriodicityValueCodec {
	return b.codec
}
func (b ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding) New(value q8.MeasurementPeriodicity,

) (ECIDMeasurementInitiationRequestIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(q9.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(err, "Value.New")
	}
	if _, err := (*q8.BridgeMeasurementPeriodicityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(q9.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q5.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding) Get(field *ECIDMeasurementInitiationRequestIEField) (*q8.MeasurementPeriodicity,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding is the concrete IEBinding[MeasurementQuantities, ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding struct {
	info   q8.FieldInfo
	codec  q14.MeasurementQuantitiesConcreteValueCodec
	inject func(q14.MeasurementQuantities,

	) q7.ECIDMeasurementInitiationRequestIEValue

	get func(*q7.ECIDMeasurementInitiationRequestIEValue,

	) (*q14.MeasurementQuantities,

		bool)
}

func (b ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding) Info() q8.FieldInfo {
	return b.info
}
func (b ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding) Codec() q14.MeasurementQuantitiesConcreteValueCodec {
	return b.codec
}
func (b ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding) New(value q14.MeasurementQuantities,

) (ECIDMeasurementInitiationRequestIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(q9.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(err, "Value.New")
	}
	if _, err := (*q14.BridgeMeasurementQuantitiesConcreteValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(q9.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q5.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding) Get(field *ECIDMeasurementInitiationRequestIEField) (*q14.MeasurementQuantities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding is the concrete IEBinding[InterRATMeasurementQuantities, ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding struct {
	info   q8.FieldInfo
	codec  q14.InterRATMeasurementQuantitiesConcreteValueCodec
	inject func(q14.InterRATMeasurementQuantities,

	) q7.ECIDMeasurementInitiationRequestIEValue

	get func(*q7.ECIDMeasurementInitiationRequestIEValue,

	) (*q14.InterRATMeasurementQuantities,

		bool)
}

func (b ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding) Info() q8.FieldInfo {
	return b.info
}
func (b ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding) Codec() q14.InterRATMeasurementQuantitiesConcreteValueCodec {
	return b.codec
}
func (b ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding) New(value q14.InterRATMeasurementQuantities,

) (ECIDMeasurementInitiationRequestIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(q9.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(err, "Value.New")
	}
	if _, err := (*q14.BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(q9.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q5.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding) Get(field *ECIDMeasurementInitiationRequestIEField) (*q14.InterRATMeasurementQuantities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding is the concrete IEBinding[WLANMeasurementQuantities, ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding struct {
	info   q8.FieldInfo
	codec  q7.WLANMeasurementQuantitiesConcreteValueCodec
	inject func(q7.WLANMeasurementQuantities,

	) q7.ECIDMeasurementInitiationRequestIEValue

	get func(*q7.ECIDMeasurementInitiationRequestIEValue,

	) (*q7.WLANMeasurementQuantities,

		bool)
}

func (b ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding) Info() q8.FieldInfo {
	return b.info
}
func (b ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding) Codec() q7.WLANMeasurementQuantitiesConcreteValueCodec {
	return b.codec
}
func (b ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding) New(value q7.WLANMeasurementQuantities,

) (ECIDMeasurementInitiationRequestIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(q9.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(err, "Value.New")
	}
	if _, err := (*q7.BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(q9.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q5.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding) Get(field *ECIDMeasurementInitiationRequestIEField) (*q7.WLANMeasurementQuantities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationRequestValueCodec is the concrete ValueCodec[ECIDMeasurementInitiationRequest].
type ECIDMeasurementInitiationRequestValueCodec struct {
	context q8.BridgeCodecContext
	capture func(ECIDMeasurementInitiationRequest, q5.DecodeState,

	) (ECIDMeasurementInitiationRequest, q5.Snapshot,

	)
	compare func(ECIDMeasurementInitiationRequest, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (ECIDMeasurementInitiationRequest,

		error)
	encode func(ECIDMeasurementInitiationRequest,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c ECIDMeasurementInitiationRequestValueCodec) New(value ECIDMeasurementInitiationRequest,

) (ECIDMeasurementInitiationRequestAPERValue, error) {
	if c.encode == nil {
		return ECIDMeasurementInitiationRequestAPERValue{}, q5.OperationError(q9.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationRequestAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ECIDMeasurementInitiationRequestAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationRequestAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c ECIDMeasurementInitiationRequestValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (ECIDMeasurementInitiationRequestAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ECIDMeasurementInitiationRequestAPERValue{}, q5.DecodeReport{}, q9.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return ECIDMeasurementInitiationRequestAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ECIDMeasurementInitiationRequestAPERValue{}, q5.DecodeReport{}, q9.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return ECIDMeasurementInitiationRequestAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return ECIDMeasurementInitiationRequestAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ECIDMeasurementInitiationRequestValueCodec) EncodeAPER(value ECIDMeasurementInitiationRequestAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q9.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c ECIDMeasurementInitiationRequestValueCodec) encodeBudget(value ECIDMeasurementInitiationRequest,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ECIDMeasurementInitiationRequestValueCodec) encodeChanged(value ECIDMeasurementInitiationRequest,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// InitiatingMessageValueCodec is the concrete ValueCodec[InitiatingMessage].
type InitiatingMessageValueCodec struct {
	context q8.BridgeCodecContext
	capture func(InitiatingMessage, q5.DecodeState,

	) (InitiatingMessage, q5.Snapshot,

	)
	compare func(InitiatingMessage, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (InitiatingMessage,

		error)
	encode func(InitiatingMessage,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c InitiatingMessageValueCodec) New(value InitiatingMessage,

) (InitiatingMessageAPERValue, error) {
	if c.encode == nil {
		return InitiatingMessageAPERValue{}, q5.OperationError(q9.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return InitiatingMessageAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitiatingMessageAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return InitiatingMessageAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c InitiatingMessageValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (InitiatingMessageAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return InitiatingMessageAPERValue{}, q5.DecodeReport{}, q9.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return InitiatingMessageAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return InitiatingMessageAPERValue{}, q5.DecodeReport{}, q9.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return InitiatingMessageAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return InitiatingMessageAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c InitiatingMessageValueCodec) EncodeAPER(value InitiatingMessageAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q9.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c InitiatingMessageValueCodec) encodeBudget(value InitiatingMessage,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c InitiatingMessageValueCodec) encodeChanged(value InitiatingMessage,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeECIDMeasurementInitiationRequestIEValueValidateLPPaIEContainer(fields ECIDMeasurementInitiationRequestIEContainer, rows []q8.FieldInfo, path string, budget *q5.DecodeBudget,

) q6.ValidationReport {
	report := func() q6.ValidationReport {
		sealed := q6.ValidationReport{Complete: true}
		*q6.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q5.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q6.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q8.ProtocolIEID]int, len(rows))
	counts := make(map[q8.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q6.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q5.Location{Path: q5.Path(q9.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q7.BridgeECIDMeasurementInitiationRequestIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q7.BridgeECIDMeasurementInitiationRequestIEValueMethodRule(field.Value)
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q8.ValueIDMismatch, Severity: q8.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q9.Sprintf("%s.id", location.Path))}, Table: func() q8.TableID {
				sealed := q8.TableID{}
				*q8.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q8.ValueIDMismatch), RelatedRules: []q5.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q5.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q8.FieldInfo
			related := []q5.SourceRule{q19.BridgeLppaAdoptedRule(q8.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q8.RepeatedIE, Severity: q8.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q8.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q8.ValidationSeverityUnrecognized
			if _, globallyKnown := q19.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q8.ValidationSeverityError
			}
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q8.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q8.NotAllowed), RelatedRules: q19.BridgeLppaHandlingRules(q8.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q8.WrongCriticality, Severity: q8.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q9.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q8.WrongCriticality), RelatedRules: []q5.SourceRule{q19.BridgeLppaAdoptedRule(q8.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q8.WrongOrder, Severity: q8.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q8.WrongOrder), RelatedRules: []q5.SourceRule{q19.BridgeLppaAdoptedRule(q8.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q8.PresenceMandatory && counts[row.ID] == 0 {
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q8.MissingMandatory, Severity: q8.ValidationSeverityError, Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q8.MissingMandatory), RelatedRules: []q5.SourceRule{q19.BridgeLppaAdoptedRule(q8.MissingMandatory), row.Rule}})
		}
		if row.Presence == q8.PresenceConditional {
			q6.BridgeValidationReportMethodAddDeferred(&report, q8.DeferredCondition{Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q6.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeWLANMeasurementQuantitiesItemIEValueValidateLPPaIEContainer(fields q7.WLANMeasurementQuantitiesItemIEContainer, rows []q8.FieldInfo, path string, budget *q5.DecodeBudget,

) q6.ValidationReport {
	report := func() q6.ValidationReport {
		sealed := q6.ValidationReport{Complete: true}
		*q6.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q5.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q6.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q8.ProtocolIEID]int, len(rows))
	counts := make(map[q8.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q6.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q5.Location{Path: q5.Path(q9.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q7.BridgeWLANMeasurementQuantitiesItemIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q7.BridgeWLANMeasurementQuantitiesItemIEValueMethodRule(field.Value)
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q8.ValueIDMismatch, Severity: q8.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q9.Sprintf("%s.id", location.Path))}, Table: func() q8.TableID {
				sealed := q8.TableID{}
				*q8.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q8.ValueIDMismatch), RelatedRules: []q5.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q5.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q8.FieldInfo
			related := []q5.SourceRule{q19.BridgeLppaAdoptedRule(q8.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q8.RepeatedIE, Severity: q8.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q8.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q8.ValidationSeverityUnrecognized
			if _, globallyKnown := q19.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q8.ValidationSeverityError
			}
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q8.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q8.NotAllowed), RelatedRules: q19.BridgeLppaHandlingRules(q8.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q8.WrongCriticality, Severity: q8.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q9.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q8.WrongCriticality), RelatedRules: []q5.SourceRule{q19.BridgeLppaAdoptedRule(q8.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q8.WrongOrder, Severity: q8.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q8.WrongOrder), RelatedRules: []q5.SourceRule{q19.BridgeLppaAdoptedRule(q8.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q8.PresenceMandatory && counts[row.ID] == 0 {
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q8.MissingMandatory, Severity: q8.ValidationSeverityError, Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q8.MissingMandatory), RelatedRules: []q5.SourceRule{q19.BridgeLppaAdoptedRule(q8.MissingMandatory), row.Rule}})
		}
		if row.Presence == q8.PresenceConditional {
			q6.BridgeValidationReportMethodAddDeferred(&report, q8.DeferredCondition{Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q6.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueValidateLPPaExtensionContainer(fields q19.WLANMeasurementQuantitiesValueExtIEsExtContainer, rows []q8.FieldInfo, path string, budget *q5.DecodeBudget) q6.ValidationReport {
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q19.WLANMeasurementQuantitiesValueExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q6.ValidationReport {
			sealed := q6.ValidationReport{}
			*q6.BridgeValidationReportFieldErr(&sealed) = err
			*q6.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q19.WLANMeasurementQuantitiesValueExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeWLANMeasurementQuantitiesValueExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// eCIDMeasurementInitiationRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q7.ECIDMeasurementInitiationRequestIEValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q8.ProtocolIEID, q5.OpaqueOpenType) (q7.ECIDMeasurementInitiationRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q8.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q8.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}

func BridgeECIDMeasurementInitiationRequestIEValueCaptureLPPaProtocolIEField(v *ECIDMeasurementInitiationRequestIEField, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q8.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q8.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q7.BridgeECIDMeasurementInitiationRequestIEValueMethodCaptureFraming(v.Value))
	v.Value = q7.BridgeECIDMeasurementInitiationRequestIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(q7.BridgeECIDMeasurementInitiationRequestIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeECIDMeasurementInitiationRequestIEValueCompareLPPaProtocolIEField(v *ECIDMeasurementInitiationRequestIEField, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q21.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q21.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q7.BridgeECIDMeasurementInitiationRequestIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, v.replay, v.withoutReplay)
}

// wLANMeasurementQuantitiesItemIEValueProtocolOpenValue is the concrete protocolOpenValue[WLANMeasurementQuantitiesItemIEValue].
type WLANMeasurementQuantitiesItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q7.WLANMeasurementQuantitiesItemIEValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q8.ProtocolIEID, q5.OpaqueOpenType) (q7.WLANMeasurementQuantitiesItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q8.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q8.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}

// wLANMeasurementQuantitiesValueExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[WLANMeasurementQuantitiesValueExtIEsValue].
type WLANMeasurementQuantitiesValueExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q11.WLANMeasurementQuantitiesValueExtIEsValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q8.ProtocolIEID, q5.OpaqueOpenType) (q11.WLANMeasurementQuantitiesValueExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q8.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q8.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}

func BridgeWLANMeasurementResultItemExtIEsValueCaptureLPPaProtocolExtensionField(v *q19.WLANMeasurementResultItemExtIEsExtField, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q19.BridgeWLANMeasurementResultItemExtIEsExtFieldFieldStream(v))
	q8.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q8.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q11.BridgeWLANMeasurementResultItemExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q11.BridgeWLANMeasurementResultItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q11.BridgeWLANMeasurementResultItemExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q19.BridgeWLANMeasurementResultItemExtIEsExtFieldFieldReplay(v), *q19.BridgeWLANMeasurementResultItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeWLANMeasurementResultItemExtIEsValueCompareLPPaProtocolExtensionField(v *q19.WLANMeasurementResultItemExtIEsExtField, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q21.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q21.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q11.BridgeWLANMeasurementResultItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q19.BridgeWLANMeasurementResultItemExtIEsExtFieldFieldReplay(v), *q19.BridgeWLANMeasurementResultItemExtIEsExtFieldFieldWithoutReplay(v))
}

// ECIDMeasurementInitiationRequestAPERValue is the concrete APERValue[ECIDMeasurementInitiationRequest].
type ECIDMeasurementInitiationRequestAPERValue struct {
	context q8.BridgeCodecContext
	Value   ECIDMeasurementInitiationRequest

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v ECIDMeasurementInitiationRequestAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v ECIDMeasurementInitiationRequestAPERValue) WithoutReplay() ECIDMeasurementInitiationRequestAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitiatingMessageAPERValue is the concrete APERValue[InitiatingMessage].
type InitiatingMessageAPERValue struct {
	context q8.BridgeCodecContext
	Value   InitiatingMessage

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v InitiatingMessageAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v InitiatingMessageAPERValue) WithoutReplay() InitiatingMessageAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeWLANMeasurementQuantitiesValueExtIEsValueValidateLPPaIEContainer(fields q19.WLANMeasurementQuantitiesValueExtIEsIEContainer, rows []q8.FieldInfo, path string, budget *q5.DecodeBudget,

) q6.ValidationReport {
	report := func() q6.ValidationReport {
		sealed := q6.ValidationReport{Complete: true}
		*q6.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q5.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q6.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q8.ProtocolIEID]int, len(rows))
	counts := make(map[q8.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q6.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q6.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q5.Location{Path: q5.Path(q9.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q11.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q11.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodRule(field.Value)
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q8.ValueIDMismatch, Severity: q8.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q9.Sprintf("%s.id", location.Path))}, Table: func() q8.TableID {
				sealed := q8.TableID{}
				*q8.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q8.ValueIDMismatch), RelatedRules: []q5.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q5.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q8.FieldInfo
			related := []q5.SourceRule{q19.BridgeLppaAdoptedRule(q8.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q8.RepeatedIE, Severity: q8.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q8.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q8.ValidationSeverityUnrecognized
			if _, globallyKnown := q19.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q8.ValidationSeverityError
			}
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q8.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q8.NotAllowed), RelatedRules: q19.BridgeLppaHandlingRules(q8.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q8.WrongCriticality, Severity: q8.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q9.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q19.BridgeLppaValidationRule(q8.WrongCriticality), RelatedRules: []q5.SourceRule{q19.BridgeLppaAdoptedRule(q8.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q8.WrongOrder, Severity: q8.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q8.WrongOrder), RelatedRules: []q5.SourceRule{q19.BridgeLppaAdoptedRule(q8.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q8.PresenceMandatory && counts[row.ID] == 0 {
			q6.BridgeValidationReportMethodAddIssue(&report, q6.ValidationIssue{Code: q8.MissingMandatory, Severity: q8.ValidationSeverityError, Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q19.BridgeLppaValidationRule(q8.MissingMandatory), RelatedRules: []q5.SourceRule{q19.BridgeLppaAdoptedRule(q8.MissingMandatory), row.Rule}})
		}
		if row.Presence == q8.PresenceConditional {
			q6.BridgeValidationReportMethodAddDeferred(&report, q8.DeferredCondition{Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q6.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// MarshalAPERWLANMeasurementQuantities encodes a WLANMeasurementQuantities list to APER.
func BridgeMarshalAPERWLANMeasurementQuantities(list q7.WLANMeasurementQuantitiesComplete) ([]byte, error) {
	return q7.BridgeWLANMeasurementQuantitiesCompleteMethodMarshalAPERLegacy(&list)
}

// UnmarshalAPERWLANMeasurementQuantities decodes a WLANMeasurementQuantities list from APER.
func BridgeUnmarshalAPERWLANMeasurementQuantities(data []byte) (q7.WLANMeasurementQuantitiesComplete, error) {
	var value q7.WLANMeasurementQuantitiesComplete
	if err := q7.BridgeWLANMeasurementQuantitiesCompleteMethodUnmarshalAPERLegacy(&value, data); err != nil {
		return value, err
	}
	return value, nil
}

// MarshalAPERWLANMeasurementQuantities encodes a complete named list.
func MarshalAPERWLANMeasurementQuantities(v q7.WLANMeasurementQuantitiesComplete, options ...q5.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERWLANMeasurementQuantities decodes a complete named list.
func UnmarshalAPERWLANMeasurementQuantities(data []byte, options ...q5.DecodeOption) (q7.WLANMeasurementQuantitiesComplete, q5.DecodeReport, error) {
	var v q7.WLANMeasurementQuantitiesComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// ECIDMeasurementInitiationRequest represents the ASN.1 type E-CIDMeasurementInitiationRequest (SEQUENCE).
type ECIDMeasurementInitiationRequest struct {
	replay           q5.Snapshot
	stream           q5.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    q5.WireSpan
	ProtocolIEs      ECIDMeasurementInitiationRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                        `asn1:"-" json:"-"`
	extCount         int64                                       `asn1:"-" json:"-"`
	extPresent       []bool                                      `asn1:"-" json:"-"`
	extData          [][]byte                                    `asn1:"-" json:"-"`
	perPadding       q5.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding    []q5.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin        []q5.OpaqueOrigin
	extWire          []q5.WireSpan
}

// MarshalAPER encodes ECIDMeasurementInitiationRequest to APER format.
func (v *ECIDMeasurementInitiationRequest) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ECIDMeasurementInitiationRequest) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
			replay.
			ReplayTo(v.stream, bb); ok ||
			err !=
				nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := q5.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = q22.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	for _, data := range extensionEncodingData {
		hasExtensions = hasExtensions || data != nil
	}
	if err := q5.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := q5.EncodeCollection(bb, int64(len(v.ProtocolIEs)), q5.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return q9.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q9.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q9.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q9.Errorf("%w: extension bitmap index %d", q5.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q5.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q9.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q5.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q9.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := q5.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	q5.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	q5.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes ECIDMeasurementInitiationRequest from APER format.
func (v *ECIDMeasurementInitiationRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ECIDMeasurementInitiationRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ECIDMeasurementInitiationRequest) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q10.WrapDecodePath(err, "ECIDMeasurementInitiationRequest")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q10.WrapDecodePath(err, "ECIDMeasurementInitiationRequest")
	}
	padding, err := q5.CaptureFinalBits(bb, "ECIDMeasurementInitiationRequest")
	if err != nil {
		return q10.WrapDecodePath(err, "ECIDMeasurementInitiationRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ECIDMeasurementInitiationRequest) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementInitiationRequest{}
	extAdditions := q5.BeginExtensionAdditions(bb)
	hasExtensions, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ECIDMeasurementInitiationRequestIEContainer, 0)
	_, errCollection_protocolies := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return q9.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ECIDMeasurementInitiationRequestIEField
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return q10.WrapDecodePath(err, q9.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			if next, err := q5.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return q10.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q10.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q9.Errorf("extension count out of range")
		}
		if err := q5.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := q5.ChargeSlice[q5.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]q5.OpaqueOrigin, len(v.extData))
		if err := q5.ChargeSlice[q5.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]q5.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q9.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q5.DecodeOpaqueOpenTypeAligned(bb, q5.UnknownSelector, q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
				if err != nil {
					return q10.WrapDecodePath(err, q9.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(q5.UnknownExtension, i); err != nil {
					return err
				}
				var retained q5.WireSpan
				opaque.RetainContents(&retained)
				v.extWire[i] = retained
				v.extOrigin[i] = opaque.Origin()
			}
		}
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage,

		bb,
	)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ECIDMeasurementInitiationRequest) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q22.BridgeReceivedFormAt(v.received, v.receivedBytes, "ECIDMeasurementInitiationRequest", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ECIDMeasurementInitiationRequest) WithoutReplay() ECIDMeasurementInitiationRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero ECIDMeasurementInitiationRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ECIDMeasurementInitiationRequest) Extensions() []q5.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q5.SequenceExtensionViews(v.extPresent, q5.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ECIDMeasurementInitiationRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q10.WrapDecodePath(q5.ErrInvalidValue, q9.Sprintf("ECIDMeasurementInitiationRequest.Extensions[%d]", index))
	}
	if err := q5.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q10.WrapDecodePath(err, q9.Sprintf("ECIDMeasurementInitiationRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ECIDMeasurementInitiationRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return q10.WrapDecodePath(q5.ErrInvalidValue, q9.Sprintf("ECIDMeasurementInitiationRequest.Extensions[%d]", index))
	}
	if err := q5.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q10.WrapDecodePath(err, q9.Sprintf("ECIDMeasurementInitiationRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *ECIDMeasurementInitiationRequest) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "ECIDMeasurementInitiationRequest")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "ECIDMeasurementInitiationRequest")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaECIDMeasurementInitiationRequest(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "ECIDMeasurementInitiationRequest")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "ECIDMeasurementInitiationRequest")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "ECIDMeasurementInitiationRequest")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "ECIDMeasurementInitiationRequest")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "ECIDMeasurementInitiationRequest")
}
func (v *ECIDMeasurementInitiationRequest) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ECIDMeasurementInitiationRequest) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ECIDMeasurementInitiationRequest) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
		BridgeCompareLPPaECIDMeasurementInitiationRequest(v, &s)
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
func (v *ECIDMeasurementInitiationRequest) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ECIDMeasurementInitiationRequest) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
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
	out, err := bb.CompleteBytesWithFinalPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ECIDMeasurementInitiationRequest) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "ECIDMeasurementInitiationRequest")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded ECIDMeasurementInitiationRequest
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaECIDMeasurementInitiationRequest(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = ECIDMeasurementInitiationRequest{}
		return report, q5.OperationError(err, "ECIDMeasurementInitiationRequest")
	}
	*v = decoded
	return report, q5.OperationError(nil, "ECIDMeasurementInitiationRequest")
}

// InitiatingMessage represents the ASN.1 type InitiatingMessage (SEQUENCE).
type InitiatingMessage struct {
	replay            q5.Snapshot
	stream            q5.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     q5.WireSpan
	ProcedureCode     q8.ProcedureCode     `asn1:"tag:0,context,implicit"`
	Criticality       q8.Criticality       `asn1:"tag:1,context,implicit"`
	LppatransactionID q8.LPPATransactionID `asn1:"tag:2,context,implicit"`
	Value             InitiatingValue      `asn1:"tag:3,context,explicit" asn1c:"raw-preserve"`
	perPadding        q5.CompletePadding   `asn1:"-" json:"-"`
}

// MarshalAPER encodes InitiatingMessage to APER format.
func (v *InitiatingMessage) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *InitiatingMessage) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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

	if v.Value.code != v.ProcedureCode {
		return q10.WrapDecodePath(q9.Errorf("%w: procedure code %d does not match its value selector", q5.ErrInvalidValue, v.ProcedureCode), "InitiatingMessage.ProcedureCode")
	}
	if err := q5.EncodeIntegerAligned(bb, int64(v.ProcedureCode), q11.BridgeInt64Ptr(0), q11.BridgeInt64Ptr(255), false); err != nil {
		return q9.Errorf("encoding procedureCode: %w", err)
	}
	if err := q5.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q9.Errorf("encoding criticality: %w", err)
	}
	if err := q5.EncodeIntegerAligned(bb, int64(v.LppatransactionID), q11.BridgeInt64Ptr(0), q11.BridgeInt64Ptr(32767), false); err != nil {
		return q9.Errorf("encoding lppatransactionID: %w", err)
	}
	openData_value, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return q9.Errorf("encoding value: %w", err)
	}
	if err := q5.EncodeOpenTypeAligned(bb, openData_value); err != nil {
		return q9.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes InitiatingMessage from APER format.
func (v *InitiatingMessage) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes InitiatingMessage with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *InitiatingMessage) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q10.WrapDecodePath(err, "InitiatingMessage")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q10.WrapDecodePath(err, "InitiatingMessage")
	}
	padding, err := q5.CaptureFinalBits(bb, "InitiatingMessage")
	if err != nil {
		return q10.WrapDecodePath(err, "InitiatingMessage")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *InitiatingMessage) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InitiatingMessage{}
	val_procedurecode, err := q5.DecodeIntegerAligned(bb, q11.BridgeInt64Ptr(0), q11.BridgeInt64Ptr(255), false)
	if err != nil {
		return q10.WrapDecodePath(err, "ProcedureCode")
	}
	v.ProcedureCode = q8.ProcedureCode(val_procedurecode)
	val_criticality, err := q5.DecodeEnumeratedAligned(bb, 3, false, q5.EnumerationSource{KnownExtensions: 0, Path: "Criticality"})
	if err != nil {
		return q10.WrapDecodePath(q9.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Criticality")
	}
	v.Criticality = q8.Criticality(val_criticality)
	val_lppatransactionid, err := q5.DecodeIntegerAligned(bb, q11.BridgeInt64Ptr(0), q11.BridgeInt64Ptr(32767), false)
	if err != nil {
		return q10.WrapDecodePath(err, "LppatransactionID")
	}
	v.LppatransactionID = q8.LPPATransactionID(val_lppatransactionid)
	opaque_value, err := q5.DecodeOpaqueOpenTypeAligned(bb, q8.InitiatingReason(v.ProcedureCode), q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "Initiating"}})
	if err != nil {
		return q10.WrapDecodePath(q9.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	opaque_value = opaque_value.WithPath("InitiatingMessage.Value")
	decoded_value, err := BridgeDecodeInitiatingValue(v.ProcedureCode, opaque_value)
	if err != nil {
		return q10.WrapDecodePath(q9.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	v.Value = decoded_value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *InitiatingMessage) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q22.BridgeReceivedFormAt(v.received, v.receivedBytes, "InitiatingMessage", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InitiatingMessage) WithoutReplay() InitiatingMessage {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero InitiatingMessage
	v.perPadding = zero.perPadding
	return v
}
func (v *InitiatingMessage) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "InitiatingMessage")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "InitiatingMessage")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaInitiatingMessage(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "InitiatingMessage")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "InitiatingMessage")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "InitiatingMessage")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "InitiatingMessage")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "InitiatingMessage")
}
func (v *InitiatingMessage) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *InitiatingMessage) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *InitiatingMessage) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
		BridgeCompareLPPaInitiatingMessage(v, &s)
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
func (v *InitiatingMessage) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *InitiatingMessage) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *InitiatingMessage) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "InitiatingMessage")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded InitiatingMessage
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaInitiatingMessage(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = InitiatingMessage{}
		return report, q5.OperationError(err, "InitiatingMessage")
	}
	*v = decoded
	return report, q5.OperationError(nil, "InitiatingMessage")
}

type InitiatingValue struct {
	code                                  q8.ProcedureCode
	withoutReplay                         bool
	received                              q5.WireSpan
	replay                                q5.Snapshot
	opaque                                *q5.OpaqueOpenType
	isOpaque                              bool
	bodyErrorIndication                   *q12.ErrorIndication
	bodyPrivateMessage                    *q4.PrivateMessage
	bodyECIDMeasurementInitiationRequest  *ECIDMeasurementInitiationRequest
	bodyECIDMeasurementFailureIndication  *q12.ECIDMeasurementFailureIndication
	bodyECIDMeasurementReport             *q13.ECIDMeasurementReport
	bodyECIDMeasurementTerminationCommand *q14.ECIDMeasurementTerminationCommand
	bodyOTDOAInformationRequest           *q15.OTDOAInformationRequest
	bodyUTDOAInformationRequest           *q16.UTDOAInformationRequest
	bodyUTDOAInformationUpdate            *q17.UTDOAInformationUpdate
	bodyAssistanceInformationControl      *q18.AssistanceInformationControl
	bodyAssistanceInformationFeedback     *q17.AssistanceInformationFeedback
}

func (v *InitiatingValue) Opaque() (q5.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q5.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (v *InitiatingValue) AsErrorIndication() (*q12.ErrorIndication, bool) {
	if v == nil || v.code != q8.ProcedureCode(0) || v.bodyErrorIndication == nil {
		return nil, false
	}
	return v.bodyErrorIndication, true
}
func (v *InitiatingValue) AsPrivateMessage() (*q4.PrivateMessage, bool) {
	if v == nil || v.code != q8.ProcedureCode(1) || v.bodyPrivateMessage == nil {
		return nil, false
	}
	return v.bodyPrivateMessage, true
}
func (v *InitiatingValue) AsECIDMeasurementInitiationRequest() (*ECIDMeasurementInitiationRequest, bool) {
	if v == nil || v.code != q8.ProcedureCode(2) || v.bodyECIDMeasurementInitiationRequest == nil {
		return nil, false
	}
	return v.bodyECIDMeasurementInitiationRequest, true
}
func (v *InitiatingValue) AsECIDMeasurementFailureIndication() (*q12.ECIDMeasurementFailureIndication, bool) {
	if v == nil || v.code != q8.ProcedureCode(3) || v.bodyECIDMeasurementFailureIndication == nil {
		return nil, false
	}
	return v.bodyECIDMeasurementFailureIndication, true
}
func (v *InitiatingValue) AsECIDMeasurementReport() (*q13.ECIDMeasurementReport, bool) {
	if v == nil || v.code != q8.ProcedureCode(4) || v.bodyECIDMeasurementReport == nil {
		return nil, false
	}
	return v.bodyECIDMeasurementReport, true
}
func (v *InitiatingValue) AsECIDMeasurementTerminationCommand() (*q14.ECIDMeasurementTerminationCommand, bool) {
	if v == nil || v.code != q8.ProcedureCode(5) || v.bodyECIDMeasurementTerminationCommand == nil {
		return nil, false
	}
	return v.bodyECIDMeasurementTerminationCommand, true
}
func (v *InitiatingValue) AsOTDOAInformationRequest() (*q15.OTDOAInformationRequest, bool) {
	if v == nil || v.code != q8.ProcedureCode(6) || v.bodyOTDOAInformationRequest == nil {
		return nil, false
	}
	return v.bodyOTDOAInformationRequest, true
}
func (v *InitiatingValue) AsUTDOAInformationRequest() (*q16.UTDOAInformationRequest, bool) {
	if v == nil || v.code != q8.ProcedureCode(7) || v.bodyUTDOAInformationRequest == nil {
		return nil, false
	}
	return v.bodyUTDOAInformationRequest, true
}
func (v *InitiatingValue) AsUTDOAInformationUpdate() (*q17.UTDOAInformationUpdate, bool) {
	if v == nil || v.code != q8.ProcedureCode(8) || v.bodyUTDOAInformationUpdate == nil {
		return nil, false
	}
	return v.bodyUTDOAInformationUpdate, true
}
func (v *InitiatingValue) AsAssistanceInformationControl() (*q18.AssistanceInformationControl, bool) {
	if v == nil || v.code != q8.ProcedureCode(9) || v.bodyAssistanceInformationControl == nil {
		return nil, false
	}
	return v.bodyAssistanceInformationControl, true
}
func (v *InitiatingValue) AsAssistanceInformationFeedback() (*q17.AssistanceInformationFeedback, bool) {
	if v == nil || v.code != q8.ProcedureCode(10) || v.bodyAssistanceInformationFeedback == nil {
		return nil, false
	}
	return v.bodyAssistanceInformationFeedback, true
}
func BridgeDecodeInitiatingValue(code q8.ProcedureCode, raw q5.OpaqueOpenType) (InitiatingValue, error) {
	v := InitiatingValue{code: code}
	var scope *q5.BitBuffer
	switch code {
	case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10:
		scope = raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return v, err
		}
		defer scope.LeaveOpenType()
	}
	switch code {
	case q8.ProcedureCode(0):
		var body q12.ErrorIndication
		child := scope
		replayUsage := child.Usage()
		if err := q12.BridgeErrorIndicationMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, q9.Errorf("%s %w", "InitiatingMessage.value.ErrorIndication:", err)
		}
		padding, err := q5.CaptureFinalBits(child, "ErrorIndication")
		if err != nil {
			return InitiatingValue{}, err
		}
		*q12.BridgeErrorIndicationFieldPerPadding(&body) = padding
		*q12.BridgeErrorIndicationFieldReceived(&body) = true
		raw.RetainContents(q12.BridgeErrorIndicationFieldReceivedBytes(&body))
		if err := q5.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyErrorIndication = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case q8.ProcedureCode(1):
		var body q4.PrivateMessage
		child := scope
		replayUsage := child.Usage()
		if err := q4.BridgePrivateMessageMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, q9.Errorf("%s %w", "InitiatingMessage.value.PrivateMessage:", err)
		}
		padding, err := q5.CaptureFinalBits(child, "PrivateMessage")
		if err != nil {
			return InitiatingValue{}, err
		}
		*q4.BridgePrivateMessageFieldPerPadding(&body) = padding
		*q4.BridgePrivateMessageFieldReceived(&body) = true
		raw.RetainContents(q4.BridgePrivateMessageFieldReceivedBytes(&body))
		if err := q5.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyPrivateMessage = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case q8.ProcedureCode(2):
		var body ECIDMeasurementInitiationRequest
		child := scope
		replayUsage := child.Usage()
		if err := body.unmarshalAPERFrom(child); err != nil {
			return InitiatingValue{}, q9.Errorf("%s %w", "InitiatingMessage.value.ECIDMeasurementInitiationRequest:", err)
		}
		padding, err := q5.CaptureFinalBits(child, "ECIDMeasurementInitiationRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		if err := q5.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyECIDMeasurementInitiationRequest = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case q8.ProcedureCode(3):
		var body q12.ECIDMeasurementFailureIndication
		child := scope
		replayUsage := child.Usage()
		if err := q12.BridgeECIDMeasurementFailureIndicationMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, q9.Errorf("%s %w", "InitiatingMessage.value.ECIDMeasurementFailureIndication:", err)
		}
		padding, err := q5.CaptureFinalBits(child, "ECIDMeasurementFailureIndication")
		if err != nil {
			return InitiatingValue{}, err
		}
		*q12.BridgeECIDMeasurementFailureIndicationFieldPerPadding(&body) = padding
		*q12.BridgeECIDMeasurementFailureIndicationFieldReceived(&body) = true
		raw.RetainContents(q12.BridgeECIDMeasurementFailureIndicationFieldReceivedBytes(&body))
		if err := q5.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyECIDMeasurementFailureIndication = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case q8.ProcedureCode(4):
		var body q13.ECIDMeasurementReport
		child := scope
		replayUsage := child.Usage()
		if err := q13.BridgeECIDMeasurementReportMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, q9.Errorf("%s %w", "InitiatingMessage.value.ECIDMeasurementReport:", err)
		}
		padding, err := q5.CaptureFinalBits(child, "ECIDMeasurementReport")
		if err != nil {
			return InitiatingValue{}, err
		}
		*q13.BridgeECIDMeasurementReportFieldPerPadding(&body) = padding
		*q13.BridgeECIDMeasurementReportFieldReceived(&body) = true
		raw.RetainContents(q13.BridgeECIDMeasurementReportFieldReceivedBytes(&body))
		if err := q5.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyECIDMeasurementReport = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case q8.ProcedureCode(5):
		var body q14.ECIDMeasurementTerminationCommand
		child := scope
		replayUsage := child.Usage()
		if err := q14.BridgeECIDMeasurementTerminationCommandMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, q9.Errorf("%s %w", "InitiatingMessage.value.ECIDMeasurementTerminationCommand:", err)
		}
		padding, err := q5.CaptureFinalBits(child, "ECIDMeasurementTerminationCommand")
		if err != nil {
			return InitiatingValue{}, err
		}
		*q14.BridgeECIDMeasurementTerminationCommandFieldPerPadding(&body) = padding
		*q14.BridgeECIDMeasurementTerminationCommandFieldReceived(&body) = true
		raw.RetainContents(q14.BridgeECIDMeasurementTerminationCommandFieldReceivedBytes(&body))
		if err := q5.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyECIDMeasurementTerminationCommand = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case q8.ProcedureCode(6):
		var body q15.OTDOAInformationRequest
		child := scope
		replayUsage := child.Usage()
		if err := q15.BridgeOTDOAInformationRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, q9.Errorf("%s %w", "InitiatingMessage.value.OTDOAInformationRequest:", err)
		}
		padding, err := q5.CaptureFinalBits(child, "OTDOAInformationRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*q15.BridgeOTDOAInformationRequestFieldPerPadding(&body) = padding
		*q15.BridgeOTDOAInformationRequestFieldReceived(&body) = true
		raw.RetainContents(q15.BridgeOTDOAInformationRequestFieldReceivedBytes(&body))
		if err := q5.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyOTDOAInformationRequest = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case q8.ProcedureCode(7):
		var body q16.UTDOAInformationRequest
		child := scope
		replayUsage := child.Usage()
		if err := q16.BridgeUTDOAInformationRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, q9.Errorf("%s %w", "InitiatingMessage.value.UTDOAInformationRequest:", err)
		}
		padding, err := q5.CaptureFinalBits(child, "UTDOAInformationRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*q16.BridgeUTDOAInformationRequestFieldPerPadding(&body) = padding
		*q16.BridgeUTDOAInformationRequestFieldReceived(&body) = true
		raw.RetainContents(q16.BridgeUTDOAInformationRequestFieldReceivedBytes(&body))
		if err := q5.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyUTDOAInformationRequest = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case q8.ProcedureCode(8):
		var body q17.UTDOAInformationUpdate
		child := scope
		replayUsage := child.Usage()
		if err := q17.BridgeUTDOAInformationUpdateMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, q9.Errorf("%s %w", "InitiatingMessage.value.UTDOAInformationUpdate:", err)
		}
		padding, err := q5.CaptureFinalBits(child, "UTDOAInformationUpdate")
		if err != nil {
			return InitiatingValue{}, err
		}
		*q17.BridgeUTDOAInformationUpdateFieldPerPadding(&body) = padding
		*q17.BridgeUTDOAInformationUpdateFieldReceived(&body) = true
		raw.RetainContents(q17.BridgeUTDOAInformationUpdateFieldReceivedBytes(&body))
		if err := q5.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyUTDOAInformationUpdate = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case q8.ProcedureCode(9):
		var body q18.AssistanceInformationControl
		child := scope
		replayUsage := child.Usage()
		if err := q18.BridgeAssistanceInformationControlMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, q9.Errorf("%s %w", "InitiatingMessage.value.AssistanceInformationControl:", err)
		}
		padding, err := q5.CaptureFinalBits(child, "AssistanceInformationControl")
		if err != nil {
			return InitiatingValue{}, err
		}
		*q18.BridgeAssistanceInformationControlFieldPerPadding(&body) = padding
		*q18.BridgeAssistanceInformationControlFieldReceived(&body) = true
		raw.RetainContents(q18.BridgeAssistanceInformationControlFieldReceivedBytes(&body))
		if err := q5.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyAssistanceInformationControl = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case q8.ProcedureCode(10):
		var body q17.AssistanceInformationFeedback
		child := scope
		replayUsage := child.Usage()
		if err := q17.BridgeAssistanceInformationFeedbackMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, q9.Errorf("%s %w", "InitiatingMessage.value.AssistanceInformationFeedback:", err)
		}
		padding, err := q5.CaptureFinalBits(child, "AssistanceInformationFeedback")
		if err != nil {
			return InitiatingValue{}, err
		}
		*q17.BridgeAssistanceInformationFeedbackFieldPerPadding(&body) = padding
		*q17.BridgeAssistanceInformationFeedbackFieldReceived(&body) = true
		raw.RetainContents(q17.BridgeAssistanceInformationFeedbackFieldReceivedBytes(&body))
		if err := q5.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyAssistanceInformationFeedback = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	default:
		if err := raw.Observe(q5.UnknownProcedure); err != nil {
			return v, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return v, err
		}
		v.opaque = retained
		v.isOpaque = true
	}
	return v, nil
}
func (v InitiatingValue) encode() ([]byte, error) {
	budget, err := q5.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v InitiatingValue) encodeFresh(fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q5.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q5.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.code {
	case q8.ProcedureCode(0):
		if v.bodyErrorIndication == nil {
			return nil, q9.Errorf("%s value: missing ErrorIndication", "Initiating")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return q12.BridgeErrorIndicationMethodMarshalAPERBudget(v.bodyErrorIndication, budget, fresh)
	case q8.ProcedureCode(1):
		if v.bodyPrivateMessage == nil {
			return nil, q9.Errorf("%s value: missing PrivateMessage", "Initiating")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return q4.BridgePrivateMessageMethodMarshalAPERBudget(v.bodyPrivateMessage, budget, fresh)
	case q8.ProcedureCode(2):
		if v.bodyECIDMeasurementInitiationRequest == nil {
			return nil, q9.Errorf("%s value: missing ECIDMeasurementInitiationRequest", "Initiating")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return v.bodyECIDMeasurementInitiationRequest.marshalAPERBudget(budget, fresh)
	case q8.ProcedureCode(3):
		if v.bodyECIDMeasurementFailureIndication == nil {
			return nil, q9.Errorf("%s value: missing ECIDMeasurementFailureIndication", "Initiating")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return q12.BridgeECIDMeasurementFailureIndicationMethodMarshalAPERBudget(v.bodyECIDMeasurementFailureIndication, budget, fresh)
	case q8.ProcedureCode(4):
		if v.bodyECIDMeasurementReport == nil {
			return nil, q9.Errorf("%s value: missing ECIDMeasurementReport", "Initiating")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return q13.BridgeECIDMeasurementReportMethodMarshalAPERBudget(v.bodyECIDMeasurementReport, budget, fresh)
	case q8.ProcedureCode(5):
		if v.bodyECIDMeasurementTerminationCommand == nil {
			return nil, q9.Errorf("%s value: missing ECIDMeasurementTerminationCommand", "Initiating")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return q14.BridgeECIDMeasurementTerminationCommandMethodMarshalAPERBudget(v.bodyECIDMeasurementTerminationCommand, budget, fresh)
	case q8.ProcedureCode(6):
		if v.bodyOTDOAInformationRequest == nil {
			return nil, q9.Errorf("%s value: missing OTDOAInformationRequest", "Initiating")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return q15.BridgeOTDOAInformationRequestMethodMarshalAPERBudget(v.bodyOTDOAInformationRequest, budget, fresh)
	case q8.ProcedureCode(7):
		if v.bodyUTDOAInformationRequest == nil {
			return nil, q9.Errorf("%s value: missing UTDOAInformationRequest", "Initiating")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return q16.BridgeUTDOAInformationRequestMethodMarshalAPERBudget(v.bodyUTDOAInformationRequest, budget, fresh)
	case q8.ProcedureCode(8):
		if v.bodyUTDOAInformationUpdate == nil {
			return nil, q9.Errorf("%s value: missing UTDOAInformationUpdate", "Initiating")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return q17.BridgeUTDOAInformationUpdateMethodMarshalAPERBudget(v.bodyUTDOAInformationUpdate, budget, fresh)
	case q8.ProcedureCode(9):
		if v.bodyAssistanceInformationControl == nil {
			return nil, q9.Errorf("%s value: missing AssistanceInformationControl", "Initiating")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return q18.BridgeAssistanceInformationControlMethodMarshalAPERBudget(v.bodyAssistanceInformationControl, budget, fresh)
	case q8.ProcedureCode(10):
		if v.bodyAssistanceInformationFeedback == nil {
			return nil, q9.Errorf("%s value: missing AssistanceInformationFeedback", "Initiating")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return q17.BridgeAssistanceInformationFeedbackMethodMarshalAPERBudget(v.bodyAssistanceInformationFeedback, budget, fresh)
	default:
		return nil, q9.Errorf("%s value: unknown code %d without opaque content", "Initiating", v.code)
	}
}
func NewOpaqueInitiatingMessage(code q8.ProcedureCode, criticality q8.Criticality, transactionID q8.LPPATransactionID, data []byte) (InitiatingMessage, error) {
	if err := q8.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "OpaqueInitiatingMessage")
	}
	switch code {
	case q8.ProcedureCode(0):
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("known Initiating procedure id-errorIndication requires its typed binding"), "OpaqueInitiatingMessage")
	case q8.ProcedureCode(1):
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("known Initiating procedure id-privateMessage requires its typed binding"), "OpaqueInitiatingMessage")
	case q8.ProcedureCode(2):
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("known Initiating procedure id-e-CIDMeasurementInitiation requires its typed binding"), "OpaqueInitiatingMessage")
	case q8.ProcedureCode(3):
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("known Initiating procedure id-e-CIDMeasurementFailureIndication requires its typed binding"), "OpaqueInitiatingMessage")
	case q8.ProcedureCode(4):
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("known Initiating procedure id-e-CIDMeasurementReport requires its typed binding"), "OpaqueInitiatingMessage")
	case q8.ProcedureCode(5):
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("known Initiating procedure id-e-CIDMeasurementTermination requires its typed binding"), "OpaqueInitiatingMessage")
	case q8.ProcedureCode(6):
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("known Initiating procedure id-oTDOAInformationExchange requires its typed binding"), "OpaqueInitiatingMessage")
	case q8.ProcedureCode(7):
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("known Initiating procedure id-uTDOAInformationExchange requires its typed binding"), "OpaqueInitiatingMessage")
	case q8.ProcedureCode(8):
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("known Initiating procedure id-uTDOAInformationUpdate requires its typed binding"), "OpaqueInitiatingMessage")
	case q8.ProcedureCode(9):
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("known Initiating procedure id-assistanceInformationControl requires its typed binding"), "OpaqueInitiatingMessage")
	case q8.ProcedureCode(10):
		return InitiatingMessage{}, q5.OperationError(q9.Errorf("known Initiating procedure id-assistanceInformationFeedback requires its typed binding"), "OpaqueInitiatingMessage")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "OpaqueInitiatingMessage")
	}
	opaque, err := q5.BuildOpaqueOpenType(data, budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "OpaqueInitiatingMessage")
	}
	retained, err := opaque.Retained(budget)
	if err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "OpaqueInitiatingMessage")
	}
	message := InitiatingMessage{ProcedureCode: code, Criticality: criticality, LppatransactionID: transactionID, Value: InitiatingValue{code: code, opaque: retained, isOpaque: true}}
	if _, err := message.marshalAPERBudget(budget, false); err != nil {
		return InitiatingMessage{}, q5.OperationError(err, "OpaqueInitiatingMessage")
	}
	return message, q5.OperationError(nil, "OpaqueInitiatingMessage")
}
func BridgeCaptureLPPaECIDMeasurementInitiationRequest(v *ECIDMeasurementInitiationRequest, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgeECIDMeasurementInitiationRequestIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaECIDMeasurementInitiationRequest(v *ECIDMeasurementInitiationRequest, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeECIDMeasurementInitiationRequestIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaInitiatingMessage(v *InitiatingMessage, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q8.BridgeCaptureLPPaProcedureCode(&v.ProcedureCode, s)
	q8.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	q8.BridgeCaptureLPPaLPPATransactionID(&v.LppatransactionID, s)
	s.OpenBytes(v.Value.captureFraming())
	BridgeCaptureLPPaInitiatingValue(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaInitiatingMessage(v *InitiatingMessage, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q21.BridgeCompareLPPaProcedureCode(&v.ProcedureCode, s)
	q21.BridgeCompareLPPaCriticality(&v.Criticality, s)
	q21.BridgeCompareLPPaLPPATransactionID(&v.LppatransactionID, s)
	BridgeCompareLPPaInitiatingValue(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaInitiatingValue(v *InitiatingValue, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q8.BridgeCaptureLPPaProcedureCode(&v.code, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, nil, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.code {
		case q8.ProcedureCode(0):
			{
				f := s.Begin()
				s.Bool(v.bodyErrorIndication == nil)
				if v.bodyErrorIndication != nil {
					q12.BridgeCaptureLPPaErrorIndication(v.bodyErrorIndication, s)
				}
				s.End(f, nil, false)
			}
		case q8.ProcedureCode(1):
			{
				f := s.Begin()
				s.Bool(v.bodyPrivateMessage == nil)
				if v.bodyPrivateMessage != nil {
					q4.BridgeCaptureLPPaPrivateMessage(v.bodyPrivateMessage, s)
				}
				s.End(f, nil, false)
			}
		case q8.ProcedureCode(2):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementInitiationRequest == nil)
				if v.bodyECIDMeasurementInitiationRequest != nil {
					BridgeCaptureLPPaECIDMeasurementInitiationRequest(v.bodyECIDMeasurementInitiationRequest, s)
				}
				s.End(f, nil, false)
			}
		case q8.ProcedureCode(3):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementFailureIndication == nil)
				if v.bodyECIDMeasurementFailureIndication != nil {
					q12.BridgeCaptureLPPaECIDMeasurementFailureIndication(v.bodyECIDMeasurementFailureIndication, s)
				}
				s.End(f, nil, false)
			}
		case q8.ProcedureCode(4):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementReport == nil)
				if v.bodyECIDMeasurementReport != nil {
					q13.BridgeCaptureLPPaECIDMeasurementReport(v.bodyECIDMeasurementReport, s)
				}
				s.End(f, nil, false)
			}
		case q8.ProcedureCode(5):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementTerminationCommand == nil)
				if v.bodyECIDMeasurementTerminationCommand != nil {
					q14.BridgeCaptureLPPaECIDMeasurementTerminationCommand(v.bodyECIDMeasurementTerminationCommand, s)
				}
				s.End(f, nil, false)
			}
		case q8.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyOTDOAInformationRequest == nil)
				if v.bodyOTDOAInformationRequest != nil {
					q15.BridgeCaptureLPPaOTDOAInformationRequest(v.bodyOTDOAInformationRequest, s)
				}
				s.End(f, nil, false)
			}
		case q8.ProcedureCode(7):
			{
				f := s.Begin()
				s.Bool(v.bodyUTDOAInformationRequest == nil)
				if v.bodyUTDOAInformationRequest != nil {
					q16.BridgeCaptureLPPaUTDOAInformationRequest(v.bodyUTDOAInformationRequest, s)
				}
				s.End(f, nil, false)
			}
		case q8.ProcedureCode(8):
			{
				f := s.Begin()
				s.Bool(v.bodyUTDOAInformationUpdate == nil)
				if v.bodyUTDOAInformationUpdate != nil {
					q17.BridgeCaptureLPPaUTDOAInformationUpdate(v.bodyUTDOAInformationUpdate, s)
				}
				s.End(f, nil, false)
			}
		case q8.ProcedureCode(9):
			{
				f := s.Begin()
				s.Bool(v.bodyAssistanceInformationControl == nil)
				if v.bodyAssistanceInformationControl != nil {
					q18.BridgeCaptureLPPaAssistanceInformationControl(v.bodyAssistanceInformationControl, s)
				}
				s.End(f, nil, false)
			}
		case q8.ProcedureCode(10):
			{
				f := s.Begin()
				s.Bool(v.bodyAssistanceInformationFeedback == nil)
				if v.bodyAssistanceInformationFeedback != nil {
					q17.BridgeCaptureLPPaAssistanceInformationFeedback(v.bodyAssistanceInformationFeedback, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v InitiatingValue) captureSnapshot() q5.Snapshot { return v.replay }
func (v InitiatingValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v InitiatingValue) captureSemantics(s q5.SemanticCapture) InitiatingValue {
	BridgeCaptureLPPaInitiatingValue(&v, &s)
	return v
}
func BridgeCompareLPPaInitiatingValue(v *InitiatingValue, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q21.BridgeCompareLPPaProcedureCode(&v.code, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.code {
		case q8.ProcedureCode(0):
			{
				f := s.Begin()
				s.Bool(v.bodyErrorIndication == nil)
				if v.bodyErrorIndication != nil {
					q12.BridgeCompareLPPaErrorIndication(v.bodyErrorIndication, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		case q8.ProcedureCode(1):
			{
				f := s.Begin()
				s.Bool(v.bodyPrivateMessage == nil)
				if v.bodyPrivateMessage != nil {
					q4.BridgeCompareLPPaPrivateMessage(v.bodyPrivateMessage, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		case q8.ProcedureCode(2):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementInitiationRequest == nil)
				if v.bodyECIDMeasurementInitiationRequest != nil {
					BridgeCompareLPPaECIDMeasurementInitiationRequest(v.bodyECIDMeasurementInitiationRequest, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		case q8.ProcedureCode(3):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementFailureIndication == nil)
				if v.bodyECIDMeasurementFailureIndication != nil {
					q12.BridgeCompareLPPaECIDMeasurementFailureIndication(v.bodyECIDMeasurementFailureIndication, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		case q8.ProcedureCode(4):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementReport == nil)
				if v.bodyECIDMeasurementReport != nil {
					q13.BridgeCompareLPPaECIDMeasurementReport(v.bodyECIDMeasurementReport, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		case q8.ProcedureCode(5):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementTerminationCommand == nil)
				if v.bodyECIDMeasurementTerminationCommand != nil {
					q14.BridgeCompareLPPaECIDMeasurementTerminationCommand(v.bodyECIDMeasurementTerminationCommand, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		case q8.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyOTDOAInformationRequest == nil)
				if v.bodyOTDOAInformationRequest != nil {
					q15.BridgeCompareLPPaOTDOAInformationRequest(v.bodyOTDOAInformationRequest, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		case q8.ProcedureCode(7):
			{
				f := s.Begin()
				s.Bool(v.bodyUTDOAInformationRequest == nil)
				if v.bodyUTDOAInformationRequest != nil {
					q16.BridgeCompareLPPaUTDOAInformationRequest(v.bodyUTDOAInformationRequest, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		case q8.ProcedureCode(8):
			{
				f := s.Begin()
				s.Bool(v.bodyUTDOAInformationUpdate == nil)
				if v.bodyUTDOAInformationUpdate != nil {
					q17.BridgeCompareLPPaUTDOAInformationUpdate(v.bodyUTDOAInformationUpdate, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		case q8.ProcedureCode(9):
			{
				f := s.Begin()
				s.Bool(v.bodyAssistanceInformationControl == nil)
				if v.bodyAssistanceInformationControl != nil {
					q18.BridgeCompareLPPaAssistanceInformationControl(v.bodyAssistanceInformationControl, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		case q8.ProcedureCode(10):
			{
				f := s.Begin()
				s.Bool(v.bodyAssistanceInformationFeedback == nil)
				if v.bodyAssistanceInformationFeedback != nil {
					q17.BridgeCompareLPPaAssistanceInformationFeedback(v.bodyAssistanceInformationFeedback, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v InitiatingValue) compareSemantics(s q5.SemanticComparison) q5.SemanticComparison {
	BridgeCompareLPPaInitiatingValue(&v, &s)
	return s
}
func (v InitiatingValue) WithoutReplay() InitiatingValue {
	v.withoutReplay = true
	v.replay = q5.Snapshot{}
	return v
}

type PrivateMessageDescriptor struct{}

func PrivateMessageProcedure() PrivateMessageDescriptor { return PrivateMessageDescriptor{} }
func (PrivateMessageDescriptor) Info() q8.ProcedureInfo {
	return q8.ProcedureInfo{Code: q8.ProcedureCode(1), Criticality: q8.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-privateMessage"}}}
}

type ECIDMeasurementInitiationRequestIETable struct{}

func ECIDMeasurementInitiationRequestIEs() ECIDMeasurementInitiationRequestIETable {
	return ECIDMeasurementInitiationRequestIETable{}
}
func (ECIDMeasurementInitiationRequestIETable) ID() q8.TableID {
	return func() q8.TableID {
		sealed := q8.TableID{}
		*q8.BridgeTableIDFieldSource(&sealed) = q5.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationRequest-IEs"}
		return sealed
	}()
}
func (ECIDMeasurementInitiationRequestIETable) infoESMLCUEMeasurementID() q8.FieldInfo {
	return q8.FieldInfo{Table: ECIDMeasurementInitiationRequestIEs().ID(), ID: q8.ProtocolIEID(2), Criticality: q8.CriticalityReject, Presence: q8.PresenceMandatory, ValueType: func() q8.TypeID {
		sealed := q8.TypeID{}
		*q8.BridgeTypeIDFieldSource(&sealed) = q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationRequest-IEs", Row: "id-E-SMLC-UE-Measurement-ID"}}}
}
func (t ECIDMeasurementInitiationRequestIETable) ESMLCUEMeasurementID() ECIDMeasurementInitiationRequestMeasurementIDIEBinding {
	return ECIDMeasurementInitiationRequestMeasurementIDIEBinding{info: t.infoESMLCUEMeasurementID(), codec: func() q8.MeasurementIDValueCodec {
		sealed := q8.MeasurementIDValueCodec{}
		*q8.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*q8.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q8.MeasurementID, error) {
			raw, err := q5.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q8.MeasurementID
				return empty, err
			}
			var zero q7.ECIDMeasurementInitiationRequestIEValue
			decoded, err := q7.BridgeECIDMeasurementInitiationRequestIEValueMethodDecode(zero, q8.ProtocolIEID(2), raw)
			if err != nil {
				var empty q8.MeasurementID
				return empty, err
			}
			value, ok := decoded.AsESMLCUEMeasurementID()
			if !ok {
				var empty q8.MeasurementID
				return empty, q9.Errorf("binding E-CIDMeasurementInitiationRequest-IEs.id-E-SMLC-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*q8.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value q8.MeasurementID, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q7.BridgeECIDMeasurementInitiationRequestIEValueMethodEncodeFresh((func() q7.ECIDMeasurementInitiationRequestIEValue {
				sealed := q7.ECIDMeasurementInitiationRequestIEValue{}
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldId(&sealed) = q8.ProtocolIEID(2)
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldRowESMLCUEMeasurementID(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*q8.BridgeMeasurementIDValueCodecFieldCapture(&sealed) = func(v q8.MeasurementID, options q5.DecodeState) (q8.MeasurementID, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q8.BridgeCaptureLPPaMeasurementID(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q8.BridgeMeasurementIDValueCodecFieldCompare(&sealed) = func(v q8.MeasurementID, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q21.BridgeCompareLPPaMeasurementID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q8.BridgeMeasurementIDValueCodecFieldContext(&sealed) = func() q8.BridgeCodecContext {
			sealed := q8.BridgeCodecContext{}
			*q8.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementID"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q8.MeasurementID) q7.ECIDMeasurementInitiationRequestIEValue {
			return func() q7.ECIDMeasurementInitiationRequestIEValue {
				sealed := q7.ECIDMeasurementInitiationRequestIEValue{}
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldId(&sealed) = q8.ProtocolIEID(2)
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldRowESMLCUEMeasurementID(&sealed) = &value
				return sealed
			}()
		}, get: func(value *q7.ECIDMeasurementInitiationRequestIEValue) (*q8.MeasurementID, bool) {
			return value.AsESMLCUEMeasurementID()
		}}
}
func (ECIDMeasurementInitiationRequestIETable) infoReportCharacteristics() q8.FieldInfo {
	return q8.FieldInfo{Table: ECIDMeasurementInitiationRequestIEs().ID(), ID: q8.ProtocolIEID(3), Criticality: q8.CriticalityReject, Presence: q8.PresenceMandatory, ValueType: func() q8.TypeID {
		sealed := q8.TypeID{}
		*q8.BridgeTypeIDFieldSource(&sealed) = q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "ReportCharacteristics"}
		return sealed
	}(), Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationRequest-IEs", Row: "id-ReportCharacteristics"}}}
}
func (t ECIDMeasurementInitiationRequestIETable) ReportCharacteristics() ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding {
	return ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding{info: t.infoReportCharacteristics(), codec: func() q20.ReportCharacteristicsValueCodec {
		sealed := q20.ReportCharacteristicsValueCodec{}
		*q20.BridgeReportCharacteristicsValueCodecFieldPath(&sealed) = "ReportCharacteristics"
		*q20.BridgeReportCharacteristicsValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q8.ReportCharacteristics, error) {
			raw, err := q5.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q8.ReportCharacteristics
				return empty, err
			}
			var zero q7.ECIDMeasurementInitiationRequestIEValue
			decoded, err := q7.BridgeECIDMeasurementInitiationRequestIEValueMethodDecode(zero, q8.ProtocolIEID(3), raw)
			if err != nil {
				var empty q8.ReportCharacteristics
				return empty, err
			}
			value, ok := decoded.AsReportCharacteristics()
			if !ok {
				var empty q8.ReportCharacteristics
				return empty, q9.Errorf("binding E-CIDMeasurementInitiationRequest-IEs.id-ReportCharacteristics: no selected value")
			}
			return *value, nil
		}
		*q20.BridgeReportCharacteristicsValueCodecFieldEncode(&sealed) = func(value q8.ReportCharacteristics, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q7.BridgeECIDMeasurementInitiationRequestIEValueMethodEncodeFresh((func() q7.ECIDMeasurementInitiationRequestIEValue {
				sealed := q7.ECIDMeasurementInitiationRequestIEValue{}
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldId(&sealed) = q8.ProtocolIEID(3)
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldRowReportCharacteristics(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*q20.BridgeReportCharacteristicsValueCodecFieldCapture(&sealed) = func(v q8.ReportCharacteristics, options q5.DecodeState) (q8.ReportCharacteristics, q5.Snapshot,
		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q8.BridgeCaptureLPPaReportCharacteristics(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*q20.BridgeReportCharacteristicsValueCodecFieldCompare(&sealed) = func(v q8.ReportCharacteristics, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q11.BridgeCompareLPPaReportCharacteristics(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q20.BridgeReportCharacteristicsValueCodecFieldContext(&sealed) = func() q8.BridgeCodecContext {
			sealed := q8.BridgeCodecContext{}
			*q8.BridgecodecContextFieldSource(&sealed) = "source-value:ReportCharacteristics"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q8.ReportCharacteristics) q7.ECIDMeasurementInitiationRequestIEValue {
			return func() q7.ECIDMeasurementInitiationRequestIEValue {
				sealed := q7.ECIDMeasurementInitiationRequestIEValue{}
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldId(&sealed) = q8.ProtocolIEID(3)
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldRowReportCharacteristics(&sealed) = &value
				return sealed
			}()
		}, get: func(value *q7.ECIDMeasurementInitiationRequestIEValue) (*q8.ReportCharacteristics, bool) {
			return value.AsReportCharacteristics()
		}}
}
func (ECIDMeasurementInitiationRequestIETable) infoMeasurementPeriodicity() q8.FieldInfo {
	return q8.FieldInfo{Table: ECIDMeasurementInitiationRequestIEs().ID(), ID: q8.ProtocolIEID(4), Criticality: q8.CriticalityReject, Presence: q8.PresenceConditional, ValueType: func() q8.TypeID {
		sealed := q8.TypeID{}
		*q8.BridgeTypeIDFieldSource(&sealed) = q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementPeriodicity"}
		return sealed
	}(), Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationRequest-IEs", Row: "id-MeasurementPeriodicity"}}}
}
func (t ECIDMeasurementInitiationRequestIETable) MeasurementPeriodicity() ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding {
	return ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding{info: t.infoMeasurementPeriodicity(), codec: func() q8.MeasurementPeriodicityValueCodec {
		sealed := q8.MeasurementPeriodicityValueCodec{}
		*q8.BridgeMeasurementPeriodicityValueCodecFieldPath(&sealed) = "MeasurementPeriodicity"
		*q8.BridgeMeasurementPeriodicityValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q8.MeasurementPeriodicity, error) {
			raw, err := q5.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q8.MeasurementPeriodicity
				return empty, err
			}
			var zero q7.ECIDMeasurementInitiationRequestIEValue
			decoded, err := q7.BridgeECIDMeasurementInitiationRequestIEValueMethodDecode(zero, q8.ProtocolIEID(4), raw)
			if err != nil {
				var empty q8.MeasurementPeriodicity
				return empty, err
			}
			value, ok := decoded.AsMeasurementPeriodicity()
			if !ok {
				var empty q8.MeasurementPeriodicity
				return empty, q9.Errorf("binding E-CIDMeasurementInitiationRequest-IEs.id-MeasurementPeriodicity: no selected value")
			}
			return *value, nil
		}
		*q8.BridgeMeasurementPeriodicityValueCodecFieldEncode(&sealed) = func(value q8.MeasurementPeriodicity, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q7.BridgeECIDMeasurementInitiationRequestIEValueMethodEncodeFresh((func() q7.ECIDMeasurementInitiationRequestIEValue {
				sealed := q7.ECIDMeasurementInitiationRequestIEValue{}
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldId(&sealed) = q8.ProtocolIEID(4)
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldRowMeasurementPeriodicity(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*q8.BridgeMeasurementPeriodicityValueCodecFieldCapture(&sealed) = func(v q8.MeasurementPeriodicity, options q5.DecodeState) (q8.MeasurementPeriodicity, q5.Snapshot,

		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q8.BridgeCaptureLPPaMeasurementPeriodicity(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q8.BridgeMeasurementPeriodicityValueCodecFieldCompare(&sealed) = func(v q8.MeasurementPeriodicity, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q21.BridgeCompareLPPaMeasurementPeriodicity(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q8.BridgeMeasurementPeriodicityValueCodecFieldContext(&sealed) = func() q8.BridgeCodecContext {
			sealed := q8.BridgeCodecContext{}
			*q8.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementPeriodicity"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q8.MeasurementPeriodicity) q7.ECIDMeasurementInitiationRequestIEValue {
			return func() q7.ECIDMeasurementInitiationRequestIEValue {
				sealed := q7.ECIDMeasurementInitiationRequestIEValue{}
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldId(&sealed) = q8.ProtocolIEID(4)
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldRowMeasurementPeriodicity(&sealed) = &value
				return sealed
			}()
		}, get: func(value *q7.ECIDMeasurementInitiationRequestIEValue) (*q8.MeasurementPeriodicity, bool) {
			return value.AsMeasurementPeriodicity()
		}}
}
func (ECIDMeasurementInitiationRequestIETable) infoMeasurementQuantities() q8.FieldInfo {
	return q8.FieldInfo{Table: ECIDMeasurementInitiationRequestIEs().ID(), ID: q8.ProtocolIEID(5), Criticality: q8.CriticalityReject, Presence: q8.PresenceMandatory, ValueType: func() q8.TypeID {
		sealed := q8.TypeID{}
		*q8.BridgeTypeIDFieldSource(&sealed) = q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementQuantities"}
		return sealed
	}(), Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationRequest-IEs", Row: "id-MeasurementQuantities"}}}
}
func (t ECIDMeasurementInitiationRequestIETable) MeasurementQuantities() ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding {
	return ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding{info: t.infoMeasurementQuantities(), codec: func() q14.MeasurementQuantitiesConcreteValueCodec {
		sealed := q14.MeasurementQuantitiesConcreteValueCodec{}
		*q14.BridgeMeasurementQuantitiesConcreteValueCodecFieldPath(&sealed) = "MeasurementQuantities"
		*q14.BridgeMeasurementQuantitiesConcreteValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q14.MeasurementQuantities, error) {
			raw, err := q5.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q14.MeasurementQuantities
				return empty, err
			}
			var zero q7.ECIDMeasurementInitiationRequestIEValue
			decoded, err := q7.BridgeECIDMeasurementInitiationRequestIEValueMethodDecode(zero, q8.ProtocolIEID(5), raw)
			if err != nil {
				var empty q14.MeasurementQuantities
				return empty, err
			}
			value, ok := decoded.AsMeasurementQuantities()
			if !ok {
				var empty q14.MeasurementQuantities
				return empty, q9.Errorf("binding E-CIDMeasurementInitiationRequest-IEs.id-MeasurementQuantities: no selected value")
			}
			return *value, nil
		}
		*q14.BridgeMeasurementQuantitiesConcreteValueCodecFieldEncode(&sealed) = func(value q14.MeasurementQuantities, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q7.BridgeECIDMeasurementInitiationRequestIEValueMethodEncodeFresh((func() q7.ECIDMeasurementInitiationRequestIEValue {
				sealed := q7.ECIDMeasurementInitiationRequestIEValue{}
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldId(&sealed) = q8.ProtocolIEID(5)
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldRowMeasurementQuantities(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*q14.BridgeMeasurementQuantitiesConcreteValueCodecFieldCapture(&sealed) = func(v q14.MeasurementQuantities, options q5.DecodeState) (q14.MeasurementQuantities, q5.Snapshot,
		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q12.BridgeCaptureLPPaMeasurementQuantities(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*q14.BridgeMeasurementQuantitiesConcreteValueCodecFieldCompare(&sealed) = func(v q14.MeasurementQuantities, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q12.BridgeCompareLPPaMeasurementQuantities(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q14.BridgeMeasurementQuantitiesConcreteValueCodecFieldContext(&sealed) = func() q8.BridgeCodecContext {
			sealed := q8.BridgeCodecContext{}
			*q8.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementQuantities"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q14.MeasurementQuantities) q7.ECIDMeasurementInitiationRequestIEValue {
			return func() q7.ECIDMeasurementInitiationRequestIEValue {
				sealed := q7.ECIDMeasurementInitiationRequestIEValue{}
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldId(&sealed) = q8.ProtocolIEID(5)
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldRowMeasurementQuantities(&sealed) = &value
				return sealed
			}()
		}, get: func(value *q7.ECIDMeasurementInitiationRequestIEValue) (*q14.MeasurementQuantities, bool) {
			return value.AsMeasurementQuantities()
		}}
}
func (ECIDMeasurementInitiationRequestIETable) infoInterRATMeasurementQuantities() q8.FieldInfo {
	return q8.FieldInfo{Table: ECIDMeasurementInitiationRequestIEs().ID(), ID: q8.ProtocolIEID(15), Criticality: q8.CriticalityIgnore, Presence: q8.PresenceOptional, ValueType: func() q8.TypeID {
		sealed := q8.TypeID{}
		*q8.BridgeTypeIDFieldSource(&sealed) = q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "InterRATMeasurementQuantities"}
		return sealed
	}(), Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationRequest-IEs", Row: "id-InterRATMeasurementQuantities"}}}
}
func (t ECIDMeasurementInitiationRequestIETable) InterRATMeasurementQuantities() ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding {
	return ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding{info: t.infoInterRATMeasurementQuantities(), codec: func() q14.InterRATMeasurementQuantitiesConcreteValueCodec {
		sealed := q14.InterRATMeasurementQuantitiesConcreteValueCodec{}
		*q14.BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldPath(&sealed) = "InterRATMeasurementQuantities"
		*q14.BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q14.InterRATMeasurementQuantities, error) {
			raw, err := q5.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q14.InterRATMeasurementQuantities
				return empty, err
			}
			var zero q7.ECIDMeasurementInitiationRequestIEValue
			decoded, err := q7.BridgeECIDMeasurementInitiationRequestIEValueMethodDecode(zero, q8.ProtocolIEID(15), raw)
			if err != nil {
				var empty q14.InterRATMeasurementQuantities
				return empty, err
			}
			value, ok := decoded.AsInterRATMeasurementQuantities()
			if !ok {
				var empty q14.InterRATMeasurementQuantities
				return empty, q9.Errorf("binding E-CIDMeasurementInitiationRequest-IEs.id-InterRATMeasurementQuantities: no selected value")
			}
			return *value, nil
		}
		*q14.BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldEncode(&sealed) = func(value q14.InterRATMeasurementQuantities, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q7.BridgeECIDMeasurementInitiationRequestIEValueMethodEncodeFresh((func() q7.ECIDMeasurementInitiationRequestIEValue {
				sealed := q7.ECIDMeasurementInitiationRequestIEValue{}
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldId(&sealed) = q8.ProtocolIEID(15)
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldRowInterRATMeasurementQuantities(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*q14.BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldCapture(&sealed) = func(v q14.InterRATMeasurementQuantities, options q5.DecodeState) (q14.InterRATMeasurementQuantities, q5.Snapshot,

		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q12.BridgeCaptureLPPaInterRATMeasurementQuantities(&v, &s)
			var root q5.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v,

				root
		}
		*q14.BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldCompare(&sealed) = func(v q14.InterRATMeasurementQuantities, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q12.BridgeCompareLPPaInterRATMeasurementQuantities(&v, &s)
			s.End(f, root, false)

			return s.Plan()
		}
		*q14.BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldContext(&sealed) = func() q8.BridgeCodecContext {
			sealed := q8.BridgeCodecContext{}
			*q8.BridgecodecContextFieldSource(&sealed) = "source-value:InterRATMeasurementQuantities"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q14.InterRATMeasurementQuantities) q7.ECIDMeasurementInitiationRequestIEValue {
			return func() q7.ECIDMeasurementInitiationRequestIEValue {
				sealed := q7.ECIDMeasurementInitiationRequestIEValue{}
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldId(&sealed) = q8.ProtocolIEID(15)
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldRowInterRATMeasurementQuantities(&sealed) = &value
				return sealed
			}()
		}, get: func(value *q7.ECIDMeasurementInitiationRequestIEValue) (*q14.InterRATMeasurementQuantities, bool) {
			return value.AsInterRATMeasurementQuantities()
		}}
}
func (ECIDMeasurementInitiationRequestIETable) infoWLANMeasurementQuantities() q8.FieldInfo {
	return q8.FieldInfo{Table: ECIDMeasurementInitiationRequestIEs().ID(), ID: q8.ProtocolIEID(19), Criticality: q8.CriticalityIgnore, Presence: q8.PresenceOptional, ValueType: func() q8.TypeID {
		sealed := q8.TypeID{}
		*q8.BridgeTypeIDFieldSource(&sealed) = q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementQuantities"}
		return sealed
	}(), Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationRequest-IEs", Row: "id-WLANMeasurementQuantities"}}}
}
func (t ECIDMeasurementInitiationRequestIETable) WLANMeasurementQuantities() ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding {
	return ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding{info: t.infoWLANMeasurementQuantities(), codec: func() q7.WLANMeasurementQuantitiesConcreteValueCodec {
		sealed := q7.WLANMeasurementQuantitiesConcreteValueCodec{}
		*q7.BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldPath(&sealed) = "WLANMeasurementQuantities"
		*q7.BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q7.WLANMeasurementQuantities, error) {
			raw, err := q5.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q7.WLANMeasurementQuantities
				return empty, err
			}
			var zero q7.ECIDMeasurementInitiationRequestIEValue
			decoded, err := q7.BridgeECIDMeasurementInitiationRequestIEValueMethodDecode(zero, q8.ProtocolIEID(19), raw)
			if err != nil {
				var empty q7.WLANMeasurementQuantities
				return empty, err
			}
			value, ok := decoded.AsWLANMeasurementQuantities()
			if !ok {
				var empty q7.WLANMeasurementQuantities
				return empty, q9.Errorf("binding E-CIDMeasurementInitiationRequest-IEs.id-WLANMeasurementQuantities: no selected value")
			}
			return *value, nil
		}
		*q7.BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldEncode(&sealed) = func(value q7.WLANMeasurementQuantities, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return q7.BridgeECIDMeasurementInitiationRequestIEValueMethodEncodeFresh((func() q7.ECIDMeasurementInitiationRequestIEValue {
				sealed := q7.ECIDMeasurementInitiationRequestIEValue{}
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldId(&sealed) = q8.ProtocolIEID(19)
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldRowWLANMeasurementQuantities(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}
		*q7.BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldCapture(&sealed) = func(v q7.WLANMeasurementQuantities, options q5.DecodeState) (q7.WLANMeasurementQuantities, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q7.BridgeCaptureLPPaWLANMeasurementQuantities(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q7.BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldCompare(&sealed) = func(v q7.WLANMeasurementQuantities, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q7.BridgeCompareLPPaWLANMeasurementQuantities(&v, &s)
			s.End(f, root, false)
			return s.
				Plan()
		}
		*q7.BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldContext(&sealed) = func() q8.BridgeCodecContext {
			sealed := q8.BridgeCodecContext{}
			*q8.BridgecodecContextFieldSource(&sealed) = "source-value:WLANMeasurementQuantities"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q7.WLANMeasurementQuantities) q7.ECIDMeasurementInitiationRequestIEValue {
			return func() q7.ECIDMeasurementInitiationRequestIEValue {
				sealed := q7.ECIDMeasurementInitiationRequestIEValue{}
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldId(&sealed) = q8.ProtocolIEID(19)
				*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldRowWLANMeasurementQuantities(&sealed) = &value
				return sealed
			}()
		}, get: func(value *q7.ECIDMeasurementInitiationRequestIEValue) (*q7.WLANMeasurementQuantities, bool) {
			return value.AsWLANMeasurementQuantities()
		}}
}
func (t ECIDMeasurementInitiationRequestIETable) NewOpaque(id q8.ProtocolIEID, criticality q8.Criticality, data []byte) (ECIDMeasurementInitiationRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(q9.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q8.ProtocolIEID(2):
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(q9.Errorf("known IE id-E-SMLC-UE-Measurement-ID requires its typed binding"), "Opaque")
	case q8.ProtocolIEID(3):
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(q9.Errorf("known IE id-ReportCharacteristics requires its typed binding"), "Opaque")
	case q8.ProtocolIEID(4):
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(q9.Errorf("known IE id-MeasurementPeriodicity requires its typed binding"), "Opaque")
	case q8.ProtocolIEID(5):
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(q9.Errorf("known IE id-MeasurementQuantities requires its typed binding"), "Opaque")
	case q8.ProtocolIEID(15):
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(q9.Errorf("known IE id-InterRATMeasurementQuantities requires its typed binding"), "Opaque")
	case q8.ProtocolIEID(19):
		return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(q9.Errorf("known IE id-WLANMeasurementQuantities requires its typed binding"), "Opaque")
	default:
		budget, err := q5.BuildBudget()
		if err != nil {
			return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(err, "Opaque")
		}
		opaque, err := q5.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ECIDMeasurementInitiationRequestIEField{}, q5.OperationError(err, "Opaque")
		}
		return ECIDMeasurementInitiationRequestIEField{Id: id, Criticality: criticality, Value: func() q7.ECIDMeasurementInitiationRequestIEValue {
			sealed := q7.ECIDMeasurementInitiationRequestIEValue{}
			*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldId(&sealed) = id
			*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldOpaque(&sealed) = retained
			*q7.BridgeECIDMeasurementInitiationRequestIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q5.OperationError(nil, "Opaque")
	}
}

// InitiatingMessageCodec binds the complete source value type.
func InitiatingMessageCodec() InitiatingMessageValueCodec {
	return InitiatingMessageValueCodec{path: "InitiatingMessage", decode: func(data []byte, options q5.DecodeState) (InitiatingMessage, error) {
		var value InitiatingMessage
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return InitiatingMessage{}, err
		}
		value.received = true
		value.receivedBytes = q5.OriginalWire(data)
		return value, nil
	}, encode: func(value InitiatingMessage, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v InitiatingMessage, options q5.DecodeState) (InitiatingMessage, q5.Snapshot) {
		s := q5.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaInitiatingMessage(&v, &s)
		var root q5.Snapshot
		s.OperationCounts()
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v InitiatingMessage, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
		s := q5.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaInitiatingMessage(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q8.BridgeCodecContext {
		sealed := q8.BridgeCodecContext{}
		*q8.BridgecodecContextFieldSource(&sealed) = "source-value:InitiatingMessage"
		return sealed
	}(),
	}
}

// InterRATMeasurementQuantitiesCodec binds the complete APER value type.
func InterRATMeasurementQuantitiesCodec() q14.InterRATMeasurementQuantitiesConcreteValueCodec {
	return ECIDMeasurementInitiationRequestIEs().InterRATMeasurementQuantities().Codec()
}

// MeasurementPeriodicityCodec binds the complete APER value type.
func MeasurementPeriodicityCodec() q8.MeasurementPeriodicityValueCodec {
	return ECIDMeasurementInitiationRequestIEs().MeasurementPeriodicity().Codec()
}

// MeasurementQuantitiesCodec binds the complete APER value type.
func MeasurementQuantitiesCodec() q14.MeasurementQuantitiesConcreteValueCodec {
	return ECIDMeasurementInitiationRequestIEs().MeasurementQuantities().Codec()
}

// PrivateMessageCodec binds the complete APER value type.
func PrivateMessageCodec() q4.PrivateMessageValueCodec {
	return PrivateMessageProcedure().Initiating().Codec()
}

// ReportCharacteristicsCodec binds the complete APER value type.
func ReportCharacteristicsCodec() q20.ReportCharacteristicsValueCodec {
	return ECIDMeasurementInitiationRequestIEs().ReportCharacteristics().Codec()
}

// WLANMeasurementQuantitiesCodec binds the complete APER value type.
func WLANMeasurementQuantitiesCodec() q7.WLANMeasurementQuantitiesConcreteValueCodec {
	return ECIDMeasurementInitiationRequestIEs().WLANMeasurementQuantities().Codec()
}
func BridgeAssistanceInformationControlInitiatingBindingFieldCapture(v *AssistanceInformationControlInitiatingBinding) *func(q18.AssistanceInformationControl, q5.DecodeState) (q18.AssistanceInformationControl, q5.Snapshot) {
	return &v.capture
}
func BridgeAssistanceInformationControlInitiatingBindingFieldCompare(v *AssistanceInformationControlInitiatingBinding) *func(q18.AssistanceInformationControl, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeAssistanceInformationControlInitiatingBindingFieldContext(v *AssistanceInformationControlInitiatingBinding) *q8.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationControlInitiatingBindingFieldDecode(v *AssistanceInformationControlInitiatingBinding) *func([]byte, q5.DecodeState) (q18.AssistanceInformationControl, error) {
	return &v.decode
}
func BridgeAssistanceInformationControlInitiatingBindingFieldEncode(v *AssistanceInformationControlInitiatingBinding) *func(*q18.AssistanceInformationControl, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceInformationControlInitiatingBindingFieldInfo(v *AssistanceInformationControlInitiatingBinding) *q8.ProcedureInfo {
	return &v.info
}
func BridgeAssistanceInformationControlInitiatingBindingFieldInject(v *AssistanceInformationControlInitiatingBinding) *func(q18.AssistanceInformationControl) InitiatingValue {
	return &v.inject
}
func BridgeAssistanceInformationControlInitiatingBindingFieldValidate(v *AssistanceInformationControlInitiatingBinding) *func(*q18.AssistanceInformationControl, *q5.DecodeBudget) (q6.ValidationReport, error) {
	return &v.validate
}
func BridgeAssistanceInformationFeedbackInitiatingBindingFieldCapture(v *AssistanceInformationFeedbackInitiatingBinding) *func(q17.AssistanceInformationFeedback, q5.DecodeState) (q17.AssistanceInformationFeedback, q5.Snapshot) {
	return &v.capture
}
func BridgeAssistanceInformationFeedbackInitiatingBindingFieldCompare(v *AssistanceInformationFeedbackInitiatingBinding) *func(q17.AssistanceInformationFeedback, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeAssistanceInformationFeedbackInitiatingBindingFieldContext(v *AssistanceInformationFeedbackInitiatingBinding) *q8.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationFeedbackInitiatingBindingFieldDecode(v *AssistanceInformationFeedbackInitiatingBinding) *func([]byte, q5.DecodeState) (q17.AssistanceInformationFeedback, error) {
	return &v.decode
}
func BridgeAssistanceInformationFeedbackInitiatingBindingFieldEncode(v *AssistanceInformationFeedbackInitiatingBinding) *func(*q17.AssistanceInformationFeedback, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceInformationFeedbackInitiatingBindingFieldInfo(v *AssistanceInformationFeedbackInitiatingBinding) *q8.ProcedureInfo {
	return &v.info
}
func BridgeAssistanceInformationFeedbackInitiatingBindingFieldInject(v *AssistanceInformationFeedbackInitiatingBinding) *func(q17.AssistanceInformationFeedback) InitiatingValue {
	return &v.inject
}
func BridgeAssistanceInformationFeedbackInitiatingBindingFieldValidate(v *AssistanceInformationFeedbackInitiatingBinding) *func(*q17.AssistanceInformationFeedback, *q5.DecodeBudget) (q6.ValidationReport, error) {
	return &v.validate
}
func BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldCapture(v *ECIDMeasurementFailureIndicationInitiatingBinding) *func(q12.ECIDMeasurementFailureIndication, q5.DecodeState) (q12.ECIDMeasurementFailureIndication, q5.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldCompare(v *ECIDMeasurementFailureIndicationInitiatingBinding) *func(q12.ECIDMeasurementFailureIndication, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldContext(v *ECIDMeasurementFailureIndicationInitiatingBinding) *q8.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldDecode(v *ECIDMeasurementFailureIndicationInitiatingBinding) *func([]byte, q5.DecodeState) (q12.ECIDMeasurementFailureIndication, error) {
	return &v.decode
}
func BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldEncode(v *ECIDMeasurementFailureIndicationInitiatingBinding) *func(*q12.ECIDMeasurementFailureIndication, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldInfo(v *ECIDMeasurementFailureIndicationInitiatingBinding) *q8.ProcedureInfo {
	return &v.info
}
func BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldInject(v *ECIDMeasurementFailureIndicationInitiatingBinding) *func(q12.ECIDMeasurementFailureIndication) InitiatingValue {
	return &v.inject
}
func BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldValidate(v *ECIDMeasurementFailureIndicationInitiatingBinding) *func(*q12.ECIDMeasurementFailureIndication, *q5.DecodeBudget) (q6.ValidationReport, error) {
	return &v.validate
}
func BridgeECIDMeasurementInitiationRequestAPERValueFieldContext(v *ECIDMeasurementInitiationRequestAPERValue) *q8.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementInitiationRequestAPERValueFieldReceived(v *ECIDMeasurementInitiationRequestAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementInitiationRequestAPERValueFieldReplay(v *ECIDMeasurementInitiationRequestAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationRequestAPERValueFieldWithoutReplay(v *ECIDMeasurementInitiationRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationRequestFieldExtCount(v *ECIDMeasurementInitiationRequest) *int64 {
	return &v.extCount
}
func BridgeECIDMeasurementInitiationRequestFieldExtData(v *ECIDMeasurementInitiationRequest) *[][]byte {
	return &v.extData
}
func BridgeECIDMeasurementInitiationRequestFieldExtOrigin(v *ECIDMeasurementInitiationRequest) *[]q5.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeECIDMeasurementInitiationRequestFieldExtPresent(v *ECIDMeasurementInitiationRequest) *[]bool {
	return &v.extPresent
}
func BridgeECIDMeasurementInitiationRequestFieldExtWire(v *ECIDMeasurementInitiationRequest) *[]q5.WireSpan {
	return &v.extWire
}
func BridgeECIDMeasurementInitiationRequestFieldPerExtPadding(v *ECIDMeasurementInitiationRequest) *[]q5.CompletePadding {
	return &v.perExtPadding
}
func BridgeECIDMeasurementInitiationRequestFieldPerPadding(v *ECIDMeasurementInitiationRequest) *q5.FinalPadding {
	return &v.perPadding
}
func BridgeECIDMeasurementInitiationRequestFieldProtocolIEsIndef(v *ECIDMeasurementInitiationRequest) *bool {
	return &v.protocolIEsIndef
}
func BridgeECIDMeasurementInitiationRequestFieldReceived(v *ECIDMeasurementInitiationRequest) *bool {
	return &v.received
}
func BridgeECIDMeasurementInitiationRequestFieldReceivedBytes(v *ECIDMeasurementInitiationRequest) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeECIDMeasurementInitiationRequestFieldReplay(v *ECIDMeasurementInitiationRequest) *q5.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationRequestFieldStream(v *ECIDMeasurementInitiationRequest) *q5.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementInitiationRequestFieldWithoutReplay(v *ECIDMeasurementInitiationRequest) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationRequestIEFieldFieldReceived(v *ECIDMeasurementInitiationRequestIEField) *q5.CompletePadding {
	return &v.received
}
func BridgeECIDMeasurementInitiationRequestIEFieldFieldReplay(v *ECIDMeasurementInitiationRequestIEField) *q5.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationRequestIEFieldFieldStream(v *ECIDMeasurementInitiationRequestIEField) *q5.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementInitiationRequestIEFieldFieldWithoutReplay(v *ECIDMeasurementInitiationRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationRequestIEFieldMethodMarshalAPERTo(v *ECIDMeasurementInitiationRequestIEField, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementInitiationRequestIEFieldMethodUnmarshalAPERFrom(v *ECIDMeasurementInitiationRequestIEField, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementInitiationRequestIETableMethodInfoESMLCUEMeasurementID(v ECIDMeasurementInitiationRequestIETable) q8.FieldInfo {
	return v.infoESMLCUEMeasurementID()
}
func BridgeECIDMeasurementInitiationRequestIETableMethodInfoInterRATMeasurementQuantities(v ECIDMeasurementInitiationRequestIETable) q8.FieldInfo {
	return v.infoInterRATMeasurementQuantities()
}
func BridgeECIDMeasurementInitiationRequestIETableMethodInfoMeasurementPeriodicity(v ECIDMeasurementInitiationRequestIETable) q8.FieldInfo {
	return v.infoMeasurementPeriodicity()
}
func BridgeECIDMeasurementInitiationRequestIETableMethodInfoMeasurementQuantities(v ECIDMeasurementInitiationRequestIETable) q8.FieldInfo {
	return v.infoMeasurementQuantities()
}
func BridgeECIDMeasurementInitiationRequestIETableMethodInfoReportCharacteristics(v ECIDMeasurementInitiationRequestIETable) q8.FieldInfo {
	return v.infoReportCharacteristics()
}
func BridgeECIDMeasurementInitiationRequestIETableMethodInfoWLANMeasurementQuantities(v ECIDMeasurementInitiationRequestIETable) q8.FieldInfo {
	return v.infoWLANMeasurementQuantities()
}
func BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldCapture(v *ECIDMeasurementInitiationRequestInitiatingBinding) *func(ECIDMeasurementInitiationRequest, q5.DecodeState) (ECIDMeasurementInitiationRequest, q5.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldCompare(v *ECIDMeasurementInitiationRequestInitiatingBinding) *func(ECIDMeasurementInitiationRequest, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldContext(v *ECIDMeasurementInitiationRequestInitiatingBinding) *q8.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldDecode(v *ECIDMeasurementInitiationRequestInitiatingBinding) *func([]byte, q5.DecodeState) (ECIDMeasurementInitiationRequest, error) {
	return &v.decode
}
func BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldEncode(v *ECIDMeasurementInitiationRequestInitiatingBinding) *func(*ECIDMeasurementInitiationRequest, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldInfo(v *ECIDMeasurementInitiationRequestInitiatingBinding) *q8.ProcedureInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldInject(v *ECIDMeasurementInitiationRequestInitiatingBinding) *func(ECIDMeasurementInitiationRequest) InitiatingValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldValidate(v *ECIDMeasurementInitiationRequestInitiatingBinding) *func(*ECIDMeasurementInitiationRequest, *q5.DecodeBudget) (q6.ValidationReport, error) {
	return &v.validate
}
func BridgeECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBindingFieldCodec(v *ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding) *q14.InterRATMeasurementQuantitiesConcreteValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBindingFieldGet(v *ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding) *func(*q7.ECIDMeasurementInitiationRequestIEValue) (*q14.InterRATMeasurementQuantities, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBindingFieldInfo(v *ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding) *q8.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBindingFieldInject(v *ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding) *func(q14.InterRATMeasurementQuantities) q7.ECIDMeasurementInitiationRequestIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationRequestMeasurementIDIEBindingFieldCodec(v *ECIDMeasurementInitiationRequestMeasurementIDIEBinding) *q8.MeasurementIDValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationRequestMeasurementIDIEBindingFieldGet(v *ECIDMeasurementInitiationRequestMeasurementIDIEBinding) *func(*q7.ECIDMeasurementInitiationRequestIEValue) (*q8.MeasurementID, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationRequestMeasurementIDIEBindingFieldInfo(v *ECIDMeasurementInitiationRequestMeasurementIDIEBinding) *q8.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationRequestMeasurementIDIEBindingFieldInject(v *ECIDMeasurementInitiationRequestMeasurementIDIEBinding) *func(q8.MeasurementID) q7.ECIDMeasurementInitiationRequestIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationRequestMeasurementPeriodicityIEBindingFieldCodec(v *ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding) *q8.MeasurementPeriodicityValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationRequestMeasurementPeriodicityIEBindingFieldGet(v *ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding) *func(*q7.ECIDMeasurementInitiationRequestIEValue) (*q8.MeasurementPeriodicity, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationRequestMeasurementPeriodicityIEBindingFieldInfo(v *ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding) *q8.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationRequestMeasurementPeriodicityIEBindingFieldInject(v *ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding) *func(q8.MeasurementPeriodicity) q7.ECIDMeasurementInitiationRequestIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationRequestMeasurementQuantitiesIEBindingFieldCodec(v *ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding) *q14.MeasurementQuantitiesConcreteValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationRequestMeasurementQuantitiesIEBindingFieldGet(v *ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding) *func(*q7.ECIDMeasurementInitiationRequestIEValue) (*q14.MeasurementQuantities, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationRequestMeasurementQuantitiesIEBindingFieldInfo(v *ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding) *q8.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationRequestMeasurementQuantitiesIEBindingFieldInject(v *ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding) *func(q14.MeasurementQuantities) q7.ECIDMeasurementInitiationRequestIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationRequestMethodMarshalAPERBudget(v *ECIDMeasurementInitiationRequest, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeECIDMeasurementInitiationRequestMethodMarshalAPERChanged(v *ECIDMeasurementInitiationRequest, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeECIDMeasurementInitiationRequestMethodMarshalAPERChangedValue(v *ECIDMeasurementInitiationRequest, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeECIDMeasurementInitiationRequestMethodMarshalAPERFreshValue(v *ECIDMeasurementInitiationRequest, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeECIDMeasurementInitiationRequestMethodMarshalAPERLegacy(v *ECIDMeasurementInitiationRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeECIDMeasurementInitiationRequestMethodMarshalAPERPlanned(v *ECIDMeasurementInitiationRequest, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeECIDMeasurementInitiationRequestMethodMarshalAPERTo(v *ECIDMeasurementInitiationRequest, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementInitiationRequestMethodUnmarshalAPERFrom(v *ECIDMeasurementInitiationRequest, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementInitiationRequestMethodUnmarshalAPERLegacy(v *ECIDMeasurementInitiationRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeECIDMeasurementInitiationRequestMethodUnmarshalAPERWithOptions(v *ECIDMeasurementInitiationRequest, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeECIDMeasurementInitiationRequestReportCharacteristicsIEBindingFieldCodec(v *ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding) *q20.ReportCharacteristicsValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationRequestReportCharacteristicsIEBindingFieldGet(v *ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding) *func(*q7.ECIDMeasurementInitiationRequestIEValue) (*q8.ReportCharacteristics, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationRequestReportCharacteristicsIEBindingFieldInfo(v *ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding) *q8.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationRequestReportCharacteristicsIEBindingFieldInject(v *ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding) *func(q8.ReportCharacteristics) q7.ECIDMeasurementInitiationRequestIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationRequestValueCodecFieldCapture(v *ECIDMeasurementInitiationRequestValueCodec) *func(ECIDMeasurementInitiationRequest, q5.DecodeState) (ECIDMeasurementInitiationRequest, q5.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementInitiationRequestValueCodecFieldCompare(v *ECIDMeasurementInitiationRequestValueCodec) *func(ECIDMeasurementInitiationRequest, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementInitiationRequestValueCodecFieldContext(v *ECIDMeasurementInitiationRequestValueCodec) *q8.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementInitiationRequestValueCodecFieldDecode(v *ECIDMeasurementInitiationRequestValueCodec) *func([]byte, q5.DecodeState) (ECIDMeasurementInitiationRequest, error) {
	return &v.decode
}
func BridgeECIDMeasurementInitiationRequestValueCodecFieldEncode(v *ECIDMeasurementInitiationRequestValueCodec) *func(ECIDMeasurementInitiationRequest, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementInitiationRequestValueCodecFieldPath(v *ECIDMeasurementInitiationRequestValueCodec) *q5.Path {
	return &v.path
}
func BridgeECIDMeasurementInitiationRequestValueCodecMethodEncodeBudget(v ECIDMeasurementInitiationRequestValueCodec, a0 ECIDMeasurementInitiationRequest, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeECIDMeasurementInitiationRequestValueCodecMethodEncodeChanged(v ECIDMeasurementInitiationRequestValueCodec, a0 ECIDMeasurementInitiationRequest, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBindingFieldCodec(v *ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding) *q7.WLANMeasurementQuantitiesConcreteValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBindingFieldGet(v *ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding) *func(*q7.ECIDMeasurementInitiationRequestIEValue) (*q7.WLANMeasurementQuantities, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBindingFieldInfo(v *ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding) *q8.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBindingFieldInject(v *ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding) *func(q7.WLANMeasurementQuantities) q7.ECIDMeasurementInitiationRequestIEValue {
	return &v.inject
}
func BridgeECIDMeasurementReportInitiatingBindingFieldCapture(v *ECIDMeasurementReportInitiatingBinding) *func(q13.ECIDMeasurementReport, q5.DecodeState) (q13.ECIDMeasurementReport, q5.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementReportInitiatingBindingFieldCompare(v *ECIDMeasurementReportInitiatingBinding) *func(q13.ECIDMeasurementReport, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementReportInitiatingBindingFieldContext(v *ECIDMeasurementReportInitiatingBinding) *q8.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementReportInitiatingBindingFieldDecode(v *ECIDMeasurementReportInitiatingBinding) *func([]byte, q5.DecodeState) (q13.ECIDMeasurementReport, error) {
	return &v.decode
}
func BridgeECIDMeasurementReportInitiatingBindingFieldEncode(v *ECIDMeasurementReportInitiatingBinding) *func(*q13.ECIDMeasurementReport, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementReportInitiatingBindingFieldInfo(v *ECIDMeasurementReportInitiatingBinding) *q8.ProcedureInfo {
	return &v.info
}
func BridgeECIDMeasurementReportInitiatingBindingFieldInject(v *ECIDMeasurementReportInitiatingBinding) *func(q13.ECIDMeasurementReport) InitiatingValue {
	return &v.inject
}
func BridgeECIDMeasurementReportInitiatingBindingFieldValidate(v *ECIDMeasurementReportInitiatingBinding) *func(*q13.ECIDMeasurementReport, *q5.DecodeBudget) (q6.ValidationReport, error) {
	return &v.validate
}
func BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldCapture(v *ECIDMeasurementTerminationCommandInitiatingBinding) *func(q14.ECIDMeasurementTerminationCommand, q5.DecodeState) (q14.ECIDMeasurementTerminationCommand, q5.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldCompare(v *ECIDMeasurementTerminationCommandInitiatingBinding) *func(q14.ECIDMeasurementTerminationCommand, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldContext(v *ECIDMeasurementTerminationCommandInitiatingBinding) *q8.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldDecode(v *ECIDMeasurementTerminationCommandInitiatingBinding) *func([]byte, q5.DecodeState) (q14.ECIDMeasurementTerminationCommand, error) {
	return &v.decode
}
func BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldEncode(v *ECIDMeasurementTerminationCommandInitiatingBinding) *func(*q14.ECIDMeasurementTerminationCommand, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldInfo(v *ECIDMeasurementTerminationCommandInitiatingBinding) *q8.ProcedureInfo {
	return &v.info
}
func BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldInject(v *ECIDMeasurementTerminationCommandInitiatingBinding) *func(q14.ECIDMeasurementTerminationCommand) InitiatingValue {
	return &v.inject
}
func BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldValidate(v *ECIDMeasurementTerminationCommandInitiatingBinding) *func(*q14.ECIDMeasurementTerminationCommand, *q5.DecodeBudget) (q6.ValidationReport, error) {
	return &v.validate
}
func BridgeErrorIndicationInitiatingBindingFieldCapture(v *ErrorIndicationInitiatingBinding) *func(q12.ErrorIndication, q5.DecodeState) (q12.ErrorIndication, q5.Snapshot) {
	return &v.capture
}
func BridgeErrorIndicationInitiatingBindingFieldCompare(v *ErrorIndicationInitiatingBinding) *func(q12.ErrorIndication, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeErrorIndicationInitiatingBindingFieldContext(v *ErrorIndicationInitiatingBinding) *q8.BridgeCodecContext {
	return &v.context
}
func BridgeErrorIndicationInitiatingBindingFieldDecode(v *ErrorIndicationInitiatingBinding) *func([]byte, q5.DecodeState) (q12.ErrorIndication, error) {
	return &v.decode
}
func BridgeErrorIndicationInitiatingBindingFieldEncode(v *ErrorIndicationInitiatingBinding) *func(*q12.ErrorIndication, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeErrorIndicationInitiatingBindingFieldInfo(v *ErrorIndicationInitiatingBinding) *q8.ProcedureInfo {
	return &v.info
}
func BridgeErrorIndicationInitiatingBindingFieldInject(v *ErrorIndicationInitiatingBinding) *func(q12.ErrorIndication) InitiatingValue {
	return &v.inject
}
func BridgeErrorIndicationInitiatingBindingFieldValidate(v *ErrorIndicationInitiatingBinding) *func(*q12.ErrorIndication, *q5.DecodeBudget) (q6.ValidationReport, error) {
	return &v.validate
}
func BridgeInitiatingMessageAPERValueFieldContext(v *InitiatingMessageAPERValue) *q8.BridgeCodecContext {
	return &v.context
}
func BridgeInitiatingMessageAPERValueFieldReceived(v *InitiatingMessageAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeInitiatingMessageAPERValueFieldReplay(v *InitiatingMessageAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeInitiatingMessageAPERValueFieldWithoutReplay(v *InitiatingMessageAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitiatingMessageFieldPerPadding(v *InitiatingMessage) *q5.CompletePadding {
	return &v.perPadding
}
func BridgeInitiatingMessageFieldReceived(v *InitiatingMessage) *bool { return &v.received }
func BridgeInitiatingMessageFieldReceivedBytes(v *InitiatingMessage) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeInitiatingMessageFieldReplay(v *InitiatingMessage) *q5.Snapshot { return &v.replay }
func BridgeInitiatingMessageFieldStream(v *InitiatingMessage) *q5.WireSpan { return &v.stream }
func BridgeInitiatingMessageFieldWithoutReplay(v *InitiatingMessage) *bool { return &v.withoutReplay }
func BridgeInitiatingMessageMethodMarshalAPERBudget(v *InitiatingMessage, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInitiatingMessageMethodMarshalAPERChanged(v *InitiatingMessage, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeInitiatingMessageMethodMarshalAPERChangedValue(v *InitiatingMessage, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeInitiatingMessageMethodMarshalAPERFreshValue(v *InitiatingMessage, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeInitiatingMessageMethodMarshalAPERLegacy(v *InitiatingMessage) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeInitiatingMessageMethodMarshalAPERPlanned(v *InitiatingMessage, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeInitiatingMessageMethodMarshalAPERTo(v *InitiatingMessage, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInitiatingMessageMethodUnmarshalAPERFrom(v *InitiatingMessage, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInitiatingMessageMethodUnmarshalAPERLegacy(v *InitiatingMessage, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeInitiatingMessageMethodUnmarshalAPERWithOptions(v *InitiatingMessage, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeInitiatingMessageValueCodecFieldCapture(v *InitiatingMessageValueCodec) *func(InitiatingMessage, q5.DecodeState) (InitiatingMessage, q5.Snapshot) {
	return &v.capture
}
func BridgeInitiatingMessageValueCodecFieldCompare(v *InitiatingMessageValueCodec) *func(InitiatingMessage, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeInitiatingMessageValueCodecFieldContext(v *InitiatingMessageValueCodec) *q8.BridgeCodecContext {
	return &v.context
}
func BridgeInitiatingMessageValueCodecFieldDecode(v *InitiatingMessageValueCodec) *func([]byte, q5.DecodeState) (InitiatingMessage, error) {
	return &v.decode
}
func BridgeInitiatingMessageValueCodecFieldEncode(v *InitiatingMessageValueCodec) *func(InitiatingMessage, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitiatingMessageValueCodecFieldPath(v *InitiatingMessageValueCodec) *q5.Path {
	return &v.path
}
func BridgeInitiatingMessageValueCodecMethodEncodeBudget(v InitiatingMessageValueCodec, a0 InitiatingMessage, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeInitiatingMessageValueCodecMethodEncodeChanged(v InitiatingMessageValueCodec, a0 InitiatingMessage, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitiatingValueFieldBodyAssistanceInformationControl(v *InitiatingValue) **q18.AssistanceInformationControl {
	return &v.bodyAssistanceInformationControl
}
func BridgeInitiatingValueFieldBodyAssistanceInformationFeedback(v *InitiatingValue) **q17.AssistanceInformationFeedback {
	return &v.bodyAssistanceInformationFeedback
}
func BridgeInitiatingValueFieldBodyECIDMeasurementFailureIndication(v *InitiatingValue) **q12.ECIDMeasurementFailureIndication {
	return &v.bodyECIDMeasurementFailureIndication
}
func BridgeInitiatingValueFieldBodyECIDMeasurementInitiationRequest(v *InitiatingValue) **ECIDMeasurementInitiationRequest {
	return &v.bodyECIDMeasurementInitiationRequest
}
func BridgeInitiatingValueFieldBodyECIDMeasurementReport(v *InitiatingValue) **q13.ECIDMeasurementReport {
	return &v.bodyECIDMeasurementReport
}
func BridgeInitiatingValueFieldBodyECIDMeasurementTerminationCommand(v *InitiatingValue) **q14.ECIDMeasurementTerminationCommand {
	return &v.bodyECIDMeasurementTerminationCommand
}
func BridgeInitiatingValueFieldBodyErrorIndication(v *InitiatingValue) **q12.ErrorIndication {
	return &v.bodyErrorIndication
}
func BridgeInitiatingValueFieldBodyOTDOAInformationRequest(v *InitiatingValue) **q15.OTDOAInformationRequest {
	return &v.bodyOTDOAInformationRequest
}
func BridgeInitiatingValueFieldBodyPrivateMessage(v *InitiatingValue) **q4.PrivateMessage {
	return &v.bodyPrivateMessage
}
func BridgeInitiatingValueFieldBodyUTDOAInformationRequest(v *InitiatingValue) **q16.UTDOAInformationRequest {
	return &v.bodyUTDOAInformationRequest
}
func BridgeInitiatingValueFieldBodyUTDOAInformationUpdate(v *InitiatingValue) **q17.UTDOAInformationUpdate {
	return &v.bodyUTDOAInformationUpdate
}
func BridgeInitiatingValueFieldCode(v *InitiatingValue) *q8.ProcedureCode     { return &v.code }
func BridgeInitiatingValueFieldIsOpaque(v *InitiatingValue) *bool             { return &v.isOpaque }
func BridgeInitiatingValueFieldOpaque(v *InitiatingValue) **q5.OpaqueOpenType { return &v.opaque }
func BridgeInitiatingValueFieldReceived(v *InitiatingValue) *q5.WireSpan      { return &v.received }
func BridgeInitiatingValueFieldReplay(v *InitiatingValue) *q5.Snapshot        { return &v.replay }
func BridgeInitiatingValueFieldWithoutReplay(v *InitiatingValue) *bool        { return &v.withoutReplay }
func BridgeInitiatingValueMethodCaptureFraming(v InitiatingValue) uint64      { return v.captureFraming() }
func BridgeInitiatingValueMethodCaptureSemantics(v InitiatingValue, a0 q5.SemanticCapture) InitiatingValue {
	return v.captureSemantics(a0)
}
func BridgeInitiatingValueMethodCaptureSnapshot(v InitiatingValue) q5.Snapshot {
	return v.captureSnapshot()
}
func BridgeInitiatingValueMethodCompareSemantics(v InitiatingValue, a0 q5.SemanticComparison) q5.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeInitiatingValueMethodEncode(v InitiatingValue) ([]byte, error) { return v.encode() }
func BridgeInitiatingValueMethodEncodeFresh(v InitiatingValue, a0 bool, a1 *q5.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeOTDOAInformationRequestInitiatingBindingFieldCapture(v *OTDOAInformationRequestInitiatingBinding) *func(q15.OTDOAInformationRequest, q5.DecodeState) (q15.OTDOAInformationRequest, q5.Snapshot) {
	return &v.capture
}
func BridgeOTDOAInformationRequestInitiatingBindingFieldCompare(v *OTDOAInformationRequestInitiatingBinding) *func(q15.OTDOAInformationRequest, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeOTDOAInformationRequestInitiatingBindingFieldContext(v *OTDOAInformationRequestInitiatingBinding) *q8.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationRequestInitiatingBindingFieldDecode(v *OTDOAInformationRequestInitiatingBinding) *func([]byte, q5.DecodeState) (q15.OTDOAInformationRequest, error) {
	return &v.decode
}
func BridgeOTDOAInformationRequestInitiatingBindingFieldEncode(v *OTDOAInformationRequestInitiatingBinding) *func(*q15.OTDOAInformationRequest, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOAInformationRequestInitiatingBindingFieldInfo(v *OTDOAInformationRequestInitiatingBinding) *q8.ProcedureInfo {
	return &v.info
}
func BridgeOTDOAInformationRequestInitiatingBindingFieldInject(v *OTDOAInformationRequestInitiatingBinding) *func(q15.OTDOAInformationRequest) InitiatingValue {
	return &v.inject
}
func BridgeOTDOAInformationRequestInitiatingBindingFieldValidate(v *OTDOAInformationRequestInitiatingBinding) *func(*q15.OTDOAInformationRequest, *q5.DecodeBudget) (q6.ValidationReport, error) {
	return &v.validate
}
func BridgePrivateMessageInitiatingBindingFieldCapture(v *PrivateMessageInitiatingBinding) *func(q4.PrivateMessage, q5.DecodeState) (q4.PrivateMessage, q5.Snapshot) {
	return &v.capture
}
func BridgePrivateMessageInitiatingBindingFieldCompare(v *PrivateMessageInitiatingBinding) *func(q4.PrivateMessage, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgePrivateMessageInitiatingBindingFieldContext(v *PrivateMessageInitiatingBinding) *q8.BridgeCodecContext {
	return &v.context
}
func BridgePrivateMessageInitiatingBindingFieldDecode(v *PrivateMessageInitiatingBinding) *func([]byte, q5.DecodeState) (q4.PrivateMessage, error) {
	return &v.decode
}
func BridgePrivateMessageInitiatingBindingFieldEncode(v *PrivateMessageInitiatingBinding) *func(*q4.PrivateMessage, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePrivateMessageInitiatingBindingFieldInfo(v *PrivateMessageInitiatingBinding) *q8.ProcedureInfo {
	return &v.info
}
func BridgePrivateMessageInitiatingBindingFieldInject(v *PrivateMessageInitiatingBinding) *func(q4.PrivateMessage) InitiatingValue {
	return &v.inject
}
func BridgePrivateMessageInitiatingBindingFieldValidate(v *PrivateMessageInitiatingBinding) *func(*q4.PrivateMessage, *q5.DecodeBudget) (q6.ValidationReport, error) {
	return &v.validate
}
func BridgeUTDOAInformationRequestInitiatingBindingFieldCapture(v *UTDOAInformationRequestInitiatingBinding) *func(q16.UTDOAInformationRequest, q5.DecodeState) (q16.UTDOAInformationRequest, q5.Snapshot) {
	return &v.capture
}
func BridgeUTDOAInformationRequestInitiatingBindingFieldCompare(v *UTDOAInformationRequestInitiatingBinding) *func(q16.UTDOAInformationRequest, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeUTDOAInformationRequestInitiatingBindingFieldContext(v *UTDOAInformationRequestInitiatingBinding) *q8.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationRequestInitiatingBindingFieldDecode(v *UTDOAInformationRequestInitiatingBinding) *func([]byte, q5.DecodeState) (q16.UTDOAInformationRequest, error) {
	return &v.decode
}
func BridgeUTDOAInformationRequestInitiatingBindingFieldEncode(v *UTDOAInformationRequestInitiatingBinding) *func(*q16.UTDOAInformationRequest, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTDOAInformationRequestInitiatingBindingFieldInfo(v *UTDOAInformationRequestInitiatingBinding) *q8.ProcedureInfo {
	return &v.info
}
func BridgeUTDOAInformationRequestInitiatingBindingFieldInject(v *UTDOAInformationRequestInitiatingBinding) *func(q16.UTDOAInformationRequest) InitiatingValue {
	return &v.inject
}
func BridgeUTDOAInformationRequestInitiatingBindingFieldValidate(v *UTDOAInformationRequestInitiatingBinding) *func(*q16.UTDOAInformationRequest, *q5.DecodeBudget) (q6.ValidationReport, error) {
	return &v.validate
}
func BridgeUTDOAInformationUpdateInitiatingBindingFieldCapture(v *UTDOAInformationUpdateInitiatingBinding) *func(q17.UTDOAInformationUpdate, q5.DecodeState) (q17.UTDOAInformationUpdate, q5.Snapshot) {
	return &v.capture
}
func BridgeUTDOAInformationUpdateInitiatingBindingFieldCompare(v *UTDOAInformationUpdateInitiatingBinding) *func(q17.UTDOAInformationUpdate, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeUTDOAInformationUpdateInitiatingBindingFieldContext(v *UTDOAInformationUpdateInitiatingBinding) *q8.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationUpdateInitiatingBindingFieldDecode(v *UTDOAInformationUpdateInitiatingBinding) *func([]byte, q5.DecodeState) (q17.UTDOAInformationUpdate, error) {
	return &v.decode
}
func BridgeUTDOAInformationUpdateInitiatingBindingFieldEncode(v *UTDOAInformationUpdateInitiatingBinding) *func(*q17.UTDOAInformationUpdate, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTDOAInformationUpdateInitiatingBindingFieldInfo(v *UTDOAInformationUpdateInitiatingBinding) *q8.ProcedureInfo {
	return &v.info
}
func BridgeUTDOAInformationUpdateInitiatingBindingFieldInject(v *UTDOAInformationUpdateInitiatingBinding) *func(q17.UTDOAInformationUpdate) InitiatingValue {
	return &v.inject
}
func BridgeUTDOAInformationUpdateInitiatingBindingFieldValidate(v *UTDOAInformationUpdateInitiatingBinding) *func(*q17.UTDOAInformationUpdate, *q5.DecodeBudget) (q6.ValidationReport, error) {
	return &v.validate
}
