// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s21 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s21

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s12"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s13"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s15"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s16"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s17"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s18"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s20"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// Initiating returns the binding for this procedure's initiating message.
func (PrivateMessageDescriptor) Initiating() PrivateMessageInitiatingBinding {
	return PrivateMessageInitiatingBinding{info: PrivateMessageProcedure().Info(), validate: func(v *s12.PrivateMessage, budget *aper.DecodeBudget) (s09.ValidationReport, error) {
		return s20.BridgeValidatePrivateMessageBudget(v, budget)
	}, encode: func(v *s12.PrivateMessage, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return s12.BridgePrivateMessageMethodMarshalAPERBudget(v, budget, fresh)
	}, decode: func(data []byte, options aper.DecodeState) (s12.PrivateMessage, error) {
		var v s12.PrivateMessage
		err := s12.BridgePrivateMessageMethodUnmarshalAPERWithOptions(&v, data, options)
		if err != nil {
			return s12.PrivateMessage{}, err
		}
		*s12.BridgePrivateMessageFieldReceived(&v) = true
		*s12.BridgePrivateMessageFieldReceivedBytes(&v) = aper.OriginalWire(data)
		return v, nil
	}, inject: func(v s12.PrivateMessage) InitiatingValue {
		return InitiatingValue{code: s00.ProcedureCode(1), bodyPrivateMessage: &v}
	}, capture: func(v s12.PrivateMessage, options aper.DecodeState) (s12.PrivateMessage, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.
			Begin()
		s12.BridgeCaptureLPPaPrivateMessage(&v, &s)
		var root aper.Snapshot

		s.OperationCounts()
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v s12.PrivateMessage, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root,
			limits)
		f := s.Begin()
		s12.BridgeCompareLPPaPrivateMessage(&v, &s)
		s.
			End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PrivateMessage"
		return sealed
	}(),
	}
}

// ECIDMeasurementInitiationRequestIEContainer is ProtocolIE-Container {{E-CIDMeasurementInitiationRequest-IEs}} of TS 36.455: a list of ECIDMeasurementInitiationRequestIEField values.
type ECIDMeasurementInitiationRequestIEContainer []ECIDMeasurementInitiationRequestIEField

// ECIDMeasurementInitiationRequestIEField is ProtocolIE-Field {{E-CIDMeasurementInitiationRequest-IEs}} of TS 36.455: a field carrying a value of ECIDMeasurementInitiationRequestIEValue.
type ECIDMeasurementInitiationRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ECIDMeasurementInitiationRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECIDMeasurementInitiationRequestIEField) WithoutReplay() ECIDMeasurementInitiationRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ECIDMeasurementInitiationRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ECIDMeasurementInitiationRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ECIDMeasurementInitiationRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementInitiationRequestIEField{}
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
	var zero ECIDMeasurementInitiationRequestIEValue

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
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// ErrorIndicationInitiatingBinding is the concrete InitiatingBinding[ErrorIndication].
type ErrorIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s11.ErrorIndication, aper.DecodeState,

	) (s11.ErrorIndication, aper.Snapshot,

	)
	compare func(s11.ErrorIndication, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*s11.ErrorIndication,

		*aper.DecodeBudget) (s09.ValidationReport, error)
	encode func(*s11.ErrorIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s11.ErrorIndication,

		error)
	inject func(s11.ErrorIndication,

	) InitiatingValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ErrorIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ErrorIndicationInitiatingBinding) Codec() s11.ErrorIndicationValueCodec {
	return func() s11.ErrorIndicationValueCodec {
		sealed := s11.ErrorIndicationValueCodec{}
		*s11.BridgeErrorIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s11.BridgeErrorIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s11.BridgeErrorIndicationValueCodecFieldEncode(&sealed) = func(value s11.ErrorIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s11.BridgeErrorIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s11.BridgeErrorIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s11.BridgeErrorIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b ErrorIndicationInitiatingBinding) Build(body s11.ErrorIndication,

	transactionID s00.LPPATransactionID, options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// PrivateMessageInitiatingBinding is the concrete InitiatingBinding[PrivateMessage].
type PrivateMessageInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s12.PrivateMessage, aper.DecodeState,

	) (s12.PrivateMessage, aper.Snapshot,

	)
	compare func(s12.PrivateMessage, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*s12.PrivateMessage,

		*aper.DecodeBudget) (s09.ValidationReport, error)
	encode func(*s12.PrivateMessage,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s12.PrivateMessage,

		error)
	inject func(s12.PrivateMessage,

	) InitiatingValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b PrivateMessageInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b PrivateMessageInitiatingBinding) Codec() s12.PrivateMessageValueCodec {
	return func() s12.PrivateMessageValueCodec {
		sealed := s12.PrivateMessageValueCodec{}
		*s12.BridgePrivateMessageValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s12.BridgePrivateMessageValueCodecFieldDecode(&sealed) = b.decode
		*s12.BridgePrivateMessageValueCodecFieldEncode(&sealed) = func(value s12.PrivateMessage,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s12.BridgePrivateMessageValueCodecFieldCapture(&sealed) = b.capture
		*s12.BridgePrivateMessageValueCodecFieldCompare(&sealed) = b.compare
		*s12.BridgePrivateMessageValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b PrivateMessageInitiatingBinding) Build(body s12.PrivateMessage,

	transactionID s00.LPPATransactionID, options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ECIDMeasurementInitiationRequestInitiatingBinding is the concrete InitiatingBinding[ECIDMeasurementInitiationRequest].
type ECIDMeasurementInitiationRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(ECIDMeasurementInitiationRequest, aper.DecodeState,

	) (ECIDMeasurementInitiationRequest, aper.Snapshot,

	)
	compare func(ECIDMeasurementInitiationRequest, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*ECIDMeasurementInitiationRequest,

		*aper.DecodeBudget) (s09.ValidationReport, error)
	encode func(*ECIDMeasurementInitiationRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (ECIDMeasurementInitiationRequest,

		error)
	inject func(ECIDMeasurementInitiationRequest,

	) InitiatingValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementInitiationRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementInitiationRequestInitiatingBinding) Codec() ECIDMeasurementInitiationRequestValueCodec {
	return ECIDMeasurementInitiationRequestValueCodec{path: aper.Path(b.info.Rule.Assignment.Assignment), decode: b.decode, encode: func(value ECIDMeasurementInitiationRequest,

		fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return b.encode(&value, fresh, budget)
	}, capture: b.capture, compare: b.compare, context: b.context,
	}
}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b ECIDMeasurementInitiationRequestInitiatingBinding) Build(body ECIDMeasurementInitiationRequest,

	transactionID s00.LPPATransactionID, options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ECIDMeasurementFailureIndicationInitiatingBinding is the concrete InitiatingBinding[ECIDMeasurementFailureIndication].
type ECIDMeasurementFailureIndicationInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s11.ECIDMeasurementFailureIndication, aper.DecodeState,

	) (s11.ECIDMeasurementFailureIndication, aper.Snapshot,

	)
	compare func(s11.ECIDMeasurementFailureIndication, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*s11.ECIDMeasurementFailureIndication,

		*aper.DecodeBudget) (s09.ValidationReport, error)
	encode func(*s11.ECIDMeasurementFailureIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s11.ECIDMeasurementFailureIndication,

		error)
	inject func(s11.ECIDMeasurementFailureIndication,

	) InitiatingValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementFailureIndicationInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementFailureIndicationInitiatingBinding) Codec() s11.ECIDMeasurementFailureIndicationValueCodec {
	return func() s11.ECIDMeasurementFailureIndicationValueCodec {
		sealed := s11.ECIDMeasurementFailureIndicationValueCodec{}
		*s11.BridgeECIDMeasurementFailureIndicationValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s11.BridgeECIDMeasurementFailureIndicationValueCodecFieldDecode(&sealed) = b.decode
		*s11.BridgeECIDMeasurementFailureIndicationValueCodecFieldEncode(&sealed) = func(value s11.ECIDMeasurementFailureIndication,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s11.BridgeECIDMeasurementFailureIndicationValueCodecFieldCapture(&sealed) = b.capture
		*s11.BridgeECIDMeasurementFailureIndicationValueCodecFieldCompare(&sealed) = b.compare
		*s11.BridgeECIDMeasurementFailureIndicationValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b ECIDMeasurementFailureIndicationInitiatingBinding) Build(body s11.ECIDMeasurementFailureIndication,

	transactionID s00.LPPATransactionID, options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ECIDMeasurementReportInitiatingBinding is the concrete InitiatingBinding[ECIDMeasurementReport].
type ECIDMeasurementReportInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s13.ECIDMeasurementReport, aper.DecodeState,

	) (s13.ECIDMeasurementReport, aper.Snapshot,

	)
	compare func(s13.ECIDMeasurementReport, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*s13.ECIDMeasurementReport,

		*aper.DecodeBudget) (s09.ValidationReport, error)
	encode func(*s13.ECIDMeasurementReport,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s13.ECIDMeasurementReport,

		error)
	inject func(s13.ECIDMeasurementReport,

	) InitiatingValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementReportInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementReportInitiatingBinding) Codec() s13.ECIDMeasurementReportValueCodec {
	return func() s13.ECIDMeasurementReportValueCodec {
		sealed := s13.ECIDMeasurementReportValueCodec{}
		*s13.BridgeECIDMeasurementReportValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s13.BridgeECIDMeasurementReportValueCodecFieldDecode(&sealed) = b.decode
		*s13.BridgeECIDMeasurementReportValueCodecFieldEncode(&sealed) = func(value s13.ECIDMeasurementReport,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s13.BridgeECIDMeasurementReportValueCodecFieldCapture(&sealed) = b.capture
		*s13.BridgeECIDMeasurementReportValueCodecFieldCompare(&sealed) = b.compare
		*s13.BridgeECIDMeasurementReportValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b ECIDMeasurementReportInitiatingBinding) Build(body s13.ECIDMeasurementReport,

	transactionID s00.LPPATransactionID, options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// ECIDMeasurementTerminationCommandInitiatingBinding is the concrete InitiatingBinding[ECIDMeasurementTerminationCommand].
type ECIDMeasurementTerminationCommandInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s06.ECIDMeasurementTerminationCommand, aper.DecodeState,

	) (s06.ECIDMeasurementTerminationCommand, aper.Snapshot,

	)
	compare func(s06.ECIDMeasurementTerminationCommand, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*s06.ECIDMeasurementTerminationCommand,

		*aper.DecodeBudget) (s09.ValidationReport, error)
	encode func(*s06.ECIDMeasurementTerminationCommand,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s06.ECIDMeasurementTerminationCommand,

		error)
	inject func(s06.ECIDMeasurementTerminationCommand,

	) InitiatingValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementTerminationCommandInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementTerminationCommandInitiatingBinding) Codec() s06.ECIDMeasurementTerminationCommandValueCodec {
	return func() s06.ECIDMeasurementTerminationCommandValueCodec {
		sealed := s06.ECIDMeasurementTerminationCommandValueCodec{}
		*s06.BridgeECIDMeasurementTerminationCommandValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s06.BridgeECIDMeasurementTerminationCommandValueCodecFieldDecode(&sealed) = b.decode
		*s06.BridgeECIDMeasurementTerminationCommandValueCodecFieldEncode(&sealed) = func(value s06.ECIDMeasurementTerminationCommand,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s06.BridgeECIDMeasurementTerminationCommandValueCodecFieldCapture(&sealed) = b.capture
		*s06.BridgeECIDMeasurementTerminationCommandValueCodecFieldCompare(&sealed) = b.compare
		*s06.BridgeECIDMeasurementTerminationCommandValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b ECIDMeasurementTerminationCommandInitiatingBinding) Build(body s06.ECIDMeasurementTerminationCommand,

	transactionID s00.LPPATransactionID, options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// OTDOAInformationRequestInitiatingBinding is the concrete InitiatingBinding[OTDOAInformationRequest].
type OTDOAInformationRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s18.OTDOAInformationRequest, aper.DecodeState,

	) (s18.OTDOAInformationRequest, aper.Snapshot,

	)
	compare func(s18.OTDOAInformationRequest, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*s18.OTDOAInformationRequest,

		*aper.DecodeBudget) (s09.ValidationReport, error)
	encode func(*s18.OTDOAInformationRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s18.OTDOAInformationRequest,

		error)
	inject func(s18.OTDOAInformationRequest,

	) InitiatingValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b OTDOAInformationRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b OTDOAInformationRequestInitiatingBinding) Codec() s18.OTDOAInformationRequestValueCodec {
	return func() s18.OTDOAInformationRequestValueCodec {
		sealed := s18.OTDOAInformationRequestValueCodec{}
		*s18.BridgeOTDOAInformationRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s18.BridgeOTDOAInformationRequestValueCodecFieldDecode(&sealed) = b.decode
		*s18.BridgeOTDOAInformationRequestValueCodecFieldEncode(&sealed) = func(value s18.OTDOAInformationRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s18.BridgeOTDOAInformationRequestValueCodecFieldCapture(&sealed) = b.capture
		*s18.BridgeOTDOAInformationRequestValueCodecFieldCompare(&sealed) = b.compare
		*s18.BridgeOTDOAInformationRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b OTDOAInformationRequestInitiatingBinding) Build(body s18.OTDOAInformationRequest,

	transactionID s00.LPPATransactionID, options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UTDOAInformationRequestInitiatingBinding is the concrete InitiatingBinding[UTDOAInformationRequest].
type UTDOAInformationRequestInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s16.UTDOAInformationRequest, aper.DecodeState,

	) (s16.UTDOAInformationRequest, aper.Snapshot,

	)
	compare func(s16.UTDOAInformationRequest, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*s16.UTDOAInformationRequest,

		*aper.DecodeBudget) (s09.ValidationReport, error)
	encode func(*s16.UTDOAInformationRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s16.UTDOAInformationRequest,

		error)
	inject func(s16.UTDOAInformationRequest,

	) InitiatingValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b UTDOAInformationRequestInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b UTDOAInformationRequestInitiatingBinding) Codec() s16.UTDOAInformationRequestValueCodec {
	return func() s16.UTDOAInformationRequestValueCodec {
		sealed := s16.UTDOAInformationRequestValueCodec{}
		*s16.BridgeUTDOAInformationRequestValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s16.BridgeUTDOAInformationRequestValueCodecFieldDecode(&sealed) = b.decode
		*s16.BridgeUTDOAInformationRequestValueCodecFieldEncode(&sealed) = func(value s16.UTDOAInformationRequest,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s16.BridgeUTDOAInformationRequestValueCodecFieldCapture(&sealed) = b.capture
		*s16.BridgeUTDOAInformationRequestValueCodecFieldCompare(&sealed) = b.compare
		*s16.BridgeUTDOAInformationRequestValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b UTDOAInformationRequestInitiatingBinding) Build(body s16.UTDOAInformationRequest,

	transactionID s00.LPPATransactionID, options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// UTDOAInformationUpdateInitiatingBinding is the concrete InitiatingBinding[UTDOAInformationUpdate].
type UTDOAInformationUpdateInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s17.UTDOAInformationUpdate, aper.DecodeState,

	) (s17.UTDOAInformationUpdate, aper.Snapshot,

	)
	compare func(s17.UTDOAInformationUpdate, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*s17.UTDOAInformationUpdate,

		*aper.DecodeBudget) (s09.ValidationReport, error)
	encode func(*s17.UTDOAInformationUpdate,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s17.UTDOAInformationUpdate,

		error)
	inject func(s17.UTDOAInformationUpdate,

	) InitiatingValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b UTDOAInformationUpdateInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b UTDOAInformationUpdateInitiatingBinding) Codec() s17.UTDOAInformationUpdateValueCodec {
	return func() s17.UTDOAInformationUpdateValueCodec {
		sealed := s17.UTDOAInformationUpdateValueCodec{}
		*s17.BridgeUTDOAInformationUpdateValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s17.BridgeUTDOAInformationUpdateValueCodecFieldDecode(&sealed) = b.decode
		*s17.BridgeUTDOAInformationUpdateValueCodecFieldEncode(&sealed) = func(value s17.UTDOAInformationUpdate,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s17.BridgeUTDOAInformationUpdateValueCodecFieldCapture(&sealed) = b.capture
		*s17.BridgeUTDOAInformationUpdateValueCodecFieldCompare(&sealed) = b.compare
		*s17.BridgeUTDOAInformationUpdateValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b UTDOAInformationUpdateInitiatingBinding) Build(body s17.UTDOAInformationUpdate,

	transactionID s00.LPPATransactionID, options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// AssistanceInformationControlInitiatingBinding is the concrete InitiatingBinding[AssistanceInformationControl].
type AssistanceInformationControlInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s15.AssistanceInformationControl, aper.DecodeState,

	) (s15.AssistanceInformationControl, aper.Snapshot,

	)
	compare func(s15.AssistanceInformationControl, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*s15.AssistanceInformationControl,

		*aper.DecodeBudget) (s09.ValidationReport, error)
	encode func(*s15.AssistanceInformationControl,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s15.AssistanceInformationControl,

		error)
	inject func(s15.AssistanceInformationControl,

	) InitiatingValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b AssistanceInformationControlInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b AssistanceInformationControlInitiatingBinding) Codec() s15.AssistanceInformationControlValueCodec {
	return func() s15.AssistanceInformationControlValueCodec {
		sealed := s15.AssistanceInformationControlValueCodec{}
		*s15.BridgeAssistanceInformationControlValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s15.BridgeAssistanceInformationControlValueCodecFieldDecode(&sealed) = b.decode
		*s15.BridgeAssistanceInformationControlValueCodecFieldEncode(&sealed) = func(value s15.AssistanceInformationControl,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s15.BridgeAssistanceInformationControlValueCodecFieldCapture(&sealed) = b.capture
		*s15.BridgeAssistanceInformationControlValueCodecFieldCompare(&sealed) = b.compare
		*s15.BridgeAssistanceInformationControlValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b AssistanceInformationControlInitiatingBinding) Build(body s15.AssistanceInformationControl,

	transactionID s00.LPPATransactionID, options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}

// AssistanceInformationFeedbackInitiatingBinding is the concrete InitiatingBinding[AssistanceInformationFeedback].
type AssistanceInformationFeedbackInitiatingBinding struct {
	context s00.BridgeCodecContext
	capture func(s17.AssistanceInformationFeedback, aper.DecodeState,

	) (s17.AssistanceInformationFeedback, aper.Snapshot,

	)
	compare func(s17.AssistanceInformationFeedback, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	info     s00.ProcedureInfo
	validate func(*s17.AssistanceInformationFeedback,

		*aper.DecodeBudget) (s09.ValidationReport, error)
	encode func(*s17.AssistanceInformationFeedback,

		bool, *aper.DecodeBudget) ([]byte, error)
	decode func([]byte, aper.DecodeState) (s17.AssistanceInformationFeedback,

		error)
	inject func(s17.AssistanceInformationFeedback,

	) InitiatingValue
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b AssistanceInformationFeedbackInitiatingBinding) Info() s00.ProcedureInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b AssistanceInformationFeedbackInitiatingBinding) Codec() s17.AssistanceInformationFeedbackValueCodec {
	return func() s17.AssistanceInformationFeedbackValueCodec {
		sealed := s17.AssistanceInformationFeedbackValueCodec{}
		*s17.BridgeAssistanceInformationFeedbackValueCodecFieldPath(&sealed) = aper.Path(b.info.Rule.Assignment.Assignment)
		*s17.BridgeAssistanceInformationFeedbackValueCodecFieldDecode(&sealed) = b.decode
		*s17.BridgeAssistanceInformationFeedbackValueCodecFieldEncode(&sealed) = func(value s17.AssistanceInformationFeedback,

			fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return b.encode(&value, fresh, budget)
		}
		*s17.BridgeAssistanceInformationFeedbackValueCodecFieldCapture(&sealed) = b.capture
		*s17.BridgeAssistanceInformationFeedbackValueCodecFieldCompare(&sealed) = b.compare
		*s17.BridgeAssistanceInformationFeedbackValueCodecFieldContext(&sealed) = b.context
		return sealed
	}()

}

// Build validates the body and constructs a procedure message with the supplied transaction identifier.
func (b AssistanceInformationFeedbackInitiatingBinding) Build(body s17.AssistanceInformationFeedback,

	transactionID s00.LPPATransactionID, options ...aper.BuildOption) (InitiatingMessage, error) {
	if b.validate == nil || b.encode == nil || b.inject == nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("%w: unbound procedure binding", aper.ErrInvalidValue), "Build")
	}
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	report, err := b.validate(&body, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return InitiatingMessage{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "Build")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return InitiatingMessage{}, aper.OperationError(&s09.BuildError{Issues: issues}, "Build")
	}
	_, err = b.encode(&body, false, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("initiatingMessage.value: %w", err), "Build")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), body); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "Build")
	}
	return InitiatingMessage{ProcedureCode: b.info.Code, Criticality: b.info.Criticality, LppatransactionID: transactionID, Value: b.inject(body)}, aper.OperationError(nil, "Build")
}
func BridgeECIDMeasurementInitiationRequestIEValueCaptureLPPaProtocolIEContainer(v *ECIDMeasurementInitiationRequestIEContainer, s *aper.SemanticCapture) {
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
func BridgeECIDMeasurementInitiationRequestIEValueCompareLPPaProtocolIEContainer(v *ECIDMeasurementInitiationRequestIEContainer, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
}

// ECIDMeasurementInitiationRequestMeasurementIDIEBinding binds MeasurementID to ProtocolIE-Field {{E-CIDMeasurementInitiationRequest-IEs}} of TS 36.455.
type ECIDMeasurementInitiationRequestMeasurementIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.MeasurementIDValueCodec
	inject func(s00.MeasurementID,

	) ECIDMeasurementInitiationRequestIEValue

	get func(*ECIDMeasurementInitiationRequestIEValue,

	) (*s00.MeasurementID,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementInitiationRequestMeasurementIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementInitiationRequestMeasurementIDIEBinding) Codec() s00.MeasurementIDValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementInitiationRequestMeasurementIDIEBinding) New(value s00.MeasurementID,

) (ECIDMeasurementInitiationRequestIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeMeasurementIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementInitiationRequestMeasurementIDIEBinding) Get(field *ECIDMeasurementInitiationRequestIEField) (*s00.MeasurementID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding binds ReportCharacteristics to ProtocolIE-Field {{E-CIDMeasurementInitiationRequest-IEs}} of TS 36.455.
type ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding struct {
	info   s00.FieldInfo
	codec  s01.ReportCharacteristicsValueCodec
	inject func(s00.ReportCharacteristics,

	) ECIDMeasurementInitiationRequestIEValue

	get func(*ECIDMeasurementInitiationRequestIEValue,

	) (*s00.ReportCharacteristics,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding) Codec() s01.ReportCharacteristicsValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding) New(value s00.ReportCharacteristics,

) (ECIDMeasurementInitiationRequestIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeReportCharacteristicsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding) Get(field *ECIDMeasurementInitiationRequestIEField) (*s00.ReportCharacteristics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding binds MeasurementPeriodicity to ProtocolIE-Field {{E-CIDMeasurementInitiationRequest-IEs}} of TS 36.455.
type ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding struct {
	info   s00.FieldInfo
	codec  s00.MeasurementPeriodicityValueCodec
	inject func(s00.MeasurementPeriodicity,

	) ECIDMeasurementInitiationRequestIEValue

	get func(*ECIDMeasurementInitiationRequestIEValue,

	) (*s00.MeasurementPeriodicity,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding) Codec() s00.MeasurementPeriodicityValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding) New(value s00.MeasurementPeriodicity,

) (ECIDMeasurementInitiationRequestIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeMeasurementPeriodicityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding) Get(field *ECIDMeasurementInitiationRequestIEField) (*s00.MeasurementPeriodicity,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding binds MeasurementQuantities to ProtocolIE-Field {{E-CIDMeasurementInitiationRequest-IEs}} of TS 36.455.
type ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s06.MeasurementQuantitiesConcreteValueCodec
	inject func(s06.MeasurementQuantities,

	) ECIDMeasurementInitiationRequestIEValue

	get func(*ECIDMeasurementInitiationRequestIEValue,

	) (*s06.MeasurementQuantities,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding) Codec() s06.MeasurementQuantitiesConcreteValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding) New(value s06.MeasurementQuantities,

) (ECIDMeasurementInitiationRequestIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s06.BridgeMeasurementQuantitiesConcreteValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding) Get(field *ECIDMeasurementInitiationRequestIEField) (*s06.MeasurementQuantities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding binds InterRATMeasurementQuantities to ProtocolIE-Field {{E-CIDMeasurementInitiationRequest-IEs}} of TS 36.455.
type ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s06.InterRATMeasurementQuantitiesConcreteValueCodec
	inject func(s06.InterRATMeasurementQuantities,

	) ECIDMeasurementInitiationRequestIEValue

	get func(*ECIDMeasurementInitiationRequestIEValue,

	) (*s06.InterRATMeasurementQuantities,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding) Codec() s06.InterRATMeasurementQuantitiesConcreteValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding) New(value s06.InterRATMeasurementQuantities,

) (ECIDMeasurementInitiationRequestIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s06.BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding) Get(field *ECIDMeasurementInitiationRequestIEField) (*s06.InterRATMeasurementQuantities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding binds WLANMeasurementQuantities to ProtocolIE-Field {{E-CIDMeasurementInitiationRequest-IEs}} of TS 36.455.
type ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s20.WLANMeasurementQuantitiesConcreteValueCodec
	inject func(s20.WLANMeasurementQuantities,

	) ECIDMeasurementInitiationRequestIEValue

	get func(*ECIDMeasurementInitiationRequestIEValue,

	) (*s20.WLANMeasurementQuantities,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding) Codec() s20.WLANMeasurementQuantitiesConcreteValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding) New(value s20.WLANMeasurementQuantities,

) (ECIDMeasurementInitiationRequestIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding) Get(field *ECIDMeasurementInitiationRequestIEField) (*s20.WLANMeasurementQuantities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationRequestValueCodec is the concrete ValueCodec[ECIDMeasurementInitiationRequest].
type ECIDMeasurementInitiationRequestValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ECIDMeasurementInitiationRequest, aper.DecodeState,

	) (ECIDMeasurementInitiationRequest, aper.Snapshot,

	)
	compare func(ECIDMeasurementInitiationRequest, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ECIDMeasurementInitiationRequest,

		error)
	encode func(ECIDMeasurementInitiationRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ECIDMeasurementInitiationRequestValueCodec) New(value ECIDMeasurementInitiationRequest,

) (ECIDMeasurementInitiationRequestAPERValue, error) {
	if c.encode == nil {
		return ECIDMeasurementInitiationRequestAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ECIDMeasurementInitiationRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ECIDMeasurementInitiationRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ECIDMeasurementInitiationRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ECIDMeasurementInitiationRequestAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ECIDMeasurementInitiationRequestAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ECIDMeasurementInitiationRequestAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ECIDMeasurementInitiationRequestAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ECIDMeasurementInitiationRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ECIDMeasurementInitiationRequestValueCodec) EncodeAPER(value ECIDMeasurementInitiationRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ECIDMeasurementInitiationRequestValueCodec) encodeBudget(value ECIDMeasurementInitiationRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ECIDMeasurementInitiationRequestValueCodec) encodeChanged(value ECIDMeasurementInitiationRequest,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// InitiatingMessageValueCodec is the concrete ValueCodec[InitiatingMessage].
type InitiatingMessageValueCodec struct {
	context s00.BridgeCodecContext
	capture func(InitiatingMessage, aper.DecodeState,

	) (InitiatingMessage, aper.Snapshot,

	)
	compare func(InitiatingMessage, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (InitiatingMessage,

		error)
	encode func(InitiatingMessage,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c InitiatingMessageValueCodec) New(value InitiatingMessage,

) (InitiatingMessageAPERValue, error) {
	if c.encode == nil {
		return InitiatingMessageAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitiatingMessageAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitiatingMessageAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return InitiatingMessageAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c InitiatingMessageValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitiatingMessageAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return InitiatingMessageAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return InitiatingMessageAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return InitiatingMessageAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return InitiatingMessageAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return InitiatingMessageAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c InitiatingMessageValueCodec) EncodeAPER(value InitiatingMessageAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c InitiatingMessageValueCodec) encodeBudget(value InitiatingMessage,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c InitiatingMessageValueCodec) encodeChanged(value InitiatingMessage,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeECIDMeasurementInitiationRequestIEValueValidateLPPaIEContainer(fields ECIDMeasurementInitiationRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
			}(), IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		aper.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row s00.FieldInfo
			related := []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s05.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.NotAllowed), RelatedRules: s05.BridgeLppaHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s05.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.MissingMandatory), row.Rule}})
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

// eCIDMeasurementInitiationRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[ECIDMeasurementInitiationRequestIEValue].
type ECIDMeasurementInitiationRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ECIDMeasurementInitiationRequestIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ECIDMeasurementInitiationRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeECIDMeasurementInitiationRequestIEValueCaptureLPPaProtocolIEField(v *ECIDMeasurementInitiationRequestIEField, s *aper.SemanticCapture) {
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
func BridgeECIDMeasurementInitiationRequestIEValueCompareLPPaProtocolIEField(v *ECIDMeasurementInitiationRequestIEField, s *aper.SemanticComparison) {
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

// wLANMeasurementQuantitiesItemIEValueProtocolOpenValue is the concrete protocolOpenValue[WLANMeasurementQuantitiesItemIEValue].
type WLANMeasurementQuantitiesItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s20.WLANMeasurementQuantitiesItemIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s20.WLANMeasurementQuantitiesItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// ECIDMeasurementInitiationRequestAPERValue is the concrete APERValue[ECIDMeasurementInitiationRequest].
type ECIDMeasurementInitiationRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   ECIDMeasurementInitiationRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ECIDMeasurementInitiationRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECIDMeasurementInitiationRequestAPERValue) WithoutReplay() ECIDMeasurementInitiationRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitiatingMessageAPERValue is the concrete APERValue[InitiatingMessage].
type InitiatingMessageAPERValue struct {
	context s00.BridgeCodecContext
	Value   InitiatingMessage

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v InitiatingMessageAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v InitiatingMessageAPERValue) WithoutReplay() InitiatingMessageAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MarshalAPERWLANMeasurementQuantities encodes a WLANMeasurementQuantities list to APER.
func BridgeMarshalAPERWLANMeasurementQuantities(list s20.WLANMeasurementQuantitiesComplete) ([]byte, error) {
	return s20.BridgeWLANMeasurementQuantitiesCompleteMethodMarshalAPERLegacy(&list)
}

// UnmarshalAPERWLANMeasurementQuantities decodes a WLANMeasurementQuantities list from APER.
func BridgeUnmarshalAPERWLANMeasurementQuantities(data []byte) (s20.WLANMeasurementQuantitiesComplete, error) {
	var value s20.WLANMeasurementQuantitiesComplete
	if err := s20.BridgeWLANMeasurementQuantitiesCompleteMethodUnmarshalAPERLegacy(&value, data); err != nil {
		return value, err
	}
	return value, nil
}

// MarshalAPERWLANMeasurementQuantities encodes a complete named list.
func MarshalAPERWLANMeasurementQuantities(v s20.WLANMeasurementQuantitiesComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERWLANMeasurementQuantities decodes a complete named list.
func UnmarshalAPERWLANMeasurementQuantities(data []byte, options ...aper.DecodeOption) (s20.WLANMeasurementQuantitiesComplete, aper.DecodeReport, error) {
	var v s20.WLANMeasurementQuantitiesComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// ECIDMeasurementInitiationRequest represents the ASN.1 type E-CIDMeasurementInitiationRequest (SEQUENCE).
type ECIDMeasurementInitiationRequest struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    aper.WireSpan
	ProtocolIEs      ECIDMeasurementInitiationRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                        `asn1:"-" json:"-"`
	extCount         int64                                       `asn1:"-" json:"-"`
	extPresent       []bool                                      `asn1:"-" json:"-"`
	extData          [][]byte                                    `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                           `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                      `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes ECIDMeasurementInitiationRequest to APER format.
func (v *ECIDMeasurementInitiationRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ECIDMeasurementInitiationRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s05.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
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

// UnmarshalAPER decodes ECIDMeasurementInitiationRequest from APER format.
func (v *ECIDMeasurementInitiationRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ECIDMeasurementInitiationRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ECIDMeasurementInitiationRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementInitiationRequest")
	}
	bb.EnterComponent("ECIDMeasurementInitiationRequest")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementInitiationRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "ECIDMeasurementInitiationRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementInitiationRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ECIDMeasurementInitiationRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementInitiationRequest{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(ECIDMeasurementInitiationRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ECIDMeasurementInitiationRequestIEField
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
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
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
func (v *ECIDMeasurementInitiationRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ECIDMeasurementInitiationRequest", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ECIDMeasurementInitiationRequest) WithoutReplay() ECIDMeasurementInitiationRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ECIDMeasurementInitiationRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ECIDMeasurementInitiationRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ECIDMeasurementInitiationRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ECIDMeasurementInitiationRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ECIDMeasurementInitiationRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ECIDMeasurementInitiationRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ECIDMeasurementInitiationRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ECIDMeasurementInitiationRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *ECIDMeasurementInitiationRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ECIDMeasurementInitiationRequest")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ECIDMeasurementInitiationRequest")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaECIDMeasurementInitiationRequest(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ECIDMeasurementInitiationRequest")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ECIDMeasurementInitiationRequest")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ECIDMeasurementInitiationRequest")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ECIDMeasurementInitiationRequest")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ECIDMeasurementInitiationRequest")
}
func (v *ECIDMeasurementInitiationRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ECIDMeasurementInitiationRequest) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ECIDMeasurementInitiationRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *ECIDMeasurementInitiationRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ECIDMeasurementInitiationRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ECIDMeasurementInitiationRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ECIDMeasurementInitiationRequest")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ECIDMeasurementInitiationRequest
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaECIDMeasurementInitiationRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ECIDMeasurementInitiationRequest{}
		return report, aper.OperationError(err, "ECIDMeasurementInitiationRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ECIDMeasurementInitiationRequest")
}

// InitiatingMessage represents the ASN.1 type InitiatingMessage (SEQUENCE).
type InitiatingMessage struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     aper.WireSpan
	ProcedureCode     s00.ProcedureCode     `asn1:"tag:0,context,implicit"`
	Criticality       s00.Criticality       `asn1:"tag:1,context,implicit"`
	LppatransactionID s00.LPPATransactionID `asn1:"tag:2,context,implicit"`
	Value             InitiatingValue       `asn1:"tag:3,context,explicit" asn1c:"raw-preserve"`
	perPadding        aper.CompletePadding  `asn1:"-" json:"-"`
}

// MarshalAPER encodes InitiatingMessage to APER format.
func (v *InitiatingMessage) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *InitiatingMessage) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		return runtime.WrapDecodePath(fmt.Errorf("%w: procedure code %d does not match its value selector", aper.ErrInvalidValue, v.ProcedureCode), "InitiatingMessage.ProcedureCode")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.ProcedureCode), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false); err != nil {
		return fmt.Errorf("encoding procedureCode: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.LppatransactionID), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(32767), false); err != nil {
		return fmt.Errorf("encoding lppatransactionID: %w", err)
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

// UnmarshalAPER decodes InitiatingMessage from APER format.
func (v *InitiatingMessage) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes InitiatingMessage with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *InitiatingMessage) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "InitiatingMessage")
	}
	bb.EnterComponent("InitiatingMessage")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InitiatingMessage")
	}
	padding, err := aper.CaptureFinalBits(bb, "InitiatingMessage")
	if err != nil {
		return runtime.WrapDecodePath(err, "InitiatingMessage")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *InitiatingMessage) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InitiatingMessage{}
	val_procedurecode, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProcedureCode")
	}
	v.ProcedureCode = s00.ProcedureCode(val_procedurecode)
	val_criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Criticality"})
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Criticality")
	}
	v.Criticality = s00.Criticality(val_criticality)
	val_lppatransactionid, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(32767), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "LppatransactionID")
	}
	v.LppatransactionID = s00.LPPATransactionID(val_lppatransactionid)
	toleranceMark_value := bb.EnterComponent("Value")
	opaque_value, err := aper.DecodeOpaqueOpenTypeAligned(bb, s00.InitiatingReason(v.ProcedureCode), aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "Initiating"}})
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	opaque_value = opaque_value.WithPath("InitiatingMessage.Value")
	decoded_value, err := BridgeDecodeInitiatingValue(v.ProcedureCode, opaque_value)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	v.Value = decoded_value
	bb.LeaveComponent(toleranceMark_value)
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *InitiatingMessage) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "InitiatingMessage", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InitiatingMessage) WithoutReplay() InitiatingMessage {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero InitiatingMessage
	v.perPadding = zero.perPadding
	return v
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *InitiatingMessage) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "InitiatingMessage")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "InitiatingMessage")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaInitiatingMessage(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "InitiatingMessage")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "InitiatingMessage")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "InitiatingMessage")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "InitiatingMessage")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "InitiatingMessage")
}
func (v *InitiatingMessage) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *InitiatingMessage) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *InitiatingMessage) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *InitiatingMessage) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *InitiatingMessage) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *InitiatingMessage) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "InitiatingMessage")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded InitiatingMessage
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaInitiatingMessage(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = InitiatingMessage{}
		return report, aper.OperationError(err, "InitiatingMessage")
	}
	*v = decoded
	return report, aper.OperationError(nil, "InitiatingMessage")
}

type InitiatingValue struct {
	code                                  s00.ProcedureCode
	withoutReplay                         bool
	received                              aper.WireSpan
	replay                                aper.Snapshot
	opaque                                *aper.OpaqueOpenType
	isOpaque                              bool
	bodyErrorIndication                   *s11.ErrorIndication
	bodyPrivateMessage                    *s12.PrivateMessage
	bodyECIDMeasurementInitiationRequest  *ECIDMeasurementInitiationRequest
	bodyECIDMeasurementFailureIndication  *s11.ECIDMeasurementFailureIndication
	bodyECIDMeasurementReport             *s13.ECIDMeasurementReport
	bodyECIDMeasurementTerminationCommand *s06.ECIDMeasurementTerminationCommand
	bodyOTDOAInformationRequest           *s18.OTDOAInformationRequest
	bodyUTDOAInformationRequest           *s16.UTDOAInformationRequest
	bodyUTDOAInformationUpdate            *s17.UTDOAInformationUpdate
	bodyAssistanceInformationControl      *s15.AssistanceInformationControl
	bodyAssistanceInformationFeedback     *s17.AssistanceInformationFeedback
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *InitiatingValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}

// AsErrorIndication returns the selected ErrorIndication value and reports whether that alternative is active.
func (v *InitiatingValue) AsErrorIndication() (*s11.ErrorIndication, bool) {
	if v == nil || v.code != s00.ProcedureCode(0) || v.bodyErrorIndication == nil {
		return nil, false
	}
	return v.bodyErrorIndication, true
}

// AsPrivateMessage returns the selected PrivateMessage value and reports whether that alternative is active.
func (v *InitiatingValue) AsPrivateMessage() (*s12.PrivateMessage, bool) {
	if v == nil || v.code != s00.ProcedureCode(1) || v.bodyPrivateMessage == nil {
		return nil, false
	}
	return v.bodyPrivateMessage, true
}

// AsECIDMeasurementInitiationRequest returns the selected ECIDMeasurementInitiationRequest value and reports whether that alternative is active.
func (v *InitiatingValue) AsECIDMeasurementInitiationRequest() (*ECIDMeasurementInitiationRequest, bool) {
	if v == nil || v.code != s00.ProcedureCode(2) || v.bodyECIDMeasurementInitiationRequest == nil {
		return nil, false
	}
	return v.bodyECIDMeasurementInitiationRequest, true
}

// AsECIDMeasurementFailureIndication returns the selected ECIDMeasurementFailureIndication value and reports whether that alternative is active.
func (v *InitiatingValue) AsECIDMeasurementFailureIndication() (*s11.ECIDMeasurementFailureIndication, bool) {
	if v == nil || v.code != s00.ProcedureCode(3) || v.bodyECIDMeasurementFailureIndication == nil {
		return nil, false
	}
	return v.bodyECIDMeasurementFailureIndication, true
}

// AsECIDMeasurementReport returns the selected ECIDMeasurementReport value and reports whether that alternative is active.
func (v *InitiatingValue) AsECIDMeasurementReport() (*s13.ECIDMeasurementReport, bool) {
	if v == nil || v.code != s00.ProcedureCode(4) || v.bodyECIDMeasurementReport == nil {
		return nil, false
	}
	return v.bodyECIDMeasurementReport, true
}

// AsECIDMeasurementTerminationCommand returns the selected ECIDMeasurementTerminationCommand value and reports whether that alternative is active.
func (v *InitiatingValue) AsECIDMeasurementTerminationCommand() (*s06.ECIDMeasurementTerminationCommand, bool) {
	if v == nil || v.code != s00.ProcedureCode(5) || v.bodyECIDMeasurementTerminationCommand == nil {
		return nil, false
	}
	return v.bodyECIDMeasurementTerminationCommand, true
}

// AsOTDOAInformationRequest returns the selected OTDOAInformationRequest value and reports whether that alternative is active.
func (v *InitiatingValue) AsOTDOAInformationRequest() (*s18.OTDOAInformationRequest, bool) {
	if v == nil || v.code != s00.ProcedureCode(6) || v.bodyOTDOAInformationRequest == nil {
		return nil, false
	}
	return v.bodyOTDOAInformationRequest, true
}

// AsUTDOAInformationRequest returns the selected UTDOAInformationRequest value and reports whether that alternative is active.
func (v *InitiatingValue) AsUTDOAInformationRequest() (*s16.UTDOAInformationRequest, bool) {
	if v == nil || v.code != s00.ProcedureCode(7) || v.bodyUTDOAInformationRequest == nil {
		return nil, false
	}
	return v.bodyUTDOAInformationRequest, true
}

// AsUTDOAInformationUpdate returns the selected UTDOAInformationUpdate value and reports whether that alternative is active.
func (v *InitiatingValue) AsUTDOAInformationUpdate() (*s17.UTDOAInformationUpdate, bool) {
	if v == nil || v.code != s00.ProcedureCode(8) || v.bodyUTDOAInformationUpdate == nil {
		return nil, false
	}
	return v.bodyUTDOAInformationUpdate, true
}

// AsAssistanceInformationControl returns the selected AssistanceInformationControl value and reports whether that alternative is active.
func (v *InitiatingValue) AsAssistanceInformationControl() (*s15.AssistanceInformationControl, bool) {
	if v == nil || v.code != s00.ProcedureCode(9) || v.bodyAssistanceInformationControl == nil {
		return nil, false
	}
	return v.bodyAssistanceInformationControl, true
}

// AsAssistanceInformationFeedback returns the selected AssistanceInformationFeedback value and reports whether that alternative is active.
func (v *InitiatingValue) AsAssistanceInformationFeedback() (*s17.AssistanceInformationFeedback, bool) {
	if v == nil || v.code != s00.ProcedureCode(10) || v.bodyAssistanceInformationFeedback == nil {
		return nil, false
	}
	return v.bodyAssistanceInformationFeedback, true
}
func BridgeDecodeInitiatingValue(code s00.ProcedureCode, raw aper.OpaqueOpenType) (InitiatingValue, error) {
	v := InitiatingValue{code: code}
	var scope *aper.BitBuffer
	switch code {
	case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10:
		scope = raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return v, err
		}
		defer scope.LeaveOpenType()
	}
	switch code {
	case s00.ProcedureCode(0):
		var body s11.ErrorIndication
		child := scope
		replayUsage := child.Usage()
		if err := s11.BridgeErrorIndicationMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.ErrorIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ErrorIndication")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s11.BridgeErrorIndicationFieldPerPadding(&body) = padding
		*s11.BridgeErrorIndicationFieldReceived(&body) = true
		raw.RetainContents(s11.BridgeErrorIndicationFieldReceivedBytes(&body))
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyErrorIndication = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case s00.ProcedureCode(1):
		var body s12.PrivateMessage
		child := scope
		replayUsage := child.Usage()
		if err := s12.BridgePrivateMessageMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.PrivateMessage:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PrivateMessage")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s12.BridgePrivateMessageFieldPerPadding(&body) = padding
		*s12.BridgePrivateMessageFieldReceived(&body) = true
		raw.RetainContents(s12.BridgePrivateMessageFieldReceivedBytes(&body))
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyPrivateMessage = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case s00.ProcedureCode(2):
		var body ECIDMeasurementInitiationRequest
		child := scope
		replayUsage := child.Usage()
		if err := body.unmarshalAPERFrom(child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.ECIDMeasurementInitiationRequest:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ECIDMeasurementInitiationRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyECIDMeasurementInitiationRequest = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case s00.ProcedureCode(3):
		var body s11.ECIDMeasurementFailureIndication
		child := scope
		replayUsage := child.Usage()
		if err := s11.BridgeECIDMeasurementFailureIndicationMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.ECIDMeasurementFailureIndication:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ECIDMeasurementFailureIndication")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s11.BridgeECIDMeasurementFailureIndicationFieldPerPadding(&body) = padding
		*s11.BridgeECIDMeasurementFailureIndicationFieldReceived(&body) = true
		raw.RetainContents(s11.BridgeECIDMeasurementFailureIndicationFieldReceivedBytes(&body))
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyECIDMeasurementFailureIndication = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case s00.ProcedureCode(4):
		var body s13.ECIDMeasurementReport
		child := scope
		replayUsage := child.Usage()
		if err := s13.BridgeECIDMeasurementReportMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.ECIDMeasurementReport:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ECIDMeasurementReport")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s13.BridgeECIDMeasurementReportFieldPerPadding(&body) = padding
		*s13.BridgeECIDMeasurementReportFieldReceived(&body) = true
		raw.RetainContents(s13.BridgeECIDMeasurementReportFieldReceivedBytes(&body))
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyECIDMeasurementReport = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case s00.ProcedureCode(5):
		var body s06.ECIDMeasurementTerminationCommand
		child := scope
		replayUsage := child.Usage()
		if err := s06.BridgeECIDMeasurementTerminationCommandMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.ECIDMeasurementTerminationCommand:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ECIDMeasurementTerminationCommand")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s06.BridgeECIDMeasurementTerminationCommandFieldPerPadding(&body) = padding
		*s06.BridgeECIDMeasurementTerminationCommandFieldReceived(&body) = true
		raw.RetainContents(s06.BridgeECIDMeasurementTerminationCommandFieldReceivedBytes(&body))
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyECIDMeasurementTerminationCommand = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case s00.ProcedureCode(6):
		var body s18.OTDOAInformationRequest
		child := scope
		replayUsage := child.Usage()
		if err := s18.BridgeOTDOAInformationRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.OTDOAInformationRequest:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "OTDOAInformationRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s18.BridgeOTDOAInformationRequestFieldPerPadding(&body) = padding
		*s18.BridgeOTDOAInformationRequestFieldReceived(&body) = true
		raw.RetainContents(s18.BridgeOTDOAInformationRequestFieldReceivedBytes(&body))
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyOTDOAInformationRequest = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case s00.ProcedureCode(7):
		var body s16.UTDOAInformationRequest
		child := scope
		replayUsage := child.Usage()
		if err := s16.BridgeUTDOAInformationRequestMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.UTDOAInformationRequest:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UTDOAInformationRequest")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s16.BridgeUTDOAInformationRequestFieldPerPadding(&body) = padding
		*s16.BridgeUTDOAInformationRequestFieldReceived(&body) = true
		raw.RetainContents(s16.BridgeUTDOAInformationRequestFieldReceivedBytes(&body))
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyUTDOAInformationRequest = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case s00.ProcedureCode(8):
		var body s17.UTDOAInformationUpdate
		child := scope
		replayUsage := child.Usage()
		if err := s17.BridgeUTDOAInformationUpdateMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.UTDOAInformationUpdate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UTDOAInformationUpdate")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s17.BridgeUTDOAInformationUpdateFieldPerPadding(&body) = padding
		*s17.BridgeUTDOAInformationUpdateFieldReceived(&body) = true
		raw.RetainContents(s17.BridgeUTDOAInformationUpdateFieldReceivedBytes(&body))
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyUTDOAInformationUpdate = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case s00.ProcedureCode(9):
		var body s15.AssistanceInformationControl
		child := scope
		replayUsage := child.Usage()
		if err := s15.BridgeAssistanceInformationControlMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.AssistanceInformationControl:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "AssistanceInformationControl")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s15.BridgeAssistanceInformationControlFieldPerPadding(&body) = padding
		*s15.BridgeAssistanceInformationControlFieldReceived(&body) = true
		raw.RetainContents(s15.BridgeAssistanceInformationControlFieldReceivedBytes(&body))
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyAssistanceInformationControl = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case s00.ProcedureCode(10):
		var body s17.AssistanceInformationFeedback
		child := scope
		replayUsage := child.Usage()
		if err := s17.BridgeAssistanceInformationFeedbackMethodUnmarshalAPERFrom(&body, child); err != nil {
			return InitiatingValue{}, fmt.Errorf("%s %w", "InitiatingMessage.value.AssistanceInformationFeedback:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "AssistanceInformationFeedback")
		if err != nil {
			return InitiatingValue{}, err
		}
		*s17.BridgeAssistanceInformationFeedbackFieldPerPadding(&body) = padding
		*s17.BridgeAssistanceInformationFeedbackFieldReceived(&body) = true
		raw.RetainContents(s17.BridgeAssistanceInformationFeedbackFieldReceivedBytes(&body))
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyAssistanceInformationFeedback = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	default:
		if err := raw.Observe(aper.UnknownProcedure); err != nil {
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
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v InitiatingValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := aper.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, aper.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.code {
	case s00.ProcedureCode(0):
		if v.bodyErrorIndication == nil {
			return nil, fmt.Errorf("%s value: missing ErrorIndication", "Initiating")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return s11.BridgeErrorIndicationMethodMarshalAPERBudget(v.bodyErrorIndication, budget, fresh)
	case s00.ProcedureCode(1):
		if v.bodyPrivateMessage == nil {
			return nil, fmt.Errorf("%s value: missing PrivateMessage", "Initiating")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return s12.BridgePrivateMessageMethodMarshalAPERBudget(v.bodyPrivateMessage, budget, fresh)
	case s00.ProcedureCode(2):
		if v.bodyECIDMeasurementInitiationRequest == nil {
			return nil, fmt.Errorf("%s value: missing ECIDMeasurementInitiationRequest", "Initiating")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return v.bodyECIDMeasurementInitiationRequest.marshalAPERBudget(budget, fresh)
	case s00.ProcedureCode(3):
		if v.bodyECIDMeasurementFailureIndication == nil {
			return nil, fmt.Errorf("%s value: missing ECIDMeasurementFailureIndication", "Initiating")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return s11.BridgeECIDMeasurementFailureIndicationMethodMarshalAPERBudget(v.bodyECIDMeasurementFailureIndication, budget, fresh)
	case s00.ProcedureCode(4):
		if v.bodyECIDMeasurementReport == nil {
			return nil, fmt.Errorf("%s value: missing ECIDMeasurementReport", "Initiating")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return s13.BridgeECIDMeasurementReportMethodMarshalAPERBudget(v.bodyECIDMeasurementReport, budget, fresh)
	case s00.ProcedureCode(5):
		if v.bodyECIDMeasurementTerminationCommand == nil {
			return nil, fmt.Errorf("%s value: missing ECIDMeasurementTerminationCommand", "Initiating")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return s06.BridgeECIDMeasurementTerminationCommandMethodMarshalAPERBudget(v.bodyECIDMeasurementTerminationCommand, budget, fresh)
	case s00.ProcedureCode(6):
		if v.bodyOTDOAInformationRequest == nil {
			return nil, fmt.Errorf("%s value: missing OTDOAInformationRequest", "Initiating")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return s18.BridgeOTDOAInformationRequestMethodMarshalAPERBudget(v.bodyOTDOAInformationRequest, budget, fresh)
	case s00.ProcedureCode(7):
		if v.bodyUTDOAInformationRequest == nil {
			return nil, fmt.Errorf("%s value: missing UTDOAInformationRequest", "Initiating")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return s16.BridgeUTDOAInformationRequestMethodMarshalAPERBudget(v.bodyUTDOAInformationRequest, budget, fresh)
	case s00.ProcedureCode(8):
		if v.bodyUTDOAInformationUpdate == nil {
			return nil, fmt.Errorf("%s value: missing UTDOAInformationUpdate", "Initiating")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return s17.BridgeUTDOAInformationUpdateMethodMarshalAPERBudget(v.bodyUTDOAInformationUpdate, budget, fresh)
	case s00.ProcedureCode(9):
		if v.bodyAssistanceInformationControl == nil {
			return nil, fmt.Errorf("%s value: missing AssistanceInformationControl", "Initiating")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return s15.BridgeAssistanceInformationControlMethodMarshalAPERBudget(v.bodyAssistanceInformationControl, budget, fresh)
	case s00.ProcedureCode(10):
		if v.bodyAssistanceInformationFeedback == nil {
			return nil, fmt.Errorf("%s value: missing AssistanceInformationFeedback", "Initiating")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return s17.BridgeAssistanceInformationFeedbackMethodMarshalAPERBudget(v.bodyAssistanceInformationFeedback, budget, fresh)
	default:
		return nil, fmt.Errorf("%s value: unknown code %d without opaque content", "Initiating", v.code)
	}
}
func NewOpaqueInitiatingMessage(code s00.ProcedureCode, criticality s00.Criticality, transactionID s00.LPPATransactionID, data []byte) (InitiatingMessage, error) {
	if err := s00.BridgeCheckLPPaTransactionID(transactionID); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "OpaqueInitiatingMessage")
	}
	switch code {
	case s00.ProcedureCode(0):
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-errorIndication requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(1):
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-privateMessage requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(2):
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-e-CIDMeasurementInitiation requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(3):
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-e-CIDMeasurementFailureIndication requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(4):
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-e-CIDMeasurementReport requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(5):
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-e-CIDMeasurementTermination requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(6):
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-oTDOAInformationExchange requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(7):
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-uTDOAInformationExchange requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(8):
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-uTDOAInformationUpdate requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(9):
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-assistanceInformationControl requires its typed binding"), "OpaqueInitiatingMessage")
	case s00.ProcedureCode(10):
		return InitiatingMessage{}, aper.OperationError(fmt.Errorf("known Initiating procedure id-assistanceInformationFeedback requires its typed binding"), "OpaqueInitiatingMessage")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "OpaqueInitiatingMessage")
	}
	opaque, err := aper.BuildOpaqueOpenType(data, budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "OpaqueInitiatingMessage")
	}
	retained, err := opaque.Retained(budget)
	if err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "OpaqueInitiatingMessage")
	}
	message := InitiatingMessage{ProcedureCode: code, Criticality: criticality, LppatransactionID: transactionID, Value: InitiatingValue{code: code, opaque: retained, isOpaque: true}}
	if _, err := message.marshalAPERBudget(budget, false); err != nil {
		return InitiatingMessage{}, aper.OperationError(err, "OpaqueInitiatingMessage")
	}
	return message, aper.OperationError(nil, "OpaqueInitiatingMessage")
}
func BridgeCaptureLPPaECIDMeasurementInitiationRequest(v *ECIDMeasurementInitiationRequest, s *aper.SemanticCapture) {
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
func BridgeCompareLPPaECIDMeasurementInitiationRequest(v *ECIDMeasurementInitiationRequest, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeECIDMeasurementInitiationRequestIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaECIDMeasurementInitiationRequestIEValue(v *ECIDMeasurementInitiationRequestIEValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
		switch v.id {
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowESMLCUEMeasurementID == nil)
				if v.rowESMLCUEMeasurementID != nil {
					s00.BridgeCaptureLPPaMeasurementID(v.rowESMLCUEMeasurementID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(3):
			{
				f := s.Begin()
				s.Bool(v.rowReportCharacteristics == nil)
				if v.rowReportCharacteristics != nil {
					s00.BridgeCaptureLPPaReportCharacteristics(v.rowReportCharacteristics, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(4):
			{
				f := s.Begin()
				s.Bool(v.rowMeasurementPeriodicity == nil)
				if v.rowMeasurementPeriodicity != nil {
					s00.BridgeCaptureLPPaMeasurementPeriodicity(v.rowMeasurementPeriodicity, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(5):
			{
				f := s.Begin()
				s.Bool(v.rowMeasurementQuantities == nil)
				if v.rowMeasurementQuantities != nil {
					s11.BridgeCaptureLPPaMeasurementQuantities(v.rowMeasurementQuantities, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(15):
			{
				f := s.Begin()
				s.Bool(v.rowInterRATMeasurementQuantities == nil)
				if v.rowInterRATMeasurementQuantities != nil {
					s11.BridgeCaptureLPPaInterRATMeasurementQuantities(v.rowInterRATMeasurementQuantities, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(19):
			{
				f := s.Begin()
				s.Bool(v.rowWLANMeasurementQuantities == nil)
				if v.rowWLANMeasurementQuantities != nil {
					s20.BridgeCaptureLPPaWLANMeasurementQuantities(v.rowWLANMeasurementQuantities, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ECIDMeasurementInitiationRequestIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v ECIDMeasurementInitiationRequestIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ECIDMeasurementInitiationRequestIEValue) captureSemantics(s aper.SemanticCapture) ECIDMeasurementInitiationRequestIEValue {
	BridgeCaptureLPPaECIDMeasurementInitiationRequestIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaECIDMeasurementInitiationRequestIEValue(v *ECIDMeasurementInitiationRequestIEValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowESMLCUEMeasurementID == nil)
				if v.rowESMLCUEMeasurementID != nil {
					s02.BridgeCompareLPPaMeasurementID(v.rowESMLCUEMeasurementID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(3):
			{
				f := s.Begin()
				s.Bool(v.rowReportCharacteristics == nil)
				if v.rowReportCharacteristics != nil {
					s03.BridgeCompareLPPaReportCharacteristics(v.rowReportCharacteristics, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(4):
			{
				f := s.Begin()
				s.Bool(v.rowMeasurementPeriodicity == nil)
				if v.rowMeasurementPeriodicity != nil {
					s02.BridgeCompareLPPaMeasurementPeriodicity(v.rowMeasurementPeriodicity, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(5):
			{
				f := s.Begin()
				s.Bool(v.rowMeasurementQuantities == nil)
				if v.rowMeasurementQuantities != nil {
					s11.BridgeCompareLPPaMeasurementQuantities(v.rowMeasurementQuantities, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(15):
			{
				f := s.Begin()
				s.Bool(v.rowInterRATMeasurementQuantities == nil)
				if v.rowInterRATMeasurementQuantities != nil {
					s11.BridgeCompareLPPaInterRATMeasurementQuantities(v.rowInterRATMeasurementQuantities, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(19):
			{
				f := s.Begin()
				s.Bool(v.rowWLANMeasurementQuantities == nil)
				if v.rowWLANMeasurementQuantities != nil {
					s20.BridgeCompareLPPaWLANMeasurementQuantities(v.rowWLANMeasurementQuantities, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v ECIDMeasurementInitiationRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaECIDMeasurementInitiationRequestIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECIDMeasurementInitiationRequestIEValue) WithoutReplay() ECIDMeasurementInitiationRequestIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaInitiatingMessage(v *InitiatingMessage, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaProcedureCode(&v.ProcedureCode, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s00.BridgeCaptureLPPaLPPATransactionID(&v.LppatransactionID, s)
	s.OpenBytes(v.Value.captureFraming())
	BridgeCaptureLPPaInitiatingValue(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaInitiatingMessage(v *InitiatingMessage, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProcedureCode(&v.ProcedureCode, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)
	s02.BridgeCompareLPPaLPPATransactionID(&v.LppatransactionID, s)
	BridgeCompareLPPaInitiatingValue(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaInitiatingValue(v *InitiatingValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProcedureCode(&v.code, s)
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
		case s00.ProcedureCode(0):
			{
				f := s.Begin()
				s.Bool(v.bodyErrorIndication == nil)
				if v.bodyErrorIndication != nil {
					s11.BridgeCaptureLPPaErrorIndication(v.bodyErrorIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(1):
			{
				f := s.Begin()
				s.Bool(v.bodyPrivateMessage == nil)
				if v.bodyPrivateMessage != nil {
					s12.BridgeCaptureLPPaPrivateMessage(v.bodyPrivateMessage, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(2):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementInitiationRequest == nil)
				if v.bodyECIDMeasurementInitiationRequest != nil {
					BridgeCaptureLPPaECIDMeasurementInitiationRequest(v.bodyECIDMeasurementInitiationRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(3):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementFailureIndication == nil)
				if v.bodyECIDMeasurementFailureIndication != nil {
					s11.BridgeCaptureLPPaECIDMeasurementFailureIndication(v.bodyECIDMeasurementFailureIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(4):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementReport == nil)
				if v.bodyECIDMeasurementReport != nil {
					s13.BridgeCaptureLPPaECIDMeasurementReport(v.bodyECIDMeasurementReport, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(5):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementTerminationCommand == nil)
				if v.bodyECIDMeasurementTerminationCommand != nil {
					s06.BridgeCaptureLPPaECIDMeasurementTerminationCommand(v.bodyECIDMeasurementTerminationCommand, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyOTDOAInformationRequest == nil)
				if v.bodyOTDOAInformationRequest != nil {
					s18.BridgeCaptureLPPaOTDOAInformationRequest(v.bodyOTDOAInformationRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(7):
			{
				f := s.Begin()
				s.Bool(v.bodyUTDOAInformationRequest == nil)
				if v.bodyUTDOAInformationRequest != nil {
					s16.BridgeCaptureLPPaUTDOAInformationRequest(v.bodyUTDOAInformationRequest, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(8):
			{
				f := s.Begin()
				s.Bool(v.bodyUTDOAInformationUpdate == nil)
				if v.bodyUTDOAInformationUpdate != nil {
					s17.BridgeCaptureLPPaUTDOAInformationUpdate(v.bodyUTDOAInformationUpdate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(9):
			{
				f := s.Begin()
				s.Bool(v.bodyAssistanceInformationControl == nil)
				if v.bodyAssistanceInformationControl != nil {
					s15.BridgeCaptureLPPaAssistanceInformationControl(v.bodyAssistanceInformationControl, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(10):
			{
				f := s.Begin()
				s.Bool(v.bodyAssistanceInformationFeedback == nil)
				if v.bodyAssistanceInformationFeedback != nil {
					s17.BridgeCaptureLPPaAssistanceInformationFeedback(v.bodyAssistanceInformationFeedback, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v InitiatingValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v InitiatingValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v InitiatingValue) captureSemantics(s aper.SemanticCapture) InitiatingValue {
	BridgeCaptureLPPaInitiatingValue(&v, &s)
	return v
}
func BridgeCompareLPPaInitiatingValue(v *InitiatingValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProcedureCode(&v.code, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.code {
		case s00.ProcedureCode(0):
			{
				f := s.Begin()
				s.Bool(v.bodyErrorIndication == nil)
				if v.bodyErrorIndication != nil {
					s11.BridgeCompareLPPaErrorIndication(v.bodyErrorIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(1):
			{
				f := s.Begin()
				s.Bool(v.bodyPrivateMessage == nil)
				if v.bodyPrivateMessage != nil {
					s12.BridgeCompareLPPaPrivateMessage(v.bodyPrivateMessage, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(2):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementInitiationRequest == nil)
				if v.bodyECIDMeasurementInitiationRequest != nil {
					BridgeCompareLPPaECIDMeasurementInitiationRequest(v.bodyECIDMeasurementInitiationRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(3):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementFailureIndication == nil)
				if v.bodyECIDMeasurementFailureIndication != nil {
					s11.BridgeCompareLPPaECIDMeasurementFailureIndication(v.bodyECIDMeasurementFailureIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(4):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementReport == nil)
				if v.bodyECIDMeasurementReport != nil {
					s13.BridgeCompareLPPaECIDMeasurementReport(v.bodyECIDMeasurementReport, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(5):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementTerminationCommand == nil)
				if v.bodyECIDMeasurementTerminationCommand != nil {
					s06.BridgeCompareLPPaECIDMeasurementTerminationCommand(v.bodyECIDMeasurementTerminationCommand, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyOTDOAInformationRequest == nil)
				if v.bodyOTDOAInformationRequest != nil {
					s18.BridgeCompareLPPaOTDOAInformationRequest(v.bodyOTDOAInformationRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(7):
			{
				f := s.Begin()
				s.Bool(v.bodyUTDOAInformationRequest == nil)
				if v.bodyUTDOAInformationRequest != nil {
					s16.BridgeCompareLPPaUTDOAInformationRequest(v.bodyUTDOAInformationRequest, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(8):
			{
				f := s.Begin()
				s.Bool(v.bodyUTDOAInformationUpdate == nil)
				if v.bodyUTDOAInformationUpdate != nil {
					s17.BridgeCompareLPPaUTDOAInformationUpdate(v.bodyUTDOAInformationUpdate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(9):
			{
				f := s.Begin()
				s.Bool(v.bodyAssistanceInformationControl == nil)
				if v.bodyAssistanceInformationControl != nil {
					s15.BridgeCompareLPPaAssistanceInformationControl(v.bodyAssistanceInformationControl, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(10):
			{
				f := s.Begin()
				s.Bool(v.bodyAssistanceInformationFeedback == nil)
				if v.bodyAssistanceInformationFeedback != nil {
					s17.BridgeCompareLPPaAssistanceInformationFeedback(v.bodyAssistanceInformationFeedback, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v InitiatingValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaInitiatingValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v InitiatingValue) WithoutReplay() InitiatingValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}

type ECIDMeasurementInitiationRequestIEValue struct {
	id                               s00.ProtocolIEID
	withoutReplay                    bool
	received                         aper.WireSpan
	replay                           aper.Snapshot
	opaque                           *aper.OpaqueOpenType
	isOpaque                         bool
	rowESMLCUEMeasurementID          *s00.MeasurementID
	rowReportCharacteristics         *s00.ReportCharacteristics
	rowMeasurementPeriodicity        *s00.MeasurementPeriodicity
	rowMeasurementQuantities         *s06.MeasurementQuantities
	rowInterRATMeasurementQuantities *s06.InterRATMeasurementQuantities
	rowWLANMeasurementQuantities     *s20.WLANMeasurementQuantities
}

func (v ECIDMeasurementInitiationRequestIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case s00.ProtocolIEID(2):
		return v.rowESMLCUEMeasurementID != nil
	case s00.ProtocolIEID(3):
		return v.rowReportCharacteristics != nil
	case s00.ProtocolIEID(4):
		return v.rowMeasurementPeriodicity != nil
	case s00.ProtocolIEID(5):
		return v.rowMeasurementQuantities != nil
	case s00.ProtocolIEID(15):
		return v.rowInterRATMeasurementQuantities != nil
	case s00.ProtocolIEID(19):
		return v.rowWLANMeasurementQuantities != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *ECIDMeasurementInitiationRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ECIDMeasurementInitiationRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationRequest-IEs"}}
}
func (ECIDMeasurementInitiationRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(3):
		return aper.UnknownSelector
	case s00.ProtocolIEID(4):
		return aper.UnknownSelector
	case s00.ProtocolIEID(5):
		return aper.UnknownSelector
	case s00.ProtocolIEID(15):
		return aper.UnknownSelector
	case s00.ProtocolIEID(19):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(6):
		return aper.NotInTable
	case s00.ProtocolIEID(7):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(9):
		return aper.NotInTable
	case s00.ProtocolIEID(10):
		return aper.NotInTable
	case s00.ProtocolIEID(11):
		return aper.NotInTable
	case s00.ProtocolIEID(12):
		return aper.NotInTable
	case s00.ProtocolIEID(13):
		return aper.NotInTable
	case s00.ProtocolIEID(14):
		return aper.NotInTable
	case s00.ProtocolIEID(16):
		return aper.NotInTable
	case s00.ProtocolIEID(17):
		return aper.NotInTable
	case s00.ProtocolIEID(18):
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
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}

// AsESMLCUEMeasurementID returns the selected ESMLCUEMeasurementID value and reports whether that alternative is active.
func (v *ECIDMeasurementInitiationRequestIEValue) AsESMLCUEMeasurementID() (*s00.MeasurementID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowESMLCUEMeasurementID == nil {
		return nil, false
	}
	return v.rowESMLCUEMeasurementID, true
}

// AsReportCharacteristics returns the selected ReportCharacteristics value and reports whether that alternative is active.
func (v *ECIDMeasurementInitiationRequestIEValue) AsReportCharacteristics() (*s00.ReportCharacteristics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(3) || v.rowReportCharacteristics == nil {
		return nil, false
	}
	return v.rowReportCharacteristics, true
}

// AsMeasurementPeriodicity returns the selected MeasurementPeriodicity value and reports whether that alternative is active.
func (v *ECIDMeasurementInitiationRequestIEValue) AsMeasurementPeriodicity() (*s00.MeasurementPeriodicity, bool) {
	if v == nil || v.id != s00.ProtocolIEID(4) || v.rowMeasurementPeriodicity == nil {
		return nil, false
	}
	return v.rowMeasurementPeriodicity, true
}

// AsMeasurementQuantities returns the selected MeasurementQuantities value and reports whether that alternative is active.
func (v *ECIDMeasurementInitiationRequestIEValue) AsMeasurementQuantities() (*s06.MeasurementQuantities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(5) || v.rowMeasurementQuantities == nil {
		return nil, false
	}
	return v.rowMeasurementQuantities, true
}

// AsInterRATMeasurementQuantities returns the selected InterRATMeasurementQuantities value and reports whether that alternative is active.
func (v *ECIDMeasurementInitiationRequestIEValue) AsInterRATMeasurementQuantities() (*s06.InterRATMeasurementQuantities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(15) || v.rowInterRATMeasurementQuantities == nil {
		return nil, false
	}
	return v.rowInterRATMeasurementQuantities, true
}

// AsWLANMeasurementQuantities returns the selected WLANMeasurementQuantities value and reports whether that alternative is active.
func (v *ECIDMeasurementInitiationRequestIEValue) AsWLANMeasurementQuantities() (*s20.WLANMeasurementQuantities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(19) || v.rowWLANMeasurementQuantities == nil {
		return nil, false
	}
	return v.rowWLANMeasurementQuantities, true
}
func (v ECIDMeasurementInitiationRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ECIDMeasurementInitiationRequestIEValue, error) {
	out := ECIDMeasurementInitiationRequestIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 2, 3, 4, 5, 15, 19:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case s00.ProtocolIEID(2):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound2, s00.BridgeAsn1IntegerBound7, true)
		value := s00.MeasurementID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ESMLCUEMeasurementID:", err)
		}
		if _, err := aper.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowESMLCUEMeasurementID = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case s00.ProtocolIEID(3):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "ReportCharacteristics"})
		value := s00.ReportCharacteristics(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ReportCharacteristics:", err)
		}
		if _, err := aper.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		out.rowReportCharacteristics = (*s00.ReportCharacteristics)(scope.OwnInt64(int64(value)))
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case s00.ProtocolIEID(4):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := aper.DecodeEnumeratedAligned(bb, 13, true, aper.EnumerationSource{KnownExtensions: 0, Path: "MeasurementPeriodicity"})
		value := s00.MeasurementPeriodicity(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "MeasurementPeriodicity:", err)
		}
		if _, err := aper.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		out.rowMeasurementPeriodicity = (*s00.MeasurementPeriodicity)(scope.OwnInt64(int64(value)))
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case s00.ProtocolIEID(5):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := s18.BridgeUnmarshalAPERMeasurementQuantitiesFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "MeasurementQuantities:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := func() s18.MeasurementQuantitiesComplete {
			sealed := s18.MeasurementQuantitiesComplete{Value: list}
			*s18.BridgeMeasurementQuantitiesCompleteFieldPerPadding(&sealed) = padding
			return sealed
		}()
		value := complete.Value
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowMeasurementQuantities = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case s00.ProtocolIEID(15):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := s17.BridgeUnmarshalAPERInterRATMeasurementQuantitiesFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "InterRATMeasurementQuantities:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := func() s17.InterRATMeasurementQuantitiesComplete {
			sealed := s17.InterRATMeasurementQuantitiesComplete{Value: list}
			*s17.BridgeInterRATMeasurementQuantitiesCompleteFieldPerPadding(&sealed) = padding
			return sealed
		}()
		value := complete.Value
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowInterRATMeasurementQuantities = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case s00.ProtocolIEID(19):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := s20.BridgeUnmarshalAPERWLANMeasurementQuantitiesFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "WLANMeasurementQuantities:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := func() s20.WLANMeasurementQuantitiesComplete {
			sealed := s20.WLANMeasurementQuantitiesComplete{Value: list}
			*s20.BridgeWLANMeasurementQuantitiesCompleteFieldPerPadding(&sealed) = padding
			return sealed
		}()
		value := complete.Value
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowWLANMeasurementQuantities = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return out, err
		}
		out.opaque = retained
		out.isOpaque = true
	}
	return out, nil
}
func (v ECIDMeasurementInitiationRequestIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ECIDMeasurementInitiationRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := aper.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, aper.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	case s00.ProtocolIEID(2):
		if v.rowESMLCUEMeasurementID == nil {
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementInitiationRequest-IEs.id-E-SMLC-UE-Measurement-ID:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerBigBoundsAligned(encodeBB, *v.rowESMLCUEMeasurementID, s00.BridgeAsn1IntegerBound2, s00.BridgeAsn1IntegerBound7, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(3):
		if v.rowReportCharacteristics == nil {
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementInitiationRequest-IEs.id-ReportCharacteristics:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowReportCharacteristics), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(4):
		if v.rowMeasurementPeriodicity == nil {
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementInitiationRequest-IEs.id-MeasurementPeriodicity:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowMeasurementPeriodicity), 13, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(5):
		if v.rowMeasurementQuantities == nil {
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementInitiationRequest-IEs.id-MeasurementQuantities:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		complete := s18.MeasurementQuantitiesComplete{Value: *v.rowMeasurementQuantities}
		candidate, err := s18.BridgeMeasurementQuantitiesCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(15):
		if v.rowInterRATMeasurementQuantities == nil {
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementInitiationRequest-IEs.id-InterRATMeasurementQuantities:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		complete := s17.InterRATMeasurementQuantitiesComplete{Value: *v.rowInterRATMeasurementQuantities}
		candidate, err := s17.BridgeInterRATMeasurementQuantitiesCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(19):
		if v.rowWLANMeasurementQuantities == nil {
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementInitiationRequest-IEs.id-WLANMeasurementQuantities:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		complete := s20.WLANMeasurementQuantitiesComplete{Value: *v.rowWLANMeasurementQuantities}
		candidate, err := s20.BridgeWLANMeasurementQuantitiesCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ECIDMeasurementInitiationRequestIEValue:", v.id)
	}
}

type PrivateMessageDescriptor struct{}

func PrivateMessageProcedure() PrivateMessageDescriptor { return PrivateMessageDescriptor{} }

// Info returns the source-derived metadata for this descriptor or binding.
func (PrivateMessageDescriptor) Info() s00.ProcedureInfo {
	return s00.ProcedureInfo{Code: s00.ProcedureCode(1), Criticality: s00.CriticalityIgnore, HasSuccessfulOutcome: false, HasUnsuccessfulOutcome: false, Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "id-privateMessage"}}}
}

type ECIDMeasurementInitiationRequestIETable struct{}

func ECIDMeasurementInitiationRequestIEs() ECIDMeasurementInitiationRequestIETable {
	return ECIDMeasurementInitiationRequestIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (ECIDMeasurementInitiationRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationRequest-IEs"}
		return sealed
	}()
}
func (ECIDMeasurementInitiationRequestIETable) infoESMLCUEMeasurementID() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementInitiationRequestIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationRequest-IEs", Row: "id-E-SMLC-UE-Measurement-ID"}}}
}

// ESMLCUEMeasurementID returns the typed binding for the ESMLCUEMeasurementID row of this table.
func (t ECIDMeasurementInitiationRequestIETable) ESMLCUEMeasurementID() ECIDMeasurementInitiationRequestMeasurementIDIEBinding {
	return ECIDMeasurementInitiationRequestMeasurementIDIEBinding{info: t.infoESMLCUEMeasurementID(), codec: func() s00.MeasurementIDValueCodec {
		sealed := s00.MeasurementIDValueCodec{}
		*s00.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*s00.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MeasurementID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MeasurementID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MeasurementID")
			var zero ECIDMeasurementInitiationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s00.MeasurementID
				return empty, runtime.WrapDecodePath(err, "MeasurementID")
			}
			value, ok := decoded.AsESMLCUEMeasurementID()
			if !ok {
				var empty s00.MeasurementID
				return empty, fmt.Errorf("binding E-CIDMeasurementInitiationRequest-IEs.id-E-SMLC-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value s00.MeasurementID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationRequestIEValue{id: s00.ProtocolIEID(2), rowESMLCUEMeasurementID: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeMeasurementIDValueCodecFieldCapture(&sealed) = func(v s00.MeasurementID, options aper.DecodeState) (s00.MeasurementID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaMeasurementID(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeMeasurementIDValueCodecFieldCompare(&sealed) = func(v s00.MeasurementID, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s02.BridgeCompareLPPaMeasurementID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeMeasurementIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementID"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MeasurementID) ECIDMeasurementInitiationRequestIEValue {
			return ECIDMeasurementInitiationRequestIEValue{id: s00.ProtocolIEID(2), rowESMLCUEMeasurementID: &value}
		}, get: func(value *ECIDMeasurementInitiationRequestIEValue) (*s00.MeasurementID, bool) {
			return value.AsESMLCUEMeasurementID()
		}}
}
func (ECIDMeasurementInitiationRequestIETable) infoReportCharacteristics() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementInitiationRequestIEs().ID(), ID: s00.ProtocolIEID(3), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ReportCharacteristics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationRequest-IEs", Row: "id-ReportCharacteristics"}}}
}

// ReportCharacteristics returns the typed binding for the ReportCharacteristics row of this table.
func (t ECIDMeasurementInitiationRequestIETable) ReportCharacteristics() ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding {
	return ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding{info: t.infoReportCharacteristics(), codec: func() s01.ReportCharacteristicsValueCodec {
		sealed := s01.ReportCharacteristicsValueCodec{}
		*s01.BridgeReportCharacteristicsValueCodecFieldPath(&sealed) = "ReportCharacteristics"
		*s01.BridgeReportCharacteristicsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ReportCharacteristics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ReportCharacteristics
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ReportCharacteristics")
			var zero ECIDMeasurementInitiationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(3), raw)
			if err != nil {
				var empty s00.ReportCharacteristics
				return empty, runtime.WrapDecodePath(err, "ReportCharacteristics")
			}
			value, ok := decoded.AsReportCharacteristics()
			if !ok {
				var empty s00.ReportCharacteristics
				return empty, fmt.Errorf("binding E-CIDMeasurementInitiationRequest-IEs.id-ReportCharacteristics: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeReportCharacteristicsValueCodecFieldEncode(&sealed) = func(value s00.ReportCharacteristics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationRequestIEValue{id: s00.ProtocolIEID(3), rowReportCharacteristics: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeReportCharacteristicsValueCodecFieldCapture(&sealed) = func(v s00.ReportCharacteristics, options aper.DecodeState) (s00.ReportCharacteristics, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaReportCharacteristics(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*s01.BridgeReportCharacteristicsValueCodecFieldCompare(&sealed) = func(v s00.ReportCharacteristics, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s03.BridgeCompareLPPaReportCharacteristics(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeReportCharacteristicsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ReportCharacteristics"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.ReportCharacteristics) ECIDMeasurementInitiationRequestIEValue {
			return ECIDMeasurementInitiationRequestIEValue{id: s00.ProtocolIEID(3), rowReportCharacteristics: &value}
		}, get: func(value *ECIDMeasurementInitiationRequestIEValue) (*s00.ReportCharacteristics, bool) {
			return value.AsReportCharacteristics()
		}}
}
func (ECIDMeasurementInitiationRequestIETable) infoMeasurementPeriodicity() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementInitiationRequestIEs().ID(), ID: s00.ProtocolIEID(4), Criticality: s00.CriticalityReject, Presence: s00.PresenceConditional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementPeriodicity"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationRequest-IEs", Row: "id-MeasurementPeriodicity"}}}
}

// MeasurementPeriodicity returns the typed binding for the MeasurementPeriodicity row of this table.
func (t ECIDMeasurementInitiationRequestIETable) MeasurementPeriodicity() ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding {
	return ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding{info: t.infoMeasurementPeriodicity(), codec: func() s00.MeasurementPeriodicityValueCodec {
		sealed := s00.MeasurementPeriodicityValueCodec{}
		*s00.BridgeMeasurementPeriodicityValueCodecFieldPath(&sealed) = "MeasurementPeriodicity"
		*s00.BridgeMeasurementPeriodicityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MeasurementPeriodicity, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MeasurementPeriodicity
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MeasurementPeriodicity")
			var zero ECIDMeasurementInitiationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(4), raw)
			if err != nil {
				var empty s00.MeasurementPeriodicity
				return empty, runtime.WrapDecodePath(err, "MeasurementPeriodicity")
			}
			value, ok := decoded.AsMeasurementPeriodicity()
			if !ok {
				var empty s00.MeasurementPeriodicity
				return empty, fmt.Errorf("binding E-CIDMeasurementInitiationRequest-IEs.id-MeasurementPeriodicity: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeMeasurementPeriodicityValueCodecFieldEncode(&sealed) = func(value s00.MeasurementPeriodicity, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationRequestIEValue{id: s00.ProtocolIEID(4), rowMeasurementPeriodicity: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeMeasurementPeriodicityValueCodecFieldCapture(&sealed) = func(v s00.MeasurementPeriodicity, options aper.DecodeState) (s00.MeasurementPeriodicity, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaMeasurementPeriodicity(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeMeasurementPeriodicityValueCodecFieldCompare(&sealed) = func(v s00.MeasurementPeriodicity, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s02.BridgeCompareLPPaMeasurementPeriodicity(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeMeasurementPeriodicityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementPeriodicity"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MeasurementPeriodicity) ECIDMeasurementInitiationRequestIEValue {
			return ECIDMeasurementInitiationRequestIEValue{id: s00.ProtocolIEID(4), rowMeasurementPeriodicity: &value}
		}, get: func(value *ECIDMeasurementInitiationRequestIEValue) (*s00.MeasurementPeriodicity, bool) {
			return value.AsMeasurementPeriodicity()
		}}
}
func (ECIDMeasurementInitiationRequestIETable) infoMeasurementQuantities() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementInitiationRequestIEs().ID(), ID: s00.ProtocolIEID(5), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementQuantities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationRequest-IEs", Row: "id-MeasurementQuantities"}}}
}

// MeasurementQuantities returns the typed binding for the MeasurementQuantities row of this table.
func (t ECIDMeasurementInitiationRequestIETable) MeasurementQuantities() ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding {
	return ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding{info: t.infoMeasurementQuantities(), codec: func() s06.MeasurementQuantitiesConcreteValueCodec {
		sealed := s06.MeasurementQuantitiesConcreteValueCodec{}
		*s06.BridgeMeasurementQuantitiesConcreteValueCodecFieldPath(&sealed) = "MeasurementQuantities"
		*s06.BridgeMeasurementQuantitiesConcreteValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s06.MeasurementQuantities, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s06.MeasurementQuantities
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MeasurementQuantities")
			var zero ECIDMeasurementInitiationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(5), raw)
			if err != nil {
				var empty s06.MeasurementQuantities
				return empty, runtime.WrapDecodePath(err, "MeasurementQuantities")
			}
			value, ok := decoded.AsMeasurementQuantities()
			if !ok {
				var empty s06.MeasurementQuantities
				return empty, fmt.Errorf("binding E-CIDMeasurementInitiationRequest-IEs.id-MeasurementQuantities: no selected value")
			}
			return *value, nil
		}
		*s06.BridgeMeasurementQuantitiesConcreteValueCodecFieldEncode(&sealed) = func(value s06.MeasurementQuantities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationRequestIEValue{id: s00.ProtocolIEID(5), rowMeasurementQuantities: &value}).encodeFresh(fresh, budget)
		}
		*s06.BridgeMeasurementQuantitiesConcreteValueCodecFieldCapture(&sealed) = func(v s06.MeasurementQuantities, options aper.DecodeState) (s06.MeasurementQuantities, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s11.BridgeCaptureLPPaMeasurementQuantities(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*s06.BridgeMeasurementQuantitiesConcreteValueCodecFieldCompare(&sealed) = func(v s06.MeasurementQuantities, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s11.BridgeCompareLPPaMeasurementQuantities(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s06.BridgeMeasurementQuantitiesConcreteValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementQuantities"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s06.MeasurementQuantities) ECIDMeasurementInitiationRequestIEValue {
			return ECIDMeasurementInitiationRequestIEValue{id: s00.ProtocolIEID(5), rowMeasurementQuantities: &value}
		}, get: func(value *ECIDMeasurementInitiationRequestIEValue) (*s06.MeasurementQuantities, bool) {
			return value.AsMeasurementQuantities()
		}}
}
func (ECIDMeasurementInitiationRequestIETable) infoInterRATMeasurementQuantities() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementInitiationRequestIEs().ID(), ID: s00.ProtocolIEID(15), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "InterRATMeasurementQuantities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationRequest-IEs", Row: "id-InterRATMeasurementQuantities"}}}
}

// InterRATMeasurementQuantities returns the typed binding for the InterRATMeasurementQuantities row of this table.
func (t ECIDMeasurementInitiationRequestIETable) InterRATMeasurementQuantities() ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding {
	return ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding{info: t.infoInterRATMeasurementQuantities(), codec: func() s06.InterRATMeasurementQuantitiesConcreteValueCodec {
		sealed := s06.InterRATMeasurementQuantitiesConcreteValueCodec{}
		*s06.BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldPath(&sealed) = "InterRATMeasurementQuantities"
		*s06.BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s06.InterRATMeasurementQuantities, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s06.InterRATMeasurementQuantities
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("InterRATMeasurementQuantities")
			var zero ECIDMeasurementInitiationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(15), raw)
			if err != nil {
				var empty s06.InterRATMeasurementQuantities
				return empty, runtime.WrapDecodePath(err, "InterRATMeasurementQuantities")
			}
			value, ok := decoded.AsInterRATMeasurementQuantities()
			if !ok {
				var empty s06.InterRATMeasurementQuantities
				return empty, fmt.Errorf("binding E-CIDMeasurementInitiationRequest-IEs.id-InterRATMeasurementQuantities: no selected value")
			}
			return *value, nil
		}
		*s06.BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldEncode(&sealed) = func(value s06.InterRATMeasurementQuantities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationRequestIEValue{id: s00.ProtocolIEID(15), rowInterRATMeasurementQuantities: &value}).encodeFresh(fresh, budget)
		}
		*s06.BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldCapture(&sealed) = func(v s06.InterRATMeasurementQuantities, options aper.DecodeState) (s06.InterRATMeasurementQuantities, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s11.BridgeCaptureLPPaInterRATMeasurementQuantities(&v, &s)
			var root aper.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v,

				root
		}
		*s06.BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldCompare(&sealed) = func(v s06.InterRATMeasurementQuantities, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s11.BridgeCompareLPPaInterRATMeasurementQuantities(&v, &s)
			s.End(f, root, false)

			return s.Plan()
		}
		*s06.BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InterRATMeasurementQuantities"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s06.InterRATMeasurementQuantities) ECIDMeasurementInitiationRequestIEValue {
			return ECIDMeasurementInitiationRequestIEValue{id: s00.ProtocolIEID(15), rowInterRATMeasurementQuantities: &value}
		}, get: func(value *ECIDMeasurementInitiationRequestIEValue) (*s06.InterRATMeasurementQuantities, bool) {
			return value.AsInterRATMeasurementQuantities()
		}}
}
func (ECIDMeasurementInitiationRequestIETable) infoWLANMeasurementQuantities() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementInitiationRequestIEs().ID(), ID: s00.ProtocolIEID(19), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementQuantities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationRequest-IEs", Row: "id-WLANMeasurementQuantities"}}}
}

// WLANMeasurementQuantities returns the typed binding for the WLANMeasurementQuantities row of this table.
func (t ECIDMeasurementInitiationRequestIETable) WLANMeasurementQuantities() ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding {
	return ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding{info: t.infoWLANMeasurementQuantities(), codec: func() s20.WLANMeasurementQuantitiesConcreteValueCodec {
		sealed := s20.WLANMeasurementQuantitiesConcreteValueCodec{}
		*s20.BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldPath(&sealed) = "WLANMeasurementQuantities"
		*s20.BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.WLANMeasurementQuantities, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s20.WLANMeasurementQuantities
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("WLANMeasurementQuantities")
			var zero ECIDMeasurementInitiationRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(19), raw)
			if err != nil {
				var empty s20.WLANMeasurementQuantities
				return empty, runtime.WrapDecodePath(err, "WLANMeasurementQuantities")
			}
			value, ok := decoded.AsWLANMeasurementQuantities()
			if !ok {
				var empty s20.WLANMeasurementQuantities
				return empty, fmt.Errorf("binding E-CIDMeasurementInitiationRequest-IEs.id-WLANMeasurementQuantities: no selected value")
			}
			return *value, nil
		}
		*s20.BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldEncode(&sealed) = func(value s20.WLANMeasurementQuantities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationRequestIEValue{id: s00.ProtocolIEID(19), rowWLANMeasurementQuantities: &value}).encodeFresh(fresh, budget)
		}
		*s20.BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldCapture(&sealed) = func(v s20.WLANMeasurementQuantities, options aper.DecodeState) (s20.WLANMeasurementQuantities, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s20.BridgeCaptureLPPaWLANMeasurementQuantities(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldCompare(&sealed) = func(v s20.WLANMeasurementQuantities, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s20.BridgeCompareLPPaWLANMeasurementQuantities(&v, &s)
			s.End(f, root, false)
			return s.
				Plan()
		}
		*s20.BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WLANMeasurementQuantities"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s20.WLANMeasurementQuantities) ECIDMeasurementInitiationRequestIEValue {
			return ECIDMeasurementInitiationRequestIEValue{id: s00.ProtocolIEID(19), rowWLANMeasurementQuantities: &value}
		}, get: func(value *ECIDMeasurementInitiationRequestIEValue) (*s20.WLANMeasurementQuantities, bool) {
			return value.AsWLANMeasurementQuantities()
		}}
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t ECIDMeasurementInitiationRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ECIDMeasurementInitiationRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(2):
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-SMLC-UE-Measurement-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(3):
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-ReportCharacteristics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(4):
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MeasurementPeriodicity requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(5):
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MeasurementQuantities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(15):
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-InterRATMeasurementQuantities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(19):
		return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-WLANMeasurementQuantities requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ECIDMeasurementInitiationRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return ECIDMeasurementInitiationRequestIEField{Id: id, Criticality: criticality, Value: ECIDMeasurementInitiationRequestIEValue{id: id, opaque: retained, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// InitiatingMessageCodec binds the complete source value type.
func InitiatingMessageCodec() InitiatingMessageValueCodec {
	return InitiatingMessageValueCodec{path: "InitiatingMessage", decode: func(data []byte, options aper.DecodeState) (InitiatingMessage, error) {
		var value InitiatingMessage
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return InitiatingMessage{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value InitiatingMessage, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v InitiatingMessage, options aper.DecodeState) (InitiatingMessage, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaInitiatingMessage(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v InitiatingMessage, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaInitiatingMessage(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InitiatingMessage"
		return sealed
	}(),
	}
}

// InterRATMeasurementQuantitiesCodec binds the complete APER value type.
func InterRATMeasurementQuantitiesCodec() s06.InterRATMeasurementQuantitiesConcreteValueCodec {
	return ECIDMeasurementInitiationRequestIEs().InterRATMeasurementQuantities().Codec()
}

// MeasurementPeriodicityCodec binds the complete APER value type.
func MeasurementPeriodicityCodec() s00.MeasurementPeriodicityValueCodec {
	return ECIDMeasurementInitiationRequestIEs().MeasurementPeriodicity().Codec()
}

// MeasurementQuantitiesCodec binds the complete APER value type.
func MeasurementQuantitiesCodec() s06.MeasurementQuantitiesConcreteValueCodec {
	return ECIDMeasurementInitiationRequestIEs().MeasurementQuantities().Codec()
}

// PrivateMessageCodec binds the complete APER value type.
func PrivateMessageCodec() s12.PrivateMessageValueCodec {
	return PrivateMessageProcedure().Initiating().Codec()
}

// ReportCharacteristicsCodec binds the complete APER value type.
func ReportCharacteristicsCodec() s01.ReportCharacteristicsValueCodec {
	return ECIDMeasurementInitiationRequestIEs().ReportCharacteristics().Codec()
}

// WLANMeasurementQuantitiesCodec binds the complete APER value type.
func WLANMeasurementQuantitiesCodec() s20.WLANMeasurementQuantitiesConcreteValueCodec {
	return ECIDMeasurementInitiationRequestIEs().WLANMeasurementQuantities().Codec()
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ECIDMeasurementInitiationRequestIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 2:
		if v.rowESMLCUEMeasurementID != nil {
			return v.rowESMLCUEMeasurementID, true
		}
	case 3:
		if v.rowReportCharacteristics != nil {
			return v.rowReportCharacteristics, true
		}
	case 4:
		if v.rowMeasurementPeriodicity != nil {
			return v.rowMeasurementPeriodicity, true
		}
	case 5:
		if v.rowMeasurementQuantities != nil {
			return v.rowMeasurementQuantities, true
		}
	case 15:
		if v.rowInterRATMeasurementQuantities != nil {
			return v.rowInterRATMeasurementQuantities, true
		}
	case 19:
		if v.rowWLANMeasurementQuantities != nil {
			return v.rowWLANMeasurementQuantities, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *InitiatingValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.code {
	case 0:
		if v.bodyErrorIndication != nil {
			return v.bodyErrorIndication, true
		}
	case 1:
		if v.bodyPrivateMessage != nil {
			return v.bodyPrivateMessage, true
		}
	case 2:
		if v.bodyECIDMeasurementInitiationRequest != nil {
			return v.bodyECIDMeasurementInitiationRequest, true
		}
	case 3:
		if v.bodyECIDMeasurementFailureIndication != nil {
			return v.bodyECIDMeasurementFailureIndication, true
		}
	case 4:
		if v.bodyECIDMeasurementReport != nil {
			return v.bodyECIDMeasurementReport, true
		}
	case 5:
		if v.bodyECIDMeasurementTerminationCommand != nil {
			return v.bodyECIDMeasurementTerminationCommand, true
		}
	case 6:
		if v.bodyOTDOAInformationRequest != nil {
			return v.bodyOTDOAInformationRequest, true
		}
	case 7:
		if v.bodyUTDOAInformationRequest != nil {
			return v.bodyUTDOAInformationRequest, true
		}
	case 8:
		if v.bodyUTDOAInformationUpdate != nil {
			return v.bodyUTDOAInformationUpdate, true
		}
	case 9:
		if v.bodyAssistanceInformationControl != nil {
			return v.bodyAssistanceInformationControl, true
		}
	case 10:
		if v.bodyAssistanceInformationFeedback != nil {
			return v.bodyAssistanceInformationFeedback, true
		}
	}
	return nil, false
}

func BridgeAssistanceInformationControlInitiatingBindingFieldCapture(v *AssistanceInformationControlInitiatingBinding) *func(s15.AssistanceInformationControl, aper.DecodeState) (s15.AssistanceInformationControl, aper.Snapshot) {
	return &v.capture
}
func BridgeAssistanceInformationControlInitiatingBindingFieldCompare(v *AssistanceInformationControlInitiatingBinding) *func(s15.AssistanceInformationControl, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeAssistanceInformationControlInitiatingBindingFieldContext(v *AssistanceInformationControlInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationControlInitiatingBindingFieldDecode(v *AssistanceInformationControlInitiatingBinding) *func([]byte, aper.DecodeState) (s15.AssistanceInformationControl, error) {
	return &v.decode
}
func BridgeAssistanceInformationControlInitiatingBindingFieldEncode(v *AssistanceInformationControlInitiatingBinding) *func(*s15.AssistanceInformationControl, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceInformationControlInitiatingBindingFieldInfo(v *AssistanceInformationControlInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeAssistanceInformationControlInitiatingBindingFieldInject(v *AssistanceInformationControlInitiatingBinding) *func(s15.AssistanceInformationControl) InitiatingValue {
	return &v.inject
}
func BridgeAssistanceInformationControlInitiatingBindingFieldValidate(v *AssistanceInformationControlInitiatingBinding) *func(*s15.AssistanceInformationControl, *aper.DecodeBudget) (s09.ValidationReport, error) {
	return &v.validate
}
func BridgeAssistanceInformationFeedbackInitiatingBindingFieldCapture(v *AssistanceInformationFeedbackInitiatingBinding) *func(s17.AssistanceInformationFeedback, aper.DecodeState) (s17.AssistanceInformationFeedback, aper.Snapshot) {
	return &v.capture
}
func BridgeAssistanceInformationFeedbackInitiatingBindingFieldCompare(v *AssistanceInformationFeedbackInitiatingBinding) *func(s17.AssistanceInformationFeedback, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeAssistanceInformationFeedbackInitiatingBindingFieldContext(v *AssistanceInformationFeedbackInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationFeedbackInitiatingBindingFieldDecode(v *AssistanceInformationFeedbackInitiatingBinding) *func([]byte, aper.DecodeState) (s17.AssistanceInformationFeedback, error) {
	return &v.decode
}
func BridgeAssistanceInformationFeedbackInitiatingBindingFieldEncode(v *AssistanceInformationFeedbackInitiatingBinding) *func(*s17.AssistanceInformationFeedback, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceInformationFeedbackInitiatingBindingFieldInfo(v *AssistanceInformationFeedbackInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeAssistanceInformationFeedbackInitiatingBindingFieldInject(v *AssistanceInformationFeedbackInitiatingBinding) *func(s17.AssistanceInformationFeedback) InitiatingValue {
	return &v.inject
}
func BridgeAssistanceInformationFeedbackInitiatingBindingFieldValidate(v *AssistanceInformationFeedbackInitiatingBinding) *func(*s17.AssistanceInformationFeedback, *aper.DecodeBudget) (s09.ValidationReport, error) {
	return &v.validate
}
func BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldCapture(v *ECIDMeasurementFailureIndicationInitiatingBinding) *func(s11.ECIDMeasurementFailureIndication, aper.DecodeState) (s11.ECIDMeasurementFailureIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldCompare(v *ECIDMeasurementFailureIndicationInitiatingBinding) *func(s11.ECIDMeasurementFailureIndication, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldContext(v *ECIDMeasurementFailureIndicationInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldDecode(v *ECIDMeasurementFailureIndicationInitiatingBinding) *func([]byte, aper.DecodeState) (s11.ECIDMeasurementFailureIndication, error) {
	return &v.decode
}
func BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldEncode(v *ECIDMeasurementFailureIndicationInitiatingBinding) *func(*s11.ECIDMeasurementFailureIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldInfo(v *ECIDMeasurementFailureIndicationInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldInject(v *ECIDMeasurementFailureIndicationInitiatingBinding) *func(s11.ECIDMeasurementFailureIndication) InitiatingValue {
	return &v.inject
}
func BridgeECIDMeasurementFailureIndicationInitiatingBindingFieldValidate(v *ECIDMeasurementFailureIndicationInitiatingBinding) *func(*s11.ECIDMeasurementFailureIndication, *aper.DecodeBudget) (s09.ValidationReport, error) {
	return &v.validate
}
func BridgeECIDMeasurementInitiationRequestAPERValueFieldContext(v *ECIDMeasurementInitiationRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementInitiationRequestAPERValueFieldReceived(v *ECIDMeasurementInitiationRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementInitiationRequestAPERValueFieldReplay(v *ECIDMeasurementInitiationRequestAPERValue) *aper.Snapshot {
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
func BridgeECIDMeasurementInitiationRequestFieldExtOrigin(v *ECIDMeasurementInitiationRequest) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeECIDMeasurementInitiationRequestFieldExtPresent(v *ECIDMeasurementInitiationRequest) *[]bool {
	return &v.extPresent
}
func BridgeECIDMeasurementInitiationRequestFieldExtWire(v *ECIDMeasurementInitiationRequest) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeECIDMeasurementInitiationRequestFieldPerExtPadding(v *ECIDMeasurementInitiationRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeECIDMeasurementInitiationRequestFieldPerPadding(v *ECIDMeasurementInitiationRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeECIDMeasurementInitiationRequestFieldProtocolIEsIndef(v *ECIDMeasurementInitiationRequest) *bool {
	return &v.protocolIEsIndef
}
func BridgeECIDMeasurementInitiationRequestFieldReceived(v *ECIDMeasurementInitiationRequest) *bool {
	return &v.received
}
func BridgeECIDMeasurementInitiationRequestFieldReceivedBytes(v *ECIDMeasurementInitiationRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeECIDMeasurementInitiationRequestFieldReplay(v *ECIDMeasurementInitiationRequest) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationRequestFieldStream(v *ECIDMeasurementInitiationRequest) *aper.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementInitiationRequestFieldWithoutReplay(v *ECIDMeasurementInitiationRequest) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationRequestIEFieldFieldReceived(v *ECIDMeasurementInitiationRequestIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeECIDMeasurementInitiationRequestIEFieldFieldReplay(v *ECIDMeasurementInitiationRequestIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationRequestIEFieldFieldStream(v *ECIDMeasurementInitiationRequestIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementInitiationRequestIEFieldFieldWithoutReplay(v *ECIDMeasurementInitiationRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationRequestIEFieldMethodMarshalAPERTo(v *ECIDMeasurementInitiationRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementInitiationRequestIEFieldMethodUnmarshalAPERFrom(v *ECIDMeasurementInitiationRequestIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementInitiationRequestIETableMethodInfoESMLCUEMeasurementID(v ECIDMeasurementInitiationRequestIETable) s00.FieldInfo {
	return v.infoESMLCUEMeasurementID()
}
func BridgeECIDMeasurementInitiationRequestIETableMethodInfoInterRATMeasurementQuantities(v ECIDMeasurementInitiationRequestIETable) s00.FieldInfo {
	return v.infoInterRATMeasurementQuantities()
}
func BridgeECIDMeasurementInitiationRequestIETableMethodInfoMeasurementPeriodicity(v ECIDMeasurementInitiationRequestIETable) s00.FieldInfo {
	return v.infoMeasurementPeriodicity()
}
func BridgeECIDMeasurementInitiationRequestIETableMethodInfoMeasurementQuantities(v ECIDMeasurementInitiationRequestIETable) s00.FieldInfo {
	return v.infoMeasurementQuantities()
}
func BridgeECIDMeasurementInitiationRequestIETableMethodInfoReportCharacteristics(v ECIDMeasurementInitiationRequestIETable) s00.FieldInfo {
	return v.infoReportCharacteristics()
}
func BridgeECIDMeasurementInitiationRequestIETableMethodInfoWLANMeasurementQuantities(v ECIDMeasurementInitiationRequestIETable) s00.FieldInfo {
	return v.infoWLANMeasurementQuantities()
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldId(v *ECIDMeasurementInitiationRequestIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldIsOpaque(v *ECIDMeasurementInitiationRequestIEValue) *bool {
	return &v.isOpaque
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldOpaque(v *ECIDMeasurementInitiationRequestIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldReceived(v *ECIDMeasurementInitiationRequestIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldReplay(v *ECIDMeasurementInitiationRequestIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldRowESMLCUEMeasurementID(v *ECIDMeasurementInitiationRequestIEValue) **s00.MeasurementID {
	return &v.rowESMLCUEMeasurementID
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldRowInterRATMeasurementQuantities(v *ECIDMeasurementInitiationRequestIEValue) **s06.InterRATMeasurementQuantities {
	return &v.rowInterRATMeasurementQuantities
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldRowMeasurementPeriodicity(v *ECIDMeasurementInitiationRequestIEValue) **s00.MeasurementPeriodicity {
	return &v.rowMeasurementPeriodicity
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldRowMeasurementQuantities(v *ECIDMeasurementInitiationRequestIEValue) **s06.MeasurementQuantities {
	return &v.rowMeasurementQuantities
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldRowReportCharacteristics(v *ECIDMeasurementInitiationRequestIEValue) **s00.ReportCharacteristics {
	return &v.rowReportCharacteristics
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldRowWLANMeasurementQuantities(v *ECIDMeasurementInitiationRequestIEValue) **s20.WLANMeasurementQuantities {
	return &v.rowWLANMeasurementQuantities
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldWithoutReplay(v *ECIDMeasurementInitiationRequestIEValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodCaptureFraming(v ECIDMeasurementInitiationRequestIEValue) uint64 {
	return v.captureFraming()
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodCaptureSemantics(v ECIDMeasurementInitiationRequestIEValue, a0 aper.SemanticCapture) ECIDMeasurementInitiationRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodCaptureSnapshot(v ECIDMeasurementInitiationRequestIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodCompareSemantics(v ECIDMeasurementInitiationRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodDecode(v ECIDMeasurementInitiationRequestIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ECIDMeasurementInitiationRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodEncode(v ECIDMeasurementInitiationRequestIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodEncodeFresh(v ECIDMeasurementInitiationRequestIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodMatchesID(v ECIDMeasurementInitiationRequestIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodReason(v ECIDMeasurementInitiationRequestIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodRule(v ECIDMeasurementInitiationRequestIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldCapture(v *ECIDMeasurementInitiationRequestInitiatingBinding) *func(ECIDMeasurementInitiationRequest, aper.DecodeState) (ECIDMeasurementInitiationRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldCompare(v *ECIDMeasurementInitiationRequestInitiatingBinding) *func(ECIDMeasurementInitiationRequest, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldContext(v *ECIDMeasurementInitiationRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldDecode(v *ECIDMeasurementInitiationRequestInitiatingBinding) *func([]byte, aper.DecodeState) (ECIDMeasurementInitiationRequest, error) {
	return &v.decode
}
func BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldEncode(v *ECIDMeasurementInitiationRequestInitiatingBinding) *func(*ECIDMeasurementInitiationRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldInfo(v *ECIDMeasurementInitiationRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldInject(v *ECIDMeasurementInitiationRequestInitiatingBinding) *func(ECIDMeasurementInitiationRequest) InitiatingValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationRequestInitiatingBindingFieldValidate(v *ECIDMeasurementInitiationRequestInitiatingBinding) *func(*ECIDMeasurementInitiationRequest, *aper.DecodeBudget) (s09.ValidationReport, error) {
	return &v.validate
}
func BridgeECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBindingFieldCodec(v *ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding) *s06.InterRATMeasurementQuantitiesConcreteValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBindingFieldGet(v *ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding) *func(*ECIDMeasurementInitiationRequestIEValue) (*s06.InterRATMeasurementQuantities, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBindingFieldInfo(v *ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBindingFieldInject(v *ECIDMeasurementInitiationRequestInterRATMeasurementQuantitiesIEBinding) *func(s06.InterRATMeasurementQuantities) ECIDMeasurementInitiationRequestIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationRequestMeasurementIDIEBindingFieldCodec(v *ECIDMeasurementInitiationRequestMeasurementIDIEBinding) *s00.MeasurementIDValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationRequestMeasurementIDIEBindingFieldGet(v *ECIDMeasurementInitiationRequestMeasurementIDIEBinding) *func(*ECIDMeasurementInitiationRequestIEValue) (*s00.MeasurementID, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationRequestMeasurementIDIEBindingFieldInfo(v *ECIDMeasurementInitiationRequestMeasurementIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationRequestMeasurementIDIEBindingFieldInject(v *ECIDMeasurementInitiationRequestMeasurementIDIEBinding) *func(s00.MeasurementID) ECIDMeasurementInitiationRequestIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationRequestMeasurementPeriodicityIEBindingFieldCodec(v *ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding) *s00.MeasurementPeriodicityValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationRequestMeasurementPeriodicityIEBindingFieldGet(v *ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding) *func(*ECIDMeasurementInitiationRequestIEValue) (*s00.MeasurementPeriodicity, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationRequestMeasurementPeriodicityIEBindingFieldInfo(v *ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationRequestMeasurementPeriodicityIEBindingFieldInject(v *ECIDMeasurementInitiationRequestMeasurementPeriodicityIEBinding) *func(s00.MeasurementPeriodicity) ECIDMeasurementInitiationRequestIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationRequestMeasurementQuantitiesIEBindingFieldCodec(v *ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding) *s06.MeasurementQuantitiesConcreteValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationRequestMeasurementQuantitiesIEBindingFieldGet(v *ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding) *func(*ECIDMeasurementInitiationRequestIEValue) (*s06.MeasurementQuantities, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationRequestMeasurementQuantitiesIEBindingFieldInfo(v *ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationRequestMeasurementQuantitiesIEBindingFieldInject(v *ECIDMeasurementInitiationRequestMeasurementQuantitiesIEBinding) *func(s06.MeasurementQuantities) ECIDMeasurementInitiationRequestIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationRequestMethodMarshalAPERBudget(v *ECIDMeasurementInitiationRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeECIDMeasurementInitiationRequestMethodMarshalAPERChanged(v *ECIDMeasurementInitiationRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeECIDMeasurementInitiationRequestMethodMarshalAPERChangedValue(v *ECIDMeasurementInitiationRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeECIDMeasurementInitiationRequestMethodMarshalAPERFreshValue(v *ECIDMeasurementInitiationRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeECIDMeasurementInitiationRequestMethodMarshalAPERLegacy(v *ECIDMeasurementInitiationRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeECIDMeasurementInitiationRequestMethodMarshalAPERPlanned(v *ECIDMeasurementInitiationRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeECIDMeasurementInitiationRequestMethodMarshalAPERTo(v *ECIDMeasurementInitiationRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementInitiationRequestMethodUnmarshalAPERFrom(v *ECIDMeasurementInitiationRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementInitiationRequestMethodUnmarshalAPERLegacy(v *ECIDMeasurementInitiationRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeECIDMeasurementInitiationRequestMethodUnmarshalAPERWithOptions(v *ECIDMeasurementInitiationRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeECIDMeasurementInitiationRequestReportCharacteristicsIEBindingFieldCodec(v *ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding) *s01.ReportCharacteristicsValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationRequestReportCharacteristicsIEBindingFieldGet(v *ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding) *func(*ECIDMeasurementInitiationRequestIEValue) (*s00.ReportCharacteristics, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationRequestReportCharacteristicsIEBindingFieldInfo(v *ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationRequestReportCharacteristicsIEBindingFieldInject(v *ECIDMeasurementInitiationRequestReportCharacteristicsIEBinding) *func(s00.ReportCharacteristics) ECIDMeasurementInitiationRequestIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationRequestValueCodecFieldCapture(v *ECIDMeasurementInitiationRequestValueCodec) *func(ECIDMeasurementInitiationRequest, aper.DecodeState) (ECIDMeasurementInitiationRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementInitiationRequestValueCodecFieldCompare(v *ECIDMeasurementInitiationRequestValueCodec) *func(ECIDMeasurementInitiationRequest, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementInitiationRequestValueCodecFieldContext(v *ECIDMeasurementInitiationRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementInitiationRequestValueCodecFieldDecode(v *ECIDMeasurementInitiationRequestValueCodec) *func([]byte, aper.DecodeState) (ECIDMeasurementInitiationRequest, error) {
	return &v.decode
}
func BridgeECIDMeasurementInitiationRequestValueCodecFieldEncode(v *ECIDMeasurementInitiationRequestValueCodec) *func(ECIDMeasurementInitiationRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementInitiationRequestValueCodecFieldPath(v *ECIDMeasurementInitiationRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeECIDMeasurementInitiationRequestValueCodecMethodEncodeBudget(v ECIDMeasurementInitiationRequestValueCodec, a0 ECIDMeasurementInitiationRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeECIDMeasurementInitiationRequestValueCodecMethodEncodeChanged(v ECIDMeasurementInitiationRequestValueCodec, a0 ECIDMeasurementInitiationRequest, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBindingFieldCodec(v *ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding) *s20.WLANMeasurementQuantitiesConcreteValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBindingFieldGet(v *ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding) *func(*ECIDMeasurementInitiationRequestIEValue) (*s20.WLANMeasurementQuantities, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBindingFieldInfo(v *ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBindingFieldInject(v *ECIDMeasurementInitiationRequestWLANMeasurementQuantitiesIEBinding) *func(s20.WLANMeasurementQuantities) ECIDMeasurementInitiationRequestIEValue {
	return &v.inject
}
func BridgeECIDMeasurementReportInitiatingBindingFieldCapture(v *ECIDMeasurementReportInitiatingBinding) *func(s13.ECIDMeasurementReport, aper.DecodeState) (s13.ECIDMeasurementReport, aper.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementReportInitiatingBindingFieldCompare(v *ECIDMeasurementReportInitiatingBinding) *func(s13.ECIDMeasurementReport, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementReportInitiatingBindingFieldContext(v *ECIDMeasurementReportInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementReportInitiatingBindingFieldDecode(v *ECIDMeasurementReportInitiatingBinding) *func([]byte, aper.DecodeState) (s13.ECIDMeasurementReport, error) {
	return &v.decode
}
func BridgeECIDMeasurementReportInitiatingBindingFieldEncode(v *ECIDMeasurementReportInitiatingBinding) *func(*s13.ECIDMeasurementReport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementReportInitiatingBindingFieldInfo(v *ECIDMeasurementReportInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeECIDMeasurementReportInitiatingBindingFieldInject(v *ECIDMeasurementReportInitiatingBinding) *func(s13.ECIDMeasurementReport) InitiatingValue {
	return &v.inject
}
func BridgeECIDMeasurementReportInitiatingBindingFieldValidate(v *ECIDMeasurementReportInitiatingBinding) *func(*s13.ECIDMeasurementReport, *aper.DecodeBudget) (s09.ValidationReport, error) {
	return &v.validate
}
func BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldCapture(v *ECIDMeasurementTerminationCommandInitiatingBinding) *func(s06.ECIDMeasurementTerminationCommand, aper.DecodeState) (s06.ECIDMeasurementTerminationCommand, aper.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldCompare(v *ECIDMeasurementTerminationCommandInitiatingBinding) *func(s06.ECIDMeasurementTerminationCommand, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldContext(v *ECIDMeasurementTerminationCommandInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldDecode(v *ECIDMeasurementTerminationCommandInitiatingBinding) *func([]byte, aper.DecodeState) (s06.ECIDMeasurementTerminationCommand, error) {
	return &v.decode
}
func BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldEncode(v *ECIDMeasurementTerminationCommandInitiatingBinding) *func(*s06.ECIDMeasurementTerminationCommand, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldInfo(v *ECIDMeasurementTerminationCommandInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldInject(v *ECIDMeasurementTerminationCommandInitiatingBinding) *func(s06.ECIDMeasurementTerminationCommand) InitiatingValue {
	return &v.inject
}
func BridgeECIDMeasurementTerminationCommandInitiatingBindingFieldValidate(v *ECIDMeasurementTerminationCommandInitiatingBinding) *func(*s06.ECIDMeasurementTerminationCommand, *aper.DecodeBudget) (s09.ValidationReport, error) {
	return &v.validate
}
func BridgeErrorIndicationInitiatingBindingFieldCapture(v *ErrorIndicationInitiatingBinding) *func(s11.ErrorIndication, aper.DecodeState) (s11.ErrorIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeErrorIndicationInitiatingBindingFieldCompare(v *ErrorIndicationInitiatingBinding) *func(s11.ErrorIndication, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeErrorIndicationInitiatingBindingFieldContext(v *ErrorIndicationInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeErrorIndicationInitiatingBindingFieldDecode(v *ErrorIndicationInitiatingBinding) *func([]byte, aper.DecodeState) (s11.ErrorIndication, error) {
	return &v.decode
}
func BridgeErrorIndicationInitiatingBindingFieldEncode(v *ErrorIndicationInitiatingBinding) *func(*s11.ErrorIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeErrorIndicationInitiatingBindingFieldInfo(v *ErrorIndicationInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeErrorIndicationInitiatingBindingFieldInject(v *ErrorIndicationInitiatingBinding) *func(s11.ErrorIndication) InitiatingValue {
	return &v.inject
}
func BridgeErrorIndicationInitiatingBindingFieldValidate(v *ErrorIndicationInitiatingBinding) *func(*s11.ErrorIndication, *aper.DecodeBudget) (s09.ValidationReport, error) {
	return &v.validate
}
func BridgeInitiatingMessageAPERValueFieldContext(v *InitiatingMessageAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitiatingMessageAPERValueFieldReceived(v *InitiatingMessageAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitiatingMessageAPERValueFieldReplay(v *InitiatingMessageAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitiatingMessageAPERValueFieldWithoutReplay(v *InitiatingMessageAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitiatingMessageFieldPerPadding(v *InitiatingMessage) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeInitiatingMessageFieldReceived(v *InitiatingMessage) *bool { return &v.received }
func BridgeInitiatingMessageFieldReceivedBytes(v *InitiatingMessage) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeInitiatingMessageFieldReplay(v *InitiatingMessage) *aper.Snapshot { return &v.replay }
func BridgeInitiatingMessageFieldStream(v *InitiatingMessage) *aper.WireSpan { return &v.stream }
func BridgeInitiatingMessageFieldWithoutReplay(v *InitiatingMessage) *bool   { return &v.withoutReplay }
func BridgeInitiatingMessageMethodMarshalAPERBudget(v *InitiatingMessage, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInitiatingMessageMethodMarshalAPERChanged(v *InitiatingMessage, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeInitiatingMessageMethodMarshalAPERChangedValue(v *InitiatingMessage, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeInitiatingMessageMethodMarshalAPERFreshValue(v *InitiatingMessage, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeInitiatingMessageMethodMarshalAPERLegacy(v *InitiatingMessage) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeInitiatingMessageMethodMarshalAPERPlanned(v *InitiatingMessage, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeInitiatingMessageMethodMarshalAPERTo(v *InitiatingMessage, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInitiatingMessageMethodUnmarshalAPERFrom(v *InitiatingMessage, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInitiatingMessageMethodUnmarshalAPERLegacy(v *InitiatingMessage, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeInitiatingMessageMethodUnmarshalAPERWithOptions(v *InitiatingMessage, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeInitiatingMessageValueCodecFieldCapture(v *InitiatingMessageValueCodec) *func(InitiatingMessage, aper.DecodeState) (InitiatingMessage, aper.Snapshot) {
	return &v.capture
}
func BridgeInitiatingMessageValueCodecFieldCompare(v *InitiatingMessageValueCodec) *func(InitiatingMessage, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeInitiatingMessageValueCodecFieldContext(v *InitiatingMessageValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitiatingMessageValueCodecFieldDecode(v *InitiatingMessageValueCodec) *func([]byte, aper.DecodeState) (InitiatingMessage, error) {
	return &v.decode
}
func BridgeInitiatingMessageValueCodecFieldEncode(v *InitiatingMessageValueCodec) *func(InitiatingMessage, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitiatingMessageValueCodecFieldPath(v *InitiatingMessageValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitiatingMessageValueCodecMethodEncodeBudget(v InitiatingMessageValueCodec, a0 InitiatingMessage, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeInitiatingMessageValueCodecMethodEncodeChanged(v InitiatingMessageValueCodec, a0 InitiatingMessage, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitiatingValueFieldBodyAssistanceInformationControl(v *InitiatingValue) **s15.AssistanceInformationControl {
	return &v.bodyAssistanceInformationControl
}
func BridgeInitiatingValueFieldBodyAssistanceInformationFeedback(v *InitiatingValue) **s17.AssistanceInformationFeedback {
	return &v.bodyAssistanceInformationFeedback
}
func BridgeInitiatingValueFieldBodyECIDMeasurementFailureIndication(v *InitiatingValue) **s11.ECIDMeasurementFailureIndication {
	return &v.bodyECIDMeasurementFailureIndication
}
func BridgeInitiatingValueFieldBodyECIDMeasurementInitiationRequest(v *InitiatingValue) **ECIDMeasurementInitiationRequest {
	return &v.bodyECIDMeasurementInitiationRequest
}
func BridgeInitiatingValueFieldBodyECIDMeasurementReport(v *InitiatingValue) **s13.ECIDMeasurementReport {
	return &v.bodyECIDMeasurementReport
}
func BridgeInitiatingValueFieldBodyECIDMeasurementTerminationCommand(v *InitiatingValue) **s06.ECIDMeasurementTerminationCommand {
	return &v.bodyECIDMeasurementTerminationCommand
}
func BridgeInitiatingValueFieldBodyErrorIndication(v *InitiatingValue) **s11.ErrorIndication {
	return &v.bodyErrorIndication
}
func BridgeInitiatingValueFieldBodyOTDOAInformationRequest(v *InitiatingValue) **s18.OTDOAInformationRequest {
	return &v.bodyOTDOAInformationRequest
}
func BridgeInitiatingValueFieldBodyPrivateMessage(v *InitiatingValue) **s12.PrivateMessage {
	return &v.bodyPrivateMessage
}
func BridgeInitiatingValueFieldBodyUTDOAInformationRequest(v *InitiatingValue) **s16.UTDOAInformationRequest {
	return &v.bodyUTDOAInformationRequest
}
func BridgeInitiatingValueFieldBodyUTDOAInformationUpdate(v *InitiatingValue) **s17.UTDOAInformationUpdate {
	return &v.bodyUTDOAInformationUpdate
}
func BridgeInitiatingValueFieldCode(v *InitiatingValue) *s00.ProcedureCode      { return &v.code }
func BridgeInitiatingValueFieldIsOpaque(v *InitiatingValue) *bool               { return &v.isOpaque }
func BridgeInitiatingValueFieldOpaque(v *InitiatingValue) **aper.OpaqueOpenType { return &v.opaque }
func BridgeInitiatingValueFieldReceived(v *InitiatingValue) *aper.WireSpan      { return &v.received }
func BridgeInitiatingValueFieldReplay(v *InitiatingValue) *aper.Snapshot        { return &v.replay }
func BridgeInitiatingValueFieldWithoutReplay(v *InitiatingValue) *bool          { return &v.withoutReplay }
func BridgeInitiatingValueMethodCaptureFraming(v InitiatingValue) uint64        { return v.captureFraming() }
func BridgeInitiatingValueMethodCaptureSemantics(v InitiatingValue, a0 aper.SemanticCapture) InitiatingValue {
	return v.captureSemantics(a0)
}
func BridgeInitiatingValueMethodCaptureSnapshot(v InitiatingValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeInitiatingValueMethodCompareSemantics(v InitiatingValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeInitiatingValueMethodEncode(v InitiatingValue) ([]byte, error) { return v.encode() }
func BridgeInitiatingValueMethodEncodeFresh(v InitiatingValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeOTDOAInformationRequestInitiatingBindingFieldCapture(v *OTDOAInformationRequestInitiatingBinding) *func(s18.OTDOAInformationRequest, aper.DecodeState) (s18.OTDOAInformationRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeOTDOAInformationRequestInitiatingBindingFieldCompare(v *OTDOAInformationRequestInitiatingBinding) *func(s18.OTDOAInformationRequest, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeOTDOAInformationRequestInitiatingBindingFieldContext(v *OTDOAInformationRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationRequestInitiatingBindingFieldDecode(v *OTDOAInformationRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s18.OTDOAInformationRequest, error) {
	return &v.decode
}
func BridgeOTDOAInformationRequestInitiatingBindingFieldEncode(v *OTDOAInformationRequestInitiatingBinding) *func(*s18.OTDOAInformationRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOAInformationRequestInitiatingBindingFieldInfo(v *OTDOAInformationRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeOTDOAInformationRequestInitiatingBindingFieldInject(v *OTDOAInformationRequestInitiatingBinding) *func(s18.OTDOAInformationRequest) InitiatingValue {
	return &v.inject
}
func BridgeOTDOAInformationRequestInitiatingBindingFieldValidate(v *OTDOAInformationRequestInitiatingBinding) *func(*s18.OTDOAInformationRequest, *aper.DecodeBudget) (s09.ValidationReport, error) {
	return &v.validate
}
func BridgePrivateMessageInitiatingBindingFieldCapture(v *PrivateMessageInitiatingBinding) *func(s12.PrivateMessage, aper.DecodeState) (s12.PrivateMessage, aper.Snapshot) {
	return &v.capture
}
func BridgePrivateMessageInitiatingBindingFieldCompare(v *PrivateMessageInitiatingBinding) *func(s12.PrivateMessage, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePrivateMessageInitiatingBindingFieldContext(v *PrivateMessageInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePrivateMessageInitiatingBindingFieldDecode(v *PrivateMessageInitiatingBinding) *func([]byte, aper.DecodeState) (s12.PrivateMessage, error) {
	return &v.decode
}
func BridgePrivateMessageInitiatingBindingFieldEncode(v *PrivateMessageInitiatingBinding) *func(*s12.PrivateMessage, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePrivateMessageInitiatingBindingFieldInfo(v *PrivateMessageInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgePrivateMessageInitiatingBindingFieldInject(v *PrivateMessageInitiatingBinding) *func(s12.PrivateMessage) InitiatingValue {
	return &v.inject
}
func BridgePrivateMessageInitiatingBindingFieldValidate(v *PrivateMessageInitiatingBinding) *func(*s12.PrivateMessage, *aper.DecodeBudget) (s09.ValidationReport, error) {
	return &v.validate
}
func BridgeUTDOAInformationRequestInitiatingBindingFieldCapture(v *UTDOAInformationRequestInitiatingBinding) *func(s16.UTDOAInformationRequest, aper.DecodeState) (s16.UTDOAInformationRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUTDOAInformationRequestInitiatingBindingFieldCompare(v *UTDOAInformationRequestInitiatingBinding) *func(s16.UTDOAInformationRequest, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeUTDOAInformationRequestInitiatingBindingFieldContext(v *UTDOAInformationRequestInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationRequestInitiatingBindingFieldDecode(v *UTDOAInformationRequestInitiatingBinding) *func([]byte, aper.DecodeState) (s16.UTDOAInformationRequest, error) {
	return &v.decode
}
func BridgeUTDOAInformationRequestInitiatingBindingFieldEncode(v *UTDOAInformationRequestInitiatingBinding) *func(*s16.UTDOAInformationRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTDOAInformationRequestInitiatingBindingFieldInfo(v *UTDOAInformationRequestInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUTDOAInformationRequestInitiatingBindingFieldInject(v *UTDOAInformationRequestInitiatingBinding) *func(s16.UTDOAInformationRequest) InitiatingValue {
	return &v.inject
}
func BridgeUTDOAInformationRequestInitiatingBindingFieldValidate(v *UTDOAInformationRequestInitiatingBinding) *func(*s16.UTDOAInformationRequest, *aper.DecodeBudget) (s09.ValidationReport, error) {
	return &v.validate
}
func BridgeUTDOAInformationUpdateInitiatingBindingFieldCapture(v *UTDOAInformationUpdateInitiatingBinding) *func(s17.UTDOAInformationUpdate, aper.DecodeState) (s17.UTDOAInformationUpdate, aper.Snapshot) {
	return &v.capture
}
func BridgeUTDOAInformationUpdateInitiatingBindingFieldCompare(v *UTDOAInformationUpdateInitiatingBinding) *func(s17.UTDOAInformationUpdate, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeUTDOAInformationUpdateInitiatingBindingFieldContext(v *UTDOAInformationUpdateInitiatingBinding) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationUpdateInitiatingBindingFieldDecode(v *UTDOAInformationUpdateInitiatingBinding) *func([]byte, aper.DecodeState) (s17.UTDOAInformationUpdate, error) {
	return &v.decode
}
func BridgeUTDOAInformationUpdateInitiatingBindingFieldEncode(v *UTDOAInformationUpdateInitiatingBinding) *func(*s17.UTDOAInformationUpdate, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTDOAInformationUpdateInitiatingBindingFieldInfo(v *UTDOAInformationUpdateInitiatingBinding) *s00.ProcedureInfo {
	return &v.info
}
func BridgeUTDOAInformationUpdateInitiatingBindingFieldInject(v *UTDOAInformationUpdateInitiatingBinding) *func(s17.UTDOAInformationUpdate) InitiatingValue {
	return &v.inject
}
func BridgeUTDOAInformationUpdateInitiatingBindingFieldValidate(v *UTDOAInformationUpdateInitiatingBinding) *func(*s17.UTDOAInformationUpdate, *aper.DecodeBudget) (s09.ValidationReport, error) {
	return &v.validate
}
