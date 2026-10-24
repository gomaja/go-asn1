// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s17 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s17

import (
	q6 "fmt"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q13 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	q17 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	q11 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	q15 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s15"
	q16 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s16"
	q7 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// AssistanceInformationFeedbackIEContainer is the concrete ProtocolIEContainer[AssistanceInformationFeedbackIEValue].
type AssistanceInformationFeedbackIEContainer []AssistanceInformationFeedbackIEField

// AssistanceInformationFeedbackIEField is the concrete ProtocolIEField[AssistanceInformationFeedbackIEValue].
type AssistanceInformationFeedbackIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         AssistanceInformationFeedbackIEValue

	received q4.CompletePadding
}

func (v AssistanceInformationFeedbackIEField) WithoutReplay() AssistanceInformationFeedbackIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *AssistanceInformationFeedbackIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AssistanceInformationFeedbackIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.WrapDecodePath(q6.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false); err != nil {
		return q6.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q6.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *AssistanceInformationFeedbackIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationFeedbackIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q7.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q7.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero AssistanceInformationFeedbackIEValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return q7.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return q7.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}
func BridgeAssistanceInformationFeedbackIEValueCaptureLPPaProtocolIEContainer(v *AssistanceInformationFeedbackIEContainer, s *q4.SemanticCapture) {
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
			BridgeAssistanceInformationFeedbackIEValueCaptureLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeAssistanceInformationFeedbackIEValueCompareLPPaProtocolIEContainer(v *AssistanceInformationFeedbackIEContainer, s *q4.SemanticComparison) {
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
			BridgeAssistanceInformationFeedbackIEValueCompareLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeUTDOAInformationUpdateIEValueCaptureLPPaProtocolIEContainer(v *q9.UTDOAInformationUpdateIEContainer, s *q4.SemanticCapture) {
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
			BridgeUTDOAInformationUpdateIEValueCaptureLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeUTDOAInformationUpdateIEValueCompareLPPaProtocolIEContainer(v *q9.UTDOAInformationUpdateIEContainer, s *q4.SemanticComparison) {
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
			BridgeUTDOAInformationUpdateIEValueCompareLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
}

// AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding is the concrete IEBinding[AssistanceInformationFailureList, AssistanceInformationFeedbackIEValue].
type AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding struct {
	info   q5.FieldInfo
	codec  q10.AssistanceInformationFailureListValueCodec
	inject func(q10.AssistanceInformationFailureList,

	) AssistanceInformationFeedbackIEValue

	get func(*AssistanceInformationFeedbackIEValue,

	) (*q10.AssistanceInformationFailureList,

		bool)
}

func (b AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding) Info() q5.FieldInfo {
	return b.info
}
func (b AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding) Codec() q10.AssistanceInformationFailureListValueCodec {
	return b.codec
}
func (b AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding) New(value q10.AssistanceInformationFailureList,

) (AssistanceInformationFeedbackIEField, error) {
	if b.inject == nil {
		return AssistanceInformationFeedbackIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return AssistanceInformationFeedbackIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q10.BridgeAssistanceInformationFailureListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return AssistanceInformationFeedbackIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return AssistanceInformationFeedbackIEField{}, q4.OperationError(err, "Value.New")
	}
	return AssistanceInformationFeedbackIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding) Get(field *AssistanceInformationFeedbackIEField) (*q10.AssistanceInformationFailureList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, AssistanceInformationFeedbackIEValue].
type AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding struct {
	info   q5.FieldInfo
	codec  q11.CriticalityDiagnosticsValueCodec
	inject func(q11.CriticalityDiagnostics,

	) AssistanceInformationFeedbackIEValue

	get func(*AssistanceInformationFeedbackIEValue,

	) (*q11.CriticalityDiagnostics,

		bool)
}

func (b AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding) Info() q5.FieldInfo {
	return b.info
}
func (b AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding) Codec() q11.CriticalityDiagnosticsValueCodec {
	return b.codec
}
func (b AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding) New(value q11.CriticalityDiagnostics,

) (AssistanceInformationFeedbackIEField, error) {
	if b.inject == nil {
		return AssistanceInformationFeedbackIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return AssistanceInformationFeedbackIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q11.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return AssistanceInformationFeedbackIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return AssistanceInformationFeedbackIEField{}, q4.OperationError(err, "Value.New")
	}
	return AssistanceInformationFeedbackIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding) Get(field *AssistanceInformationFeedbackIEField) (*q11.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// AssistanceInformationFeedbackValueCodec is the concrete ValueCodec[AssistanceInformationFeedback].
type AssistanceInformationFeedbackValueCodec struct {
	context q5.BridgeCodecContext
	capture func(AssistanceInformationFeedback, q4.DecodeState,

	) (AssistanceInformationFeedback, q4.Snapshot,

	)
	compare func(AssistanceInformationFeedback, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (AssistanceInformationFeedback,

		error)
	encode func(AssistanceInformationFeedback,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c AssistanceInformationFeedbackValueCodec) New(value AssistanceInformationFeedback,

) (AssistanceInformationFeedbackAPERValue, error) {
	if c.encode == nil {
		return AssistanceInformationFeedbackAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return AssistanceInformationFeedbackAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AssistanceInformationFeedbackAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return AssistanceInformationFeedbackAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c AssistanceInformationFeedbackValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (AssistanceInformationFeedbackAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return AssistanceInformationFeedbackAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return AssistanceInformationFeedbackAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return AssistanceInformationFeedbackAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return AssistanceInformationFeedbackAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return AssistanceInformationFeedbackAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c AssistanceInformationFeedbackValueCodec) EncodeAPER(value AssistanceInformationFeedbackAPERValue, options ...q4.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q4.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q4.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q4.OperationError(err, c.path)
}
func (c AssistanceInformationFeedbackValueCodec) encodeBudget(value AssistanceInformationFeedback,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c AssistanceInformationFeedbackValueCodec) encodeChanged(value AssistanceInformationFeedback,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// UTDOAInformationResponseValueCodec is the concrete ValueCodec[UTDOAInformationResponse].
type UTDOAInformationResponseValueCodec struct {
	context q5.BridgeCodecContext
	capture func(UTDOAInformationResponse, q4.DecodeState,

	) (UTDOAInformationResponse, q4.Snapshot,

	)
	compare func(UTDOAInformationResponse, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (UTDOAInformationResponse,

		error)
	encode func(UTDOAInformationResponse,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c UTDOAInformationResponseValueCodec) New(value UTDOAInformationResponse,

) (UTDOAInformationResponseAPERValue, error) {
	if c.encode == nil {
		return UTDOAInformationResponseAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return UTDOAInformationResponseAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UTDOAInformationResponseAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return UTDOAInformationResponseAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c UTDOAInformationResponseValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (UTDOAInformationResponseAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return UTDOAInformationResponseAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return UTDOAInformationResponseAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return UTDOAInformationResponseAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return UTDOAInformationResponseAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return UTDOAInformationResponseAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c UTDOAInformationResponseValueCodec) EncodeAPER(value UTDOAInformationResponseAPERValue, options ...q4.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q4.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q4.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q4.OperationError(err, c.path)
}
func (c UTDOAInformationResponseValueCodec) encodeBudget(value UTDOAInformationResponse,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c UTDOAInformationResponseValueCodec) encodeChanged(value UTDOAInformationResponse,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// UTDOAInformationUpdateValueCodec is the concrete ValueCodec[UTDOAInformationUpdate].
type UTDOAInformationUpdateValueCodec struct {
	context q5.BridgeCodecContext
	capture func(UTDOAInformationUpdate, q4.DecodeState,

	) (UTDOAInformationUpdate, q4.Snapshot,

	)
	compare func(UTDOAInformationUpdate, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (UTDOAInformationUpdate,

		error)
	encode func(UTDOAInformationUpdate,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c UTDOAInformationUpdateValueCodec) New(value UTDOAInformationUpdate,

) (UTDOAInformationUpdateAPERValue, error) {
	if c.encode == nil {
		return UTDOAInformationUpdateAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return UTDOAInformationUpdateAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UTDOAInformationUpdateAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return UTDOAInformationUpdateAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c UTDOAInformationUpdateValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (UTDOAInformationUpdateAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return UTDOAInformationUpdateAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return UTDOAInformationUpdateAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return UTDOAInformationUpdateAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return UTDOAInformationUpdateAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return UTDOAInformationUpdateAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c UTDOAInformationUpdateValueCodec) EncodeAPER(value UTDOAInformationUpdateAPERValue, options ...q4.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q4.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q4.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q4.OperationError(err, c.path)
}
func (c UTDOAInformationUpdateValueCodec) encodeBudget(value UTDOAInformationUpdate,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c UTDOAInformationUpdateValueCodec) encodeChanged(value UTDOAInformationUpdate,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeUTDOAInformationResponseIEValueValidateLPPaIEContainer(fields q12.UTDOAInformationResponseIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

) q11.ValidationReport {
	report := func() q11.ValidationReport {
		sealed := q11.ValidationReport{Complete: true}
		*q11.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q11.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q5.ProtocolIEID]int, len(rows))
	counts := make(map[q5.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q11.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q11.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q4.Location{Path: q4.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q12.BridgeUTDOAInformationResponseIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q12.BridgeUTDOAInformationResponseIEValueMethodRule(field.Value)
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.ValueIDMismatch, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q5.TableID {
				sealed := q5.TableID{}
				*q5.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q5.FieldInfo
			related := []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.RepeatedIE, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q5.ValidationSeverityUnrecognized
			if _, globallyKnown := q13.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q5.ValidationSeverityError
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.NotAllowed), RelatedRules: q13.BridgeLppaHandlingRules(q5.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.WrongCriticality, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q13.BridgeLppaValidationRule(q5.WrongCriticality), RelatedRules: []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.WrongOrder, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.WrongOrder), RelatedRules: []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q5.PresenceMandatory && counts[row.ID] == 0 {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.MissingMandatory, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.MissingMandatory), RelatedRules: []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.MissingMandatory), row.Rule}})
		}
		if row.Presence == q5.PresenceConditional {
			q11.BridgeValidationReportMethodAddDeferred(&report, q5.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q11.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeUTDOAInformationUpdateIEValueValidateLPPaIEContainer(fields q9.UTDOAInformationUpdateIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

) q11.ValidationReport {
	report := func() q11.ValidationReport {
		sealed := q11.ValidationReport{Complete: true}
		*q11.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q11.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q5.ProtocolIEID]int, len(rows))
	counts := make(map[q5.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q11.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q11.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q4.Location{Path: q4.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q9.BridgeUTDOAInformationUpdateIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q9.BridgeUTDOAInformationUpdateIEValueMethodRule(field.Value)
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.ValueIDMismatch, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q5.TableID {
				sealed := q5.TableID{}
				*q5.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q5.FieldInfo
			related := []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.RepeatedIE, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q5.ValidationSeverityUnrecognized
			if _, globallyKnown := q13.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q5.ValidationSeverityError
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.NotAllowed), RelatedRules: q13.BridgeLppaHandlingRules(q5.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.WrongCriticality, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q13.BridgeLppaValidationRule(q5.WrongCriticality), RelatedRules: []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.WrongOrder, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.WrongOrder), RelatedRules: []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q5.PresenceMandatory && counts[row.ID] == 0 {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.MissingMandatory, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.MissingMandatory), RelatedRules: []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.MissingMandatory), row.Rule}})
		}
		if row.Presence == q5.PresenceConditional {
			q11.BridgeValidationReportMethodAddDeferred(&report, q5.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q11.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeAssistanceInformationFeedbackIEValueValidateLPPaIEContainer(fields AssistanceInformationFeedbackIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

) q11.ValidationReport {
	report := func() q11.ValidationReport {
		sealed := q11.ValidationReport{Complete: true}
		*q11.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q11.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q5.ProtocolIEID]int, len(rows))
	counts := make(map[q5.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q11.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q11.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q4.Location{Path: q4.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.ValueIDMismatch, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q5.TableID {
				sealed := q5.TableID{}
				*q5.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q5.FieldInfo
			related := []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.RepeatedIE, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q5.ValidationSeverityUnrecognized
			if _, globallyKnown := q13.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q5.ValidationSeverityError
			}
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.NotAllowed), RelatedRules: q13.BridgeLppaHandlingRules(q5.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.WrongCriticality, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q13.BridgeLppaValidationRule(q5.WrongCriticality), RelatedRules: []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.WrongOrder, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.WrongOrder), RelatedRules: []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q5.PresenceMandatory && counts[row.ID] == 0 {
			q11.BridgeValidationReportMethodAddIssue(&report, q11.ValidationIssue{Code: q5.MissingMandatory, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q13.BridgeLppaValidationRule(q5.MissingMandatory), RelatedRules: []q4.SourceRule{q13.BridgeLppaAdoptedRule(q5.MissingMandatory), row.Rule}})
		}
		if row.Presence == q5.PresenceConditional {
			q11.BridgeValidationReportMethodAddDeferred(&report, q5.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q11.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// assistanceInformationFeedbackIEValueProtocolOpenValue is the concrete protocolOpenValue[AssistanceInformationFeedbackIEValue].
type AssistanceInformationFeedbackIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) AssistanceInformationFeedbackIEValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (AssistanceInformationFeedbackIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

func BridgeAssistanceInformationFeedbackIEValueCaptureLPPaProtocolIEField(v *AssistanceInformationFeedbackIEField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(v.Value.captureFraming())
	v.Value = v.Value.captureSemantics(*s)
	s.Child(v.Value.captureSnapshot())
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeAssistanceInformationFeedbackIEValueCompareLPPaProtocolIEField(v *AssistanceInformationFeedbackIEField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q14.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q14.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// uTDOAInformationResponseIEValueProtocolOpenValue is the concrete protocolOpenValue[UTDOAInformationResponseIEValue].
type UTDOAInformationResponseIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) q12.UTDOAInformationResponseIEValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (q12.UTDOAInformationResponseIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

// uTDOAInformationUpdateIEValueProtocolOpenValue is the concrete protocolOpenValue[UTDOAInformationUpdateIEValue].
type UTDOAInformationUpdateIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) q9.UTDOAInformationUpdateIEValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (q9.UTDOAInformationUpdateIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

func BridgeUTDOAInformationUpdateIEValueCaptureLPPaProtocolIEField(v *q9.UTDOAInformationUpdateIEField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q9.BridgeUTDOAInformationUpdateIEFieldFieldStream(v))
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q9.BridgeUTDOAInformationUpdateIEValueMethodCaptureFraming(v.Value))
	v.Value = q9.BridgeUTDOAInformationUpdateIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(q9.BridgeUTDOAInformationUpdateIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, q9.BridgeUTDOAInformationUpdateIEFieldFieldReplay(v), *q9.BridgeUTDOAInformationUpdateIEFieldFieldWithoutReplay(v))
}
func BridgeUTDOAInformationUpdateIEValueCompareLPPaProtocolIEField(v *q9.UTDOAInformationUpdateIEField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q14.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q14.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q9.BridgeUTDOAInformationUpdateIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *q9.BridgeUTDOAInformationUpdateIEFieldFieldReplay(v), *q9.BridgeUTDOAInformationUpdateIEFieldFieldWithoutReplay(v))
}

// AssistanceInformationFeedbackAPERValue is the concrete APERValue[AssistanceInformationFeedback].
type AssistanceInformationFeedbackAPERValue struct {
	context q5.BridgeCodecContext
	Value   AssistanceInformationFeedback

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v AssistanceInformationFeedbackAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v AssistanceInformationFeedbackAPERValue) WithoutReplay() AssistanceInformationFeedbackAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// UTDOAInformationResponseAPERValue is the concrete APERValue[UTDOAInformationResponse].
type UTDOAInformationResponseAPERValue struct {
	context q5.BridgeCodecContext
	Value   UTDOAInformationResponse

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v UTDOAInformationResponseAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v UTDOAInformationResponseAPERValue) WithoutReplay() UTDOAInformationResponseAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// UTDOAInformationUpdateAPERValue is the concrete APERValue[UTDOAInformationUpdate].
type UTDOAInformationUpdateAPERValue struct {
	context q5.BridgeCodecContext
	Value   UTDOAInformationUpdate

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v UTDOAInformationUpdateAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v UTDOAInformationUpdateAPERValue) WithoutReplay() UTDOAInformationUpdateAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// AddOTDOACellsComplete carries a complete AddOTDOACells encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type AddOTDOACellsComplete struct {
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         q15.AddOTDOACells
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *AddOTDOACellsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := q16.BridgeMarshalAPERAddOTDOACellsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes AddOTDOACells from APER format.
func (v *AddOTDOACellsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AddOTDOACells with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AddOTDOACellsComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "AddOTDOACells")
	}
	value, err := BridgeUnmarshalAPERAddOTDOACellsFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "AddOTDOACells")
	}
	padding, err := q4.CaptureFinalBits(bb, "AddOTDOACells")
	if err != nil {
		return q7.WrapDecodePath(err, "AddOTDOACells")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERAddOTDOACells encodes a AddOTDOACells list to APER.
func BridgeMarshalAPERAddOTDOACells(list AddOTDOACellsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERAddOTDOACells decodes a AddOTDOACells list from APER.
func BridgeUnmarshalAPERAddOTDOACells(data []byte) (AddOTDOACellsComplete, error) {
	var value AddOTDOACellsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERAddOTDOACellsFrom decodes a AddOTDOACells list from bb.
func BridgeUnmarshalAPERAddOTDOACellsFrom(bb *q4.BitBuffer) (q15.AddOTDOACells, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q15.BridgeAsn1cAPERAddOTDOACellsListValue
	if err := BridgeUnmarshalAPERAddOTDOACellsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERAddOTDOACellsInto(v *q15.BridgeAsn1cAPERAddOTDOACellsListValue, bb *q4.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(q15.AddOTDOACells, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 3840, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q15.AddOTDOACellsElem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := q15.BridgeAddOTDOACellsElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := q4.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return q7.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// AddOTDOACellInformationComplete carries a complete AddOTDOACellInformation encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type AddOTDOACellInformationComplete struct {
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         q15.AddOTDOACellInformation
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *AddOTDOACellInformationComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := q16.BridgeMarshalAPERAddOTDOACellInformationTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes AddOTDOACellInformation from APER format.
func (v *AddOTDOACellInformationComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AddOTDOACellInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AddOTDOACellInformationComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "AddOTDOACellInformation")
	}
	value, err := BridgeUnmarshalAPERAddOTDOACellInformationFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "AddOTDOACellInformation")
	}
	padding, err := q4.CaptureFinalBits(bb, "AddOTDOACellInformation")
	if err != nil {
		return q7.WrapDecodePath(err, "AddOTDOACellInformation")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERAddOTDOACellInformation encodes a AddOTDOACellInformation list to APER.
func BridgeMarshalAPERAddOTDOACellInformation(list AddOTDOACellInformationComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERAddOTDOACellInformation decodes a AddOTDOACellInformation list from APER.
func BridgeUnmarshalAPERAddOTDOACellInformation(data []byte) (AddOTDOACellInformationComplete, error) {
	var value AddOTDOACellInformationComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERAddOTDOACellInformationFrom decodes a AddOTDOACellInformation list from bb.
func BridgeUnmarshalAPERAddOTDOACellInformationFrom(bb *q4.BitBuffer) (q15.AddOTDOACellInformation, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q15.BridgeAsn1cAPERAddOTDOACellInformationListValue
	if err := BridgeUnmarshalAPERAddOTDOACellInformationInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERAddOTDOACellInformationInto(v *q15.BridgeAsn1cAPERAddOTDOACellInformationListValue, bb *q4.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(q15.AddOTDOACellInformation, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q15.OTDOACellInformationItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := q15.BridgeOTDOACellInformationItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := q4.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return q7.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// AssistanceInformationFailureListComplete carries a complete AssistanceInformationFailureList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type AssistanceInformationFailureListComplete struct {
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         q10.AssistanceInformationFailureList
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *AssistanceInformationFailureListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := q9.BridgeMarshalAPERAssistanceInformationFailureListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes AssistanceInformationFailureList from APER format.
func (v *AssistanceInformationFailureListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AssistanceInformationFailureList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AssistanceInformationFailureListComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "AssistanceInformationFailureList")
	}
	value, err := BridgeUnmarshalAPERAssistanceInformationFailureListFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "AssistanceInformationFailureList")
	}
	padding, err := q4.CaptureFinalBits(bb, "AssistanceInformationFailureList")
	if err != nil {
		return q7.WrapDecodePath(err, "AssistanceInformationFailureList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERAssistanceInformationFailureList encodes a AssistanceInformationFailureList list to APER.
func BridgeMarshalAPERAssistanceInformationFailureList(list AssistanceInformationFailureListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERAssistanceInformationFailureList decodes a AssistanceInformationFailureList list from APER.
func BridgeUnmarshalAPERAssistanceInformationFailureList(data []byte) (AssistanceInformationFailureListComplete, error) {
	var value AssistanceInformationFailureListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERAssistanceInformationFailureListFrom decodes a AssistanceInformationFailureList list from bb.
func BridgeUnmarshalAPERAssistanceInformationFailureListFrom(bb *q4.BitBuffer) (q10.AssistanceInformationFailureList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q11.BridgeAsn1cAPERAssistanceInformationFailureListListValue
	if err := BridgeUnmarshalAPERAssistanceInformationFailureListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERAssistanceInformationFailureListInto(v *q11.BridgeAsn1cAPERAssistanceInformationFailureListListValue, bb *q4.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(q10.AssistanceInformationFailureList, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q10.AssistanceInformationFailureListElem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := q10.BridgeAssistanceInformationFailureListElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := q4.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return q7.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// CriticalityDiagnosticsIEListComplete carries a complete CriticalityDiagnosticsIEList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type CriticalityDiagnosticsIEListComplete struct {
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         q10.CriticalityDiagnosticsIEList
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *CriticalityDiagnosticsIEListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := q9.BridgeMarshalAPERCriticalityDiagnosticsIEListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes CriticalityDiagnosticsIEList from APER format.
func (v *CriticalityDiagnosticsIEListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes CriticalityDiagnosticsIEList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *CriticalityDiagnosticsIEListComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "CriticalityDiagnosticsIEList")
	}
	value, err := BridgeUnmarshalAPERCriticalityDiagnosticsIEListFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "CriticalityDiagnosticsIEList")
	}
	padding, err := q4.CaptureFinalBits(bb, "CriticalityDiagnosticsIEList")
	if err != nil {
		return q7.WrapDecodePath(err, "CriticalityDiagnosticsIEList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERCriticalityDiagnosticsIEList encodes a CriticalityDiagnosticsIEList list to APER.
func BridgeMarshalAPERCriticalityDiagnosticsIEList(list CriticalityDiagnosticsIEListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERCriticalityDiagnosticsIEList decodes a CriticalityDiagnosticsIEList list from APER.
func BridgeUnmarshalAPERCriticalityDiagnosticsIEList(data []byte) (CriticalityDiagnosticsIEListComplete, error) {
	var value CriticalityDiagnosticsIEListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERCriticalityDiagnosticsIEListFrom decodes a CriticalityDiagnosticsIEList list from bb.
func BridgeUnmarshalAPERCriticalityDiagnosticsIEListFrom(bb *q4.BitBuffer) (q10.CriticalityDiagnosticsIEList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q11.BridgeAsn1cAPERCriticalityDiagnosticsIEListListValue
	if err := BridgeUnmarshalAPERCriticalityDiagnosticsIEListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERCriticalityDiagnosticsIEListInto(v *q11.BridgeAsn1cAPERCriticalityDiagnosticsIEListListValue, bb *q4.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(q10.CriticalityDiagnosticsIEList, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q10.CriticalityDiagnosticsIEListElem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := q10.BridgeCriticalityDiagnosticsIEListElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := q4.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return q7.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// InterRATMeasurementQuantitiesComplete carries a complete InterRATMeasurementQuantities encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type InterRATMeasurementQuantitiesComplete struct {
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         q17.InterRATMeasurementQuantities
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *InterRATMeasurementQuantitiesComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := q9.BridgeMarshalAPERInterRATMeasurementQuantitiesTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes InterRATMeasurementQuantities from APER format.
func (v *InterRATMeasurementQuantitiesComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes InterRATMeasurementQuantities with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *InterRATMeasurementQuantitiesComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "InterRATMeasurementQuantities")
	}
	value, err := BridgeUnmarshalAPERInterRATMeasurementQuantitiesFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "InterRATMeasurementQuantities")
	}
	padding, err := q4.CaptureFinalBits(bb, "InterRATMeasurementQuantities")
	if err != nil {
		return q7.WrapDecodePath(err, "InterRATMeasurementQuantities")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERInterRATMeasurementQuantities encodes a InterRATMeasurementQuantities list to APER.
func BridgeMarshalAPERInterRATMeasurementQuantities(list InterRATMeasurementQuantitiesComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERInterRATMeasurementQuantities decodes a InterRATMeasurementQuantities list from APER.
func BridgeUnmarshalAPERInterRATMeasurementQuantities(data []byte) (InterRATMeasurementQuantitiesComplete, error) {
	var value InterRATMeasurementQuantitiesComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERInterRATMeasurementQuantitiesFrom decodes a InterRATMeasurementQuantities list from bb.
func BridgeUnmarshalAPERInterRATMeasurementQuantitiesFrom(bb *q4.BitBuffer) (q17.InterRATMeasurementQuantities, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q11.BridgeAsn1cAPERInterRATMeasurementQuantitiesListValue
	if err := BridgeUnmarshalAPERInterRATMeasurementQuantitiesInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERInterRATMeasurementQuantitiesInto(v *q11.BridgeAsn1cAPERInterRATMeasurementQuantitiesListValue, bb *q4.BitBuffer) error {
	v.Value = make(q17.InterRATMeasurementQuantities, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q17.InterRATMeasurementQuantitiesItemIEValueProtocolIESingleContainer
			if err := q17.BridgeInterRATMeasurementQuantitiesItemIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := q4.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return q7.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// UnmarshalAPERMBSFNsubframeConfigurationFrom decodes a MBSFNsubframeConfiguration list from bb.
func BridgeUnmarshalAPERMBSFNsubframeConfigurationFrom(bb *q4.BitBuffer) (q11.MBSFNsubframeConfiguration, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q11.BridgeAsn1cAPERMBSFNsubframeConfigurationListValue
	if err := BridgeUnmarshalAPERMBSFNsubframeConfigurationInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERMBSFNsubframeConfigurationInto(v *q11.BridgeAsn1cAPERMBSFNsubframeConfigurationListValue, bb *q4.BitBuffer) error {
	v.Value = make(q11.MBSFNsubframeConfiguration, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q11.MBSFNsubframeConfigurationValue
			if err := q11.BridgeMBSFNsubframeConfigurationValueMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := q4.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return q7.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AddOTDOACellInformationComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q10.BridgeReceivedFormAt(v.received, v.receivedBytes, "AddOTDOACellInformationComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AddOTDOACellInformationComplete) WithoutReplay() AddOTDOACellInformationComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero AddOTDOACellInformationComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AddOTDOACellsComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q10.BridgeReceivedFormAt(v.received, v.receivedBytes, "AddOTDOACellsComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AddOTDOACellsComplete) WithoutReplay() AddOTDOACellsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero AddOTDOACellsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AssistanceInformationFailureListComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q10.BridgeReceivedFormAt(v.received, v.receivedBytes, "AssistanceInformationFailureListComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AssistanceInformationFailureListComplete) WithoutReplay() AssistanceInformationFailureListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero AssistanceInformationFailureListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *CriticalityDiagnosticsIEListComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q10.BridgeReceivedFormAt(v.received, v.receivedBytes, "CriticalityDiagnosticsIEListComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v CriticalityDiagnosticsIEListComplete) WithoutReplay() CriticalityDiagnosticsIEListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero CriticalityDiagnosticsIEListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *InterRATMeasurementQuantitiesComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q10.BridgeReceivedFormAt(v.received, v.receivedBytes, "InterRATMeasurementQuantitiesComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InterRATMeasurementQuantitiesComplete) WithoutReplay() InterRATMeasurementQuantitiesComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero InterRATMeasurementQuantitiesComplete
	v.perPadding = zero.perPadding
	return v
}
func (v *AddOTDOACellInformationComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "AddOTDOACellInformationComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "AddOTDOACellInformationComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaAddOTDOACellInformationComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "AddOTDOACellInformationComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "AddOTDOACellInformationComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "AddOTDOACellInformationComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "AddOTDOACellInformationComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "AddOTDOACellInformationComplete")
}
func (v *AddOTDOACellInformationComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *AddOTDOACellInformationComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *AddOTDOACellInformationComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaAddOTDOACellInformationComplete(v, &s)
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
func (v *AddOTDOACellInformationComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AddOTDOACellInformationComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q16.BridgeMarshalAPERAddOTDOACellInformationTo(value.Value, bb, fresh); err != nil {
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
func (v *AddOTDOACellsComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "AddOTDOACellsComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "AddOTDOACellsComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaAddOTDOACellsComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "AddOTDOACellsComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "AddOTDOACellsComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "AddOTDOACellsComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "AddOTDOACellsComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "AddOTDOACellsComplete")
}
func (v *AddOTDOACellsComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *AddOTDOACellsComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *AddOTDOACellsComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaAddOTDOACellsComplete(v, &s)
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
func (v *AddOTDOACellsComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AddOTDOACellsComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q16.BridgeMarshalAPERAddOTDOACellsTo(value.Value, bb, fresh); err != nil {
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
func (v *AssistanceInformationFailureListComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "AssistanceInformationFailureListComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "AssistanceInformationFailureListComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaAssistanceInformationFailureListComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "AssistanceInformationFailureListComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "AssistanceInformationFailureListComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "AssistanceInformationFailureListComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "AssistanceInformationFailureListComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "AssistanceInformationFailureListComplete")
}
func (v *AssistanceInformationFailureListComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *AssistanceInformationFailureListComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *AssistanceInformationFailureListComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaAssistanceInformationFailureListComplete(v, &s)
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
func (v *AssistanceInformationFailureListComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AssistanceInformationFailureListComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q9.BridgeMarshalAPERAssistanceInformationFailureListTo(value.Value, bb, fresh); err != nil {
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
func (v *CriticalityDiagnosticsIEListComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "CriticalityDiagnosticsIEListComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "CriticalityDiagnosticsIEListComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaCriticalityDiagnosticsIEListComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "CriticalityDiagnosticsIEListComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "CriticalityDiagnosticsIEListComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "CriticalityDiagnosticsIEListComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "CriticalityDiagnosticsIEListComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "CriticalityDiagnosticsIEListComplete")
}
func (v *CriticalityDiagnosticsIEListComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *CriticalityDiagnosticsIEListComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *CriticalityDiagnosticsIEListComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaCriticalityDiagnosticsIEListComplete(v, &s)
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
func (v *CriticalityDiagnosticsIEListComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *CriticalityDiagnosticsIEListComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q9.BridgeMarshalAPERCriticalityDiagnosticsIEListTo(value.Value, bb, fresh); err != nil {
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
func (v *InterRATMeasurementQuantitiesComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "InterRATMeasurementQuantitiesComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "InterRATMeasurementQuantitiesComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaInterRATMeasurementQuantitiesComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "InterRATMeasurementQuantitiesComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "InterRATMeasurementQuantitiesComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "InterRATMeasurementQuantitiesComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "InterRATMeasurementQuantitiesComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "InterRATMeasurementQuantitiesComplete")
}
func (v *InterRATMeasurementQuantitiesComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *InterRATMeasurementQuantitiesComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *InterRATMeasurementQuantitiesComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaInterRATMeasurementQuantitiesComplete(v, &s)
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
func (v *InterRATMeasurementQuantitiesComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *InterRATMeasurementQuantitiesComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q9.BridgeMarshalAPERInterRATMeasurementQuantitiesTo(value.Value, bb, fresh); err != nil {
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
func (v *AddOTDOACellInformationComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "AddOTDOACellInformationComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded AddOTDOACellInformationComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaAddOTDOACellInformationComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = AddOTDOACellInformationComplete{}
		return report, q4.OperationError(err, "AddOTDOACellInformationComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "AddOTDOACellInformationComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *AddOTDOACellsComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "AddOTDOACellsComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded AddOTDOACellsComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaAddOTDOACellsComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = AddOTDOACellsComplete{}
		return report, q4.OperationError(err, "AddOTDOACellsComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "AddOTDOACellsComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *AssistanceInformationFailureListComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "AssistanceInformationFailureListComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded AssistanceInformationFailureListComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaAssistanceInformationFailureListComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = AssistanceInformationFailureListComplete{}
		return report, q4.OperationError(err, "AssistanceInformationFailureListComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "AssistanceInformationFailureListComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *CriticalityDiagnosticsIEListComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "CriticalityDiagnosticsIEListComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded CriticalityDiagnosticsIEListComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaCriticalityDiagnosticsIEListComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = CriticalityDiagnosticsIEListComplete{}
		return report, q4.OperationError(err, "CriticalityDiagnosticsIEListComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "CriticalityDiagnosticsIEListComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *InterRATMeasurementQuantitiesComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "InterRATMeasurementQuantitiesComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded InterRATMeasurementQuantitiesComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaInterRATMeasurementQuantitiesComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = InterRATMeasurementQuantitiesComplete{}
		return report, q4.OperationError(err, "InterRATMeasurementQuantitiesComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "InterRATMeasurementQuantitiesComplete")
}

// MarshalAPERAddOTDOACells encodes a complete named list.
func MarshalAPERAddOTDOACells(v AddOTDOACellsComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERAddOTDOACellInformation encodes a complete named list.
func MarshalAPERAddOTDOACellInformation(v AddOTDOACellInformationComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERAssistanceInformationFailureList encodes a complete named list.
func MarshalAPERAssistanceInformationFailureList(v AssistanceInformationFailureListComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERCriticalityDiagnosticsIEList encodes a complete named list.
func MarshalAPERCriticalityDiagnosticsIEList(v CriticalityDiagnosticsIEListComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERInterRATMeasurementQuantities encodes a complete named list.
func MarshalAPERInterRATMeasurementQuantities(v InterRATMeasurementQuantitiesComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERAddOTDOACells decodes a complete named list.
func UnmarshalAPERAddOTDOACells(data []byte, options ...q4.DecodeOption) (AddOTDOACellsComplete, q4.DecodeReport, error) {
	var v AddOTDOACellsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERAddOTDOACellInformation decodes a complete named list.
func UnmarshalAPERAddOTDOACellInformation(data []byte, options ...q4.DecodeOption) (AddOTDOACellInformationComplete, q4.DecodeReport, error) {
	var v AddOTDOACellInformationComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERAssistanceInformationFailureList decodes a complete named list.
func UnmarshalAPERAssistanceInformationFailureList(data []byte, options ...q4.DecodeOption) (AssistanceInformationFailureListComplete, q4.DecodeReport, error) {
	var v AssistanceInformationFailureListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERCriticalityDiagnosticsIEList decodes a complete named list.
func UnmarshalAPERCriticalityDiagnosticsIEList(data []byte, options ...q4.DecodeOption) (CriticalityDiagnosticsIEListComplete, q4.DecodeReport, error) {
	var v CriticalityDiagnosticsIEListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERInterRATMeasurementQuantities decodes a complete named list.
func UnmarshalAPERInterRATMeasurementQuantities(data []byte, options ...q4.DecodeOption) (InterRATMeasurementQuantitiesComplete, q4.DecodeReport, error) {
	var v InterRATMeasurementQuantitiesComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UTDOAInformationResponse represents the ASN.1 type UTDOAInformationResponse (SEQUENCE).
type UTDOAInformationResponse struct {
	replay           q4.Snapshot
	stream           q4.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    q4.WireSpan
	ProtocolIEs      q12.UTDOAInformationResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                    `asn1:"-" json:"-"`
	extCount         int64                                   `asn1:"-" json:"-"`
	extPresent       []bool                                  `asn1:"-" json:"-"`
	extData          [][]byte                                `asn1:"-" json:"-"`
	perPadding       q4.FinalPadding                         `asn1:"-" json:"-"`
	perExtPadding    []q4.CompletePadding                    `asn1:"-" json:"-"`
	extOrigin        []q4.OpaqueOrigin
	extWire          []q4.WireSpan
}

// UTDOAInformationUpdate represents the ASN.1 type UTDOAInformationUpdate (SEQUENCE).
type UTDOAInformationUpdate struct {
	replay           q4.Snapshot
	stream           q4.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    q4.WireSpan
	ProtocolIEs      q9.UTDOAInformationUpdateIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                 `asn1:"-" json:"-"`
	extCount         int64                                `asn1:"-" json:"-"`
	extPresent       []bool                               `asn1:"-" json:"-"`
	extData          [][]byte                             `asn1:"-" json:"-"`
	perPadding       q4.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding    []q4.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin        []q4.OpaqueOrigin
	extWire          []q4.WireSpan
}

// AssistanceInformationFeedback represents the ASN.1 type AssistanceInformationFeedback (SEQUENCE).
type AssistanceInformationFeedback struct {
	replay           q4.Snapshot
	stream           q4.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    q4.WireSpan
	ProtocolIEs      AssistanceInformationFeedbackIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                     `asn1:"-" json:"-"`
	extCount         int64                                    `asn1:"-" json:"-"`
	extPresent       []bool                                   `asn1:"-" json:"-"`
	extData          [][]byte                                 `asn1:"-" json:"-"`
	perPadding       q4.FinalPadding                          `asn1:"-" json:"-"`
	perExtPadding    []q4.CompletePadding                     `asn1:"-" json:"-"`
	extOrigin        []q4.OpaqueOrigin
	extWire          []q4.WireSpan
}

// MarshalAPER encodes UTDOAInformationResponse to APER format.
func (v *UTDOAInformationResponse) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UTDOAInformationResponse) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := q4.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = q10.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := q4.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := q4.EncodeCollection(bb, int64(len(v.ProtocolIEs)), q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := q12.BridgeUTDOAInformationResponseIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q6.Errorf("%w: extension bitmap index %d", q4.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q4.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q4.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	q4.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	q4.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes UTDOAInformationResponse from APER format.
func (v *UTDOAInformationResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UTDOAInformationResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UTDOAInformationResponse) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "UTDOAInformationResponse")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "UTDOAInformationResponse")
	}
	padding, err := q4.CaptureFinalBits(bb, "UTDOAInformationResponse")
	if err != nil {
		return q7.WrapDecodePath(err, "UTDOAInformationResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UTDOAInformationResponse) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UTDOAInformationResponse{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(q12.UTDOAInformationResponseIEContainer, 0)
	_, errCollection_protocolies := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem q12.UTDOAInformationResponseIEField
			if err := q12.BridgeUTDOAInformationResponseIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			if next, err := q4.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return q7.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q7.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		if err := q4.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := q4.ChargeSlice[q4.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]q4.OpaqueOrigin, len(v.extData))
		if err := q4.ChargeSlice[q4.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]q4.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q4.DecodeOpaqueOpenTypeAligned(bb, q4.UnknownSelector, q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
				if err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(q4.UnknownExtension, i); err != nil {
					return err
				}
				var retained q4.WireSpan
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

// MarshalAPER encodes UTDOAInformationUpdate to APER format.
func (v *UTDOAInformationUpdate) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *UTDOAInformationUpdate) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := q4.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = q10.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := q4.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := q4.EncodeCollection(bb, int64(len(v.ProtocolIEs)), q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := q9.BridgeUTDOAInformationUpdateIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q6.Errorf("%w: extension bitmap index %d", q4.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q4.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q4.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	q4.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	q4.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes UTDOAInformationUpdate from APER format.
func (v *UTDOAInformationUpdate) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes UTDOAInformationUpdate with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *UTDOAInformationUpdate) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "UTDOAInformationUpdate")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "UTDOAInformationUpdate")
	}
	padding, err := q4.CaptureFinalBits(bb, "UTDOAInformationUpdate")
	if err != nil {
		return q7.WrapDecodePath(err, "UTDOAInformationUpdate")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *UTDOAInformationUpdate) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UTDOAInformationUpdate{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(q9.UTDOAInformationUpdateIEContainer, 0)
	_, errCollection_protocolies := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem q9.UTDOAInformationUpdateIEField
			if err := q9.BridgeUTDOAInformationUpdateIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			if next, err := q4.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return q7.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q7.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		if err := q4.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := q4.ChargeSlice[q4.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]q4.OpaqueOrigin, len(v.extData))
		if err := q4.ChargeSlice[q4.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]q4.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q4.DecodeOpaqueOpenTypeAligned(bb, q4.UnknownSelector, q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
				if err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(q4.UnknownExtension, i); err != nil {
					return err
				}
				var retained q4.WireSpan
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

// MarshalAPER encodes AssistanceInformationFeedback to APER format.
func (v *AssistanceInformationFeedback) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *AssistanceInformationFeedback) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := q4.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = q10.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := q4.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := q4.EncodeCollection(bb, int64(len(v.ProtocolIEs)), q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q6.Errorf("%w: extension bitmap index %d", q4.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q4.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q4.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	q4.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	q4.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes AssistanceInformationFeedback from APER format.
func (v *AssistanceInformationFeedback) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AssistanceInformationFeedback with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AssistanceInformationFeedback) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "AssistanceInformationFeedback")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "AssistanceInformationFeedback")
	}
	padding, err := q4.CaptureFinalBits(bb, "AssistanceInformationFeedback")
	if err != nil {
		return q7.WrapDecodePath(err, "AssistanceInformationFeedback")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *AssistanceInformationFeedback) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationFeedback{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(AssistanceInformationFeedbackIEContainer, 0)
	_, errCollection_protocolies := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem AssistanceInformationFeedbackIEField
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			if next, err := q4.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return q7.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q7.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		if err := q4.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := q4.ChargeSlice[q4.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]q4.OpaqueOrigin, len(v.extData))
		if err := q4.ChargeSlice[q4.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]q4.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q4.DecodeOpaqueOpenTypeAligned(bb, q4.UnknownSelector, q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
				if err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(q4.UnknownExtension, i); err != nil {
					return err
				}
				var retained q4.WireSpan
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
func (v *AssistanceInformationFeedback) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q10.BridgeReceivedFormAt(v.received, v.receivedBytes, "AssistanceInformationFeedback", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AssistanceInformationFeedback) WithoutReplay() AssistanceInformationFeedback {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero AssistanceInformationFeedback
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UTDOAInformationResponse) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q10.BridgeReceivedFormAt(v.received, v.receivedBytes, "UTDOAInformationResponse", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UTDOAInformationResponse) WithoutReplay() UTDOAInformationResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero UTDOAInformationResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *UTDOAInformationUpdate) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q10.BridgeReceivedFormAt(v.received, v.receivedBytes, "UTDOAInformationUpdate", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v UTDOAInformationUpdate) WithoutReplay() UTDOAInformationUpdate {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero UTDOAInformationUpdate
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *AssistanceInformationFeedback) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *AssistanceInformationFeedback) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("AssistanceInformationFeedback.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("AssistanceInformationFeedback.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *AssistanceInformationFeedback) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("AssistanceInformationFeedback.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("AssistanceInformationFeedback.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UTDOAInformationResponse) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UTDOAInformationResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("UTDOAInformationResponse.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("UTDOAInformationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UTDOAInformationResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("UTDOAInformationResponse.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("UTDOAInformationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *UTDOAInformationUpdate) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *UTDOAInformationUpdate) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("UTDOAInformationUpdate.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("UTDOAInformationUpdate.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *UTDOAInformationUpdate) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("UTDOAInformationUpdate.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("UTDOAInformationUpdate.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *AssistanceInformationFeedback) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "AssistanceInformationFeedback")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "AssistanceInformationFeedback")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaAssistanceInformationFeedback(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "AssistanceInformationFeedback")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "AssistanceInformationFeedback")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "AssistanceInformationFeedback")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "AssistanceInformationFeedback")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "AssistanceInformationFeedback")
}
func (v *AssistanceInformationFeedback) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *AssistanceInformationFeedback) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *AssistanceInformationFeedback) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaAssistanceInformationFeedback(v, &s)
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
func (v *AssistanceInformationFeedback) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AssistanceInformationFeedback) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
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
func (v *UTDOAInformationResponse) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "UTDOAInformationResponse")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "UTDOAInformationResponse")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaUTDOAInformationResponse(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "UTDOAInformationResponse")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "UTDOAInformationResponse")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "UTDOAInformationResponse")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "UTDOAInformationResponse")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "UTDOAInformationResponse")
}
func (v *UTDOAInformationResponse) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *UTDOAInformationResponse) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *UTDOAInformationResponse) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaUTDOAInformationResponse(v, &s)
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
func (v *UTDOAInformationResponse) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *UTDOAInformationResponse) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
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
func (v *UTDOAInformationUpdate) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "UTDOAInformationUpdate")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "UTDOAInformationUpdate")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaUTDOAInformationUpdate(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "UTDOAInformationUpdate")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "UTDOAInformationUpdate")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "UTDOAInformationUpdate")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "UTDOAInformationUpdate")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "UTDOAInformationUpdate")
}
func (v *UTDOAInformationUpdate) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *UTDOAInformationUpdate) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *UTDOAInformationUpdate) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaUTDOAInformationUpdate(v, &s)
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
func (v *UTDOAInformationUpdate) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *UTDOAInformationUpdate) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
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
func (v *AssistanceInformationFeedback) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "AssistanceInformationFeedback")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded AssistanceInformationFeedback
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaAssistanceInformationFeedback(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = AssistanceInformationFeedback{}
		return report, q4.OperationError(err, "AssistanceInformationFeedback")
	}
	*v = decoded
	return report, q4.OperationError(nil, "AssistanceInformationFeedback")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *UTDOAInformationResponse) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "UTDOAInformationResponse")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded UTDOAInformationResponse
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaUTDOAInformationResponse(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = UTDOAInformationResponse{}
		return report, q4.OperationError(err, "UTDOAInformationResponse")
	}
	*v = decoded
	return report, q4.OperationError(nil, "UTDOAInformationResponse")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *UTDOAInformationUpdate) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "UTDOAInformationUpdate")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded UTDOAInformationUpdate
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaUTDOAInformationUpdate(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = UTDOAInformationUpdate{}
		return report, q4.OperationError(err, "UTDOAInformationUpdate")
	}
	*v = decoded
	return report, q4.OperationError(nil, "UTDOAInformationUpdate")
}
func BridgeCaptureLPPaAddOTDOACellInformationComplete(v *AddOTDOACellInformationComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q15.BridgeCaptureLPPaAddOTDOACellInformation(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaAddOTDOACellInformationComplete(v *AddOTDOACellInformationComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q15.BridgeCompareLPPaAddOTDOACellInformation(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaAddOTDOACellsComplete(v *AddOTDOACellsComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q15.BridgeCaptureLPPaAddOTDOACells(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaAddOTDOACellsComplete(v *AddOTDOACellsComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q15.BridgeCompareLPPaAddOTDOACells(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaAssistanceInformationFailureListComplete(v *AssistanceInformationFailureListComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q11.BridgeCaptureLPPaAssistanceInformationFailureList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaAssistanceInformationFailureListComplete(v *AssistanceInformationFailureListComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q11.BridgeCompareLPPaAssistanceInformationFailureList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaAssistanceInformationFeedback(v *AssistanceInformationFeedback, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgeAssistanceInformationFeedbackIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaAssistanceInformationFeedback(v *AssistanceInformationFeedback, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeAssistanceInformationFeedbackIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaAssistanceInformationFeedbackIEValue(v *AssistanceInformationFeedbackIEValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q5.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
		case q5.ProtocolIEID(24):
			{
				f := s.Begin()
				s.Bool(v.rowAssistanceInformationFailureList == nil)
				if v.rowAssistanceInformationFailureList != nil {
					q11.BridgeCaptureLPPaAssistanceInformationFailureList(v.rowAssistanceInformationFailureList, s)
				}
				s.End(f, nil, false)
			}
		case q5.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					q11.BridgeCaptureLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v AssistanceInformationFeedbackIEValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v AssistanceInformationFeedbackIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v AssistanceInformationFeedbackIEValue) captureSemantics(s q4.SemanticCapture) AssistanceInformationFeedbackIEValue {
	BridgeCaptureLPPaAssistanceInformationFeedbackIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaAssistanceInformationFeedbackIEValue(v *AssistanceInformationFeedbackIEValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q14.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case q5.ProtocolIEID(24):
			{
				f := s.Begin()
				s.Bool(v.rowAssistanceInformationFailureList == nil)
				if v.rowAssistanceInformationFailureList != nil {
					q11.BridgeCompareLPPaAssistanceInformationFailureList(v.rowAssistanceInformationFailureList, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					q11.BridgeCompareLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v AssistanceInformationFeedbackIEValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaAssistanceInformationFeedbackIEValue(&v, &s)
	return s
}
func (v AssistanceInformationFeedbackIEValue) WithoutReplay() AssistanceInformationFeedbackIEValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCaptureLPPaCriticalityDiagnosticsIEListComplete(v *CriticalityDiagnosticsIEListComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q11.BridgeCaptureLPPaCriticalityDiagnosticsIEList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaCriticalityDiagnosticsIEListComplete(v *CriticalityDiagnosticsIEListComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q11.BridgeCompareLPPaCriticalityDiagnosticsIEList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaInterRATMeasurementQuantitiesComplete(v *InterRATMeasurementQuantitiesComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q9.BridgeCaptureLPPaInterRATMeasurementQuantities(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaInterRATMeasurementQuantitiesComplete(v *InterRATMeasurementQuantitiesComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q9.BridgeCompareLPPaInterRATMeasurementQuantities(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaUTDOAInformationResponse(v *UTDOAInformationResponse, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q16.BridgeUTDOAInformationResponseIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaUTDOAInformationResponse(v *UTDOAInformationResponse, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q16.BridgeUTDOAInformationResponseIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaUTDOAInformationUpdate(v *UTDOAInformationUpdate, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgeUTDOAInformationUpdateIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaUTDOAInformationUpdate(v *UTDOAInformationUpdate, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeUTDOAInformationUpdateIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}

type AssistanceInformationFeedbackIEValue struct {
	id                                  q5.ProtocolIEID
	withoutReplay                       bool
	received                            q4.WireSpan
	replay                              q4.Snapshot
	opaque                              *q4.OpaqueOpenType
	isOpaque                            bool
	rowAssistanceInformationFailureList *q10.AssistanceInformationFailureList
	rowCriticalityDiagnostics           *q11.CriticalityDiagnostics
}

func (v AssistanceInformationFeedbackIEValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q5.ProtocolIEID(24):
		return v.rowAssistanceInformationFailureList != nil
	case q5.ProtocolIEID(1):
		return v.rowCriticalityDiagnostics != nil
	default:
		return false
	}
}
func (v *AssistanceInformationFeedbackIEValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (AssistanceInformationFeedbackIEValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "AssistanceInformationFeedback-IEs"}}
}
func (AssistanceInformationFeedbackIEValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(24):
		return q4.UnknownSelector
	case q5.ProtocolIEID(1):
		return q4.UnknownSelector
	case q5.ProtocolIEID(0):
		return q4.NotInTable
	case q5.ProtocolIEID(2):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
		return q4.NotInTable
	case q5.ProtocolIEID(6):
		return q4.NotInTable
	case q5.ProtocolIEID(7):
		return q4.NotInTable
	case q5.ProtocolIEID(8):
		return q4.NotInTable
	case q5.ProtocolIEID(9):
		return q4.NotInTable
	case q5.ProtocolIEID(10):
		return q4.NotInTable
	case q5.ProtocolIEID(11):
		return q4.NotInTable
	case q5.ProtocolIEID(12):
		return q4.NotInTable
	case q5.ProtocolIEID(13):
		return q4.NotInTable
	case q5.ProtocolIEID(14):
		return q4.NotInTable
	case q5.ProtocolIEID(15):
		return q4.NotInTable
	case q5.ProtocolIEID(16):
		return q4.NotInTable
	case q5.ProtocolIEID(17):
		return q4.NotInTable
	case q5.ProtocolIEID(18):
		return q4.NotInTable
	case q5.ProtocolIEID(19):
		return q4.NotInTable
	case q5.ProtocolIEID(20):
		return q4.NotInTable
	case q5.ProtocolIEID(21):
		return q4.NotInTable
	case q5.ProtocolIEID(22):
		return q4.NotInTable
	case q5.ProtocolIEID(23):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v *AssistanceInformationFeedbackIEValue) AsAssistanceInformationFailureList() (*q10.AssistanceInformationFailureList, bool) {
	if v == nil || v.id != q5.ProtocolIEID(24) || v.rowAssistanceInformationFailureList == nil {
		return nil, false
	}
	return v.rowAssistanceInformationFailureList, true
}
func (v *AssistanceInformationFeedbackIEValue) AsCriticalityDiagnostics() (*q11.CriticalityDiagnostics, bool) {
	if v == nil || v.id != q5.ProtocolIEID(1) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v AssistanceInformationFeedbackIEValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (AssistanceInformationFeedbackIEValue, error) {
	out := AssistanceInformationFeedbackIEValue{id: id}
	var scope *q4.BitBuffer
	switch id {
	case 24, 1:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q5.ProtocolIEID(24):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := BridgeUnmarshalAPERAssistanceInformationFailureListFrom(child)
		if err != nil {
			return out, q6.Errorf("%s %w", "AssistanceInformationFailureList:", err)
		}
		padding, err := q4.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := AssistanceInformationFailureListComplete{Value: list, perPadding: padding}
		value := complete.Value
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowAssistanceInformationFailureList = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q5.ProtocolIEID(1):
		replayUsage := scope.Usage()
		var value q11.CriticalityDiagnostics
		child := raw.ChildDecodeBuffer()
		if err := q11.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, q6.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*q11.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*q11.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(q11.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCriticalityDiagnostics = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	default:
		if err := raw.Observe(q4.UnknownIE); err != nil {
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
func (v AssistanceInformationFeedbackIEValue) encode() ([]byte, error) {
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v AssistanceInformationFeedbackIEValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q4.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q4.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	case q5.ProtocolIEID(24):
		if v.rowAssistanceInformationFailureList == nil {
			return nil, q6.Errorf("%s missing value", "AssistanceInformationFeedback-IEs.id-AssistanceInformationFailureList:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		complete := AssistanceInformationFailureListComplete{Value: *v.rowAssistanceInformationFailureList}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case q5.ProtocolIEID(1):
		if v.rowCriticalityDiagnostics == nil {
			return nil, q6.Errorf("%s missing value", "AssistanceInformationFeedback-IEs.id-CriticalityDiagnostics:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := q11.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, q6.Errorf("%s id %d has no value", "AssistanceInformationFeedbackIEValue:", v.id)
	}
}

type AssistanceInformationFeedbackIETable struct{}

func AssistanceInformationFeedbackIEs() AssistanceInformationFeedbackIETable {
	return AssistanceInformationFeedbackIETable{}
}
func (AssistanceInformationFeedbackIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "AssistanceInformationFeedback-IEs"}
		return sealed
	}()
}
func (AssistanceInformationFeedbackIETable) infoAssistanceInformationFailureList() q5.FieldInfo {
	return q5.FieldInfo{Table: AssistanceInformationFeedbackIEs().ID(), ID: q5.ProtocolIEID(24), Criticality: q5.CriticalityReject, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "AssistanceInformationFailureList"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "AssistanceInformationFeedback-IEs", Row: "id-AssistanceInformationFailureList"}}}
}
func (t AssistanceInformationFeedbackIETable) AssistanceInformationFailureList() AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding {
	return AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding{info: t.infoAssistanceInformationFailureList(), codec: func() q10.AssistanceInformationFailureListValueCodec {
		sealed := q10.AssistanceInformationFailureListValueCodec{}
		*q10.BridgeAssistanceInformationFailureListValueCodecFieldPath(&sealed) = "AssistanceInformationFailureList"
		*q10.BridgeAssistanceInformationFailureListValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q10.AssistanceInformationFailureList, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q10.AssistanceInformationFailureList
				return empty, err
			}
			var zero AssistanceInformationFeedbackIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(24), raw)
			if err != nil {
				var empty q10.AssistanceInformationFailureList
				return empty, err
			}
			value, ok := decoded.AsAssistanceInformationFailureList()
			if !ok {
				var empty q10.AssistanceInformationFailureList
				return empty, q6.Errorf("binding AssistanceInformationFeedback-IEs.id-AssistanceInformationFailureList: no selected value")
			}
			return *value, nil
		}
		*q10.BridgeAssistanceInformationFailureListValueCodecFieldEncode(&sealed) = func(value q10.AssistanceInformationFailureList, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (AssistanceInformationFeedbackIEValue{id: q5.ProtocolIEID(24), rowAssistanceInformationFailureList: &value}).encodeFresh(fresh, budget)
		}
		*q10.BridgeAssistanceInformationFailureListValueCodecFieldCapture(&sealed) = func(v q10.AssistanceInformationFailureList, options q4.DecodeState) (q10.AssistanceInformationFailureList, q4.Snapshot,
		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q11.BridgeCaptureLPPaAssistanceInformationFailureList(&v, &s)
			var root q4.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)

			return v, root
		}
		*q10.BridgeAssistanceInformationFailureListValueCodecFieldCompare(&sealed) = func(v q10.AssistanceInformationFailureList, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q11.BridgeCompareLPPaAssistanceInformationFailureList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan()
		}
		*q10.BridgeAssistanceInformationFailureListValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:AssistanceInformationFailureList"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q10.AssistanceInformationFailureList) AssistanceInformationFeedbackIEValue {
			return AssistanceInformationFeedbackIEValue{id: q5.ProtocolIEID(24), rowAssistanceInformationFailureList: &value}
		}, get: func(value *AssistanceInformationFeedbackIEValue) (*q10.AssistanceInformationFailureList, bool) {
			return value.AsAssistanceInformationFailureList()
		}}
}
func (AssistanceInformationFeedbackIETable) infoCriticalityDiagnostics() q5.FieldInfo {
	return q5.FieldInfo{Table: AssistanceInformationFeedbackIEs().ID(), ID: q5.ProtocolIEID(1), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "AssistanceInformationFeedback-IEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t AssistanceInformationFeedbackIETable) CriticalityDiagnostics() AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding {
	return AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() q11.CriticalityDiagnosticsValueCodec {
		sealed := q11.CriticalityDiagnosticsValueCodec{}
		*q11.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*q11.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q11.CriticalityDiagnostics, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q11.CriticalityDiagnostics
				return empty, err
			}
			var zero AssistanceInformationFeedbackIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(1), raw)
			if err != nil {
				var empty q11.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty q11.CriticalityDiagnostics
				return empty, q6.Errorf("binding AssistanceInformationFeedback-IEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*q11.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value q11.CriticalityDiagnostics, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (AssistanceInformationFeedbackIEValue{id: q5.ProtocolIEID(1), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*q11.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v q11.CriticalityDiagnostics, options q4.DecodeState) (q11.CriticalityDiagnostics, q4.Snapshot,

		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q11.BridgeCaptureLPPaCriticalityDiagnostics(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q11.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v q11.CriticalityDiagnostics, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q11.BridgeCompareLPPaCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q11.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q11.CriticalityDiagnostics) AssistanceInformationFeedbackIEValue {
			return AssistanceInformationFeedbackIEValue{id: q5.ProtocolIEID(1), rowCriticalityDiagnostics: &value}
		}, get: func(value *AssistanceInformationFeedbackIEValue) (*q11.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (t AssistanceInformationFeedbackIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (AssistanceInformationFeedbackIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return AssistanceInformationFeedbackIEField{}, q4.OperationError(q6.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q5.ProtocolIEID(24):
		return AssistanceInformationFeedbackIEField{}, q4.OperationError(q6.Errorf("known IE id-AssistanceInformationFailureList requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(1):
		return AssistanceInformationFeedbackIEField{}, q4.OperationError(q6.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return AssistanceInformationFeedbackIEField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return AssistanceInformationFeedbackIEField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return AssistanceInformationFeedbackIEField{}, q4.OperationError(err, "Opaque")
		}
		return AssistanceInformationFeedbackIEField{Id: id, Criticality: criticality, Value: AssistanceInformationFeedbackIEValue{id: id, opaque: retained, isOpaque: true}}, q4.OperationError(nil, "Opaque")
	}
}

// AddOTDOACellInformationCodec binds the complete source value type.
func AddOTDOACellInformationCodec() q15.AddOTDOACellInformationValueCodec {
	return func() q15.AddOTDOACellInformationValueCodec {
		sealed := q15.AddOTDOACellInformationValueCodec{}
		*q15.BridgeAddOTDOACellInformationValueCodecFieldPath(&sealed) = "AddOTDOACellInformation"
		*q15.BridgeAddOTDOACellInformationValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q15.AddOTDOACellInformation, error) {
			var complete AddOTDOACellInformationComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero q15.AddOTDOACellInformation
				return zero, err
			}
			return complete.Value, nil
		}
		*q15.BridgeAddOTDOACellInformationValueCodecFieldEncode(&sealed) = func(value q15.AddOTDOACellInformation, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			complete := AddOTDOACellInformationComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*q15.BridgeAddOTDOACellInformationValueCodecFieldCapture(&sealed) = func(v q15.AddOTDOACellInformation, options q4.DecodeState) (q15.AddOTDOACellInformation, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q15.BridgeCaptureLPPaAddOTDOACellInformation(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q15.BridgeAddOTDOACellInformationValueCodecFieldCompare(&sealed) = func(v q15.AddOTDOACellInformation, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q15.BridgeCompareLPPaAddOTDOACellInformation(&v, &s)
			s.End(f, root, false)
			return s.
				Plan()
		}
		*q15.BridgeAddOTDOACellInformationValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:AddOTDOACellInformation"
			return sealed
		}()
		return sealed
	}()

}

// AssistanceInformationFailureListCodec binds the complete APER value type.
func AssistanceInformationFailureListCodec() q10.AssistanceInformationFailureListValueCodec {
	return AssistanceInformationFeedbackIEs().AssistanceInformationFailureList().Codec()
}

// CriticalityDiagnosticsCodec binds the complete APER value type.
func CriticalityDiagnosticsCodec() q11.CriticalityDiagnosticsValueCodec {
	return AssistanceInformationFeedbackIEs().CriticalityDiagnostics().Codec()
}

// CriticalityDiagnosticsIEListCodec binds the complete source value type.
func CriticalityDiagnosticsIEListCodec() q10.CriticalityDiagnosticsIEListValueCodec {
	return func() q10.CriticalityDiagnosticsIEListValueCodec {
		sealed := q10.CriticalityDiagnosticsIEListValueCodec{}
		*q10.BridgeCriticalityDiagnosticsIEListValueCodecFieldPath(&sealed) = "CriticalityDiagnosticsIEList"
		*q10.BridgeCriticalityDiagnosticsIEListValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q10.CriticalityDiagnosticsIEList, error) {
			var complete CriticalityDiagnosticsIEListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero q10.CriticalityDiagnosticsIEList
				return zero, err
			}
			return complete.Value, nil
		}
		*q10.BridgeCriticalityDiagnosticsIEListValueCodecFieldEncode(&sealed) = func(value q10.CriticalityDiagnosticsIEList, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			complete := CriticalityDiagnosticsIEListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*q10.BridgeCriticalityDiagnosticsIEListValueCodecFieldCapture(&sealed) = func(v q10.CriticalityDiagnosticsIEList, options q4.DecodeState) (q10.CriticalityDiagnosticsIEList, q4.Snapshot,
		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q11.BridgeCaptureLPPaCriticalityDiagnosticsIEList(&v, &s)
			var root q4.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v, root

		}
		*q10.BridgeCriticalityDiagnosticsIEListValueCodecFieldCompare(&sealed) = func(v q10.CriticalityDiagnosticsIEList, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q11.BridgeCompareLPPaCriticalityDiagnosticsIEList(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q10.BridgeCriticalityDiagnosticsIEListValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnosticsIEList"
			return sealed
		}()
		return sealed
	}()

}
func BridgeAddOTDOACellInformationCompleteFieldPerPadding(v *AddOTDOACellInformationComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeAddOTDOACellInformationCompleteFieldReceived(v *AddOTDOACellInformationComplete) *bool {
	return &v.received
}
func BridgeAddOTDOACellInformationCompleteFieldReceivedBytes(v *AddOTDOACellInformationComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeAddOTDOACellInformationCompleteFieldReplay(v *AddOTDOACellInformationComplete) *q4.Snapshot {
	return &v.replay
}
func BridgeAddOTDOACellInformationCompleteFieldStream(v *AddOTDOACellInformationComplete) *q4.WireSpan {
	return &v.stream
}
func BridgeAddOTDOACellInformationCompleteFieldWithoutReplay(v *AddOTDOACellInformationComplete) *bool {
	return &v.withoutReplay
}
func BridgeAddOTDOACellInformationCompleteMethodMarshalAPERBudget(v *AddOTDOACellInformationComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAddOTDOACellInformationCompleteMethodMarshalAPERChanged(v *AddOTDOACellInformationComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAddOTDOACellInformationCompleteMethodMarshalAPERChangedValue(v *AddOTDOACellInformationComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAddOTDOACellInformationCompleteMethodMarshalAPERFreshValue(v *AddOTDOACellInformationComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeAddOTDOACellInformationCompleteMethodMarshalAPERLegacy(v *AddOTDOACellInformationComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAddOTDOACellInformationCompleteMethodMarshalAPERPlanned(v *AddOTDOACellInformationComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeAddOTDOACellInformationCompleteMethodUnmarshalAPERLegacy(v *AddOTDOACellInformationComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAddOTDOACellInformationCompleteMethodUnmarshalAPERWithOptions(v *AddOTDOACellInformationComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAddOTDOACellsCompleteFieldPerPadding(v *AddOTDOACellsComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeAddOTDOACellsCompleteFieldReceived(v *AddOTDOACellsComplete) *bool { return &v.received }
func BridgeAddOTDOACellsCompleteFieldReceivedBytes(v *AddOTDOACellsComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeAddOTDOACellsCompleteFieldReplay(v *AddOTDOACellsComplete) *q4.Snapshot { return &v.replay }
func BridgeAddOTDOACellsCompleteFieldStream(v *AddOTDOACellsComplete) *q4.WireSpan { return &v.stream }
func BridgeAddOTDOACellsCompleteFieldWithoutReplay(v *AddOTDOACellsComplete) *bool {
	return &v.withoutReplay
}
func BridgeAddOTDOACellsCompleteMethodMarshalAPERBudget(v *AddOTDOACellsComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAddOTDOACellsCompleteMethodMarshalAPERChanged(v *AddOTDOACellsComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAddOTDOACellsCompleteMethodMarshalAPERChangedValue(v *AddOTDOACellsComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAddOTDOACellsCompleteMethodMarshalAPERFreshValue(v *AddOTDOACellsComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeAddOTDOACellsCompleteMethodMarshalAPERLegacy(v *AddOTDOACellsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAddOTDOACellsCompleteMethodMarshalAPERPlanned(v *AddOTDOACellsComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeAddOTDOACellsCompleteMethodUnmarshalAPERLegacy(v *AddOTDOACellsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAddOTDOACellsCompleteMethodUnmarshalAPERWithOptions(v *AddOTDOACellsComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAssistanceInformationFailureListCompleteFieldPerPadding(v *AssistanceInformationFailureListComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeAssistanceInformationFailureListCompleteFieldReceived(v *AssistanceInformationFailureListComplete) *bool {
	return &v.received
}
func BridgeAssistanceInformationFailureListCompleteFieldReceivedBytes(v *AssistanceInformationFailureListComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeAssistanceInformationFailureListCompleteFieldReplay(v *AssistanceInformationFailureListComplete) *q4.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFailureListCompleteFieldStream(v *AssistanceInformationFailureListComplete) *q4.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationFailureListCompleteFieldWithoutReplay(v *AssistanceInformationFailureListComplete) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFailureListCompleteMethodMarshalAPERBudget(v *AssistanceInformationFailureListComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAssistanceInformationFailureListCompleteMethodMarshalAPERChanged(v *AssistanceInformationFailureListComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAssistanceInformationFailureListCompleteMethodMarshalAPERChangedValue(v *AssistanceInformationFailureListComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAssistanceInformationFailureListCompleteMethodMarshalAPERFreshValue(v *AssistanceInformationFailureListComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeAssistanceInformationFailureListCompleteMethodMarshalAPERLegacy(v *AssistanceInformationFailureListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAssistanceInformationFailureListCompleteMethodMarshalAPERPlanned(v *AssistanceInformationFailureListComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeAssistanceInformationFailureListCompleteMethodUnmarshalAPERLegacy(v *AssistanceInformationFailureListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAssistanceInformationFailureListCompleteMethodUnmarshalAPERWithOptions(v *AssistanceInformationFailureListComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAssistanceInformationFeedbackAPERValueFieldContext(v *AssistanceInformationFeedbackAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationFeedbackAPERValueFieldReceived(v *AssistanceInformationFeedbackAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationFeedbackAPERValueFieldReplay(v *AssistanceInformationFeedbackAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFeedbackAPERValueFieldWithoutReplay(v *AssistanceInformationFeedbackAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFeedbackAssistanceInformationFailureListIEBindingFieldCodec(v *AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding) *q10.AssistanceInformationFailureListValueCodec {
	return &v.codec
}
func BridgeAssistanceInformationFeedbackAssistanceInformationFailureListIEBindingFieldGet(v *AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding) *func(*AssistanceInformationFeedbackIEValue) (*q10.AssistanceInformationFailureList, bool) {
	return &v.get
}
func BridgeAssistanceInformationFeedbackAssistanceInformationFailureListIEBindingFieldInfo(v *AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeAssistanceInformationFeedbackAssistanceInformationFailureListIEBindingFieldInject(v *AssistanceInformationFeedbackAssistanceInformationFailureListIEBinding) *func(q10.AssistanceInformationFailureList) AssistanceInformationFeedbackIEValue {
	return &v.inject
}
func BridgeAssistanceInformationFeedbackCriticalityDiagnosticsIEBindingFieldCodec(v *AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding) *q11.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeAssistanceInformationFeedbackCriticalityDiagnosticsIEBindingFieldGet(v *AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding) *func(*AssistanceInformationFeedbackIEValue) (*q11.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeAssistanceInformationFeedbackCriticalityDiagnosticsIEBindingFieldInfo(v *AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeAssistanceInformationFeedbackCriticalityDiagnosticsIEBindingFieldInject(v *AssistanceInformationFeedbackCriticalityDiagnosticsIEBinding) *func(q11.CriticalityDiagnostics) AssistanceInformationFeedbackIEValue {
	return &v.inject
}
func BridgeAssistanceInformationFeedbackFieldExtCount(v *AssistanceInformationFeedback) *int64 {
	return &v.extCount
}
func BridgeAssistanceInformationFeedbackFieldExtData(v *AssistanceInformationFeedback) *[][]byte {
	return &v.extData
}
func BridgeAssistanceInformationFeedbackFieldExtOrigin(v *AssistanceInformationFeedback) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeAssistanceInformationFeedbackFieldExtPresent(v *AssistanceInformationFeedback) *[]bool {
	return &v.extPresent
}
func BridgeAssistanceInformationFeedbackFieldExtWire(v *AssistanceInformationFeedback) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeAssistanceInformationFeedbackFieldPerExtPadding(v *AssistanceInformationFeedback) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeAssistanceInformationFeedbackFieldPerPadding(v *AssistanceInformationFeedback) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeAssistanceInformationFeedbackFieldProtocolIEsIndef(v *AssistanceInformationFeedback) *bool {
	return &v.protocolIEsIndef
}
func BridgeAssistanceInformationFeedbackFieldReceived(v *AssistanceInformationFeedback) *bool {
	return &v.received
}
func BridgeAssistanceInformationFeedbackFieldReceivedBytes(v *AssistanceInformationFeedback) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeAssistanceInformationFeedbackFieldReplay(v *AssistanceInformationFeedback) *q4.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFeedbackFieldStream(v *AssistanceInformationFeedback) *q4.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationFeedbackFieldWithoutReplay(v *AssistanceInformationFeedback) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFeedbackIEFieldFieldReceived(v *AssistanceInformationFeedbackIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeAssistanceInformationFeedbackIEFieldFieldReplay(v *AssistanceInformationFeedbackIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFeedbackIEFieldFieldStream(v *AssistanceInformationFeedbackIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationFeedbackIEFieldFieldWithoutReplay(v *AssistanceInformationFeedbackIEField) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFeedbackIEFieldMethodMarshalAPERTo(v *AssistanceInformationFeedbackIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationFeedbackIEFieldMethodUnmarshalAPERFrom(v *AssistanceInformationFeedbackIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationFeedbackIETableMethodInfoAssistanceInformationFailureList(v AssistanceInformationFeedbackIETable) q5.FieldInfo {
	return v.infoAssistanceInformationFailureList()
}
func BridgeAssistanceInformationFeedbackIETableMethodInfoCriticalityDiagnostics(v AssistanceInformationFeedbackIETable) q5.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeAssistanceInformationFeedbackIEValueFieldId(v *AssistanceInformationFeedbackIEValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeAssistanceInformationFeedbackIEValueFieldIsOpaque(v *AssistanceInformationFeedbackIEValue) *bool {
	return &v.isOpaque
}
func BridgeAssistanceInformationFeedbackIEValueFieldOpaque(v *AssistanceInformationFeedbackIEValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeAssistanceInformationFeedbackIEValueFieldReceived(v *AssistanceInformationFeedbackIEValue) *q4.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationFeedbackIEValueFieldReplay(v *AssistanceInformationFeedbackIEValue) *q4.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFeedbackIEValueFieldRowAssistanceInformationFailureList(v *AssistanceInformationFeedbackIEValue) **q10.AssistanceInformationFailureList {
	return &v.rowAssistanceInformationFailureList
}
func BridgeAssistanceInformationFeedbackIEValueFieldRowCriticalityDiagnostics(v *AssistanceInformationFeedbackIEValue) **q11.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeAssistanceInformationFeedbackIEValueFieldWithoutReplay(v *AssistanceInformationFeedbackIEValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFeedbackIEValueMethodCaptureFraming(v AssistanceInformationFeedbackIEValue) uint64 {
	return v.captureFraming()
}
func BridgeAssistanceInformationFeedbackIEValueMethodCaptureSemantics(v AssistanceInformationFeedbackIEValue, a0 q4.SemanticCapture) AssistanceInformationFeedbackIEValue {
	return v.captureSemantics(a0)
}
func BridgeAssistanceInformationFeedbackIEValueMethodCaptureSnapshot(v AssistanceInformationFeedbackIEValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeAssistanceInformationFeedbackIEValueMethodCompareSemantics(v AssistanceInformationFeedbackIEValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeAssistanceInformationFeedbackIEValueMethodDecode(v AssistanceInformationFeedbackIEValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (AssistanceInformationFeedbackIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeAssistanceInformationFeedbackIEValueMethodEncode(v AssistanceInformationFeedbackIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeAssistanceInformationFeedbackIEValueMethodEncodeFresh(v AssistanceInformationFeedbackIEValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeAssistanceInformationFeedbackIEValueMethodMatchesID(v AssistanceInformationFeedbackIEValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeAssistanceInformationFeedbackIEValueMethodReason(v AssistanceInformationFeedbackIEValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeAssistanceInformationFeedbackIEValueMethodRule(v AssistanceInformationFeedbackIEValue) q4.SourceRule {
	return v.rule()
}
func BridgeAssistanceInformationFeedbackMethodMarshalAPERBudget(v *AssistanceInformationFeedback, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAssistanceInformationFeedbackMethodMarshalAPERChanged(v *AssistanceInformationFeedback, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAssistanceInformationFeedbackMethodMarshalAPERChangedValue(v *AssistanceInformationFeedback, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAssistanceInformationFeedbackMethodMarshalAPERFreshValue(v *AssistanceInformationFeedback, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeAssistanceInformationFeedbackMethodMarshalAPERLegacy(v *AssistanceInformationFeedback) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAssistanceInformationFeedbackMethodMarshalAPERPlanned(v *AssistanceInformationFeedback, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeAssistanceInformationFeedbackMethodMarshalAPERTo(v *AssistanceInformationFeedback, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationFeedbackMethodUnmarshalAPERFrom(v *AssistanceInformationFeedback, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationFeedbackMethodUnmarshalAPERLegacy(v *AssistanceInformationFeedback, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAssistanceInformationFeedbackMethodUnmarshalAPERWithOptions(v *AssistanceInformationFeedback, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAssistanceInformationFeedbackValueCodecFieldCapture(v *AssistanceInformationFeedbackValueCodec) *func(AssistanceInformationFeedback, q4.DecodeState) (AssistanceInformationFeedback, q4.Snapshot) {
	return &v.capture
}
func BridgeAssistanceInformationFeedbackValueCodecFieldCompare(v *AssistanceInformationFeedbackValueCodec) *func(AssistanceInformationFeedback, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeAssistanceInformationFeedbackValueCodecFieldContext(v *AssistanceInformationFeedbackValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationFeedbackValueCodecFieldDecode(v *AssistanceInformationFeedbackValueCodec) *func([]byte, q4.DecodeState) (AssistanceInformationFeedback, error) {
	return &v.decode
}
func BridgeAssistanceInformationFeedbackValueCodecFieldEncode(v *AssistanceInformationFeedbackValueCodec) *func(AssistanceInformationFeedback, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceInformationFeedbackValueCodecFieldPath(v *AssistanceInformationFeedbackValueCodec) *q4.Path {
	return &v.path
}
func BridgeAssistanceInformationFeedbackValueCodecMethodEncodeBudget(v AssistanceInformationFeedbackValueCodec, a0 AssistanceInformationFeedback, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeAssistanceInformationFeedbackValueCodecMethodEncodeChanged(v AssistanceInformationFeedbackValueCodec, a0 AssistanceInformationFeedback, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCriticalityDiagnosticsIEListCompleteFieldPerPadding(v *CriticalityDiagnosticsIEListComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeCriticalityDiagnosticsIEListCompleteFieldReceived(v *CriticalityDiagnosticsIEListComplete) *bool {
	return &v.received
}
func BridgeCriticalityDiagnosticsIEListCompleteFieldReceivedBytes(v *CriticalityDiagnosticsIEListComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeCriticalityDiagnosticsIEListCompleteFieldReplay(v *CriticalityDiagnosticsIEListComplete) *q4.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsIEListCompleteFieldStream(v *CriticalityDiagnosticsIEListComplete) *q4.WireSpan {
	return &v.stream
}
func BridgeCriticalityDiagnosticsIEListCompleteFieldWithoutReplay(v *CriticalityDiagnosticsIEListComplete) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsIEListCompleteMethodMarshalAPERBudget(v *CriticalityDiagnosticsIEListComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListCompleteMethodMarshalAPERChanged(v *CriticalityDiagnosticsIEListComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsIEListCompleteMethodMarshalAPERChangedValue(v *CriticalityDiagnosticsIEListComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeCriticalityDiagnosticsIEListCompleteMethodMarshalAPERFreshValue(v *CriticalityDiagnosticsIEListComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListCompleteMethodMarshalAPERLegacy(v *CriticalityDiagnosticsIEListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeCriticalityDiagnosticsIEListCompleteMethodMarshalAPERPlanned(v *CriticalityDiagnosticsIEListComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListCompleteMethodUnmarshalAPERLegacy(v *CriticalityDiagnosticsIEListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeCriticalityDiagnosticsIEListCompleteMethodUnmarshalAPERWithOptions(v *CriticalityDiagnosticsIEListComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesCompleteFieldPerPadding(v *InterRATMeasurementQuantitiesComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeInterRATMeasurementQuantitiesCompleteFieldReceived(v *InterRATMeasurementQuantitiesComplete) *bool {
	return &v.received
}
func BridgeInterRATMeasurementQuantitiesCompleteFieldReceivedBytes(v *InterRATMeasurementQuantitiesComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeInterRATMeasurementQuantitiesCompleteFieldReplay(v *InterRATMeasurementQuantitiesComplete) *q4.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementQuantitiesCompleteFieldStream(v *InterRATMeasurementQuantitiesComplete) *q4.WireSpan {
	return &v.stream
}
func BridgeInterRATMeasurementQuantitiesCompleteFieldWithoutReplay(v *InterRATMeasurementQuantitiesComplete) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementQuantitiesCompleteMethodMarshalAPERBudget(v *InterRATMeasurementQuantitiesComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesCompleteMethodMarshalAPERChanged(v *InterRATMeasurementQuantitiesComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeInterRATMeasurementQuantitiesCompleteMethodMarshalAPERChangedValue(v *InterRATMeasurementQuantitiesComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeInterRATMeasurementQuantitiesCompleteMethodMarshalAPERFreshValue(v *InterRATMeasurementQuantitiesComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesCompleteMethodMarshalAPERLegacy(v *InterRATMeasurementQuantitiesComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeInterRATMeasurementQuantitiesCompleteMethodMarshalAPERPlanned(v *InterRATMeasurementQuantitiesComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesCompleteMethodUnmarshalAPERLegacy(v *InterRATMeasurementQuantitiesComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeInterRATMeasurementQuantitiesCompleteMethodUnmarshalAPERWithOptions(v *InterRATMeasurementQuantitiesComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUTDOAInformationResponseAPERValueFieldContext(v *UTDOAInformationResponseAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationResponseAPERValueFieldReceived(v *UTDOAInformationResponseAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeUTDOAInformationResponseAPERValueFieldReplay(v *UTDOAInformationResponseAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationResponseAPERValueFieldWithoutReplay(v *UTDOAInformationResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationResponseFieldExtCount(v *UTDOAInformationResponse) *int64 {
	return &v.extCount
}
func BridgeUTDOAInformationResponseFieldExtData(v *UTDOAInformationResponse) *[][]byte {
	return &v.extData
}
func BridgeUTDOAInformationResponseFieldExtOrigin(v *UTDOAInformationResponse) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUTDOAInformationResponseFieldExtPresent(v *UTDOAInformationResponse) *[]bool {
	return &v.extPresent
}
func BridgeUTDOAInformationResponseFieldExtWire(v *UTDOAInformationResponse) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeUTDOAInformationResponseFieldPerExtPadding(v *UTDOAInformationResponse) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeUTDOAInformationResponseFieldPerPadding(v *UTDOAInformationResponse) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeUTDOAInformationResponseFieldProtocolIEsIndef(v *UTDOAInformationResponse) *bool {
	return &v.protocolIEsIndef
}
func BridgeUTDOAInformationResponseFieldReceived(v *UTDOAInformationResponse) *bool {
	return &v.received
}
func BridgeUTDOAInformationResponseFieldReceivedBytes(v *UTDOAInformationResponse) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeUTDOAInformationResponseFieldReplay(v *UTDOAInformationResponse) *q4.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationResponseFieldStream(v *UTDOAInformationResponse) *q4.WireSpan {
	return &v.stream
}
func BridgeUTDOAInformationResponseFieldWithoutReplay(v *UTDOAInformationResponse) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationResponseMethodMarshalAPERBudget(v *UTDOAInformationResponse, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUTDOAInformationResponseMethodMarshalAPERChanged(v *UTDOAInformationResponse, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUTDOAInformationResponseMethodMarshalAPERChangedValue(v *UTDOAInformationResponse, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUTDOAInformationResponseMethodMarshalAPERFreshValue(v *UTDOAInformationResponse, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeUTDOAInformationResponseMethodMarshalAPERLegacy(v *UTDOAInformationResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUTDOAInformationResponseMethodMarshalAPERPlanned(v *UTDOAInformationResponse, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeUTDOAInformationResponseMethodMarshalAPERTo(v *UTDOAInformationResponse, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUTDOAInformationResponseMethodUnmarshalAPERFrom(v *UTDOAInformationResponse, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUTDOAInformationResponseMethodUnmarshalAPERLegacy(v *UTDOAInformationResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUTDOAInformationResponseMethodUnmarshalAPERWithOptions(v *UTDOAInformationResponse, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUTDOAInformationResponseValueCodecFieldCapture(v *UTDOAInformationResponseValueCodec) *func(UTDOAInformationResponse, q4.DecodeState) (UTDOAInformationResponse, q4.Snapshot) {
	return &v.capture
}
func BridgeUTDOAInformationResponseValueCodecFieldCompare(v *UTDOAInformationResponseValueCodec) *func(UTDOAInformationResponse, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeUTDOAInformationResponseValueCodecFieldContext(v *UTDOAInformationResponseValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationResponseValueCodecFieldDecode(v *UTDOAInformationResponseValueCodec) *func([]byte, q4.DecodeState) (UTDOAInformationResponse, error) {
	return &v.decode
}
func BridgeUTDOAInformationResponseValueCodecFieldEncode(v *UTDOAInformationResponseValueCodec) *func(UTDOAInformationResponse, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTDOAInformationResponseValueCodecFieldPath(v *UTDOAInformationResponseValueCodec) *q4.Path {
	return &v.path
}
func BridgeUTDOAInformationResponseValueCodecMethodEncodeBudget(v UTDOAInformationResponseValueCodec, a0 UTDOAInformationResponse, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeUTDOAInformationResponseValueCodecMethodEncodeChanged(v UTDOAInformationResponseValueCodec, a0 UTDOAInformationResponse, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUTDOAInformationUpdateAPERValueFieldContext(v *UTDOAInformationUpdateAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationUpdateAPERValueFieldReceived(v *UTDOAInformationUpdateAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeUTDOAInformationUpdateAPERValueFieldReplay(v *UTDOAInformationUpdateAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationUpdateAPERValueFieldWithoutReplay(v *UTDOAInformationUpdateAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationUpdateFieldExtCount(v *UTDOAInformationUpdate) *int64   { return &v.extCount }
func BridgeUTDOAInformationUpdateFieldExtData(v *UTDOAInformationUpdate) *[][]byte { return &v.extData }
func BridgeUTDOAInformationUpdateFieldExtOrigin(v *UTDOAInformationUpdate) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeUTDOAInformationUpdateFieldExtPresent(v *UTDOAInformationUpdate) *[]bool {
	return &v.extPresent
}
func BridgeUTDOAInformationUpdateFieldExtWire(v *UTDOAInformationUpdate) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeUTDOAInformationUpdateFieldPerExtPadding(v *UTDOAInformationUpdate) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeUTDOAInformationUpdateFieldPerPadding(v *UTDOAInformationUpdate) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeUTDOAInformationUpdateFieldProtocolIEsIndef(v *UTDOAInformationUpdate) *bool {
	return &v.protocolIEsIndef
}
func BridgeUTDOAInformationUpdateFieldReceived(v *UTDOAInformationUpdate) *bool { return &v.received }
func BridgeUTDOAInformationUpdateFieldReceivedBytes(v *UTDOAInformationUpdate) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeUTDOAInformationUpdateFieldReplay(v *UTDOAInformationUpdate) *q4.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationUpdateFieldStream(v *UTDOAInformationUpdate) *q4.WireSpan {
	return &v.stream
}
func BridgeUTDOAInformationUpdateFieldWithoutReplay(v *UTDOAInformationUpdate) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationUpdateMethodMarshalAPERBudget(v *UTDOAInformationUpdate, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeUTDOAInformationUpdateMethodMarshalAPERChanged(v *UTDOAInformationUpdate, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeUTDOAInformationUpdateMethodMarshalAPERChangedValue(v *UTDOAInformationUpdate, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeUTDOAInformationUpdateMethodMarshalAPERFreshValue(v *UTDOAInformationUpdate, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeUTDOAInformationUpdateMethodMarshalAPERLegacy(v *UTDOAInformationUpdate) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeUTDOAInformationUpdateMethodMarshalAPERPlanned(v *UTDOAInformationUpdate, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeUTDOAInformationUpdateMethodMarshalAPERTo(v *UTDOAInformationUpdate, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUTDOAInformationUpdateMethodUnmarshalAPERFrom(v *UTDOAInformationUpdate, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUTDOAInformationUpdateMethodUnmarshalAPERLegacy(v *UTDOAInformationUpdate, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeUTDOAInformationUpdateMethodUnmarshalAPERWithOptions(v *UTDOAInformationUpdate, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeUTDOAInformationUpdateValueCodecFieldCapture(v *UTDOAInformationUpdateValueCodec) *func(UTDOAInformationUpdate, q4.DecodeState) (UTDOAInformationUpdate, q4.Snapshot) {
	return &v.capture
}
func BridgeUTDOAInformationUpdateValueCodecFieldCompare(v *UTDOAInformationUpdateValueCodec) *func(UTDOAInformationUpdate, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeUTDOAInformationUpdateValueCodecFieldContext(v *UTDOAInformationUpdateValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeUTDOAInformationUpdateValueCodecFieldDecode(v *UTDOAInformationUpdateValueCodec) *func([]byte, q4.DecodeState) (UTDOAInformationUpdate, error) {
	return &v.decode
}
func BridgeUTDOAInformationUpdateValueCodecFieldEncode(v *UTDOAInformationUpdateValueCodec) *func(UTDOAInformationUpdate, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTDOAInformationUpdateValueCodecFieldPath(v *UTDOAInformationUpdateValueCodec) *q4.Path {
	return &v.path
}
func BridgeUTDOAInformationUpdateValueCodecMethodEncodeBudget(v UTDOAInformationUpdateValueCodec, a0 UTDOAInformationUpdate, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeUTDOAInformationUpdateValueCodecMethodEncodeChanged(v UTDOAInformationUpdateValueCodec, a0 UTDOAInformationUpdate, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
