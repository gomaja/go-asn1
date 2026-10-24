// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s20 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s20

import (
	q8 "fmt"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q23 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"
	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q18 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	q20 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	q7 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	q19 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	q16 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	q6 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s12"
	q15 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s14"
	q17 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s15"
	q22 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s17"
	q21 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s18"
	q13 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s19"
	q11 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

func NewPrivateMessage(fields q4.PrivateMessageIEsValuePrivateIEContainer, options ...q5.BuildOption) (q6.PrivateMessage, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q6.PrivateMessage{}, q5.OperationError(err, "PrivateMessage")
	}
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q4.PrivateMessageIEsValuePrivateIEField](bb, uint64(len(fields))); err != nil {
		return q6.PrivateMessage{}, q5.OperationError(err, "PrivateMessage")
	}
	v := q6.PrivateMessage{PrivateIEs: append(q4.PrivateMessageIEsValuePrivateIEContainer(nil), fields...)}
	report, err := BridgeValidatePrivateMessageBudget(&v, budget)
	if err != nil {
		return q6.PrivateMessage{}, q5.OperationError(err, "PrivateMessage")
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		return q6.PrivateMessage{}, q5.OperationError(*q7.BridgeValidationReportFieldErr(&report), "PrivateMessage")
	}
	if issues := q7.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return q6.PrivateMessage{}, q5.OperationError(&q7.BuildError{Issues: issues}, "PrivateMessage")
	}
	if _, err := q6.BridgePrivateMessageMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return q6.PrivateMessage{}, q5.OperationError(q8.Errorf("%s %w", "PrivateMessage.privateIEs:", err), "PrivateMessage")
	}
	return v, q5.OperationError(nil, "PrivateMessage")
}

// WLANMeasurementQuantitiesItemIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[WLANMeasurementQuantitiesItemIEValue].
type WLANMeasurementQuantitiesItemIEValueProtocolIESingleContainer = WLANMeasurementQuantitiesItemIEField

func BridgeWLANMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIESingleContainer(v *WLANMeasurementQuantitiesItemIEValueProtocolIESingleContainer, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	BridgeWLANMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIEField(v, s)
}
func BridgeWLANMeasurementQuantitiesItemIEValueCompareLPPaProtocolIESingleContainer(v *WLANMeasurementQuantitiesItemIEValueProtocolIESingleContainer, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	BridgeWLANMeasurementQuantitiesItemIEValueCompareLPPaProtocolIEField(v, s)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q9.WLANMeasurementQuantitiesValueExtIEsExtContainer, s *q5.SemanticCapture) {
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
			BridgeWLANMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionContainer(v *q9.WLANMeasurementQuantitiesValueExtIEsExtContainer, s *q5.SemanticComparison) {
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
			BridgeWLANMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
}

// WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding is the concrete IEBinding[WLANMeasurementQuantitiesItem, WLANMeasurementQuantitiesItemIEValue].
type WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding struct {
	info   q10.FieldInfo
	codec  WLANMeasurementQuantitiesItemValueCodec
	inject func(WLANMeasurementQuantitiesItem,

	) WLANMeasurementQuantitiesItemIEValue

	get func(*WLANMeasurementQuantitiesItemIEValue,

	) (*WLANMeasurementQuantitiesItem,

		bool)
}

func (b WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding) Info() q10.FieldInfo {
	return b.info
}
func (b WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding) Codec() WLANMeasurementQuantitiesItemValueCodec {
	return b.codec
}
func (b WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding) New(value WLANMeasurementQuantitiesItem,

) (WLANMeasurementQuantitiesItemIEField, error) {
	if b.inject == nil {
		return WLANMeasurementQuantitiesItemIEField{}, q5.OperationError(q8.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return WLANMeasurementQuantitiesItemIEField{}, q5.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return WLANMeasurementQuantitiesItemIEField{}, q5.OperationError(q8.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), value); err != nil {
		return WLANMeasurementQuantitiesItemIEField{}, q5.OperationError(err, "Value.New")
	}
	return WLANMeasurementQuantitiesItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q5.OperationError(nil, "Value.New")
}
func (b WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding) Get(field *WLANMeasurementQuantitiesItemIEField) (*WLANMeasurementQuantitiesItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WLANMeasurementQuantitiesItemValueCodec is the concrete ValueCodec[WLANMeasurementQuantitiesItem].
type WLANMeasurementQuantitiesItemValueCodec struct {
	context q10.BridgeCodecContext
	capture func(WLANMeasurementQuantitiesItem, q5.DecodeState,

	) (WLANMeasurementQuantitiesItem, q5.Snapshot,

	)
	compare func(WLANMeasurementQuantitiesItem, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (WLANMeasurementQuantitiesItem,

		error)
	encode func(WLANMeasurementQuantitiesItem,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c WLANMeasurementQuantitiesItemValueCodec) New(value WLANMeasurementQuantitiesItem,

) (WLANMeasurementQuantitiesItemAPERValue, error) {
	if c.encode == nil {
		return WLANMeasurementQuantitiesItemAPERValue{}, q5.OperationError(q8.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return WLANMeasurementQuantitiesItemAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANMeasurementQuantitiesItemAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return WLANMeasurementQuantitiesItemAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c WLANMeasurementQuantitiesItemValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (WLANMeasurementQuantitiesItemAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANMeasurementQuantitiesItemAPERValue{}, q5.DecodeReport{}, q8.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return WLANMeasurementQuantitiesItemAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANMeasurementQuantitiesItemAPERValue{}, q5.DecodeReport{}, q8.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return WLANMeasurementQuantitiesItemAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return WLANMeasurementQuantitiesItemAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c WLANMeasurementQuantitiesItemValueCodec) EncodeAPER(value WLANMeasurementQuantitiesItemAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q8.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c WLANMeasurementQuantitiesItemValueCodec) encodeBudget(value WLANMeasurementQuantitiesItem,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANMeasurementQuantitiesItemValueCodec) encodeChanged(value WLANMeasurementQuantitiesItem,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// WLANMeasurementQuantitiesItemIEField is the concrete ProtocolIEField[WLANMeasurementQuantitiesItemIEValue].
type WLANMeasurementQuantitiesItemIEField struct {
	withoutReplay bool
	replay        q5.Snapshot
	stream        q5.WireSpan
	Id            q10.ProtocolIEID
	Criticality   q10.Criticality
	Value         WLANMeasurementQuantitiesItemIEValue

	received q5.CompletePadding
}

func (v WLANMeasurementQuantitiesItemIEField) WithoutReplay() WLANMeasurementQuantitiesItemIEField {
	v.withoutReplay = true
	v.stream = q5.WireSpan{}
	return v
}
func (v *WLANMeasurementQuantitiesItemIEField) ReceivedForm() q5.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q5.ReceivedForm{}
	}
	return q5.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *WLANMeasurementQuantitiesItemIEField) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
		return q8.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return q11.WrapDecodePath(q8.Errorf("%w: field id %d does not match its value selector", q5.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q5.EncodeIntegerAligned(bb, int64(v.Id), q12.BridgeInt64Ptr(0), q12.BridgeInt64Ptr(65535), false); err != nil {
		return q8.Errorf("encoding id: %w", err)
	}
	if err := q5.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q8.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q8.Errorf("encoding value: %w", err)
	}
	if err := q5.EncodeOpenTypeAligned(bb, data); err != nil {
		return q8.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *WLANMeasurementQuantitiesItemIEField) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q8.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WLANMeasurementQuantitiesItemIEField{}
	id, err := q5.DecodeIntegerAligned(bb, q12.BridgeInt64Ptr(0), q12.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q11.WrapDecodePath(err, "Id")
	}
	v.Id = q10.ProtocolIEID(id)
	criticality, err := q5.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q11.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q10.Criticality(criticality)
	var zero WLANMeasurementQuantitiesItemIEValue

	raw, err := q5.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return q11.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return q11.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// WLANMeasurementQuantitiesConcreteValueCodec is the concrete ValueCodec[WLANMeasurementQuantities].
type WLANMeasurementQuantitiesConcreteValueCodec struct {
	context q10.BridgeCodecContext
	capture func(WLANMeasurementQuantities, q5.DecodeState,

	) (WLANMeasurementQuantities, q5.Snapshot,

	)
	compare func(WLANMeasurementQuantities, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (WLANMeasurementQuantities,

		error)
	encode func(WLANMeasurementQuantities,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c WLANMeasurementQuantitiesConcreteValueCodec) New(value WLANMeasurementQuantities,

) (WLANMeasurementQuantitiesAPERValue, error) {
	if c.encode == nil {
		return WLANMeasurementQuantitiesAPERValue{}, q5.OperationError(q8.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return WLANMeasurementQuantitiesAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANMeasurementQuantitiesAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return WLANMeasurementQuantitiesAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c WLANMeasurementQuantitiesConcreteValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (WLANMeasurementQuantitiesAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANMeasurementQuantitiesAPERValue{}, q5.DecodeReport{}, q8.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return WLANMeasurementQuantitiesAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANMeasurementQuantitiesAPERValue{}, q5.DecodeReport{}, q8.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return WLANMeasurementQuantitiesAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return WLANMeasurementQuantitiesAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c WLANMeasurementQuantitiesConcreteValueCodec) EncodeAPER(value WLANMeasurementQuantitiesAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q8.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c WLANMeasurementQuantitiesConcreteValueCodec) encodeBudget(value WLANMeasurementQuantities,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANMeasurementQuantitiesConcreteValueCodec) encodeChanged(value WLANMeasurementQuantities,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// InterRATMeasurementResultValueCodec is the concrete ValueCodec[InterRATMeasurementResult].
type InterRATMeasurementResultValueCodec struct {
	context q10.BridgeCodecContext
	capture func(InterRATMeasurementResult, q5.DecodeState,

	) (InterRATMeasurementResult, q5.Snapshot,

	)
	compare func(InterRATMeasurementResult, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (InterRATMeasurementResult,

		error)
	encode func(InterRATMeasurementResult,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c InterRATMeasurementResultValueCodec) New(value InterRATMeasurementResult,

) (InterRATMeasurementResultAPERValue, error) {
	if c.encode == nil {
		return InterRATMeasurementResultAPERValue{}, q5.OperationError(q8.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return InterRATMeasurementResultAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InterRATMeasurementResultAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return InterRATMeasurementResultAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c InterRATMeasurementResultValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (InterRATMeasurementResultAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return InterRATMeasurementResultAPERValue{}, q5.DecodeReport{}, q8.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return InterRATMeasurementResultAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return InterRATMeasurementResultAPERValue{}, q5.DecodeReport{}, q8.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return InterRATMeasurementResultAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return InterRATMeasurementResultAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c InterRATMeasurementResultValueCodec) EncodeAPER(value InterRATMeasurementResultAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q8.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c InterRATMeasurementResultValueCodec) encodeBudget(value InterRATMeasurementResult,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c InterRATMeasurementResultValueCodec) encodeChanged(value InterRATMeasurementResult,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// InterRATMeasuredResultsValueValueCodec is the concrete ValueCodec[InterRATMeasuredResultsValue].
type InterRATMeasuredResultsValueValueCodec struct {
	context q10.BridgeCodecContext
	capture func(q13.InterRATMeasuredResultsValue, q5.DecodeState,

	) (q13.InterRATMeasuredResultsValue, q5.Snapshot,

	)
	compare func(q13.InterRATMeasuredResultsValue, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q13.InterRATMeasuredResultsValue,

		error)
	encode func(q13.InterRATMeasuredResultsValue,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c InterRATMeasuredResultsValueValueCodec) New(value q13.InterRATMeasuredResultsValue,

) (InterRATMeasuredResultsValueAPERValue, error) {
	if c.encode == nil {
		return InterRATMeasuredResultsValueAPERValue{}, q5.OperationError(q8.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return InterRATMeasuredResultsValueAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InterRATMeasuredResultsValueAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return InterRATMeasuredResultsValueAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c InterRATMeasuredResultsValueValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (InterRATMeasuredResultsValueAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return InterRATMeasuredResultsValueAPERValue{}, q5.DecodeReport{}, q8.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return InterRATMeasuredResultsValueAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return InterRATMeasuredResultsValueAPERValue{}, q5.DecodeReport{}, q8.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return InterRATMeasuredResultsValueAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return InterRATMeasuredResultsValueAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c InterRATMeasuredResultsValueValueCodec) EncodeAPER(value InterRATMeasuredResultsValueAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q8.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c InterRATMeasuredResultsValueValueCodec) encodeBudget(value q13.InterRATMeasuredResultsValue,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c InterRATMeasuredResultsValueValueCodec) encodeChanged(value q13.InterRATMeasuredResultsValue,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}
func BridgeResultNRItemExtIEsValueValidateLPPaExtensionContainer(fields q13.ResultNRItemExtIEsExtContainer, rows []q10.FieldInfo, path string, budget *q5.DecodeBudget) q7.ValidationReport {
	bb := q5.NewBudgetBuffer(budget)
	if err := q5.ChargeSlice[q13.ResultNRItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q7.ValidationReport {
			sealed := q7.ValidationReport{}
			*q7.BridgeValidationReportFieldErr(&sealed) = err
			*q7.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q13.ResultNRItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeResultNRItemExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// WLANMeasurementQuantitiesItemIEContainer is the concrete ProtocolIEContainer[WLANMeasurementQuantitiesItemIEValue].
type WLANMeasurementQuantitiesItemIEContainer []WLANMeasurementQuantitiesItemIEField

// resultNRItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ResultNRItemExtIEsValue].
type ResultNRItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q5.SemanticCapture) q13.ResultNRItemExtIEsValue

	captureFraming() uint64
	captureSnapshot() q5.Snapshot
	compareSemantics(q5.SemanticComparison) q5.SemanticComparison
	decode(q10.ProtocolIEID, q5.OpaqueOpenType) (q13.ResultNRItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q5.DecodeBudget) ([]byte, error)
	matchesID(q10.ProtocolIEID, *q5.DecodeBudget) bool
	reason(q10.ProtocolIEID) q5.OpaqueReason
	rule() q5.SourceRule
}

func BridgeWLANMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIEField(v *WLANMeasurementQuantitiesItemIEField, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q10.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q10.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(v.Value.captureFraming())
	v.Value = v.Value.captureSemantics(*s)
	s.Child(v.Value.captureSnapshot())
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeWLANMeasurementQuantitiesItemIEValueCompareLPPaProtocolIEField(v *WLANMeasurementQuantitiesItemIEField, s *q5.SemanticComparison) {
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
func BridgeWLANMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionField(v *q9.WLANMeasurementQuantitiesValueExtIEsExtField, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q9.BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldFieldStream(v))
	q10.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q10.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q12.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q12.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q12.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q9.BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldFieldReplay(v), *q9.BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionField(v *q9.WLANMeasurementQuantitiesValueExtIEsExtField, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q14.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q14.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q12.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q9.BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldFieldReplay(v), *q9.BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldFieldWithoutReplay(v))
}

// WLANMeasurementQuantitiesItemAPERValue is the concrete APERValue[WLANMeasurementQuantitiesItem].
type WLANMeasurementQuantitiesItemAPERValue struct {
	context q10.BridgeCodecContext
	Value   WLANMeasurementQuantitiesItem

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v WLANMeasurementQuantitiesItemAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v WLANMeasurementQuantitiesItemAPERValue) WithoutReplay() WLANMeasurementQuantitiesItemAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// WLANMeasurementQuantitiesAPERValue is the concrete APERValue[WLANMeasurementQuantities].
type WLANMeasurementQuantitiesAPERValue struct {
	context q10.BridgeCodecContext
	Value   WLANMeasurementQuantities

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v WLANMeasurementQuantitiesAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v WLANMeasurementQuantitiesAPERValue) WithoutReplay() WLANMeasurementQuantitiesAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// InterRATMeasurementResultAPERValue is the concrete APERValue[InterRATMeasurementResult].
type InterRATMeasurementResultAPERValue struct {
	context q10.BridgeCodecContext
	Value   InterRATMeasurementResult

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v InterRATMeasurementResultAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v InterRATMeasurementResultAPERValue) WithoutReplay() InterRATMeasurementResultAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// InterRATMeasuredResultsValueAPERValue is the concrete APERValue[InterRATMeasuredResultsValue].
type InterRATMeasuredResultsValueAPERValue struct {
	context q10.BridgeCodecContext
	Value   q13.InterRATMeasuredResultsValue

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v InterRATMeasuredResultsValueAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v InterRATMeasuredResultsValueAPERValue) WithoutReplay() InterRATMeasuredResultsValueAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeResultNRItemExtIEsValueValidateLPPaIEContainer(fields q13.ResultNRItemExtIEsIEContainer, rows []q10.FieldInfo, path string, budget *q5.DecodeBudget,

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
	byID := make(map[q10.ProtocolIEID]int, len(rows))
	counts := make(map[q10.ProtocolIEID]int, len(fields))
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
		location := q5.Location{Path: q5.Path(q8.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q13.BridgeResultNRItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q13.BridgeResultNRItemExtIEsValueMethodRule(field.Value)
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q10.ValueIDMismatch, Severity: q10.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q8.Sprintf("%s.id", location.Path))}, Table: func() q10.TableID {
				sealed := q10.TableID{}
				*q10.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q9.BridgeLppaValidationRule(q10.ValueIDMismatch), RelatedRules: []q5.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q5.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q10.FieldInfo
			related := []q5.SourceRule{q9.BridgeLppaAdoptedRule(q10.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q10.RepeatedIE, Severity: q10.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q9.BridgeLppaValidationRule(q10.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q10.ValidationSeverityUnrecognized
			if _, globallyKnown := q9.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q10.ValidationSeverityError
			}
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q10.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q9.BridgeLppaValidationRule(q10.NotAllowed), RelatedRules: q9.BridgeLppaHandlingRules(q10.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q10.WrongCriticality, Severity: q10.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q8.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q9.BridgeLppaValidationRule(q10.WrongCriticality), RelatedRules: []q5.SourceRule{q9.BridgeLppaAdoptedRule(q10.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q10.WrongOrder, Severity: q10.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q9.BridgeLppaValidationRule(q10.WrongOrder), RelatedRules: []q5.SourceRule{q9.BridgeLppaAdoptedRule(q10.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q10.PresenceMandatory && counts[row.ID] == 0 {
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q10.MissingMandatory, Severity: q10.ValidationSeverityError, Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q9.BridgeLppaValidationRule(q10.MissingMandatory), RelatedRules: []q5.SourceRule{q9.BridgeLppaAdoptedRule(q10.MissingMandatory), row.Rule}})
		}
		if row.Presence == q10.PresenceConditional {
			q7.BridgeValidationReportMethodAddDeferred(&report, q10.DeferredCondition{Location: q5.Location{Path: q5.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q7.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

type InterRATMeasurementResult = []q13.InterRATMeasuredResultsValue

// NewInterRATMeasuredResultsValueResultGERAN creates a InterRATMeasuredResultsValue with the resultGERAN alternative.
func BridgeNewInterRATMeasuredResultsValueResultGERANLegacy(v q6.ResultGERAN) q13.InterRATMeasuredResultsValue {
	return q13.InterRATMeasuredResultsValue{
		Choice:      q10.InterRATMeasuredResultsValueChoiceResultGERAN,
		ResultGERAN: v,
	}
}

// NewInterRATMeasuredResultsValueResultUTRAN creates a InterRATMeasuredResultsValue with the resultUTRAN alternative.
func BridgeNewInterRATMeasuredResultsValueResultUTRANLegacy(v q15.ResultUTRAN) q13.InterRATMeasuredResultsValue {
	return q13.InterRATMeasuredResultsValue{
		Choice:      q10.InterRATMeasuredResultsValueChoiceResultUTRAN,
		ResultUTRAN: v,
	}
}

// NewInterRATMeasuredResultsValueResultNR creates a InterRATMeasuredResultsValue with the resultNR alternative.
func BridgeNewInterRATMeasuredResultsValueResultNRLegacy(v q13.ResultNR) q13.InterRATMeasuredResultsValue {
	return q13.InterRATMeasuredResultsValue{
		Choice:   q10.InterRATMeasuredResultsValueChoiceResultNR,
		ResultNR: v,
	}
}

type WLANMeasurementQuantities = []WLANMeasurementQuantitiesItemIEValueProtocolIESingleContainer

// WLANMeasurementQuantitiesItem represents the ASN.1 type WLANMeasurementQuantities-Item (SEQUENCE).
type WLANMeasurementQuantitiesItem struct {
	replay                         q5.Snapshot
	stream                         q5.WireSpan
	withoutReplay                  bool
	received                       bool
	receivedBytes                  q5.WireSpan
	WLANMeasurementQuantitiesValue q10.WLANMeasurementQuantitiesValue                  `asn1:"tag:0,context,implicit"`
	IEExtensions                   q9.WLANMeasurementQuantitiesValueExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef              bool                                                `asn1:"-" json:"-"`
	extCount                       int64                                               `asn1:"-" json:"-"`
	extPresent                     []bool                                              `asn1:"-" json:"-"`
	extData                        [][]byte                                            `asn1:"-" json:"-"`
	perPadding                     q5.FinalPadding                                     `asn1:"-" json:"-"`
	perExtPadding                  []q5.CompletePadding                                `asn1:"-" json:"-"`
	extOrigin                      []q5.OpaqueOrigin
	extWire                        []q5.WireSpan
}
type BridgeAsn1cAPERInterRATMeasurementResultListValue struct{ Value InterRATMeasurementResult }

// InterRATMeasurementResultComplete carries a complete InterRATMeasurementResult encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type InterRATMeasurementResultComplete struct {
	replay        q5.Snapshot
	stream        q5.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q5.WireSpan
	Value         InterRATMeasurementResult
	perPadding    q5.CompletePadding `json:"-"`
}

func (v *InterRATMeasurementResultComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := BridgeMarshalAPERInterRATMeasurementResultTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes InterRATMeasurementResult from APER format.
func (v *InterRATMeasurementResultComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes InterRATMeasurementResult with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *InterRATMeasurementResultComplete) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q11.WrapDecodePath(err, "InterRATMeasurementResult")
	}
	value, err := BridgeUnmarshalAPERInterRATMeasurementResultFrom(bb)
	if err != nil {
		return q11.WrapDecodePath(err, "InterRATMeasurementResult")
	}
	padding, err := q5.CaptureFinalBits(bb, "InterRATMeasurementResult")
	if err != nil {
		return q11.WrapDecodePath(err, "InterRATMeasurementResult")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERInterRATMeasurementResult encodes a InterRATMeasurementResult list to APER.
func BridgeMarshalAPERInterRATMeasurementResult(list InterRATMeasurementResultComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// MarshalAPERInterRATMeasurementResultTo appends a InterRATMeasurementResult list to bb.
func BridgeMarshalAPERInterRATMeasurementResultTo(list InterRATMeasurementResult, bb *q5.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERInterRATMeasurementResultListValue{Value: list}
	if err := q5.EncodeCollection(bb, int64(len(v.Value)), q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q8.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := q13.BridgeInterRATMeasuredResultsValueMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q8.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q8.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERInterRATMeasurementResult decodes a InterRATMeasurementResult list from APER.
func BridgeUnmarshalAPERInterRATMeasurementResult(data []byte) (InterRATMeasurementResultComplete, error) {
	var value InterRATMeasurementResultComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERInterRATMeasurementResultFrom decodes a InterRATMeasurementResult list from bb.
func BridgeUnmarshalAPERInterRATMeasurementResultFrom(bb *q5.BitBuffer) (InterRATMeasurementResult, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v BridgeAsn1cAPERInterRATMeasurementResultListValue
	if err := BridgeUnmarshalAPERInterRATMeasurementResultInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERInterRATMeasurementResultInto(v *BridgeAsn1cAPERInterRATMeasurementResultListValue, bb *q5.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(InterRATMeasurementResult, 0)
	_, errCollection_value := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q8.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q13.InterRATMeasuredResultsValue
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := q13.BridgeInterRATMeasuredResultsValueMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q11.WrapDecodePath(err, q8.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := q5.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return q11.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// ResultNRComplete carries a complete ResultNR encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultNRComplete struct {
	replay        q5.Snapshot
	stream        q5.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q5.WireSpan
	Value         q13.ResultNR
	perPadding    q5.CompletePadding `json:"-"`
}

func (v *ResultNRComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := BridgeMarshalAPERResultNRTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ResultNR from APER format.
func (v *ResultNRComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResultNR with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResultNRComplete) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q11.WrapDecodePath(err, "ResultNR")
	}
	value, err := BridgeUnmarshalAPERResultNRFrom(bb)
	if err != nil {
		return q11.WrapDecodePath(err, "ResultNR")
	}
	padding, err := q5.CaptureFinalBits(bb, "ResultNR")
	if err != nil {
		return q11.WrapDecodePath(err, "ResultNR")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERResultNR encodes a ResultNR list to APER.
func BridgeMarshalAPERResultNR(list ResultNRComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// MarshalAPERResultNRTo appends a ResultNR list to bb.
func BridgeMarshalAPERResultNRTo(list q13.ResultNR, bb *q5.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := q13.BridgeAsn1cAPERResultNRListValue{Value: list}
	if err := q5.EncodeCollection(bb, int64(len(v.Value)), q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q8.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := q13.BridgeResultNRItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q8.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q8.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERResultNR decodes a ResultNR list from APER.
func BridgeUnmarshalAPERResultNR(data []byte) (ResultNRComplete, error) {
	var value ResultNRComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERResultNRFrom decodes a ResultNR list from bb.
func BridgeUnmarshalAPERResultNRFrom(bb *q5.BitBuffer) (q13.ResultNR, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q13.BridgeAsn1cAPERResultNRListValue
	if err := BridgeUnmarshalAPERResultNRInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERResultNRInto(v *q13.BridgeAsn1cAPERResultNRListValue, bb *q5.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(q13.ResultNR, 0)
	_, errCollection_value := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q8.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q13.ResultNRItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := q13.BridgeResultNRItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q11.WrapDecodePath(err, q8.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := q5.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return q11.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// UnmarshalAPERResultsPerSSBIndexList decodes a ResultsPerSSBIndexList list from APER.
func BridgeUnmarshalAPERResultsPerSSBIndexList(data []byte) (q13.ResultsPerSSBIndexListComplete, error) {
	var value q13.ResultsPerSSBIndexListComplete
	if err := q13.BridgeResultsPerSSBIndexListCompleteMethodUnmarshalAPERLegacy(&value, data); err != nil {
		return value, err
	}
	return value, nil
}

// SRSConfigurationForAllCellsComplete carries a complete SRSConfigurationForAllCells encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type SRSConfigurationForAllCellsComplete struct {
	replay        q5.Snapshot
	stream        q5.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q5.WireSpan
	Value         q7.SRSConfigurationForAllCells
	perPadding    q5.CompletePadding `json:"-"`
}

func (v *SRSConfigurationForAllCellsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := q16.BridgeMarshalAPERSRSConfigurationForAllCellsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes SRSConfigurationForAllCells from APER format.
func (v *SRSConfigurationForAllCellsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SRSConfigurationForAllCells with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SRSConfigurationForAllCellsComplete) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q11.WrapDecodePath(err, "SRSConfigurationForAllCells")
	}
	value, err := BridgeUnmarshalAPERSRSConfigurationForAllCellsFrom(bb)
	if err != nil {
		return q11.WrapDecodePath(err, "SRSConfigurationForAllCells")
	}
	padding, err := q5.CaptureFinalBits(bb, "SRSConfigurationForAllCells")
	if err != nil {
		return q11.WrapDecodePath(err, "SRSConfigurationForAllCells")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERSRSConfigurationForAllCells encodes a SRSConfigurationForAllCells list to APER.
func BridgeMarshalAPERSRSConfigurationForAllCells(list SRSConfigurationForAllCellsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERSRSConfigurationForAllCells decodes a SRSConfigurationForAllCells list from APER.
func BridgeUnmarshalAPERSRSConfigurationForAllCells(data []byte) (SRSConfigurationForAllCellsComplete, error) {
	var value SRSConfigurationForAllCellsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERSRSConfigurationForAllCellsFrom decodes a SRSConfigurationForAllCells list from bb.
func BridgeUnmarshalAPERSRSConfigurationForAllCellsFrom(bb *q5.BitBuffer) (q7.SRSConfigurationForAllCells, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q7.BridgeAsn1cAPERSRSConfigurationForAllCellsListValue
	if err := BridgeUnmarshalAPERSRSConfigurationForAllCellsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERSRSConfigurationForAllCellsInto(v *q7.BridgeAsn1cAPERSRSConfigurationForAllCellsListValue, bb *q5.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(q7.SRSConfigurationForAllCells, 0)
	_, errCollection_value := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 5, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q8.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q7.SRSConfigurationForOneCell
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := q7.BridgeSRSConfigurationForOneCellMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q11.WrapDecodePath(err, q8.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := q5.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return q11.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// SystemInformationComplete carries a complete SystemInformation encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type SystemInformationComplete struct {
	replay        q5.Snapshot
	stream        q5.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q5.WireSpan
	Value         q15.SystemInformation
	perPadding    q5.CompletePadding `json:"-"`
}

func (v *SystemInformationComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := q17.BridgeMarshalAPERSystemInformationTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes SystemInformation from APER format.
func (v *SystemInformationComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SystemInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SystemInformationComplete) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q11.WrapDecodePath(err, "SystemInformation")
	}
	value, err := BridgeUnmarshalAPERSystemInformationFrom(bb)
	if err != nil {
		return q11.WrapDecodePath(err, "SystemInformation")
	}
	padding, err := q5.CaptureFinalBits(bb, "SystemInformation")
	if err != nil {
		return q11.WrapDecodePath(err, "SystemInformation")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERSystemInformation encodes a SystemInformation list to APER.
func BridgeMarshalAPERSystemInformation(list SystemInformationComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERSystemInformation decodes a SystemInformation list from APER.
func BridgeUnmarshalAPERSystemInformation(data []byte) (SystemInformationComplete, error) {
	var value SystemInformationComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERSystemInformationFrom decodes a SystemInformation list from bb.
func BridgeUnmarshalAPERSystemInformationFrom(bb *q5.BitBuffer) (q15.SystemInformation, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q15.BridgeAsn1cAPERSystemInformationListValue
	if err := BridgeUnmarshalAPERSystemInformationInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERSystemInformationInto(v *q15.BridgeAsn1cAPERSystemInformationListValue, bb *q5.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(q15.SystemInformation, 0)
	_, errCollection_value := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q8.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q15.SystemInformationElem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := q15.BridgeSystemInformationElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q11.WrapDecodePath(err, q8.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := q5.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return q11.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

type BridgeAsn1cAPERWLANMeasurementQuantitiesListValue struct{ Value WLANMeasurementQuantities }

// WLANMeasurementQuantitiesComplete carries a complete WLANMeasurementQuantities encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type WLANMeasurementQuantitiesComplete struct {
	replay        q5.Snapshot
	stream        q5.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q5.WireSpan
	Value         WLANMeasurementQuantities
	perPadding    q5.CompletePadding `json:"-"`
}

func (v *WLANMeasurementQuantitiesComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := BridgeMarshalAPERWLANMeasurementQuantitiesTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes WLANMeasurementQuantities from APER format.
func (v *WLANMeasurementQuantitiesComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes WLANMeasurementQuantities with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *WLANMeasurementQuantitiesComplete) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q11.WrapDecodePath(err, "WLANMeasurementQuantities")
	}
	value, err := BridgeUnmarshalAPERWLANMeasurementQuantitiesFrom(bb)
	if err != nil {
		return q11.WrapDecodePath(err, "WLANMeasurementQuantities")
	}
	padding, err := q5.CaptureFinalBits(bb, "WLANMeasurementQuantities")
	if err != nil {
		return q11.WrapDecodePath(err, "WLANMeasurementQuantities")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERWLANMeasurementQuantitiesTo appends a WLANMeasurementQuantities list to bb.
func BridgeMarshalAPERWLANMeasurementQuantitiesTo(list WLANMeasurementQuantities, bb *q5.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERWLANMeasurementQuantitiesListValue{Value: list}
	if err := q5.EncodeCollection(bb, int64(len(v.Value)), q5.SizeConstraint{Lower: 0, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q8.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q8.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q8.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERWLANMeasurementQuantitiesFrom decodes a WLANMeasurementQuantities list from bb.
func BridgeUnmarshalAPERWLANMeasurementQuantitiesFrom(bb *q5.BitBuffer) (WLANMeasurementQuantities, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v BridgeAsn1cAPERWLANMeasurementQuantitiesListValue
	if err := BridgeUnmarshalAPERWLANMeasurementQuantitiesInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERWLANMeasurementQuantitiesInto(v *BridgeAsn1cAPERWLANMeasurementQuantitiesListValue, bb *q5.BitBuffer) error {
	v.Value = make(WLANMeasurementQuantities, 0)
	_, errCollection_value := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 0, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q8.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem WLANMeasurementQuantitiesItemIEValueProtocolIESingleContainer
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return q11.WrapDecodePath(err, q8.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := q5.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return q11.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// MarshalAPER encodes WLANMeasurementQuantitiesItem to APER format.
func (v *WLANMeasurementQuantitiesItem) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *WLANMeasurementQuantitiesItem) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.replay.
			ReplayTo(v.stream, bb); ok ||
			err != nil {
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
		extensionCount, _ = q18.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	// Preamble bitmap for optional root fields
	if err := q5.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q5.EncodeEnumeratedAligned(bb, int64(v.WLANMeasurementQuantitiesValue), 1, true); err != nil {
		return q8.Errorf("encoding wLANMeasurementQuantitiesValue: %w", err)
	}
	if v.IEExtensions != nil {
		if err := q5.EncodeCollection(bb, int64(len(v.IEExtensions)), q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q8.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q9.BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return q8.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return q8.Errorf("encoding iE-Extensions: %w", err)
		}
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q8.Errorf("%w: extension bitmap index %d", q5.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q5.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q8.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q5.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q8.Errorf("extension count out of range")
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

// UnmarshalAPER decodes WLANMeasurementQuantitiesItem from APER format.
func (v *WLANMeasurementQuantitiesItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes WLANMeasurementQuantitiesItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *WLANMeasurementQuantitiesItem) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q11.WrapDecodePath(err, "WLANMeasurementQuantitiesItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q11.WrapDecodePath(err, "WLANMeasurementQuantitiesItem")
	}
	padding, err := q5.CaptureFinalBits(bb, "WLANMeasurementQuantitiesItem")
	if err != nil {
		return q11.WrapDecodePath(err, "WLANMeasurementQuantitiesItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *WLANMeasurementQuantitiesItem) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WLANMeasurementQuantitiesItem{}
	extAdditions := q5.BeginExtensionAdditions(bb)
	hasExtensions, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_wlanmeasurementquantitiesvalue, err := q5.DecodeEnumeratedAligned(bb, 1, true, q5.EnumerationSource{KnownExtensions: 0, Path: "WLANMeasurementQuantitiesValue"})
	if err != nil {
		return q11.WrapDecodePath(err, "WLANMeasurementQuantitiesValue")
	}
	v.WLANMeasurementQuantitiesValue = q10.WLANMeasurementQuantitiesValue(val_wlanmeasurementquantitiesvalue)
	if opt_ieextensions {
		tmp_ieextensions := make(q9.WLANMeasurementQuantitiesValueExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q8.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q9.WLANMeasurementQuantitiesValueExtIEsExtField
				if err := q9.BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q11.WrapDecodePath(err, q8.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				if next, err := q5.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return q11.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q11.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q8.Errorf("extension count out of range")
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
			return q8.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q5.DecodeOpaqueOpenTypeAligned(bb, q5.UnknownSelector, q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
				if err != nil {
					return q11.WrapDecodePath(err, q8.Sprintf("ExtData_[%d]", i))
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
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// WLANChannelListComplete carries a complete WLANChannelList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type WLANChannelListComplete struct {
	replay        q5.Snapshot
	stream        q5.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q5.WireSpan
	Value         q10.WLANChannelList
	perPadding    q5.CompletePadding `json:"-"`
}

func (v *WLANChannelListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := q9.BridgeMarshalAPERWLANChannelListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes WLANChannelList from APER format.
func (v *WLANChannelListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes WLANChannelList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *WLANChannelListComplete) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q11.WrapDecodePath(err, "WLANChannelList")
	}
	value, err := BridgeUnmarshalAPERWLANChannelListFrom(bb)
	if err != nil {
		return q11.WrapDecodePath(err, "WLANChannelList")
	}
	padding, err := q5.CaptureFinalBits(bb, "WLANChannelList")
	if err != nil {
		return q11.WrapDecodePath(err, "WLANChannelList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERWLANChannelList encodes a WLANChannelList list to APER.
func BridgeMarshalAPERWLANChannelList(list WLANChannelListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERWLANChannelList decodes a WLANChannelList list from APER.
func BridgeUnmarshalAPERWLANChannelList(data []byte) (WLANChannelListComplete, error) {
	var value WLANChannelListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERWLANChannelListFrom decodes a WLANChannelList list from bb.
func BridgeUnmarshalAPERWLANChannelListFrom(bb *q5.BitBuffer) (q10.WLANChannelList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q10.BridgeAsn1cAPERWLANChannelListListValue
	if err := BridgeUnmarshalAPERWLANChannelListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERWLANChannelListInto(v *q10.BridgeAsn1cAPERWLANChannelListListValue, bb *q5.BitBuffer) error {
	v.Value = make(q10.WLANChannelList, 0)
	_, errCollection_value := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_2: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1136
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q8.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := q5.DecodeIntegerAligned(bb, q12.BridgeInt64Ptr(0), q12.BridgeInt64Ptr(255), false)
			if err != nil {
				return q11.WrapDecodePath(err, q8.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := q5.AppendValues(bb, v.Value, q10.WLANChannel(val)); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return q11.WrapDecodePath(errCollection_value, "Value")
	}
	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *InterRATMeasurementResultComplete) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q18.BridgeReceivedFormAt(v.received, v.receivedBytes, "InterRATMeasurementResultComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InterRATMeasurementResultComplete) WithoutReplay() InterRATMeasurementResultComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero InterRATMeasurementResultComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultNRComplete) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q18.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultNRComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultNRComplete) WithoutReplay() ResultNRComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero ResultNRComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SRSConfigurationForAllCellsComplete) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q18.BridgeReceivedFormAt(v.received, v.receivedBytes, "SRSConfigurationForAllCellsComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SRSConfigurationForAllCellsComplete) WithoutReplay() SRSConfigurationForAllCellsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero SRSConfigurationForAllCellsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SystemInformationComplete) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q18.BridgeReceivedFormAt(v.received, v.receivedBytes, "SystemInformationComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SystemInformationComplete) WithoutReplay() SystemInformationComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero SystemInformationComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WLANChannelListComplete) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q18.BridgeReceivedFormAt(v.received, v.receivedBytes, "WLANChannelListComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WLANChannelListComplete) WithoutReplay() WLANChannelListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero WLANChannelListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WLANMeasurementQuantitiesComplete) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q18.BridgeReceivedFormAt(v.received, v.receivedBytes, "WLANMeasurementQuantitiesComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WLANMeasurementQuantitiesComplete) WithoutReplay() WLANMeasurementQuantitiesComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero WLANMeasurementQuantitiesComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WLANMeasurementQuantitiesItem) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q18.BridgeReceivedFormAt(v.received, v.receivedBytes, "WLANMeasurementQuantitiesItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WLANMeasurementQuantitiesItem) WithoutReplay() WLANMeasurementQuantitiesItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero WLANMeasurementQuantitiesItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *WLANMeasurementQuantitiesItem) Extensions() []q5.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q5.SequenceExtensionViews(v.extPresent, q5.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *WLANMeasurementQuantitiesItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q11.WrapDecodePath(q5.ErrInvalidValue, q8.Sprintf("WLANMeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if err := q5.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q11.WrapDecodePath(err, q8.Sprintf("WLANMeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *WLANMeasurementQuantitiesItem) RemoveExtension(index uint64) error {
	if v == nil {
		return q11.WrapDecodePath(q5.ErrInvalidValue, q8.Sprintf("WLANMeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if err := q5.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q11.WrapDecodePath(err, q8.Sprintf("WLANMeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *InterRATMeasurementResultComplete) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "InterRATMeasurementResultComplete")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "InterRATMeasurementResultComplete")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaInterRATMeasurementResultComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "InterRATMeasurementResultComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "InterRATMeasurementResultComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "InterRATMeasurementResultComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "InterRATMeasurementResultComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "InterRATMeasurementResultComplete")
}
func (v *InterRATMeasurementResultComplete) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *InterRATMeasurementResultComplete) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *InterRATMeasurementResultComplete) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
		BridgeCompareLPPaInterRATMeasurementResultComplete(v, &s)
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
func (v *InterRATMeasurementResultComplete) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *InterRATMeasurementResultComplete) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q5.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := BridgeMarshalAPERInterRATMeasurementResultTo(value.Value, bb, fresh); err != nil {
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
func (v *ResultNRComplete) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "ResultNRComplete")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "ResultNRComplete")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaResultNRComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "ResultNRComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "ResultNRComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "ResultNRComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "ResultNRComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "ResultNRComplete")
}
func (v *ResultNRComplete) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultNRComplete) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultNRComplete) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
		BridgeCompareLPPaResultNRComplete(v, &s)
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
func (v *ResultNRComplete) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultNRComplete) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q5.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := BridgeMarshalAPERResultNRTo(value.Value, bb, fresh); err != nil {
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
func (v *SRSConfigurationForAllCellsComplete) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "SRSConfigurationForAllCellsComplete")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "SRSConfigurationForAllCellsComplete")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaSRSConfigurationForAllCellsComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "SRSConfigurationForAllCellsComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "SRSConfigurationForAllCellsComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "SRSConfigurationForAllCellsComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "SRSConfigurationForAllCellsComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "SRSConfigurationForAllCellsComplete")
}
func (v *SRSConfigurationForAllCellsComplete) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *SRSConfigurationForAllCellsComplete) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *SRSConfigurationForAllCellsComplete) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
		BridgeCompareLPPaSRSConfigurationForAllCellsComplete(v, &s)
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
func (v *SRSConfigurationForAllCellsComplete) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *SRSConfigurationForAllCellsComplete) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q5.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q16.BridgeMarshalAPERSRSConfigurationForAllCellsTo(value.Value, bb, fresh); err != nil {
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
func (v *SystemInformationComplete) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "SystemInformationComplete")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "SystemInformationComplete")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaSystemInformationComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "SystemInformationComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "SystemInformationComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "SystemInformationComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "SystemInformationComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "SystemInformationComplete")
}
func (v *SystemInformationComplete) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *SystemInformationComplete) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *SystemInformationComplete) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
		BridgeCompareLPPaSystemInformationComplete(v, &s)
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
func (v *SystemInformationComplete) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *SystemInformationComplete) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q5.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q17.BridgeMarshalAPERSystemInformationTo(value.Value, bb, fresh); err != nil {
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
func (v *WLANChannelListComplete) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "WLANChannelListComplete")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "WLANChannelListComplete")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaWLANChannelListComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "WLANChannelListComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "WLANChannelListComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "WLANChannelListComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "WLANChannelListComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "WLANChannelListComplete")
}
func (v *WLANChannelListComplete) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *WLANChannelListComplete) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *WLANChannelListComplete) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
		BridgeCompareLPPaWLANChannelListComplete(v, &s)
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
func (v *WLANChannelListComplete) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *WLANChannelListComplete) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q5.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q9.BridgeMarshalAPERWLANChannelListTo(value.Value, bb, fresh); err != nil {
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
func (v *WLANMeasurementQuantitiesComplete) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "WLANMeasurementQuantitiesComplete")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "WLANMeasurementQuantitiesComplete")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaWLANMeasurementQuantitiesComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "WLANMeasurementQuantitiesComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "WLANMeasurementQuantitiesComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "WLANMeasurementQuantitiesComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "WLANMeasurementQuantitiesComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "WLANMeasurementQuantitiesComplete")
}
func (v *WLANMeasurementQuantitiesComplete) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *WLANMeasurementQuantitiesComplete) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *WLANMeasurementQuantitiesComplete) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
		BridgeCompareLPPaWLANMeasurementQuantitiesComplete(v, &s)
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
func (v *WLANMeasurementQuantitiesComplete) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *WLANMeasurementQuantitiesComplete) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q5.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := BridgeMarshalAPERWLANMeasurementQuantitiesTo(value.Value, bb, fresh); err != nil {
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
func (v *WLANMeasurementQuantitiesItem) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "WLANMeasurementQuantitiesItem")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "WLANMeasurementQuantitiesItem")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaWLANMeasurementQuantitiesItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "WLANMeasurementQuantitiesItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "WLANMeasurementQuantitiesItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "WLANMeasurementQuantitiesItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "WLANMeasurementQuantitiesItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "WLANMeasurementQuantitiesItem")
}
func (v *WLANMeasurementQuantitiesItem) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *WLANMeasurementQuantitiesItem) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *WLANMeasurementQuantitiesItem) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
		BridgeCompareLPPaWLANMeasurementQuantitiesItem(v, &s)
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
func (v *WLANMeasurementQuantitiesItem) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *WLANMeasurementQuantitiesItem) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *InterRATMeasurementResultComplete) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "InterRATMeasurementResultComplete")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded InterRATMeasurementResultComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaInterRATMeasurementResultComplete(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = InterRATMeasurementResultComplete{}
		return report, q5.OperationError(err, "InterRATMeasurementResultComplete")
	}
	*v = decoded
	return report, q5.OperationError(nil, "InterRATMeasurementResultComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultNRComplete) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "ResultNRComplete")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded ResultNRComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultNRComplete(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = ResultNRComplete{}
		return report, q5.OperationError(err, "ResultNRComplete")
	}
	*v = decoded
	return report, q5.OperationError(nil, "ResultNRComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *SRSConfigurationForAllCellsComplete) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "SRSConfigurationForAllCellsComplete")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded SRSConfigurationForAllCellsComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaSRSConfigurationForAllCellsComplete(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = SRSConfigurationForAllCellsComplete{}
		return report, q5.OperationError(err, "SRSConfigurationForAllCellsComplete")
	}
	*v = decoded
	return report, q5.OperationError(nil, "SRSConfigurationForAllCellsComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *SystemInformationComplete) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "SystemInformationComplete")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded SystemInformationComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaSystemInformationComplete(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = SystemInformationComplete{}
		return report, q5.OperationError(err, "SystemInformationComplete")
	}
	*v = decoded
	return report, q5.OperationError(nil, "SystemInformationComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *WLANChannelListComplete) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "WLANChannelListComplete")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded WLANChannelListComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaWLANChannelListComplete(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = WLANChannelListComplete{}
		return report, q5.OperationError(err, "WLANChannelListComplete")
	}
	*v = decoded
	return report, q5.OperationError(nil, "WLANChannelListComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *WLANMeasurementQuantitiesComplete) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "WLANMeasurementQuantitiesComplete")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded WLANMeasurementQuantitiesComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaWLANMeasurementQuantitiesComplete(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = WLANMeasurementQuantitiesComplete{}
		return report, q5.OperationError(err, "WLANMeasurementQuantitiesComplete")
	}
	*v = decoded
	return report, q5.OperationError(nil, "WLANMeasurementQuantitiesComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *WLANMeasurementQuantitiesItem) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "WLANMeasurementQuantitiesItem")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded WLANMeasurementQuantitiesItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaWLANMeasurementQuantitiesItem(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = WLANMeasurementQuantitiesItem{}
		return report, q5.OperationError(err, "WLANMeasurementQuantitiesItem")
	}
	*v = decoded
	return report, q5.OperationError(nil, "WLANMeasurementQuantitiesItem")
}

// NewInterRATMeasuredResultsValueResultGERAN constructs a checked complete value.
func NewInterRATMeasuredResultsValueResultGERAN(v q6.ResultGERAN, options ...q5.BuildOption) (q13.InterRATMeasuredResultsValue, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q13.InterRATMeasuredResultsValue{}, q5.OperationError(err, "InterRATMeasuredResultsValueResultGERAN")
	}
	value := BridgeNewInterRATMeasuredResultsValueResultGERANLegacy(v)
	if _, err := q13.BridgeInterRATMeasuredResultsValueMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q13.InterRATMeasuredResultsValue{}, q5.OperationError(err, "InterRATMeasuredResultsValueResultGERAN")
	}
	return value, q5.OperationError(nil, "InterRATMeasuredResultsValueResultGERAN")
}

// NewInterRATMeasuredResultsValueResultUTRAN constructs a checked complete value.
func NewInterRATMeasuredResultsValueResultUTRAN(v q15.ResultUTRAN, options ...q5.BuildOption) (q13.InterRATMeasuredResultsValue, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q13.InterRATMeasuredResultsValue{}, q5.OperationError(err, "InterRATMeasuredResultsValueResultUTRAN")
	}
	value := BridgeNewInterRATMeasuredResultsValueResultUTRANLegacy(v)
	if _, err := q13.BridgeInterRATMeasuredResultsValueMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q13.InterRATMeasuredResultsValue{}, q5.OperationError(err, "InterRATMeasuredResultsValueResultUTRAN")
	}
	return value, q5.OperationError(nil, "InterRATMeasuredResultsValueResultUTRAN")
}

// NewInterRATMeasuredResultsValueResultNR constructs a checked complete value.
func NewInterRATMeasuredResultsValueResultNR(v q13.ResultNR, options ...q5.BuildOption) (q13.InterRATMeasuredResultsValue, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q13.InterRATMeasuredResultsValue{}, q5.OperationError(err, "InterRATMeasuredResultsValueResultNR")
	}
	value := BridgeNewInterRATMeasuredResultsValueResultNRLegacy(v)
	if _, err := q13.BridgeInterRATMeasuredResultsValueMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q13.InterRATMeasuredResultsValue{}, q5.OperationError(err, "InterRATMeasuredResultsValueResultNR")
	}
	return value, q5.OperationError(nil, "InterRATMeasuredResultsValueResultNR")
}

// NewInterRATMeasuredResultsValueUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewInterRATMeasuredResultsValueUnknownExtension(index uint64, contents []byte, options ...q5.BuildOption) (q13.InterRATMeasuredResultsValue, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q13.InterRATMeasuredResultsValue{}, q5.OperationError(err, "InterRATMeasuredResultsValueUnknownExtension")
	}
	extension, err := q5.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return q13.InterRATMeasuredResultsValue{}, q5.OperationError(err, "InterRATMeasuredResultsValueUnknownExtension")
	}
	value := q13.InterRATMeasuredResultsValue{UnknownExtension: &extension}
	if _, err := q13.BridgeInterRATMeasuredResultsValueMethodMarshalAPERBudget(&value, budget, false); err != nil {
		return q13.InterRATMeasuredResultsValue{}, q5.OperationError(err, "InterRATMeasuredResultsValueUnknownExtension")
	}
	return value, q5.OperationError(nil, "InterRATMeasuredResultsValueUnknownExtension")
}

// MarshalAPERInterRATMeasurementResult encodes a complete named list.
func MarshalAPERInterRATMeasurementResult(v InterRATMeasurementResultComplete, options ...q5.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERResultNR encodes a complete named list.
func MarshalAPERResultNR(v ResultNRComplete, options ...q5.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERSRSConfigurationForAllCells encodes a complete named list.
func MarshalAPERSRSConfigurationForAllCells(v SRSConfigurationForAllCellsComplete, options ...q5.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERSystemInformation encodes a complete named list.
func MarshalAPERSystemInformation(v SystemInformationComplete, options ...q5.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERWLANChannelList encodes a complete named list.
func MarshalAPERWLANChannelList(v WLANChannelListComplete, options ...q5.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERInterRATMeasurementResult decodes a complete named list.
func UnmarshalAPERInterRATMeasurementResult(data []byte, options ...q5.DecodeOption) (InterRATMeasurementResultComplete, q5.DecodeReport, error) {
	var v InterRATMeasurementResultComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERResultNR decodes a complete named list.
func UnmarshalAPERResultNR(data []byte, options ...q5.DecodeOption) (ResultNRComplete, q5.DecodeReport, error) {
	var v ResultNRComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERSRSConfigurationForAllCells decodes a complete named list.
func UnmarshalAPERSRSConfigurationForAllCells(data []byte, options ...q5.DecodeOption) (SRSConfigurationForAllCellsComplete, q5.DecodeReport, error) {
	var v SRSConfigurationForAllCellsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERSystemInformation decodes a complete named list.
func UnmarshalAPERSystemInformation(data []byte, options ...q5.DecodeOption) (SystemInformationComplete, q5.DecodeReport, error) {
	var v SystemInformationComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERWLANChannelList decodes a complete named list.
func UnmarshalAPERWLANChannelList(data []byte, options ...q5.DecodeOption) (WLANChannelListComplete, q5.DecodeReport, error) {
	var v WLANChannelListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}
func BridgeCaptureLPPaECIDMeasurementInitiationRequestIEValue(v *ECIDMeasurementInitiationRequestIEValue, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q10.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
		case q10.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowESMLCUEMeasurementID == nil)
				if v.rowESMLCUEMeasurementID != nil {
					q10.BridgeCaptureLPPaMeasurementID(v.rowESMLCUEMeasurementID, s)
				}
				s.End(f, nil, false)
			}
		case q10.ProtocolIEID(3):
			{
				f := s.Begin()
				s.Bool(v.rowReportCharacteristics == nil)
				if v.rowReportCharacteristics != nil {
					q10.BridgeCaptureLPPaReportCharacteristics(v.rowReportCharacteristics, s)
				}
				s.End(f, nil, false)
			}
		case q10.ProtocolIEID(4):
			{
				f := s.Begin()
				s.Bool(v.rowMeasurementPeriodicity == nil)
				if v.rowMeasurementPeriodicity != nil {
					q10.BridgeCaptureLPPaMeasurementPeriodicity(v.rowMeasurementPeriodicity, s)
				}
				s.End(f, nil, false)
			}
		case q10.ProtocolIEID(5):
			{
				f := s.Begin()
				s.Bool(v.rowMeasurementQuantities == nil)
				if v.rowMeasurementQuantities != nil {
					q16.BridgeCaptureLPPaMeasurementQuantities(v.rowMeasurementQuantities, s)
				}
				s.End(f, nil, false)
			}
		case q10.ProtocolIEID(15):
			{
				f := s.Begin()
				s.Bool(v.rowInterRATMeasurementQuantities == nil)
				if v.rowInterRATMeasurementQuantities != nil {
					q16.BridgeCaptureLPPaInterRATMeasurementQuantities(v.rowInterRATMeasurementQuantities, s)
				}
				s.End(f, nil, false)
			}
		case q10.ProtocolIEID(19):
			{
				f := s.Begin()
				s.Bool(v.rowWLANMeasurementQuantities == nil)
				if v.rowWLANMeasurementQuantities != nil {
					BridgeCaptureLPPaWLANMeasurementQuantities(v.rowWLANMeasurementQuantities, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ECIDMeasurementInitiationRequestIEValue) captureSnapshot() q5.Snapshot { return v.replay }
func (v ECIDMeasurementInitiationRequestIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ECIDMeasurementInitiationRequestIEValue) captureSemantics(s q5.SemanticCapture) ECIDMeasurementInitiationRequestIEValue {
	BridgeCaptureLPPaECIDMeasurementInitiationRequestIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaECIDMeasurementInitiationRequestIEValue(v *ECIDMeasurementInitiationRequestIEValue, s *q5.SemanticComparison) {
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
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case q10.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowESMLCUEMeasurementID == nil)
				if v.rowESMLCUEMeasurementID != nil {
					q14.BridgeCompareLPPaMeasurementID(v.rowESMLCUEMeasurementID, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		case q10.ProtocolIEID(3):
			{
				f := s.Begin()
				s.Bool(v.rowReportCharacteristics == nil)
				if v.rowReportCharacteristics != nil {
					q12.BridgeCompareLPPaReportCharacteristics(v.rowReportCharacteristics, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		case q10.ProtocolIEID(4):
			{
				f := s.Begin()
				s.Bool(v.rowMeasurementPeriodicity == nil)
				if v.rowMeasurementPeriodicity != nil {
					q14.BridgeCompareLPPaMeasurementPeriodicity(v.rowMeasurementPeriodicity, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		case q10.ProtocolIEID(5):
			{
				f := s.Begin()
				s.Bool(v.rowMeasurementQuantities == nil)
				if v.rowMeasurementQuantities != nil {
					q16.BridgeCompareLPPaMeasurementQuantities(v.rowMeasurementQuantities, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		case q10.ProtocolIEID(15):
			{
				f := s.Begin()
				s.Bool(v.rowInterRATMeasurementQuantities == nil)
				if v.rowInterRATMeasurementQuantities != nil {
					q16.BridgeCompareLPPaInterRATMeasurementQuantities(v.rowInterRATMeasurementQuantities, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		case q10.ProtocolIEID(19):
			{
				f := s.Begin()
				s.Bool(v.rowWLANMeasurementQuantities == nil)
				if v.rowWLANMeasurementQuantities != nil {
					BridgeCompareLPPaWLANMeasurementQuantities(v.rowWLANMeasurementQuantities, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v ECIDMeasurementInitiationRequestIEValue) compareSemantics(s q5.SemanticComparison) q5.SemanticComparison {
	BridgeCompareLPPaECIDMeasurementInitiationRequestIEValue(&v, &s)
	return s
}
func (v ECIDMeasurementInitiationRequestIEValue) WithoutReplay() ECIDMeasurementInitiationRequestIEValue {
	v.withoutReplay = true
	v.replay = q5.Snapshot{}
	return v
}
func BridgeCaptureLPPaInterRATMeasurementResult(v *InterRATMeasurementResult, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			q13.BridgeCaptureLPPaInterRATMeasuredResultsValue(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaInterRATMeasurementResult(v *InterRATMeasurementResult, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			q13.BridgeCompareLPPaInterRATMeasuredResultsValue(&(*v)[i], s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
	s.End(f, q5.Snapshot{}, false)
}
func BridgeCaptureLPPaInterRATMeasurementResultComplete(v *InterRATMeasurementResultComplete, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	BridgeCaptureLPPaInterRATMeasurementResult(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaInterRATMeasurementResultComplete(v *InterRATMeasurementResultComplete, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaInterRATMeasurementResult(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultNRComplete(v *ResultNRComplete, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q13.BridgeCaptureLPPaResultNR(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultNRComplete(v *ResultNRComplete, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q13.BridgeCompareLPPaResultNR(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaSRSConfigurationForAllCellsComplete(v *SRSConfigurationForAllCellsComplete, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q7.BridgeCaptureLPPaSRSConfigurationForAllCells(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaSRSConfigurationForAllCellsComplete(v *SRSConfigurationForAllCellsComplete, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q19.BridgeCompareLPPaSRSConfigurationForAllCells(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaSystemInformationComplete(v *SystemInformationComplete, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q15.BridgeCaptureLPPaSystemInformation(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaSystemInformationComplete(v *SystemInformationComplete, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q15.BridgeCompareLPPaSystemInformation(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaWLANChannelListComplete(v *WLANChannelListComplete, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q10.BridgeCaptureLPPaWLANChannelList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaWLANChannelListComplete(v *WLANChannelListComplete, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q12.BridgeCompareLPPaWLANChannelList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaWLANMeasurementQuantities(v *WLANMeasurementQuantities, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeWLANMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaWLANMeasurementQuantities(v *WLANMeasurementQuantities, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeWLANMeasurementQuantitiesItemIEValueCompareLPPaProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
	s.End(f, q5.Snapshot{}, false)
}
func BridgeCaptureLPPaWLANMeasurementQuantitiesComplete(v *WLANMeasurementQuantitiesComplete, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	BridgeCaptureLPPaWLANMeasurementQuantities(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaWLANMeasurementQuantitiesComplete(v *WLANMeasurementQuantitiesComplete, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaWLANMeasurementQuantities(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaWLANMeasurementQuantitiesItem(v *WLANMeasurementQuantitiesItem, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q10.BridgeCaptureLPPaWLANMeasurementQuantitiesValue(&v.WLANMeasurementQuantitiesValue, s)
	s.Bool(v.IEExtensions == nil)
	BridgeWLANMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaWLANMeasurementQuantitiesItem(v *WLANMeasurementQuantitiesItem, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q12.BridgeCompareLPPaWLANMeasurementQuantitiesValue(&v.WLANMeasurementQuantitiesValue, s)
	s.Bool(v.IEExtensions == nil)
	BridgeWLANMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaWLANMeasurementQuantitiesItemIEValue(v *WLANMeasurementQuantitiesItemIEValue, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q10.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
		case q10.ProtocolIEID(20):
			{
				f := s.Begin()
				s.Bool(v.rowWLANMeasurementQuantitiesItem == nil)
				if v.rowWLANMeasurementQuantitiesItem != nil {
					BridgeCaptureLPPaWLANMeasurementQuantitiesItem(v.rowWLANMeasurementQuantitiesItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v WLANMeasurementQuantitiesItemIEValue) captureSnapshot() q5.Snapshot { return v.replay }
func (v WLANMeasurementQuantitiesItemIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v WLANMeasurementQuantitiesItemIEValue) captureSemantics(s q5.SemanticCapture) WLANMeasurementQuantitiesItemIEValue {
	BridgeCaptureLPPaWLANMeasurementQuantitiesItemIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaWLANMeasurementQuantitiesItemIEValue(v *WLANMeasurementQuantitiesItemIEValue, s *q5.SemanticComparison) {
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
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case q10.ProtocolIEID(20):
			{
				f := s.Begin()
				s.Bool(v.rowWLANMeasurementQuantitiesItem == nil)
				if v.rowWLANMeasurementQuantitiesItem != nil {
					BridgeCompareLPPaWLANMeasurementQuantitiesItem(v.rowWLANMeasurementQuantitiesItem, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v WLANMeasurementQuantitiesItemIEValue) compareSemantics(s q5.SemanticComparison) q5.SemanticComparison {
	BridgeCompareLPPaWLANMeasurementQuantitiesItemIEValue(&v, &s)
	return s
}
func (v WLANMeasurementQuantitiesItemIEValue) WithoutReplay() WLANMeasurementQuantitiesItemIEValue {
	v.withoutReplay = true
	v.replay = q5.Snapshot{}
	return v
}

type WLANMeasurementQuantitiesItemIEValue struct {
	id                               q10.ProtocolIEID
	withoutReplay                    bool
	received                         q5.WireSpan
	replay                           q5.Snapshot
	opaque                           *q5.OpaqueOpenType
	isOpaque                         bool
	rowWLANMeasurementQuantitiesItem *WLANMeasurementQuantitiesItem
}

func (v WLANMeasurementQuantitiesItemIEValue) matchesID(id q10.ProtocolIEID, _ *q5.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q10.ProtocolIEID(20):
		return v.rowWLANMeasurementQuantitiesItem != nil
	default:
		return false
	}
}
func (v *WLANMeasurementQuantitiesItemIEValue) Opaque() (q5.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q5.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (WLANMeasurementQuantitiesItemIEValue) rule() q5.SourceRule {
	return q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementQuantities-ItemIEs"}}
}
func (WLANMeasurementQuantitiesItemIEValue) reason(id q10.ProtocolIEID) q5.OpaqueReason {
	switch id {
	case q10.ProtocolIEID(20):
		return q5.UnknownSelector
	case q10.ProtocolIEID(0):
		return q5.NotInTable
	case q10.ProtocolIEID(1):
		return q5.NotInTable
	case q10.ProtocolIEID(2):
		return q5.NotInTable
	case q10.ProtocolIEID(3):
		return q5.NotInTable
	case q10.ProtocolIEID(4):
		return q5.NotInTable
	case q10.ProtocolIEID(5):
		return q5.NotInTable
	case q10.ProtocolIEID(6):
		return q5.NotInTable
	case q10.ProtocolIEID(7):
		return q5.NotInTable
	case q10.ProtocolIEID(8):
		return q5.NotInTable
	case q10.ProtocolIEID(9):
		return q5.NotInTable
	case q10.ProtocolIEID(10):
		return q5.NotInTable
	case q10.ProtocolIEID(11):
		return q5.NotInTable
	case q10.ProtocolIEID(12):
		return q5.NotInTable
	case q10.ProtocolIEID(13):
		return q5.NotInTable
	case q10.ProtocolIEID(14):
		return q5.NotInTable
	case q10.ProtocolIEID(15):
		return q5.NotInTable
	case q10.ProtocolIEID(16):
		return q5.NotInTable
	case q10.ProtocolIEID(17):
		return q5.NotInTable
	case q10.ProtocolIEID(18):
		return q5.NotInTable
	case q10.ProtocolIEID(19):
		return q5.NotInTable
	case q10.ProtocolIEID(21):
		return q5.NotInTable
	case q10.ProtocolIEID(22):
		return q5.NotInTable
	case q10.ProtocolIEID(23):
		return q5.NotInTable
	case q10.ProtocolIEID(24):
		return q5.NotInTable
	case q10.ProtocolIEID(25):
		return q5.NotInTable
	case q10.ProtocolIEID(27):
		return q5.NotInTable
	default:
		return q5.UnknownSelector
	}
}
func (v *WLANMeasurementQuantitiesItemIEValue) AsWLANMeasurementQuantitiesItem() (*WLANMeasurementQuantitiesItem, bool) {
	if v == nil || v.id != q10.ProtocolIEID(20) || v.rowWLANMeasurementQuantitiesItem == nil {
		return nil, false
	}
	return v.rowWLANMeasurementQuantitiesItem, true
}
func (v WLANMeasurementQuantitiesItemIEValue) decode(id q10.ProtocolIEID, raw q5.OpaqueOpenType) (WLANMeasurementQuantitiesItemIEValue, error) {
	out := WLANMeasurementQuantitiesItemIEValue{id: id}
	var scope *q5.BitBuffer
	switch id {
	case 20:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q10.ProtocolIEID(20):
		replayUsage := scope.Usage()
		var value WLANMeasurementQuantitiesItem
		child := raw.ChildDecodeBuffer()
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, q8.Errorf("%s %w", "WLANMeasurementQuantitiesItem:", err)
		}
		padding, err := q5.CaptureFinalBits(child, "WLANMeasurementQuantitiesItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		if err := q5.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowWLANMeasurementQuantitiesItem = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	default:
		if err := raw.Observe(q5.UnknownIE); err != nil {
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
func (v WLANMeasurementQuantitiesItemIEValue) encode() ([]byte, error) {
	budget, err := q5.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v WLANMeasurementQuantitiesItemIEValue) encodeFresh(fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
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
	switch v.id {
	case q10.ProtocolIEID(20):
		if v.rowWLANMeasurementQuantitiesItem == nil {
			return nil, q8.Errorf("%s missing value", "WLANMeasurementQuantities-ItemIEs.id-WLANMeasurementQuantities-Item:")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := v.rowWLANMeasurementQuantitiesItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, q8.Errorf("%s id %d has no value", "WLANMeasurementQuantitiesItemIEValue:", v.id)
	}
}

type ECIDMeasurementInitiationRequestIEValue struct {
	id                               q10.ProtocolIEID
	withoutReplay                    bool
	received                         q5.WireSpan
	replay                           q5.Snapshot
	opaque                           *q5.OpaqueOpenType
	isOpaque                         bool
	rowESMLCUEMeasurementID          *q10.MeasurementID
	rowReportCharacteristics         *q10.ReportCharacteristics
	rowMeasurementPeriodicity        *q10.MeasurementPeriodicity
	rowMeasurementQuantities         *q20.MeasurementQuantities
	rowInterRATMeasurementQuantities *q20.InterRATMeasurementQuantities
	rowWLANMeasurementQuantities     *WLANMeasurementQuantities
}

func (v ECIDMeasurementInitiationRequestIEValue) matchesID(id q10.ProtocolIEID, _ *q5.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q10.ProtocolIEID(2):
		return v.rowESMLCUEMeasurementID != nil
	case q10.ProtocolIEID(3):
		return v.rowReportCharacteristics != nil
	case q10.ProtocolIEID(4):
		return v.rowMeasurementPeriodicity != nil
	case q10.ProtocolIEID(5):
		return v.rowMeasurementQuantities != nil
	case q10.ProtocolIEID(15):
		return v.rowInterRATMeasurementQuantities != nil
	case q10.ProtocolIEID(19):
		return v.rowWLANMeasurementQuantities != nil
	default:
		return false
	}
}
func (v *ECIDMeasurementInitiationRequestIEValue) Opaque() (q5.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q5.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ECIDMeasurementInitiationRequestIEValue) rule() q5.SourceRule {
	return q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationRequest-IEs"}}
}
func (ECIDMeasurementInitiationRequestIEValue) reason(id q10.ProtocolIEID) q5.OpaqueReason {
	switch id {
	case q10.ProtocolIEID(2):
		return q5.UnknownSelector
	case q10.ProtocolIEID(3):
		return q5.UnknownSelector
	case q10.ProtocolIEID(4):
		return q5.UnknownSelector
	case q10.ProtocolIEID(5):
		return q5.UnknownSelector
	case q10.ProtocolIEID(15):
		return q5.UnknownSelector
	case q10.ProtocolIEID(19):
		return q5.UnknownSelector
	case q10.ProtocolIEID(0):
		return q5.NotInTable
	case q10.ProtocolIEID(1):
		return q5.NotInTable
	case q10.ProtocolIEID(6):
		return q5.NotInTable
	case q10.ProtocolIEID(7):
		return q5.NotInTable
	case q10.ProtocolIEID(8):
		return q5.NotInTable
	case q10.ProtocolIEID(9):
		return q5.NotInTable
	case q10.ProtocolIEID(10):
		return q5.NotInTable
	case q10.ProtocolIEID(11):
		return q5.NotInTable
	case q10.ProtocolIEID(12):
		return q5.NotInTable
	case q10.ProtocolIEID(13):
		return q5.NotInTable
	case q10.ProtocolIEID(14):
		return q5.NotInTable
	case q10.ProtocolIEID(16):
		return q5.NotInTable
	case q10.ProtocolIEID(17):
		return q5.NotInTable
	case q10.ProtocolIEID(18):
		return q5.NotInTable
	case q10.ProtocolIEID(20):
		return q5.NotInTable
	case q10.ProtocolIEID(21):
		return q5.NotInTable
	case q10.ProtocolIEID(22):
		return q5.NotInTable
	case q10.ProtocolIEID(23):
		return q5.NotInTable
	case q10.ProtocolIEID(24):
		return q5.NotInTable
	case q10.ProtocolIEID(25):
		return q5.NotInTable
	case q10.ProtocolIEID(27):
		return q5.NotInTable
	default:
		return q5.UnknownSelector
	}
}
func (v *ECIDMeasurementInitiationRequestIEValue) AsESMLCUEMeasurementID() (*q10.MeasurementID, bool) {
	if v == nil || v.id != q10.ProtocolIEID(2) || v.rowESMLCUEMeasurementID == nil {
		return nil, false
	}
	return v.rowESMLCUEMeasurementID, true
}
func (v *ECIDMeasurementInitiationRequestIEValue) AsReportCharacteristics() (*q10.ReportCharacteristics, bool) {
	if v == nil || v.id != q10.ProtocolIEID(3) || v.rowReportCharacteristics == nil {
		return nil, false
	}
	return v.rowReportCharacteristics, true
}
func (v *ECIDMeasurementInitiationRequestIEValue) AsMeasurementPeriodicity() (*q10.MeasurementPeriodicity, bool) {
	if v == nil || v.id != q10.ProtocolIEID(4) || v.rowMeasurementPeriodicity == nil {
		return nil, false
	}
	return v.rowMeasurementPeriodicity, true
}
func (v *ECIDMeasurementInitiationRequestIEValue) AsMeasurementQuantities() (*q20.MeasurementQuantities, bool) {
	if v == nil || v.id != q10.ProtocolIEID(5) || v.rowMeasurementQuantities == nil {
		return nil, false
	}
	return v.rowMeasurementQuantities, true
}
func (v *ECIDMeasurementInitiationRequestIEValue) AsInterRATMeasurementQuantities() (*q20.InterRATMeasurementQuantities, bool) {
	if v == nil || v.id != q10.ProtocolIEID(15) || v.rowInterRATMeasurementQuantities == nil {
		return nil, false
	}
	return v.rowInterRATMeasurementQuantities, true
}
func (v *ECIDMeasurementInitiationRequestIEValue) AsWLANMeasurementQuantities() (*WLANMeasurementQuantities, bool) {
	if v == nil || v.id != q10.ProtocolIEID(19) || v.rowWLANMeasurementQuantities == nil {
		return nil, false
	}
	return v.rowWLANMeasurementQuantities, true
}
func (v ECIDMeasurementInitiationRequestIEValue) decode(id q10.ProtocolIEID, raw q5.OpaqueOpenType) (ECIDMeasurementInitiationRequestIEValue, error) {
	out := ECIDMeasurementInitiationRequestIEValue{id: id}
	var scope *q5.BitBuffer
	switch id {
	case 2, 3, 4, 5, 15, 19:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q10.ProtocolIEID(2):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := q5.DecodeIntegerBigBoundsAligned(bb, q10.BridgeAsn1IntegerBound2, q10.BridgeAsn1IntegerBound7, true)
		value := q10.MeasurementID(decoded)
		if err != nil {
			return out, q8.Errorf("%s %w", "ESMLCUEMeasurementID:", err)
		}
		if _, err := q5.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		if err := q5.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowESMLCUEMeasurementID = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q10.ProtocolIEID(3):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := q5.DecodeEnumeratedAligned(bb, 2, true, q5.EnumerationSource{KnownExtensions: 0, Path: "ReportCharacteristics"})
		value := q10.ReportCharacteristics(decoded)
		if err != nil {
			return out, q8.Errorf("%s %w", "ReportCharacteristics:", err)
		}
		if _, err := q5.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		out.rowReportCharacteristics = (*q10.ReportCharacteristics)(scope.OwnInt64(int64(value)))
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q10.ProtocolIEID(4):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := q5.DecodeEnumeratedAligned(bb, 13, true, q5.EnumerationSource{KnownExtensions: 0, Path: "MeasurementPeriodicity"})
		value := q10.MeasurementPeriodicity(decoded)
		if err != nil {
			return out, q8.Errorf("%s %w", "MeasurementPeriodicity:", err)
		}
		if _, err := q5.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		out.rowMeasurementPeriodicity = (*q10.MeasurementPeriodicity)(scope.OwnInt64(int64(value)))
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q10.ProtocolIEID(5):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := q21.BridgeUnmarshalAPERMeasurementQuantitiesFrom(child)
		if err != nil {
			return out, q8.Errorf("%s %w", "MeasurementQuantities:", err)
		}
		padding, err := q5.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := func() q21.MeasurementQuantitiesComplete {
			sealed := q21.MeasurementQuantitiesComplete{Value: list}
			*q21.BridgeMeasurementQuantitiesCompleteFieldPerPadding(&sealed) = padding
			return sealed
		}()
		value := complete.Value
		if err := q5.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowMeasurementQuantities = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q10.ProtocolIEID(15):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := q22.BridgeUnmarshalAPERInterRATMeasurementQuantitiesFrom(child)
		if err != nil {
			return out, q8.Errorf("%s %w", "InterRATMeasurementQuantities:", err)
		}
		padding, err := q5.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := func() q22.InterRATMeasurementQuantitiesComplete {
			sealed := q22.InterRATMeasurementQuantitiesComplete{Value: list}
			*q22.BridgeInterRATMeasurementQuantitiesCompleteFieldPerPadding(&sealed) = padding
			return sealed
		}()
		value := complete.Value
		if err := q5.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowInterRATMeasurementQuantities = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q10.ProtocolIEID(19):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := BridgeUnmarshalAPERWLANMeasurementQuantitiesFrom(child)
		if err != nil {
			return out, q8.Errorf("%s %w", "WLANMeasurementQuantities:", err)
		}
		padding, err := q5.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := WLANMeasurementQuantitiesComplete{Value: list, perPadding: padding}
		value := complete.Value
		if err := q5.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowWLANMeasurementQuantities = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	default:
		if err := raw.Observe(q5.UnknownIE); err != nil {
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
	budget, err := q5.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ECIDMeasurementInitiationRequestIEValue) encodeFresh(fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
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
	switch v.id {
	case q10.ProtocolIEID(2):
		if v.rowESMLCUEMeasurementID == nil {
			return nil, q8.Errorf("%s missing value", "E-CIDMeasurementInitiationRequest-IEs.id-E-SMLC-UE-Measurement-ID:")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := q5.NewBudgetBuffer(budget)
		if err := q5.EncodeIntegerBigBoundsAligned(encodeBB, *v.rowESMLCUEMeasurementID, q10.BridgeAsn1IntegerBound2, q10.BridgeAsn1IntegerBound7, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case q10.ProtocolIEID(3):
		if v.rowReportCharacteristics == nil {
			return nil, q8.Errorf("%s missing value", "E-CIDMeasurementInitiationRequest-IEs.id-ReportCharacteristics:")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := q5.NewBudgetBuffer(budget)
		if err := q5.EncodeEnumeratedAligned(encodeBB, int64(*v.rowReportCharacteristics), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case q10.ProtocolIEID(4):
		if v.rowMeasurementPeriodicity == nil {
			return nil, q8.Errorf("%s missing value", "E-CIDMeasurementInitiationRequest-IEs.id-MeasurementPeriodicity:")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := q5.NewBudgetBuffer(budget)
		if err := q5.EncodeEnumeratedAligned(encodeBB, int64(*v.rowMeasurementPeriodicity), 13, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case q10.ProtocolIEID(5):
		if v.rowMeasurementQuantities == nil {
			return nil, q8.Errorf("%s missing value", "E-CIDMeasurementInitiationRequest-IEs.id-MeasurementQuantities:")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		complete := q21.MeasurementQuantitiesComplete{Value: *v.rowMeasurementQuantities}
		candidate, err := q21.BridgeMeasurementQuantitiesCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case q10.ProtocolIEID(15):
		if v.rowInterRATMeasurementQuantities == nil {
			return nil, q8.Errorf("%s missing value", "E-CIDMeasurementInitiationRequest-IEs.id-InterRATMeasurementQuantities:")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		complete := q22.InterRATMeasurementQuantitiesComplete{Value: *v.rowInterRATMeasurementQuantities}
		candidate, err := q22.BridgeInterRATMeasurementQuantitiesCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case q10.ProtocolIEID(19):
		if v.rowWLANMeasurementQuantities == nil {
			return nil, q8.Errorf("%s missing value", "E-CIDMeasurementInitiationRequest-IEs.id-WLANMeasurementQuantities:")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		complete := WLANMeasurementQuantitiesComplete{Value: *v.rowWLANMeasurementQuantities}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, q8.Errorf("%s id %d has no value", "ECIDMeasurementInitiationRequestIEValue:", v.id)
	}
}

type WLANMeasurementQuantitiesItemIETable struct{}

func WLANMeasurementQuantitiesItemIEs() WLANMeasurementQuantitiesItemIETable {
	return WLANMeasurementQuantitiesItemIETable{}
}
func (WLANMeasurementQuantitiesItemIETable) ID() q10.TableID {
	return func() q10.TableID {
		sealed := q10.TableID{}
		*q10.BridgeTableIDFieldSource(&sealed) = q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementQuantities-ItemIEs"}
		return sealed
	}()
}
func (WLANMeasurementQuantitiesItemIETable) infoWLANMeasurementQuantitiesItem() q10.FieldInfo {
	return q10.FieldInfo{Table: WLANMeasurementQuantitiesItemIEs().ID(), ID: q10.ProtocolIEID(20), Criticality: q10.CriticalityReject, Presence: q10.PresenceMandatory, ValueType: func() q10.TypeID {
		sealed := q10.TypeID{}
		*q10.BridgeTypeIDFieldSource(&sealed) = q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementQuantitiesItem"}
		return sealed
	}(), Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementQuantities-ItemIEs", Row: "id-WLANMeasurementQuantities-Item"}}}
}
func (t WLANMeasurementQuantitiesItemIETable) WLANMeasurementQuantitiesItem() WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding {
	return WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding{info: t.infoWLANMeasurementQuantitiesItem(), codec: WLANMeasurementQuantitiesItemValueCodec{path: "WLANMeasurementQuantitiesItem",
		decode: func(data []byte, options q5.DecodeState) (WLANMeasurementQuantitiesItem, error) {
			raw, err := q5.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty WLANMeasurementQuantitiesItem
				return empty, err
			}
			var zero WLANMeasurementQuantitiesItemIEValue
			decoded, err := zero.decode(q10.ProtocolIEID(20), raw)
			if err != nil {
				var empty WLANMeasurementQuantitiesItem
				return empty, err
			}
			value, ok := decoded.AsWLANMeasurementQuantitiesItem()
			if !ok {
				var empty WLANMeasurementQuantitiesItem
				return empty, q8.Errorf("binding WLANMeasurementQuantities-ItemIEs.id-WLANMeasurementQuantities-Item: no selected value")
			}
			return *value, nil
		},
		encode: func(value WLANMeasurementQuantitiesItem, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return (WLANMeasurementQuantitiesItemIEValue{id: q10.ProtocolIEID(20), rowWLANMeasurementQuantitiesItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v WLANMeasurementQuantitiesItem, options q5.DecodeState) (WLANMeasurementQuantitiesItem, q5.Snapshot,

		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureLPPaWLANMeasurementQuantitiesItem(&v, &s)
			var root q5.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v,

				root
		}, compare: func(v WLANMeasurementQuantitiesItem, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaWLANMeasurementQuantitiesItem(&v, &s)
			s.End(f, root, false)

			return s.Plan()
		}, context: func() q10.BridgeCodecContext {
			sealed := q10.BridgeCodecContext{}
			*q10.BridgecodecContextFieldSource(&sealed) = "source-value:WLANMeasurementQuantitiesItem"
			return sealed
		}(),
	}, inject: func(value WLANMeasurementQuantitiesItem) WLANMeasurementQuantitiesItemIEValue {
		return WLANMeasurementQuantitiesItemIEValue{id: q10.ProtocolIEID(20), rowWLANMeasurementQuantitiesItem: &value}
	}, get: func(value *WLANMeasurementQuantitiesItemIEValue) (*WLANMeasurementQuantitiesItem, bool) {
		return value.AsWLANMeasurementQuantitiesItem()
	}}
}
func (t WLANMeasurementQuantitiesItemIETable) NewOpaque(id q10.ProtocolIEID, criticality q10.Criticality, data []byte) (WLANMeasurementQuantitiesItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return WLANMeasurementQuantitiesItemIEField{}, q5.OperationError(q8.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q10.ProtocolIEID(20):
		return WLANMeasurementQuantitiesItemIEField{}, q5.OperationError(q8.Errorf("known IE id-WLANMeasurementQuantities-Item requires its typed binding"), "Opaque")
	default:
		budget, err := q5.BuildBudget()
		if err != nil {
			return WLANMeasurementQuantitiesItemIEField{}, q5.OperationError(err, "Opaque")
		}
		opaque, err := q5.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return WLANMeasurementQuantitiesItemIEField{}, q5.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return WLANMeasurementQuantitiesItemIEField{}, q5.OperationError(err, "Opaque")
		}
		return WLANMeasurementQuantitiesItemIEField{Id: id, Criticality: criticality, Value: WLANMeasurementQuantitiesItemIEValue{id: id, opaque: retained, isOpaque: true}}, q5.OperationError(nil, "Opaque")
	}
}

// InterRATMeasuredResultsValueCodec binds the complete source value type.
func InterRATMeasuredResultsValueCodec() InterRATMeasuredResultsValueValueCodec {
	return InterRATMeasuredResultsValueValueCodec{path: "InterRATMeasuredResultsValue", decode: func(data []byte, options q5.DecodeState) (q13.InterRATMeasuredResultsValue, error) {
		var value q13.InterRATMeasuredResultsValue
		if err := q13.BridgeInterRATMeasuredResultsValueMethodUnmarshalAPERWithOptions(&value, data, options); err != nil {
			return q13.InterRATMeasuredResultsValue{}, err
		}
		*q13.BridgeInterRATMeasuredResultsValueFieldReceived(&value) = true
		*q13.BridgeInterRATMeasuredResultsValueFieldReceivedBytes(&value) = q5.OriginalWire(data)
		return value, nil
	}, encode: func(value q13.InterRATMeasuredResultsValue, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return q13.BridgeInterRATMeasuredResultsValueMethodMarshalAPERBudget((&value), budget, fresh)
	}, capture: func(v q13.InterRATMeasuredResultsValue, options q5.DecodeState) (q13.InterRATMeasuredResultsValue, q5.Snapshot,
	) {
		s := q5.SemanticCaptureFor(options)
		f := s.Begin()
		q13.BridgeCaptureLPPaInterRATMeasuredResultsValue(&v, &s)
		var root q5.Snapshot

		s.OperationCounts()
		s.End(f, &root, false)
		return v, root

	}, compare: func(v q13.InterRATMeasuredResultsValue, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
		s := q5.NewSemanticComparison(root, limits)
		f := s.Begin()
		q13.BridgeCompareLPPaInterRATMeasuredResultsValue(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q10.BridgeCodecContext {
		sealed := q10.BridgeCodecContext{}
		*q10.BridgecodecContextFieldSource(&sealed) = "source-value:InterRATMeasuredResultsValue"
		return sealed
	}(),
	}
}

// ResultNRCodec binds the complete source value type.
func ResultNRCodec() q13.ResultNRValueCodec {
	return func() q13.ResultNRValueCodec {
		sealed := q13.ResultNRValueCodec{}
		*q13.BridgeResultNRValueCodecFieldPath(&sealed) = "ResultNR"
		*q13.BridgeResultNRValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q13.ResultNR, error) {
			var complete ResultNRComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero q13.ResultNR
				return zero, err
			}
			return complete.Value, nil
		}
		*q13.BridgeResultNRValueCodecFieldEncode(&sealed) = func(value q13.ResultNR, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			complete := ResultNRComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*q13.BridgeResultNRValueCodecFieldCapture(&sealed) = func(v q13.ResultNR, options q5.DecodeState) (q13.ResultNR, q5.Snapshot) {
			s := q5.SemanticCaptureFor(
				options)
			f := s.Begin()
			q13.BridgeCaptureLPPaResultNR(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q13.BridgeResultNRValueCodecFieldCompare(&sealed) = func(v q13.ResultNR, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q13.BridgeCompareLPPaResultNR(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q13.BridgeResultNRValueCodecFieldContext(&sealed) = func() q10.BridgeCodecContext {
			sealed := q10.BridgeCodecContext{}
			*q10.BridgecodecContextFieldSource(&sealed) = "source-value:ResultNR"
			return sealed
		}()
		return sealed
	}()

}

// SRSConfigurationForAllCellsCodec binds the complete source value type.
func SRSConfigurationForAllCellsCodec() q7.SRSConfigurationForAllCellsValueCodec {
	return func() q7.SRSConfigurationForAllCellsValueCodec {
		sealed := q7.SRSConfigurationForAllCellsValueCodec{}
		*q7.BridgeSRSConfigurationForAllCellsValueCodecFieldPath(&sealed) = "SRSConfigurationForAllCells"
		*q7.BridgeSRSConfigurationForAllCellsValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q7.SRSConfigurationForAllCells, error) {
			var complete SRSConfigurationForAllCellsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero q7.SRSConfigurationForAllCells
				return zero, err
			}
			return complete.Value, nil
		}
		*q7.BridgeSRSConfigurationForAllCellsValueCodecFieldEncode(&sealed) = func(value q7.SRSConfigurationForAllCells, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			complete := SRSConfigurationForAllCellsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*q7.BridgeSRSConfigurationForAllCellsValueCodecFieldCapture(&sealed) = func(v q7.SRSConfigurationForAllCells, options q5.DecodeState) (q7.SRSConfigurationForAllCells, q5.Snapshot,
		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q7.BridgeCaptureLPPaSRSConfigurationForAllCells(&v, &s)
			var root q5.Snapshot
			s.
				OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q7.BridgeSRSConfigurationForAllCellsValueCodecFieldCompare(&sealed) = func(v q7.SRSConfigurationForAllCells, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q19.BridgeCompareLPPaSRSConfigurationForAllCells(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q7.BridgeSRSConfigurationForAllCellsValueCodecFieldContext(&sealed) = func() q10.BridgeCodecContext {
			sealed := q10.BridgeCodecContext{}
			*q10.BridgecodecContextFieldSource(&sealed) = "source-value:SRSConfigurationForAllCells"
			return sealed
		}()
		return sealed
	}()

}

// SystemInformationCodec binds the complete source value type.
func SystemInformationCodec() q15.SystemInformationValueCodec {
	return func() q15.SystemInformationValueCodec {
		sealed := q15.SystemInformationValueCodec{}
		*q15.BridgeSystemInformationValueCodecFieldPath(&sealed) = "SystemInformation"
		*q15.BridgeSystemInformationValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q15.SystemInformation, error) {
			var complete SystemInformationComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero q15.SystemInformation
				return zero, err
			}
			return complete.Value, nil
		}
		*q15.BridgeSystemInformationValueCodecFieldEncode(&sealed) = func(value q15.SystemInformation, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			complete := SystemInformationComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*q15.BridgeSystemInformationValueCodecFieldCapture(&sealed) = func(v q15.SystemInformation, options q5.DecodeState) (q15.SystemInformation, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q15.BridgeCaptureLPPaSystemInformation(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root,

				false)
			return v, root
		}
		*q15.BridgeSystemInformationValueCodecFieldCompare(&sealed) = func(v q15.SystemInformation, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q15.BridgeCompareLPPaSystemInformation(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q15.BridgeSystemInformationValueCodecFieldContext(&sealed) = func() q10.BridgeCodecContext {
			sealed := q10.BridgeCodecContext{}
			*q10.BridgecodecContextFieldSource(&sealed) = "source-value:SystemInformation"
			return sealed
		}()
		return sealed
	}()

}

// WLANChannelListCodec binds the complete source value type.
func WLANChannelListCodec() q23.WLANChannelListValueCodec {
	return func() q23.WLANChannelListValueCodec {
		sealed := q23.WLANChannelListValueCodec{}
		*q23.BridgeWLANChannelListValueCodecFieldPath(&sealed) = "WLANChannelList"
		*q23.BridgeWLANChannelListValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q10.WLANChannelList, error) {
			var complete WLANChannelListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero q10.WLANChannelList
				return zero, err
			}
			return complete.Value, nil
		}
		*q23.BridgeWLANChannelListValueCodecFieldEncode(&sealed) = func(value q10.WLANChannelList, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			complete := WLANChannelListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*q23.BridgeWLANChannelListValueCodecFieldCapture(&sealed) = func(v q10.WLANChannelList, options q5.DecodeState) (q10.WLANChannelList, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q10.BridgeCaptureLPPaWLANChannelList(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q23.BridgeWLANChannelListValueCodecFieldCompare(&sealed) = func(v q10.WLANChannelList, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			q12.BridgeCompareLPPaWLANChannelList(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q23.BridgeWLANChannelListValueCodecFieldContext(&sealed) = func() q10.BridgeCodecContext {
			sealed := q10.BridgeCodecContext{}
			*q10.BridgecodecContextFieldSource(&sealed) = "source-value:WLANChannelList"
			return sealed
		}()
		return sealed
	}()

}

// WLANMeasurementQuantitiesItemCodec binds the complete APER value type.
func WLANMeasurementQuantitiesItemCodec() WLANMeasurementQuantitiesItemValueCodec {
	return WLANMeasurementQuantitiesItemIEs().WLANMeasurementQuantitiesItem().Codec()
}
func BridgeValidationHasValueMismatch(report q7.ValidationReport) bool {
	for _, issue := range report.Issues {
		if issue.Code == q10.ValueIDMismatch {
			return true
		}
	}
	return false
}
func BridgeValidatePrivateMessageBudget(v *q6.PrivateMessage, budget *q5.DecodeBudget,

) (q7.ValidationReport, error) {
	if v == nil {
		return func() q7.ValidationReport {
			sealed := q7.ValidationReport{}
			*q7.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), q8.Errorf("nil PrivateMessage")
	}
	report := func() q7.ValidationReport {
		report := func() q7.ValidationReport {
			sealed := q7.ValidationReport{Complete: false}
			*q7.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
		q7.BridgeValidationReportMethodAddUnchecked(&report, q5.Location{Path: "PrivateMessage.privateIEs"})
		return report
	}()
	for i, field := range v.PrivateIEs {
		if *q7.BridgeValidationReportFieldErr(&report) != nil {
			return report, *q7.BridgeValidationReportFieldErr(&report)
		}
		if !q4.BridgePrivateMessageIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			id := field.Id
			q7.BridgeValidationReportMethodAddIssue(&report, q7.ValidationIssue{Code: q10.ValueIDMismatch, Severity: q10.ValidationSeverityError, Location: q5.Location{Path: q5.Path(q8.Sprintf("PrivateMessage.privateIEs[%d].id", i))}, PrivateID: &id, Rule: q9.BridgeLppaValidationRule(q10.ValueIDMismatch), RelatedRules: []q5.SourceRule{q4.BridgePrivateMessageIEsValueMethodRule(field.Value)}})
		}
	}
	return report, nil
}
func ValidatePrivateMessage(v *q6.PrivateMessage, options ...q5.ValidationOption) (q7.ValidationReport, error) {
	budget, err := q5.ValidationBudget(options...)
	if err != nil {
		return q7.ValidationReport{}, q5.OperationError(err, "PrivateMessage")
	}
	report, err := BridgeValidatePrivateMessageBudget(v, budget)
	if err == nil && !BridgeValidationHasValueMismatch(report) {
		_, err = q6.BridgePrivateMessageMethodMarshalAPERBudget(v, budget, false)
	}
	if *q7.BridgeValidationReportFieldErr(&report) != nil {
		err = *q7.BridgeValidationReportFieldErr(&report)
	}
	*q7.BridgeValidationReportFieldBudget(&report) = nil
	*q7.BridgeValidationReportFieldErr(&report) = nil
	return report, q5.OperationError(err, "PrivateMessage")
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldId(v *ECIDMeasurementInitiationRequestIEValue) *q10.ProtocolIEID {
	return &v.id
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldIsOpaque(v *ECIDMeasurementInitiationRequestIEValue) *bool {
	return &v.isOpaque
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldOpaque(v *ECIDMeasurementInitiationRequestIEValue) **q5.OpaqueOpenType {
	return &v.opaque
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldReceived(v *ECIDMeasurementInitiationRequestIEValue) *q5.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldReplay(v *ECIDMeasurementInitiationRequestIEValue) *q5.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldRowESMLCUEMeasurementID(v *ECIDMeasurementInitiationRequestIEValue) **q10.MeasurementID {
	return &v.rowESMLCUEMeasurementID
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldRowInterRATMeasurementQuantities(v *ECIDMeasurementInitiationRequestIEValue) **q20.InterRATMeasurementQuantities {
	return &v.rowInterRATMeasurementQuantities
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldRowMeasurementPeriodicity(v *ECIDMeasurementInitiationRequestIEValue) **q10.MeasurementPeriodicity {
	return &v.rowMeasurementPeriodicity
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldRowMeasurementQuantities(v *ECIDMeasurementInitiationRequestIEValue) **q20.MeasurementQuantities {
	return &v.rowMeasurementQuantities
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldRowReportCharacteristics(v *ECIDMeasurementInitiationRequestIEValue) **q10.ReportCharacteristics {
	return &v.rowReportCharacteristics
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldRowWLANMeasurementQuantities(v *ECIDMeasurementInitiationRequestIEValue) **WLANMeasurementQuantities {
	return &v.rowWLANMeasurementQuantities
}
func BridgeECIDMeasurementInitiationRequestIEValueFieldWithoutReplay(v *ECIDMeasurementInitiationRequestIEValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodCaptureFraming(v ECIDMeasurementInitiationRequestIEValue) uint64 {
	return v.captureFraming()
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodCaptureSemantics(v ECIDMeasurementInitiationRequestIEValue, a0 q5.SemanticCapture) ECIDMeasurementInitiationRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodCaptureSnapshot(v ECIDMeasurementInitiationRequestIEValue) q5.Snapshot {
	return v.captureSnapshot()
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodCompareSemantics(v ECIDMeasurementInitiationRequestIEValue, a0 q5.SemanticComparison) q5.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodDecode(v ECIDMeasurementInitiationRequestIEValue, a0 q10.ProtocolIEID, a1 q5.OpaqueOpenType) (ECIDMeasurementInitiationRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodEncode(v ECIDMeasurementInitiationRequestIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodEncodeFresh(v ECIDMeasurementInitiationRequestIEValue, a0 bool, a1 *q5.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodMatchesID(v ECIDMeasurementInitiationRequestIEValue, a0 q10.ProtocolIEID, a1 *q5.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodReason(v ECIDMeasurementInitiationRequestIEValue, a0 q10.ProtocolIEID) q5.OpaqueReason {
	return v.reason(a0)
}
func BridgeECIDMeasurementInitiationRequestIEValueMethodRule(v ECIDMeasurementInitiationRequestIEValue) q5.SourceRule {
	return v.rule()
}
func BridgeInterRATMeasuredResultsValueAPERValueFieldContext(v *InterRATMeasuredResultsValueAPERValue) *q10.BridgeCodecContext {
	return &v.context
}
func BridgeInterRATMeasuredResultsValueAPERValueFieldReceived(v *InterRATMeasuredResultsValueAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeInterRATMeasuredResultsValueAPERValueFieldReplay(v *InterRATMeasuredResultsValueAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasuredResultsValueAPERValueFieldWithoutReplay(v *InterRATMeasuredResultsValueAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasuredResultsValueValueCodecFieldCapture(v *InterRATMeasuredResultsValueValueCodec) *func(q13.InterRATMeasuredResultsValue, q5.DecodeState) (q13.InterRATMeasuredResultsValue, q5.Snapshot) {
	return &v.capture
}
func BridgeInterRATMeasuredResultsValueValueCodecFieldCompare(v *InterRATMeasuredResultsValueValueCodec) *func(q13.InterRATMeasuredResultsValue, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeInterRATMeasuredResultsValueValueCodecFieldContext(v *InterRATMeasuredResultsValueValueCodec) *q10.BridgeCodecContext {
	return &v.context
}
func BridgeInterRATMeasuredResultsValueValueCodecFieldDecode(v *InterRATMeasuredResultsValueValueCodec) *func([]byte, q5.DecodeState) (q13.InterRATMeasuredResultsValue, error) {
	return &v.decode
}
func BridgeInterRATMeasuredResultsValueValueCodecFieldEncode(v *InterRATMeasuredResultsValueValueCodec) *func(q13.InterRATMeasuredResultsValue, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInterRATMeasuredResultsValueValueCodecFieldPath(v *InterRATMeasuredResultsValueValueCodec) *q5.Path {
	return &v.path
}
func BridgeInterRATMeasuredResultsValueValueCodecMethodEncodeBudget(v InterRATMeasuredResultsValueValueCodec, a0 q13.InterRATMeasuredResultsValue, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeInterRATMeasuredResultsValueValueCodecMethodEncodeChanged(v InterRATMeasuredResultsValueValueCodec, a0 q13.InterRATMeasuredResultsValue, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInterRATMeasurementResultAPERValueFieldContext(v *InterRATMeasurementResultAPERValue) *q10.BridgeCodecContext {
	return &v.context
}
func BridgeInterRATMeasurementResultAPERValueFieldReceived(v *InterRATMeasurementResultAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeInterRATMeasurementResultAPERValueFieldReplay(v *InterRATMeasurementResultAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementResultAPERValueFieldWithoutReplay(v *InterRATMeasurementResultAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementResultCompleteFieldPerPadding(v *InterRATMeasurementResultComplete) *q5.CompletePadding {
	return &v.perPadding
}
func BridgeInterRATMeasurementResultCompleteFieldReceived(v *InterRATMeasurementResultComplete) *bool {
	return &v.received
}
func BridgeInterRATMeasurementResultCompleteFieldReceivedBytes(v *InterRATMeasurementResultComplete) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeInterRATMeasurementResultCompleteFieldReplay(v *InterRATMeasurementResultComplete) *q5.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementResultCompleteFieldStream(v *InterRATMeasurementResultComplete) *q5.WireSpan {
	return &v.stream
}
func BridgeInterRATMeasurementResultCompleteFieldWithoutReplay(v *InterRATMeasurementResultComplete) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementResultCompleteMethodMarshalAPERBudget(v *InterRATMeasurementResultComplete, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInterRATMeasurementResultCompleteMethodMarshalAPERChanged(v *InterRATMeasurementResultComplete, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeInterRATMeasurementResultCompleteMethodMarshalAPERChangedValue(v *InterRATMeasurementResultComplete, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeInterRATMeasurementResultCompleteMethodMarshalAPERFreshValue(v *InterRATMeasurementResultComplete, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeInterRATMeasurementResultCompleteMethodMarshalAPERLegacy(v *InterRATMeasurementResultComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeInterRATMeasurementResultCompleteMethodMarshalAPERPlanned(v *InterRATMeasurementResultComplete, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeInterRATMeasurementResultCompleteMethodUnmarshalAPERLegacy(v *InterRATMeasurementResultComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeInterRATMeasurementResultCompleteMethodUnmarshalAPERWithOptions(v *InterRATMeasurementResultComplete, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeInterRATMeasurementResultValueCodecFieldCapture(v *InterRATMeasurementResultValueCodec) *func(InterRATMeasurementResult, q5.DecodeState) (InterRATMeasurementResult, q5.Snapshot) {
	return &v.capture
}
func BridgeInterRATMeasurementResultValueCodecFieldCompare(v *InterRATMeasurementResultValueCodec) *func(InterRATMeasurementResult, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeInterRATMeasurementResultValueCodecFieldContext(v *InterRATMeasurementResultValueCodec) *q10.BridgeCodecContext {
	return &v.context
}
func BridgeInterRATMeasurementResultValueCodecFieldDecode(v *InterRATMeasurementResultValueCodec) *func([]byte, q5.DecodeState) (InterRATMeasurementResult, error) {
	return &v.decode
}
func BridgeInterRATMeasurementResultValueCodecFieldEncode(v *InterRATMeasurementResultValueCodec) *func(InterRATMeasurementResult, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInterRATMeasurementResultValueCodecFieldPath(v *InterRATMeasurementResultValueCodec) *q5.Path {
	return &v.path
}
func BridgeInterRATMeasurementResultValueCodecMethodEncodeBudget(v InterRATMeasurementResultValueCodec, a0 InterRATMeasurementResult, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeInterRATMeasurementResultValueCodecMethodEncodeChanged(v InterRATMeasurementResultValueCodec, a0 InterRATMeasurementResult, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultNRCompleteFieldPerPadding(v *ResultNRComplete) *q5.CompletePadding {
	return &v.perPadding
}
func BridgeResultNRCompleteFieldReceived(v *ResultNRComplete) *bool { return &v.received }
func BridgeResultNRCompleteFieldReceivedBytes(v *ResultNRComplete) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeResultNRCompleteFieldReplay(v *ResultNRComplete) *q5.Snapshot { return &v.replay }
func BridgeResultNRCompleteFieldStream(v *ResultNRComplete) *q5.WireSpan { return &v.stream }
func BridgeResultNRCompleteFieldWithoutReplay(v *ResultNRComplete) *bool { return &v.withoutReplay }
func BridgeResultNRCompleteMethodMarshalAPERBudget(v *ResultNRComplete, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultNRCompleteMethodMarshalAPERChanged(v *ResultNRComplete, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultNRCompleteMethodMarshalAPERChangedValue(v *ResultNRComplete, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultNRCompleteMethodMarshalAPERFreshValue(v *ResultNRComplete, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultNRCompleteMethodMarshalAPERLegacy(v *ResultNRComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultNRCompleteMethodMarshalAPERPlanned(v *ResultNRComplete, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultNRCompleteMethodUnmarshalAPERLegacy(v *ResultNRComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultNRCompleteMethodUnmarshalAPERWithOptions(v *ResultNRComplete, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSRSConfigurationForAllCellsCompleteFieldPerPadding(v *SRSConfigurationForAllCellsComplete) *q5.CompletePadding {
	return &v.perPadding
}
func BridgeSRSConfigurationForAllCellsCompleteFieldReceived(v *SRSConfigurationForAllCellsComplete) *bool {
	return &v.received
}
func BridgeSRSConfigurationForAllCellsCompleteFieldReceivedBytes(v *SRSConfigurationForAllCellsComplete) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeSRSConfigurationForAllCellsCompleteFieldReplay(v *SRSConfigurationForAllCellsComplete) *q5.Snapshot {
	return &v.replay
}
func BridgeSRSConfigurationForAllCellsCompleteFieldStream(v *SRSConfigurationForAllCellsComplete) *q5.WireSpan {
	return &v.stream
}
func BridgeSRSConfigurationForAllCellsCompleteFieldWithoutReplay(v *SRSConfigurationForAllCellsComplete) *bool {
	return &v.withoutReplay
}
func BridgeSRSConfigurationForAllCellsCompleteMethodMarshalAPERBudget(v *SRSConfigurationForAllCellsComplete, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSRSConfigurationForAllCellsCompleteMethodMarshalAPERChanged(v *SRSConfigurationForAllCellsComplete, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSRSConfigurationForAllCellsCompleteMethodMarshalAPERChangedValue(v *SRSConfigurationForAllCellsComplete, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSRSConfigurationForAllCellsCompleteMethodMarshalAPERFreshValue(v *SRSConfigurationForAllCellsComplete, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeSRSConfigurationForAllCellsCompleteMethodMarshalAPERLegacy(v *SRSConfigurationForAllCellsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSRSConfigurationForAllCellsCompleteMethodMarshalAPERPlanned(v *SRSConfigurationForAllCellsComplete, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeSRSConfigurationForAllCellsCompleteMethodUnmarshalAPERLegacy(v *SRSConfigurationForAllCellsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSRSConfigurationForAllCellsCompleteMethodUnmarshalAPERWithOptions(v *SRSConfigurationForAllCellsComplete, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSystemInformationCompleteFieldPerPadding(v *SystemInformationComplete) *q5.CompletePadding {
	return &v.perPadding
}
func BridgeSystemInformationCompleteFieldReceived(v *SystemInformationComplete) *bool {
	return &v.received
}
func BridgeSystemInformationCompleteFieldReceivedBytes(v *SystemInformationComplete) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeSystemInformationCompleteFieldReplay(v *SystemInformationComplete) *q5.Snapshot {
	return &v.replay
}
func BridgeSystemInformationCompleteFieldStream(v *SystemInformationComplete) *q5.WireSpan {
	return &v.stream
}
func BridgeSystemInformationCompleteFieldWithoutReplay(v *SystemInformationComplete) *bool {
	return &v.withoutReplay
}
func BridgeSystemInformationCompleteMethodMarshalAPERBudget(v *SystemInformationComplete, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSystemInformationCompleteMethodMarshalAPERChanged(v *SystemInformationComplete, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSystemInformationCompleteMethodMarshalAPERChangedValue(v *SystemInformationComplete, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSystemInformationCompleteMethodMarshalAPERFreshValue(v *SystemInformationComplete, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeSystemInformationCompleteMethodMarshalAPERLegacy(v *SystemInformationComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSystemInformationCompleteMethodMarshalAPERPlanned(v *SystemInformationComplete, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeSystemInformationCompleteMethodUnmarshalAPERLegacy(v *SystemInformationComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSystemInformationCompleteMethodUnmarshalAPERWithOptions(v *SystemInformationComplete, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeWLANChannelListCompleteFieldPerPadding(v *WLANChannelListComplete) *q5.CompletePadding {
	return &v.perPadding
}
func BridgeWLANChannelListCompleteFieldReceived(v *WLANChannelListComplete) *bool { return &v.received }
func BridgeWLANChannelListCompleteFieldReceivedBytes(v *WLANChannelListComplete) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeWLANChannelListCompleteFieldReplay(v *WLANChannelListComplete) *q5.Snapshot {
	return &v.replay
}
func BridgeWLANChannelListCompleteFieldStream(v *WLANChannelListComplete) *q5.WireSpan {
	return &v.stream
}
func BridgeWLANChannelListCompleteFieldWithoutReplay(v *WLANChannelListComplete) *bool {
	return &v.withoutReplay
}
func BridgeWLANChannelListCompleteMethodMarshalAPERBudget(v *WLANChannelListComplete, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeWLANChannelListCompleteMethodMarshalAPERChanged(v *WLANChannelListComplete, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeWLANChannelListCompleteMethodMarshalAPERChangedValue(v *WLANChannelListComplete, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeWLANChannelListCompleteMethodMarshalAPERFreshValue(v *WLANChannelListComplete, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeWLANChannelListCompleteMethodMarshalAPERLegacy(v *WLANChannelListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeWLANChannelListCompleteMethodMarshalAPERPlanned(v *WLANChannelListComplete, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeWLANChannelListCompleteMethodUnmarshalAPERLegacy(v *WLANChannelListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeWLANChannelListCompleteMethodUnmarshalAPERWithOptions(v *WLANChannelListComplete, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeWLANMeasurementQuantitiesAPERValueFieldContext(v *WLANMeasurementQuantitiesAPERValue) *q10.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementQuantitiesAPERValueFieldReceived(v *WLANMeasurementQuantitiesAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesAPERValueFieldReplay(v *WLANMeasurementQuantitiesAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesAPERValueFieldWithoutReplay(v *WLANMeasurementQuantitiesAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesCompleteFieldPerPadding(v *WLANMeasurementQuantitiesComplete) *q5.CompletePadding {
	return &v.perPadding
}
func BridgeWLANMeasurementQuantitiesCompleteFieldReceived(v *WLANMeasurementQuantitiesComplete) *bool {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesCompleteFieldReceivedBytes(v *WLANMeasurementQuantitiesComplete) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeWLANMeasurementQuantitiesCompleteFieldReplay(v *WLANMeasurementQuantitiesComplete) *q5.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesCompleteFieldStream(v *WLANMeasurementQuantitiesComplete) *q5.WireSpan {
	return &v.stream
}
func BridgeWLANMeasurementQuantitiesCompleteFieldWithoutReplay(v *WLANMeasurementQuantitiesComplete) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesCompleteMethodMarshalAPERBudget(v *WLANMeasurementQuantitiesComplete, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeWLANMeasurementQuantitiesCompleteMethodMarshalAPERChanged(v *WLANMeasurementQuantitiesComplete, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeWLANMeasurementQuantitiesCompleteMethodMarshalAPERChangedValue(v *WLANMeasurementQuantitiesComplete, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeWLANMeasurementQuantitiesCompleteMethodMarshalAPERFreshValue(v *WLANMeasurementQuantitiesComplete, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeWLANMeasurementQuantitiesCompleteMethodMarshalAPERLegacy(v *WLANMeasurementQuantitiesComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeWLANMeasurementQuantitiesCompleteMethodMarshalAPERPlanned(v *WLANMeasurementQuantitiesComplete, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeWLANMeasurementQuantitiesCompleteMethodUnmarshalAPERLegacy(v *WLANMeasurementQuantitiesComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeWLANMeasurementQuantitiesCompleteMethodUnmarshalAPERWithOptions(v *WLANMeasurementQuantitiesComplete, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldCapture(v *WLANMeasurementQuantitiesConcreteValueCodec) *func(WLANMeasurementQuantities, q5.DecodeState) (WLANMeasurementQuantities, q5.Snapshot) {
	return &v.capture
}
func BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldCompare(v *WLANMeasurementQuantitiesConcreteValueCodec) *func(WLANMeasurementQuantities, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldContext(v *WLANMeasurementQuantitiesConcreteValueCodec) *q10.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldDecode(v *WLANMeasurementQuantitiesConcreteValueCodec) *func([]byte, q5.DecodeState) (WLANMeasurementQuantities, error) {
	return &v.decode
}
func BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldEncode(v *WLANMeasurementQuantitiesConcreteValueCodec) *func(WLANMeasurementQuantities, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldPath(v *WLANMeasurementQuantitiesConcreteValueCodec) *q5.Path {
	return &v.path
}
func BridgeWLANMeasurementQuantitiesConcreteValueCodecMethodEncodeBudget(v WLANMeasurementQuantitiesConcreteValueCodec, a0 WLANMeasurementQuantities, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANMeasurementQuantitiesConcreteValueCodecMethodEncodeChanged(v WLANMeasurementQuantitiesConcreteValueCodec, a0 WLANMeasurementQuantities, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANMeasurementQuantitiesItemAPERValueFieldContext(v *WLANMeasurementQuantitiesItemAPERValue) *q10.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementQuantitiesItemAPERValueFieldReceived(v *WLANMeasurementQuantitiesItemAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesItemAPERValueFieldReplay(v *WLANMeasurementQuantitiesItemAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesItemAPERValueFieldWithoutReplay(v *WLANMeasurementQuantitiesItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesItemFieldExtCount(v *WLANMeasurementQuantitiesItem) *int64 {
	return &v.extCount
}
func BridgeWLANMeasurementQuantitiesItemFieldExtData(v *WLANMeasurementQuantitiesItem) *[][]byte {
	return &v.extData
}
func BridgeWLANMeasurementQuantitiesItemFieldExtOrigin(v *WLANMeasurementQuantitiesItem) *[]q5.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeWLANMeasurementQuantitiesItemFieldExtPresent(v *WLANMeasurementQuantitiesItem) *[]bool {
	return &v.extPresent
}
func BridgeWLANMeasurementQuantitiesItemFieldExtWire(v *WLANMeasurementQuantitiesItem) *[]q5.WireSpan {
	return &v.extWire
}
func BridgeWLANMeasurementQuantitiesItemFieldIEExtensionsIndef(v *WLANMeasurementQuantitiesItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeWLANMeasurementQuantitiesItemFieldPerExtPadding(v *WLANMeasurementQuantitiesItem) *[]q5.CompletePadding {
	return &v.perExtPadding
}
func BridgeWLANMeasurementQuantitiesItemFieldPerPadding(v *WLANMeasurementQuantitiesItem) *q5.FinalPadding {
	return &v.perPadding
}
func BridgeWLANMeasurementQuantitiesItemFieldReceived(v *WLANMeasurementQuantitiesItem) *bool {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesItemFieldReceivedBytes(v *WLANMeasurementQuantitiesItem) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeWLANMeasurementQuantitiesItemFieldReplay(v *WLANMeasurementQuantitiesItem) *q5.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesItemFieldStream(v *WLANMeasurementQuantitiesItem) *q5.WireSpan {
	return &v.stream
}
func BridgeWLANMeasurementQuantitiesItemFieldWithoutReplay(v *WLANMeasurementQuantitiesItem) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesItemIEFieldFieldReceived(v *WLANMeasurementQuantitiesItemIEField) *q5.CompletePadding {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesItemIEFieldFieldReplay(v *WLANMeasurementQuantitiesItemIEField) *q5.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesItemIEFieldFieldStream(v *WLANMeasurementQuantitiesItemIEField) *q5.WireSpan {
	return &v.stream
}
func BridgeWLANMeasurementQuantitiesItemIEFieldFieldWithoutReplay(v *WLANMeasurementQuantitiesItemIEField) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesItemIEFieldMethodMarshalAPERTo(v *WLANMeasurementQuantitiesItemIEField, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWLANMeasurementQuantitiesItemIEFieldMethodUnmarshalAPERFrom(v *WLANMeasurementQuantitiesItemIEField, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWLANMeasurementQuantitiesItemIETableMethodInfoWLANMeasurementQuantitiesItem(v WLANMeasurementQuantitiesItemIETable) q10.FieldInfo {
	return v.infoWLANMeasurementQuantitiesItem()
}
func BridgeWLANMeasurementQuantitiesItemIEValueFieldId(v *WLANMeasurementQuantitiesItemIEValue) *q10.ProtocolIEID {
	return &v.id
}
func BridgeWLANMeasurementQuantitiesItemIEValueFieldIsOpaque(v *WLANMeasurementQuantitiesItemIEValue) *bool {
	return &v.isOpaque
}
func BridgeWLANMeasurementQuantitiesItemIEValueFieldOpaque(v *WLANMeasurementQuantitiesItemIEValue) **q5.OpaqueOpenType {
	return &v.opaque
}
func BridgeWLANMeasurementQuantitiesItemIEValueFieldReceived(v *WLANMeasurementQuantitiesItemIEValue) *q5.WireSpan {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesItemIEValueFieldReplay(v *WLANMeasurementQuantitiesItemIEValue) *q5.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesItemIEValueFieldRowWLANMeasurementQuantitiesItem(v *WLANMeasurementQuantitiesItemIEValue) **WLANMeasurementQuantitiesItem {
	return &v.rowWLANMeasurementQuantitiesItem
}
func BridgeWLANMeasurementQuantitiesItemIEValueFieldWithoutReplay(v *WLANMeasurementQuantitiesItemIEValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodCaptureFraming(v WLANMeasurementQuantitiesItemIEValue) uint64 {
	return v.captureFraming()
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodCaptureSemantics(v WLANMeasurementQuantitiesItemIEValue, a0 q5.SemanticCapture) WLANMeasurementQuantitiesItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodCaptureSnapshot(v WLANMeasurementQuantitiesItemIEValue) q5.Snapshot {
	return v.captureSnapshot()
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodCompareSemantics(v WLANMeasurementQuantitiesItemIEValue, a0 q5.SemanticComparison) q5.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodDecode(v WLANMeasurementQuantitiesItemIEValue, a0 q10.ProtocolIEID, a1 q5.OpaqueOpenType) (WLANMeasurementQuantitiesItemIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodEncode(v WLANMeasurementQuantitiesItemIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodEncodeFresh(v WLANMeasurementQuantitiesItemIEValue, a0 bool, a1 *q5.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodMatchesID(v WLANMeasurementQuantitiesItemIEValue, a0 q10.ProtocolIEID, a1 *q5.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodReason(v WLANMeasurementQuantitiesItemIEValue, a0 q10.ProtocolIEID) q5.OpaqueReason {
	return v.reason(a0)
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodRule(v WLANMeasurementQuantitiesItemIEValue) q5.SourceRule {
	return v.rule()
}
func BridgeWLANMeasurementQuantitiesItemMethodMarshalAPERBudget(v *WLANMeasurementQuantitiesItem, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeWLANMeasurementQuantitiesItemMethodMarshalAPERChanged(v *WLANMeasurementQuantitiesItem, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeWLANMeasurementQuantitiesItemMethodMarshalAPERChangedValue(v *WLANMeasurementQuantitiesItem, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeWLANMeasurementQuantitiesItemMethodMarshalAPERFreshValue(v *WLANMeasurementQuantitiesItem, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeWLANMeasurementQuantitiesItemMethodMarshalAPERLegacy(v *WLANMeasurementQuantitiesItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeWLANMeasurementQuantitiesItemMethodMarshalAPERPlanned(v *WLANMeasurementQuantitiesItem, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeWLANMeasurementQuantitiesItemMethodMarshalAPERTo(v *WLANMeasurementQuantitiesItem, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWLANMeasurementQuantitiesItemMethodUnmarshalAPERFrom(v *WLANMeasurementQuantitiesItem, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWLANMeasurementQuantitiesItemMethodUnmarshalAPERLegacy(v *WLANMeasurementQuantitiesItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeWLANMeasurementQuantitiesItemMethodUnmarshalAPERWithOptions(v *WLANMeasurementQuantitiesItem, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeWLANMeasurementQuantitiesItemValueCodecFieldCapture(v *WLANMeasurementQuantitiesItemValueCodec) *func(WLANMeasurementQuantitiesItem, q5.DecodeState) (WLANMeasurementQuantitiesItem, q5.Snapshot) {
	return &v.capture
}
func BridgeWLANMeasurementQuantitiesItemValueCodecFieldCompare(v *WLANMeasurementQuantitiesItemValueCodec) *func(WLANMeasurementQuantitiesItem, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeWLANMeasurementQuantitiesItemValueCodecFieldContext(v *WLANMeasurementQuantitiesItemValueCodec) *q10.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementQuantitiesItemValueCodecFieldDecode(v *WLANMeasurementQuantitiesItemValueCodec) *func([]byte, q5.DecodeState) (WLANMeasurementQuantitiesItem, error) {
	return &v.decode
}
func BridgeWLANMeasurementQuantitiesItemValueCodecFieldEncode(v *WLANMeasurementQuantitiesItemValueCodec) *func(WLANMeasurementQuantitiesItem, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANMeasurementQuantitiesItemValueCodecFieldPath(v *WLANMeasurementQuantitiesItemValueCodec) *q5.Path {
	return &v.path
}
func BridgeWLANMeasurementQuantitiesItemValueCodecMethodEncodeBudget(v WLANMeasurementQuantitiesItemValueCodec, a0 WLANMeasurementQuantitiesItem, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANMeasurementQuantitiesItemValueCodecMethodEncodeChanged(v WLANMeasurementQuantitiesItemValueCodec, a0 WLANMeasurementQuantitiesItem, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBindingFieldCodec(v *WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding) *WLANMeasurementQuantitiesItemValueCodec {
	return &v.codec
}
func BridgeWLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBindingFieldGet(v *WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding) *func(*WLANMeasurementQuantitiesItemIEValue) (*WLANMeasurementQuantitiesItem, bool) {
	return &v.get
}
func BridgeWLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBindingFieldInfo(v *WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding) *q10.FieldInfo {
	return &v.info
}
func BridgeWLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBindingFieldInject(v *WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding) *func(WLANMeasurementQuantitiesItem) WLANMeasurementQuantitiesItemIEValue {
	return &v.inject
}
