// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s06 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s06

import (
	q6 "fmt"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q11 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	q7 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// ECIDMeasurementFailureIndicationIEContainer is the concrete ProtocolIEContainer[ECIDMeasurementFailureIndicationIEValue].
type ECIDMeasurementFailureIndicationIEContainer []ECIDMeasurementFailureIndicationIEField

// ECIDMeasurementFailureIndicationIEField is the concrete ProtocolIEField[ECIDMeasurementFailureIndicationIEValue].
type ECIDMeasurementFailureIndicationIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         ECIDMeasurementFailureIndicationIEValue

	received q4.CompletePadding
}

func (v ECIDMeasurementFailureIndicationIEField) WithoutReplay() ECIDMeasurementFailureIndicationIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ECIDMeasurementFailureIndicationIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ECIDMeasurementFailureIndicationIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
func (v *ECIDMeasurementFailureIndicationIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementFailureIndicationIEField{}
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
	var zero ECIDMeasurementFailureIndicationIEValue

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

// InterRATMeasurementQuantitiesItemIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[InterRATMeasurementQuantitiesItemIEValue].
type InterRATMeasurementQuantitiesItemIEValueProtocolIESingleContainer = InterRATMeasurementQuantitiesItemIEField

// MeasurementQuantitiesItemIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[MeasurementQuantitiesItemIEValue].
type MeasurementQuantitiesItemIEValueProtocolIESingleContainer = MeasurementQuantitiesItemIEField

// InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding is the concrete IEBinding[InterRATMeasurementQuantitiesItem, InterRATMeasurementQuantitiesItemIEValue].
type InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding struct {
	info   q5.FieldInfo
	codec  InterRATMeasurementQuantitiesItemValueCodec
	inject func(InterRATMeasurementQuantitiesItem,

	) InterRATMeasurementQuantitiesItemIEValue

	get func(*InterRATMeasurementQuantitiesItemIEValue,

	) (*InterRATMeasurementQuantitiesItem,

		bool)
}

func (b InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding) Info() q5.FieldInfo {
	return b.info
}
func (b InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding) Codec() InterRATMeasurementQuantitiesItemValueCodec {
	return b.codec
}
func (b InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding) New(value InterRATMeasurementQuantitiesItem,

) (InterRATMeasurementQuantitiesItemIEField, error) {
	if b.inject == nil {
		return InterRATMeasurementQuantitiesItemIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return InterRATMeasurementQuantitiesItemIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return InterRATMeasurementQuantitiesItemIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return InterRATMeasurementQuantitiesItemIEField{}, q4.OperationError(err, "Value.New")
	}
	return InterRATMeasurementQuantitiesItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding) Get(field *InterRATMeasurementQuantitiesItemIEField) (*InterRATMeasurementQuantitiesItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InterRATMeasurementQuantitiesItemValueCodec is the concrete ValueCodec[InterRATMeasurementQuantitiesItem].
type InterRATMeasurementQuantitiesItemValueCodec struct {
	context q5.BridgeCodecContext
	capture func(InterRATMeasurementQuantitiesItem, q4.DecodeState,

	) (InterRATMeasurementQuantitiesItem, q4.Snapshot,

	)
	compare func(InterRATMeasurementQuantitiesItem, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (InterRATMeasurementQuantitiesItem,

		error)
	encode func(InterRATMeasurementQuantitiesItem,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c InterRATMeasurementQuantitiesItemValueCodec) New(value InterRATMeasurementQuantitiesItem,

) (InterRATMeasurementQuantitiesItemAPERValue, error) {
	if c.encode == nil {
		return InterRATMeasurementQuantitiesItemAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return InterRATMeasurementQuantitiesItemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InterRATMeasurementQuantitiesItemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return InterRATMeasurementQuantitiesItemAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c InterRATMeasurementQuantitiesItemValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (InterRATMeasurementQuantitiesItemAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return InterRATMeasurementQuantitiesItemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return InterRATMeasurementQuantitiesItemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return InterRATMeasurementQuantitiesItemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return InterRATMeasurementQuantitiesItemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return InterRATMeasurementQuantitiesItemAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c InterRATMeasurementQuantitiesItemValueCodec) EncodeAPER(value InterRATMeasurementQuantitiesItemAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c InterRATMeasurementQuantitiesItemValueCodec) encodeBudget(value InterRATMeasurementQuantitiesItem,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c InterRATMeasurementQuantitiesItemValueCodec) encodeChanged(value InterRATMeasurementQuantitiesItem,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// InterRATMeasurementQuantitiesItemIEField is the concrete ProtocolIEField[InterRATMeasurementQuantitiesItemIEValue].
type InterRATMeasurementQuantitiesItemIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         InterRATMeasurementQuantitiesItemIEValue

	received q4.CompletePadding
}

func (v InterRATMeasurementQuantitiesItemIEField) WithoutReplay() InterRATMeasurementQuantitiesItemIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *InterRATMeasurementQuantitiesItemIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *InterRATMeasurementQuantitiesItemIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
func (v *InterRATMeasurementQuantitiesItemIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InterRATMeasurementQuantitiesItemIEField{}
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
	var zero InterRATMeasurementQuantitiesItemIEValue

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

// MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding is the concrete IEBinding[MeasurementQuantitiesItem, MeasurementQuantitiesItemIEValue].
type MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding struct {
	info   q5.FieldInfo
	codec  MeasurementQuantitiesItemValueCodec
	inject func(MeasurementQuantitiesItem,

	) MeasurementQuantitiesItemIEValue

	get func(*MeasurementQuantitiesItemIEValue,

	) (*MeasurementQuantitiesItem,

		bool)
}

func (b MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding) Info() q5.FieldInfo {
	return b.info
}
func (b MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding) Codec() MeasurementQuantitiesItemValueCodec {
	return b.codec
}
func (b MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding) New(value MeasurementQuantitiesItem,

) (MeasurementQuantitiesItemIEField, error) {
	if b.inject == nil {
		return MeasurementQuantitiesItemIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return MeasurementQuantitiesItemIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return MeasurementQuantitiesItemIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return MeasurementQuantitiesItemIEField{}, q4.OperationError(err, "Value.New")
	}
	return MeasurementQuantitiesItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding) Get(field *MeasurementQuantitiesItemIEField) (*MeasurementQuantitiesItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MeasurementQuantitiesItemValueCodec is the concrete ValueCodec[MeasurementQuantitiesItem].
type MeasurementQuantitiesItemValueCodec struct {
	context q5.BridgeCodecContext
	capture func(MeasurementQuantitiesItem, q4.DecodeState,

	) (MeasurementQuantitiesItem, q4.Snapshot,

	)
	compare func(MeasurementQuantitiesItem, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (MeasurementQuantitiesItem,

		error)
	encode func(MeasurementQuantitiesItem,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c MeasurementQuantitiesItemValueCodec) New(value MeasurementQuantitiesItem,

) (MeasurementQuantitiesItemAPERValue, error) {
	if c.encode == nil {
		return MeasurementQuantitiesItemAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return MeasurementQuantitiesItemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MeasurementQuantitiesItemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return MeasurementQuantitiesItemAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c MeasurementQuantitiesItemValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (MeasurementQuantitiesItemAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return MeasurementQuantitiesItemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return MeasurementQuantitiesItemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return MeasurementQuantitiesItemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return MeasurementQuantitiesItemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return MeasurementQuantitiesItemAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c MeasurementQuantitiesItemValueCodec) EncodeAPER(value MeasurementQuantitiesItemAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c MeasurementQuantitiesItemValueCodec) encodeBudget(value MeasurementQuantitiesItem,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c MeasurementQuantitiesItemValueCodec) encodeChanged(value MeasurementQuantitiesItem,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// MeasurementQuantitiesItemIEField is the concrete ProtocolIEField[MeasurementQuantitiesItemIEValue].
type MeasurementQuantitiesItemIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         MeasurementQuantitiesItemIEValue

	received q4.CompletePadding
}

func (v MeasurementQuantitiesItemIEField) WithoutReplay() MeasurementQuantitiesItemIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *MeasurementQuantitiesItemIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *MeasurementQuantitiesItemIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
func (v *MeasurementQuantitiesItemIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MeasurementQuantitiesItemIEField{}
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
	var zero MeasurementQuantitiesItemIEValue

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

// ECIDMeasurementFailureIndicationMeasurementIDIEBinding is the concrete IEBinding[MeasurementID, ECIDMeasurementFailureIndicationIEValue].
type ECIDMeasurementFailureIndicationMeasurementIDIEBinding struct {
	info   q5.FieldInfo
	codec  q5.MeasurementIDValueCodec
	inject func(q5.MeasurementID,

	) ECIDMeasurementFailureIndicationIEValue

	get func(*ECIDMeasurementFailureIndicationIEValue,

	) (*q5.MeasurementID,

		bool)
}

func (b ECIDMeasurementFailureIndicationMeasurementIDIEBinding) Info() q5.FieldInfo { return b.info }
func (b ECIDMeasurementFailureIndicationMeasurementIDIEBinding) Codec() q5.MeasurementIDValueCodec {
	return b.codec
}
func (b ECIDMeasurementFailureIndicationMeasurementIDIEBinding) New(value q5.MeasurementID,

) (ECIDMeasurementFailureIndicationIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementFailureIndicationIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementFailureIndicationIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q5.BridgeMeasurementIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementFailureIndicationIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementFailureIndicationIEField{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementFailureIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementFailureIndicationMeasurementIDIEBinding) Get(field *ECIDMeasurementFailureIndicationIEField) (*q5.MeasurementID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementFailureIndicationCauseIEBinding is the concrete IEBinding[Cause, ECIDMeasurementFailureIndicationIEValue].
type ECIDMeasurementFailureIndicationCauseIEBinding struct {
	info   q5.FieldInfo
	codec  q9.CauseValueCodec
	inject func(q9.Cause,

	) ECIDMeasurementFailureIndicationIEValue

	get func(*ECIDMeasurementFailureIndicationIEValue,

	) (*q9.Cause,

		bool)
}

func (b ECIDMeasurementFailureIndicationCauseIEBinding) Info() q5.FieldInfo        { return b.info }
func (b ECIDMeasurementFailureIndicationCauseIEBinding) Codec() q9.CauseValueCodec { return b.codec }
func (b ECIDMeasurementFailureIndicationCauseIEBinding) New(value q9.Cause,

) (ECIDMeasurementFailureIndicationIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementFailureIndicationIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementFailureIndicationIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q9.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementFailureIndicationIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementFailureIndicationIEField{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementFailureIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementFailureIndicationCauseIEBinding) Get(field *ECIDMeasurementFailureIndicationIEField) (*q9.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MeasurementQuantitiesConcreteValueCodec is the concrete ValueCodec[MeasurementQuantities].
type MeasurementQuantitiesConcreteValueCodec struct {
	context q5.BridgeCodecContext
	capture func(MeasurementQuantities, q4.DecodeState,

	) (MeasurementQuantities, q4.Snapshot,

	)
	compare func(MeasurementQuantities, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (MeasurementQuantities,

		error)
	encode func(MeasurementQuantities,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c MeasurementQuantitiesConcreteValueCodec) New(value MeasurementQuantities,

) (MeasurementQuantitiesAPERValue, error) {
	if c.encode == nil {
		return MeasurementQuantitiesAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return MeasurementQuantitiesAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MeasurementQuantitiesAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return MeasurementQuantitiesAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c MeasurementQuantitiesConcreteValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (MeasurementQuantitiesAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return MeasurementQuantitiesAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return MeasurementQuantitiesAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return MeasurementQuantitiesAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return MeasurementQuantitiesAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return MeasurementQuantitiesAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c MeasurementQuantitiesConcreteValueCodec) EncodeAPER(value MeasurementQuantitiesAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c MeasurementQuantitiesConcreteValueCodec) encodeBudget(value MeasurementQuantities,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c MeasurementQuantitiesConcreteValueCodec) encodeChanged(value MeasurementQuantities,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// InterRATMeasurementQuantitiesConcreteValueCodec is the concrete ValueCodec[InterRATMeasurementQuantities].
type InterRATMeasurementQuantitiesConcreteValueCodec struct {
	context q5.BridgeCodecContext
	capture func(InterRATMeasurementQuantities, q4.DecodeState,

	) (InterRATMeasurementQuantities, q4.Snapshot,

	)
	compare func(InterRATMeasurementQuantities, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (InterRATMeasurementQuantities,

		error)
	encode func(InterRATMeasurementQuantities,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c InterRATMeasurementQuantitiesConcreteValueCodec) New(value InterRATMeasurementQuantities,

) (InterRATMeasurementQuantitiesAPERValue, error) {
	if c.encode == nil {
		return InterRATMeasurementQuantitiesAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return InterRATMeasurementQuantitiesAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InterRATMeasurementQuantitiesAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return InterRATMeasurementQuantitiesAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c InterRATMeasurementQuantitiesConcreteValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (InterRATMeasurementQuantitiesAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return InterRATMeasurementQuantitiesAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return InterRATMeasurementQuantitiesAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return InterRATMeasurementQuantitiesAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return InterRATMeasurementQuantitiesAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return InterRATMeasurementQuantitiesAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c InterRATMeasurementQuantitiesConcreteValueCodec) EncodeAPER(value InterRATMeasurementQuantitiesAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c InterRATMeasurementQuantitiesConcreteValueCodec) encodeBudget(value InterRATMeasurementQuantities,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c InterRATMeasurementQuantitiesConcreteValueCodec) encodeChanged(value InterRATMeasurementQuantities,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// ECIDMeasurementTerminationCommandValueCodec is the concrete ValueCodec[ECIDMeasurementTerminationCommand].
type ECIDMeasurementTerminationCommandValueCodec struct {
	context q5.BridgeCodecContext
	capture func(ECIDMeasurementTerminationCommand, q4.DecodeState,

	) (ECIDMeasurementTerminationCommand, q4.Snapshot,

	)
	compare func(ECIDMeasurementTerminationCommand, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (ECIDMeasurementTerminationCommand,

		error)
	encode func(ECIDMeasurementTerminationCommand,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c ECIDMeasurementTerminationCommandValueCodec) New(value ECIDMeasurementTerminationCommand,

) (ECIDMeasurementTerminationCommandAPERValue, error) {
	if c.encode == nil {
		return ECIDMeasurementTerminationCommandAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementTerminationCommandAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ECIDMeasurementTerminationCommandAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementTerminationCommandAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c ECIDMeasurementTerminationCommandValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (ECIDMeasurementTerminationCommandAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ECIDMeasurementTerminationCommandAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return ECIDMeasurementTerminationCommandAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ECIDMeasurementTerminationCommandAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return ECIDMeasurementTerminationCommandAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return ECIDMeasurementTerminationCommandAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ECIDMeasurementTerminationCommandValueCodec) EncodeAPER(value ECIDMeasurementTerminationCommandAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c ECIDMeasurementTerminationCommandValueCodec) encodeBudget(value ECIDMeasurementTerminationCommand,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ECIDMeasurementTerminationCommandValueCodec) encodeChanged(value ECIDMeasurementTerminationCommand,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// EUTRANAccessPointPositionValueCodec is the concrete ValueCodec[EUTRANAccessPointPosition].
type EUTRANAccessPointPositionValueCodec struct {
	context q5.BridgeCodecContext
	capture func(EUTRANAccessPointPosition, q4.DecodeState,

	) (EUTRANAccessPointPosition, q4.Snapshot,

	)
	compare func(EUTRANAccessPointPosition, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (EUTRANAccessPointPosition,

		error)
	encode func(EUTRANAccessPointPosition,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c EUTRANAccessPointPositionValueCodec) New(value EUTRANAccessPointPosition,

) (EUTRANAccessPointPositionAPERValue, error) {
	if c.encode == nil {
		return EUTRANAccessPointPositionAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return EUTRANAccessPointPositionAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EUTRANAccessPointPositionAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return EUTRANAccessPointPositionAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c EUTRANAccessPointPositionValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (EUTRANAccessPointPositionAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return EUTRANAccessPointPositionAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return EUTRANAccessPointPositionAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return EUTRANAccessPointPositionAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return EUTRANAccessPointPositionAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return EUTRANAccessPointPositionAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c EUTRANAccessPointPositionValueCodec) EncodeAPER(value EUTRANAccessPointPositionAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c EUTRANAccessPointPositionValueCodec) encodeBudget(value EUTRANAccessPointPosition,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c EUTRANAccessPointPositionValueCodec) encodeChanged(value EUTRANAccessPointPosition,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// InterRATMeasurementQuantitiesItemIEContainer is the concrete ProtocolIEContainer[InterRATMeasurementQuantitiesItemIEValue].
type InterRATMeasurementQuantitiesItemIEContainer []InterRATMeasurementQuantitiesItemIEField

// MeasurementQuantitiesItemIEContainer is the concrete ProtocolIEContainer[MeasurementQuantitiesItemIEValue].
type MeasurementQuantitiesItemIEContainer []MeasurementQuantitiesItemIEField

// InterRATMeasurementQuantitiesItemAPERValue is the concrete APERValue[InterRATMeasurementQuantitiesItem].
type InterRATMeasurementQuantitiesItemAPERValue struct {
	context q5.BridgeCodecContext
	Value   InterRATMeasurementQuantitiesItem

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v InterRATMeasurementQuantitiesItemAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v InterRATMeasurementQuantitiesItemAPERValue) WithoutReplay() InterRATMeasurementQuantitiesItemAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasurementQuantitiesItemAPERValue is the concrete APERValue[MeasurementQuantitiesItem].
type MeasurementQuantitiesItemAPERValue struct {
	context q5.BridgeCodecContext
	Value   MeasurementQuantitiesItem

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v MeasurementQuantitiesItemAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v MeasurementQuantitiesItemAPERValue) WithoutReplay() MeasurementQuantitiesItemAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasurementQuantitiesAPERValue is the concrete APERValue[MeasurementQuantities].
type MeasurementQuantitiesAPERValue struct {
	context q5.BridgeCodecContext
	Value   MeasurementQuantities

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v MeasurementQuantitiesAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v MeasurementQuantitiesAPERValue) WithoutReplay() MeasurementQuantitiesAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// InterRATMeasurementQuantitiesAPERValue is the concrete APERValue[InterRATMeasurementQuantities].
type InterRATMeasurementQuantitiesAPERValue struct {
	context q5.BridgeCodecContext
	Value   InterRATMeasurementQuantities

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v InterRATMeasurementQuantitiesAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v InterRATMeasurementQuantitiesAPERValue) WithoutReplay() InterRATMeasurementQuantitiesAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// ECIDMeasurementTerminationCommandAPERValue is the concrete APERValue[ECIDMeasurementTerminationCommand].
type ECIDMeasurementTerminationCommandAPERValue struct {
	context q5.BridgeCodecContext
	Value   ECIDMeasurementTerminationCommand

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v ECIDMeasurementTerminationCommandAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v ECIDMeasurementTerminationCommandAPERValue) WithoutReplay() ECIDMeasurementTerminationCommandAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// EUTRANAccessPointPositionAPERValue is the concrete APERValue[EUTRANAccessPointPosition].
type EUTRANAccessPointPositionAPERValue struct {
	context q5.BridgeCodecContext
	Value   EUTRANAccessPointPosition

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v EUTRANAccessPointPositionAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v EUTRANAccessPointPositionAPERValue) WithoutReplay() EUTRANAccessPointPositionAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// EUTRANAccessPointPosition represents the ASN.1 type E-UTRANAccessPointPosition (SEQUENCE).
type EUTRANAccessPointPosition struct {
	replay                 q4.Snapshot
	stream                 q4.WireSpan
	withoutReplay          bool
	received               bool
	receivedBytes          q4.WireSpan
	LatitudeSign           int64                `asn1:"tag:0,context,implicit"`
	Latitude               int64                `asn1:"tag:1,context,implicit"`
	Longitude              int64                `asn1:"tag:2,context,implicit"`
	DirectionOfAltitude    int64                `asn1:"tag:3,context,implicit"`
	Altitude               int64                `asn1:"tag:4,context,implicit"`
	UncertaintySemiMajor   int64                `asn1:"tag:5,context,implicit"`
	UncertaintySemiMinor   int64                `asn1:"tag:6,context,implicit"`
	OrientationOfMajorAxis int64                `asn1:"tag:7,context,implicit"`
	UncertaintyAltitude    int64                `asn1:"tag:8,context,implicit"`
	Confidence             int64                `asn1:"tag:9,context,implicit"`
	extCount               int64                `asn1:"-" json:"-"`
	extPresent             []bool               `asn1:"-" json:"-"`
	extData                [][]byte             `asn1:"-" json:"-"`
	perPadding             q4.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding          []q4.CompletePadding `asn1:"-" json:"-"`
	extOrigin              []q4.OpaqueOrigin
	extWire                []q4.WireSpan
}
type InterRATMeasurementQuantities = []InterRATMeasurementQuantitiesItemIEValueProtocolIESingleContainer

// InterRATMeasurementQuantitiesItem represents the ASN.1 type InterRATMeasurementQuantities-Item (SEQUENCE).
type InterRATMeasurementQuantitiesItem struct {
	replay                             q4.Snapshot
	stream                             q4.WireSpan
	withoutReplay                      bool
	received                           bool
	receivedBytes                      q4.WireSpan
	InterRATMeasurementQuantitiesValue q5.InterRATMeasurementQuantitiesValue                   `asn1:"tag:0,context,implicit"`
	IEExtensions                       q8.InterRATMeasurementQuantitiesValueExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef                  bool                                                    `asn1:"-" json:"-"`
	extCount                           int64                                                   `asn1:"-" json:"-"`
	extPresent                         []bool                                                  `asn1:"-" json:"-"`
	extData                            [][]byte                                                `asn1:"-" json:"-"`
	perPadding                         q4.FinalPadding                                         `asn1:"-" json:"-"`
	perExtPadding                      []q4.CompletePadding                                    `asn1:"-" json:"-"`
	extOrigin                          []q4.OpaqueOrigin
	extWire                            []q4.WireSpan
}
type MeasurementQuantities = []MeasurementQuantitiesItemIEValueProtocolIESingleContainer

// MeasurementQuantitiesItem represents the ASN.1 type MeasurementQuantities-Item (SEQUENCE).
type MeasurementQuantitiesItem struct {
	replay                     q4.Snapshot
	stream                     q4.WireSpan
	withoutReplay              bool
	received                   bool
	receivedBytes              q4.WireSpan
	MeasurementQuantitiesValue q5.MeasurementQuantitiesValue                    `asn1:"tag:0,context,implicit"`
	IEExtensions               q10.MeasurementQuantitiesValueExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef          bool                                             `asn1:"-" json:"-"`
	extCount                   int64                                            `asn1:"-" json:"-"`
	extPresent                 []bool                                           `asn1:"-" json:"-"`
	extData                    [][]byte                                         `asn1:"-" json:"-"`
	perPadding                 q4.FinalPadding                                  `asn1:"-" json:"-"`
	perExtPadding              []q4.CompletePadding                             `asn1:"-" json:"-"`
	extOrigin                  []q4.OpaqueOrigin
	extWire                    []q4.WireSpan
}

// MarshalAPER encodes EUTRANAccessPointPosition to APER format.
func (v *EUTRANAccessPointPosition) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *EUTRANAccessPointPosition) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := q4.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = q9.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.LatitudeSign), 2, false); err != nil {
		return q6.Errorf("encoding latitudeSign: %w", err)
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Latitude), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(8388607), false); err != nil {
		return q6.Errorf("encoding latitude: %w", err)
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Longitude), q8.BridgeInt64Ptr(-8388608), q8.BridgeInt64Ptr(8388607), false); err != nil {
		return q6.Errorf("encoding longitude: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.DirectionOfAltitude), 2, false); err != nil {
		return q6.Errorf("encoding directionOfAltitude: %w", err)
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Altitude), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(32767), false); err != nil {
		return q6.Errorf("encoding altitude: %w", err)
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.UncertaintySemiMajor), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(127), false); err != nil {
		return q6.Errorf("encoding uncertaintySemi-major: %w", err)
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.UncertaintySemiMinor), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(127), false); err != nil {
		return q6.Errorf("encoding uncertaintySemi-minor: %w", err)
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.OrientationOfMajorAxis), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(179), false); err != nil {
		return q6.Errorf("encoding orientationOfMajorAxis: %w", err)
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.UncertaintyAltitude), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(127), false); err != nil {
		return q6.Errorf("encoding uncertaintyAltitude: %w", err)
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Confidence), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(100), false); err != nil {
		return q6.Errorf("encoding confidence: %w", err)
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

// UnmarshalAPER decodes EUTRANAccessPointPosition from APER format.
func (v *EUTRANAccessPointPosition) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes EUTRANAccessPointPosition with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *EUTRANAccessPointPosition) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "EUTRANAccessPointPosition")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "EUTRANAccessPointPosition")
	}
	padding, err := q4.CaptureFinalBits(bb, "EUTRANAccessPointPosition")
	if err != nil {
		return q7.WrapDecodePath(err, "EUTRANAccessPointPosition")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *EUTRANAccessPointPosition) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EUTRANAccessPointPosition{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_latitudesign, err := q4.DecodeEnumeratedAligned(bb, 2, false, q4.EnumerationSource{KnownExtensions: 0, Path: "LatitudeSign"})
	if err != nil {
		return q7.WrapDecodePath(err, "LatitudeSign")
	}
	v.LatitudeSign = val_latitudesign
	val_latitude, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(8388607), false)
	if err != nil {
		return q7.WrapDecodePath(err, "Latitude")
	}
	v.Latitude = val_latitude
	val_longitude, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(-8388608), q8.BridgeInt64Ptr(8388607), false)
	if err != nil {
		return q7.WrapDecodePath(err, "Longitude")
	}
	v.Longitude = val_longitude
	val_directionofaltitude, err := q4.DecodeEnumeratedAligned(bb, 2, false, q4.EnumerationSource{KnownExtensions: 0, Path: "DirectionOfAltitude"})
	if err != nil {
		return q7.WrapDecodePath(err, "DirectionOfAltitude")
	}
	v.DirectionOfAltitude = val_directionofaltitude
	val_altitude, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(32767), false)
	if err != nil {
		return q7.WrapDecodePath(err, "Altitude")
	}
	v.Altitude = val_altitude
	val_uncertaintysemimajor, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(127), false)
	if err != nil {
		return q7.WrapDecodePath(err, "UncertaintySemiMajor")
	}
	v.UncertaintySemiMajor = val_uncertaintysemimajor
	val_uncertaintysemiminor, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(127), false)
	if err != nil {
		return q7.WrapDecodePath(err, "UncertaintySemiMinor")
	}
	v.UncertaintySemiMinor = val_uncertaintysemiminor
	val_orientationofmajoraxis, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(179), false)
	if err != nil {
		return q7.WrapDecodePath(err, "OrientationOfMajorAxis")
	}
	v.OrientationOfMajorAxis = val_orientationofmajoraxis
	val_uncertaintyaltitude, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(127), false)
	if err != nil {
		return q7.WrapDecodePath(err, "UncertaintyAltitude")
	}
	v.UncertaintyAltitude = val_uncertaintyaltitude
	val_confidence, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(100), false)
	if err != nil {
		return q7.WrapDecodePath(err, "Confidence")
	}
	v.Confidence = val_confidence
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
				opaque, err := q4.DecodeOpaqueOpenTypeAligned(bb, q4.UnknownSelector, q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
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
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// MarshalAPER encodes InterRATMeasurementQuantitiesItem to APER format.
func (v *InterRATMeasurementQuantitiesItem) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *InterRATMeasurementQuantitiesItem) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := q4.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = q9.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	// Preamble bitmap for optional root fields
	if err := q4.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.InterRATMeasurementQuantitiesValue), 2, true); err != nil {
		return q6.Errorf("encoding interRATMeasurementQuantitiesValue: %w", err)
	}
	if v.IEExtensions != nil {
		if err := q4.EncodeCollection(bb, int64(len(v.IEExtensions)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q8.BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return q6.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return q6.Errorf("encoding iE-Extensions: %w", err)
		}
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

// UnmarshalAPER decodes InterRATMeasurementQuantitiesItem from APER format.
func (v *InterRATMeasurementQuantitiesItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes InterRATMeasurementQuantitiesItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *InterRATMeasurementQuantitiesItem) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "InterRATMeasurementQuantitiesItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "InterRATMeasurementQuantitiesItem")
	}
	padding, err := q4.CaptureFinalBits(bb, "InterRATMeasurementQuantitiesItem")
	if err != nil {
		return q7.WrapDecodePath(err, "InterRATMeasurementQuantitiesItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *InterRATMeasurementQuantitiesItem) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InterRATMeasurementQuantitiesItem{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_interratmeasurementquantitiesvalue, err := q4.DecodeEnumeratedAligned(bb, 2, true, q4.EnumerationSource{KnownExtensions: 1, Path: "InterRATMeasurementQuantitiesValue"})
	if err != nil {
		return q7.WrapDecodePath(err, "InterRATMeasurementQuantitiesValue")
	}
	v.InterRATMeasurementQuantitiesValue = q5.InterRATMeasurementQuantitiesValue(val_interratmeasurementquantitiesvalue)
	if opt_ieextensions {
		tmp_ieextensions := make(q8.InterRATMeasurementQuantitiesValueExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q8.InterRATMeasurementQuantitiesValueExtIEsExtField
				if err := q8.BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				if next, err := q4.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return q7.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
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
				opaque, err := q4.DecodeOpaqueOpenTypeAligned(bb, q4.UnknownSelector, q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
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
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// MarshalAPER encodes MeasurementQuantitiesItem to APER format.
func (v *MeasurementQuantitiesItem) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *MeasurementQuantitiesItem) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := q4.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = q9.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	// Preamble bitmap for optional root fields
	if err := q4.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.MeasurementQuantitiesValue), 6, true); err != nil {
		return q6.Errorf("encoding measurementQuantitiesValue: %w", err)
	}
	if v.IEExtensions != nil {
		if err := q4.EncodeCollection(bb, int64(len(v.IEExtensions)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q10.BridgeMeasurementQuantitiesValueExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return q6.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return q6.Errorf("encoding iE-Extensions: %w", err)
		}
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

// UnmarshalAPER decodes MeasurementQuantitiesItem from APER format.
func (v *MeasurementQuantitiesItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MeasurementQuantitiesItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MeasurementQuantitiesItem) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "MeasurementQuantitiesItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "MeasurementQuantitiesItem")
	}
	padding, err := q4.CaptureFinalBits(bb, "MeasurementQuantitiesItem")
	if err != nil {
		return q7.WrapDecodePath(err, "MeasurementQuantitiesItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *MeasurementQuantitiesItem) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MeasurementQuantitiesItem{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_measurementquantitiesvalue, err := q4.DecodeEnumeratedAligned(bb, 6, true, q4.EnumerationSource{KnownExtensions: 0, Path: "MeasurementQuantitiesValue"})
	if err != nil {
		return q7.WrapDecodePath(err, "MeasurementQuantitiesValue")
	}
	v.MeasurementQuantitiesValue = q5.MeasurementQuantitiesValue(val_measurementquantitiesvalue)
	if opt_ieextensions {
		tmp_ieextensions := make(q10.MeasurementQuantitiesValueExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q10.MeasurementQuantitiesValueExtIEsExtField
				if err := q10.BridgeMeasurementQuantitiesValueExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				if next, err := q4.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return q7.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
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
				opaque, err := q4.DecodeOpaqueOpenTypeAligned(bb, q4.UnknownSelector, q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
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
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *EUTRANAccessPointPosition) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q9.BridgeReceivedFormAt(v.received, v.receivedBytes, "EUTRANAccessPointPosition", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v EUTRANAccessPointPosition) WithoutReplay() EUTRANAccessPointPosition {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero EUTRANAccessPointPosition
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *InterRATMeasurementQuantitiesItem) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q9.BridgeReceivedFormAt(v.received, v.receivedBytes, "InterRATMeasurementQuantitiesItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InterRATMeasurementQuantitiesItem) WithoutReplay() InterRATMeasurementQuantitiesItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero InterRATMeasurementQuantitiesItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MeasurementQuantitiesItem) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q9.BridgeReceivedFormAt(v.received, v.receivedBytes, "MeasurementQuantitiesItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MeasurementQuantitiesItem) WithoutReplay() MeasurementQuantitiesItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero MeasurementQuantitiesItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *EUTRANAccessPointPosition) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *EUTRANAccessPointPosition) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("EUTRANAccessPointPosition.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("EUTRANAccessPointPosition.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *EUTRANAccessPointPosition) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("EUTRANAccessPointPosition.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("EUTRANAccessPointPosition.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *InterRATMeasurementQuantitiesItem) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *InterRATMeasurementQuantitiesItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("InterRATMeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("InterRATMeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *InterRATMeasurementQuantitiesItem) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("InterRATMeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("InterRATMeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *MeasurementQuantitiesItem) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *MeasurementQuantitiesItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("MeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("MeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *MeasurementQuantitiesItem) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("MeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("MeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *EUTRANAccessPointPosition) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "EUTRANAccessPointPosition")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "EUTRANAccessPointPosition")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaEUTRANAccessPointPosition(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "EUTRANAccessPointPosition")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "EUTRANAccessPointPosition")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "EUTRANAccessPointPosition")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "EUTRANAccessPointPosition")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "EUTRANAccessPointPosition")
}
func (v *EUTRANAccessPointPosition) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *EUTRANAccessPointPosition) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *EUTRANAccessPointPosition) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaEUTRANAccessPointPosition(v, &s)
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
func (v *EUTRANAccessPointPosition) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *EUTRANAccessPointPosition) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *InterRATMeasurementQuantitiesItem) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "InterRATMeasurementQuantitiesItem")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "InterRATMeasurementQuantitiesItem")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaInterRATMeasurementQuantitiesItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "InterRATMeasurementQuantitiesItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "InterRATMeasurementQuantitiesItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "InterRATMeasurementQuantitiesItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "InterRATMeasurementQuantitiesItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "InterRATMeasurementQuantitiesItem")
}
func (v *InterRATMeasurementQuantitiesItem) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *InterRATMeasurementQuantitiesItem) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *InterRATMeasurementQuantitiesItem) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaInterRATMeasurementQuantitiesItem(v, &s)
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
func (v *InterRATMeasurementQuantitiesItem) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *InterRATMeasurementQuantitiesItem) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *MeasurementQuantitiesItem) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "MeasurementQuantitiesItem")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "MeasurementQuantitiesItem")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaMeasurementQuantitiesItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "MeasurementQuantitiesItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "MeasurementQuantitiesItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "MeasurementQuantitiesItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "MeasurementQuantitiesItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "MeasurementQuantitiesItem")
}
func (v *MeasurementQuantitiesItem) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *MeasurementQuantitiesItem) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *MeasurementQuantitiesItem) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaMeasurementQuantitiesItem(v, &s)
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
func (v *MeasurementQuantitiesItem) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *MeasurementQuantitiesItem) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *EUTRANAccessPointPosition) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "EUTRANAccessPointPosition")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded EUTRANAccessPointPosition
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaEUTRANAccessPointPosition(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = EUTRANAccessPointPosition{}
		return report, q4.OperationError(err, "EUTRANAccessPointPosition")
	}
	*v = decoded
	return report, q4.OperationError(nil, "EUTRANAccessPointPosition")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *InterRATMeasurementQuantitiesItem) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "InterRATMeasurementQuantitiesItem")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded InterRATMeasurementQuantitiesItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaInterRATMeasurementQuantitiesItem(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = InterRATMeasurementQuantitiesItem{}
		return report, q4.OperationError(err, "InterRATMeasurementQuantitiesItem")
	}
	*v = decoded
	return report, q4.OperationError(nil, "InterRATMeasurementQuantitiesItem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *MeasurementQuantitiesItem) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "MeasurementQuantitiesItem")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded MeasurementQuantitiesItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaMeasurementQuantitiesItem(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = MeasurementQuantitiesItem{}
		return report, q4.OperationError(err, "MeasurementQuantitiesItem")
	}
	*v = decoded
	return report, q4.OperationError(nil, "MeasurementQuantitiesItem")
}

// ECIDMeasurementTerminationCommand represents the ASN.1 type E-CIDMeasurementTerminationCommand (SEQUENCE).
type ECIDMeasurementTerminationCommand struct {
	replay           q4.Snapshot
	stream           q4.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    q4.WireSpan
	ProtocolIEs      q8.ECIDMeasurementTerminationCommandIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                            `asn1:"-" json:"-"`
	extCount         int64                                           `asn1:"-" json:"-"`
	extPresent       []bool                                          `asn1:"-" json:"-"`
	extData          [][]byte                                        `asn1:"-" json:"-"`
	perPadding       q4.FinalPadding                                 `asn1:"-" json:"-"`
	perExtPadding    []q4.CompletePadding                            `asn1:"-" json:"-"`
	extOrigin        []q4.OpaqueOrigin
	extWire          []q4.WireSpan
}

// MarshalAPER encodes ECIDMeasurementTerminationCommand to APER format.
func (v *ECIDMeasurementTerminationCommand) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ECIDMeasurementTerminationCommand) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = q9.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
			if err := q8.BridgeECIDMeasurementTerminationCommandIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ECIDMeasurementTerminationCommand from APER format.
func (v *ECIDMeasurementTerminationCommand) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ECIDMeasurementTerminationCommand with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ECIDMeasurementTerminationCommand) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "ECIDMeasurementTerminationCommand")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "ECIDMeasurementTerminationCommand")
	}
	padding, err := q4.CaptureFinalBits(bb, "ECIDMeasurementTerminationCommand")
	if err != nil {
		return q7.WrapDecodePath(err, "ECIDMeasurementTerminationCommand")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ECIDMeasurementTerminationCommand) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementTerminationCommand{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(q8.ECIDMeasurementTerminationCommandIEContainer, 0)
	_, errCollection_protocolies := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem q8.ECIDMeasurementTerminationCommandIEField
			if err := q8.BridgeECIDMeasurementTerminationCommandIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ECIDMeasurementTerminationCommand) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q9.BridgeReceivedFormAt(v.received, v.receivedBytes, "ECIDMeasurementTerminationCommand", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ECIDMeasurementTerminationCommand) WithoutReplay() ECIDMeasurementTerminationCommand {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero ECIDMeasurementTerminationCommand
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ECIDMeasurementTerminationCommand) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ECIDMeasurementTerminationCommand) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ECIDMeasurementTerminationCommand.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ECIDMeasurementTerminationCommand.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ECIDMeasurementTerminationCommand) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ECIDMeasurementTerminationCommand.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ECIDMeasurementTerminationCommand.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *ECIDMeasurementTerminationCommand) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "ECIDMeasurementTerminationCommand")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "ECIDMeasurementTerminationCommand")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaECIDMeasurementTerminationCommand(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "ECIDMeasurementTerminationCommand")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "ECIDMeasurementTerminationCommand")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "ECIDMeasurementTerminationCommand")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "ECIDMeasurementTerminationCommand")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "ECIDMeasurementTerminationCommand")
}
func (v *ECIDMeasurementTerminationCommand) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ECIDMeasurementTerminationCommand) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ECIDMeasurementTerminationCommand) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaECIDMeasurementTerminationCommand(v, &s)
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
func (v *ECIDMeasurementTerminationCommand) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ECIDMeasurementTerminationCommand) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ECIDMeasurementTerminationCommand) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "ECIDMeasurementTerminationCommand")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded ECIDMeasurementTerminationCommand
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaECIDMeasurementTerminationCommand(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = ECIDMeasurementTerminationCommand{}
		return report, q4.OperationError(err, "ECIDMeasurementTerminationCommand")
	}
	*v = decoded
	return report, q4.OperationError(nil, "ECIDMeasurementTerminationCommand")
}
func BridgeCaptureLPPaECIDMeasurementFailureIndicationIEValue(v *ECIDMeasurementFailureIndicationIEValue, s *q4.SemanticCapture) {
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
		case q5.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowESMLCUEMeasurementID == nil)
				if v.rowESMLCUEMeasurementID != nil {
					q5.BridgeCaptureLPPaMeasurementID(v.rowESMLCUEMeasurementID, s)
				}
				s.End(f, nil, false)
			}
		case q5.ProtocolIEID(6):
			{
				f := s.Begin()
				s.Bool(v.rowENBUEMeasurementID == nil)
				if v.rowENBUEMeasurementID != nil {
					q5.BridgeCaptureLPPaMeasurementID(v.rowENBUEMeasurementID, s)
				}
				s.End(f, nil, false)
			}
		case q5.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					q9.BridgeCaptureLPPaCause(v.rowCause, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ECIDMeasurementFailureIndicationIEValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v ECIDMeasurementFailureIndicationIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ECIDMeasurementFailureIndicationIEValue) captureSemantics(s q4.SemanticCapture) ECIDMeasurementFailureIndicationIEValue {
	BridgeCaptureLPPaECIDMeasurementFailureIndicationIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaECIDMeasurementFailureIndicationIEValue(v *ECIDMeasurementFailureIndicationIEValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q11.BridgeCompareLPPaProtocolIEID(&v.id, s)
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
		case q5.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowESMLCUEMeasurementID == nil)
				if v.rowESMLCUEMeasurementID != nil {
					q11.BridgeCompareLPPaMeasurementID(v.rowESMLCUEMeasurementID, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(6):
			{
				f := s.Begin()
				s.Bool(v.rowENBUEMeasurementID == nil)
				if v.rowENBUEMeasurementID != nil {
					q11.BridgeCompareLPPaMeasurementID(v.rowENBUEMeasurementID, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					q9.BridgeCompareLPPaCause(v.rowCause, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v ECIDMeasurementFailureIndicationIEValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaECIDMeasurementFailureIndicationIEValue(&v, &s)
	return s
}
func (v ECIDMeasurementFailureIndicationIEValue) WithoutReplay() ECIDMeasurementFailureIndicationIEValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCaptureLPPaECIDMeasurementTerminationCommand(v *ECIDMeasurementTerminationCommand, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q10.BridgeECIDMeasurementTerminationCommandIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaECIDMeasurementTerminationCommand(v *ECIDMeasurementTerminationCommand, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q10.BridgeECIDMeasurementTerminationCommandIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaEUTRANAccessPointPosition(v *EUTRANAccessPointPosition, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s.Int(int64(v.LatitudeSign))
	s.Int(int64(v.Latitude))
	s.Int(int64(v.Longitude))
	s.Int(int64(v.DirectionOfAltitude))
	s.Int(int64(v.Altitude))
	s.Int(int64(v.UncertaintySemiMajor))
	s.Int(int64(v.UncertaintySemiMinor))
	s.Int(int64(v.OrientationOfMajorAxis))
	s.Int(int64(v.UncertaintyAltitude))
	s.Int(int64(v.Confidence))
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaEUTRANAccessPointPosition(v *EUTRANAccessPointPosition, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

	s.Int(int64(v.LatitudeSign))
	s.Int(int64(v.Latitude))
	s.Int(int64(v.Longitude))
	s.Int(int64(v.DirectionOfAltitude))
	s.Int(int64(v.Altitude))
	s.Int(int64(v.UncertaintySemiMajor))
	s.Int(int64(v.UncertaintySemiMinor))
	s.Int(int64(v.OrientationOfMajorAxis))
	s.Int(int64(v.UncertaintyAltitude))
	s.Int(int64(v.Confidence))
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaInterRATMeasurementQuantitiesItem(v *InterRATMeasurementQuantitiesItem, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q5.BridgeCaptureLPPaInterRATMeasurementQuantitiesValue(&v.InterRATMeasurementQuantitiesValue, s)
	s.Bool(v.IEExtensions == nil)
	q10.BridgeInterRATMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaInterRATMeasurementQuantitiesItem(v *InterRATMeasurementQuantitiesItem, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q11.BridgeCompareLPPaInterRATMeasurementQuantitiesValue(&v.InterRATMeasurementQuantitiesValue, s)
	s.Bool(v.IEExtensions == nil)
	q10.BridgeInterRATMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaInterRATMeasurementQuantitiesItemIEValue(v *InterRATMeasurementQuantitiesItemIEValue, s *q4.SemanticCapture) {
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
		case q5.ProtocolIEID(16):
			{
				f := s.Begin()
				s.Bool(v.rowInterRATMeasurementQuantitiesItem == nil)
				if v.rowInterRATMeasurementQuantitiesItem != nil {
					BridgeCaptureLPPaInterRATMeasurementQuantitiesItem(v.rowInterRATMeasurementQuantitiesItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v InterRATMeasurementQuantitiesItemIEValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v InterRATMeasurementQuantitiesItemIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v InterRATMeasurementQuantitiesItemIEValue) captureSemantics(s q4.SemanticCapture) InterRATMeasurementQuantitiesItemIEValue {
	BridgeCaptureLPPaInterRATMeasurementQuantitiesItemIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaInterRATMeasurementQuantitiesItemIEValue(v *InterRATMeasurementQuantitiesItemIEValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q11.BridgeCompareLPPaProtocolIEID(&v.id, s)
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
		case q5.ProtocolIEID(16):
			{
				f := s.Begin()
				s.Bool(v.rowInterRATMeasurementQuantitiesItem == nil)
				if v.rowInterRATMeasurementQuantitiesItem != nil {
					BridgeCompareLPPaInterRATMeasurementQuantitiesItem(v.rowInterRATMeasurementQuantitiesItem, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v InterRATMeasurementQuantitiesItemIEValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaInterRATMeasurementQuantitiesItemIEValue(&v, &s)
	return s
}
func (v InterRATMeasurementQuantitiesItemIEValue) WithoutReplay() InterRATMeasurementQuantitiesItemIEValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCaptureLPPaMeasurementQuantitiesItem(v *MeasurementQuantitiesItem, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q5.BridgeCaptureLPPaMeasurementQuantitiesValue(&v.MeasurementQuantitiesValue, s)
	s.Bool(v.IEExtensions == nil)
	q10.BridgeMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaMeasurementQuantitiesItem(v *MeasurementQuantitiesItem, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q11.BridgeCompareLPPaMeasurementQuantitiesValue(&v.MeasurementQuantitiesValue, s)
	s.Bool(v.IEExtensions == nil)
	q9.BridgeMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaMeasurementQuantitiesItemIEValue(v *MeasurementQuantitiesItemIEValue, s *q4.SemanticCapture) {
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
		case q5.ProtocolIEID(11):
			{
				f := s.Begin()
				s.Bool(v.rowMeasurementQuantitiesItem == nil)
				if v.rowMeasurementQuantitiesItem != nil {
					BridgeCaptureLPPaMeasurementQuantitiesItem(v.rowMeasurementQuantitiesItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v MeasurementQuantitiesItemIEValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v MeasurementQuantitiesItemIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v MeasurementQuantitiesItemIEValue) captureSemantics(s q4.SemanticCapture) MeasurementQuantitiesItemIEValue {
	BridgeCaptureLPPaMeasurementQuantitiesItemIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaMeasurementQuantitiesItemIEValue(v *MeasurementQuantitiesItemIEValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q11.BridgeCompareLPPaProtocolIEID(&v.id, s)
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
		case q5.ProtocolIEID(11):
			{
				f := s.Begin()
				s.Bool(v.rowMeasurementQuantitiesItem == nil)
				if v.rowMeasurementQuantitiesItem != nil {
					BridgeCompareLPPaMeasurementQuantitiesItem(v.rowMeasurementQuantitiesItem, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v MeasurementQuantitiesItemIEValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaMeasurementQuantitiesItemIEValue(&v, &s)
	return s
}
func (v MeasurementQuantitiesItemIEValue) WithoutReplay() MeasurementQuantitiesItemIEValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}

type InterRATMeasurementQuantitiesItemIEValue struct {
	id                                   q5.ProtocolIEID
	withoutReplay                        bool
	received                             q4.WireSpan
	replay                               q4.Snapshot
	opaque                               *q4.OpaqueOpenType
	isOpaque                             bool
	rowInterRATMeasurementQuantitiesItem *InterRATMeasurementQuantitiesItem
}

func (v InterRATMeasurementQuantitiesItemIEValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q5.ProtocolIEID(16):
		return v.rowInterRATMeasurementQuantitiesItem != nil
	default:
		return false
	}
}
func (v *InterRATMeasurementQuantitiesItemIEValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (InterRATMeasurementQuantitiesItemIEValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "InterRATMeasurementQuantities-ItemIEs"}}
}
func (InterRATMeasurementQuantitiesItemIEValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(16):
		return q4.UnknownSelector
	case q5.ProtocolIEID(0):
		return q4.NotInTable
	case q5.ProtocolIEID(1):
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
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v *InterRATMeasurementQuantitiesItemIEValue) AsInterRATMeasurementQuantitiesItem() (*InterRATMeasurementQuantitiesItem, bool) {
	if v == nil || v.id != q5.ProtocolIEID(16) || v.rowInterRATMeasurementQuantitiesItem == nil {
		return nil, false
	}
	return v.rowInterRATMeasurementQuantitiesItem, true
}
func (v InterRATMeasurementQuantitiesItemIEValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (InterRATMeasurementQuantitiesItemIEValue, error) {
	out := InterRATMeasurementQuantitiesItemIEValue{id: id}
	var scope *q4.BitBuffer
	switch id {
	case 16:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q5.ProtocolIEID(16):
		replayUsage := scope.Usage()
		var value InterRATMeasurementQuantitiesItem
		child := raw.ChildDecodeBuffer()
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, q6.Errorf("%s %w", "InterRATMeasurementQuantitiesItem:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "InterRATMeasurementQuantitiesItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowInterRATMeasurementQuantitiesItem = &value
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
func (v InterRATMeasurementQuantitiesItemIEValue) encode() ([]byte, error) {
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v InterRATMeasurementQuantitiesItemIEValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
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
	case q5.ProtocolIEID(16):
		if v.rowInterRATMeasurementQuantitiesItem == nil {
			return nil, q6.Errorf("%s missing value", "InterRATMeasurementQuantities-ItemIEs.id-InterRATMeasurementQuantities-Item:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := v.rowInterRATMeasurementQuantitiesItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, q6.Errorf("%s id %d has no value", "InterRATMeasurementQuantitiesItemIEValue:", v.id)
	}
}

type MeasurementQuantitiesItemIEValue struct {
	id                           q5.ProtocolIEID
	withoutReplay                bool
	received                     q4.WireSpan
	replay                       q4.Snapshot
	opaque                       *q4.OpaqueOpenType
	isOpaque                     bool
	rowMeasurementQuantitiesItem *MeasurementQuantitiesItem
}

func (v MeasurementQuantitiesItemIEValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q5.ProtocolIEID(11):
		return v.rowMeasurementQuantitiesItem != nil
	default:
		return false
	}
}
func (v *MeasurementQuantitiesItemIEValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (MeasurementQuantitiesItemIEValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementQuantities-ItemIEs"}}
}
func (MeasurementQuantitiesItemIEValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(11):
		return q4.UnknownSelector
	case q5.ProtocolIEID(0):
		return q4.NotInTable
	case q5.ProtocolIEID(1):
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
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v *MeasurementQuantitiesItemIEValue) AsMeasurementQuantitiesItem() (*MeasurementQuantitiesItem, bool) {
	if v == nil || v.id != q5.ProtocolIEID(11) || v.rowMeasurementQuantitiesItem == nil {
		return nil, false
	}
	return v.rowMeasurementQuantitiesItem, true
}
func (v MeasurementQuantitiesItemIEValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (MeasurementQuantitiesItemIEValue, error) {
	out := MeasurementQuantitiesItemIEValue{id: id}
	var scope *q4.BitBuffer
	switch id {
	case 11:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q5.ProtocolIEID(11):
		replayUsage := scope.Usage()
		var value MeasurementQuantitiesItem
		child := raw.ChildDecodeBuffer()
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, q6.Errorf("%s %w", "MeasurementQuantitiesItem:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "MeasurementQuantitiesItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowMeasurementQuantitiesItem = &value
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
func (v MeasurementQuantitiesItemIEValue) encode() ([]byte, error) {
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v MeasurementQuantitiesItemIEValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
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
	case q5.ProtocolIEID(11):
		if v.rowMeasurementQuantitiesItem == nil {
			return nil, q6.Errorf("%s missing value", "MeasurementQuantities-ItemIEs.id-MeasurementQuantities-Item:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := v.rowMeasurementQuantitiesItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, q6.Errorf("%s id %d has no value", "MeasurementQuantitiesItemIEValue:", v.id)
	}
}

type ECIDMeasurementFailureIndicationIEValue struct {
	id                      q5.ProtocolIEID
	withoutReplay           bool
	received                q4.WireSpan
	replay                  q4.Snapshot
	opaque                  *q4.OpaqueOpenType
	isOpaque                bool
	rowESMLCUEMeasurementID *q5.MeasurementID
	rowENBUEMeasurementID   *q5.MeasurementID
	rowCause                *q9.Cause
}

func (v ECIDMeasurementFailureIndicationIEValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q5.ProtocolIEID(2):
		return v.rowESMLCUEMeasurementID != nil
	case q5.ProtocolIEID(6):
		return v.rowENBUEMeasurementID != nil
	case q5.ProtocolIEID(0):
		return v.rowCause != nil
	default:
		return false
	}
}
func (v *ECIDMeasurementFailureIndicationIEValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ECIDMeasurementFailureIndicationIEValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementFailureIndication-IEs"}}
}
func (ECIDMeasurementFailureIndicationIEValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(2):
		return q4.UnknownSelector
	case q5.ProtocolIEID(6):
		return q4.UnknownSelector
	case q5.ProtocolIEID(0):
		return q4.UnknownSelector
	case q5.ProtocolIEID(1):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
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
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v *ECIDMeasurementFailureIndicationIEValue) AsESMLCUEMeasurementID() (*q5.MeasurementID, bool) {
	if v == nil || v.id != q5.ProtocolIEID(2) || v.rowESMLCUEMeasurementID == nil {
		return nil, false
	}
	return v.rowESMLCUEMeasurementID, true
}
func (v *ECIDMeasurementFailureIndicationIEValue) AsENBUEMeasurementID() (*q5.MeasurementID, bool) {
	if v == nil || v.id != q5.ProtocolIEID(6) || v.rowENBUEMeasurementID == nil {
		return nil, false
	}
	return v.rowENBUEMeasurementID, true
}
func (v *ECIDMeasurementFailureIndicationIEValue) AsCause() (*q9.Cause, bool) {
	if v == nil || v.id != q5.ProtocolIEID(0) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v ECIDMeasurementFailureIndicationIEValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (ECIDMeasurementFailureIndicationIEValue, error) {
	out := ECIDMeasurementFailureIndicationIEValue{id: id}
	var scope *q4.BitBuffer
	switch id {
	case 2, 6, 0:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q5.ProtocolIEID(2):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound2, q5.BridgeAsn1IntegerBound7, true)
		value := q5.MeasurementID(decoded)
		if err != nil {
			return out, q6.Errorf("%s %w", "ESMLCUEMeasurementID:", err)
		}
		if _, err := q4.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowESMLCUEMeasurementID = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q5.ProtocolIEID(6):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound2, q5.BridgeAsn1IntegerBound7, true)
		value := q5.MeasurementID(decoded)
		if err != nil {
			return out, q6.Errorf("%s %w", "ENBUEMeasurementID:", err)
		}
		if _, err := q4.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowENBUEMeasurementID = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q5.ProtocolIEID(0):
		replayUsage := scope.Usage()
		var value q9.Cause
		child := raw.ChildDecodeBuffer()
		if err := q9.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, q6.Errorf("%s %w", "Cause:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*q9.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*q9.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(q9.BridgeCauseFieldReceivedBytes(&value))
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCause = &value
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
func (v ECIDMeasurementFailureIndicationIEValue) encode() ([]byte, error) {
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ECIDMeasurementFailureIndicationIEValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
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
	case q5.ProtocolIEID(2):
		if v.rowESMLCUEMeasurementID == nil {
			return nil, q6.Errorf("%s missing value", "E-CIDMeasurementFailureIndication-IEs.id-E-SMLC-UE-Measurement-ID:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := q4.NewBudgetBuffer(budget)
		if err := q4.EncodeIntegerBigBoundsAligned(encodeBB, *v.rowESMLCUEMeasurementID, q5.BridgeAsn1IntegerBound2, q5.BridgeAsn1IntegerBound7, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case q5.ProtocolIEID(6):
		if v.rowENBUEMeasurementID == nil {
			return nil, q6.Errorf("%s missing value", "E-CIDMeasurementFailureIndication-IEs.id-eNB-UE-Measurement-ID:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := q4.NewBudgetBuffer(budget)
		if err := q4.EncodeIntegerBigBoundsAligned(encodeBB, *v.rowENBUEMeasurementID, q5.BridgeAsn1IntegerBound2, q5.BridgeAsn1IntegerBound7, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case q5.ProtocolIEID(0):
		if v.rowCause == nil {
			return nil, q6.Errorf("%s missing value", "E-CIDMeasurementFailureIndication-IEs.id-Cause:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := q9.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, q6.Errorf("%s id %d has no value", "ECIDMeasurementFailureIndicationIEValue:", v.id)
	}
}

type InterRATMeasurementQuantitiesItemIETable struct{}

func InterRATMeasurementQuantitiesItemIEs() InterRATMeasurementQuantitiesItemIETable {
	return InterRATMeasurementQuantitiesItemIETable{}
}
func (InterRATMeasurementQuantitiesItemIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "InterRATMeasurementQuantities-ItemIEs"}
		return sealed
	}()
}
func (InterRATMeasurementQuantitiesItemIETable) infoInterRATMeasurementQuantitiesItem() q5.FieldInfo {
	return q5.FieldInfo{Table: InterRATMeasurementQuantitiesItemIEs().ID(), ID: q5.ProtocolIEID(16), Criticality: q5.CriticalityReject, Presence: q5.PresenceMandatory, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "InterRATMeasurementQuantitiesItem"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "InterRATMeasurementQuantities-ItemIEs", Row: "id-InterRATMeasurementQuantities-Item"}}}
}
func (t InterRATMeasurementQuantitiesItemIETable) InterRATMeasurementQuantitiesItem() InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding {
	return InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding{info: t.infoInterRATMeasurementQuantitiesItem(), codec: InterRATMeasurementQuantitiesItemValueCodec{path: "InterRATMeasurementQuantitiesItem",
		decode: func(data []byte, options q4.DecodeState) (InterRATMeasurementQuantitiesItem, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty InterRATMeasurementQuantitiesItem
				return empty, err
			}
			var zero InterRATMeasurementQuantitiesItemIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(16), raw)
			if err != nil {
				var empty InterRATMeasurementQuantitiesItem
				return empty, err
			}
			value, ok := decoded.AsInterRATMeasurementQuantitiesItem()
			if !ok {
				var empty InterRATMeasurementQuantitiesItem
				return empty, q6.Errorf("binding InterRATMeasurementQuantities-ItemIEs.id-InterRATMeasurementQuantities-Item: no selected value")
			}
			return *value, nil
		},
		encode: func(value InterRATMeasurementQuantitiesItem, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (InterRATMeasurementQuantitiesItemIEValue{id: q5.ProtocolIEID(16), rowInterRATMeasurementQuantitiesItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v InterRATMeasurementQuantitiesItem, options q4.DecodeState) (InterRATMeasurementQuantitiesItem, q4.Snapshot,
		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureLPPaInterRATMeasurementQuantitiesItem(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}, compare: func(v InterRATMeasurementQuantitiesItem, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaInterRATMeasurementQuantitiesItem(&v, &s)
			s.End(f, root,

				false)
			return s.Plan()
		}, context: func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:InterRATMeasurementQuantitiesItem"
			return sealed
		}(),
	}, inject: func(value InterRATMeasurementQuantitiesItem) InterRATMeasurementQuantitiesItemIEValue {
		return InterRATMeasurementQuantitiesItemIEValue{id: q5.ProtocolIEID(16), rowInterRATMeasurementQuantitiesItem: &value}
	}, get: func(value *InterRATMeasurementQuantitiesItemIEValue) (*InterRATMeasurementQuantitiesItem, bool) {
		return value.AsInterRATMeasurementQuantitiesItem()
	}}
}
func (t InterRATMeasurementQuantitiesItemIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (InterRATMeasurementQuantitiesItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return InterRATMeasurementQuantitiesItemIEField{}, q4.OperationError(q6.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q5.ProtocolIEID(16):
		return InterRATMeasurementQuantitiesItemIEField{}, q4.OperationError(q6.Errorf("known IE id-InterRATMeasurementQuantities-Item requires its typed binding"), "Opaque")
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return InterRATMeasurementQuantitiesItemIEField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return InterRATMeasurementQuantitiesItemIEField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return InterRATMeasurementQuantitiesItemIEField{}, q4.OperationError(err, "Opaque")
		}
		return InterRATMeasurementQuantitiesItemIEField{Id: id, Criticality: criticality, Value: InterRATMeasurementQuantitiesItemIEValue{id: id, opaque: retained, isOpaque: true}}, q4.OperationError(nil, "Opaque")
	}
}

type ECIDMeasurementFailureIndicationIETable struct{}

func ECIDMeasurementFailureIndicationIEs() ECIDMeasurementFailureIndicationIETable {
	return ECIDMeasurementFailureIndicationIETable{}
}
func (ECIDMeasurementFailureIndicationIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementFailureIndication-IEs"}
		return sealed
	}()
}
func (ECIDMeasurementFailureIndicationIETable) infoESMLCUEMeasurementID() q5.FieldInfo {
	return q5.FieldInfo{Table: ECIDMeasurementFailureIndicationIEs().ID(), ID: q5.ProtocolIEID(2), Criticality: q5.CriticalityReject, Presence: q5.PresenceMandatory, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementFailureIndication-IEs", Row: "id-E-SMLC-UE-Measurement-ID"}}}
}
func (t ECIDMeasurementFailureIndicationIETable) ESMLCUEMeasurementID() ECIDMeasurementFailureIndicationMeasurementIDIEBinding {
	return ECIDMeasurementFailureIndicationMeasurementIDIEBinding{info: t.infoESMLCUEMeasurementID(), codec: func() q5.MeasurementIDValueCodec {
		sealed := q5.MeasurementIDValueCodec{}
		*q5.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*q5.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.MeasurementID, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q5.MeasurementID
				return empty, err
			}
			var zero ECIDMeasurementFailureIndicationIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(2), raw)
			if err != nil {
				var empty q5.MeasurementID
				return empty, err
			}
			value, ok := decoded.AsESMLCUEMeasurementID()
			if !ok {
				var empty q5.MeasurementID
				return empty, q6.Errorf("binding E-CIDMeasurementFailureIndication-IEs.id-E-SMLC-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*q5.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value q5.MeasurementID, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementFailureIndicationIEValue{id: q5.ProtocolIEID(2), rowESMLCUEMeasurementID: &value}).encodeFresh(fresh, budget)
		}
		*q5.BridgeMeasurementIDValueCodecFieldCapture(&sealed) = func(v q5.MeasurementID, options q4.DecodeState) (q5.MeasurementID, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaMeasurementID(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q5.BridgeMeasurementIDValueCodecFieldCompare(&sealed) = func(v q5.MeasurementID, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q11.BridgeCompareLPPaMeasurementID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q5.BridgeMeasurementIDValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementID"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q5.MeasurementID) ECIDMeasurementFailureIndicationIEValue {
			return ECIDMeasurementFailureIndicationIEValue{id: q5.ProtocolIEID(2), rowESMLCUEMeasurementID: &value}
		}, get: func(value *ECIDMeasurementFailureIndicationIEValue) (*q5.MeasurementID, bool) {
			return value.AsESMLCUEMeasurementID()
		}}
}
func (ECIDMeasurementFailureIndicationIETable) infoENBUEMeasurementID() q5.FieldInfo {
	return q5.FieldInfo{Table: ECIDMeasurementFailureIndicationIEs().ID(), ID: q5.ProtocolIEID(6), Criticality: q5.CriticalityReject, Presence: q5.PresenceMandatory, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementFailureIndication-IEs", Row: "id-eNB-UE-Measurement-ID"}}}
}
func (t ECIDMeasurementFailureIndicationIETable) ENBUEMeasurementID() ECIDMeasurementFailureIndicationMeasurementIDIEBinding {
	return ECIDMeasurementFailureIndicationMeasurementIDIEBinding{info: t.infoENBUEMeasurementID(), codec: func() q5.MeasurementIDValueCodec {
		sealed := q5.MeasurementIDValueCodec{}
		*q5.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*q5.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.MeasurementID, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q5.MeasurementID
				return empty, err
			}
			var zero ECIDMeasurementFailureIndicationIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(6), raw)
			if err != nil {
				var empty q5.MeasurementID
				return empty, err
			}
			value, ok := decoded.AsENBUEMeasurementID()
			if !ok {
				var empty q5.MeasurementID
				return empty, q6.Errorf("binding E-CIDMeasurementFailureIndication-IEs.id-eNB-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*q5.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value q5.MeasurementID, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementFailureIndicationIEValue{id: q5.ProtocolIEID(6), rowENBUEMeasurementID: &value}).encodeFresh(fresh, budget)
		}
		*q5.BridgeMeasurementIDValueCodecFieldCapture(&sealed) = func(v q5.MeasurementID, options q4.DecodeState) (q5.MeasurementID, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaMeasurementID(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q5.BridgeMeasurementIDValueCodecFieldCompare(&sealed) = func(v q5.MeasurementID, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q11.BridgeCompareLPPaMeasurementID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q5.BridgeMeasurementIDValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementID"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q5.MeasurementID) ECIDMeasurementFailureIndicationIEValue {
			return ECIDMeasurementFailureIndicationIEValue{id: q5.ProtocolIEID(6), rowENBUEMeasurementID: &value}
		}, get: func(value *ECIDMeasurementFailureIndicationIEValue) (*q5.MeasurementID, bool) {
			return value.AsENBUEMeasurementID()
		}}
}
func (ECIDMeasurementFailureIndicationIETable) infoCause() q5.FieldInfo {
	return q5.FieldInfo{Table: ECIDMeasurementFailureIndicationIEs().ID(), ID: q5.ProtocolIEID(0), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceMandatory, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementFailureIndication-IEs", Row: "id-Cause"}}}
}
func (t ECIDMeasurementFailureIndicationIETable) Cause() ECIDMeasurementFailureIndicationCauseIEBinding {
	return ECIDMeasurementFailureIndicationCauseIEBinding{info: t.infoCause(), codec: func() q9.CauseValueCodec {
		sealed := q9.CauseValueCodec{}
		*q9.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*q9.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q9.Cause, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q9.Cause
				return empty, err
			}
			var zero ECIDMeasurementFailureIndicationIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(0), raw)
			if err != nil {
				var empty q9.Cause
				return empty, err
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty q9.Cause
				return empty, q6.Errorf("binding E-CIDMeasurementFailureIndication-IEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*q9.BridgeCauseValueCodecFieldEncode(&sealed) = func(value q9.Cause, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementFailureIndicationIEValue{id: q5.ProtocolIEID(0), rowCause: &value}).encodeFresh(fresh, budget)
		}
		*q9.BridgeCauseValueCodecFieldCapture(&sealed) = func(v q9.Cause, options q4.DecodeState) (q9.Cause, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q9.BridgeCaptureLPPaCause(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q9.BridgeCauseValueCodecFieldCompare(&sealed) = func(v q9.Cause, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			q9.BridgeCompareLPPaCause(&v, &s)
			s.End(
				f, root, false)
			return s.Plan()
		}
		*q9.BridgeCauseValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q9.Cause) ECIDMeasurementFailureIndicationIEValue {
			return ECIDMeasurementFailureIndicationIEValue{id: q5.ProtocolIEID(0), rowCause: &value}
		}, get: func(value *ECIDMeasurementFailureIndicationIEValue) (*q9.Cause, bool) { return value.AsCause() }}
}
func (t ECIDMeasurementFailureIndicationIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (ECIDMeasurementFailureIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ECIDMeasurementFailureIndicationIEField{}, q4.OperationError(q6.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q5.ProtocolIEID(2):
		return ECIDMeasurementFailureIndicationIEField{}, q4.OperationError(q6.Errorf("known IE id-E-SMLC-UE-Measurement-ID requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(6):
		return ECIDMeasurementFailureIndicationIEField{}, q4.OperationError(q6.Errorf("known IE id-eNB-UE-Measurement-ID requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(0):
		return ECIDMeasurementFailureIndicationIEField{}, q4.OperationError(q6.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return ECIDMeasurementFailureIndicationIEField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ECIDMeasurementFailureIndicationIEField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ECIDMeasurementFailureIndicationIEField{}, q4.OperationError(err, "Opaque")
		}
		return ECIDMeasurementFailureIndicationIEField{Id: id, Criticality: criticality, Value: ECIDMeasurementFailureIndicationIEValue{id: id, opaque: retained, isOpaque: true}}, q4.OperationError(nil, "Opaque")
	}
}

// CauseCodec binds the complete APER value type.
func CauseCodec() q9.CauseValueCodec { return ECIDMeasurementFailureIndicationIEs().Cause().Codec() }

// EUTRANAccessPointPositionCodec binds the complete source value type.
func EUTRANAccessPointPositionCodec() EUTRANAccessPointPositionValueCodec {
	return EUTRANAccessPointPositionValueCodec{path: "EUTRANAccessPointPosition", decode: func(data []byte, options q4.DecodeState) (EUTRANAccessPointPosition, error) {
		var value EUTRANAccessPointPosition
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return EUTRANAccessPointPosition{}, err
		}
		value.received = true
		value.receivedBytes = q4.OriginalWire(data)
		return value, nil
	}, encode: func(value EUTRANAccessPointPosition, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v EUTRANAccessPointPosition, options q4.DecodeState) (EUTRANAccessPointPosition, q4.Snapshot) {
		s := q4.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaEUTRANAccessPointPosition(&v, &s)
		var root q4.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v EUTRANAccessPointPosition, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
		s := q4.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaEUTRANAccessPointPosition(&v, &s)
		s.End(f, root, false)
		return s.
			Plan()
	}, context: func() q5.BridgeCodecContext {
		sealed := q5.BridgeCodecContext{}
		*q5.BridgecodecContextFieldSource(&sealed) = "source-value:EUTRANAccessPointPosition"
		return sealed
	}(),
	}
}

// InterRATMeasurementQuantitiesItemCodec binds the complete APER value type.
func InterRATMeasurementQuantitiesItemCodec() InterRATMeasurementQuantitiesItemValueCodec {
	return InterRATMeasurementQuantitiesItemIEs().InterRATMeasurementQuantitiesItem().Codec()
}

// MeasurementIDCodec binds the complete APER value type.
func MeasurementIDCodec() q5.MeasurementIDValueCodec {
	return ECIDMeasurementFailureIndicationIEs().ESMLCUEMeasurementID().Codec()
}
func BridgeECIDMeasurementFailureIndicationCauseIEBindingFieldCodec(v *ECIDMeasurementFailureIndicationCauseIEBinding) *q9.CauseValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementFailureIndicationCauseIEBindingFieldGet(v *ECIDMeasurementFailureIndicationCauseIEBinding) *func(*ECIDMeasurementFailureIndicationIEValue) (*q9.Cause, bool) {
	return &v.get
}
func BridgeECIDMeasurementFailureIndicationCauseIEBindingFieldInfo(v *ECIDMeasurementFailureIndicationCauseIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementFailureIndicationCauseIEBindingFieldInject(v *ECIDMeasurementFailureIndicationCauseIEBinding) *func(q9.Cause) ECIDMeasurementFailureIndicationIEValue {
	return &v.inject
}
func BridgeECIDMeasurementFailureIndicationIEFieldFieldReceived(v *ECIDMeasurementFailureIndicationIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeECIDMeasurementFailureIndicationIEFieldFieldReplay(v *ECIDMeasurementFailureIndicationIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementFailureIndicationIEFieldFieldStream(v *ECIDMeasurementFailureIndicationIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementFailureIndicationIEFieldFieldWithoutReplay(v *ECIDMeasurementFailureIndicationIEField) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementFailureIndicationIEFieldMethodMarshalAPERTo(v *ECIDMeasurementFailureIndicationIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementFailureIndicationIEFieldMethodUnmarshalAPERFrom(v *ECIDMeasurementFailureIndicationIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementFailureIndicationIETableMethodInfoCause(v ECIDMeasurementFailureIndicationIETable) q5.FieldInfo {
	return v.infoCause()
}
func BridgeECIDMeasurementFailureIndicationIETableMethodInfoENBUEMeasurementID(v ECIDMeasurementFailureIndicationIETable) q5.FieldInfo {
	return v.infoENBUEMeasurementID()
}
func BridgeECIDMeasurementFailureIndicationIETableMethodInfoESMLCUEMeasurementID(v ECIDMeasurementFailureIndicationIETable) q5.FieldInfo {
	return v.infoESMLCUEMeasurementID()
}
func BridgeECIDMeasurementFailureIndicationIEValueFieldId(v *ECIDMeasurementFailureIndicationIEValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeECIDMeasurementFailureIndicationIEValueFieldIsOpaque(v *ECIDMeasurementFailureIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgeECIDMeasurementFailureIndicationIEValueFieldOpaque(v *ECIDMeasurementFailureIndicationIEValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeECIDMeasurementFailureIndicationIEValueFieldReceived(v *ECIDMeasurementFailureIndicationIEValue) *q4.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementFailureIndicationIEValueFieldReplay(v *ECIDMeasurementFailureIndicationIEValue) *q4.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementFailureIndicationIEValueFieldRowCause(v *ECIDMeasurementFailureIndicationIEValue) **q9.Cause {
	return &v.rowCause
}
func BridgeECIDMeasurementFailureIndicationIEValueFieldRowENBUEMeasurementID(v *ECIDMeasurementFailureIndicationIEValue) **q5.MeasurementID {
	return &v.rowENBUEMeasurementID
}
func BridgeECIDMeasurementFailureIndicationIEValueFieldRowESMLCUEMeasurementID(v *ECIDMeasurementFailureIndicationIEValue) **q5.MeasurementID {
	return &v.rowESMLCUEMeasurementID
}
func BridgeECIDMeasurementFailureIndicationIEValueFieldWithoutReplay(v *ECIDMeasurementFailureIndicationIEValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodCaptureFraming(v ECIDMeasurementFailureIndicationIEValue) uint64 {
	return v.captureFraming()
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodCaptureSemantics(v ECIDMeasurementFailureIndicationIEValue, a0 q4.SemanticCapture) ECIDMeasurementFailureIndicationIEValue {
	return v.captureSemantics(a0)
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodCaptureSnapshot(v ECIDMeasurementFailureIndicationIEValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodCompareSemantics(v ECIDMeasurementFailureIndicationIEValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodDecode(v ECIDMeasurementFailureIndicationIEValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (ECIDMeasurementFailureIndicationIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodEncode(v ECIDMeasurementFailureIndicationIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodEncodeFresh(v ECIDMeasurementFailureIndicationIEValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodMatchesID(v ECIDMeasurementFailureIndicationIEValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodReason(v ECIDMeasurementFailureIndicationIEValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodRule(v ECIDMeasurementFailureIndicationIEValue) q4.SourceRule {
	return v.rule()
}
func BridgeECIDMeasurementFailureIndicationMeasurementIDIEBindingFieldCodec(v *ECIDMeasurementFailureIndicationMeasurementIDIEBinding) *q5.MeasurementIDValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementFailureIndicationMeasurementIDIEBindingFieldGet(v *ECIDMeasurementFailureIndicationMeasurementIDIEBinding) *func(*ECIDMeasurementFailureIndicationIEValue) (*q5.MeasurementID, bool) {
	return &v.get
}
func BridgeECIDMeasurementFailureIndicationMeasurementIDIEBindingFieldInfo(v *ECIDMeasurementFailureIndicationMeasurementIDIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementFailureIndicationMeasurementIDIEBindingFieldInject(v *ECIDMeasurementFailureIndicationMeasurementIDIEBinding) *func(q5.MeasurementID) ECIDMeasurementFailureIndicationIEValue {
	return &v.inject
}
func BridgeECIDMeasurementTerminationCommandAPERValueFieldContext(v *ECIDMeasurementTerminationCommandAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementTerminationCommandAPERValueFieldReceived(v *ECIDMeasurementTerminationCommandAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementTerminationCommandAPERValueFieldReplay(v *ECIDMeasurementTerminationCommandAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementTerminationCommandAPERValueFieldWithoutReplay(v *ECIDMeasurementTerminationCommandAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementTerminationCommandFieldExtCount(v *ECIDMeasurementTerminationCommand) *int64 {
	return &v.extCount
}
func BridgeECIDMeasurementTerminationCommandFieldExtData(v *ECIDMeasurementTerminationCommand) *[][]byte {
	return &v.extData
}
func BridgeECIDMeasurementTerminationCommandFieldExtOrigin(v *ECIDMeasurementTerminationCommand) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeECIDMeasurementTerminationCommandFieldExtPresent(v *ECIDMeasurementTerminationCommand) *[]bool {
	return &v.extPresent
}
func BridgeECIDMeasurementTerminationCommandFieldExtWire(v *ECIDMeasurementTerminationCommand) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeECIDMeasurementTerminationCommandFieldPerExtPadding(v *ECIDMeasurementTerminationCommand) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeECIDMeasurementTerminationCommandFieldPerPadding(v *ECIDMeasurementTerminationCommand) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeECIDMeasurementTerminationCommandFieldProtocolIEsIndef(v *ECIDMeasurementTerminationCommand) *bool {
	return &v.protocolIEsIndef
}
func BridgeECIDMeasurementTerminationCommandFieldReceived(v *ECIDMeasurementTerminationCommand) *bool {
	return &v.received
}
func BridgeECIDMeasurementTerminationCommandFieldReceivedBytes(v *ECIDMeasurementTerminationCommand) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeECIDMeasurementTerminationCommandFieldReplay(v *ECIDMeasurementTerminationCommand) *q4.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementTerminationCommandFieldStream(v *ECIDMeasurementTerminationCommand) *q4.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementTerminationCommandFieldWithoutReplay(v *ECIDMeasurementTerminationCommand) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementTerminationCommandMethodMarshalAPERBudget(v *ECIDMeasurementTerminationCommand, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeECIDMeasurementTerminationCommandMethodMarshalAPERChanged(v *ECIDMeasurementTerminationCommand, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeECIDMeasurementTerminationCommandMethodMarshalAPERChangedValue(v *ECIDMeasurementTerminationCommand, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeECIDMeasurementTerminationCommandMethodMarshalAPERFreshValue(v *ECIDMeasurementTerminationCommand, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeECIDMeasurementTerminationCommandMethodMarshalAPERLegacy(v *ECIDMeasurementTerminationCommand) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeECIDMeasurementTerminationCommandMethodMarshalAPERPlanned(v *ECIDMeasurementTerminationCommand, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeECIDMeasurementTerminationCommandMethodMarshalAPERTo(v *ECIDMeasurementTerminationCommand, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementTerminationCommandMethodUnmarshalAPERFrom(v *ECIDMeasurementTerminationCommand, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementTerminationCommandMethodUnmarshalAPERLegacy(v *ECIDMeasurementTerminationCommand, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeECIDMeasurementTerminationCommandMethodUnmarshalAPERWithOptions(v *ECIDMeasurementTerminationCommand, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeECIDMeasurementTerminationCommandValueCodecFieldCapture(v *ECIDMeasurementTerminationCommandValueCodec) *func(ECIDMeasurementTerminationCommand, q4.DecodeState) (ECIDMeasurementTerminationCommand, q4.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementTerminationCommandValueCodecFieldCompare(v *ECIDMeasurementTerminationCommandValueCodec) *func(ECIDMeasurementTerminationCommand, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementTerminationCommandValueCodecFieldContext(v *ECIDMeasurementTerminationCommandValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementTerminationCommandValueCodecFieldDecode(v *ECIDMeasurementTerminationCommandValueCodec) *func([]byte, q4.DecodeState) (ECIDMeasurementTerminationCommand, error) {
	return &v.decode
}
func BridgeECIDMeasurementTerminationCommandValueCodecFieldEncode(v *ECIDMeasurementTerminationCommandValueCodec) *func(ECIDMeasurementTerminationCommand, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementTerminationCommandValueCodecFieldPath(v *ECIDMeasurementTerminationCommandValueCodec) *q4.Path {
	return &v.path
}
func BridgeECIDMeasurementTerminationCommandValueCodecMethodEncodeBudget(v ECIDMeasurementTerminationCommandValueCodec, a0 ECIDMeasurementTerminationCommand, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeECIDMeasurementTerminationCommandValueCodecMethodEncodeChanged(v ECIDMeasurementTerminationCommandValueCodec, a0 ECIDMeasurementTerminationCommand, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeEUTRANAccessPointPositionAPERValueFieldContext(v *EUTRANAccessPointPositionAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeEUTRANAccessPointPositionAPERValueFieldReceived(v *EUTRANAccessPointPositionAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeEUTRANAccessPointPositionAPERValueFieldReplay(v *EUTRANAccessPointPositionAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeEUTRANAccessPointPositionAPERValueFieldWithoutReplay(v *EUTRANAccessPointPositionAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeEUTRANAccessPointPositionFieldExtCount(v *EUTRANAccessPointPosition) *int64 {
	return &v.extCount
}
func BridgeEUTRANAccessPointPositionFieldExtData(v *EUTRANAccessPointPosition) *[][]byte {
	return &v.extData
}
func BridgeEUTRANAccessPointPositionFieldExtOrigin(v *EUTRANAccessPointPosition) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeEUTRANAccessPointPositionFieldExtPresent(v *EUTRANAccessPointPosition) *[]bool {
	return &v.extPresent
}
func BridgeEUTRANAccessPointPositionFieldExtWire(v *EUTRANAccessPointPosition) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeEUTRANAccessPointPositionFieldPerExtPadding(v *EUTRANAccessPointPosition) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeEUTRANAccessPointPositionFieldPerPadding(v *EUTRANAccessPointPosition) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeEUTRANAccessPointPositionFieldReceived(v *EUTRANAccessPointPosition) *bool {
	return &v.received
}
func BridgeEUTRANAccessPointPositionFieldReceivedBytes(v *EUTRANAccessPointPosition) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeEUTRANAccessPointPositionFieldReplay(v *EUTRANAccessPointPosition) *q4.Snapshot {
	return &v.replay
}
func BridgeEUTRANAccessPointPositionFieldStream(v *EUTRANAccessPointPosition) *q4.WireSpan {
	return &v.stream
}
func BridgeEUTRANAccessPointPositionFieldWithoutReplay(v *EUTRANAccessPointPosition) *bool {
	return &v.withoutReplay
}
func BridgeEUTRANAccessPointPositionMethodMarshalAPERBudget(v *EUTRANAccessPointPosition, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeEUTRANAccessPointPositionMethodMarshalAPERChanged(v *EUTRANAccessPointPosition, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeEUTRANAccessPointPositionMethodMarshalAPERChangedValue(v *EUTRANAccessPointPosition, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeEUTRANAccessPointPositionMethodMarshalAPERFreshValue(v *EUTRANAccessPointPosition, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeEUTRANAccessPointPositionMethodMarshalAPERLegacy(v *EUTRANAccessPointPosition) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeEUTRANAccessPointPositionMethodMarshalAPERPlanned(v *EUTRANAccessPointPosition, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeEUTRANAccessPointPositionMethodMarshalAPERTo(v *EUTRANAccessPointPosition, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeEUTRANAccessPointPositionMethodUnmarshalAPERFrom(v *EUTRANAccessPointPosition, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeEUTRANAccessPointPositionMethodUnmarshalAPERLegacy(v *EUTRANAccessPointPosition, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeEUTRANAccessPointPositionMethodUnmarshalAPERWithOptions(v *EUTRANAccessPointPosition, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeEUTRANAccessPointPositionValueCodecFieldCapture(v *EUTRANAccessPointPositionValueCodec) *func(EUTRANAccessPointPosition, q4.DecodeState) (EUTRANAccessPointPosition, q4.Snapshot) {
	return &v.capture
}
func BridgeEUTRANAccessPointPositionValueCodecFieldCompare(v *EUTRANAccessPointPositionValueCodec) *func(EUTRANAccessPointPosition, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeEUTRANAccessPointPositionValueCodecFieldContext(v *EUTRANAccessPointPositionValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeEUTRANAccessPointPositionValueCodecFieldDecode(v *EUTRANAccessPointPositionValueCodec) *func([]byte, q4.DecodeState) (EUTRANAccessPointPosition, error) {
	return &v.decode
}
func BridgeEUTRANAccessPointPositionValueCodecFieldEncode(v *EUTRANAccessPointPositionValueCodec) *func(EUTRANAccessPointPosition, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEUTRANAccessPointPositionValueCodecFieldPath(v *EUTRANAccessPointPositionValueCodec) *q4.Path {
	return &v.path
}
func BridgeEUTRANAccessPointPositionValueCodecMethodEncodeBudget(v EUTRANAccessPointPositionValueCodec, a0 EUTRANAccessPointPosition, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeEUTRANAccessPointPositionValueCodecMethodEncodeChanged(v EUTRANAccessPointPositionValueCodec, a0 EUTRANAccessPointPosition, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInterRATMeasurementQuantitiesAPERValueFieldContext(v *InterRATMeasurementQuantitiesAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeInterRATMeasurementQuantitiesAPERValueFieldReceived(v *InterRATMeasurementQuantitiesAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeInterRATMeasurementQuantitiesAPERValueFieldReplay(v *InterRATMeasurementQuantitiesAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementQuantitiesAPERValueFieldWithoutReplay(v *InterRATMeasurementQuantitiesAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldCapture(v *InterRATMeasurementQuantitiesConcreteValueCodec) *func(InterRATMeasurementQuantities, q4.DecodeState) (InterRATMeasurementQuantities, q4.Snapshot) {
	return &v.capture
}
func BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldCompare(v *InterRATMeasurementQuantitiesConcreteValueCodec) *func(InterRATMeasurementQuantities, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldContext(v *InterRATMeasurementQuantitiesConcreteValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldDecode(v *InterRATMeasurementQuantitiesConcreteValueCodec) *func([]byte, q4.DecodeState) (InterRATMeasurementQuantities, error) {
	return &v.decode
}
func BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldEncode(v *InterRATMeasurementQuantitiesConcreteValueCodec) *func(InterRATMeasurementQuantities, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldPath(v *InterRATMeasurementQuantitiesConcreteValueCodec) *q4.Path {
	return &v.path
}
func BridgeInterRATMeasurementQuantitiesConcreteValueCodecMethodEncodeBudget(v InterRATMeasurementQuantitiesConcreteValueCodec, a0 InterRATMeasurementQuantities, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeInterRATMeasurementQuantitiesConcreteValueCodecMethodEncodeChanged(v InterRATMeasurementQuantitiesConcreteValueCodec, a0 InterRATMeasurementQuantities, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInterRATMeasurementQuantitiesItemAPERValueFieldContext(v *InterRATMeasurementQuantitiesItemAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeInterRATMeasurementQuantitiesItemAPERValueFieldReceived(v *InterRATMeasurementQuantitiesItemAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeInterRATMeasurementQuantitiesItemAPERValueFieldReplay(v *InterRATMeasurementQuantitiesItemAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementQuantitiesItemAPERValueFieldWithoutReplay(v *InterRATMeasurementQuantitiesItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementQuantitiesItemFieldExtCount(v *InterRATMeasurementQuantitiesItem) *int64 {
	return &v.extCount
}
func BridgeInterRATMeasurementQuantitiesItemFieldExtData(v *InterRATMeasurementQuantitiesItem) *[][]byte {
	return &v.extData
}
func BridgeInterRATMeasurementQuantitiesItemFieldExtOrigin(v *InterRATMeasurementQuantitiesItem) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeInterRATMeasurementQuantitiesItemFieldExtPresent(v *InterRATMeasurementQuantitiesItem) *[]bool {
	return &v.extPresent
}
func BridgeInterRATMeasurementQuantitiesItemFieldExtWire(v *InterRATMeasurementQuantitiesItem) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeInterRATMeasurementQuantitiesItemFieldIEExtensionsIndef(v *InterRATMeasurementQuantitiesItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeInterRATMeasurementQuantitiesItemFieldPerExtPadding(v *InterRATMeasurementQuantitiesItem) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeInterRATMeasurementQuantitiesItemFieldPerPadding(v *InterRATMeasurementQuantitiesItem) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeInterRATMeasurementQuantitiesItemFieldReceived(v *InterRATMeasurementQuantitiesItem) *bool {
	return &v.received
}
func BridgeInterRATMeasurementQuantitiesItemFieldReceivedBytes(v *InterRATMeasurementQuantitiesItem) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeInterRATMeasurementQuantitiesItemFieldReplay(v *InterRATMeasurementQuantitiesItem) *q4.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementQuantitiesItemFieldStream(v *InterRATMeasurementQuantitiesItem) *q4.WireSpan {
	return &v.stream
}
func BridgeInterRATMeasurementQuantitiesItemFieldWithoutReplay(v *InterRATMeasurementQuantitiesItem) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementQuantitiesItemIEFieldFieldReceived(v *InterRATMeasurementQuantitiesItemIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeInterRATMeasurementQuantitiesItemIEFieldFieldReplay(v *InterRATMeasurementQuantitiesItemIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementQuantitiesItemIEFieldFieldStream(v *InterRATMeasurementQuantitiesItemIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeInterRATMeasurementQuantitiesItemIEFieldFieldWithoutReplay(v *InterRATMeasurementQuantitiesItemIEField) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementQuantitiesItemIEFieldMethodMarshalAPERTo(v *InterRATMeasurementQuantitiesItemIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInterRATMeasurementQuantitiesItemIEFieldMethodUnmarshalAPERFrom(v *InterRATMeasurementQuantitiesItemIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInterRATMeasurementQuantitiesItemIETableMethodInfoInterRATMeasurementQuantitiesItem(v InterRATMeasurementQuantitiesItemIETable) q5.FieldInfo {
	return v.infoInterRATMeasurementQuantitiesItem()
}
func BridgeInterRATMeasurementQuantitiesItemIEValueFieldId(v *InterRATMeasurementQuantitiesItemIEValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeInterRATMeasurementQuantitiesItemIEValueFieldIsOpaque(v *InterRATMeasurementQuantitiesItemIEValue) *bool {
	return &v.isOpaque
}
func BridgeInterRATMeasurementQuantitiesItemIEValueFieldOpaque(v *InterRATMeasurementQuantitiesItemIEValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeInterRATMeasurementQuantitiesItemIEValueFieldReceived(v *InterRATMeasurementQuantitiesItemIEValue) *q4.WireSpan {
	return &v.received
}
func BridgeInterRATMeasurementQuantitiesItemIEValueFieldReplay(v *InterRATMeasurementQuantitiesItemIEValue) *q4.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementQuantitiesItemIEValueFieldRowInterRATMeasurementQuantitiesItem(v *InterRATMeasurementQuantitiesItemIEValue) **InterRATMeasurementQuantitiesItem {
	return &v.rowInterRATMeasurementQuantitiesItem
}
func BridgeInterRATMeasurementQuantitiesItemIEValueFieldWithoutReplay(v *InterRATMeasurementQuantitiesItemIEValue) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementQuantitiesItemIEValueMethodCaptureFraming(v InterRATMeasurementQuantitiesItemIEValue) uint64 {
	return v.captureFraming()
}
func BridgeInterRATMeasurementQuantitiesItemIEValueMethodCaptureSemantics(v InterRATMeasurementQuantitiesItemIEValue, a0 q4.SemanticCapture) InterRATMeasurementQuantitiesItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeInterRATMeasurementQuantitiesItemIEValueMethodCaptureSnapshot(v InterRATMeasurementQuantitiesItemIEValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeInterRATMeasurementQuantitiesItemIEValueMethodCompareSemantics(v InterRATMeasurementQuantitiesItemIEValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeInterRATMeasurementQuantitiesItemIEValueMethodDecode(v InterRATMeasurementQuantitiesItemIEValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (InterRATMeasurementQuantitiesItemIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesItemIEValueMethodEncode(v InterRATMeasurementQuantitiesItemIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeInterRATMeasurementQuantitiesItemIEValueMethodEncodeFresh(v InterRATMeasurementQuantitiesItemIEValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesItemIEValueMethodMatchesID(v InterRATMeasurementQuantitiesItemIEValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesItemIEValueMethodReason(v InterRATMeasurementQuantitiesItemIEValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeInterRATMeasurementQuantitiesItemIEValueMethodRule(v InterRATMeasurementQuantitiesItemIEValue) q4.SourceRule {
	return v.rule()
}
func BridgeInterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBindingFieldCodec(v *InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding) *InterRATMeasurementQuantitiesItemValueCodec {
	return &v.codec
}
func BridgeInterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBindingFieldGet(v *InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding) *func(*InterRATMeasurementQuantitiesItemIEValue) (*InterRATMeasurementQuantitiesItem, bool) {
	return &v.get
}
func BridgeInterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBindingFieldInfo(v *InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeInterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBindingFieldInject(v *InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding) *func(InterRATMeasurementQuantitiesItem) InterRATMeasurementQuantitiesItemIEValue {
	return &v.inject
}
func BridgeInterRATMeasurementQuantitiesItemMethodMarshalAPERBudget(v *InterRATMeasurementQuantitiesItem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesItemMethodMarshalAPERChanged(v *InterRATMeasurementQuantitiesItem, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeInterRATMeasurementQuantitiesItemMethodMarshalAPERChangedValue(v *InterRATMeasurementQuantitiesItem, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeInterRATMeasurementQuantitiesItemMethodMarshalAPERFreshValue(v *InterRATMeasurementQuantitiesItem, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesItemMethodMarshalAPERLegacy(v *InterRATMeasurementQuantitiesItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeInterRATMeasurementQuantitiesItemMethodMarshalAPERPlanned(v *InterRATMeasurementQuantitiesItem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesItemMethodMarshalAPERTo(v *InterRATMeasurementQuantitiesItem, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInterRATMeasurementQuantitiesItemMethodUnmarshalAPERFrom(v *InterRATMeasurementQuantitiesItem, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInterRATMeasurementQuantitiesItemMethodUnmarshalAPERLegacy(v *InterRATMeasurementQuantitiesItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeInterRATMeasurementQuantitiesItemMethodUnmarshalAPERWithOptions(v *InterRATMeasurementQuantitiesItem, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesItemValueCodecFieldCapture(v *InterRATMeasurementQuantitiesItemValueCodec) *func(InterRATMeasurementQuantitiesItem, q4.DecodeState) (InterRATMeasurementQuantitiesItem, q4.Snapshot) {
	return &v.capture
}
func BridgeInterRATMeasurementQuantitiesItemValueCodecFieldCompare(v *InterRATMeasurementQuantitiesItemValueCodec) *func(InterRATMeasurementQuantitiesItem, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeInterRATMeasurementQuantitiesItemValueCodecFieldContext(v *InterRATMeasurementQuantitiesItemValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeInterRATMeasurementQuantitiesItemValueCodecFieldDecode(v *InterRATMeasurementQuantitiesItemValueCodec) *func([]byte, q4.DecodeState) (InterRATMeasurementQuantitiesItem, error) {
	return &v.decode
}
func BridgeInterRATMeasurementQuantitiesItemValueCodecFieldEncode(v *InterRATMeasurementQuantitiesItemValueCodec) *func(InterRATMeasurementQuantitiesItem, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInterRATMeasurementQuantitiesItemValueCodecFieldPath(v *InterRATMeasurementQuantitiesItemValueCodec) *q4.Path {
	return &v.path
}
func BridgeInterRATMeasurementQuantitiesItemValueCodecMethodEncodeBudget(v InterRATMeasurementQuantitiesItemValueCodec, a0 InterRATMeasurementQuantitiesItem, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeInterRATMeasurementQuantitiesItemValueCodecMethodEncodeChanged(v InterRATMeasurementQuantitiesItemValueCodec, a0 InterRATMeasurementQuantitiesItem, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMeasurementQuantitiesAPERValueFieldContext(v *MeasurementQuantitiesAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementQuantitiesAPERValueFieldReceived(v *MeasurementQuantitiesAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeMeasurementQuantitiesAPERValueFieldReplay(v *MeasurementQuantitiesAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeMeasurementQuantitiesAPERValueFieldWithoutReplay(v *MeasurementQuantitiesAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementQuantitiesConcreteValueCodecFieldCapture(v *MeasurementQuantitiesConcreteValueCodec) *func(MeasurementQuantities, q4.DecodeState) (MeasurementQuantities, q4.Snapshot) {
	return &v.capture
}
func BridgeMeasurementQuantitiesConcreteValueCodecFieldCompare(v *MeasurementQuantitiesConcreteValueCodec) *func(MeasurementQuantities, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeMeasurementQuantitiesConcreteValueCodecFieldContext(v *MeasurementQuantitiesConcreteValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementQuantitiesConcreteValueCodecFieldDecode(v *MeasurementQuantitiesConcreteValueCodec) *func([]byte, q4.DecodeState) (MeasurementQuantities, error) {
	return &v.decode
}
func BridgeMeasurementQuantitiesConcreteValueCodecFieldEncode(v *MeasurementQuantitiesConcreteValueCodec) *func(MeasurementQuantities, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMeasurementQuantitiesConcreteValueCodecFieldPath(v *MeasurementQuantitiesConcreteValueCodec) *q4.Path {
	return &v.path
}
func BridgeMeasurementQuantitiesConcreteValueCodecMethodEncodeBudget(v MeasurementQuantitiesConcreteValueCodec, a0 MeasurementQuantities, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeMeasurementQuantitiesConcreteValueCodecMethodEncodeChanged(v MeasurementQuantitiesConcreteValueCodec, a0 MeasurementQuantities, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMeasurementQuantitiesItemAPERValueFieldContext(v *MeasurementQuantitiesItemAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementQuantitiesItemAPERValueFieldReceived(v *MeasurementQuantitiesItemAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeMeasurementQuantitiesItemAPERValueFieldReplay(v *MeasurementQuantitiesItemAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeMeasurementQuantitiesItemAPERValueFieldWithoutReplay(v *MeasurementQuantitiesItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementQuantitiesItemFieldExtCount(v *MeasurementQuantitiesItem) *int64 {
	return &v.extCount
}
func BridgeMeasurementQuantitiesItemFieldExtData(v *MeasurementQuantitiesItem) *[][]byte {
	return &v.extData
}
func BridgeMeasurementQuantitiesItemFieldExtOrigin(v *MeasurementQuantitiesItem) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeMeasurementQuantitiesItemFieldExtPresent(v *MeasurementQuantitiesItem) *[]bool {
	return &v.extPresent
}
func BridgeMeasurementQuantitiesItemFieldExtWire(v *MeasurementQuantitiesItem) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeMeasurementQuantitiesItemFieldIEExtensionsIndef(v *MeasurementQuantitiesItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeMeasurementQuantitiesItemFieldPerExtPadding(v *MeasurementQuantitiesItem) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeMeasurementQuantitiesItemFieldPerPadding(v *MeasurementQuantitiesItem) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeMeasurementQuantitiesItemFieldReceived(v *MeasurementQuantitiesItem) *bool {
	return &v.received
}
func BridgeMeasurementQuantitiesItemFieldReceivedBytes(v *MeasurementQuantitiesItem) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeMeasurementQuantitiesItemFieldReplay(v *MeasurementQuantitiesItem) *q4.Snapshot {
	return &v.replay
}
func BridgeMeasurementQuantitiesItemFieldStream(v *MeasurementQuantitiesItem) *q4.WireSpan {
	return &v.stream
}
func BridgeMeasurementQuantitiesItemFieldWithoutReplay(v *MeasurementQuantitiesItem) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementQuantitiesItemIEFieldFieldReceived(v *MeasurementQuantitiesItemIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeMeasurementQuantitiesItemIEFieldFieldReplay(v *MeasurementQuantitiesItemIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeMeasurementQuantitiesItemIEFieldFieldStream(v *MeasurementQuantitiesItemIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeMeasurementQuantitiesItemIEFieldFieldWithoutReplay(v *MeasurementQuantitiesItemIEField) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementQuantitiesItemIEFieldMethodMarshalAPERTo(v *MeasurementQuantitiesItemIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMeasurementQuantitiesItemIEFieldMethodUnmarshalAPERFrom(v *MeasurementQuantitiesItemIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMeasurementQuantitiesItemIEValueFieldId(v *MeasurementQuantitiesItemIEValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeMeasurementQuantitiesItemIEValueFieldIsOpaque(v *MeasurementQuantitiesItemIEValue) *bool {
	return &v.isOpaque
}
func BridgeMeasurementQuantitiesItemIEValueFieldOpaque(v *MeasurementQuantitiesItemIEValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeMeasurementQuantitiesItemIEValueFieldReceived(v *MeasurementQuantitiesItemIEValue) *q4.WireSpan {
	return &v.received
}
func BridgeMeasurementQuantitiesItemIEValueFieldReplay(v *MeasurementQuantitiesItemIEValue) *q4.Snapshot {
	return &v.replay
}
func BridgeMeasurementQuantitiesItemIEValueFieldRowMeasurementQuantitiesItem(v *MeasurementQuantitiesItemIEValue) **MeasurementQuantitiesItem {
	return &v.rowMeasurementQuantitiesItem
}
func BridgeMeasurementQuantitiesItemIEValueFieldWithoutReplay(v *MeasurementQuantitiesItemIEValue) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementQuantitiesItemIEValueMethodCaptureFraming(v MeasurementQuantitiesItemIEValue) uint64 {
	return v.captureFraming()
}
func BridgeMeasurementQuantitiesItemIEValueMethodCaptureSemantics(v MeasurementQuantitiesItemIEValue, a0 q4.SemanticCapture) MeasurementQuantitiesItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeMeasurementQuantitiesItemIEValueMethodCaptureSnapshot(v MeasurementQuantitiesItemIEValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeMeasurementQuantitiesItemIEValueMethodCompareSemantics(v MeasurementQuantitiesItemIEValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeMeasurementQuantitiesItemIEValueMethodDecode(v MeasurementQuantitiesItemIEValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (MeasurementQuantitiesItemIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeMeasurementQuantitiesItemIEValueMethodEncode(v MeasurementQuantitiesItemIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeMeasurementQuantitiesItemIEValueMethodEncodeFresh(v MeasurementQuantitiesItemIEValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeMeasurementQuantitiesItemIEValueMethodMatchesID(v MeasurementQuantitiesItemIEValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeMeasurementQuantitiesItemIEValueMethodReason(v MeasurementQuantitiesItemIEValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeMeasurementQuantitiesItemIEValueMethodRule(v MeasurementQuantitiesItemIEValue) q4.SourceRule {
	return v.rule()
}
func BridgeMeasurementQuantitiesItemMeasurementQuantitiesItemIEBindingFieldCodec(v *MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding) *MeasurementQuantitiesItemValueCodec {
	return &v.codec
}
func BridgeMeasurementQuantitiesItemMeasurementQuantitiesItemIEBindingFieldGet(v *MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding) *func(*MeasurementQuantitiesItemIEValue) (*MeasurementQuantitiesItem, bool) {
	return &v.get
}
func BridgeMeasurementQuantitiesItemMeasurementQuantitiesItemIEBindingFieldInfo(v *MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeMeasurementQuantitiesItemMeasurementQuantitiesItemIEBindingFieldInject(v *MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding) *func(MeasurementQuantitiesItem) MeasurementQuantitiesItemIEValue {
	return &v.inject
}
func BridgeMeasurementQuantitiesItemMethodMarshalAPERBudget(v *MeasurementQuantitiesItem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMeasurementQuantitiesItemMethodMarshalAPERChanged(v *MeasurementQuantitiesItem, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMeasurementQuantitiesItemMethodMarshalAPERChangedValue(v *MeasurementQuantitiesItem, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMeasurementQuantitiesItemMethodMarshalAPERFreshValue(v *MeasurementQuantitiesItem, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeMeasurementQuantitiesItemMethodMarshalAPERLegacy(v *MeasurementQuantitiesItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMeasurementQuantitiesItemMethodMarshalAPERPlanned(v *MeasurementQuantitiesItem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeMeasurementQuantitiesItemMethodMarshalAPERTo(v *MeasurementQuantitiesItem, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMeasurementQuantitiesItemMethodUnmarshalAPERFrom(v *MeasurementQuantitiesItem, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMeasurementQuantitiesItemMethodUnmarshalAPERLegacy(v *MeasurementQuantitiesItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMeasurementQuantitiesItemMethodUnmarshalAPERWithOptions(v *MeasurementQuantitiesItem, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMeasurementQuantitiesItemValueCodecFieldCapture(v *MeasurementQuantitiesItemValueCodec) *func(MeasurementQuantitiesItem, q4.DecodeState) (MeasurementQuantitiesItem, q4.Snapshot) {
	return &v.capture
}
func BridgeMeasurementQuantitiesItemValueCodecFieldCompare(v *MeasurementQuantitiesItemValueCodec) *func(MeasurementQuantitiesItem, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeMeasurementQuantitiesItemValueCodecFieldContext(v *MeasurementQuantitiesItemValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementQuantitiesItemValueCodecFieldDecode(v *MeasurementQuantitiesItemValueCodec) *func([]byte, q4.DecodeState) (MeasurementQuantitiesItem, error) {
	return &v.decode
}
func BridgeMeasurementQuantitiesItemValueCodecFieldEncode(v *MeasurementQuantitiesItemValueCodec) *func(MeasurementQuantitiesItem, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMeasurementQuantitiesItemValueCodecFieldPath(v *MeasurementQuantitiesItemValueCodec) *q4.Path {
	return &v.path
}
func BridgeMeasurementQuantitiesItemValueCodecMethodEncodeBudget(v MeasurementQuantitiesItemValueCodec, a0 MeasurementQuantitiesItem, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeMeasurementQuantitiesItemValueCodecMethodEncodeChanged(v MeasurementQuantitiesItemValueCodec, a0 MeasurementQuantitiesItem, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
