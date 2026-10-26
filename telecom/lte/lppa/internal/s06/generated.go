// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s06 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s06

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// ECIDMeasurementFailureIndicationIEContainer is ProtocolIE-Container {{E-CIDMeasurementFailureIndication-IEs}} of TS 36.455: a list of ECIDMeasurementFailureIndicationIEField values.
type ECIDMeasurementFailureIndicationIEContainer []ECIDMeasurementFailureIndicationIEField

// ECIDMeasurementFailureIndicationIEField is ProtocolIE-Field {{E-CIDMeasurementFailureIndication-IEs}} of TS 36.455: a field carrying a value of ECIDMeasurementFailureIndicationIEValue.
type ECIDMeasurementFailureIndicationIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ECIDMeasurementFailureIndicationIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECIDMeasurementFailureIndicationIEField) WithoutReplay() ECIDMeasurementFailureIndicationIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ECIDMeasurementFailureIndicationIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ECIDMeasurementFailureIndicationIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ECIDMeasurementFailureIndicationIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementFailureIndicationIEField{}
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
	var zero ECIDMeasurementFailureIndicationIEValue

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

// InterRATMeasurementQuantitiesItemIEValueProtocolIESingleContainer is ProtocolIE-Single-Container {{InterRATMeasurementQuantities-ItemIEs}} of TS 36.455: a single field carrying a value of InterRATMeasurementQuantitiesItemIEValue.
type InterRATMeasurementQuantitiesItemIEValueProtocolIESingleContainer = InterRATMeasurementQuantitiesItemIEField

// MeasurementQuantitiesItemIEValueProtocolIESingleContainer is ProtocolIE-Single-Container {{MeasurementQuantities-ItemIEs}} of TS 36.455: a single field carrying a value of MeasurementQuantitiesItemIEValue.
type MeasurementQuantitiesItemIEValueProtocolIESingleContainer = MeasurementQuantitiesItemIEField

// InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding binds InterRATMeasurementQuantitiesItem to ProtocolIE-Field {{InterRATMeasurementQuantities-ItemIEs}} of TS 36.455.
type InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding struct {
	info   s00.FieldInfo
	codec  InterRATMeasurementQuantitiesItemValueCodec
	inject func(InterRATMeasurementQuantitiesItem,

	) InterRATMeasurementQuantitiesItemIEValue

	get func(*InterRATMeasurementQuantitiesItemIEValue,

	) (*InterRATMeasurementQuantitiesItem,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete APER codec for this binding's value type.
func (b InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding) Codec() InterRATMeasurementQuantitiesItemValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding) New(value InterRATMeasurementQuantitiesItem,

) (InterRATMeasurementQuantitiesItemIEField, error) {
	if b.inject == nil {
		return InterRATMeasurementQuantitiesItemIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InterRATMeasurementQuantitiesItemIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return InterRATMeasurementQuantitiesItemIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InterRATMeasurementQuantitiesItemIEField{}, aper.OperationError(err, "Value.New")
	}
	return InterRATMeasurementQuantitiesItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding) Get(field *InterRATMeasurementQuantitiesItemIEField) (*InterRATMeasurementQuantitiesItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InterRATMeasurementQuantitiesItemValueCodec is the concrete ValueCodec[InterRATMeasurementQuantitiesItem].
type InterRATMeasurementQuantitiesItemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(InterRATMeasurementQuantitiesItem, aper.DecodeState,

	) (InterRATMeasurementQuantitiesItem, aper.Snapshot,

	)
	compare func(InterRATMeasurementQuantitiesItem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (InterRATMeasurementQuantitiesItem,

		error)
	encode func(InterRATMeasurementQuantitiesItem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c InterRATMeasurementQuantitiesItemValueCodec) New(value InterRATMeasurementQuantitiesItem,

) (InterRATMeasurementQuantitiesItemAPERValue, error) {
	if c.encode == nil {
		return InterRATMeasurementQuantitiesItemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InterRATMeasurementQuantitiesItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InterRATMeasurementQuantitiesItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return InterRATMeasurementQuantitiesItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c InterRATMeasurementQuantitiesItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InterRATMeasurementQuantitiesItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return InterRATMeasurementQuantitiesItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return InterRATMeasurementQuantitiesItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return InterRATMeasurementQuantitiesItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return InterRATMeasurementQuantitiesItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return InterRATMeasurementQuantitiesItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c InterRATMeasurementQuantitiesItemValueCodec) EncodeAPER(value InterRATMeasurementQuantitiesItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c InterRATMeasurementQuantitiesItemValueCodec) encodeBudget(value InterRATMeasurementQuantitiesItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c InterRATMeasurementQuantitiesItemValueCodec) encodeChanged(value InterRATMeasurementQuantitiesItem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// InterRATMeasurementQuantitiesItemIEField is ProtocolIE-Field {{InterRATMeasurementQuantities-ItemIEs}} of TS 36.455: a field carrying a value of InterRATMeasurementQuantitiesItemIEValue.
type InterRATMeasurementQuantitiesItemIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         InterRATMeasurementQuantitiesItemIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v InterRATMeasurementQuantitiesItemIEField) WithoutReplay() InterRATMeasurementQuantitiesItemIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *InterRATMeasurementQuantitiesItemIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *InterRATMeasurementQuantitiesItemIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *InterRATMeasurementQuantitiesItemIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InterRATMeasurementQuantitiesItemIEField{}
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
	var zero InterRATMeasurementQuantitiesItemIEValue

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

// MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding binds MeasurementQuantitiesItem to ProtocolIE-Field {{MeasurementQuantities-ItemIEs}} of TS 36.455.
type MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding struct {
	info   s00.FieldInfo
	codec  MeasurementQuantitiesItemValueCodec
	inject func(MeasurementQuantitiesItem,

	) MeasurementQuantitiesItemIEValue

	get func(*MeasurementQuantitiesItemIEValue,

	) (*MeasurementQuantitiesItem,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete APER codec for this binding's value type.
func (b MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding) Codec() MeasurementQuantitiesItemValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding) New(value MeasurementQuantitiesItem,

) (MeasurementQuantitiesItemIEField, error) {
	if b.inject == nil {
		return MeasurementQuantitiesItemIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MeasurementQuantitiesItemIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return MeasurementQuantitiesItemIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return MeasurementQuantitiesItemIEField{}, aper.OperationError(err, "Value.New")
	}
	return MeasurementQuantitiesItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding) Get(field *MeasurementQuantitiesItemIEField) (*MeasurementQuantitiesItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MeasurementQuantitiesItemValueCodec is the concrete ValueCodec[MeasurementQuantitiesItem].
type MeasurementQuantitiesItemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(MeasurementQuantitiesItem, aper.DecodeState,

	) (MeasurementQuantitiesItem, aper.Snapshot,

	)
	compare func(MeasurementQuantitiesItem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (MeasurementQuantitiesItem,

		error)
	encode func(MeasurementQuantitiesItem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c MeasurementQuantitiesItemValueCodec) New(value MeasurementQuantitiesItem,

) (MeasurementQuantitiesItemAPERValue, error) {
	if c.encode == nil {
		return MeasurementQuantitiesItemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MeasurementQuantitiesItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MeasurementQuantitiesItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return MeasurementQuantitiesItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c MeasurementQuantitiesItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MeasurementQuantitiesItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return MeasurementQuantitiesItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return MeasurementQuantitiesItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return MeasurementQuantitiesItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return MeasurementQuantitiesItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return MeasurementQuantitiesItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c MeasurementQuantitiesItemValueCodec) EncodeAPER(value MeasurementQuantitiesItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MeasurementQuantitiesItemValueCodec) encodeBudget(value MeasurementQuantitiesItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c MeasurementQuantitiesItemValueCodec) encodeChanged(value MeasurementQuantitiesItem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// MeasurementQuantitiesItemIEField is ProtocolIE-Field {{MeasurementQuantities-ItemIEs}} of TS 36.455: a field carrying a value of MeasurementQuantitiesItemIEValue.
type MeasurementQuantitiesItemIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         MeasurementQuantitiesItemIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v MeasurementQuantitiesItemIEField) WithoutReplay() MeasurementQuantitiesItemIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *MeasurementQuantitiesItemIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *MeasurementQuantitiesItemIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *MeasurementQuantitiesItemIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MeasurementQuantitiesItemIEField{}
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
	var zero MeasurementQuantitiesItemIEValue

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

// ECIDMeasurementFailureIndicationMeasurementIDIEBinding binds MeasurementID to ProtocolIE-Field {{E-CIDMeasurementFailureIndication-IEs}} of TS 36.455.
type ECIDMeasurementFailureIndicationMeasurementIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.MeasurementIDValueCodec
	inject func(s00.MeasurementID,

	) ECIDMeasurementFailureIndicationIEValue

	get func(*ECIDMeasurementFailureIndicationIEValue,

	) (*s00.MeasurementID,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementFailureIndicationMeasurementIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementFailureIndicationMeasurementIDIEBinding) Codec() s00.MeasurementIDValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementFailureIndicationMeasurementIDIEBinding) New(value s00.MeasurementID,

) (ECIDMeasurementFailureIndicationIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeMeasurementIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementFailureIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementFailureIndicationMeasurementIDIEBinding) Get(field *ECIDMeasurementFailureIndicationIEField) (*s00.MeasurementID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementFailureIndicationCauseIEBinding binds Cause to ProtocolIE-Field {{E-CIDMeasurementFailureIndication-IEs}} of TS 36.455.
type ECIDMeasurementFailureIndicationCauseIEBinding struct {
	info   s00.FieldInfo
	codec  s05.CauseValueCodec
	inject func(s05.Cause,

	) ECIDMeasurementFailureIndicationIEValue

	get func(*ECIDMeasurementFailureIndicationIEValue,

	) (*s05.Cause,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementFailureIndicationCauseIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementFailureIndicationCauseIEBinding) Codec() s05.CauseValueCodec { return b.codec }

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementFailureIndicationCauseIEBinding) New(value s05.Cause,

) (ECIDMeasurementFailureIndicationIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s05.BridgeCauseValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementFailureIndicationIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementFailureIndicationIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementFailureIndicationCauseIEBinding) Get(field *ECIDMeasurementFailureIndicationIEField) (*s05.Cause,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// MeasurementQuantitiesConcreteValueCodec is the concrete ValueCodec[MeasurementQuantities].
type MeasurementQuantitiesConcreteValueCodec struct {
	context s00.BridgeCodecContext
	capture func(MeasurementQuantities, aper.DecodeState,

	) (MeasurementQuantities, aper.Snapshot,

	)
	compare func(MeasurementQuantities, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (MeasurementQuantities,

		error)
	encode func(MeasurementQuantities,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c MeasurementQuantitiesConcreteValueCodec) New(value MeasurementQuantities,

) (MeasurementQuantitiesAPERValue, error) {
	if c.encode == nil {
		return MeasurementQuantitiesAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MeasurementQuantitiesAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MeasurementQuantitiesAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return MeasurementQuantitiesAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c MeasurementQuantitiesConcreteValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MeasurementQuantitiesAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return MeasurementQuantitiesAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return MeasurementQuantitiesAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return MeasurementQuantitiesAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return MeasurementQuantitiesAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return MeasurementQuantitiesAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c MeasurementQuantitiesConcreteValueCodec) EncodeAPER(value MeasurementQuantitiesAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MeasurementQuantitiesConcreteValueCodec) encodeBudget(value MeasurementQuantities,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c MeasurementQuantitiesConcreteValueCodec) encodeChanged(value MeasurementQuantities,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// InterRATMeasurementQuantitiesConcreteValueCodec is the concrete ValueCodec[InterRATMeasurementQuantities].
type InterRATMeasurementQuantitiesConcreteValueCodec struct {
	context s00.BridgeCodecContext
	capture func(InterRATMeasurementQuantities, aper.DecodeState,

	) (InterRATMeasurementQuantities, aper.Snapshot,

	)
	compare func(InterRATMeasurementQuantities, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (InterRATMeasurementQuantities,

		error)
	encode func(InterRATMeasurementQuantities,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c InterRATMeasurementQuantitiesConcreteValueCodec) New(value InterRATMeasurementQuantities,

) (InterRATMeasurementQuantitiesAPERValue, error) {
	if c.encode == nil {
		return InterRATMeasurementQuantitiesAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InterRATMeasurementQuantitiesAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InterRATMeasurementQuantitiesAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return InterRATMeasurementQuantitiesAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c InterRATMeasurementQuantitiesConcreteValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InterRATMeasurementQuantitiesAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return InterRATMeasurementQuantitiesAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return InterRATMeasurementQuantitiesAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return InterRATMeasurementQuantitiesAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return InterRATMeasurementQuantitiesAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return InterRATMeasurementQuantitiesAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c InterRATMeasurementQuantitiesConcreteValueCodec) EncodeAPER(value InterRATMeasurementQuantitiesAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c InterRATMeasurementQuantitiesConcreteValueCodec) encodeBudget(value InterRATMeasurementQuantities,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c InterRATMeasurementQuantitiesConcreteValueCodec) encodeChanged(value InterRATMeasurementQuantities,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ECIDMeasurementTerminationCommandValueCodec is the concrete ValueCodec[ECIDMeasurementTerminationCommand].
type ECIDMeasurementTerminationCommandValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ECIDMeasurementTerminationCommand, aper.DecodeState,

	) (ECIDMeasurementTerminationCommand, aper.Snapshot,

	)
	compare func(ECIDMeasurementTerminationCommand, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ECIDMeasurementTerminationCommand,

		error)
	encode func(ECIDMeasurementTerminationCommand,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ECIDMeasurementTerminationCommandValueCodec) New(value ECIDMeasurementTerminationCommand,

) (ECIDMeasurementTerminationCommandAPERValue, error) {
	if c.encode == nil {
		return ECIDMeasurementTerminationCommandAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementTerminationCommandAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ECIDMeasurementTerminationCommandAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementTerminationCommandAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ECIDMeasurementTerminationCommandValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ECIDMeasurementTerminationCommandAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ECIDMeasurementTerminationCommandAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ECIDMeasurementTerminationCommandAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ECIDMeasurementTerminationCommandAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ECIDMeasurementTerminationCommandAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ECIDMeasurementTerminationCommandAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ECIDMeasurementTerminationCommandValueCodec) EncodeAPER(value ECIDMeasurementTerminationCommandAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ECIDMeasurementTerminationCommandValueCodec) encodeBudget(value ECIDMeasurementTerminationCommand,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ECIDMeasurementTerminationCommandValueCodec) encodeChanged(value ECIDMeasurementTerminationCommand,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// EUTRANAccessPointPositionValueCodec is the concrete ValueCodec[EUTRANAccessPointPosition].
type EUTRANAccessPointPositionValueCodec struct {
	context s00.BridgeCodecContext
	capture func(EUTRANAccessPointPosition, aper.DecodeState,

	) (EUTRANAccessPointPosition, aper.Snapshot,

	)
	compare func(EUTRANAccessPointPosition, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (EUTRANAccessPointPosition,

		error)
	encode func(EUTRANAccessPointPosition,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c EUTRANAccessPointPositionValueCodec) New(value EUTRANAccessPointPosition,

) (EUTRANAccessPointPositionAPERValue, error) {
	if c.encode == nil {
		return EUTRANAccessPointPositionAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return EUTRANAccessPointPositionAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EUTRANAccessPointPositionAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return EUTRANAccessPointPositionAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c EUTRANAccessPointPositionValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (EUTRANAccessPointPositionAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return EUTRANAccessPointPositionAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return EUTRANAccessPointPositionAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return EUTRANAccessPointPositionAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return EUTRANAccessPointPositionAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return EUTRANAccessPointPositionAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c EUTRANAccessPointPositionValueCodec) EncodeAPER(value EUTRANAccessPointPositionAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c EUTRANAccessPointPositionValueCodec) encodeBudget(value EUTRANAccessPointPosition,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c EUTRANAccessPointPositionValueCodec) encodeChanged(value EUTRANAccessPointPosition,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// InterRATMeasurementQuantitiesItemIEContainer is ProtocolIE-Container {{InterRATMeasurementQuantities-ItemIEs}} of TS 36.455: a list of InterRATMeasurementQuantitiesItemIEField values.
type InterRATMeasurementQuantitiesItemIEContainer []InterRATMeasurementQuantitiesItemIEField

// MeasurementQuantitiesItemIEContainer is ProtocolIE-Container {{MeasurementQuantities-ItemIEs}} of TS 36.455: a list of MeasurementQuantitiesItemIEField values.
type MeasurementQuantitiesItemIEContainer []MeasurementQuantitiesItemIEField

// InterRATMeasurementQuantitiesItemAPERValue is the concrete APERValue[InterRATMeasurementQuantitiesItem].
type InterRATMeasurementQuantitiesItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   InterRATMeasurementQuantitiesItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v InterRATMeasurementQuantitiesItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v InterRATMeasurementQuantitiesItemAPERValue) WithoutReplay() InterRATMeasurementQuantitiesItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasurementQuantitiesItemAPERValue is the concrete APERValue[MeasurementQuantitiesItem].
type MeasurementQuantitiesItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   MeasurementQuantitiesItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v MeasurementQuantitiesItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v MeasurementQuantitiesItemAPERValue) WithoutReplay() MeasurementQuantitiesItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasurementQuantitiesAPERValue is the concrete APERValue[MeasurementQuantities].
type MeasurementQuantitiesAPERValue struct {
	context s00.BridgeCodecContext
	Value   MeasurementQuantities

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v MeasurementQuantitiesAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v MeasurementQuantitiesAPERValue) WithoutReplay() MeasurementQuantitiesAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InterRATMeasurementQuantitiesAPERValue is the concrete APERValue[InterRATMeasurementQuantities].
type InterRATMeasurementQuantitiesAPERValue struct {
	context s00.BridgeCodecContext
	Value   InterRATMeasurementQuantities

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v InterRATMeasurementQuantitiesAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v InterRATMeasurementQuantitiesAPERValue) WithoutReplay() InterRATMeasurementQuantitiesAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ECIDMeasurementTerminationCommandAPERValue is the concrete APERValue[ECIDMeasurementTerminationCommand].
type ECIDMeasurementTerminationCommandAPERValue struct {
	context s00.BridgeCodecContext
	Value   ECIDMeasurementTerminationCommand

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ECIDMeasurementTerminationCommandAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECIDMeasurementTerminationCommandAPERValue) WithoutReplay() ECIDMeasurementTerminationCommandAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EUTRANAccessPointPositionAPERValue is the concrete APERValue[EUTRANAccessPointPosition].
type EUTRANAccessPointPositionAPERValue struct {
	context s00.BridgeCodecContext
	Value   EUTRANAccessPointPosition

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v EUTRANAccessPointPositionAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v EUTRANAccessPointPositionAPERValue) WithoutReplay() EUTRANAccessPointPositionAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// EUTRANAccessPointPosition represents the ASN.1 type E-UTRANAccessPointPosition (SEQUENCE).
type EUTRANAccessPointPosition struct {
	replay                 aper.Snapshot
	stream                 aper.WireSpan
	withoutReplay          bool
	received               bool
	receivedBytes          aper.WireSpan
	LatitudeSign           int64                  `asn1:"tag:0,context,implicit"`
	Latitude               int64                  `asn1:"tag:1,context,implicit"`
	Longitude              int64                  `asn1:"tag:2,context,implicit"`
	DirectionOfAltitude    int64                  `asn1:"tag:3,context,implicit"`
	Altitude               int64                  `asn1:"tag:4,context,implicit"`
	UncertaintySemiMajor   int64                  `asn1:"tag:5,context,implicit"`
	UncertaintySemiMinor   int64                  `asn1:"tag:6,context,implicit"`
	OrientationOfMajorAxis int64                  `asn1:"tag:7,context,implicit"`
	UncertaintyAltitude    int64                  `asn1:"tag:8,context,implicit"`
	Confidence             int64                  `asn1:"tag:9,context,implicit"`
	extCount               int64                  `asn1:"-" json:"-"`
	extPresent             []bool                 `asn1:"-" json:"-"`
	extData                [][]byte               `asn1:"-" json:"-"`
	perPadding             aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding          []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin              []aper.OpaqueOrigin
	extWire                []aper.WireSpan
}
type InterRATMeasurementQuantities = []InterRATMeasurementQuantitiesItemIEValueProtocolIESingleContainer

// InterRATMeasurementQuantitiesItem represents the ASN.1 type InterRATMeasurementQuantities-Item (SEQUENCE).
type InterRATMeasurementQuantitiesItem struct {
	replay                             aper.Snapshot
	stream                             aper.WireSpan
	withoutReplay                      bool
	received                           bool
	receivedBytes                      aper.WireSpan
	InterRATMeasurementQuantitiesValue s00.InterRATMeasurementQuantitiesValue                   `asn1:"tag:0,context,implicit"`
	IEExtensions                       s03.InterRATMeasurementQuantitiesValueExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef                  bool                                                     `asn1:"-" json:"-"`
	extCount                           int64                                                    `asn1:"-" json:"-"`
	extPresent                         []bool                                                   `asn1:"-" json:"-"`
	extData                            [][]byte                                                 `asn1:"-" json:"-"`
	perPadding                         aper.FinalPadding                                        `asn1:"-" json:"-"`
	perExtPadding                      []aper.CompletePadding                                   `asn1:"-" json:"-"`
	extOrigin                          []aper.OpaqueOrigin
	extWire                            []aper.WireSpan
}
type MeasurementQuantities = []MeasurementQuantitiesItemIEValueProtocolIESingleContainer

// MeasurementQuantitiesItem represents the ASN.1 type MeasurementQuantities-Item (SEQUENCE).
type MeasurementQuantitiesItem struct {
	replay                     aper.Snapshot
	stream                     aper.WireSpan
	withoutReplay              bool
	received                   bool
	receivedBytes              aper.WireSpan
	MeasurementQuantitiesValue s00.MeasurementQuantitiesValue                   `asn1:"tag:0,context,implicit"`
	IEExtensions               s04.MeasurementQuantitiesValueExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef          bool                                             `asn1:"-" json:"-"`
	extCount                   int64                                            `asn1:"-" json:"-"`
	extPresent                 []bool                                           `asn1:"-" json:"-"`
	extData                    [][]byte                                         `asn1:"-" json:"-"`
	perPadding                 aper.FinalPadding                                `asn1:"-" json:"-"`
	perExtPadding              []aper.CompletePadding                           `asn1:"-" json:"-"`
	extOrigin                  []aper.OpaqueOrigin
	extWire                    []aper.WireSpan
}

// MarshalAPER encodes EUTRANAccessPointPosition to APER format.
func (v *EUTRANAccessPointPosition) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *EUTRANAccessPointPosition) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.LatitudeSign), 2, false); err != nil {
		return fmt.Errorf("encoding latitudeSign: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Latitude), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(8388607), false); err != nil {
		return fmt.Errorf("encoding latitude: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Longitude), s03.BridgeInt64Ptr(-8388608), s03.BridgeInt64Ptr(8388607), false); err != nil {
		return fmt.Errorf("encoding longitude: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.DirectionOfAltitude), 2, false); err != nil {
		return fmt.Errorf("encoding directionOfAltitude: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Altitude), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(32767), false); err != nil {
		return fmt.Errorf("encoding altitude: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.UncertaintySemiMajor), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(127), false); err != nil {
		return fmt.Errorf("encoding uncertaintySemi-major: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.UncertaintySemiMinor), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(127), false); err != nil {
		return fmt.Errorf("encoding uncertaintySemi-minor: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.OrientationOfMajorAxis), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(179), false); err != nil {
		return fmt.Errorf("encoding orientationOfMajorAxis: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.UncertaintyAltitude), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(127), false); err != nil {
		return fmt.Errorf("encoding uncertaintyAltitude: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Confidence), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(100), false); err != nil {
		return fmt.Errorf("encoding confidence: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:443
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:447
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:454
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

// UnmarshalAPER decodes EUTRANAccessPointPosition from APER format.
func (v *EUTRANAccessPointPosition) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *EUTRANAccessPointPosition) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "EUTRANAccessPointPosition")
	}
	bb.EnterComponent("EUTRANAccessPointPosition")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "EUTRANAccessPointPosition")
	}
	padding, err := aper.CaptureFinalBits(bb, "EUTRANAccessPointPosition")
	if err != nil {
		return runtime.WrapDecodePath(err, "EUTRANAccessPointPosition")
	}
	v.perPadding = padding
	return nil
}
func (v *EUTRANAccessPointPosition) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = EUTRANAccessPointPosition{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_latitudesign, err := aper.DecodeEnumeratedAligned(bb, 2, false, aper.EnumerationSource{KnownExtensions: 0, Path: "LatitudeSign"})
	if err != nil {
		return runtime.WrapDecodePath(err, "LatitudeSign")
	}
	v.LatitudeSign = val_latitudesign
	val_latitude, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(8388607), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Latitude")
	}
	v.Latitude = val_latitude
	val_longitude, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(-8388608), s03.BridgeInt64Ptr(8388607), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Longitude")
	}
	v.Longitude = val_longitude
	val_directionofaltitude, err := aper.DecodeEnumeratedAligned(bb, 2, false, aper.EnumerationSource{KnownExtensions: 0, Path: "DirectionOfAltitude"})
	if err != nil {
		return runtime.WrapDecodePath(err, "DirectionOfAltitude")
	}
	v.DirectionOfAltitude = val_directionofaltitude
	val_altitude, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(32767), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Altitude")
	}
	v.Altitude = val_altitude
	val_uncertaintysemimajor, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(127), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "UncertaintySemiMajor")
	}
	v.UncertaintySemiMajor = val_uncertaintysemimajor
	val_uncertaintysemiminor, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(127), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "UncertaintySemiMinor")
	}
	v.UncertaintySemiMinor = val_uncertaintysemiminor
	val_orientationofmajoraxis, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(179), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "OrientationOfMajorAxis")
	}
	v.OrientationOfMajorAxis = val_orientationofmajoraxis
	val_uncertaintyaltitude, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(127), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "UncertaintyAltitude")
	}
	v.UncertaintyAltitude = val_uncertaintyaltitude
	val_confidence, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(100), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Confidence")
	}
	v.Confidence = val_confidence
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:629
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:632
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
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
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// MarshalAPER encodes InterRATMeasurementQuantitiesItem to APER format.
func (v *InterRATMeasurementQuantitiesItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *InterRATMeasurementQuantitiesItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.InterRATMeasurementQuantitiesValue), 2, true); err != nil {
		return fmt.Errorf("encoding interRATMeasurementQuantitiesValue: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s03.BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:443
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:447
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:454
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

// UnmarshalAPER decodes InterRATMeasurementQuantitiesItem from APER format.
func (v *InterRATMeasurementQuantitiesItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *InterRATMeasurementQuantitiesItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasurementQuantitiesItem")
	}
	bb.EnterComponent("InterRATMeasurementQuantitiesItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasurementQuantitiesItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "InterRATMeasurementQuantitiesItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasurementQuantitiesItem")
	}
	v.perPadding = padding
	return nil
}
func (v *InterRATMeasurementQuantitiesItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InterRATMeasurementQuantitiesItem{}
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
	val_interratmeasurementquantitiesvalue, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 1, Path: "InterRATMeasurementQuantitiesValue"})
	if err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasurementQuantitiesValue")
	}
	v.InterRATMeasurementQuantitiesValue = s00.InterRATMeasurementQuantitiesValue(val_interratmeasurementquantitiesvalue)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s03.InterRATMeasurementQuantitiesValueExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s03.InterRATMeasurementQuantitiesValueExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s03.BridgeInterRATMeasurementQuantitiesValueExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:629
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:632
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
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
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// MarshalAPER encodes MeasurementQuantitiesItem to APER format.
func (v *MeasurementQuantitiesItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *MeasurementQuantitiesItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.MeasurementQuantitiesValue), 6, true); err != nil {
		return fmt.Errorf("encoding measurementQuantitiesValue: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s04.BridgeMeasurementQuantitiesValueExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:443
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:447
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:454
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

// UnmarshalAPER decodes MeasurementQuantitiesItem from APER format.
func (v *MeasurementQuantitiesItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *MeasurementQuantitiesItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MeasurementQuantitiesItem")
	}
	bb.EnterComponent("MeasurementQuantitiesItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MeasurementQuantitiesItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "MeasurementQuantitiesItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasurementQuantitiesItem")
	}
	v.perPadding = padding
	return nil
}
func (v *MeasurementQuantitiesItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MeasurementQuantitiesItem{}
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
	val_measurementquantitiesvalue, err := aper.DecodeEnumeratedAligned(bb, 6, true, aper.EnumerationSource{KnownExtensions: 0, Path: "MeasurementQuantitiesValue"})
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasurementQuantitiesValue")
	}
	v.MeasurementQuantitiesValue = s00.MeasurementQuantitiesValue(val_measurementquantitiesvalue)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s04.MeasurementQuantitiesValueExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s04.MeasurementQuantitiesValueExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s04.BridgeMeasurementQuantitiesValueExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:629
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:632
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
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
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *EUTRANAccessPointPosition) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "EUTRANAccessPointPosition", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v EUTRANAccessPointPosition) WithoutReplay() EUTRANAccessPointPosition {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero EUTRANAccessPointPosition
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *InterRATMeasurementQuantitiesItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "InterRATMeasurementQuantitiesItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InterRATMeasurementQuantitiesItem) WithoutReplay() InterRATMeasurementQuantitiesItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero InterRATMeasurementQuantitiesItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MeasurementQuantitiesItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "MeasurementQuantitiesItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MeasurementQuantitiesItem) WithoutReplay() MeasurementQuantitiesItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero MeasurementQuantitiesItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *EUTRANAccessPointPosition) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *EUTRANAccessPointPosition) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EUTRANAccessPointPosition.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EUTRANAccessPointPosition.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *EUTRANAccessPointPosition) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("EUTRANAccessPointPosition.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("EUTRANAccessPointPosition.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *InterRATMeasurementQuantitiesItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *InterRATMeasurementQuantitiesItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("InterRATMeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("InterRATMeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *InterRATMeasurementQuantitiesItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("InterRATMeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("InterRATMeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *MeasurementQuantitiesItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *MeasurementQuantitiesItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *MeasurementQuantitiesItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("MeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("MeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *EUTRANAccessPointPosition) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "EUTRANAccessPointPosition")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "EUTRANAccessPointPosition")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaEUTRANAccessPointPosition(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "EUTRANAccessPointPosition")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "EUTRANAccessPointPosition")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "EUTRANAccessPointPosition")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "EUTRANAccessPointPosition")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "EUTRANAccessPointPosition")
}
func (v *EUTRANAccessPointPosition) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *EUTRANAccessPointPosition) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *EUTRANAccessPointPosition) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *EUTRANAccessPointPosition) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *EUTRANAccessPointPosition) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *InterRATMeasurementQuantitiesItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "InterRATMeasurementQuantitiesItem")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "InterRATMeasurementQuantitiesItem")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaInterRATMeasurementQuantitiesItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "InterRATMeasurementQuantitiesItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "InterRATMeasurementQuantitiesItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "InterRATMeasurementQuantitiesItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "InterRATMeasurementQuantitiesItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "InterRATMeasurementQuantitiesItem")
}
func (v *InterRATMeasurementQuantitiesItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *InterRATMeasurementQuantitiesItem) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *InterRATMeasurementQuantitiesItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *InterRATMeasurementQuantitiesItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *InterRATMeasurementQuantitiesItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *MeasurementQuantitiesItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MeasurementQuantitiesItem")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "MeasurementQuantitiesItem")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaMeasurementQuantitiesItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "MeasurementQuantitiesItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "MeasurementQuantitiesItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "MeasurementQuantitiesItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "MeasurementQuantitiesItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "MeasurementQuantitiesItem")
}
func (v *MeasurementQuantitiesItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *MeasurementQuantitiesItem) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *MeasurementQuantitiesItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *MeasurementQuantitiesItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *MeasurementQuantitiesItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *EUTRANAccessPointPosition) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "EUTRANAccessPointPosition")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded EUTRANAccessPointPosition
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaEUTRANAccessPointPosition(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = EUTRANAccessPointPosition{}
		return report, aper.OperationError(err, "EUTRANAccessPointPosition")
	}
	*v = decoded
	return report, aper.OperationError(nil, "EUTRANAccessPointPosition")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *InterRATMeasurementQuantitiesItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "InterRATMeasurementQuantitiesItem")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded InterRATMeasurementQuantitiesItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaInterRATMeasurementQuantitiesItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = InterRATMeasurementQuantitiesItem{}
		return report, aper.OperationError(err, "InterRATMeasurementQuantitiesItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "InterRATMeasurementQuantitiesItem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *MeasurementQuantitiesItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MeasurementQuantitiesItem")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded MeasurementQuantitiesItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaMeasurementQuantitiesItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = MeasurementQuantitiesItem{}
		return report, aper.OperationError(err, "MeasurementQuantitiesItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MeasurementQuantitiesItem")
}

// ECIDMeasurementTerminationCommand represents the ASN.1 type E-CIDMeasurementTerminationCommand (SEQUENCE).
type ECIDMeasurementTerminationCommand struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    aper.WireSpan
	ProtocolIEs      s03.ECIDMeasurementTerminationCommandIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                             `asn1:"-" json:"-"`
	extCount         int64                                            `asn1:"-" json:"-"`
	extPresent       []bool                                           `asn1:"-" json:"-"`
	extData          [][]byte                                         `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                                `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                           `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes ECIDMeasurementTerminationCommand to APER format.
func (v *ECIDMeasurementTerminationCommand) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ECIDMeasurementTerminationCommand) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s03.BridgeECIDMeasurementTerminationCommandIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:443
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:447
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:454
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

// UnmarshalAPER decodes ECIDMeasurementTerminationCommand from APER format.
func (v *ECIDMeasurementTerminationCommand) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ECIDMeasurementTerminationCommand) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementTerminationCommand")
	}
	bb.EnterComponent("ECIDMeasurementTerminationCommand")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementTerminationCommand")
	}
	padding, err := aper.CaptureFinalBits(bb, "ECIDMeasurementTerminationCommand")
	if err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementTerminationCommand")
	}
	v.perPadding = padding
	return nil
}
func (v *ECIDMeasurementTerminationCommand) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementTerminationCommand{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s03.ECIDMeasurementTerminationCommandIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s03.ECIDMeasurementTerminationCommandIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s03.BridgeECIDMeasurementTerminationCommandIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:629
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:632
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
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
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage,

		bb,
	)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ECIDMeasurementTerminationCommand) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ECIDMeasurementTerminationCommand", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ECIDMeasurementTerminationCommand) WithoutReplay() ECIDMeasurementTerminationCommand {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ECIDMeasurementTerminationCommand
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ECIDMeasurementTerminationCommand) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ECIDMeasurementTerminationCommand) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ECIDMeasurementTerminationCommand.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ECIDMeasurementTerminationCommand.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ECIDMeasurementTerminationCommand) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ECIDMeasurementTerminationCommand.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ECIDMeasurementTerminationCommand.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *ECIDMeasurementTerminationCommand) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ECIDMeasurementTerminationCommand")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ECIDMeasurementTerminationCommand")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaECIDMeasurementTerminationCommand(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ECIDMeasurementTerminationCommand")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ECIDMeasurementTerminationCommand")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ECIDMeasurementTerminationCommand")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ECIDMeasurementTerminationCommand")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ECIDMeasurementTerminationCommand")
}
func (v *ECIDMeasurementTerminationCommand) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ECIDMeasurementTerminationCommand) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ECIDMeasurementTerminationCommand) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *ECIDMeasurementTerminationCommand) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ECIDMeasurementTerminationCommand) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ECIDMeasurementTerminationCommand) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ECIDMeasurementTerminationCommand")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ECIDMeasurementTerminationCommand
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaECIDMeasurementTerminationCommand(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ECIDMeasurementTerminationCommand{}
		return report, aper.OperationError(err, "ECIDMeasurementTerminationCommand")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ECIDMeasurementTerminationCommand")
}
func BridgeCaptureLPPaECIDMeasurementFailureIndicationIEValue(v *ECIDMeasurementFailureIndicationIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(6):
			{
				f := s.Begin()
				s.Bool(v.rowENBUEMeasurementID == nil)
				if v.rowENBUEMeasurementID != nil {
					s00.BridgeCaptureLPPaMeasurementID(v.rowENBUEMeasurementID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s05.BridgeCaptureLPPaCause(v.rowCause, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ECIDMeasurementFailureIndicationIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v ECIDMeasurementFailureIndicationIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ECIDMeasurementFailureIndicationIEValue) captureSemantics(s aper.SemanticCapture) ECIDMeasurementFailureIndicationIEValue {
	BridgeCaptureLPPaECIDMeasurementFailureIndicationIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaECIDMeasurementFailureIndicationIEValue(v *ECIDMeasurementFailureIndicationIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(6):
			{
				f := s.Begin()
				s.Bool(v.rowENBUEMeasurementID == nil)
				if v.rowENBUEMeasurementID != nil {
					s02.BridgeCompareLPPaMeasurementID(v.rowENBUEMeasurementID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowCause == nil)
				if v.rowCause != nil {
					s05.BridgeCompareLPPaCause(v.rowCause, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v ECIDMeasurementFailureIndicationIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaECIDMeasurementFailureIndicationIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECIDMeasurementFailureIndicationIEValue) WithoutReplay() ECIDMeasurementFailureIndicationIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaECIDMeasurementTerminationCommand(v *ECIDMeasurementTerminationCommand, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s04.BridgeECIDMeasurementTerminationCommandIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaECIDMeasurementTerminationCommand(v *ECIDMeasurementTerminationCommand, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s04.BridgeECIDMeasurementTerminationCommandIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaEUTRANAccessPointPosition(v *EUTRANAccessPointPosition, s *aper.SemanticCapture) {
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
func BridgeCompareLPPaEUTRANAccessPointPosition(v *EUTRANAccessPointPosition, s *aper.SemanticComparison) {
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
func BridgeCaptureLPPaInterRATMeasurementQuantitiesItem(v *InterRATMeasurementQuantitiesItem, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaInterRATMeasurementQuantitiesValue(&v.InterRATMeasurementQuantitiesValue, s)
	s.Bool(v.IEExtensions == nil)
	s04.BridgeInterRATMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaInterRATMeasurementQuantitiesItem(v *InterRATMeasurementQuantitiesItem, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaInterRATMeasurementQuantitiesValue(&v.InterRATMeasurementQuantitiesValue, s)
	s.Bool(v.IEExtensions == nil)
	s05.BridgeInterRATMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaInterRATMeasurementQuantitiesItemIEValue(v *InterRATMeasurementQuantitiesItemIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(16):
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
func (v InterRATMeasurementQuantitiesItemIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v InterRATMeasurementQuantitiesItemIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v InterRATMeasurementQuantitiesItemIEValue) captureSemantics(s aper.SemanticCapture) InterRATMeasurementQuantitiesItemIEValue {
	BridgeCaptureLPPaInterRATMeasurementQuantitiesItemIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaInterRATMeasurementQuantitiesItemIEValue(v *InterRATMeasurementQuantitiesItemIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(16):
			{
				f := s.Begin()
				s.Bool(v.rowInterRATMeasurementQuantitiesItem == nil)
				if v.rowInterRATMeasurementQuantitiesItem != nil {
					BridgeCompareLPPaInterRATMeasurementQuantitiesItem(v.rowInterRATMeasurementQuantitiesItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v InterRATMeasurementQuantitiesItemIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaInterRATMeasurementQuantitiesItemIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v InterRATMeasurementQuantitiesItemIEValue) WithoutReplay() InterRATMeasurementQuantitiesItemIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaMeasurementQuantitiesItem(v *MeasurementQuantitiesItem, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaMeasurementQuantitiesValue(&v.MeasurementQuantitiesValue, s)
	s.Bool(v.IEExtensions == nil)
	s05.BridgeMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaMeasurementQuantitiesItem(v *MeasurementQuantitiesItem, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaMeasurementQuantitiesValue(&v.MeasurementQuantitiesValue, s)
	s.Bool(v.IEExtensions == nil)
	s05.BridgeMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaMeasurementQuantitiesItemIEValue(v *MeasurementQuantitiesItemIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(11):
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
func (v MeasurementQuantitiesItemIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v MeasurementQuantitiesItemIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v MeasurementQuantitiesItemIEValue) captureSemantics(s aper.SemanticCapture) MeasurementQuantitiesItemIEValue {
	BridgeCaptureLPPaMeasurementQuantitiesItemIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaMeasurementQuantitiesItemIEValue(v *MeasurementQuantitiesItemIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(11):
			{
				f := s.Begin()
				s.Bool(v.rowMeasurementQuantitiesItem == nil)
				if v.rowMeasurementQuantitiesItem != nil {
					BridgeCompareLPPaMeasurementQuantitiesItem(v.rowMeasurementQuantitiesItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v MeasurementQuantitiesItemIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaMeasurementQuantitiesItemIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v MeasurementQuantitiesItemIEValue) WithoutReplay() MeasurementQuantitiesItemIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}

type InterRATMeasurementQuantitiesItemIEValue struct {
	id                                   s00.ProtocolIEID
	withoutReplay                        bool
	received                             aper.WireSpan
	replay                               aper.Snapshot
	opaque                               *aper.OpaqueOpenType
	isOpaque                             bool
	rowInterRATMeasurementQuantitiesItem *InterRATMeasurementQuantitiesItem
}

func (v InterRATMeasurementQuantitiesItemIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case s00.ProtocolIEID(16):
		return v.rowInterRATMeasurementQuantitiesItem != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *InterRATMeasurementQuantitiesItemIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (InterRATMeasurementQuantitiesItemIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "InterRATMeasurementQuantities-ItemIEs"}}
}
func (InterRATMeasurementQuantitiesItemIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(16):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
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
	case s00.ProtocolIEID(15):
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
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}

// AsInterRATMeasurementQuantitiesItem returns the selected InterRATMeasurementQuantitiesItem value and reports whether that alternative is active.
func (v *InterRATMeasurementQuantitiesItemIEValue) AsInterRATMeasurementQuantitiesItem() (*InterRATMeasurementQuantitiesItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(16) || v.rowInterRATMeasurementQuantitiesItem == nil {
		return nil, false
	}
	return v.rowInterRATMeasurementQuantitiesItem, true
}
func (v InterRATMeasurementQuantitiesItemIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (InterRATMeasurementQuantitiesItemIEValue, error) {
	out := InterRATMeasurementQuantitiesItemIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 16:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case s00.ProtocolIEID(16):
		replayUsage := scope.Usage()
		var value InterRATMeasurementQuantitiesItem
		child := raw.ChildDecodeBuffer()
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "InterRATMeasurementQuantitiesItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "InterRATMeasurementQuantitiesItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowInterRATMeasurementQuantitiesItem = &value
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
func (v InterRATMeasurementQuantitiesItemIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v InterRATMeasurementQuantitiesItemIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(16):
		if v.rowInterRATMeasurementQuantitiesItem == nil {
			return nil, fmt.Errorf("%s missing value", "InterRATMeasurementQuantities-ItemIEs.id-InterRATMeasurementQuantities-Item:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
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
		return nil, fmt.Errorf("%s id %d has no value", "InterRATMeasurementQuantitiesItemIEValue:", v.id)
	}
}

type MeasurementQuantitiesItemIEValue struct {
	id                           s00.ProtocolIEID
	withoutReplay                bool
	received                     aper.WireSpan
	replay                       aper.Snapshot
	opaque                       *aper.OpaqueOpenType
	isOpaque                     bool
	rowMeasurementQuantitiesItem *MeasurementQuantitiesItem
}

func (v MeasurementQuantitiesItemIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case s00.ProtocolIEID(11):
		return v.rowMeasurementQuantitiesItem != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *MeasurementQuantitiesItemIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (MeasurementQuantitiesItemIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementQuantities-ItemIEs"}}
}
func (MeasurementQuantitiesItemIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(11):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
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
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}

// AsMeasurementQuantitiesItem returns the selected MeasurementQuantitiesItem value and reports whether that alternative is active.
func (v *MeasurementQuantitiesItemIEValue) AsMeasurementQuantitiesItem() (*MeasurementQuantitiesItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(11) || v.rowMeasurementQuantitiesItem == nil {
		return nil, false
	}
	return v.rowMeasurementQuantitiesItem, true
}
func (v MeasurementQuantitiesItemIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (MeasurementQuantitiesItemIEValue, error) {
	out := MeasurementQuantitiesItemIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 11:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case s00.ProtocolIEID(11):
		replayUsage := scope.Usage()
		var value MeasurementQuantitiesItem
		child := raw.ChildDecodeBuffer()
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "MeasurementQuantitiesItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "MeasurementQuantitiesItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowMeasurementQuantitiesItem = &value
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
func (v MeasurementQuantitiesItemIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v MeasurementQuantitiesItemIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(11):
		if v.rowMeasurementQuantitiesItem == nil {
			return nil, fmt.Errorf("%s missing value", "MeasurementQuantities-ItemIEs.id-MeasurementQuantities-Item:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
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
		return nil, fmt.Errorf("%s id %d has no value", "MeasurementQuantitiesItemIEValue:", v.id)
	}
}

type ECIDMeasurementFailureIndicationIEValue struct {
	id                      s00.ProtocolIEID
	withoutReplay           bool
	received                aper.WireSpan
	replay                  aper.Snapshot
	opaque                  *aper.OpaqueOpenType
	isOpaque                bool
	rowESMLCUEMeasurementID *s00.MeasurementID
	rowENBUEMeasurementID   *s00.MeasurementID
	rowCause                *s05.Cause
}

func (v ECIDMeasurementFailureIndicationIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case s00.ProtocolIEID(2):
		return v.rowESMLCUEMeasurementID != nil
	case s00.ProtocolIEID(6):
		return v.rowENBUEMeasurementID != nil
	case s00.ProtocolIEID(0):
		return v.rowCause != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *ECIDMeasurementFailureIndicationIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ECIDMeasurementFailureIndicationIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementFailureIndication-IEs"}}
}
func (ECIDMeasurementFailureIndicationIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(6):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
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
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}

// AsESMLCUEMeasurementID returns the selected ESMLCUEMeasurementID value and reports whether that alternative is active.
func (v *ECIDMeasurementFailureIndicationIEValue) AsESMLCUEMeasurementID() (*s00.MeasurementID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowESMLCUEMeasurementID == nil {
		return nil, false
	}
	return v.rowESMLCUEMeasurementID, true
}

// AsENBUEMeasurementID returns the selected ENBUEMeasurementID value and reports whether that alternative is active.
func (v *ECIDMeasurementFailureIndicationIEValue) AsENBUEMeasurementID() (*s00.MeasurementID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(6) || v.rowENBUEMeasurementID == nil {
		return nil, false
	}
	return v.rowENBUEMeasurementID, true
}

// AsCause returns the selected Cause value and reports whether that alternative is active.
func (v *ECIDMeasurementFailureIndicationIEValue) AsCause() (*s05.Cause, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowCause == nil {
		return nil, false
	}
	return v.rowCause, true
}
func (v ECIDMeasurementFailureIndicationIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ECIDMeasurementFailureIndicationIEValue, error) {
	out := ECIDMeasurementFailureIndicationIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 2, 6, 0:
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
	case s00.ProtocolIEID(6):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound2, s00.BridgeAsn1IntegerBound7, true)
		value := s00.MeasurementID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ENBUEMeasurementID:", err)
		}
		if _, err := aper.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowENBUEMeasurementID = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case s00.ProtocolIEID(0):
		replayUsage := scope.Usage()
		var value s05.Cause
		child := raw.ChildDecodeBuffer()
		if err := s05.BridgeCauseMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "Cause:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "Cause")
		if err != nil {
			return out, err
		}
		*s05.BridgeCauseFieldPerPadding(&value) = padding.Padding()
		*s05.BridgeCauseFieldReceived(&value) = true
		raw.RetainContents(s05.BridgeCauseFieldReceivedBytes(&value))
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCause = &value
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
func (v ECIDMeasurementFailureIndicationIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ECIDMeasurementFailureIndicationIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementFailureIndication-IEs.id-E-SMLC-UE-Measurement-ID:")
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
	case s00.ProtocolIEID(6):
		if v.rowENBUEMeasurementID == nil {
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementFailureIndication-IEs.id-eNB-UE-Measurement-ID:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerBigBoundsAligned(encodeBB, *v.rowENBUEMeasurementID, s00.BridgeAsn1IntegerBound2, s00.BridgeAsn1IntegerBound7, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(0):
		if v.rowCause == nil {
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementFailureIndication-IEs.id-Cause:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := s05.BridgeCauseMethodMarshalAPERBudget(v.rowCause, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ECIDMeasurementFailureIndicationIEValue:", v.id)
	}
}

type InterRATMeasurementQuantitiesItemIETable struct{}

func InterRATMeasurementQuantitiesItemIEs() InterRATMeasurementQuantitiesItemIETable {
	return InterRATMeasurementQuantitiesItemIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (InterRATMeasurementQuantitiesItemIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "InterRATMeasurementQuantities-ItemIEs"}
		return sealed
	}()
}
func (InterRATMeasurementQuantitiesItemIETable) infoInterRATMeasurementQuantitiesItem() s00.FieldInfo {
	return s00.FieldInfo{Table: InterRATMeasurementQuantitiesItemIEs().ID(), ID: s00.ProtocolIEID(16), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "InterRATMeasurementQuantitiesItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "InterRATMeasurementQuantities-ItemIEs", Row: "id-InterRATMeasurementQuantities-Item"}}}
}

// InterRATMeasurementQuantitiesItem returns the typed binding for the InterRATMeasurementQuantitiesItem row of this table.
func (t InterRATMeasurementQuantitiesItemIETable) InterRATMeasurementQuantitiesItem() InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding {
	return InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding{info: t.infoInterRATMeasurementQuantitiesItem(), codec: InterRATMeasurementQuantitiesItemValueCodec{path: "InterRATMeasurementQuantitiesItem",
		decode: func(data []byte, options aper.DecodeState) (InterRATMeasurementQuantitiesItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty InterRATMeasurementQuantitiesItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("InterRATMeasurementQuantitiesItem")
			var zero InterRATMeasurementQuantitiesItemIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(16), raw)
			if err != nil {
				var empty InterRATMeasurementQuantitiesItem
				return empty, runtime.WrapDecodePath(err, "InterRATMeasurementQuantitiesItem")
			}
			value, ok := decoded.AsInterRATMeasurementQuantitiesItem()
			if !ok {
				var empty InterRATMeasurementQuantitiesItem
				return empty, fmt.Errorf("binding InterRATMeasurementQuantities-ItemIEs.id-InterRATMeasurementQuantities-Item: no selected value")
			}
			return *value, nil
		},
		encode: func(value InterRATMeasurementQuantitiesItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InterRATMeasurementQuantitiesItemIEValue{id: s00.ProtocolIEID(16), rowInterRATMeasurementQuantitiesItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v InterRATMeasurementQuantitiesItem, options aper.DecodeState) (InterRATMeasurementQuantitiesItem, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureLPPaInterRATMeasurementQuantitiesItem(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}, compare: func(v InterRATMeasurementQuantitiesItem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaInterRATMeasurementQuantitiesItem(&v, &s)
			s.End(f, root,

				false)
			return s.Plan()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InterRATMeasurementQuantitiesItem"
			return sealed
		}(),
	}, inject: func(value InterRATMeasurementQuantitiesItem) InterRATMeasurementQuantitiesItemIEValue {
		return InterRATMeasurementQuantitiesItemIEValue{id: s00.ProtocolIEID(16), rowInterRATMeasurementQuantitiesItem: &value}
	}, get: func(value *InterRATMeasurementQuantitiesItemIEValue) (*InterRATMeasurementQuantitiesItem, bool) {
		return value.AsInterRATMeasurementQuantitiesItem()
	}}
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t InterRATMeasurementQuantitiesItemIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (InterRATMeasurementQuantitiesItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return InterRATMeasurementQuantitiesItemIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(16):
		return InterRATMeasurementQuantitiesItemIEField{}, aper.OperationError(fmt.Errorf("known IE id-InterRATMeasurementQuantities-Item requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return InterRATMeasurementQuantitiesItemIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return InterRATMeasurementQuantitiesItemIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return InterRATMeasurementQuantitiesItemIEField{}, aper.OperationError(err, "Opaque")
		}
		return InterRATMeasurementQuantitiesItemIEField{Id: id, Criticality: criticality, Value: InterRATMeasurementQuantitiesItemIEValue{id: id, opaque: retained, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type ECIDMeasurementFailureIndicationIETable struct{}

func ECIDMeasurementFailureIndicationIEs() ECIDMeasurementFailureIndicationIETable {
	return ECIDMeasurementFailureIndicationIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (ECIDMeasurementFailureIndicationIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementFailureIndication-IEs"}
		return sealed
	}()
}
func (ECIDMeasurementFailureIndicationIETable) infoESMLCUEMeasurementID() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementFailureIndicationIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementFailureIndication-IEs", Row: "id-E-SMLC-UE-Measurement-ID"}}}
}

// ESMLCUEMeasurementID returns the typed binding for the ESMLCUEMeasurementID row of this table.
func (t ECIDMeasurementFailureIndicationIETable) ESMLCUEMeasurementID() ECIDMeasurementFailureIndicationMeasurementIDIEBinding {
	return ECIDMeasurementFailureIndicationMeasurementIDIEBinding{info: t.infoESMLCUEMeasurementID(), codec: func() s00.MeasurementIDValueCodec {
		sealed := s00.MeasurementIDValueCodec{}
		*s00.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*s00.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MeasurementID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MeasurementID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MeasurementID")
			var zero ECIDMeasurementFailureIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s00.MeasurementID
				return empty, runtime.WrapDecodePath(err, "MeasurementID")
			}
			value, ok := decoded.AsESMLCUEMeasurementID()
			if !ok {
				var empty s00.MeasurementID
				return empty, fmt.Errorf("binding E-CIDMeasurementFailureIndication-IEs.id-E-SMLC-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value s00.MeasurementID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementFailureIndicationIEValue{id: s00.ProtocolIEID(2), rowESMLCUEMeasurementID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MeasurementID) ECIDMeasurementFailureIndicationIEValue {
			return ECIDMeasurementFailureIndicationIEValue{id: s00.ProtocolIEID(2), rowESMLCUEMeasurementID: &value}
		}, get: func(value *ECIDMeasurementFailureIndicationIEValue) (*s00.MeasurementID, bool) {
			return value.AsESMLCUEMeasurementID()
		}}
}
func (ECIDMeasurementFailureIndicationIETable) infoENBUEMeasurementID() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementFailureIndicationIEs().ID(), ID: s00.ProtocolIEID(6), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementFailureIndication-IEs", Row: "id-eNB-UE-Measurement-ID"}}}
}

// ENBUEMeasurementID returns the typed binding for the ENBUEMeasurementID row of this table.
func (t ECIDMeasurementFailureIndicationIETable) ENBUEMeasurementID() ECIDMeasurementFailureIndicationMeasurementIDIEBinding {
	return ECIDMeasurementFailureIndicationMeasurementIDIEBinding{info: t.infoENBUEMeasurementID(), codec: func() s00.MeasurementIDValueCodec {
		sealed := s00.MeasurementIDValueCodec{}
		*s00.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*s00.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MeasurementID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MeasurementID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MeasurementID")
			var zero ECIDMeasurementFailureIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(6), raw)
			if err != nil {
				var empty s00.MeasurementID
				return empty, runtime.WrapDecodePath(err, "MeasurementID")
			}
			value, ok := decoded.AsENBUEMeasurementID()
			if !ok {
				var empty s00.MeasurementID
				return empty, fmt.Errorf("binding E-CIDMeasurementFailureIndication-IEs.id-eNB-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value s00.MeasurementID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementFailureIndicationIEValue{id: s00.ProtocolIEID(6), rowENBUEMeasurementID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MeasurementID) ECIDMeasurementFailureIndicationIEValue {
			return ECIDMeasurementFailureIndicationIEValue{id: s00.ProtocolIEID(6), rowENBUEMeasurementID: &value}
		}, get: func(value *ECIDMeasurementFailureIndicationIEValue) (*s00.MeasurementID, bool) {
			return value.AsENBUEMeasurementID()
		}}
}
func (ECIDMeasurementFailureIndicationIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementFailureIndicationIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementFailureIndication-IEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of this table.
func (t ECIDMeasurementFailureIndicationIETable) Cause() ECIDMeasurementFailureIndicationCauseIEBinding {
	return ECIDMeasurementFailureIndicationCauseIEBinding{info: t.infoCause(), codec: func() s05.CauseValueCodec {
		sealed := s05.CauseValueCodec{}
		*s05.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
		*s05.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s05.Cause, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s05.Cause
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Cause")
			var zero ECIDMeasurementFailureIndicationIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s05.Cause
				return empty, runtime.WrapDecodePath(err, "Cause")
			}
			value, ok := decoded.AsCause()
			if !ok {
				var empty s05.Cause
				return empty, fmt.Errorf("binding E-CIDMeasurementFailureIndication-IEs.id-Cause: no selected value")
			}
			return *value, nil
		}
		*s05.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s05.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementFailureIndicationIEValue{id: s00.ProtocolIEID(0), rowCause: &value}).encodeFresh(fresh, budget)
		}
		*s05.BridgeCauseValueCodecFieldCapture(&sealed) = func(v s05.Cause, options aper.DecodeState) (s05.Cause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s05.BridgeCaptureLPPaCause(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s05.BridgeCauseValueCodecFieldCompare(&sealed) = func(v s05.Cause, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			s05.BridgeCompareLPPaCause(&v, &s)
			s.End(
				f, root, false)
			return s.Plan()
		}
		*s05.BridgeCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s05.Cause) ECIDMeasurementFailureIndicationIEValue {
			return ECIDMeasurementFailureIndicationIEValue{id: s00.ProtocolIEID(0), rowCause: &value}
		}, get: func(value *ECIDMeasurementFailureIndicationIEValue) (*s05.Cause, bool) { return value.AsCause() }}
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t ECIDMeasurementFailureIndicationIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ECIDMeasurementFailureIndicationIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ECIDMeasurementFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(2):
		return ECIDMeasurementFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-SMLC-UE-Measurement-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(6):
		return ECIDMeasurementFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-Measurement-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(0):
		return ECIDMeasurementFailureIndicationIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ECIDMeasurementFailureIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ECIDMeasurementFailureIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ECIDMeasurementFailureIndicationIEField{}, aper.OperationError(err, "Opaque")
		}
		return ECIDMeasurementFailureIndicationIEField{Id: id, Criticality: criticality, Value: ECIDMeasurementFailureIndicationIEValue{id: id, opaque: retained, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// CauseCodec binds the complete APER value type.
func CauseCodec() s05.CauseValueCodec { return ECIDMeasurementFailureIndicationIEs().Cause().Codec() }

// ECGICodec binds the complete source value type.
func ECGICodec() s05.ECGIValueCodec {
	return func() s05.ECGIValueCodec {
		sealed := s05.ECGIValueCodec{}
		*s05.BridgeECGIValueCodecFieldPath(&sealed) = "ECGI"
		*s05.BridgeECGIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s05.ECGI, error) {
			var value s05.ECGI
			if err := s05.BridgeECGIMethodUnmarshalAPERWithOptions(&value, data, options); err != nil {
				return s05.ECGI{}, err
			}
			*s05.BridgeECGIFieldReceived(&value) = true
			*s05.BridgeECGIFieldReceivedBytes(&value) = aper.OriginalWire(data)
			return value, nil
		}
		*s05.BridgeECGIValueCodecFieldEncode(&sealed) = func(value s05.ECGI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s05.BridgeECGIMethodMarshalAPERBudget((&value), budget, fresh)
		}
		*s05.BridgeECGIValueCodecFieldCapture(&sealed) = func(v s05.ECGI, options aper.DecodeState) (s05.ECGI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s05.BridgeCaptureLPPaECGI(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s05.BridgeECGIValueCodecFieldCompare(&sealed) = func(v s05.ECGI, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			s05.BridgeCompareLPPaECGI(&v, &s)
			s.End(f,
				root, false)
			return s.Plan()
		}
		*s05.BridgeECGIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ECGI"
			return sealed
		}()
		return sealed
	}()

}

// EUTRANAccessPointPositionCodec binds the complete source value type.
func EUTRANAccessPointPositionCodec() EUTRANAccessPointPositionValueCodec {
	return EUTRANAccessPointPositionValueCodec{path: "EUTRANAccessPointPosition", decode: func(data []byte, options aper.DecodeState) (EUTRANAccessPointPosition, error) {
		var value EUTRANAccessPointPosition
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return EUTRANAccessPointPosition{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value EUTRANAccessPointPosition, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v EUTRANAccessPointPosition, options aper.DecodeState) (EUTRANAccessPointPosition, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaEUTRANAccessPointPosition(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v EUTRANAccessPointPosition, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaEUTRANAccessPointPosition(&v, &s)
		s.End(f, root, false)
		return s.
			Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EUTRANAccessPointPosition"
		return sealed
	}(),
	}
}

// InterRATMeasurementQuantitiesItemCodec binds the complete APER value type.
func InterRATMeasurementQuantitiesItemCodec() InterRATMeasurementQuantitiesItemValueCodec {
	return InterRATMeasurementQuantitiesItemIEs().InterRATMeasurementQuantitiesItem().Codec()
}

// MeasurementIDCodec binds the complete APER value type.
func MeasurementIDCodec() s00.MeasurementIDValueCodec {
	return ECIDMeasurementFailureIndicationIEs().ESMLCUEMeasurementID().Codec()
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives that share a Go type.
func (v *ECIDMeasurementFailureIndicationIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 2:
		if v.rowESMLCUEMeasurementID != nil {
			return v.rowESMLCUEMeasurementID, true
		}
	case 6:
		if v.rowENBUEMeasurementID != nil {
			return v.rowENBUEMeasurementID, true
		}
	case 0:
		if v.rowCause != nil {
			return v.rowCause, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *InterRATMeasurementQuantitiesItemIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 16:
		if v.rowInterRATMeasurementQuantitiesItem != nil {
			return v.rowInterRATMeasurementQuantitiesItem, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *MeasurementQuantitiesItemIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 11:
		if v.rowMeasurementQuantitiesItem != nil {
			return v.rowMeasurementQuantitiesItem, true
		}
	}
	return nil, false
}

func BridgeECIDMeasurementFailureIndicationCauseIEBindingFieldCodec(v *ECIDMeasurementFailureIndicationCauseIEBinding) *s05.CauseValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementFailureIndicationCauseIEBindingFieldGet(v *ECIDMeasurementFailureIndicationCauseIEBinding) *func(*ECIDMeasurementFailureIndicationIEValue) (*s05.Cause, bool) {
	return &v.get
}
func BridgeECIDMeasurementFailureIndicationCauseIEBindingFieldInfo(v *ECIDMeasurementFailureIndicationCauseIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementFailureIndicationCauseIEBindingFieldInject(v *ECIDMeasurementFailureIndicationCauseIEBinding) *func(s05.Cause) ECIDMeasurementFailureIndicationIEValue {
	return &v.inject
}
func BridgeECIDMeasurementFailureIndicationIEFieldFieldReceived(v *ECIDMeasurementFailureIndicationIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeECIDMeasurementFailureIndicationIEFieldFieldReplay(v *ECIDMeasurementFailureIndicationIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementFailureIndicationIEFieldFieldStream(v *ECIDMeasurementFailureIndicationIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementFailureIndicationIEFieldFieldWithoutReplay(v *ECIDMeasurementFailureIndicationIEField) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementFailureIndicationIEFieldMethodMarshalAPERTo(v *ECIDMeasurementFailureIndicationIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementFailureIndicationIEFieldMethodUnmarshalAPERFrom(v *ECIDMeasurementFailureIndicationIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementFailureIndicationIETableMethodInfoCause(v ECIDMeasurementFailureIndicationIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeECIDMeasurementFailureIndicationIETableMethodInfoENBUEMeasurementID(v ECIDMeasurementFailureIndicationIETable) s00.FieldInfo {
	return v.infoENBUEMeasurementID()
}
func BridgeECIDMeasurementFailureIndicationIETableMethodInfoESMLCUEMeasurementID(v ECIDMeasurementFailureIndicationIETable) s00.FieldInfo {
	return v.infoESMLCUEMeasurementID()
}
func BridgeECIDMeasurementFailureIndicationIEValueFieldId(v *ECIDMeasurementFailureIndicationIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeECIDMeasurementFailureIndicationIEValueFieldIsOpaque(v *ECIDMeasurementFailureIndicationIEValue) *bool {
	return &v.isOpaque
}
func BridgeECIDMeasurementFailureIndicationIEValueFieldOpaque(v *ECIDMeasurementFailureIndicationIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeECIDMeasurementFailureIndicationIEValueFieldReceived(v *ECIDMeasurementFailureIndicationIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementFailureIndicationIEValueFieldReplay(v *ECIDMeasurementFailureIndicationIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementFailureIndicationIEValueFieldRowCause(v *ECIDMeasurementFailureIndicationIEValue) **s05.Cause {
	return &v.rowCause
}
func BridgeECIDMeasurementFailureIndicationIEValueFieldRowENBUEMeasurementID(v *ECIDMeasurementFailureIndicationIEValue) **s00.MeasurementID {
	return &v.rowENBUEMeasurementID
}
func BridgeECIDMeasurementFailureIndicationIEValueFieldRowESMLCUEMeasurementID(v *ECIDMeasurementFailureIndicationIEValue) **s00.MeasurementID {
	return &v.rowESMLCUEMeasurementID
}
func BridgeECIDMeasurementFailureIndicationIEValueFieldWithoutReplay(v *ECIDMeasurementFailureIndicationIEValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodCaptureFraming(v ECIDMeasurementFailureIndicationIEValue) uint64 {
	return v.captureFraming()
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodCaptureSemantics(v ECIDMeasurementFailureIndicationIEValue, a0 aper.SemanticCapture) ECIDMeasurementFailureIndicationIEValue {
	return v.captureSemantics(a0)
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodCaptureSnapshot(v ECIDMeasurementFailureIndicationIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodCompareSemantics(v ECIDMeasurementFailureIndicationIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodDecode(v ECIDMeasurementFailureIndicationIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ECIDMeasurementFailureIndicationIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodEncode(v ECIDMeasurementFailureIndicationIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodEncodeFresh(v ECIDMeasurementFailureIndicationIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodMatchesID(v ECIDMeasurementFailureIndicationIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodReason(v ECIDMeasurementFailureIndicationIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeECIDMeasurementFailureIndicationIEValueMethodRule(v ECIDMeasurementFailureIndicationIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeECIDMeasurementFailureIndicationMeasurementIDIEBindingFieldCodec(v *ECIDMeasurementFailureIndicationMeasurementIDIEBinding) *s00.MeasurementIDValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementFailureIndicationMeasurementIDIEBindingFieldGet(v *ECIDMeasurementFailureIndicationMeasurementIDIEBinding) *func(*ECIDMeasurementFailureIndicationIEValue) (*s00.MeasurementID, bool) {
	return &v.get
}
func BridgeECIDMeasurementFailureIndicationMeasurementIDIEBindingFieldInfo(v *ECIDMeasurementFailureIndicationMeasurementIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementFailureIndicationMeasurementIDIEBindingFieldInject(v *ECIDMeasurementFailureIndicationMeasurementIDIEBinding) *func(s00.MeasurementID) ECIDMeasurementFailureIndicationIEValue {
	return &v.inject
}
func BridgeECIDMeasurementTerminationCommandAPERValueFieldContext(v *ECIDMeasurementTerminationCommandAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementTerminationCommandAPERValueFieldReceived(v *ECIDMeasurementTerminationCommandAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementTerminationCommandAPERValueFieldReplay(v *ECIDMeasurementTerminationCommandAPERValue) *aper.Snapshot {
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
func BridgeECIDMeasurementTerminationCommandFieldExtOrigin(v *ECIDMeasurementTerminationCommand) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeECIDMeasurementTerminationCommandFieldExtPresent(v *ECIDMeasurementTerminationCommand) *[]bool {
	return &v.extPresent
}
func BridgeECIDMeasurementTerminationCommandFieldExtWire(v *ECIDMeasurementTerminationCommand) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeECIDMeasurementTerminationCommandFieldPerExtPadding(v *ECIDMeasurementTerminationCommand) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeECIDMeasurementTerminationCommandFieldPerPadding(v *ECIDMeasurementTerminationCommand) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeECIDMeasurementTerminationCommandFieldProtocolIEsIndef(v *ECIDMeasurementTerminationCommand) *bool {
	return &v.protocolIEsIndef
}
func BridgeECIDMeasurementTerminationCommandFieldReceived(v *ECIDMeasurementTerminationCommand) *bool {
	return &v.received
}
func BridgeECIDMeasurementTerminationCommandFieldReceivedBytes(v *ECIDMeasurementTerminationCommand) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeECIDMeasurementTerminationCommandFieldReplay(v *ECIDMeasurementTerminationCommand) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementTerminationCommandFieldStream(v *ECIDMeasurementTerminationCommand) *aper.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementTerminationCommandFieldWithoutReplay(v *ECIDMeasurementTerminationCommand) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementTerminationCommandMethodMarshalAPERBudget(v *ECIDMeasurementTerminationCommand, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeECIDMeasurementTerminationCommandMethodMarshalAPERChanged(v *ECIDMeasurementTerminationCommand, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeECIDMeasurementTerminationCommandMethodMarshalAPERChangedValue(v *ECIDMeasurementTerminationCommand, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeECIDMeasurementTerminationCommandMethodMarshalAPERFreshValue(v *ECIDMeasurementTerminationCommand, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeECIDMeasurementTerminationCommandMethodMarshalAPERLegacy(v *ECIDMeasurementTerminationCommand) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeECIDMeasurementTerminationCommandMethodMarshalAPERPlanned(v *ECIDMeasurementTerminationCommand, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeECIDMeasurementTerminationCommandMethodMarshalAPERTo(v *ECIDMeasurementTerminationCommand, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementTerminationCommandMethodUnmarshalAPERFrom(v *ECIDMeasurementTerminationCommand, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementTerminationCommandMethodUnmarshalAPERLegacy(v *ECIDMeasurementTerminationCommand, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeECIDMeasurementTerminationCommandMethodUnmarshalAPERWithOptions(v *ECIDMeasurementTerminationCommand, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeECIDMeasurementTerminationCommandValueCodecFieldCapture(v *ECIDMeasurementTerminationCommandValueCodec) *func(ECIDMeasurementTerminationCommand, aper.DecodeState) (ECIDMeasurementTerminationCommand, aper.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementTerminationCommandValueCodecFieldCompare(v *ECIDMeasurementTerminationCommandValueCodec) *func(ECIDMeasurementTerminationCommand, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementTerminationCommandValueCodecFieldContext(v *ECIDMeasurementTerminationCommandValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementTerminationCommandValueCodecFieldDecode(v *ECIDMeasurementTerminationCommandValueCodec) *func([]byte, aper.DecodeState) (ECIDMeasurementTerminationCommand, error) {
	return &v.decode
}
func BridgeECIDMeasurementTerminationCommandValueCodecFieldEncode(v *ECIDMeasurementTerminationCommandValueCodec) *func(ECIDMeasurementTerminationCommand, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementTerminationCommandValueCodecFieldPath(v *ECIDMeasurementTerminationCommandValueCodec) *aper.Path {
	return &v.path
}
func BridgeECIDMeasurementTerminationCommandValueCodecMethodEncodeBudget(v ECIDMeasurementTerminationCommandValueCodec, a0 ECIDMeasurementTerminationCommand, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeECIDMeasurementTerminationCommandValueCodecMethodEncodeChanged(v ECIDMeasurementTerminationCommandValueCodec, a0 ECIDMeasurementTerminationCommand, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeEUTRANAccessPointPositionAPERValueFieldContext(v *EUTRANAccessPointPositionAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEUTRANAccessPointPositionAPERValueFieldReceived(v *EUTRANAccessPointPositionAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeEUTRANAccessPointPositionAPERValueFieldReplay(v *EUTRANAccessPointPositionAPERValue) *aper.Snapshot {
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
func BridgeEUTRANAccessPointPositionFieldExtOrigin(v *EUTRANAccessPointPosition) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeEUTRANAccessPointPositionFieldExtPresent(v *EUTRANAccessPointPosition) *[]bool {
	return &v.extPresent
}
func BridgeEUTRANAccessPointPositionFieldExtWire(v *EUTRANAccessPointPosition) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeEUTRANAccessPointPositionFieldPerExtPadding(v *EUTRANAccessPointPosition) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeEUTRANAccessPointPositionFieldPerPadding(v *EUTRANAccessPointPosition) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeEUTRANAccessPointPositionFieldReceived(v *EUTRANAccessPointPosition) *bool {
	return &v.received
}
func BridgeEUTRANAccessPointPositionFieldReceivedBytes(v *EUTRANAccessPointPosition) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeEUTRANAccessPointPositionFieldReplay(v *EUTRANAccessPointPosition) *aper.Snapshot {
	return &v.replay
}
func BridgeEUTRANAccessPointPositionFieldStream(v *EUTRANAccessPointPosition) *aper.WireSpan {
	return &v.stream
}
func BridgeEUTRANAccessPointPositionFieldWithoutReplay(v *EUTRANAccessPointPosition) *bool {
	return &v.withoutReplay
}
func BridgeEUTRANAccessPointPositionMethodMarshalAPERBudget(v *EUTRANAccessPointPosition, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeEUTRANAccessPointPositionMethodMarshalAPERChanged(v *EUTRANAccessPointPosition, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeEUTRANAccessPointPositionMethodMarshalAPERChangedValue(v *EUTRANAccessPointPosition, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeEUTRANAccessPointPositionMethodMarshalAPERFreshValue(v *EUTRANAccessPointPosition, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeEUTRANAccessPointPositionMethodMarshalAPERLegacy(v *EUTRANAccessPointPosition) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeEUTRANAccessPointPositionMethodMarshalAPERPlanned(v *EUTRANAccessPointPosition, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeEUTRANAccessPointPositionMethodMarshalAPERTo(v *EUTRANAccessPointPosition, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeEUTRANAccessPointPositionMethodUnmarshalAPERFrom(v *EUTRANAccessPointPosition, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeEUTRANAccessPointPositionMethodUnmarshalAPERLegacy(v *EUTRANAccessPointPosition, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeEUTRANAccessPointPositionMethodUnmarshalAPERWithOptions(v *EUTRANAccessPointPosition, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeEUTRANAccessPointPositionValueCodecFieldCapture(v *EUTRANAccessPointPositionValueCodec) *func(EUTRANAccessPointPosition, aper.DecodeState) (EUTRANAccessPointPosition, aper.Snapshot) {
	return &v.capture
}
func BridgeEUTRANAccessPointPositionValueCodecFieldCompare(v *EUTRANAccessPointPositionValueCodec) *func(EUTRANAccessPointPosition, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeEUTRANAccessPointPositionValueCodecFieldContext(v *EUTRANAccessPointPositionValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeEUTRANAccessPointPositionValueCodecFieldDecode(v *EUTRANAccessPointPositionValueCodec) *func([]byte, aper.DecodeState) (EUTRANAccessPointPosition, error) {
	return &v.decode
}
func BridgeEUTRANAccessPointPositionValueCodecFieldEncode(v *EUTRANAccessPointPositionValueCodec) *func(EUTRANAccessPointPosition, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEUTRANAccessPointPositionValueCodecFieldPath(v *EUTRANAccessPointPositionValueCodec) *aper.Path {
	return &v.path
}
func BridgeEUTRANAccessPointPositionValueCodecMethodEncodeBudget(v EUTRANAccessPointPositionValueCodec, a0 EUTRANAccessPointPosition, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeEUTRANAccessPointPositionValueCodecMethodEncodeChanged(v EUTRANAccessPointPositionValueCodec, a0 EUTRANAccessPointPosition, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInterRATMeasurementQuantitiesAPERValueFieldContext(v *InterRATMeasurementQuantitiesAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterRATMeasurementQuantitiesAPERValueFieldReceived(v *InterRATMeasurementQuantitiesAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInterRATMeasurementQuantitiesAPERValueFieldReplay(v *InterRATMeasurementQuantitiesAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementQuantitiesAPERValueFieldWithoutReplay(v *InterRATMeasurementQuantitiesAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldCapture(v *InterRATMeasurementQuantitiesConcreteValueCodec) *func(InterRATMeasurementQuantities, aper.DecodeState) (InterRATMeasurementQuantities, aper.Snapshot) {
	return &v.capture
}
func BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldCompare(v *InterRATMeasurementQuantitiesConcreteValueCodec) *func(InterRATMeasurementQuantities, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldContext(v *InterRATMeasurementQuantitiesConcreteValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldDecode(v *InterRATMeasurementQuantitiesConcreteValueCodec) *func([]byte, aper.DecodeState) (InterRATMeasurementQuantities, error) {
	return &v.decode
}
func BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldEncode(v *InterRATMeasurementQuantitiesConcreteValueCodec) *func(InterRATMeasurementQuantities, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInterRATMeasurementQuantitiesConcreteValueCodecFieldPath(v *InterRATMeasurementQuantitiesConcreteValueCodec) *aper.Path {
	return &v.path
}
func BridgeInterRATMeasurementQuantitiesConcreteValueCodecMethodEncodeBudget(v InterRATMeasurementQuantitiesConcreteValueCodec, a0 InterRATMeasurementQuantities, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeInterRATMeasurementQuantitiesConcreteValueCodecMethodEncodeChanged(v InterRATMeasurementQuantitiesConcreteValueCodec, a0 InterRATMeasurementQuantities, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInterRATMeasurementQuantitiesItemAPERValueFieldContext(v *InterRATMeasurementQuantitiesItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterRATMeasurementQuantitiesItemAPERValueFieldReceived(v *InterRATMeasurementQuantitiesItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInterRATMeasurementQuantitiesItemAPERValueFieldReplay(v *InterRATMeasurementQuantitiesItemAPERValue) *aper.Snapshot {
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
func BridgeInterRATMeasurementQuantitiesItemFieldExtOrigin(v *InterRATMeasurementQuantitiesItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeInterRATMeasurementQuantitiesItemFieldExtPresent(v *InterRATMeasurementQuantitiesItem) *[]bool {
	return &v.extPresent
}
func BridgeInterRATMeasurementQuantitiesItemFieldExtWire(v *InterRATMeasurementQuantitiesItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeInterRATMeasurementQuantitiesItemFieldIEExtensionsIndef(v *InterRATMeasurementQuantitiesItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeInterRATMeasurementQuantitiesItemFieldPerExtPadding(v *InterRATMeasurementQuantitiesItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeInterRATMeasurementQuantitiesItemFieldPerPadding(v *InterRATMeasurementQuantitiesItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeInterRATMeasurementQuantitiesItemFieldReceived(v *InterRATMeasurementQuantitiesItem) *bool {
	return &v.received
}
func BridgeInterRATMeasurementQuantitiesItemFieldReceivedBytes(v *InterRATMeasurementQuantitiesItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeInterRATMeasurementQuantitiesItemFieldReplay(v *InterRATMeasurementQuantitiesItem) *aper.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementQuantitiesItemFieldStream(v *InterRATMeasurementQuantitiesItem) *aper.WireSpan {
	return &v.stream
}
func BridgeInterRATMeasurementQuantitiesItemFieldWithoutReplay(v *InterRATMeasurementQuantitiesItem) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementQuantitiesItemIEFieldFieldReceived(v *InterRATMeasurementQuantitiesItemIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeInterRATMeasurementQuantitiesItemIEFieldFieldReplay(v *InterRATMeasurementQuantitiesItemIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementQuantitiesItemIEFieldFieldStream(v *InterRATMeasurementQuantitiesItemIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeInterRATMeasurementQuantitiesItemIEFieldFieldWithoutReplay(v *InterRATMeasurementQuantitiesItemIEField) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementQuantitiesItemIEFieldMethodMarshalAPERTo(v *InterRATMeasurementQuantitiesItemIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInterRATMeasurementQuantitiesItemIEFieldMethodUnmarshalAPERFrom(v *InterRATMeasurementQuantitiesItemIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInterRATMeasurementQuantitiesItemIETableMethodInfoInterRATMeasurementQuantitiesItem(v InterRATMeasurementQuantitiesItemIETable) s00.FieldInfo {
	return v.infoInterRATMeasurementQuantitiesItem()
}
func BridgeInterRATMeasurementQuantitiesItemIEValueFieldId(v *InterRATMeasurementQuantitiesItemIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeInterRATMeasurementQuantitiesItemIEValueFieldIsOpaque(v *InterRATMeasurementQuantitiesItemIEValue) *bool {
	return &v.isOpaque
}
func BridgeInterRATMeasurementQuantitiesItemIEValueFieldOpaque(v *InterRATMeasurementQuantitiesItemIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeInterRATMeasurementQuantitiesItemIEValueFieldReceived(v *InterRATMeasurementQuantitiesItemIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeInterRATMeasurementQuantitiesItemIEValueFieldReplay(v *InterRATMeasurementQuantitiesItemIEValue) *aper.Snapshot {
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
func BridgeInterRATMeasurementQuantitiesItemIEValueMethodCaptureSemantics(v InterRATMeasurementQuantitiesItemIEValue, a0 aper.SemanticCapture) InterRATMeasurementQuantitiesItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeInterRATMeasurementQuantitiesItemIEValueMethodCaptureSnapshot(v InterRATMeasurementQuantitiesItemIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeInterRATMeasurementQuantitiesItemIEValueMethodCompareSemantics(v InterRATMeasurementQuantitiesItemIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeInterRATMeasurementQuantitiesItemIEValueMethodDecode(v InterRATMeasurementQuantitiesItemIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (InterRATMeasurementQuantitiesItemIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesItemIEValueMethodEncode(v InterRATMeasurementQuantitiesItemIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeInterRATMeasurementQuantitiesItemIEValueMethodEncodeFresh(v InterRATMeasurementQuantitiesItemIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesItemIEValueMethodMatchesID(v InterRATMeasurementQuantitiesItemIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesItemIEValueMethodReason(v InterRATMeasurementQuantitiesItemIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeInterRATMeasurementQuantitiesItemIEValueMethodRule(v InterRATMeasurementQuantitiesItemIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeInterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBindingFieldCodec(v *InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding) *InterRATMeasurementQuantitiesItemValueCodec {
	return &v.codec
}
func BridgeInterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBindingFieldGet(v *InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding) *func(*InterRATMeasurementQuantitiesItemIEValue) (*InterRATMeasurementQuantitiesItem, bool) {
	return &v.get
}
func BridgeInterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBindingFieldInfo(v *InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBindingFieldInject(v *InterRATMeasurementQuantitiesItemInterRATMeasurementQuantitiesItemIEBinding) *func(InterRATMeasurementQuantitiesItem) InterRATMeasurementQuantitiesItemIEValue {
	return &v.inject
}
func BridgeInterRATMeasurementQuantitiesItemMethodMarshalAPERBudget(v *InterRATMeasurementQuantitiesItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesItemMethodMarshalAPERChanged(v *InterRATMeasurementQuantitiesItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeInterRATMeasurementQuantitiesItemMethodMarshalAPERChangedValue(v *InterRATMeasurementQuantitiesItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeInterRATMeasurementQuantitiesItemMethodMarshalAPERFreshValue(v *InterRATMeasurementQuantitiesItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesItemMethodMarshalAPERLegacy(v *InterRATMeasurementQuantitiesItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeInterRATMeasurementQuantitiesItemMethodMarshalAPERPlanned(v *InterRATMeasurementQuantitiesItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesItemMethodMarshalAPERTo(v *InterRATMeasurementQuantitiesItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInterRATMeasurementQuantitiesItemMethodUnmarshalAPERFrom(v *InterRATMeasurementQuantitiesItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInterRATMeasurementQuantitiesItemMethodUnmarshalAPERLegacy(v *InterRATMeasurementQuantitiesItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeInterRATMeasurementQuantitiesItemMethodUnmarshalAPERWithOptions(v *InterRATMeasurementQuantitiesItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesItemValueCodecFieldCapture(v *InterRATMeasurementQuantitiesItemValueCodec) *func(InterRATMeasurementQuantitiesItem, aper.DecodeState) (InterRATMeasurementQuantitiesItem, aper.Snapshot) {
	return &v.capture
}
func BridgeInterRATMeasurementQuantitiesItemValueCodecFieldCompare(v *InterRATMeasurementQuantitiesItemValueCodec) *func(InterRATMeasurementQuantitiesItem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeInterRATMeasurementQuantitiesItemValueCodecFieldContext(v *InterRATMeasurementQuantitiesItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterRATMeasurementQuantitiesItemValueCodecFieldDecode(v *InterRATMeasurementQuantitiesItemValueCodec) *func([]byte, aper.DecodeState) (InterRATMeasurementQuantitiesItem, error) {
	return &v.decode
}
func BridgeInterRATMeasurementQuantitiesItemValueCodecFieldEncode(v *InterRATMeasurementQuantitiesItemValueCodec) *func(InterRATMeasurementQuantitiesItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInterRATMeasurementQuantitiesItemValueCodecFieldPath(v *InterRATMeasurementQuantitiesItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeInterRATMeasurementQuantitiesItemValueCodecMethodEncodeBudget(v InterRATMeasurementQuantitiesItemValueCodec, a0 InterRATMeasurementQuantitiesItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeInterRATMeasurementQuantitiesItemValueCodecMethodEncodeChanged(v InterRATMeasurementQuantitiesItemValueCodec, a0 InterRATMeasurementQuantitiesItem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMeasurementQuantitiesAPERValueFieldContext(v *MeasurementQuantitiesAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementQuantitiesAPERValueFieldReceived(v *MeasurementQuantitiesAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMeasurementQuantitiesAPERValueFieldReplay(v *MeasurementQuantitiesAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMeasurementQuantitiesAPERValueFieldWithoutReplay(v *MeasurementQuantitiesAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementQuantitiesConcreteValueCodecFieldCapture(v *MeasurementQuantitiesConcreteValueCodec) *func(MeasurementQuantities, aper.DecodeState) (MeasurementQuantities, aper.Snapshot) {
	return &v.capture
}
func BridgeMeasurementQuantitiesConcreteValueCodecFieldCompare(v *MeasurementQuantitiesConcreteValueCodec) *func(MeasurementQuantities, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeMeasurementQuantitiesConcreteValueCodecFieldContext(v *MeasurementQuantitiesConcreteValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementQuantitiesConcreteValueCodecFieldDecode(v *MeasurementQuantitiesConcreteValueCodec) *func([]byte, aper.DecodeState) (MeasurementQuantities, error) {
	return &v.decode
}
func BridgeMeasurementQuantitiesConcreteValueCodecFieldEncode(v *MeasurementQuantitiesConcreteValueCodec) *func(MeasurementQuantities, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMeasurementQuantitiesConcreteValueCodecFieldPath(v *MeasurementQuantitiesConcreteValueCodec) *aper.Path {
	return &v.path
}
func BridgeMeasurementQuantitiesConcreteValueCodecMethodEncodeBudget(v MeasurementQuantitiesConcreteValueCodec, a0 MeasurementQuantities, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeMeasurementQuantitiesConcreteValueCodecMethodEncodeChanged(v MeasurementQuantitiesConcreteValueCodec, a0 MeasurementQuantities, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMeasurementQuantitiesItemAPERValueFieldContext(v *MeasurementQuantitiesItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementQuantitiesItemAPERValueFieldReceived(v *MeasurementQuantitiesItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMeasurementQuantitiesItemAPERValueFieldReplay(v *MeasurementQuantitiesItemAPERValue) *aper.Snapshot {
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
func BridgeMeasurementQuantitiesItemFieldExtOrigin(v *MeasurementQuantitiesItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeMeasurementQuantitiesItemFieldExtPresent(v *MeasurementQuantitiesItem) *[]bool {
	return &v.extPresent
}
func BridgeMeasurementQuantitiesItemFieldExtWire(v *MeasurementQuantitiesItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeMeasurementQuantitiesItemFieldIEExtensionsIndef(v *MeasurementQuantitiesItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeMeasurementQuantitiesItemFieldPerExtPadding(v *MeasurementQuantitiesItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeMeasurementQuantitiesItemFieldPerPadding(v *MeasurementQuantitiesItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeMeasurementQuantitiesItemFieldReceived(v *MeasurementQuantitiesItem) *bool {
	return &v.received
}
func BridgeMeasurementQuantitiesItemFieldReceivedBytes(v *MeasurementQuantitiesItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMeasurementQuantitiesItemFieldReplay(v *MeasurementQuantitiesItem) *aper.Snapshot {
	return &v.replay
}
func BridgeMeasurementQuantitiesItemFieldStream(v *MeasurementQuantitiesItem) *aper.WireSpan {
	return &v.stream
}
func BridgeMeasurementQuantitiesItemFieldWithoutReplay(v *MeasurementQuantitiesItem) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementQuantitiesItemIEFieldFieldReceived(v *MeasurementQuantitiesItemIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeMeasurementQuantitiesItemIEFieldFieldReplay(v *MeasurementQuantitiesItemIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeMeasurementQuantitiesItemIEFieldFieldStream(v *MeasurementQuantitiesItemIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeMeasurementQuantitiesItemIEFieldFieldWithoutReplay(v *MeasurementQuantitiesItemIEField) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementQuantitiesItemIEFieldMethodMarshalAPERTo(v *MeasurementQuantitiesItemIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMeasurementQuantitiesItemIEFieldMethodUnmarshalAPERFrom(v *MeasurementQuantitiesItemIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMeasurementQuantitiesItemIEValueFieldId(v *MeasurementQuantitiesItemIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeMeasurementQuantitiesItemIEValueFieldIsOpaque(v *MeasurementQuantitiesItemIEValue) *bool {
	return &v.isOpaque
}
func BridgeMeasurementQuantitiesItemIEValueFieldOpaque(v *MeasurementQuantitiesItemIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeMeasurementQuantitiesItemIEValueFieldReceived(v *MeasurementQuantitiesItemIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeMeasurementQuantitiesItemIEValueFieldReplay(v *MeasurementQuantitiesItemIEValue) *aper.Snapshot {
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
func BridgeMeasurementQuantitiesItemIEValueMethodCaptureSemantics(v MeasurementQuantitiesItemIEValue, a0 aper.SemanticCapture) MeasurementQuantitiesItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeMeasurementQuantitiesItemIEValueMethodCaptureSnapshot(v MeasurementQuantitiesItemIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeMeasurementQuantitiesItemIEValueMethodCompareSemantics(v MeasurementQuantitiesItemIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeMeasurementQuantitiesItemIEValueMethodDecode(v MeasurementQuantitiesItemIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (MeasurementQuantitiesItemIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeMeasurementQuantitiesItemIEValueMethodEncode(v MeasurementQuantitiesItemIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeMeasurementQuantitiesItemIEValueMethodEncodeFresh(v MeasurementQuantitiesItemIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeMeasurementQuantitiesItemIEValueMethodMatchesID(v MeasurementQuantitiesItemIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeMeasurementQuantitiesItemIEValueMethodReason(v MeasurementQuantitiesItemIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeMeasurementQuantitiesItemIEValueMethodRule(v MeasurementQuantitiesItemIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeMeasurementQuantitiesItemMeasurementQuantitiesItemIEBindingFieldCodec(v *MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding) *MeasurementQuantitiesItemValueCodec {
	return &v.codec
}
func BridgeMeasurementQuantitiesItemMeasurementQuantitiesItemIEBindingFieldGet(v *MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding) *func(*MeasurementQuantitiesItemIEValue) (*MeasurementQuantitiesItem, bool) {
	return &v.get
}
func BridgeMeasurementQuantitiesItemMeasurementQuantitiesItemIEBindingFieldInfo(v *MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeMeasurementQuantitiesItemMeasurementQuantitiesItemIEBindingFieldInject(v *MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding) *func(MeasurementQuantitiesItem) MeasurementQuantitiesItemIEValue {
	return &v.inject
}
func BridgeMeasurementQuantitiesItemMethodMarshalAPERBudget(v *MeasurementQuantitiesItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMeasurementQuantitiesItemMethodMarshalAPERChanged(v *MeasurementQuantitiesItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMeasurementQuantitiesItemMethodMarshalAPERChangedValue(v *MeasurementQuantitiesItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMeasurementQuantitiesItemMethodMarshalAPERFreshValue(v *MeasurementQuantitiesItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeMeasurementQuantitiesItemMethodMarshalAPERLegacy(v *MeasurementQuantitiesItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMeasurementQuantitiesItemMethodMarshalAPERPlanned(v *MeasurementQuantitiesItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeMeasurementQuantitiesItemMethodMarshalAPERTo(v *MeasurementQuantitiesItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMeasurementQuantitiesItemMethodUnmarshalAPERFrom(v *MeasurementQuantitiesItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMeasurementQuantitiesItemMethodUnmarshalAPERLegacy(v *MeasurementQuantitiesItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMeasurementQuantitiesItemMethodUnmarshalAPERWithOptions(v *MeasurementQuantitiesItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMeasurementQuantitiesItemValueCodecFieldCapture(v *MeasurementQuantitiesItemValueCodec) *func(MeasurementQuantitiesItem, aper.DecodeState) (MeasurementQuantitiesItem, aper.Snapshot) {
	return &v.capture
}
func BridgeMeasurementQuantitiesItemValueCodecFieldCompare(v *MeasurementQuantitiesItemValueCodec) *func(MeasurementQuantitiesItem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeMeasurementQuantitiesItemValueCodecFieldContext(v *MeasurementQuantitiesItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementQuantitiesItemValueCodecFieldDecode(v *MeasurementQuantitiesItemValueCodec) *func([]byte, aper.DecodeState) (MeasurementQuantitiesItem, error) {
	return &v.decode
}
func BridgeMeasurementQuantitiesItemValueCodecFieldEncode(v *MeasurementQuantitiesItemValueCodec) *func(MeasurementQuantitiesItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMeasurementQuantitiesItemValueCodecFieldPath(v *MeasurementQuantitiesItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeMeasurementQuantitiesItemValueCodecMethodEncodeBudget(v MeasurementQuantitiesItemValueCodec, a0 MeasurementQuantitiesItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeMeasurementQuantitiesItemValueCodecMethodEncodeChanged(v MeasurementQuantitiesItemValueCodec, a0 MeasurementQuantitiesItem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
