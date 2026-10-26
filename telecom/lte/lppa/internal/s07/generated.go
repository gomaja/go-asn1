// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s07 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s07

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// OTDOAInformationTypeIEValueProtocolIESingleContainer is ProtocolIE-Single-Container {{OTDOA-Information-TypeIEs}} of TS 36.455: a single field carrying a value of OTDOAInformationTypeIEValue.
type OTDOAInformationTypeIEValueProtocolIESingleContainer = OTDOAInformationTypeIEField

// NRCGIValueCodec is the concrete ValueCodec[NRCGI].
type NRCGIValueCodec struct {
	context s00.BridgeCodecContext
	capture func(NRCGI, aper.DecodeState,

	) (NRCGI, aper.Snapshot,

	)
	compare func(NRCGI, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (NRCGI,

		error)
	encode func(NRCGI,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c NRCGIValueCodec) New(value NRCGI,

) (NRCGIAPERValue, error) {
	if c.encode == nil {
		return NRCGIAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NRCGIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRCGIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return NRCGIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c NRCGIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NRCGIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NRCGIAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return NRCGIAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NRCGIAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return NRCGIAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return NRCGIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c NRCGIValueCodec) EncodeAPER(value NRCGIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NRCGIValueCodec) encodeBudget(value NRCGI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NRCGIValueCodec) encodeChanged(value NRCGI,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// OTDOAInformationTypeOTDOAInformationTypeItemIEBinding binds OTDOAInformationTypeItem to ProtocolIE-Field {{OTDOA-Information-TypeIEs}} of TS 36.455.
type OTDOAInformationTypeOTDOAInformationTypeItemIEBinding struct {
	info   s00.FieldInfo
	codec  OTDOAInformationTypeItemValueCodec
	inject func(OTDOAInformationTypeItem,

	) OTDOAInformationTypeIEValue

	get func(*OTDOAInformationTypeIEValue,

	) (*OTDOAInformationTypeItem,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b OTDOAInformationTypeOTDOAInformationTypeItemIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b OTDOAInformationTypeOTDOAInformationTypeItemIEBinding) Codec() OTDOAInformationTypeItemValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b OTDOAInformationTypeOTDOAInformationTypeItemIEBinding) New(value OTDOAInformationTypeItem,

) (OTDOAInformationTypeIEField, error) {
	if b.inject == nil {
		return OTDOAInformationTypeIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OTDOAInformationTypeIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return OTDOAInformationTypeIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return OTDOAInformationTypeIEField{}, aper.OperationError(err, "Value.New")
	}
	return OTDOAInformationTypeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b OTDOAInformationTypeOTDOAInformationTypeItemIEBinding) Get(field *OTDOAInformationTypeIEField) (*OTDOAInformationTypeItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// OTDOAInformationTypeItemValueCodec is the concrete ValueCodec[OTDOAInformationTypeItem].
type OTDOAInformationTypeItemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(OTDOAInformationTypeItem, aper.DecodeState,

	) (OTDOAInformationTypeItem, aper.Snapshot,

	)
	compare func(OTDOAInformationTypeItem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (OTDOAInformationTypeItem,

		error)
	encode func(OTDOAInformationTypeItem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c OTDOAInformationTypeItemValueCodec) New(value OTDOAInformationTypeItem,

) (OTDOAInformationTypeItemAPERValue, error) {
	if c.encode == nil {
		return OTDOAInformationTypeItemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OTDOAInformationTypeItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOAInformationTypeItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return OTDOAInformationTypeItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c OTDOAInformationTypeItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OTDOAInformationTypeItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOAInformationTypeItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return OTDOAInformationTypeItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOAInformationTypeItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return OTDOAInformationTypeItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return OTDOAInformationTypeItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c OTDOAInformationTypeItemValueCodec) EncodeAPER(value OTDOAInformationTypeItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OTDOAInformationTypeItemValueCodec) encodeBudget(value OTDOAInformationTypeItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOAInformationTypeItemValueCodec) encodeChanged(value OTDOAInformationTypeItem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// OTDOAInformationTypeIEField is ProtocolIE-Field {{OTDOA-Information-TypeIEs}} of TS 36.455: a field carrying a value of OTDOAInformationTypeIEValue.
type OTDOAInformationTypeIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         OTDOAInformationTypeIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOAInformationTypeIEField) WithoutReplay() OTDOAInformationTypeIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *OTDOAInformationTypeIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *OTDOAInformationTypeIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *OTDOAInformationTypeIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationTypeIEField{}
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
	var zero OTDOAInformationTypeIEValue

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

// OTDOAInformationTypeValueCodec is the concrete ValueCodec[OTDOAInformationType].
type OTDOAInformationTypeValueCodec struct {
	context s00.BridgeCodecContext
	capture func(OTDOAInformationType, aper.DecodeState,

	) (OTDOAInformationType, aper.Snapshot,

	)
	compare func(OTDOAInformationType, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (OTDOAInformationType,

		error)
	encode func(OTDOAInformationType,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c OTDOAInformationTypeValueCodec) New(value OTDOAInformationType,

) (OTDOAInformationTypeAPERValue, error) {
	if c.encode == nil {
		return OTDOAInformationTypeAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OTDOAInformationTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOAInformationTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return OTDOAInformationTypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c OTDOAInformationTypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OTDOAInformationTypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOAInformationTypeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return OTDOAInformationTypeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOAInformationTypeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return OTDOAInformationTypeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return OTDOAInformationTypeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c OTDOAInformationTypeValueCodec) EncodeAPER(value OTDOAInformationTypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OTDOAInformationTypeValueCodec) encodeBudget(value OTDOAInformationType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOAInformationTypeValueCodec) encodeChanged(value OTDOAInformationType,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// NPRSConfigurationValueCodec is the concrete ValueCodec[NPRSConfiguration].
type NPRSConfigurationValueCodec struct {
	context s00.BridgeCodecContext
	capture func(NPRSConfiguration, aper.DecodeState,

	) (NPRSConfiguration, aper.Snapshot,

	)
	compare func(NPRSConfiguration, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (NPRSConfiguration,

		error)
	encode func(NPRSConfiguration,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c NPRSConfigurationValueCodec) New(value NPRSConfiguration,

) (NPRSConfigurationAPERValue, error) {
	if c.encode == nil {
		return NPRSConfigurationAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NPRSConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NPRSConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return NPRSConfigurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c NPRSConfigurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NPRSConfigurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NPRSConfigurationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return NPRSConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NPRSConfigurationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return NPRSConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return NPRSConfigurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c NPRSConfigurationValueCodec) EncodeAPER(value NPRSConfigurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NPRSConfigurationValueCodec) encodeBudget(value NPRSConfiguration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NPRSConfigurationValueCodec) encodeChanged(value NPRSConfiguration,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// NPRSMutingConfigurationValueCodec is the concrete ValueCodec[NPRSMutingConfiguration].
type NPRSMutingConfigurationValueCodec struct {
	context s00.BridgeCodecContext
	capture func(NPRSMutingConfiguration, aper.DecodeState,

	) (NPRSMutingConfiguration, aper.Snapshot,

	)
	compare func(NPRSMutingConfiguration, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (NPRSMutingConfiguration,

		error)
	encode func(NPRSMutingConfiguration,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c NPRSMutingConfigurationValueCodec) New(value NPRSMutingConfiguration,

) (NPRSMutingConfigurationAPERValue, error) {
	if c.encode == nil {
		return NPRSMutingConfigurationAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NPRSMutingConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NPRSMutingConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return NPRSMutingConfigurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c NPRSMutingConfigurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NPRSMutingConfigurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NPRSMutingConfigurationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return NPRSMutingConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NPRSMutingConfigurationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return NPRSMutingConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return NPRSMutingConfigurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c NPRSMutingConfigurationValueCodec) EncodeAPER(value NPRSMutingConfigurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NPRSMutingConfigurationValueCodec) encodeBudget(value NPRSMutingConfiguration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NPRSMutingConfigurationValueCodec) encodeChanged(value NPRSMutingConfiguration,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// NPRSSubframePartAValueCodec is the concrete ValueCodec[NPRSSubframePartA].
type NPRSSubframePartAValueCodec struct {
	context s00.BridgeCodecContext
	capture func(NPRSSubframePartA, aper.DecodeState,

	) (NPRSSubframePartA, aper.Snapshot,

	)
	compare func(NPRSSubframePartA, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (NPRSSubframePartA,

		error)
	encode func(NPRSSubframePartA,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c NPRSSubframePartAValueCodec) New(value NPRSSubframePartA,

) (NPRSSubframePartAAPERValue, error) {
	if c.encode == nil {
		return NPRSSubframePartAAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NPRSSubframePartAAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NPRSSubframePartAAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return NPRSSubframePartAAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c NPRSSubframePartAValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NPRSSubframePartAAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NPRSSubframePartAAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return NPRSSubframePartAAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NPRSSubframePartAAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return NPRSSubframePartAAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return NPRSSubframePartAAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c NPRSSubframePartAValueCodec) EncodeAPER(value NPRSSubframePartAAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NPRSSubframePartAValueCodec) encodeBudget(value NPRSSubframePartA,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NPRSSubframePartAValueCodec) encodeChanged(value NPRSSubframePartA,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// NPRSSubframePartBValueCodec is the concrete ValueCodec[NPRSSubframePartB].
type NPRSSubframePartBValueCodec struct {
	context s00.BridgeCodecContext
	capture func(NPRSSubframePartB, aper.DecodeState,

	) (NPRSSubframePartB, aper.Snapshot,

	)
	compare func(NPRSSubframePartB, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (NPRSSubframePartB,

		error)
	encode func(NPRSSubframePartB,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c NPRSSubframePartBValueCodec) New(value NPRSSubframePartB,

) (NPRSSubframePartBAPERValue, error) {
	if c.encode == nil {
		return NPRSSubframePartBAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NPRSSubframePartBAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NPRSSubframePartBAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return NPRSSubframePartBAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c NPRSSubframePartBValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NPRSSubframePartBAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NPRSSubframePartBAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return NPRSSubframePartBAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NPRSSubframePartBAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return NPRSSubframePartBAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return NPRSSubframePartBAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c NPRSSubframePartBValueCodec) EncodeAPER(value NPRSSubframePartBAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NPRSSubframePartBValueCodec) encodeBudget(value NPRSSubframePartB,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NPRSSubframePartBValueCodec) encodeChanged(value NPRSSubframePartB,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// OTDOAInformationTypeIEContainer is ProtocolIE-Container {{OTDOA-Information-TypeIEs}} of TS 36.455: a list of OTDOAInformationTypeIEField values.
type OTDOAInformationTypeIEContainer []OTDOAInformationTypeIEField

// NRCGIAPERValue is the concrete APERValue[NRCGI].
type NRCGIAPERValue struct {
	context s00.BridgeCodecContext
	Value   NRCGI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v NRCGIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v NRCGIAPERValue) WithoutReplay() NRCGIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OTDOAInformationTypeItemAPERValue is the concrete APERValue[OTDOAInformationTypeItem].
type OTDOAInformationTypeItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   OTDOAInformationTypeItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v OTDOAInformationTypeItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOAInformationTypeItemAPERValue) WithoutReplay() OTDOAInformationTypeItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OTDOAInformationTypeAPERValue is the concrete APERValue[OTDOAInformationType].
type OTDOAInformationTypeAPERValue struct {
	context s00.BridgeCodecContext
	Value   OTDOAInformationType

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v OTDOAInformationTypeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOAInformationTypeAPERValue) WithoutReplay() OTDOAInformationTypeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NPRSConfigurationAPERValue is the concrete APERValue[NPRSConfiguration].
type NPRSConfigurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   NPRSConfiguration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v NPRSConfigurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v NPRSConfigurationAPERValue) WithoutReplay() NPRSConfigurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NPRSMutingConfigurationAPERValue is the concrete APERValue[NPRSMutingConfiguration].
type NPRSMutingConfigurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   NPRSMutingConfiguration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v NPRSMutingConfigurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v NPRSMutingConfigurationAPERValue) WithoutReplay() NPRSMutingConfigurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NPRSSubframePartAAPERValue is the concrete APERValue[NPRSSubframePartA].
type NPRSSubframePartAAPERValue struct {
	context s00.BridgeCodecContext
	Value   NPRSSubframePartA

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v NPRSSubframePartAAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v NPRSSubframePartAAPERValue) WithoutReplay() NPRSSubframePartAAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NPRSSubframePartBAPERValue is the concrete APERValue[NPRSSubframePartB].
type NPRSSubframePartBAPERValue struct {
	context s00.BridgeCodecContext
	Value   NPRSSubframePartB

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v NPRSSubframePartBAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v NPRSSubframePartBAPERValue) WithoutReplay() NPRSSubframePartBAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRCGI represents the ASN.1 type NR-CGI (SEQUENCE).
type NRCGI struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     aper.WireSpan
	PLMNIdentity      s00.PLMNIdentity            `asn1:"tag:0,context,implicit"`
	NRCellIdentity    s00.NRCellIdentity          `asn1:"tag:1,context,implicit"`
	IEExtensions      s04.NRCGIExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                        `asn1:"-" json:"-"`
	extCount          int64                       `asn1:"-" json:"-"`
	extPresent        []bool                      `asn1:"-" json:"-"`
	extData           [][]byte                    `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding           `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding      `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// NPRSConfiguration represents the ASN.1 type NPRSConfiguration (SEQUENCE).
type NPRSConfiguration struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     aper.WireSpan
	NPRSSubframePartA *NPRSSubframePartA     `asn1:"tag:0,context,implicit,optional" json:"NPRSSubframePartA,omitempty"`
	NPRSSubframePartB *NPRSSubframePartB     `asn1:"tag:1,context,implicit,optional" json:"NPRSSubframePartB,omitempty"`
	extCount          int64                  `asn1:"-" json:"-"`
	extPresent        []bool                 `asn1:"-" json:"-"`
	extData           [][]byte               `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// NPRSMutingConfiguration represents the ASN.1 CHOICE type NPRSMutingConfiguration.
type NPRSMutingConfiguration struct {
	knownOpenBytes     uint64
	replay             aper.Snapshot
	stream             aper.WireSpan
	withoutReplay      bool
	received           bool
	receivedBytes      aper.WireSpan
	Choice             int
	perPadding         aper.CompletePadding  `json:"-"`
	perOpenTypePadding aper.CompletePadding  `json:"-"`
	UnknownExtension   *aper.ChoiceExtension `json:"UnknownExtension,omitempty"`
	Two                *runtime.BitString    `json:"Two,omitempty"`
	Four               *runtime.BitString    `json:"Four,omitempty"`
	Eight              *runtime.BitString    `json:"Eight,omitempty"`
	Sixteen            *runtime.BitString    `json:"Sixteen,omitempty"`
}

// NPRSSubframePartA represents the ASN.1 type NPRSSubframePartA (SEQUENCE).
type NPRSSubframePartA struct {
	replay                  aper.Snapshot
	stream                  aper.WireSpan
	withoutReplay           bool
	received                bool
	receivedBytes           aper.WireSpan
	BitmapsforNPRS          s05.BitmapsforNPRS       `asn1:"tag:0,context,explicit"`
	NPRSMutingConfiguration *NPRSMutingConfiguration `asn1:"tag:1,context,explicit,optional" json:"NPRSMutingConfiguration,omitempty"`
	extCount                int64                    `asn1:"-" json:"-"`
	extPresent              []bool                   `asn1:"-" json:"-"`
	extData                 [][]byte                 `asn1:"-" json:"-"`
	perPadding              aper.FinalPadding        `asn1:"-" json:"-"`
	perExtPadding           []aper.CompletePadding   `asn1:"-" json:"-"`
	extOrigin               []aper.OpaqueOrigin
	extWire                 []aper.WireSpan
}

// NPRSSubframePartB represents the ASN.1 type NPRSSubframePartB (SEQUENCE).
type NPRSSubframePartB struct {
	knownOpenBytes          uint64
	replay                  aper.Snapshot
	stream                  aper.WireSpan
	withoutReplay           bool
	received                bool
	receivedBytes           aper.WireSpan
	NumberofNPRSOneOccasion int64                    `asn1:"tag:0,context,implicit"`
	PeriodicityofNPRS       int64                    `asn1:"tag:1,context,implicit"`
	Startingsubframeoffset  int64                    `asn1:"tag:2,context,implicit"`
	NPRSMutingConfiguration *NPRSMutingConfiguration `asn1:"tag:3,context,explicit,optional" json:"NPRSMutingConfiguration,omitempty"`
	SIB1NBSubframeTDD       *int64                   `asn1:"tag:4,context,implicit,optional" json:"SIB1NBSubframeTDD,omitempty"`
	extCount                int64                    `asn1:"-" json:"-"`
	extPresent              []bool                   `asn1:"-" json:"-"`
	extData                 [][]byte                 `asn1:"-" json:"-"`
	perPadding              aper.FinalPadding        `asn1:"-" json:"-"`
	perExtPadding           []aper.CompletePadding   `asn1:"-" json:"-"`
	extOrigin               []aper.OpaqueOrigin
	extWire                 []aper.WireSpan
}

// MarshalAPER encodes NRCGI to APER format.
func (v *NRCGI) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *NRCGI) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.PLMNIdentity), 3, 3, true); err != nil {
		return fmt.Errorf("encoding pLMN-Identity: %w", err)
	}
	if err := aper.EncodeBitStringAligned(bb, v.NRCellIdentity.Bytes, v.NRCellIdentity.BitLength, 36, 36, true); err != nil {
		return fmt.Errorf("encoding nRCellIdentity: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s04.BridgeNRCGIExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes NRCGI from APER format.
func (v *NRCGI) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *NRCGI) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "NRCGI")
	}
	bb.EnterComponent("NRCGI")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NRCGI")
	}
	padding, err := aper.CaptureFinalBits(bb, "NRCGI")
	if err != nil {
		return runtime.WrapDecodePath(err, "NRCGI")
	}
	v.perPadding = padding
	return nil
}
func (v *NRCGI) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NRCGI{}
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
	val_plmnidentity, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PLMNIdentity")
	}
	v.PLMNIdentity = s00.PLMNIdentity(val_plmnidentity)
	bsBytes_nrcellidentity, bsBitLen_nrcellidentity, err := aper.DecodeBitStringAligned(bb, 36, 36, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "NRCellIdentity")
	}
	v.NRCellIdentity = runtime.BitString{Bytes: bsBytes_nrcellidentity, BitLength: bsBitLen_nrcellidentity}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s04.NRCGIExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s04.NRCGIExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s04.BridgeNRCGIExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes NPRSConfiguration to APER format.
func (v *NPRSConfiguration) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *NPRSConfiguration) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.NPRSSubframePartA != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.NPRSSubframePartB != nil); err != nil {
		return err
	}
	if v.NPRSSubframePartA != nil {
		if err := v.NPRSSubframePartA.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding nPRSSubframePartA: %w", err)
		}
	}
	if v.NPRSSubframePartB != nil {
		if err := v.NPRSSubframePartB.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding nPRSSubframePartB: %w", err)
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

// UnmarshalAPER decodes NPRSConfiguration from APER format.
func (v *NPRSConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *NPRSConfiguration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "NPRSConfiguration")
	}
	bb.EnterComponent("NPRSConfiguration")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NPRSConfiguration")
	}
	padding, err := aper.CaptureFinalBits(bb, "NPRSConfiguration")
	if err != nil {
		return runtime.WrapDecodePath(err, "NPRSConfiguration")
	}
	v.perPadding = padding
	return nil
}
func (v *NPRSConfiguration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NPRSConfiguration{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_nprssubframeparta, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_nprssubframepartb, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_nprssubframeparta {
		toleranceMark_nprssubframeparta := bb.EnterComponent("NPRSSubframePartA")
		var dec_nprssubframeparta NPRSSubframePartA
		if err := dec_nprssubframeparta.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NPRSSubframePartA")
		}
		if err := aper.ChargeValue(bb, dec_nprssubframeparta); err != nil {
			return err
		}
		v.NPRSSubframePartA = &dec_nprssubframeparta
		bb.LeaveComponent(toleranceMark_nprssubframeparta)
	}
	if opt_nprssubframepartb {
		toleranceMark_nprssubframepartb := bb.EnterComponent("NPRSSubframePartB")
		var dec_nprssubframepartb NPRSSubframePartB
		if err := dec_nprssubframepartb.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NPRSSubframePartB")
		}
		if err := aper.ChargeValue(bb, dec_nprssubframepartb); err != nil {
			return err
		}
		v.NPRSSubframePartB = &dec_nprssubframepartb
		bb.LeaveComponent(toleranceMark_nprssubframepartb)
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

// MarshalAPER encodes NPRSMutingConfiguration to APER format.
func (v *NPRSMutingConfiguration) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *NPRSMutingConfiguration) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.
		withoutReplay {
		if ok, err := v.replay.ReplayTo(v.stream, bb); ok || err != nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "NPRSMutingConfiguration:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "NPRSMutingConfiguration:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "NPRSMutingConfiguration:", v.Choice)
	}
	isExtension := v.Choice > 4
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "NPRSMutingConfiguration:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 3); err != nil {
		return err
	}
	switch v.Choice {
	case s00.NPRSMutingConfigurationChoiceTwo:
		if v.Two == nil {
			return fmt.Errorf("choice alternative two is nil")
		}
		if err := aper.EncodeBitStringAligned(bb, v.Two.Bytes, v.Two.BitLength, 2, 2, true); err != nil {
			return fmt.Errorf("encoding two: %w", err)
		}
	case s00.NPRSMutingConfigurationChoiceFour:
		if v.Four == nil {
			return fmt.Errorf("choice alternative four is nil")
		}
		if err := aper.EncodeBitStringAligned(bb, v.Four.Bytes, v.Four.BitLength, 4, 4, true); err != nil {
			return fmt.Errorf("encoding four: %w", err)
		}
	case s00.NPRSMutingConfigurationChoiceEight:
		if v.Eight == nil {
			return fmt.Errorf("choice alternative eight is nil")
		}
		if err := aper.EncodeBitStringAligned(bb, v.Eight.Bytes, v.Eight.BitLength, 8, 8, true); err != nil {
			return fmt.Errorf("encoding eight: %w", err)
		}
	case s00.NPRSMutingConfigurationChoiceSixteen:
		if v.Sixteen == nil {
			return fmt.Errorf("choice alternative sixteen is nil")
		}
		if err := aper.EncodeBitStringAligned(bb, v.Sixteen.Bytes, v.Sixteen.BitLength, 16, 16, true); err != nil {
			return fmt.Errorf("encoding sixteen: %w", err)
		}
	default:
		return fmt.Errorf("unknown NPRSMutingConfiguration choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes NPRSMutingConfiguration from APER format.
func (v *NPRSMutingConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *NPRSMutingConfiguration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "NPRSMutingConfiguration")
	}
	bb.EnterComponent("NPRSMutingConfiguration")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NPRSMutingConfiguration")
	}
	padding, err := aper.CaptureFinalBits(bb, "NPRSMutingConfiguration")
	if err != nil {
		return runtime.WrapDecodePath(err, "NPRSMutingConfiguration")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *NPRSMutingConfiguration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NPRSMutingConfiguration{}
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
		v.
			stream.RecordUsage(replayUsage,

			bb)

		return nil
	}
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 3)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.NPRSMutingConfigurationChoiceTwo:
		bsBytes_two, bsBitLen_two, err := aper.DecodeBitStringAligned(bb, 2, 2, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Two")
		}
		tmp_two := runtime.BitString{Bytes: bsBytes_two, BitLength: bsBitLen_two}
		if err := aper.ChargeValue(bb, tmp_two); err != nil {
			return err
		}
		v.Two = &tmp_two
	case s00.NPRSMutingConfigurationChoiceFour:
		bsBytes_four, bsBitLen_four, err := aper.DecodeBitStringAligned(bb, 4, 4, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Four")
		}
		tmp_four := runtime.BitString{Bytes: bsBytes_four, BitLength: bsBitLen_four}
		if err := aper.ChargeValue(bb, tmp_four); err != nil {
			return err
		}
		v.Four = &tmp_four
	case s00.NPRSMutingConfigurationChoiceEight:
		bsBytes_eight, bsBitLen_eight, err := aper.DecodeBitStringAligned(bb, 8, 8, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Eight")
		}
		tmp_eight := runtime.BitString{Bytes: bsBytes_eight, BitLength: bsBitLen_eight}
		if err := aper.ChargeValue(bb, tmp_eight); err != nil {
			return err
		}
		v.Eight = &tmp_eight
	case s00.NPRSMutingConfigurationChoiceSixteen:
		bsBytes_sixteen, bsBitLen_sixteen, err := aper.DecodeBitStringAligned(bb, 16, 16, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Sixteen")
		}
		tmp_sixteen := runtime.BitString{Bytes: bsBytes_sixteen, BitLength: bsBitLen_sixteen}
		if err := aper.ChargeValue(bb, tmp_sixteen); err != nil {
			return err
		}
		v.Sixteen = &tmp_sixteen
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// MarshalAPER encodes NPRSSubframePartA to APER format.
func (v *NPRSSubframePartA) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *NPRSSubframePartA) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.NPRSMutingConfiguration != nil); err != nil {
		return err
	}
	if err := s05.BridgeBitmapsforNPRSMethodMarshalAPERTo(&v.BitmapsforNPRS, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding bitmapsforNPRS: %w", err)
	}
	if v.NPRSMutingConfiguration != nil {
		if err := v.NPRSMutingConfiguration.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding nPRSMutingConfiguration: %w", err)
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

// UnmarshalAPER decodes NPRSSubframePartA from APER format.
func (v *NPRSSubframePartA) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *NPRSSubframePartA) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "NPRSSubframePartA")
	}
	bb.EnterComponent("NPRSSubframePartA")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NPRSSubframePartA")
	}
	padding, err := aper.CaptureFinalBits(bb, "NPRSSubframePartA")
	if err != nil {
		return runtime.WrapDecodePath(err, "NPRSSubframePartA")
	}
	v.perPadding = padding
	return nil
}
func (v *NPRSSubframePartA) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NPRSSubframePartA{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_nprsmutingconfiguration, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_bitmapsfornprs := bb.EnterComponent("BitmapsforNPRS")
	if err := s05.BridgeBitmapsforNPRSMethodUnmarshalAPERFrom(&v.BitmapsforNPRS, bb); err != nil {
		return runtime.WrapDecodePath(err, "BitmapsforNPRS")
	}
	bb.LeaveComponent(toleranceMark_bitmapsfornprs)
	if opt_nprsmutingconfiguration {
		toleranceMark_nprsmutingconfiguration := bb.EnterComponent("NPRSMutingConfiguration")
		var dec_nprsmutingconfiguration NPRSMutingConfiguration
		if err := dec_nprsmutingconfiguration.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NPRSMutingConfiguration")
		}
		if err := aper.ChargeValue(bb, dec_nprsmutingconfiguration); err != nil {
			return err
		}
		v.NPRSMutingConfiguration = &dec_nprsmutingconfiguration
		bb.LeaveComponent(toleranceMark_nprsmutingconfiguration)
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

// MarshalAPER encodes NPRSSubframePartB to APER format.
func (v *NPRSSubframePartB) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *NPRSSubframePartB) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	hasExtensions = hasExtensions || (v.SIB1NBSubframeTDD != nil)
	for i, present := range v.extPresent {
		if i >= 1 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 1 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.NPRSMutingConfiguration != nil); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.NumberofNPRSOneOccasion), 8, true); err != nil {
		return fmt.Errorf("encoding numberofNPRSOneOccasion: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.PeriodicityofNPRS), 4, true); err != nil {
		return fmt.Errorf("encoding periodicityofNPRS: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Startingsubframeoffset), 8, true); err != nil {
		return fmt.Errorf("encoding startingsubframeoffset: %w", err)
	}
	if v.NPRSMutingConfiguration != nil {
		if err := v.NPRSMutingConfiguration.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding nPRSMutingConfiguration: %w", err)
		}
	}
	if hasExtensions {
		extHighest := int64(0)
		if v.SIB1NBSubframeTDD != nil {
			extHighest = 0
		}
		if extensionCount > extHighest {
			extHighest = extensionCount
		}
		for i, present := range v.extPresent {
			if present && int64(i) > extHighest {
				extHighest = int64(i)
			}
		}
		for i, data := range extensionEncodingData {
			if data != nil && int64(i) > extHighest {
				extHighest = int64(i)
			}
		}
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extHighest+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extHighest < 16383; gen/codegen_aper.go:359
		if extHighest < 0 || extHighest >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extHighest)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extHighest+1); err != nil {
			return err
		}
		// Extension presence bitmap
		if int64(0) <= extHighest {
			present0 := v.SIB1NBSubframeTDD != nil
			if err := aper.EncodeBoolean(bb, present0); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_HIGHEST_1: 0 <= extHighest < max int; gen/codegen_aper.go:375
		if extHighest < 0 || extHighest >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(1); i <= extHighest; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		if v.SIB1NBSubframeTDD != nil {
			extBuf := aper.NewBudgetBuffer(bb.Budget())
			if v.SIB1NBSubframeTDD != nil {
				if err := aper.EncodeEnumeratedAligned(extBuf, int64(*v.SIB1NBSubframeTDD), 3, true); err != nil {
					return fmt.Errorf("encoding sIB1-NB-Subframe-TDD: %w", err)
				}
			}
			var extPadding aper.CompletePadding
			if len(v.perExtPadding) > 0 {
				extPadding = v.perExtPadding[0]
			}
			extBytes, err := extBuf.CompleteBytesWithPadding(extPadding)
			if err != nil {
				return err
			}
			if err := aper.EncodeOpenTypeAligned(bb, extBytes); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_HIGHEST_2: 0 <= extHighest < max int; gen/codegen_aper.go:427
		if extHighest < 0 || extHighest >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(1); i <= extHighest; i++ {
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

// UnmarshalAPER decodes NPRSSubframePartB from APER format.
func (v *NPRSSubframePartB) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *NPRSSubframePartB) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "NPRSSubframePartB")
	}
	bb.EnterComponent("NPRSSubframePartB")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "NPRSSubframePartB")
	}
	padding, err := aper.CaptureFinalBits(bb, "NPRSSubframePartB")
	if err != nil {
		return runtime.WrapDecodePath(err, "NPRSSubframePartB")
	}
	v.perPadding = padding
	return nil
}
func (v *NPRSSubframePartB) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NPRSSubframePartB{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_nprsmutingconfiguration, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_numberofnprsoneoccasion, err := aper.DecodeEnumeratedAligned(bb, 8, true, aper.EnumerationSource{KnownExtensions: 1, Path: "NumberofNPRSOneOccasion"})
	if err != nil {
		return runtime.WrapDecodePath(err, "NumberofNPRSOneOccasion")
	}
	v.NumberofNPRSOneOccasion = val_numberofnprsoneoccasion
	val_periodicityofnprs, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 1, Path: "PeriodicityofNPRS"})
	if err != nil {
		return runtime.WrapDecodePath(err, "PeriodicityofNPRS")
	}
	v.PeriodicityofNPRS = val_periodicityofnprs
	val_startingsubframeoffset, err := aper.DecodeEnumeratedAligned(bb, 8, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Startingsubframeoffset"})
	if err != nil {
		return runtime.WrapDecodePath(err, "Startingsubframeoffset")
	}
	v.Startingsubframeoffset = val_startingsubframeoffset
	if opt_nprsmutingconfiguration {
		toleranceMark_nprsmutingconfiguration := bb.EnterComponent("NPRSMutingConfiguration")
		var dec_nprsmutingconfiguration NPRSMutingConfiguration
		if err := dec_nprsmutingconfiguration.unmarshalAPERFrom(bb); err != nil {
			return runtime.WrapDecodePath(err, "NPRSMutingConfiguration")
		}
		if err := aper.ChargeValue(bb, dec_nprsmutingconfiguration); err != nil {
			return err
		}
		v.NPRSMutingConfiguration = &dec_nprsmutingconfiguration
		bb.LeaveComponent(toleranceMark_nprsmutingconfiguration)
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_ALLOC_1: 0 <= extCount < max int; gen/codegen_aper.go:552
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_2: 0 <= extCount < max int; gen/codegen_aper.go:554
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		if err := aper.ChargeSlice[aper.CompletePadding](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.perExtPadding = make([]aper.CompletePadding, len(extPresent))
		if int64(0) <= extCount && extPresent[0] {
			extRaw, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§19.9"})
			if err != nil {
				return runtime.WrapDecodePath(err, "ExtData_[0]")
			}
			v.knownOpenBytes = max(v.knownOpenBytes, extRaw.ContentLength())
			if err := func() error {
				extBB := extRaw.ChildDecodeBuffer()

				if err := extBB.EnterOpenType(); err != nil {
					return err
				}
				defer extBB.LeaveOpenType()
				_ = extBB
				paddingMark := extBB.EnterComponent("Extensions[0]")
				val_sib1nbsubframetdd, err := aper.DecodeEnumeratedAligned(extBB, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "SIB1NBSubframeTDD"})
				if err != nil {
					return runtime.WrapDecodePath(err, "SIB1NBSubframeTDD")
				}
				if err := aper.ChargeValue(extBB, val_sib1nbsubframetdd); err != nil {
					return err
				}
				v.SIB1NBSubframeTDD = (*int64)(bb.OwnInt64(int64(val_sib1nbsubframetdd)))
				padding, err := aper.CaptureOpenTypePadding(extBB)
				extBB.LeaveComponent(paddingMark)
				if err != nil {
					return runtime.WrapDecodePath(err, "ExtData_[0]")
				}
				v.perExtPadding[0] = padding
				return nil
			}(); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_COUNT_LOOP_1: 0 <= extCount < max int; gen/codegen_aper.go:610
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(1); i <= extCount; i++ {
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
func (v *NPRSConfiguration) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "NPRSConfiguration", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NPRSConfiguration) WithoutReplay() NPRSConfiguration {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero NPRSConfiguration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *NPRSMutingConfiguration) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "NPRSMutingConfiguration", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NPRSMutingConfiguration) WithoutReplay() NPRSMutingConfiguration {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero NPRSMutingConfiguration
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *NPRSSubframePartA) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "NPRSSubframePartA", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NPRSSubframePartA) WithoutReplay() NPRSSubframePartA {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero NPRSSubframePartA
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *NPRSSubframePartB) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "NPRSSubframePartB", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NPRSSubframePartB) WithoutReplay() NPRSSubframePartB {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero NPRSSubframePartB
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *NRCGI) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "NRCGI", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NRCGI) WithoutReplay() NRCGI {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero NRCGI
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *NPRSConfiguration) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *NPRSConfiguration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NPRSConfiguration.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NPRSConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *NPRSConfiguration) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NPRSConfiguration.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NPRSConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *NPRSSubframePartA) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *NPRSSubframePartA) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NPRSSubframePartA.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NPRSSubframePartA.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *NPRSSubframePartA) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NPRSSubframePartA.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NPRSSubframePartA.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *NPRSSubframePartB) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	for len(views) > 0 && views[0].Index() < 1 {
		views = views[1:]
	}
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *NPRSSubframePartB) SetExtension(index uint64, contents []byte) error {
	if index < 1 {
		return runtime.WrapDecodePath(fmt.Errorf("%w: extension index %d is known to this schema", aper.ErrInvalidValue, index), fmt.Sprintf("NPRSSubframePartB.Extensions[%d]", index))
	}
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NPRSSubframePartB.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NPRSSubframePartB.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *NPRSSubframePartB) RemoveExtension(index uint64) error {
	if index < 1 {
		return runtime.WrapDecodePath(fmt.Errorf("%w: extension index %d is known to this schema", aper.ErrInvalidValue, index), fmt.Sprintf("NPRSSubframePartB.Extensions[%d]", index))
	}
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NPRSSubframePartB.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NPRSSubframePartB.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *NRCGI) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *NRCGI) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NRCGI.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NRCGI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *NRCGI) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("NRCGI.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("NRCGI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *NPRSConfiguration) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "NPRSConfiguration")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "NPRSConfiguration")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaNPRSConfiguration(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "NPRSConfiguration")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "NPRSConfiguration")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "NPRSConfiguration")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "NPRSConfiguration")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "NPRSConfiguration")
}
func (v *NPRSConfiguration) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *NPRSConfiguration) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *NPRSConfiguration) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaNPRSConfiguration(v, &s)
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
func (v *NPRSConfiguration) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *NPRSConfiguration) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *NPRSMutingConfiguration) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "NPRSMutingConfiguration")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "NPRSMutingConfiguration")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaNPRSMutingConfiguration(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "NPRSMutingConfiguration")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "NPRSMutingConfiguration")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "NPRSMutingConfiguration")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "NPRSMutingConfiguration")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "NPRSMutingConfiguration")
}
func (v *NPRSMutingConfiguration) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *NPRSMutingConfiguration) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *NPRSMutingConfiguration) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaNPRSMutingConfiguration(v, &s)
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
func (v *NPRSMutingConfiguration) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *NPRSMutingConfiguration) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *NPRSSubframePartA) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "NPRSSubframePartA")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "NPRSSubframePartA")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaNPRSSubframePartA(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "NPRSSubframePartA")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "NPRSSubframePartA")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "NPRSSubframePartA")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "NPRSSubframePartA")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "NPRSSubframePartA")
}
func (v *NPRSSubframePartA) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *NPRSSubframePartA) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *NPRSSubframePartA) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaNPRSSubframePartA(v, &s)
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
func (v *NPRSSubframePartA) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *NPRSSubframePartA) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *NPRSSubframePartB) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "NPRSSubframePartB")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "NPRSSubframePartB")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaNPRSSubframePartB(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "NPRSSubframePartB")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "NPRSSubframePartB")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "NPRSSubframePartB")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "NPRSSubframePartB")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "NPRSSubframePartB")
}
func (v *NPRSSubframePartB) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *NPRSSubframePartB) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *NPRSSubframePartB) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaNPRSSubframePartB(v, &s)
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
func (v *NPRSSubframePartB) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *NPRSSubframePartB) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *NRCGI) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "NRCGI")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "NRCGI")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaNRCGI(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "NRCGI")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "NRCGI")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "NRCGI")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "NRCGI")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "NRCGI")
}
func (v *NRCGI) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *NRCGI) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *NRCGI) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaNRCGI(v, &s)
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
func (v *NRCGI) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *NRCGI) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *NPRSConfiguration) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "NPRSConfiguration")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded NPRSConfiguration
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaNPRSConfiguration(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = NPRSConfiguration{}
		return report, aper.OperationError(err, "NPRSConfiguration")
	}
	*v = decoded
	return report, aper.OperationError(nil, "NPRSConfiguration")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *NPRSMutingConfiguration) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "NPRSMutingConfiguration")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded NPRSMutingConfiguration
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaNPRSMutingConfiguration(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = NPRSMutingConfiguration{}
		return report, aper.OperationError(err, "NPRSMutingConfiguration")
	}
	*v = decoded
	return report, aper.OperationError(nil, "NPRSMutingConfiguration")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *NPRSSubframePartA) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "NPRSSubframePartA")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded NPRSSubframePartA
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaNPRSSubframePartA(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = NPRSSubframePartA{}
		return report, aper.OperationError(err, "NPRSSubframePartA")
	}
	*v = decoded
	return report, aper.OperationError(nil, "NPRSSubframePartA")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *NPRSSubframePartB) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "NPRSSubframePartB")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded NPRSSubframePartB
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaNPRSSubframePartB(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = NPRSSubframePartB{}
		return report, aper.OperationError(err, "NPRSSubframePartB")
	}
	*v = decoded
	return report, aper.OperationError(nil, "NPRSSubframePartB")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *NRCGI) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "NRCGI")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded NRCGI
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaNRCGI(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = NRCGI{}
		return report, aper.OperationError(err, "NRCGI")
	}
	*v = decoded
	return report, aper.OperationError(nil, "NRCGI")
}

// NewBitmapsforNPRSUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewBitmapsforNPRSUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (s05.BitmapsforNPRS, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s05.BitmapsforNPRS{}, aper.OperationError(err, "BitmapsforNPRSUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return s05.BitmapsforNPRS{}, aper.OperationError(err, "BitmapsforNPRSUnknownExtension")
	}
	value := s05.BitmapsforNPRS{UnknownExtension: &extension}
	if _, err := s05.BridgeBitmapsforNPRSMethodMarshalAPERBudget(&value, budget, false); err != nil {
		return s05.BitmapsforNPRS{}, aper.OperationError(err, "BitmapsforNPRSUnknownExtension")
	}
	return value, aper.OperationError(nil, "BitmapsforNPRSUnknownExtension")
}

// NewCauseUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewCauseUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (s05.Cause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s05.Cause{}, aper.OperationError(err, "CauseUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return s05.Cause{}, aper.OperationError(err, "CauseUnknownExtension")
	}
	value := s05.Cause{UnknownExtension: &extension}
	if _, err := s05.BridgeCauseMethodMarshalAPERBudget(&value, budget, false); err != nil {
		return s05.Cause{}, aper.OperationError(err, "CauseUnknownExtension")
	}
	return value, aper.OperationError(nil, "CauseUnknownExtension")
}

// NewNPRSMutingConfigurationUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewNPRSMutingConfigurationUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (NPRSMutingConfiguration, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return NPRSMutingConfiguration{}, aper.OperationError(err, "NPRSMutingConfigurationUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return NPRSMutingConfiguration{}, aper.OperationError(err, "NPRSMutingConfigurationUnknownExtension")
	}
	value := NPRSMutingConfiguration{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return NPRSMutingConfiguration{}, aper.OperationError(err, "NPRSMutingConfigurationUnknownExtension")
	}
	return value, aper.OperationError(nil, "NPRSMutingConfigurationUnknownExtension")
}

type OTDOAInformationType = []OTDOAInformationTypeIEValueProtocolIESingleContainer

// OTDOAInformationTypeItem represents the ASN.1 type OTDOA-Information-Type-Item (SEQUENCE).
type OTDOAInformationTypeItem struct {
	replay                   aper.Snapshot
	stream                   aper.WireSpan
	withoutReplay            bool
	received                 bool
	receivedBytes            aper.WireSpan
	OTDOAInformationTypeItem s00.OTDOAInformationItem                       `asn1:"tag:0,context,implicit"`
	IEExtensions             s04.OTDOAInformationTypeItemExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef        bool                                           `asn1:"-" json:"-"`
	extCount                 int64                                          `asn1:"-" json:"-"`
	extPresent               []bool                                         `asn1:"-" json:"-"`
	extData                  [][]byte                                       `asn1:"-" json:"-"`
	perPadding               aper.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding            []aper.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin                []aper.OpaqueOrigin
	extWire                  []aper.WireSpan
}

// MarshalAPER encodes OTDOAInformationTypeItem to APER format.
func (v *OTDOAInformationTypeItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *OTDOAInformationTypeItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.OTDOAInformationTypeItem), 10, true); err != nil {
		return fmt.Errorf("encoding oTDOA-Information-Type-Item: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s04.BridgeOTDOAInformationTypeItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes OTDOAInformationTypeItem from APER format.
func (v *OTDOAInformationTypeItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *OTDOAInformationTypeItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationTypeItem")
	}
	bb.EnterComponent("OTDOAInformationTypeItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationTypeItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "OTDOAInformationTypeItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationTypeItem")
	}
	v.perPadding = padding
	return nil
}
func (v *OTDOAInformationTypeItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationTypeItem{}
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
	val_otdoainformationtypeitem, err := aper.DecodeEnumeratedAligned(bb, 10, true, aper.EnumerationSource{KnownExtensions: 19, Path: "OTDOAInformationTypeItem"})
	if err != nil {
		return runtime.WrapDecodePath(err, "OTDOAInformationTypeItem")
	}
	v.OTDOAInformationTypeItem = s00.OTDOAInformationItem(val_otdoainformationtypeitem)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s04.OTDOAInformationTypeItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s04.OTDOAInformationTypeItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s04.BridgeOTDOAInformationTypeItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *OTDOAInformationTypeItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "OTDOAInformationTypeItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OTDOAInformationTypeItem) WithoutReplay() OTDOAInformationTypeItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero OTDOAInformationTypeItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *OTDOAInformationTypeItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *OTDOAInformationTypeItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("OTDOAInformationTypeItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("OTDOAInformationTypeItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *OTDOAInformationTypeItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("OTDOAInformationTypeItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("OTDOAInformationTypeItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *OTDOAInformationTypeItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "OTDOAInformationTypeItem")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "OTDOAInformationTypeItem")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaOTDOAInformationTypeItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "OTDOAInformationTypeItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "OTDOAInformationTypeItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "OTDOAInformationTypeItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "OTDOAInformationTypeItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "OTDOAInformationTypeItem")
}
func (v *OTDOAInformationTypeItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *OTDOAInformationTypeItem) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *OTDOAInformationTypeItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaOTDOAInformationTypeItem(v, &s)
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
func (v *OTDOAInformationTypeItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOAInformationTypeItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *OTDOAInformationTypeItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "OTDOAInformationTypeItem")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded OTDOAInformationTypeItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaOTDOAInformationTypeItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = OTDOAInformationTypeItem{}
		return report, aper.OperationError(err, "OTDOAInformationTypeItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "OTDOAInformationTypeItem")
}
func BridgeCaptureLPPaNPRSConfiguration(v *NPRSConfiguration, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	{
		f := s.Begin()
		s.Bool(v.NPRSSubframePartA == nil)
		if v.NPRSSubframePartA != nil {
			BridgeCaptureLPPaNPRSSubframePartA(v.NPRSSubframePartA, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.NPRSSubframePartB == nil)
		if v.NPRSSubframePartB != nil {
			BridgeCaptureLPPaNPRSSubframePartB(v.NPRSSubframePartB, s)
		}
		s.End(f, nil, false)
	}
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaNPRSConfiguration(v *NPRSConfiguration, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

	{
		f := s.Begin()
		s.Bool(v.NPRSSubframePartA == nil)
		if v.NPRSSubframePartA != nil {
			BridgeCompareLPPaNPRSSubframePartA(v.NPRSSubframePartA, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.NPRSSubframePartB == nil)
		if v.NPRSSubframePartB != nil {
			BridgeCompareLPPaNPRSSubframePartB(v.NPRSSubframePartB, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaNPRSMutingConfiguration(v *NPRSMutingConfiguration, s *aper.SemanticCapture) {
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
	case s00.NPRSMutingConfigurationChoiceTwo:
		{
			f := s.Begin()
			s.Bool(v.Two == nil)
			if v.Two != nil {
				s.BitString((*v.Two).Bytes, (*v.Two).BitLength)
			}
			s.End(f, nil, false)
		}
	case s00.NPRSMutingConfigurationChoiceFour:
		{
			f := s.Begin()
			s.Bool(v.Four == nil)
			if v.Four != nil {
				s.BitString((*v.Four).Bytes, (*v.Four).BitLength)
			}
			s.End(f, nil, false)
		}
	case s00.NPRSMutingConfigurationChoiceEight:
		{
			f := s.Begin()
			s.Bool(v.Eight == nil)
			if v.Eight != nil {
				s.BitString((*v.Eight).Bytes, (*v.Eight).BitLength)
			}
			s.End(f, nil, false)
		}
	case s00.NPRSMutingConfigurationChoiceSixteen:
		{
			f := s.Begin()
			s.Bool(v.Sixteen == nil)
			if v.Sixteen != nil {
				s.BitString((*v.Sixteen).Bytes, (*v.Sixteen).BitLength)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaNPRSMutingConfiguration(v *NPRSMutingConfiguration, s *aper.SemanticComparison) {
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
	case s00.NPRSMutingConfigurationChoiceTwo:
		{
			f := s.Begin()
			s.Bool(v.Two == nil)
			if v.Two != nil {
				s.BitString((*v.Two).Bytes, (*v.Two).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.NPRSMutingConfigurationChoiceFour:
		{
			f := s.Begin()
			s.Bool(v.Four == nil)
			if v.Four != nil {
				s.BitString((*v.Four).Bytes, (*v.Four).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.NPRSMutingConfigurationChoiceEight:
		{
			f := s.Begin()
			s.Bool(v.Eight == nil)
			if v.Eight != nil {
				s.BitString((*v.Eight).Bytes, (*v.Eight).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.NPRSMutingConfigurationChoiceSixteen:
		{
			f := s.Begin()
			s.Bool(v.Sixteen == nil)
			if v.Sixteen != nil {
				s.BitString((*v.Sixteen).Bytes, (*v.Sixteen).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaNPRSSubframePartA(v *NPRSSubframePartA, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s05.BridgeCaptureLPPaBitmapsforNPRS(&v.BitmapsforNPRS, s)
	{
		f := s.Begin()
		s.Bool(v.NPRSMutingConfiguration == nil)
		if v.NPRSMutingConfiguration != nil {
			BridgeCaptureLPPaNPRSMutingConfiguration(v.NPRSMutingConfiguration, s)
		}
		s.End(f, nil, false)
	}
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaNPRSSubframePartA(v *NPRSSubframePartA, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s05.BridgeCompareLPPaBitmapsforNPRS(&v.BitmapsforNPRS, s)
	{
		f := s.Begin()
		s.Bool(v.NPRSMutingConfiguration == nil)
		if v.NPRSMutingConfiguration != nil {
			BridgeCompareLPPaNPRSMutingConfiguration(v.NPRSMutingConfiguration, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaNPRSSubframePartB(v *NPRSSubframePartB, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.OpenBytes(v.knownOpenBytes)
	s.Stream(v.stream)
	s.Int(int64(v.NumberofNPRSOneOccasion))
	s.Int(int64(v.PeriodicityofNPRS))
	s.Int(int64(v.Startingsubframeoffset))
	{
		f := s.Begin()
		s.Bool(v.NPRSMutingConfiguration == nil)
		if v.NPRSMutingConfiguration != nil {
			BridgeCaptureLPPaNPRSMutingConfiguration(v.NPRSMutingConfiguration, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.SIB1NBSubframeTDD == nil)
		if v.SIB1NBSubframeTDD != nil {
			s.Int(int64((*v.SIB1NBSubframeTDD)))
		}
		s.End(f, nil, false)
	}
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaNPRSSubframePartB(v *NPRSSubframePartB, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

	s.Int(int64(v.NumberofNPRSOneOccasion))
	s.Int(int64(v.PeriodicityofNPRS))
	s.Int(int64(v.Startingsubframeoffset))
	{
		f := s.Begin()
		s.Bool(v.NPRSMutingConfiguration == nil)
		if v.NPRSMutingConfiguration != nil {
			BridgeCompareLPPaNPRSMutingConfiguration(v.NPRSMutingConfiguration, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.SIB1NBSubframeTDD == nil)
		if v.SIB1NBSubframeTDD != nil {
			s.Int(int64((*v.SIB1NBSubframeTDD)))
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaNRCGI(v *NRCGI, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaPLMNIdentity(&v.PLMNIdentity, s)
	s00.BridgeCaptureLPPaNRCellIdentity(&v.NRCellIdentity, s)
	s.Bool(v.IEExtensions == nil)
	s05.BridgeNRCGIExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaNRCGI(v *NRCGI, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaPLMNIdentity(&v.PLMNIdentity, s)
	s02.BridgeCompareLPPaNRCellIdentity(&v.NRCellIdentity, s)
	s.Bool(v.IEExtensions == nil)
	s05.BridgeNRCGIExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaOTDOAInformationTypeIEValue(v *OTDOAInformationTypeIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(10):
			{
				f := s.Begin()
				s.Bool(v.rowOTDOAInformationTypeItem == nil)
				if v.rowOTDOAInformationTypeItem != nil {
					BridgeCaptureLPPaOTDOAInformationTypeItem(v.rowOTDOAInformationTypeItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v OTDOAInformationTypeIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v OTDOAInformationTypeIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v OTDOAInformationTypeIEValue) captureSemantics(s aper.SemanticCapture) OTDOAInformationTypeIEValue {
	BridgeCaptureLPPaOTDOAInformationTypeIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaOTDOAInformationTypeIEValue(v *OTDOAInformationTypeIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(10):
			{
				f := s.Begin()
				s.Bool(v.rowOTDOAInformationTypeItem == nil)
				if v.rowOTDOAInformationTypeItem != nil {
					BridgeCompareLPPaOTDOAInformationTypeItem(v.rowOTDOAInformationTypeItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v OTDOAInformationTypeIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaOTDOAInformationTypeIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOAInformationTypeIEValue) WithoutReplay() OTDOAInformationTypeIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaOTDOAInformationTypeItem(v *OTDOAInformationTypeItem, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaOTDOAInformationItem(&v.OTDOAInformationTypeItem, s)
	s.Bool(v.IEExtensions == nil)
	s05.BridgeOTDOAInformationTypeItemExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaOTDOAInformationTypeItem(v *OTDOAInformationTypeItem, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaOTDOAInformationItem(&v.OTDOAInformationTypeItem, s)
	s.Bool(v.IEExtensions == nil)
	s05.BridgeOTDOAInformationTypeItemExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}

type OTDOAInformationTypeIEValue struct {
	id                          s00.ProtocolIEID
	withoutReplay               bool
	received                    aper.WireSpan
	replay                      aper.Snapshot
	opaque                      *aper.OpaqueOpenType
	isOpaque                    bool
	rowOTDOAInformationTypeItem *OTDOAInformationTypeItem
}

func (v OTDOAInformationTypeIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case s00.ProtocolIEID(10):
		return v.rowOTDOAInformationTypeItem != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *OTDOAInformationTypeIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (OTDOAInformationTypeIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOA-Information-TypeIEs"}}
}
func (OTDOAInformationTypeIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(10):
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

// AsOTDOAInformationTypeItem returns the selected OTDOAInformationTypeItem value and reports whether that alternative is active.
func (v *OTDOAInformationTypeIEValue) AsOTDOAInformationTypeItem() (*OTDOAInformationTypeItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(10) || v.rowOTDOAInformationTypeItem == nil {
		return nil, false
	}
	return v.rowOTDOAInformationTypeItem, true
}
func (v OTDOAInformationTypeIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (OTDOAInformationTypeIEValue, error) {
	out := OTDOAInformationTypeIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 10:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case s00.ProtocolIEID(10):
		replayUsage := scope.Usage()
		var value OTDOAInformationTypeItem
		child := raw.ChildDecodeBuffer()
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "OTDOAInformationTypeItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "OTDOAInformationTypeItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowOTDOAInformationTypeItem = &value
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
func (v OTDOAInformationTypeIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v OTDOAInformationTypeIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(10):
		if v.rowOTDOAInformationTypeItem == nil {
			return nil, fmt.Errorf("%s missing value", "OTDOA-Information-TypeIEs.id-OTDOA-Information-Type-Item:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := v.rowOTDOAInformationTypeItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "OTDOAInformationTypeIEValue:", v.id)
	}
}

type MeasurementQuantitiesItemIETable struct{}

func MeasurementQuantitiesItemIEs() MeasurementQuantitiesItemIETable {
	return MeasurementQuantitiesItemIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (MeasurementQuantitiesItemIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementQuantities-ItemIEs"}
		return sealed
	}()
}
func (MeasurementQuantitiesItemIETable) infoMeasurementQuantitiesItem() s00.FieldInfo {
	return s00.FieldInfo{Table: MeasurementQuantitiesItemIEs().ID(), ID: s00.ProtocolIEID(11), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementQuantitiesItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementQuantities-ItemIEs", Row: "id-MeasurementQuantities-Item"}}}
}

// MeasurementQuantitiesItem returns the typed binding for the MeasurementQuantitiesItem row of this table.
func (t MeasurementQuantitiesItemIETable) MeasurementQuantitiesItem() s06.MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding {
	return func() s06.MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding {
		sealed := s06.MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding{}
		*s06.BridgeMeasurementQuantitiesItemMeasurementQuantitiesItemIEBindingFieldInfo(&sealed) = t.infoMeasurementQuantitiesItem()
		*s06.BridgeMeasurementQuantitiesItemMeasurementQuantitiesItemIEBindingFieldCodec(&sealed) = func() s06.MeasurementQuantitiesItemValueCodec {
			sealed := s06.MeasurementQuantitiesItemValueCodec{}
			*s06.BridgeMeasurementQuantitiesItemValueCodecFieldPath(&sealed) = "MeasurementQuantitiesItem"
			*s06.BridgeMeasurementQuantitiesItemValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s06.MeasurementQuantitiesItem, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s06.MeasurementQuantitiesItem
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MeasurementQuantitiesItem")
				var zero s06.MeasurementQuantitiesItemIEValue
				decoded, err := s06.BridgeMeasurementQuantitiesItemIEValueMethodDecode(zero, s00.ProtocolIEID(11), raw)
				if err != nil {
					var empty s06.MeasurementQuantitiesItem
					return empty, runtime.WrapDecodePath(err, "MeasurementQuantitiesItem")
				}
				value, ok := decoded.AsMeasurementQuantitiesItem()
				if !ok {
					var empty s06.MeasurementQuantitiesItem
					return empty, fmt.Errorf("binding MeasurementQuantities-ItemIEs.id-MeasurementQuantities-Item: no selected value")
				}
				return *value, nil
			}
			*s06.BridgeMeasurementQuantitiesItemValueCodecFieldEncode(&sealed) = func(value s06.MeasurementQuantitiesItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s06.BridgeMeasurementQuantitiesItemIEValueMethodEncodeFresh((func() s06.MeasurementQuantitiesItemIEValue {
					sealed := s06.MeasurementQuantitiesItemIEValue{}
					*s06.BridgeMeasurementQuantitiesItemIEValueFieldId(&sealed) = s00.ProtocolIEID(11)
					*s06.BridgeMeasurementQuantitiesItemIEValueFieldRowMeasurementQuantitiesItem(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s06.BridgeMeasurementQuantitiesItemValueCodecFieldCapture(&sealed) = func(v s06.MeasurementQuantitiesItem, options aper.DecodeState) (s06.MeasurementQuantitiesItem, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s06.BridgeCaptureLPPaMeasurementQuantitiesItem(&v, &s)
				var root aper.Snapshot
				s.OperationCounts()
				s.End(f, &root, false)
				return v, root
			}
			*s06.BridgeMeasurementQuantitiesItemValueCodecFieldCompare(&sealed) = func(v s06.MeasurementQuantitiesItem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
				s := aper.NewSemanticComparison(root, limits)
				f := s.Begin()
				s06.BridgeCompareLPPaMeasurementQuantitiesItem(&v, &s)
				s.End(f, root, false)
				return s.
					Plan()
			}
			*s06.BridgeMeasurementQuantitiesItemValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementQuantitiesItem"
				return sealed
			}()
			return sealed
		}()
		*s06.BridgeMeasurementQuantitiesItemMeasurementQuantitiesItemIEBindingFieldInject(&sealed) = func(value s06.MeasurementQuantitiesItem) s06.MeasurementQuantitiesItemIEValue {
			return func() s06.MeasurementQuantitiesItemIEValue {
				sealed := s06.MeasurementQuantitiesItemIEValue{}
				*s06.BridgeMeasurementQuantitiesItemIEValueFieldId(&sealed) = s00.ProtocolIEID(11)
				*s06.BridgeMeasurementQuantitiesItemIEValueFieldRowMeasurementQuantitiesItem(&sealed) = &value
				return sealed
			}()
		}
		*s06.BridgeMeasurementQuantitiesItemMeasurementQuantitiesItemIEBindingFieldGet(&sealed) = func(value *s06.MeasurementQuantitiesItemIEValue) (*s06.MeasurementQuantitiesItem, bool) {
			return value.AsMeasurementQuantitiesItem()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t MeasurementQuantitiesItemIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s06.MeasurementQuantitiesItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s06.MeasurementQuantitiesItemIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(11):
		return s06.MeasurementQuantitiesItemIEField{}, aper.OperationError(fmt.Errorf("known IE id-MeasurementQuantities-Item requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s06.MeasurementQuantitiesItemIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s06.MeasurementQuantitiesItemIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return s06.MeasurementQuantitiesItemIEField{}, aper.OperationError(err, "Opaque")
		}
		return s06.MeasurementQuantitiesItemIEField{Id: id, Criticality: criticality, Value: func() s06.MeasurementQuantitiesItemIEValue {
			sealed := s06.MeasurementQuantitiesItemIEValue{}
			*s06.BridgeMeasurementQuantitiesItemIEValueFieldId(&sealed) = id
			*s06.BridgeMeasurementQuantitiesItemIEValueFieldOpaque(&sealed) = retained
			*s06.BridgeMeasurementQuantitiesItemIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type OTDOAInformationTypeIETable struct{}

func OTDOAInformationTypeIEs() OTDOAInformationTypeIETable { return OTDOAInformationTypeIETable{} }

// ID returns the ASN.1 source assignment identifying this table.
func (OTDOAInformationTypeIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOA-Information-TypeIEs"}
		return sealed
	}()
}
func (OTDOAInformationTypeIETable) infoOTDOAInformationTypeItem() s00.FieldInfo {
	return s00.FieldInfo{Table: OTDOAInformationTypeIEs().ID(), ID: s00.ProtocolIEID(10), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationTypeItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOA-Information-TypeIEs", Row: "id-OTDOA-Information-Type-Item"}}}
}

// OTDOAInformationTypeItem returns the typed binding for the OTDOAInformationTypeItem row of this table.
func (t OTDOAInformationTypeIETable) OTDOAInformationTypeItem() OTDOAInformationTypeOTDOAInformationTypeItemIEBinding {
	return OTDOAInformationTypeOTDOAInformationTypeItemIEBinding{info: t.infoOTDOAInformationTypeItem(), codec: OTDOAInformationTypeItemValueCodec{path: "OTDOAInformationTypeItem",
		decode: func(data []byte, options aper.DecodeState) (OTDOAInformationTypeItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty OTDOAInformationTypeItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("OTDOAInformationTypeItem")
			var zero OTDOAInformationTypeIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(10), raw)
			if err != nil {
				var empty OTDOAInformationTypeItem
				return empty, runtime.WrapDecodePath(err, "OTDOAInformationTypeItem")
			}
			value, ok := decoded.AsOTDOAInformationTypeItem()
			if !ok {
				var empty OTDOAInformationTypeItem
				return empty, fmt.Errorf("binding OTDOA-Information-TypeIEs.id-OTDOA-Information-Type-Item: no selected value")
			}
			return *value, nil
		},
		encode: func(value OTDOAInformationTypeItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (OTDOAInformationTypeIEValue{id: s00.ProtocolIEID(10), rowOTDOAInformationTypeItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v OTDOAInformationTypeItem, options aper.DecodeState) (OTDOAInformationTypeItem, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureLPPaOTDOAInformationTypeItem(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}, compare: func(v OTDOAInformationTypeItem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaOTDOAInformationTypeItem(&v, &s)
			s.End(f, root, false)
			return s.
				Plan()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOAInformationTypeItem"
			return sealed
		}(),
	}, inject: func(value OTDOAInformationTypeItem) OTDOAInformationTypeIEValue {
		return OTDOAInformationTypeIEValue{id: s00.ProtocolIEID(10), rowOTDOAInformationTypeItem: &value}
	}, get: func(value *OTDOAInformationTypeIEValue) (*OTDOAInformationTypeItem, bool) {
		return value.AsOTDOAInformationTypeItem()
	}}
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t OTDOAInformationTypeIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (OTDOAInformationTypeIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return OTDOAInformationTypeIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(10):
		return OTDOAInformationTypeIEField{}, aper.OperationError(fmt.Errorf("known IE id-OTDOA-Information-Type-Item requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return OTDOAInformationTypeIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return OTDOAInformationTypeIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return OTDOAInformationTypeIEField{}, aper.OperationError(err, "Opaque")
		}
		return OTDOAInformationTypeIEField{Id: id, Criticality: criticality, Value: OTDOAInformationTypeIEValue{id: id, opaque: retained, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// MeasurementQuantitiesItemCodec binds the complete APER value type.
func MeasurementQuantitiesItemCodec() s06.MeasurementQuantitiesItemValueCodec {
	return MeasurementQuantitiesItemIEs().MeasurementQuantitiesItem().Codec()
}

// NPRSConfigurationCodec binds the complete source value type.
func NPRSConfigurationCodec() NPRSConfigurationValueCodec {
	return NPRSConfigurationValueCodec{path: "NPRSConfiguration", decode: func(data []byte, options aper.DecodeState) (NPRSConfiguration, error) {
		var value NPRSConfiguration
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return NPRSConfiguration{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value NPRSConfiguration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v NPRSConfiguration, options aper.DecodeState) (NPRSConfiguration, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaNPRSConfiguration(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v NPRSConfiguration, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaNPRSConfiguration(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NPRSConfiguration"
		return sealed
	}(),
	}
}

// NPRSMutingConfigurationCodec binds the complete source value type.
func NPRSMutingConfigurationCodec() NPRSMutingConfigurationValueCodec {
	return NPRSMutingConfigurationValueCodec{path: "NPRSMutingConfiguration", decode: func(data []byte, options aper.DecodeState) (NPRSMutingConfiguration, error) {
		var value NPRSMutingConfiguration
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return NPRSMutingConfiguration{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value NPRSMutingConfiguration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v NPRSMutingConfiguration, options aper.DecodeState) (NPRSMutingConfiguration, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaNPRSMutingConfiguration(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v NPRSMutingConfiguration, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaNPRSMutingConfiguration(&v, &s)
		s.End(f, root, false)
		return s.
			Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NPRSMutingConfiguration"
		return sealed
	}(),
	}
}

// NPRSSubframePartACodec binds the complete source value type.
func NPRSSubframePartACodec() NPRSSubframePartAValueCodec {
	return NPRSSubframePartAValueCodec{path: "NPRSSubframePartA", decode: func(data []byte, options aper.DecodeState) (NPRSSubframePartA, error) {
		var value NPRSSubframePartA
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return NPRSSubframePartA{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value NPRSSubframePartA, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v NPRSSubframePartA, options aper.DecodeState) (NPRSSubframePartA, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaNPRSSubframePartA(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v NPRSSubframePartA, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaNPRSSubframePartA(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NPRSSubframePartA"
		return sealed
	}(),
	}
}

// NPRSSubframePartBCodec binds the complete source value type.
func NPRSSubframePartBCodec() NPRSSubframePartBValueCodec {
	return NPRSSubframePartBValueCodec{path: "NPRSSubframePartB", decode: func(data []byte, options aper.DecodeState) (NPRSSubframePartB, error) {
		var value NPRSSubframePartB
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return NPRSSubframePartB{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value NPRSSubframePartB, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v NPRSSubframePartB, options aper.DecodeState) (NPRSSubframePartB, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaNPRSSubframePartB(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v NPRSSubframePartB, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaNPRSSubframePartB(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NPRSSubframePartB"
		return sealed
	}(),
	}
}

// OTDOAInformationTypeItemCodec binds the complete APER value type.
func OTDOAInformationTypeItemCodec() OTDOAInformationTypeItemValueCodec {
	return OTDOAInformationTypeIEs().OTDOAInformationTypeItem().Codec()
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *OTDOAInformationTypeIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 10:
		if v.rowOTDOAInformationTypeItem != nil {
			return v.rowOTDOAInformationTypeItem, true
		}
	}
	return nil, false
}

func BridgeMeasurementQuantitiesItemIETableMethodInfoMeasurementQuantitiesItem(v MeasurementQuantitiesItemIETable) s00.FieldInfo {
	return v.infoMeasurementQuantitiesItem()
}
func BridgeNPRSConfigurationAPERValueFieldContext(v *NPRSConfigurationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNPRSConfigurationAPERValueFieldReceived(v *NPRSConfigurationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeNPRSConfigurationAPERValueFieldReplay(v *NPRSConfigurationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeNPRSConfigurationAPERValueFieldWithoutReplay(v *NPRSConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNPRSConfigurationFieldExtCount(v *NPRSConfiguration) *int64   { return &v.extCount }
func BridgeNPRSConfigurationFieldExtData(v *NPRSConfiguration) *[][]byte { return &v.extData }
func BridgeNPRSConfigurationFieldExtOrigin(v *NPRSConfiguration) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeNPRSConfigurationFieldExtPresent(v *NPRSConfiguration) *[]bool       { return &v.extPresent }
func BridgeNPRSConfigurationFieldExtWire(v *NPRSConfiguration) *[]aper.WireSpan { return &v.extWire }
func BridgeNPRSConfigurationFieldPerExtPadding(v *NPRSConfiguration) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeNPRSConfigurationFieldPerPadding(v *NPRSConfiguration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeNPRSConfigurationFieldReceived(v *NPRSConfiguration) *bool { return &v.received }
func BridgeNPRSConfigurationFieldReceivedBytes(v *NPRSConfiguration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeNPRSConfigurationFieldReplay(v *NPRSConfiguration) *aper.Snapshot { return &v.replay }
func BridgeNPRSConfigurationFieldStream(v *NPRSConfiguration) *aper.WireSpan { return &v.stream }
func BridgeNPRSConfigurationFieldWithoutReplay(v *NPRSConfiguration) *bool   { return &v.withoutReplay }
func BridgeNPRSConfigurationMethodMarshalAPERBudget(v *NPRSConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNPRSConfigurationMethodMarshalAPERChanged(v *NPRSConfiguration, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNPRSConfigurationMethodMarshalAPERChangedValue(v *NPRSConfiguration, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNPRSConfigurationMethodMarshalAPERFreshValue(v *NPRSConfiguration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeNPRSConfigurationMethodMarshalAPERLegacy(v *NPRSConfiguration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeNPRSConfigurationMethodMarshalAPERPlanned(v *NPRSConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeNPRSConfigurationMethodMarshalAPERTo(v *NPRSConfiguration, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNPRSConfigurationMethodUnmarshalAPERFrom(v *NPRSConfiguration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNPRSConfigurationMethodUnmarshalAPERLegacy(v *NPRSConfiguration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNPRSConfigurationMethodUnmarshalAPERWithOptions(v *NPRSConfiguration, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeNPRSConfigurationValueCodecFieldCapture(v *NPRSConfigurationValueCodec) *func(NPRSConfiguration, aper.DecodeState) (NPRSConfiguration, aper.Snapshot) {
	return &v.capture
}
func BridgeNPRSConfigurationValueCodecFieldCompare(v *NPRSConfigurationValueCodec) *func(NPRSConfiguration, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeNPRSConfigurationValueCodecFieldContext(v *NPRSConfigurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNPRSConfigurationValueCodecFieldDecode(v *NPRSConfigurationValueCodec) *func([]byte, aper.DecodeState) (NPRSConfiguration, error) {
	return &v.decode
}
func BridgeNPRSConfigurationValueCodecFieldEncode(v *NPRSConfigurationValueCodec) *func(NPRSConfiguration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNPRSConfigurationValueCodecFieldPath(v *NPRSConfigurationValueCodec) *aper.Path {
	return &v.path
}
func BridgeNPRSConfigurationValueCodecMethodEncodeBudget(v NPRSConfigurationValueCodec, a0 NPRSConfiguration, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNPRSConfigurationValueCodecMethodEncodeChanged(v NPRSConfigurationValueCodec, a0 NPRSConfiguration, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNPRSMutingConfigurationAPERValueFieldContext(v *NPRSMutingConfigurationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNPRSMutingConfigurationAPERValueFieldReceived(v *NPRSMutingConfigurationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeNPRSMutingConfigurationAPERValueFieldReplay(v *NPRSMutingConfigurationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeNPRSMutingConfigurationAPERValueFieldWithoutReplay(v *NPRSMutingConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNPRSMutingConfigurationFieldKnownOpenBytes(v *NPRSMutingConfiguration) *uint64 {
	return &v.knownOpenBytes
}
func BridgeNPRSMutingConfigurationFieldPerOpenTypePadding(v *NPRSMutingConfiguration) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeNPRSMutingConfigurationFieldPerPadding(v *NPRSMutingConfiguration) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeNPRSMutingConfigurationFieldReceived(v *NPRSMutingConfiguration) *bool { return &v.received }
func BridgeNPRSMutingConfigurationFieldReceivedBytes(v *NPRSMutingConfiguration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeNPRSMutingConfigurationFieldReplay(v *NPRSMutingConfiguration) *aper.Snapshot {
	return &v.replay
}
func BridgeNPRSMutingConfigurationFieldStream(v *NPRSMutingConfiguration) *aper.WireSpan {
	return &v.stream
}
func BridgeNPRSMutingConfigurationFieldWithoutReplay(v *NPRSMutingConfiguration) *bool {
	return &v.withoutReplay
}
func BridgeNPRSMutingConfigurationMethodMarshalAPERBudget(v *NPRSMutingConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNPRSMutingConfigurationMethodMarshalAPERChanged(v *NPRSMutingConfiguration, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNPRSMutingConfigurationMethodMarshalAPERChangedValue(v *NPRSMutingConfiguration, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNPRSMutingConfigurationMethodMarshalAPERFreshValue(v *NPRSMutingConfiguration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeNPRSMutingConfigurationMethodMarshalAPERLegacy(v *NPRSMutingConfiguration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeNPRSMutingConfigurationMethodMarshalAPERPlanned(v *NPRSMutingConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeNPRSMutingConfigurationMethodMarshalAPERTo(v *NPRSMutingConfiguration, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNPRSMutingConfigurationMethodUnmarshalAPERFrom(v *NPRSMutingConfiguration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNPRSMutingConfigurationMethodUnmarshalAPERLegacy(v *NPRSMutingConfiguration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNPRSMutingConfigurationMethodUnmarshalAPERWithOptions(v *NPRSMutingConfiguration, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeNPRSMutingConfigurationValueCodecFieldCapture(v *NPRSMutingConfigurationValueCodec) *func(NPRSMutingConfiguration, aper.DecodeState) (NPRSMutingConfiguration, aper.Snapshot) {
	return &v.capture
}
func BridgeNPRSMutingConfigurationValueCodecFieldCompare(v *NPRSMutingConfigurationValueCodec) *func(NPRSMutingConfiguration, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeNPRSMutingConfigurationValueCodecFieldContext(v *NPRSMutingConfigurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNPRSMutingConfigurationValueCodecFieldDecode(v *NPRSMutingConfigurationValueCodec) *func([]byte, aper.DecodeState) (NPRSMutingConfiguration, error) {
	return &v.decode
}
func BridgeNPRSMutingConfigurationValueCodecFieldEncode(v *NPRSMutingConfigurationValueCodec) *func(NPRSMutingConfiguration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNPRSMutingConfigurationValueCodecFieldPath(v *NPRSMutingConfigurationValueCodec) *aper.Path {
	return &v.path
}
func BridgeNPRSMutingConfigurationValueCodecMethodEncodeBudget(v NPRSMutingConfigurationValueCodec, a0 NPRSMutingConfiguration, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNPRSMutingConfigurationValueCodecMethodEncodeChanged(v NPRSMutingConfigurationValueCodec, a0 NPRSMutingConfiguration, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNPRSSubframePartAAPERValueFieldContext(v *NPRSSubframePartAAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNPRSSubframePartAAPERValueFieldReceived(v *NPRSSubframePartAAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeNPRSSubframePartAAPERValueFieldReplay(v *NPRSSubframePartAAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeNPRSSubframePartAAPERValueFieldWithoutReplay(v *NPRSSubframePartAAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNPRSSubframePartAFieldExtCount(v *NPRSSubframePartA) *int64   { return &v.extCount }
func BridgeNPRSSubframePartAFieldExtData(v *NPRSSubframePartA) *[][]byte { return &v.extData }
func BridgeNPRSSubframePartAFieldExtOrigin(v *NPRSSubframePartA) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeNPRSSubframePartAFieldExtPresent(v *NPRSSubframePartA) *[]bool       { return &v.extPresent }
func BridgeNPRSSubframePartAFieldExtWire(v *NPRSSubframePartA) *[]aper.WireSpan { return &v.extWire }
func BridgeNPRSSubframePartAFieldPerExtPadding(v *NPRSSubframePartA) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeNPRSSubframePartAFieldPerPadding(v *NPRSSubframePartA) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeNPRSSubframePartAFieldReceived(v *NPRSSubframePartA) *bool { return &v.received }
func BridgeNPRSSubframePartAFieldReceivedBytes(v *NPRSSubframePartA) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeNPRSSubframePartAFieldReplay(v *NPRSSubframePartA) *aper.Snapshot { return &v.replay }
func BridgeNPRSSubframePartAFieldStream(v *NPRSSubframePartA) *aper.WireSpan { return &v.stream }
func BridgeNPRSSubframePartAFieldWithoutReplay(v *NPRSSubframePartA) *bool   { return &v.withoutReplay }
func BridgeNPRSSubframePartAMethodMarshalAPERBudget(v *NPRSSubframePartA, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNPRSSubframePartAMethodMarshalAPERChanged(v *NPRSSubframePartA, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNPRSSubframePartAMethodMarshalAPERChangedValue(v *NPRSSubframePartA, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNPRSSubframePartAMethodMarshalAPERFreshValue(v *NPRSSubframePartA, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeNPRSSubframePartAMethodMarshalAPERLegacy(v *NPRSSubframePartA) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeNPRSSubframePartAMethodMarshalAPERPlanned(v *NPRSSubframePartA, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeNPRSSubframePartAMethodMarshalAPERTo(v *NPRSSubframePartA, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNPRSSubframePartAMethodUnmarshalAPERFrom(v *NPRSSubframePartA, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNPRSSubframePartAMethodUnmarshalAPERLegacy(v *NPRSSubframePartA, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNPRSSubframePartAMethodUnmarshalAPERWithOptions(v *NPRSSubframePartA, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeNPRSSubframePartAValueCodecFieldCapture(v *NPRSSubframePartAValueCodec) *func(NPRSSubframePartA, aper.DecodeState) (NPRSSubframePartA, aper.Snapshot) {
	return &v.capture
}
func BridgeNPRSSubframePartAValueCodecFieldCompare(v *NPRSSubframePartAValueCodec) *func(NPRSSubframePartA, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeNPRSSubframePartAValueCodecFieldContext(v *NPRSSubframePartAValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNPRSSubframePartAValueCodecFieldDecode(v *NPRSSubframePartAValueCodec) *func([]byte, aper.DecodeState) (NPRSSubframePartA, error) {
	return &v.decode
}
func BridgeNPRSSubframePartAValueCodecFieldEncode(v *NPRSSubframePartAValueCodec) *func(NPRSSubframePartA, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNPRSSubframePartAValueCodecFieldPath(v *NPRSSubframePartAValueCodec) *aper.Path {
	return &v.path
}
func BridgeNPRSSubframePartAValueCodecMethodEncodeBudget(v NPRSSubframePartAValueCodec, a0 NPRSSubframePartA, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNPRSSubframePartAValueCodecMethodEncodeChanged(v NPRSSubframePartAValueCodec, a0 NPRSSubframePartA, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNPRSSubframePartBAPERValueFieldContext(v *NPRSSubframePartBAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNPRSSubframePartBAPERValueFieldReceived(v *NPRSSubframePartBAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeNPRSSubframePartBAPERValueFieldReplay(v *NPRSSubframePartBAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeNPRSSubframePartBAPERValueFieldWithoutReplay(v *NPRSSubframePartBAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNPRSSubframePartBFieldExtCount(v *NPRSSubframePartB) *int64   { return &v.extCount }
func BridgeNPRSSubframePartBFieldExtData(v *NPRSSubframePartB) *[][]byte { return &v.extData }
func BridgeNPRSSubframePartBFieldExtOrigin(v *NPRSSubframePartB) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeNPRSSubframePartBFieldExtPresent(v *NPRSSubframePartB) *[]bool       { return &v.extPresent }
func BridgeNPRSSubframePartBFieldExtWire(v *NPRSSubframePartB) *[]aper.WireSpan { return &v.extWire }
func BridgeNPRSSubframePartBFieldKnownOpenBytes(v *NPRSSubframePartB) *uint64 {
	return &v.knownOpenBytes
}
func BridgeNPRSSubframePartBFieldPerExtPadding(v *NPRSSubframePartB) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeNPRSSubframePartBFieldPerPadding(v *NPRSSubframePartB) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeNPRSSubframePartBFieldReceived(v *NPRSSubframePartB) *bool { return &v.received }
func BridgeNPRSSubframePartBFieldReceivedBytes(v *NPRSSubframePartB) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeNPRSSubframePartBFieldReplay(v *NPRSSubframePartB) *aper.Snapshot { return &v.replay }
func BridgeNPRSSubframePartBFieldStream(v *NPRSSubframePartB) *aper.WireSpan { return &v.stream }
func BridgeNPRSSubframePartBFieldWithoutReplay(v *NPRSSubframePartB) *bool   { return &v.withoutReplay }
func BridgeNPRSSubframePartBMethodMarshalAPERBudget(v *NPRSSubframePartB, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNPRSSubframePartBMethodMarshalAPERChanged(v *NPRSSubframePartB, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNPRSSubframePartBMethodMarshalAPERChangedValue(v *NPRSSubframePartB, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNPRSSubframePartBMethodMarshalAPERFreshValue(v *NPRSSubframePartB, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeNPRSSubframePartBMethodMarshalAPERLegacy(v *NPRSSubframePartB) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeNPRSSubframePartBMethodMarshalAPERPlanned(v *NPRSSubframePartB, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeNPRSSubframePartBMethodMarshalAPERTo(v *NPRSSubframePartB, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNPRSSubframePartBMethodUnmarshalAPERFrom(v *NPRSSubframePartB, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNPRSSubframePartBMethodUnmarshalAPERLegacy(v *NPRSSubframePartB, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNPRSSubframePartBMethodUnmarshalAPERWithOptions(v *NPRSSubframePartB, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeNPRSSubframePartBValueCodecFieldCapture(v *NPRSSubframePartBValueCodec) *func(NPRSSubframePartB, aper.DecodeState) (NPRSSubframePartB, aper.Snapshot) {
	return &v.capture
}
func BridgeNPRSSubframePartBValueCodecFieldCompare(v *NPRSSubframePartBValueCodec) *func(NPRSSubframePartB, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeNPRSSubframePartBValueCodecFieldContext(v *NPRSSubframePartBValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNPRSSubframePartBValueCodecFieldDecode(v *NPRSSubframePartBValueCodec) *func([]byte, aper.DecodeState) (NPRSSubframePartB, error) {
	return &v.decode
}
func BridgeNPRSSubframePartBValueCodecFieldEncode(v *NPRSSubframePartBValueCodec) *func(NPRSSubframePartB, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNPRSSubframePartBValueCodecFieldPath(v *NPRSSubframePartBValueCodec) *aper.Path {
	return &v.path
}
func BridgeNPRSSubframePartBValueCodecMethodEncodeBudget(v NPRSSubframePartBValueCodec, a0 NPRSSubframePartB, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNPRSSubframePartBValueCodecMethodEncodeChanged(v NPRSSubframePartBValueCodec, a0 NPRSSubframePartB, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNRCGIAPERValueFieldContext(v *NRCGIAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeNRCGIAPERValueFieldReceived(v *NRCGIAPERValue) *aper.WireSpan         { return &v.received }
func BridgeNRCGIAPERValueFieldReplay(v *NRCGIAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeNRCGIAPERValueFieldWithoutReplay(v *NRCGIAPERValue) *bool             { return &v.withoutReplay }
func BridgeNRCGIFieldExtCount(v *NRCGI) *int64                                   { return &v.extCount }
func BridgeNRCGIFieldExtData(v *NRCGI) *[][]byte                                 { return &v.extData }
func BridgeNRCGIFieldExtOrigin(v *NRCGI) *[]aper.OpaqueOrigin                    { return &v.extOrigin }
func BridgeNRCGIFieldExtPresent(v *NRCGI) *[]bool                                { return &v.extPresent }
func BridgeNRCGIFieldExtWire(v *NRCGI) *[]aper.WireSpan                          { return &v.extWire }
func BridgeNRCGIFieldIEExtensionsIndef(v *NRCGI) *bool                           { return &v.iEExtensionsIndef }
func BridgeNRCGIFieldPerExtPadding(v *NRCGI) *[]aper.CompletePadding             { return &v.perExtPadding }
func BridgeNRCGIFieldPerPadding(v *NRCGI) *aper.FinalPadding                     { return &v.perPadding }
func BridgeNRCGIFieldReceived(v *NRCGI) *bool                                    { return &v.received }
func BridgeNRCGIFieldReceivedBytes(v *NRCGI) *aper.WireSpan                      { return &v.receivedBytes }
func BridgeNRCGIFieldReplay(v *NRCGI) *aper.Snapshot                             { return &v.replay }
func BridgeNRCGIFieldStream(v *NRCGI) *aper.WireSpan                             { return &v.stream }
func BridgeNRCGIFieldWithoutReplay(v *NRCGI) *bool                               { return &v.withoutReplay }
func BridgeNRCGIMethodMarshalAPERBudget(v *NRCGI, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNRCGIMethodMarshalAPERChanged(v *NRCGI, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNRCGIMethodMarshalAPERChangedValue(v *NRCGI, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNRCGIMethodMarshalAPERFreshValue(v *NRCGI, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeNRCGIMethodMarshalAPERLegacy(v *NRCGI) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeNRCGIMethodMarshalAPERPlanned(v *NRCGI, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeNRCGIMethodMarshalAPERTo(v *NRCGI, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNRCGIMethodUnmarshalAPERFrom(v *NRCGI, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNRCGIMethodUnmarshalAPERLegacy(v *NRCGI, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNRCGIMethodUnmarshalAPERWithOptions(v *NRCGI, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeNRCGIValueCodecFieldCapture(v *NRCGIValueCodec) *func(NRCGI, aper.DecodeState) (NRCGI, aper.Snapshot) {
	return &v.capture
}
func BridgeNRCGIValueCodecFieldCompare(v *NRCGIValueCodec) *func(NRCGI, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeNRCGIValueCodecFieldContext(v *NRCGIValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeNRCGIValueCodecFieldDecode(v *NRCGIValueCodec) *func([]byte, aper.DecodeState) (NRCGI, error) {
	return &v.decode
}
func BridgeNRCGIValueCodecFieldEncode(v *NRCGIValueCodec) *func(NRCGI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRCGIValueCodecFieldPath(v *NRCGIValueCodec) *aper.Path { return &v.path }
func BridgeNRCGIValueCodecMethodEncodeBudget(v NRCGIValueCodec, a0 NRCGI, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNRCGIValueCodecMethodEncodeChanged(v NRCGIValueCodec, a0 NRCGI, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOAInformationTypeAPERValueFieldContext(v *OTDOAInformationTypeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationTypeAPERValueFieldReceived(v *OTDOAInformationTypeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationTypeAPERValueFieldReplay(v *OTDOAInformationTypeAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationTypeAPERValueFieldWithoutReplay(v *OTDOAInformationTypeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationTypeIEFieldFieldReceived(v *OTDOAInformationTypeIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeOTDOAInformationTypeIEFieldFieldReplay(v *OTDOAInformationTypeIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationTypeIEFieldFieldStream(v *OTDOAInformationTypeIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationTypeIEFieldFieldWithoutReplay(v *OTDOAInformationTypeIEField) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationTypeIEFieldMethodMarshalAPERTo(v *OTDOAInformationTypeIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationTypeIEFieldMethodUnmarshalAPERFrom(v *OTDOAInformationTypeIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationTypeIETableMethodInfoOTDOAInformationTypeItem(v OTDOAInformationTypeIETable) s00.FieldInfo {
	return v.infoOTDOAInformationTypeItem()
}
func BridgeOTDOAInformationTypeIEValueFieldId(v *OTDOAInformationTypeIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeOTDOAInformationTypeIEValueFieldIsOpaque(v *OTDOAInformationTypeIEValue) *bool {
	return &v.isOpaque
}
func BridgeOTDOAInformationTypeIEValueFieldOpaque(v *OTDOAInformationTypeIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeOTDOAInformationTypeIEValueFieldReceived(v *OTDOAInformationTypeIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationTypeIEValueFieldReplay(v *OTDOAInformationTypeIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationTypeIEValueFieldRowOTDOAInformationTypeItem(v *OTDOAInformationTypeIEValue) **OTDOAInformationTypeItem {
	return &v.rowOTDOAInformationTypeItem
}
func BridgeOTDOAInformationTypeIEValueFieldWithoutReplay(v *OTDOAInformationTypeIEValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationTypeIEValueMethodCaptureFraming(v OTDOAInformationTypeIEValue) uint64 {
	return v.captureFraming()
}
func BridgeOTDOAInformationTypeIEValueMethodCaptureSemantics(v OTDOAInformationTypeIEValue, a0 aper.SemanticCapture) OTDOAInformationTypeIEValue {
	return v.captureSemantics(a0)
}
func BridgeOTDOAInformationTypeIEValueMethodCaptureSnapshot(v OTDOAInformationTypeIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeOTDOAInformationTypeIEValueMethodCompareSemantics(v OTDOAInformationTypeIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeOTDOAInformationTypeIEValueMethodDecode(v OTDOAInformationTypeIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (OTDOAInformationTypeIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeOTDOAInformationTypeIEValueMethodEncode(v OTDOAInformationTypeIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeOTDOAInformationTypeIEValueMethodEncodeFresh(v OTDOAInformationTypeIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeOTDOAInformationTypeIEValueMethodMatchesID(v OTDOAInformationTypeIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeOTDOAInformationTypeIEValueMethodReason(v OTDOAInformationTypeIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeOTDOAInformationTypeIEValueMethodRule(v OTDOAInformationTypeIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeOTDOAInformationTypeItemAPERValueFieldContext(v *OTDOAInformationTypeItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationTypeItemAPERValueFieldReceived(v *OTDOAInformationTypeItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationTypeItemAPERValueFieldReplay(v *OTDOAInformationTypeItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationTypeItemAPERValueFieldWithoutReplay(v *OTDOAInformationTypeItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationTypeItemFieldExtCount(v *OTDOAInformationTypeItem) *int64 {
	return &v.extCount
}
func BridgeOTDOAInformationTypeItemFieldExtData(v *OTDOAInformationTypeItem) *[][]byte {
	return &v.extData
}
func BridgeOTDOAInformationTypeItemFieldExtOrigin(v *OTDOAInformationTypeItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeOTDOAInformationTypeItemFieldExtPresent(v *OTDOAInformationTypeItem) *[]bool {
	return &v.extPresent
}
func BridgeOTDOAInformationTypeItemFieldExtWire(v *OTDOAInformationTypeItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeOTDOAInformationTypeItemFieldIEExtensionsIndef(v *OTDOAInformationTypeItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeOTDOAInformationTypeItemFieldPerExtPadding(v *OTDOAInformationTypeItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeOTDOAInformationTypeItemFieldPerPadding(v *OTDOAInformationTypeItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeOTDOAInformationTypeItemFieldReceived(v *OTDOAInformationTypeItem) *bool {
	return &v.received
}
func BridgeOTDOAInformationTypeItemFieldReceivedBytes(v *OTDOAInformationTypeItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeOTDOAInformationTypeItemFieldReplay(v *OTDOAInformationTypeItem) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationTypeItemFieldStream(v *OTDOAInformationTypeItem) *aper.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationTypeItemFieldWithoutReplay(v *OTDOAInformationTypeItem) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationTypeItemMethodMarshalAPERBudget(v *OTDOAInformationTypeItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOTDOAInformationTypeItemMethodMarshalAPERChanged(v *OTDOAInformationTypeItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOTDOAInformationTypeItemMethodMarshalAPERChangedValue(v *OTDOAInformationTypeItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOTDOAInformationTypeItemMethodMarshalAPERFreshValue(v *OTDOAInformationTypeItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeOTDOAInformationTypeItemMethodMarshalAPERLegacy(v *OTDOAInformationTypeItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOTDOAInformationTypeItemMethodMarshalAPERPlanned(v *OTDOAInformationTypeItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeOTDOAInformationTypeItemMethodMarshalAPERTo(v *OTDOAInformationTypeItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationTypeItemMethodUnmarshalAPERFrom(v *OTDOAInformationTypeItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationTypeItemMethodUnmarshalAPERLegacy(v *OTDOAInformationTypeItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOTDOAInformationTypeItemMethodUnmarshalAPERWithOptions(v *OTDOAInformationTypeItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOTDOAInformationTypeItemValueCodecFieldCapture(v *OTDOAInformationTypeItemValueCodec) *func(OTDOAInformationTypeItem, aper.DecodeState) (OTDOAInformationTypeItem, aper.Snapshot) {
	return &v.capture
}
func BridgeOTDOAInformationTypeItemValueCodecFieldCompare(v *OTDOAInformationTypeItemValueCodec) *func(OTDOAInformationTypeItem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeOTDOAInformationTypeItemValueCodecFieldContext(v *OTDOAInformationTypeItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationTypeItemValueCodecFieldDecode(v *OTDOAInformationTypeItemValueCodec) *func([]byte, aper.DecodeState) (OTDOAInformationTypeItem, error) {
	return &v.decode
}
func BridgeOTDOAInformationTypeItemValueCodecFieldEncode(v *OTDOAInformationTypeItemValueCodec) *func(OTDOAInformationTypeItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOAInformationTypeItemValueCodecFieldPath(v *OTDOAInformationTypeItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeOTDOAInformationTypeItemValueCodecMethodEncodeBudget(v OTDOAInformationTypeItemValueCodec, a0 OTDOAInformationTypeItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOAInformationTypeItemValueCodecMethodEncodeChanged(v OTDOAInformationTypeItemValueCodec, a0 OTDOAInformationTypeItem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOAInformationTypeOTDOAInformationTypeItemIEBindingFieldCodec(v *OTDOAInformationTypeOTDOAInformationTypeItemIEBinding) *OTDOAInformationTypeItemValueCodec {
	return &v.codec
}
func BridgeOTDOAInformationTypeOTDOAInformationTypeItemIEBindingFieldGet(v *OTDOAInformationTypeOTDOAInformationTypeItemIEBinding) *func(*OTDOAInformationTypeIEValue) (*OTDOAInformationTypeItem, bool) {
	return &v.get
}
func BridgeOTDOAInformationTypeOTDOAInformationTypeItemIEBindingFieldInfo(v *OTDOAInformationTypeOTDOAInformationTypeItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeOTDOAInformationTypeOTDOAInformationTypeItemIEBindingFieldInject(v *OTDOAInformationTypeOTDOAInformationTypeItemIEBinding) *func(OTDOAInformationTypeItem) OTDOAInformationTypeIEValue {
	return &v.inject
}
func BridgeOTDOAInformationTypeValueCodecFieldCapture(v *OTDOAInformationTypeValueCodec) *func(OTDOAInformationType, aper.DecodeState) (OTDOAInformationType, aper.Snapshot) {
	return &v.capture
}
func BridgeOTDOAInformationTypeValueCodecFieldCompare(v *OTDOAInformationTypeValueCodec) *func(OTDOAInformationType, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeOTDOAInformationTypeValueCodecFieldContext(v *OTDOAInformationTypeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationTypeValueCodecFieldDecode(v *OTDOAInformationTypeValueCodec) *func([]byte, aper.DecodeState) (OTDOAInformationType, error) {
	return &v.decode
}
func BridgeOTDOAInformationTypeValueCodecFieldEncode(v *OTDOAInformationTypeValueCodec) *func(OTDOAInformationType, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOAInformationTypeValueCodecFieldPath(v *OTDOAInformationTypeValueCodec) *aper.Path {
	return &v.path
}
func BridgeOTDOAInformationTypeValueCodecMethodEncodeBudget(v OTDOAInformationTypeValueCodec, a0 OTDOAInformationType, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOAInformationTypeValueCodecMethodEncodeChanged(v OTDOAInformationTypeValueCodec, a0 OTDOAInformationType, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
