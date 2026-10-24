// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s07 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s07

import (
	q6 "fmt"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q11 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	q7 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// OTDOAInformationTypeIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[OTDOAInformationTypeIEValue].
type OTDOAInformationTypeIEValueProtocolIESingleContainer = OTDOAInformationTypeIEField

// NRCGIValueCodec is the concrete ValueCodec[NRCGI].
type NRCGIValueCodec struct {
	context q4.BridgeCodecContext
	capture func(NRCGI, q5.DecodeState,

	) (NRCGI, q5.Snapshot,

	)
	compare func(NRCGI, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (NRCGI,

		error)
	encode func(NRCGI,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c NRCGIValueCodec) New(value NRCGI,

) (NRCGIAPERValue, error) {
	if c.encode == nil {
		return NRCGIAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return NRCGIAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRCGIAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return NRCGIAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c NRCGIValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (NRCGIAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NRCGIAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return NRCGIAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NRCGIAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return NRCGIAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return NRCGIAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c NRCGIValueCodec) EncodeAPER(value NRCGIAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c NRCGIValueCodec) encodeBudget(value NRCGI,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NRCGIValueCodec) encodeChanged(value NRCGI,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// OTDOAInformationTypeOTDOAInformationTypeItemIEBinding is the concrete IEBinding[OTDOAInformationTypeItem, OTDOAInformationTypeIEValue].
type OTDOAInformationTypeOTDOAInformationTypeItemIEBinding struct {
	info   q4.FieldInfo
	codec  OTDOAInformationTypeItemValueCodec
	inject func(OTDOAInformationTypeItem,

	) OTDOAInformationTypeIEValue

	get func(*OTDOAInformationTypeIEValue,

	) (*OTDOAInformationTypeItem,

		bool)
}

func (b OTDOAInformationTypeOTDOAInformationTypeItemIEBinding) Info() q4.FieldInfo { return b.info }
func (b OTDOAInformationTypeOTDOAInformationTypeItemIEBinding) Codec() OTDOAInformationTypeItemValueCodec {
	return b.codec
}
func (b OTDOAInformationTypeOTDOAInformationTypeItemIEBinding) New(value OTDOAInformationTypeItem,

) (OTDOAInformationTypeIEField, error) {
	if b.inject == nil {
		return OTDOAInformationTypeIEField{}, q5.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return OTDOAInformationTypeIEField{}, q5.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return OTDOAInformationTypeIEField{}, q5.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q5.ChargeValue(q5.NewBudgetBuffer(budget), value); err != nil {
		return OTDOAInformationTypeIEField{}, q5.OperationError(err, "Value.New")
	}
	return OTDOAInformationTypeIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q5.OperationError(nil, "Value.New")
}
func (b OTDOAInformationTypeOTDOAInformationTypeItemIEBinding) Get(field *OTDOAInformationTypeIEField) (*OTDOAInformationTypeItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// OTDOAInformationTypeItemValueCodec is the concrete ValueCodec[OTDOAInformationTypeItem].
type OTDOAInformationTypeItemValueCodec struct {
	context q4.BridgeCodecContext
	capture func(OTDOAInformationTypeItem, q5.DecodeState,

	) (OTDOAInformationTypeItem, q5.Snapshot,

	)
	compare func(OTDOAInformationTypeItem, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (OTDOAInformationTypeItem,

		error)
	encode func(OTDOAInformationTypeItem,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c OTDOAInformationTypeItemValueCodec) New(value OTDOAInformationTypeItem,

) (OTDOAInformationTypeItemAPERValue, error) {
	if c.encode == nil {
		return OTDOAInformationTypeItemAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return OTDOAInformationTypeItemAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOAInformationTypeItemAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return OTDOAInformationTypeItemAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c OTDOAInformationTypeItemValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (OTDOAInformationTypeItemAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOAInformationTypeItemAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return OTDOAInformationTypeItemAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOAInformationTypeItemAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return OTDOAInformationTypeItemAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return OTDOAInformationTypeItemAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c OTDOAInformationTypeItemValueCodec) EncodeAPER(value OTDOAInformationTypeItemAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c OTDOAInformationTypeItemValueCodec) encodeBudget(value OTDOAInformationTypeItem,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOAInformationTypeItemValueCodec) encodeChanged(value OTDOAInformationTypeItem,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// OTDOAInformationTypeIEField is the concrete ProtocolIEField[OTDOAInformationTypeIEValue].
type OTDOAInformationTypeIEField struct {
	withoutReplay bool
	replay        q5.Snapshot
	stream        q5.WireSpan
	Id            q4.ProtocolIEID
	Criticality   q4.Criticality
	Value         OTDOAInformationTypeIEValue

	received q5.CompletePadding
}

func (v OTDOAInformationTypeIEField) WithoutReplay() OTDOAInformationTypeIEField {
	v.withoutReplay = true
	v.stream = q5.WireSpan{}
	return v
}
func (v *OTDOAInformationTypeIEField) ReceivedForm() q5.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q5.ReceivedForm{}
	}
	return q5.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *OTDOAInformationTypeIEField) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
		return q7.WrapDecodePath(q6.Errorf("%w: field id %d does not match its value selector", q5.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q5.EncodeIntegerAligned(bb, int64(v.Id), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false); err != nil {
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
func (v *OTDOAInformationTypeIEField) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationTypeIEField{}
	id, err := q5.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q7.WrapDecodePath(err, "Id")
	}
	v.Id = q4.ProtocolIEID(id)
	criticality, err := q5.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q7.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q4.Criticality(criticality)
	var zero OTDOAInformationTypeIEValue

	raw, err := q5.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
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

// OTDOAInformationTypeValueCodec is the concrete ValueCodec[OTDOAInformationType].
type OTDOAInformationTypeValueCodec struct {
	context q4.BridgeCodecContext
	capture func(OTDOAInformationType, q5.DecodeState,

	) (OTDOAInformationType, q5.Snapshot,

	)
	compare func(OTDOAInformationType, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (OTDOAInformationType,

		error)
	encode func(OTDOAInformationType,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c OTDOAInformationTypeValueCodec) New(value OTDOAInformationType,

) (OTDOAInformationTypeAPERValue, error) {
	if c.encode == nil {
		return OTDOAInformationTypeAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return OTDOAInformationTypeAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOAInformationTypeAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return OTDOAInformationTypeAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c OTDOAInformationTypeValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (OTDOAInformationTypeAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOAInformationTypeAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return OTDOAInformationTypeAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOAInformationTypeAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return OTDOAInformationTypeAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return OTDOAInformationTypeAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c OTDOAInformationTypeValueCodec) EncodeAPER(value OTDOAInformationTypeAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c OTDOAInformationTypeValueCodec) encodeBudget(value OTDOAInformationType,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOAInformationTypeValueCodec) encodeChanged(value OTDOAInformationType,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// NPRSConfigurationValueCodec is the concrete ValueCodec[NPRSConfiguration].
type NPRSConfigurationValueCodec struct {
	context q4.BridgeCodecContext
	capture func(NPRSConfiguration, q5.DecodeState,

	) (NPRSConfiguration, q5.Snapshot,

	)
	compare func(NPRSConfiguration, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (NPRSConfiguration,

		error)
	encode func(NPRSConfiguration,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c NPRSConfigurationValueCodec) New(value NPRSConfiguration,

) (NPRSConfigurationAPERValue, error) {
	if c.encode == nil {
		return NPRSConfigurationAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return NPRSConfigurationAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NPRSConfigurationAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return NPRSConfigurationAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c NPRSConfigurationValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (NPRSConfigurationAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NPRSConfigurationAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return NPRSConfigurationAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NPRSConfigurationAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return NPRSConfigurationAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return NPRSConfigurationAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c NPRSConfigurationValueCodec) EncodeAPER(value NPRSConfigurationAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c NPRSConfigurationValueCodec) encodeBudget(value NPRSConfiguration,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NPRSConfigurationValueCodec) encodeChanged(value NPRSConfiguration,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// NPRSMutingConfigurationValueCodec is the concrete ValueCodec[NPRSMutingConfiguration].
type NPRSMutingConfigurationValueCodec struct {
	context q4.BridgeCodecContext
	capture func(NPRSMutingConfiguration, q5.DecodeState,

	) (NPRSMutingConfiguration, q5.Snapshot,

	)
	compare func(NPRSMutingConfiguration, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (NPRSMutingConfiguration,

		error)
	encode func(NPRSMutingConfiguration,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c NPRSMutingConfigurationValueCodec) New(value NPRSMutingConfiguration,

) (NPRSMutingConfigurationAPERValue, error) {
	if c.encode == nil {
		return NPRSMutingConfigurationAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return NPRSMutingConfigurationAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NPRSMutingConfigurationAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return NPRSMutingConfigurationAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c NPRSMutingConfigurationValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (NPRSMutingConfigurationAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NPRSMutingConfigurationAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return NPRSMutingConfigurationAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NPRSMutingConfigurationAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return NPRSMutingConfigurationAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return NPRSMutingConfigurationAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c NPRSMutingConfigurationValueCodec) EncodeAPER(value NPRSMutingConfigurationAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c NPRSMutingConfigurationValueCodec) encodeBudget(value NPRSMutingConfiguration,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NPRSMutingConfigurationValueCodec) encodeChanged(value NPRSMutingConfiguration,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// NPRSSubframePartAValueCodec is the concrete ValueCodec[NPRSSubframePartA].
type NPRSSubframePartAValueCodec struct {
	context q4.BridgeCodecContext
	capture func(NPRSSubframePartA, q5.DecodeState,

	) (NPRSSubframePartA, q5.Snapshot,

	)
	compare func(NPRSSubframePartA, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (NPRSSubframePartA,

		error)
	encode func(NPRSSubframePartA,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c NPRSSubframePartAValueCodec) New(value NPRSSubframePartA,

) (NPRSSubframePartAAPERValue, error) {
	if c.encode == nil {
		return NPRSSubframePartAAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return NPRSSubframePartAAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NPRSSubframePartAAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return NPRSSubframePartAAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c NPRSSubframePartAValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (NPRSSubframePartAAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NPRSSubframePartAAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return NPRSSubframePartAAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NPRSSubframePartAAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return NPRSSubframePartAAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return NPRSSubframePartAAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c NPRSSubframePartAValueCodec) EncodeAPER(value NPRSSubframePartAAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c NPRSSubframePartAValueCodec) encodeBudget(value NPRSSubframePartA,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NPRSSubframePartAValueCodec) encodeChanged(value NPRSSubframePartA,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// NPRSSubframePartBValueCodec is the concrete ValueCodec[NPRSSubframePartB].
type NPRSSubframePartBValueCodec struct {
	context q4.BridgeCodecContext
	capture func(NPRSSubframePartB, q5.DecodeState,

	) (NPRSSubframePartB, q5.Snapshot,

	)
	compare func(NPRSSubframePartB, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (NPRSSubframePartB,

		error)
	encode func(NPRSSubframePartB,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c NPRSSubframePartBValueCodec) New(value NPRSSubframePartB,

) (NPRSSubframePartBAPERValue, error) {
	if c.encode == nil {
		return NPRSSubframePartBAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return NPRSSubframePartBAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NPRSSubframePartBAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return NPRSSubframePartBAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c NPRSSubframePartBValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (NPRSSubframePartBAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NPRSSubframePartBAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return NPRSSubframePartBAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NPRSSubframePartBAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return NPRSSubframePartBAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return NPRSSubframePartBAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c NPRSSubframePartBValueCodec) EncodeAPER(value NPRSSubframePartBAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c NPRSSubframePartBValueCodec) encodeBudget(value NPRSSubframePartB,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NPRSSubframePartBValueCodec) encodeChanged(value NPRSSubframePartB,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// OTDOAInformationTypeIEContainer is the concrete ProtocolIEContainer[OTDOAInformationTypeIEValue].
type OTDOAInformationTypeIEContainer []OTDOAInformationTypeIEField

// NRCGIAPERValue is the concrete APERValue[NRCGI].
type NRCGIAPERValue struct {
	context q4.BridgeCodecContext
	Value   NRCGI

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v NRCGIAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v NRCGIAPERValue) WithoutReplay() NRCGIAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// OTDOAInformationTypeItemAPERValue is the concrete APERValue[OTDOAInformationTypeItem].
type OTDOAInformationTypeItemAPERValue struct {
	context q4.BridgeCodecContext
	Value   OTDOAInformationTypeItem

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v OTDOAInformationTypeItemAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v OTDOAInformationTypeItemAPERValue) WithoutReplay() OTDOAInformationTypeItemAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// OTDOAInformationTypeAPERValue is the concrete APERValue[OTDOAInformationType].
type OTDOAInformationTypeAPERValue struct {
	context q4.BridgeCodecContext
	Value   OTDOAInformationType

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v OTDOAInformationTypeAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v OTDOAInformationTypeAPERValue) WithoutReplay() OTDOAInformationTypeAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// NPRSConfigurationAPERValue is the concrete APERValue[NPRSConfiguration].
type NPRSConfigurationAPERValue struct {
	context q4.BridgeCodecContext
	Value   NPRSConfiguration

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v NPRSConfigurationAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v NPRSConfigurationAPERValue) WithoutReplay() NPRSConfigurationAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// NPRSMutingConfigurationAPERValue is the concrete APERValue[NPRSMutingConfiguration].
type NPRSMutingConfigurationAPERValue struct {
	context q4.BridgeCodecContext
	Value   NPRSMutingConfiguration

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v NPRSMutingConfigurationAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v NPRSMutingConfigurationAPERValue) WithoutReplay() NPRSMutingConfigurationAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// NPRSSubframePartAAPERValue is the concrete APERValue[NPRSSubframePartA].
type NPRSSubframePartAAPERValue struct {
	context q4.BridgeCodecContext
	Value   NPRSSubframePartA

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v NPRSSubframePartAAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v NPRSSubframePartAAPERValue) WithoutReplay() NPRSSubframePartAAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// NPRSSubframePartBAPERValue is the concrete APERValue[NPRSSubframePartB].
type NPRSSubframePartBAPERValue struct {
	context q4.BridgeCodecContext
	Value   NPRSSubframePartB

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v NPRSSubframePartBAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v NPRSSubframePartBAPERValue) WithoutReplay() NPRSSubframePartBAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRCGI represents the ASN.1 type NR-CGI (SEQUENCE).
type NRCGI struct {
	replay            q5.Snapshot
	stream            q5.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     q5.WireSpan
	PLMNIdentity      q4.PLMNIdentity            `asn1:"tag:0,context,implicit"`
	NRCellIdentity    q4.NRCellIdentity          `asn1:"tag:1,context,implicit"`
	IEExtensions      q9.NRCGIExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                       `asn1:"-" json:"-"`
	extCount          int64                      `asn1:"-" json:"-"`
	extPresent        []bool                     `asn1:"-" json:"-"`
	extData           [][]byte                   `asn1:"-" json:"-"`
	perPadding        q5.FinalPadding            `asn1:"-" json:"-"`
	perExtPadding     []q5.CompletePadding       `asn1:"-" json:"-"`
	extOrigin         []q5.OpaqueOrigin
	extWire           []q5.WireSpan
}

// NPRSConfiguration represents the ASN.1 type NPRSConfiguration (SEQUENCE).
type NPRSConfiguration struct {
	replay            q5.Snapshot
	stream            q5.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     q5.WireSpan
	NPRSSubframePartA *NPRSSubframePartA   `asn1:"tag:0,context,implicit,optional" json:"NPRSSubframePartA,omitempty"`
	NPRSSubframePartB *NPRSSubframePartB   `asn1:"tag:1,context,implicit,optional" json:"NPRSSubframePartB,omitempty"`
	extCount          int64                `asn1:"-" json:"-"`
	extPresent        []bool               `asn1:"-" json:"-"`
	extData           [][]byte             `asn1:"-" json:"-"`
	perPadding        q5.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding     []q5.CompletePadding `asn1:"-" json:"-"`
	extOrigin         []q5.OpaqueOrigin
	extWire           []q5.WireSpan
}

// NPRSMutingConfiguration represents the ASN.1 CHOICE type NPRSMutingConfiguration.
type NPRSMutingConfiguration struct {
	knownOpenBytes     uint64
	replay             q5.Snapshot
	stream             q5.WireSpan
	withoutReplay      bool
	received           bool
	receivedBytes      q5.WireSpan
	Choice             int
	perPadding         q5.CompletePadding  `json:"-"`
	perOpenTypePadding q5.CompletePadding  `json:"-"`
	UnknownExtension   *q5.ChoiceExtension `json:"UnknownExtension,omitempty"`
	Two                *q7.BitString       `json:"Two,omitempty"`
	Four               *q7.BitString       `json:"Four,omitempty"`
	Eight              *q7.BitString       `json:"Eight,omitempty"`
	Sixteen            *q7.BitString       `json:"Sixteen,omitempty"`
}

// NPRSSubframePartA represents the ASN.1 type NPRSSubframePartA (SEQUENCE).
type NPRSSubframePartA struct {
	replay                  q5.Snapshot
	stream                  q5.WireSpan
	withoutReplay           bool
	received                bool
	receivedBytes           q5.WireSpan
	BitmapsforNPRS          q10.BitmapsforNPRS       `asn1:"tag:0,context,explicit"`
	NPRSMutingConfiguration *NPRSMutingConfiguration `asn1:"tag:1,context,explicit,optional" json:"NPRSMutingConfiguration,omitempty"`
	extCount                int64                    `asn1:"-" json:"-"`
	extPresent              []bool                   `asn1:"-" json:"-"`
	extData                 [][]byte                 `asn1:"-" json:"-"`
	perPadding              q5.FinalPadding          `asn1:"-" json:"-"`
	perExtPadding           []q5.CompletePadding     `asn1:"-" json:"-"`
	extOrigin               []q5.OpaqueOrigin
	extWire                 []q5.WireSpan
}

// NPRSSubframePartB represents the ASN.1 type NPRSSubframePartB (SEQUENCE).
type NPRSSubframePartB struct {
	knownOpenBytes          uint64
	replay                  q5.Snapshot
	stream                  q5.WireSpan
	withoutReplay           bool
	received                bool
	receivedBytes           q5.WireSpan
	NumberofNPRSOneOccasion int64                    `asn1:"tag:0,context,implicit"`
	PeriodicityofNPRS       int64                    `asn1:"tag:1,context,implicit"`
	Startingsubframeoffset  int64                    `asn1:"tag:2,context,implicit"`
	NPRSMutingConfiguration *NPRSMutingConfiguration `asn1:"tag:3,context,explicit,optional" json:"NPRSMutingConfiguration,omitempty"`
	SIB1NBSubframeTDD       *int64                   `asn1:"tag:4,context,implicit,optional" json:"SIB1NBSubframeTDD,omitempty"`
	extCount                int64                    `asn1:"-" json:"-"`
	extPresent              []bool                   `asn1:"-" json:"-"`
	extData                 [][]byte                 `asn1:"-" json:"-"`
	perPadding              q5.FinalPadding          `asn1:"-" json:"-"`
	perExtPadding           []q5.CompletePadding     `asn1:"-" json:"-"`
	extOrigin               []q5.OpaqueOrigin
	extWire                 []q5.WireSpan
}

// MarshalAPER encodes NRCGI to APER format.
func (v *NRCGI) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *NRCGI) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
	if err := q5.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := q5.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q5.EncodeOctetStringAligned(bb, []byte(v.PLMNIdentity), 3, 3, true); err != nil {
		return q6.Errorf("encoding pLMN-Identity: %w", err)
	}
	if err := q5.EncodeBitStringAligned(bb, v.NRCellIdentity.Bytes, v.NRCellIdentity.BitLength, 36, 36, true); err != nil {
		return q6.Errorf("encoding nRCellIdentity: %w", err)
	}
	if v.IEExtensions != nil {
		if err := q5.EncodeCollection(bb, int64(len(v.IEExtensions)), q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q9.BridgeNRCGIExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
			return q6.Errorf("%w: extension bitmap index %d", q5.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q5.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q5.EncodeBoolean(bb, p); err != nil {
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

// UnmarshalAPER decodes NRCGI from APER format.
func (v *NRCGI) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes NRCGI with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *NRCGI) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "NRCGI")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "NRCGI")
	}
	padding, err := q5.CaptureFinalBits(bb, "NRCGI")
	if err != nil {
		return q7.WrapDecodePath(err, "NRCGI")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *NRCGI) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NRCGI{}
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
	val_plmnidentity, err := q5.DecodeOctetStringAligned(bb, 3, 3, true)
	if err != nil {
		return q7.WrapDecodePath(err, "PLMNIdentity")
	}
	v.PLMNIdentity = q4.PLMNIdentity(val_plmnidentity)
	bsBytes_nrcellidentity, bsBitLen_nrcellidentity, err := q5.DecodeBitStringAligned(bb, 36, 36, true)
	if err != nil {
		return q7.WrapDecodePath(err, "NRCellIdentity")
	}
	v.NRCellIdentity = q7.BitString{Bytes: bsBytes_nrcellidentity, BitLength: bsBitLen_nrcellidentity}
	if opt_ieextensions {
		tmp_ieextensions := make(q9.NRCGIExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q9.NRCGIExtIEsExtField
				if err := q9.BridgeNRCGIExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
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
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q5.DecodeOpaqueOpenTypeAligned(bb, q5.UnknownSelector, q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
				if err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("ExtData_[%d]", i))
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

// MarshalAPER encodes NPRSConfiguration to APER format.
func (v *NPRSConfiguration) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *NPRSConfiguration) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
	if err := q5.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := q5.EncodeBoolean(bb, v.NPRSSubframePartA != nil); err != nil {
		return err
	}
	if err := q5.EncodeBoolean(bb, v.NPRSSubframePartB != nil); err != nil {
		return err
	}
	if v.NPRSSubframePartA != nil {
		if err := v.NPRSSubframePartA.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return q6.Errorf("encoding nPRSSubframePartA: %w", err)
		}
	}
	if v.NPRSSubframePartB != nil {
		if err := v.NPRSSubframePartB.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return q6.Errorf("encoding nPRSSubframePartB: %w", err)
		}
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q6.Errorf("%w: extension bitmap index %d", q5.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q5.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q5.EncodeBoolean(bb, p); err != nil {
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

// UnmarshalAPER decodes NPRSConfiguration from APER format.
func (v *NPRSConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes NPRSConfiguration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *NPRSConfiguration) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "NPRSConfiguration")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "NPRSConfiguration")
	}
	padding, err := q5.CaptureFinalBits(bb, "NPRSConfiguration")
	if err != nil {
		return q7.WrapDecodePath(err, "NPRSConfiguration")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *NPRSConfiguration) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NPRSConfiguration{}
	extAdditions := q5.BeginExtensionAdditions(bb)
	hasExtensions, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_nprssubframeparta, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_nprssubframepartb, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if opt_nprssubframeparta {
		toleranceMark_nprssubframeparta := bb.EnterComponent("NPRSSubframePartA")
		var dec_nprssubframeparta NPRSSubframePartA
		if err := dec_nprssubframeparta.unmarshalAPERFrom(bb); err != nil {
			return q7.WrapDecodePath(err, "NPRSSubframePartA")
		}
		if err := q5.ChargeValue(bb, dec_nprssubframeparta); err != nil {
			return err
		}
		v.NPRSSubframePartA = &dec_nprssubframeparta
		bb.LeaveComponent(toleranceMark_nprssubframeparta)
	}
	if opt_nprssubframepartb {
		toleranceMark_nprssubframepartb := bb.EnterComponent("NPRSSubframePartB")
		var dec_nprssubframepartb NPRSSubframePartB
		if err := dec_nprssubframepartb.unmarshalAPERFrom(bb); err != nil {
			return q7.WrapDecodePath(err, "NPRSSubframePartB")
		}
		if err := q5.ChargeValue(bb, dec_nprssubframepartb); err != nil {
			return err
		}
		v.NPRSSubframePartB = &dec_nprssubframepartb
		bb.LeaveComponent(toleranceMark_nprssubframepartb)
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
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q5.DecodeOpaqueOpenTypeAligned(bb, q5.UnknownSelector, q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
				if err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("ExtData_[%d]", i))
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

// MarshalAPER encodes NPRSMutingConfiguration to APER format.
func (v *NPRSMutingConfiguration) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *NPRSMutingConfiguration) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
			return q6.Errorf("%s known choice %d and unknown extension are both selected", "NPRSMutingConfiguration:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return q6.Errorf("%s extension index %d must be non-negative", "NPRSMutingConfiguration:", v.UnknownExtension.Index())
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
		return q6.Errorf("%s choice %d must be positive", "NPRSMutingConfiguration:", v.Choice)
	}
	isExtension := v.Choice > 4
	if err := q5.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return q6.Errorf("%s extension choice %d not supported", "NPRSMutingConfiguration:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return q6.Errorf("choice index outside root")
	}
	if err := q5.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 3); err != nil {
		return err
	}
	switch v.Choice {
	case q4.NPRSMutingConfigurationChoiceTwo:
		if v.Two == nil {
			return q6.Errorf("choice alternative two is nil")
		}
		if err := q5.EncodeBitStringAligned(bb, v.Two.Bytes, v.Two.BitLength, 2, 2, true); err != nil {
			return q6.Errorf("encoding two: %w", err)
		}
	case q4.NPRSMutingConfigurationChoiceFour:
		if v.Four == nil {
			return q6.Errorf("choice alternative four is nil")
		}
		if err := q5.EncodeBitStringAligned(bb, v.Four.Bytes, v.Four.BitLength, 4, 4, true); err != nil {
			return q6.Errorf("encoding four: %w", err)
		}
	case q4.NPRSMutingConfigurationChoiceEight:
		if v.Eight == nil {
			return q6.Errorf("choice alternative eight is nil")
		}
		if err := q5.EncodeBitStringAligned(bb, v.Eight.Bytes, v.Eight.BitLength, 8, 8, true); err != nil {
			return q6.Errorf("encoding eight: %w", err)
		}
	case q4.NPRSMutingConfigurationChoiceSixteen:
		if v.Sixteen == nil {
			return q6.Errorf("choice alternative sixteen is nil")
		}
		if err := q5.EncodeBitStringAligned(bb, v.Sixteen.Bytes, v.Sixteen.BitLength, 16, 16, true); err != nil {
			return q6.Errorf("encoding sixteen: %w", err)
		}
	default:
		return q6.Errorf("unknown NPRSMutingConfiguration choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes NPRSMutingConfiguration from APER format.
func (v *NPRSMutingConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes NPRSMutingConfiguration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *NPRSMutingConfiguration) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "NPRSMutingConfiguration")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "NPRSMutingConfiguration")
	}
	padding, err := q5.CaptureFinalBits(bb, "NPRSMutingConfiguration")
	if err != nil {
		return q7.WrapDecodePath(err, "NPRSMutingConfiguration")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *NPRSMutingConfiguration) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NPRSMutingConfiguration{}
	isExtension, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := q5.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return q7.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := q5.DecodeChoiceExtensionAligned(bb, extIdx, 0)
		if extIdx < 0 {
			v.knownOpenBytes = max(v.knownOpenBytes, openExtension.ContentLength())
		}
		if err != nil {
			return q7.WrapDecodePath(err, "UnknownExtension")
		}
		v.UnknownExtension = &openExtension
		v.stream = bb.CaptureWireSpan(replayStart)
		v.
			stream.RecordUsage(replayUsage,

			bb)

		return nil
	}
	idx, err := q5.DecodeConstrainedWholeNumberAligned(bb, 0, 3)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return q6.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case q4.NPRSMutingConfigurationChoiceTwo:
		bsBytes_two, bsBitLen_two, err := q5.DecodeBitStringAligned(bb, 2, 2, true)
		if err != nil {
			return q7.WrapDecodePath(err, "Two")
		}
		tmp_two := q7.BitString{Bytes: bsBytes_two, BitLength: bsBitLen_two}
		if err := q5.ChargeValue(bb, tmp_two); err != nil {
			return err
		}
		v.Two = &tmp_two
	case q4.NPRSMutingConfigurationChoiceFour:
		bsBytes_four, bsBitLen_four, err := q5.DecodeBitStringAligned(bb, 4, 4, true)
		if err != nil {
			return q7.WrapDecodePath(err, "Four")
		}
		tmp_four := q7.BitString{Bytes: bsBytes_four, BitLength: bsBitLen_four}
		if err := q5.ChargeValue(bb, tmp_four); err != nil {
			return err
		}
		v.Four = &tmp_four
	case q4.NPRSMutingConfigurationChoiceEight:
		bsBytes_eight, bsBitLen_eight, err := q5.DecodeBitStringAligned(bb, 8, 8, true)
		if err != nil {
			return q7.WrapDecodePath(err, "Eight")
		}
		tmp_eight := q7.BitString{Bytes: bsBytes_eight, BitLength: bsBitLen_eight}
		if err := q5.ChargeValue(bb, tmp_eight); err != nil {
			return err
		}
		v.Eight = &tmp_eight
	case q4.NPRSMutingConfigurationChoiceSixteen:
		bsBytes_sixteen, bsBitLen_sixteen, err := q5.DecodeBitStringAligned(bb, 16, 16, true)
		if err != nil {
			return q7.WrapDecodePath(err, "Sixteen")
		}
		tmp_sixteen := q7.BitString{Bytes: bsBytes_sixteen, BitLength: bsBitLen_sixteen}
		if err := q5.ChargeValue(bb, tmp_sixteen); err != nil {
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
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *NPRSSubframePartA) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
	if err := q5.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := q5.EncodeBoolean(bb, v.NPRSMutingConfiguration != nil); err != nil {
		return err
	}
	if err := q10.BridgeBitmapsforNPRSMethodMarshalAPERTo(&v.BitmapsforNPRS, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return q6.Errorf("encoding bitmapsforNPRS: %w", err)
	}
	if v.NPRSMutingConfiguration != nil {
		if err := v.NPRSMutingConfiguration.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return q6.Errorf("encoding nPRSMutingConfiguration: %w", err)
		}
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q6.Errorf("%w: extension bitmap index %d", q5.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q5.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q5.EncodeBoolean(bb, p); err != nil {
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

// UnmarshalAPER decodes NPRSSubframePartA from APER format.
func (v *NPRSSubframePartA) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes NPRSSubframePartA with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *NPRSSubframePartA) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "NPRSSubframePartA")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "NPRSSubframePartA")
	}
	padding, err := q5.CaptureFinalBits(bb, "NPRSSubframePartA")
	if err != nil {
		return q7.WrapDecodePath(err, "NPRSSubframePartA")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *NPRSSubframePartA) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NPRSSubframePartA{}
	extAdditions := q5.BeginExtensionAdditions(bb)
	hasExtensions, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_nprsmutingconfiguration, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if err := q10.BridgeBitmapsforNPRSMethodUnmarshalAPERFrom(&v.BitmapsforNPRS, bb); err != nil {
		return q7.WrapDecodePath(err, "BitmapsforNPRS")
	}
	if opt_nprsmutingconfiguration {
		var dec_nprsmutingconfiguration NPRSMutingConfiguration
		if err := dec_nprsmutingconfiguration.unmarshalAPERFrom(bb); err != nil {
			return q7.WrapDecodePath(err, "NPRSMutingConfiguration")
		}
		if err := q5.ChargeValue(bb, dec_nprsmutingconfiguration); err != nil {
			return err
		}
		v.NPRSMutingConfiguration = &dec_nprsmutingconfiguration
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
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q5.DecodeOpaqueOpenTypeAligned(bb, q5.UnknownSelector, q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
				if err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("ExtData_[%d]", i))
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

// MarshalAPER encodes NPRSSubframePartB to APER format.
func (v *NPRSSubframePartB) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *NPRSSubframePartB) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = q10.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
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
	if err := q5.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := q5.EncodeBoolean(bb, v.NPRSMutingConfiguration != nil); err != nil {
		return err
	}
	if err := q5.EncodeEnumeratedAligned(bb, int64(v.NumberofNPRSOneOccasion), 8, true); err != nil {
		return q6.Errorf("encoding numberofNPRSOneOccasion: %w", err)
	}
	if err := q5.EncodeEnumeratedAligned(bb, int64(v.PeriodicityofNPRS), 4, true); err != nil {
		return q6.Errorf("encoding periodicityofNPRS: %w", err)
	}
	if err := q5.EncodeEnumeratedAligned(bb, int64(v.Startingsubframeoffset), 8, true); err != nil {
		return q6.Errorf("encoding startingsubframeoffset: %w", err)
	}
	if v.NPRSMutingConfiguration != nil {
		if err := v.NPRSMutingConfiguration.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
			return q6.Errorf("encoding nPRSMutingConfiguration: %w", err)
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extHighest < 16383; gen/codegen_aper.go:360
		if extHighest < 0 || extHighest >= 16383 {
			return q6.Errorf("%w: extension bitmap index %d", q5.ErrUnsupportedFragmentedNormallySmallLength, extHighest)
		}
		if err := q5.EncodeNormallySmallLengthAligned(bb, extHighest+1); err != nil {
			return err
		}
		// Extension presence bitmap
		if int64(0) <= extHighest {
			present0 := v.SIB1NBSubframeTDD != nil
			if err := q5.EncodeBoolean(bb, present0); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_HIGHEST_1: 0 <= extHighest < max int; gen/codegen_aper.go:376
		if extHighest < 0 || extHighest >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(1); i <= extHighest; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q5.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		if v.SIB1NBSubframeTDD != nil {
			extBuf := q5.NewBudgetBuffer(bb.Budget())
			if v.SIB1NBSubframeTDD != nil {
				if err := q5.EncodeEnumeratedAligned(extBuf, int64(*v.SIB1NBSubframeTDD), 3, true); err != nil {
					return q6.Errorf("encoding sIB1-NB-Subframe-TDD: %w", err)
				}
			}
			var extPadding q5.CompletePadding
			if len(v.perExtPadding) > 0 {
				extPadding = v.perExtPadding[0]
			}
			extBytes, err := extBuf.CompleteBytesWithPadding(extPadding)
			if err != nil {
				return err
			}
			if err := q5.EncodeOpenTypeAligned(bb, extBytes); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_HIGHEST_2: 0 <= extHighest < max int; gen/codegen_aper.go:428
		if extHighest < 0 || extHighest >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(1); i <= extHighest; i++ {
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

// UnmarshalAPER decodes NPRSSubframePartB from APER format.
func (v *NPRSSubframePartB) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes NPRSSubframePartB with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *NPRSSubframePartB) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "NPRSSubframePartB")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "NPRSSubframePartB")
	}
	padding, err := q5.CaptureFinalBits(bb, "NPRSSubframePartB")
	if err != nil {
		return q7.WrapDecodePath(err, "NPRSSubframePartB")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *NPRSSubframePartB) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = NPRSSubframePartB{}
	extAdditions := q5.BeginExtensionAdditions(bb)
	hasExtensions, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_nprsmutingconfiguration, err := q5.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_numberofnprsoneoccasion, err := q5.DecodeEnumeratedAligned(bb, 8, true, q5.EnumerationSource{KnownExtensions: 1, Path: "NumberofNPRSOneOccasion"})
	if err != nil {
		return q7.WrapDecodePath(err, "NumberofNPRSOneOccasion")
	}
	v.NumberofNPRSOneOccasion = val_numberofnprsoneoccasion
	val_periodicityofnprs, err := q5.DecodeEnumeratedAligned(bb, 4, true, q5.EnumerationSource{KnownExtensions: 1, Path: "PeriodicityofNPRS"})
	if err != nil {
		return q7.WrapDecodePath(err, "PeriodicityofNPRS")
	}
	v.PeriodicityofNPRS = val_periodicityofnprs
	val_startingsubframeoffset, err := q5.DecodeEnumeratedAligned(bb, 8, true, q5.EnumerationSource{KnownExtensions: 0, Path: "Startingsubframeoffset"})
	if err != nil {
		return q7.WrapDecodePath(err, "Startingsubframeoffset")
	}
	v.Startingsubframeoffset = val_startingsubframeoffset
	if opt_nprsmutingconfiguration {
		var dec_nprsmutingconfiguration NPRSMutingConfiguration
		if err := dec_nprsmutingconfiguration.unmarshalAPERFrom(bb); err != nil {
			return q7.WrapDecodePath(err, "NPRSMutingConfiguration")
		}
		if err := q5.ChargeValue(bb, dec_nprsmutingconfiguration); err != nil {
			return err
		}
		v.NPRSMutingConfiguration = &dec_nprsmutingconfiguration
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q7.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_ALLOC_1: 0 <= extCount < max int; gen/codegen_aper.go:553
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_2: 0 <= extCount < max int; gen/codegen_aper.go:555
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		if err := q5.ChargeSlice[q5.CompletePadding](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.perExtPadding = make([]q5.CompletePadding, len(extPresent))
		if int64(0) <= extCount && extPresent[0] && extAdditions.Received(bb, 0) {
			extRaw, err := q5.DecodeOpaqueOpenTypeAligned(bb, q5.UnknownSelector, q5.SourceRule{Document: "ITU-T X.691", Edition: "02/2021", Clause: "§19.9"})
			if err != nil {
				return q7.WrapDecodePath(err, "ExtData_[0]")
			}
			v.knownOpenBytes = max(v.knownOpenBytes, extRaw.ContentLength())
			if extAdditions.RecoveryEnabled(bb) {
				candidate := *v
				extBB := extRaw.ChildDecodeBuffer()

				if err := extBB.EnterOpenType(); err != nil {
					return err
				}
				checkpoint := extBB.CheckpointKnownAddition()
				decodeErr := func() error {
					v := &candidate
					_ = v
					val_sib1nbsubframetdd, err := q5.DecodeEnumeratedAligned(extBB, 3, true, q5.EnumerationSource{KnownExtensions: 0, Path: "SIB1NBSubframeTDD"})
					if err != nil {
						return q7.WrapDecodePath(err, "SIB1NBSubframeTDD")
					}
					if err := q5.ChargeValue(extBB, val_sib1nbsubframetdd); err != nil {
						return err
					}
					v.SIB1NBSubframeTDD = (*int64)(bb.OwnInt64(int64(val_sib1nbsubframetdd)))
					return nil
				}()
				decoded, padding, err := extAdditions.CompleteKnownOpenAddition(extBB, 0, extRaw, checkpoint, decodeErr)
				if err != nil {
					return err
				}
				if decoded {
					*v = candidate
					v.perExtPadding[0] = padding
				}
			} else {
				if err := func() error {
					extBB := extRaw.ChildDecodeBuffer()

					if err := extBB.EnterOpenType(); err != nil {
						return err
					}
					defer extBB.LeaveOpenType()
					_ = extBB
					val_sib1nbsubframetdd, err := q5.DecodeEnumeratedAligned(extBB, 3, true, q5.EnumerationSource{KnownExtensions: 0, Path: "SIB1NBSubframeTDD"})
					if err != nil {
						return q7.WrapDecodePath(err, "SIB1NBSubframeTDD")
					}
					if err := q5.ChargeValue(extBB, val_sib1nbsubframetdd); err != nil {
						return err
					}
					v.SIB1NBSubframeTDD = (*int64)(bb.OwnInt64(int64(val_sib1nbsubframetdd)))
					padding, err := q5.CaptureOpenTypePadding(extBB)
					if err != nil {
						return q7.WrapDecodePath(err, "ExtData_[0]")
					}
					v.perExtPadding[0] = padding
					return nil
				}(); err != nil {
					return err
				}
			}
		}
		// arithmetic pattern APER_EXT_COUNT_LOOP_1: 0 <= extCount < max int; gen/codegen_aper.go:611
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(1); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q5.DecodeOpaqueOpenTypeAligned(bb, q5.UnknownSelector, q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
				if err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("ExtData_[%d]", i))
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *NPRSConfiguration) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q10.BridgeReceivedFormAt(v.received, v.receivedBytes, "NPRSConfiguration", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NPRSConfiguration) WithoutReplay() NPRSConfiguration {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero NPRSConfiguration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *NPRSMutingConfiguration) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q10.BridgeReceivedFormAt(v.received, v.receivedBytes, "NPRSMutingConfiguration", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NPRSMutingConfiguration) WithoutReplay() NPRSMutingConfiguration {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero NPRSMutingConfiguration
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *NPRSSubframePartA) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q10.BridgeReceivedFormAt(v.received, v.receivedBytes, "NPRSSubframePartA", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NPRSSubframePartA) WithoutReplay() NPRSSubframePartA {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero NPRSSubframePartA
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *NPRSSubframePartB) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q10.BridgeReceivedFormAt(v.received, v.receivedBytes, "NPRSSubframePartB", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NPRSSubframePartB) WithoutReplay() NPRSSubframePartB {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero NPRSSubframePartB
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *NRCGI) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q10.BridgeReceivedFormAt(v.received, v.receivedBytes, "NRCGI", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v NRCGI) WithoutReplay() NRCGI {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero NRCGI
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *NPRSConfiguration) Extensions() []q5.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q5.SequenceExtensionViews(v.extPresent, q5.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *NPRSConfiguration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q5.ErrInvalidValue, q6.Sprintf("NPRSConfiguration.Extensions[%d]", index))
	}
	if err := q5.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("NPRSConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *NPRSConfiguration) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q5.ErrInvalidValue, q6.Sprintf("NPRSConfiguration.Extensions[%d]", index))
	}
	if err := q5.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("NPRSConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *NPRSSubframePartA) Extensions() []q5.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q5.SequenceExtensionViews(v.extPresent, q5.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *NPRSSubframePartA) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q5.ErrInvalidValue, q6.Sprintf("NPRSSubframePartA.Extensions[%d]", index))
	}
	if err := q5.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("NPRSSubframePartA.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *NPRSSubframePartA) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q5.ErrInvalidValue, q6.Sprintf("NPRSSubframePartA.Extensions[%d]", index))
	}
	if err := q5.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("NPRSSubframePartA.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *NPRSSubframePartB) Extensions() []q5.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q5.SequenceExtensionViews(v.extPresent, q5.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	for len(views) > 0 && views[0].Index() < 1 {
		views = views[1:]
	}
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *NPRSSubframePartB) SetExtension(index uint64, contents []byte) error {
	if index < 1 {
		return q7.WrapDecodePath(q6.Errorf("%w: extension index %d is known to this schema", q5.ErrInvalidValue, index), q6.Sprintf("NPRSSubframePartB.Extensions[%d]", index))
	}
	if v == nil {
		return q7.WrapDecodePath(q5.ErrInvalidValue, q6.Sprintf("NPRSSubframePartB.Extensions[%d]", index))
	}
	if err := q5.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("NPRSSubframePartB.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *NPRSSubframePartB) RemoveExtension(index uint64) error {
	if index < 1 {
		return q7.WrapDecodePath(q6.Errorf("%w: extension index %d is known to this schema", q5.ErrInvalidValue, index), q6.Sprintf("NPRSSubframePartB.Extensions[%d]", index))
	}
	if v == nil {
		return q7.WrapDecodePath(q5.ErrInvalidValue, q6.Sprintf("NPRSSubframePartB.Extensions[%d]", index))
	}
	if err := q5.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("NPRSSubframePartB.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *NRCGI) Extensions() []q5.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q5.SequenceExtensionViews(v.extPresent, q5.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *NRCGI) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q5.ErrInvalidValue, q6.Sprintf("NRCGI.Extensions[%d]", index))
	}
	if err := q5.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("NRCGI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *NRCGI) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q5.ErrInvalidValue, q6.Sprintf("NRCGI.Extensions[%d]", index))
	}
	if err := q5.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("NRCGI.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *NPRSConfiguration) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "NPRSConfiguration")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "NPRSConfiguration")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaNPRSConfiguration(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "NPRSConfiguration")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "NPRSConfiguration")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "NPRSConfiguration")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "NPRSConfiguration")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "NPRSConfiguration")
}
func (v *NPRSConfiguration) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *NPRSConfiguration) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *NPRSConfiguration) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
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
func (v *NPRSConfiguration) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *NPRSConfiguration) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *NPRSMutingConfiguration) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "NPRSMutingConfiguration")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "NPRSMutingConfiguration")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaNPRSMutingConfiguration(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "NPRSMutingConfiguration")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "NPRSMutingConfiguration")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "NPRSMutingConfiguration")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "NPRSMutingConfiguration")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "NPRSMutingConfiguration")
}
func (v *NPRSMutingConfiguration) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *NPRSMutingConfiguration) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *NPRSMutingConfiguration) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
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
func (v *NPRSMutingConfiguration) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *NPRSMutingConfiguration) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *NPRSSubframePartA) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "NPRSSubframePartA")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "NPRSSubframePartA")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaNPRSSubframePartA(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "NPRSSubframePartA")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "NPRSSubframePartA")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "NPRSSubframePartA")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "NPRSSubframePartA")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "NPRSSubframePartA")
}
func (v *NPRSSubframePartA) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *NPRSSubframePartA) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *NPRSSubframePartA) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
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
func (v *NPRSSubframePartA) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *NPRSSubframePartA) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *NPRSSubframePartB) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "NPRSSubframePartB")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "NPRSSubframePartB")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaNPRSSubframePartB(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "NPRSSubframePartB")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "NPRSSubframePartB")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "NPRSSubframePartB")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "NPRSSubframePartB")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "NPRSSubframePartB")
}
func (v *NPRSSubframePartB) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *NPRSSubframePartB) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *NPRSSubframePartB) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
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
func (v *NPRSSubframePartB) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *NPRSSubframePartB) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *NRCGI) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "NRCGI")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "NRCGI")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaNRCGI(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "NRCGI")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "NRCGI")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "NRCGI")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "NRCGI")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "NRCGI")
}
func (v *NRCGI) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *NRCGI) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *NRCGI) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
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
func (v *NRCGI) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *NRCGI) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *NPRSConfiguration) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "NPRSConfiguration")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded NPRSConfiguration
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaNPRSConfiguration(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = NPRSConfiguration{}
		return report, q5.OperationError(err, "NPRSConfiguration")
	}
	*v = decoded
	return report, q5.OperationError(nil, "NPRSConfiguration")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *NPRSMutingConfiguration) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "NPRSMutingConfiguration")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded NPRSMutingConfiguration
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaNPRSMutingConfiguration(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = NPRSMutingConfiguration{}
		return report, q5.OperationError(err, "NPRSMutingConfiguration")
	}
	*v = decoded
	return report, q5.OperationError(nil, "NPRSMutingConfiguration")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *NPRSSubframePartA) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "NPRSSubframePartA")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded NPRSSubframePartA
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaNPRSSubframePartA(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = NPRSSubframePartA{}
		return report, q5.OperationError(err, "NPRSSubframePartA")
	}
	*v = decoded
	return report, q5.OperationError(nil, "NPRSSubframePartA")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *NPRSSubframePartB) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "NPRSSubframePartB")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded NPRSSubframePartB
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaNPRSSubframePartB(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = NPRSSubframePartB{}
		return report, q5.OperationError(err, "NPRSSubframePartB")
	}
	*v = decoded
	return report, q5.OperationError(nil, "NPRSSubframePartB")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *NRCGI) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "NRCGI")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded NRCGI
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaNRCGI(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = NRCGI{}
		return report, q5.OperationError(err, "NRCGI")
	}
	*v = decoded
	return report, q5.OperationError(nil, "NRCGI")
}

// NewBitmapsforNPRSUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewBitmapsforNPRSUnknownExtension(index uint64, contents []byte, options ...q5.BuildOption) (q10.BitmapsforNPRS, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q10.BitmapsforNPRS{}, q5.OperationError(err, "BitmapsforNPRSUnknownExtension")
	}
	extension, err := q5.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return q10.BitmapsforNPRS{}, q5.OperationError(err, "BitmapsforNPRSUnknownExtension")
	}
	value := q10.BitmapsforNPRS{UnknownExtension: &extension}
	if _, err := q10.BridgeBitmapsforNPRSMethodMarshalAPERBudget(&value, budget, false); err != nil {
		return q10.BitmapsforNPRS{}, q5.OperationError(err, "BitmapsforNPRSUnknownExtension")
	}
	return value, q5.OperationError(nil, "BitmapsforNPRSUnknownExtension")
}

// NewCauseUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewCauseUnknownExtension(index uint64, contents []byte, options ...q5.BuildOption) (q10.Cause, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return q10.Cause{}, q5.OperationError(err, "CauseUnknownExtension")
	}
	extension, err := q5.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return q10.Cause{}, q5.OperationError(err, "CauseUnknownExtension")
	}
	value := q10.Cause{UnknownExtension: &extension}
	if _, err := q10.BridgeCauseMethodMarshalAPERBudget(&value, budget, false); err != nil {
		return q10.Cause{}, q5.OperationError(err, "CauseUnknownExtension")
	}
	return value, q5.OperationError(nil, "CauseUnknownExtension")
}

// NewNPRSMutingConfigurationUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewNPRSMutingConfigurationUnknownExtension(index uint64, contents []byte, options ...q5.BuildOption) (NPRSMutingConfiguration, error) {
	budget, err := q5.BuildBudget(options...)
	if err != nil {
		return NPRSMutingConfiguration{}, q5.OperationError(err, "NPRSMutingConfigurationUnknownExtension")
	}
	extension, err := q5.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return NPRSMutingConfiguration{}, q5.OperationError(err, "NPRSMutingConfigurationUnknownExtension")
	}
	value := NPRSMutingConfiguration{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return NPRSMutingConfiguration{}, q5.OperationError(err, "NPRSMutingConfigurationUnknownExtension")
	}
	return value, q5.OperationError(nil, "NPRSMutingConfigurationUnknownExtension")
}

type OTDOAInformationType = []OTDOAInformationTypeIEValueProtocolIESingleContainer

// OTDOAInformationTypeItem represents the ASN.1 type OTDOA-Information-Type-Item (SEQUENCE).
type OTDOAInformationTypeItem struct {
	replay                   q5.Snapshot
	stream                   q5.WireSpan
	withoutReplay            bool
	received                 bool
	receivedBytes            q5.WireSpan
	OTDOAInformationTypeItem q4.OTDOAInformationItem                       `asn1:"tag:0,context,implicit"`
	IEExtensions             q9.OTDOAInformationTypeItemExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef        bool                                          `asn1:"-" json:"-"`
	extCount                 int64                                         `asn1:"-" json:"-"`
	extPresent               []bool                                        `asn1:"-" json:"-"`
	extData                  [][]byte                                      `asn1:"-" json:"-"`
	perPadding               q5.FinalPadding                               `asn1:"-" json:"-"`
	perExtPadding            []q5.CompletePadding                          `asn1:"-" json:"-"`
	extOrigin                []q5.OpaqueOrigin
	extWire                  []q5.WireSpan
}

// MarshalAPER encodes OTDOAInformationTypeItem to APER format.
func (v *OTDOAInformationTypeItem) marshalAPERLegacy() ([]byte, error) {
	bb := q5.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *OTDOAInformationTypeItem) marshalAPERTo(bb *q5.BitBuffer, fresh ...bool) error {
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
	if err := q5.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := q5.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q5.EncodeEnumeratedAligned(bb, int64(v.OTDOAInformationTypeItem), 10, true); err != nil {
		return q6.Errorf("encoding oTDOA-Information-Type-Item: %w", err)
	}
	if v.IEExtensions != nil {
		if err := q5.EncodeCollection(bb, int64(len(v.IEExtensions)), q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q9.BridgeOTDOAInformationTypeItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
			return q6.Errorf("%w: extension bitmap index %d", q5.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q5.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q5.EncodeBoolean(bb, p); err != nil {
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

// UnmarshalAPER decodes OTDOAInformationTypeItem from APER format.
func (v *OTDOAInformationTypeItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q5.DecodeState{})
}

// UnmarshalAPERWithOptions decodes OTDOAInformationTypeItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *OTDOAInformationTypeItem) unmarshalAPERWithOptions(data []byte, options q5.DecodeState) error {
	bb := q5.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "OTDOAInformationTypeItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "OTDOAInformationTypeItem")
	}
	padding, err := q5.CaptureFinalBits(bb, "OTDOAInformationTypeItem")
	if err != nil {
		return q7.WrapDecodePath(err, "OTDOAInformationTypeItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *OTDOAInformationTypeItem) unmarshalAPERFrom(bb *q5.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = OTDOAInformationTypeItem{}
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
	val_otdoainformationtypeitem, err := q5.DecodeEnumeratedAligned(bb, 10, true, q5.EnumerationSource{KnownExtensions: 19, Path: "OTDOAInformationTypeItem"})
	if err != nil {
		return q7.WrapDecodePath(err, "OTDOAInformationTypeItem")
	}
	v.OTDOAInformationTypeItem = q4.OTDOAInformationItem(val_otdoainformationtypeitem)
	if opt_ieextensions {
		tmp_ieextensions := make(q9.OTDOAInformationTypeItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q5.DecodeCollection(bb, q5.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q9.OTDOAInformationTypeItemExtIEsExtField
				if err := q9.BridgeOTDOAInformationTypeItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
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
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q5.DecodeOpaqueOpenTypeAligned(bb, q5.UnknownSelector, q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
				if err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("ExtData_[%d]", i))
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
func (v *OTDOAInformationTypeItem) ReceivedForm() q5.ReceivedForm {
	if v == nil {
		return q5.ReceivedForm{}
	}
	return q10.BridgeReceivedFormAt(v.received, v.receivedBytes, "OTDOAInformationTypeItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v OTDOAInformationTypeItem) WithoutReplay() OTDOAInformationTypeItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q5.WireSpan{}
	var zero OTDOAInformationTypeItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *OTDOAInformationTypeItem) Extensions() []q5.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q5.SequenceExtensionViews(v.extPresent, q5.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *OTDOAInformationTypeItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q5.ErrInvalidValue, q6.Sprintf("OTDOAInformationTypeItem.Extensions[%d]", index))
	}
	if err := q5.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("OTDOAInformationTypeItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *OTDOAInformationTypeItem) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q5.ErrInvalidValue, q6.Sprintf("OTDOAInformationTypeItem.Extensions[%d]", index))
	}
	if err := q5.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("OTDOAInformationTypeItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q5.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *OTDOAInformationTypeItem) MarshalAPER(options ...q5.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q5.OperationError(q5.ErrInvalidValue, "OTDOAInformationTypeItem")
	}
	fresh := v.withoutReplay || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, "OTDOAInformationTypeItem")
	}
	if !fresh && v.replay.Present() {

		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(&budget))
		BridgeCompareLPPaOTDOAInformationTypeItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, "OTDOAInformationTypeItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, "OTDOAInformationTypeItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q5.OperationError(err, "OTDOAInformationTypeItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q5.OperationError(err, "OTDOAInformationTypeItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q5.OperationError(err, "OTDOAInformationTypeItem")
}
func (v *OTDOAInformationTypeItem) marshalAPERChangedValue(budget q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *OTDOAInformationTypeItem) marshalAPERFreshValue(budget q5.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *OTDOAInformationTypeItem) marshalAPERBudget(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q5.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q5.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q5.NewSemanticComparison(v.replay, q5.ComparisonBudget(budget))
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
func (v *OTDOAInformationTypeItem) marshalAPERChanged(budget *q5.DecodeBudget, fresh bool, plan q5.ReplayPlan) ([]byte, error) {
	previous := q5.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *OTDOAInformationTypeItem) marshalAPERPlanned(budget *q5.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *OTDOAInformationTypeItem) UnmarshalAPER(data []byte, options ...q5.DecodeOption) (q5.DecodeReport, error) {
	if v == nil {
		return q5.DecodeReport{}, q5.OperationError(q5.ErrInvalidValue, "OTDOAInformationTypeItem")
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	var decoded OTDOAInformationTypeItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q5.OriginalWire(data)
		s := q5.SemanticCaptureFor(settings)
		BridgeCaptureLPPaOTDOAInformationTypeItem(&decoded, &s)
	}
	report, err := q5.FinishDecode(settings, err)
	if err != nil {
		*v = OTDOAInformationTypeItem{}
		return report, q5.OperationError(err, "OTDOAInformationTypeItem")
	}
	*v = decoded
	return report, q5.OperationError(nil, "OTDOAInformationTypeItem")
}
func BridgeCaptureLPPaNPRSConfiguration(v *NPRSConfiguration, s *q5.SemanticCapture) {
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
func BridgeCompareLPPaNPRSConfiguration(v *NPRSConfiguration, s *q5.SemanticComparison) {
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
		s.End(f, q5.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.NPRSSubframePartB == nil)
		if v.NPRSSubframePartB != nil {
			BridgeCompareLPPaNPRSSubframePartB(v.NPRSSubframePartB, s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaNPRSMutingConfiguration(v *NPRSMutingConfiguration, s *q5.SemanticCapture) {
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
	case q4.NPRSMutingConfigurationChoiceTwo:
		{
			f := s.Begin()
			s.Bool(v.Two == nil)
			if v.Two != nil {
				s.BitString((*v.Two).Bytes, (*v.Two).BitLength)
			}
			s.End(f, nil, false)
		}
	case q4.NPRSMutingConfigurationChoiceFour:
		{
			f := s.Begin()
			s.Bool(v.Four == nil)
			if v.Four != nil {
				s.BitString((*v.Four).Bytes, (*v.Four).BitLength)
			}
			s.End(f, nil, false)
		}
	case q4.NPRSMutingConfigurationChoiceEight:
		{
			f := s.Begin()
			s.Bool(v.Eight == nil)
			if v.Eight != nil {
				s.BitString((*v.Eight).Bytes, (*v.Eight).BitLength)
			}
			s.End(f, nil, false)
		}
	case q4.NPRSMutingConfigurationChoiceSixteen:
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
func BridgeCompareLPPaNPRSMutingConfiguration(v *NPRSMutingConfiguration, s *q5.SemanticComparison) {
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
	case q4.NPRSMutingConfigurationChoiceTwo:
		{
			f := s.Begin()
			s.Bool(v.Two == nil)
			if v.Two != nil {
				s.BitString((*v.Two).Bytes, (*v.Two).BitLength)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q4.NPRSMutingConfigurationChoiceFour:
		{
			f := s.Begin()
			s.Bool(v.Four == nil)
			if v.Four != nil {
				s.BitString((*v.Four).Bytes, (*v.Four).BitLength)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q4.NPRSMutingConfigurationChoiceEight:
		{
			f := s.Begin()
			s.Bool(v.Eight == nil)
			if v.Eight != nil {
				s.BitString((*v.Eight).Bytes, (*v.Eight).BitLength)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	case q4.NPRSMutingConfigurationChoiceSixteen:
		{
			f := s.Begin()
			s.Bool(v.Sixteen == nil)
			if v.Sixteen != nil {
				s.BitString((*v.Sixteen).Bytes, (*v.Sixteen).BitLength)
			}
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaNPRSSubframePartA(v *NPRSSubframePartA, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q10.BridgeCaptureLPPaBitmapsforNPRS(&v.BitmapsforNPRS, s)
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
func BridgeCompareLPPaNPRSSubframePartA(v *NPRSSubframePartA, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q10.BridgeCompareLPPaBitmapsforNPRS(&v.BitmapsforNPRS, s)
	{
		f := s.Begin()
		s.Bool(v.NPRSMutingConfiguration == nil)
		if v.NPRSMutingConfiguration != nil {
			BridgeCompareLPPaNPRSMutingConfiguration(v.NPRSMutingConfiguration, s)
		}
		s.End(f, q5.Snapshot{}, false)
	}
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaNPRSSubframePartB(v *NPRSSubframePartB, s *q5.SemanticCapture) {
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
func BridgeCompareLPPaNPRSSubframePartB(v *NPRSSubframePartB, s *q5.SemanticComparison) {
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
		s.End(f, q5.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.SIB1NBSubframeTDD == nil)
		if v.SIB1NBSubframeTDD != nil {
			s.Int(int64((*v.SIB1NBSubframeTDD)))
		}
		s.End(f, q5.Snapshot{}, false)
	}
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaNRCGI(v *NRCGI, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q4.BridgeCaptureLPPaPLMNIdentity(&v.PLMNIdentity, s)
	q4.BridgeCaptureLPPaNRCellIdentity(&v.NRCellIdentity, s)
	s.Bool(v.IEExtensions == nil)
	q10.BridgeNRCGIExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaNRCGI(v *NRCGI, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q11.BridgeCompareLPPaPLMNIdentity(&v.PLMNIdentity, s)
	q11.BridgeCompareLPPaNRCellIdentity(&v.NRCellIdentity, s)
	s.Bool(v.IEExtensions == nil)
	q10.BridgeNRCGIExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaOTDOAInformationTypeIEValue(v *OTDOAInformationTypeIEValue, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q4.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
		case q4.ProtocolIEID(10):
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
func (v OTDOAInformationTypeIEValue) captureSnapshot() q5.Snapshot { return v.replay }
func (v OTDOAInformationTypeIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v OTDOAInformationTypeIEValue) captureSemantics(s q5.SemanticCapture) OTDOAInformationTypeIEValue {
	BridgeCaptureLPPaOTDOAInformationTypeIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaOTDOAInformationTypeIEValue(v *OTDOAInformationTypeIEValue, s *q5.SemanticComparison) {
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
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case q4.ProtocolIEID(10):
			{
				f := s.Begin()
				s.Bool(v.rowOTDOAInformationTypeItem == nil)
				if v.rowOTDOAInformationTypeItem != nil {
					BridgeCompareLPPaOTDOAInformationTypeItem(v.rowOTDOAInformationTypeItem, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v OTDOAInformationTypeIEValue) compareSemantics(s q5.SemanticComparison) q5.SemanticComparison {
	BridgeCompareLPPaOTDOAInformationTypeIEValue(&v, &s)
	return s
}
func (v OTDOAInformationTypeIEValue) WithoutReplay() OTDOAInformationTypeIEValue {
	v.withoutReplay = true
	v.replay = q5.Snapshot{}
	return v
}
func BridgeCaptureLPPaOTDOAInformationTypeItem(v *OTDOAInformationTypeItem, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q4.BridgeCaptureLPPaOTDOAInformationItem(&v.OTDOAInformationTypeItem, s)
	s.Bool(v.IEExtensions == nil)
	q10.BridgeOTDOAInformationTypeItemExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaOTDOAInformationTypeItem(v *OTDOAInformationTypeItem, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q11.BridgeCompareLPPaOTDOAInformationItem(&v.OTDOAInformationTypeItem, s)
	s.Bool(v.IEExtensions == nil)
	q10.BridgeOTDOAInformationTypeItemExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}

type OTDOAInformationTypeIEValue struct {
	id                          q4.ProtocolIEID
	withoutReplay               bool
	received                    q5.WireSpan
	replay                      q5.Snapshot
	opaque                      *q5.OpaqueOpenType
	isOpaque                    bool
	rowOTDOAInformationTypeItem *OTDOAInformationTypeItem
}

func (v OTDOAInformationTypeIEValue) matchesID(id q4.ProtocolIEID, _ *q5.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q4.ProtocolIEID(10):
		return v.rowOTDOAInformationTypeItem != nil
	default:
		return false
	}
}
func (v *OTDOAInformationTypeIEValue) Opaque() (q5.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q5.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (OTDOAInformationTypeIEValue) rule() q5.SourceRule {
	return q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOA-Information-TypeIEs"}}
}
func (OTDOAInformationTypeIEValue) reason(id q4.ProtocolIEID) q5.OpaqueReason {
	switch id {
	case q4.ProtocolIEID(10):
		return q5.UnknownSelector
	case q4.ProtocolIEID(0):
		return q5.NotInTable
	case q4.ProtocolIEID(1):
		return q5.NotInTable
	case q4.ProtocolIEID(2):
		return q5.NotInTable
	case q4.ProtocolIEID(3):
		return q5.NotInTable
	case q4.ProtocolIEID(4):
		return q5.NotInTable
	case q4.ProtocolIEID(5):
		return q5.NotInTable
	case q4.ProtocolIEID(6):
		return q5.NotInTable
	case q4.ProtocolIEID(7):
		return q5.NotInTable
	case q4.ProtocolIEID(8):
		return q5.NotInTable
	case q4.ProtocolIEID(9):
		return q5.NotInTable
	case q4.ProtocolIEID(11):
		return q5.NotInTable
	case q4.ProtocolIEID(12):
		return q5.NotInTable
	case q4.ProtocolIEID(13):
		return q5.NotInTable
	case q4.ProtocolIEID(14):
		return q5.NotInTable
	case q4.ProtocolIEID(15):
		return q5.NotInTable
	case q4.ProtocolIEID(16):
		return q5.NotInTable
	case q4.ProtocolIEID(17):
		return q5.NotInTable
	case q4.ProtocolIEID(18):
		return q5.NotInTable
	case q4.ProtocolIEID(19):
		return q5.NotInTable
	case q4.ProtocolIEID(20):
		return q5.NotInTable
	case q4.ProtocolIEID(21):
		return q5.NotInTable
	case q4.ProtocolIEID(22):
		return q5.NotInTable
	case q4.ProtocolIEID(23):
		return q5.NotInTable
	case q4.ProtocolIEID(24):
		return q5.NotInTable
	case q4.ProtocolIEID(25):
		return q5.NotInTable
	case q4.ProtocolIEID(27):
		return q5.NotInTable
	default:
		return q5.UnknownSelector
	}
}
func (v *OTDOAInformationTypeIEValue) AsOTDOAInformationTypeItem() (*OTDOAInformationTypeItem, bool) {
	if v == nil || v.id != q4.ProtocolIEID(10) || v.rowOTDOAInformationTypeItem == nil {
		return nil, false
	}
	return v.rowOTDOAInformationTypeItem, true
}
func (v OTDOAInformationTypeIEValue) decode(id q4.ProtocolIEID, raw q5.OpaqueOpenType) (OTDOAInformationTypeIEValue, error) {
	out := OTDOAInformationTypeIEValue{id: id}
	var scope *q5.BitBuffer
	switch id {
	case 10:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q4.ProtocolIEID(10):
		replayUsage := scope.Usage()
		var value OTDOAInformationTypeItem
		child := raw.ChildDecodeBuffer()
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, q6.Errorf("%s %w", "OTDOAInformationTypeItem:", err)
		}
		padding, err := q5.CaptureFinalBits(child, "OTDOAInformationTypeItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		if err := q5.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowOTDOAInformationTypeItem = &value
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
func (v OTDOAInformationTypeIEValue) encode() ([]byte, error) {
	budget, err := q5.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v OTDOAInformationTypeIEValue) encodeFresh(fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
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
	case q4.ProtocolIEID(10):
		if v.rowOTDOAInformationTypeItem == nil {
			return nil, q6.Errorf("%s missing value", "OTDOA-Information-TypeIEs.id-OTDOA-Information-Type-Item:")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
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
		return nil, q6.Errorf("%s id %d has no value", "OTDOAInformationTypeIEValue:", v.id)
	}
}

type MeasurementQuantitiesItemIETable struct{}

func MeasurementQuantitiesItemIEs() MeasurementQuantitiesItemIETable {
	return MeasurementQuantitiesItemIETable{}
}
func (MeasurementQuantitiesItemIETable) ID() q4.TableID {
	return func() q4.TableID {
		sealed := q4.TableID{}
		*q4.BridgeTableIDFieldSource(&sealed) = q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementQuantities-ItemIEs"}
		return sealed
	}()
}
func (MeasurementQuantitiesItemIETable) infoMeasurementQuantitiesItem() q4.FieldInfo {
	return q4.FieldInfo{Table: MeasurementQuantitiesItemIEs().ID(), ID: q4.ProtocolIEID(11), Criticality: q4.CriticalityReject, Presence: q4.PresenceMandatory, ValueType: func() q4.TypeID {
		sealed := q4.TypeID{}
		*q4.BridgeTypeIDFieldSource(&sealed) = q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementQuantitiesItem"}
		return sealed
	}(), Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementQuantities-ItemIEs", Row: "id-MeasurementQuantities-Item"}}}
}
func (t MeasurementQuantitiesItemIETable) MeasurementQuantitiesItem() q12.MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding {
	return func() q12.MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding {
		sealed := q12.MeasurementQuantitiesItemMeasurementQuantitiesItemIEBinding{}
		*q12.BridgeMeasurementQuantitiesItemMeasurementQuantitiesItemIEBindingFieldInfo(&sealed) = t.infoMeasurementQuantitiesItem()
		*q12.BridgeMeasurementQuantitiesItemMeasurementQuantitiesItemIEBindingFieldCodec(&sealed) = func() q12.MeasurementQuantitiesItemValueCodec {
			sealed := q12.MeasurementQuantitiesItemValueCodec{}
			*q12.BridgeMeasurementQuantitiesItemValueCodecFieldPath(&sealed) = "MeasurementQuantitiesItem"
			*q12.BridgeMeasurementQuantitiesItemValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q12.MeasurementQuantitiesItem, error) {
				raw, err := q5.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty q12.MeasurementQuantitiesItem
					return empty, err
				}
				var zero q12.MeasurementQuantitiesItemIEValue
				decoded, err := q12.BridgeMeasurementQuantitiesItemIEValueMethodDecode(zero, q4.ProtocolIEID(11), raw)
				if err != nil {
					var empty q12.MeasurementQuantitiesItem
					return empty, err
				}
				value, ok := decoded.AsMeasurementQuantitiesItem()
				if !ok {
					var empty q12.MeasurementQuantitiesItem
					return empty, q6.Errorf("binding MeasurementQuantities-ItemIEs.id-MeasurementQuantities-Item: no selected value")
				}
				return *value, nil
			}
			*q12.BridgeMeasurementQuantitiesItemValueCodecFieldEncode(&sealed) = func(value q12.MeasurementQuantitiesItem, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
				return q12.BridgeMeasurementQuantitiesItemIEValueMethodEncodeFresh((func() q12.MeasurementQuantitiesItemIEValue {
					sealed := q12.MeasurementQuantitiesItemIEValue{}
					*q12.BridgeMeasurementQuantitiesItemIEValueFieldId(&sealed) = q4.ProtocolIEID(11)
					*q12.BridgeMeasurementQuantitiesItemIEValueFieldRowMeasurementQuantitiesItem(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*q12.BridgeMeasurementQuantitiesItemValueCodecFieldCapture(&sealed) = func(v q12.MeasurementQuantitiesItem, options q5.DecodeState) (q12.MeasurementQuantitiesItem, q5.Snapshot) {
				s := q5.SemanticCaptureFor(options)
				f := s.Begin()
				q12.BridgeCaptureLPPaMeasurementQuantitiesItem(&v, &s)
				var root q5.Snapshot
				s.OperationCounts()
				s.End(f, &root, false)
				return v, root
			}
			*q12.BridgeMeasurementQuantitiesItemValueCodecFieldCompare(&sealed) = func(v q12.MeasurementQuantitiesItem, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
				s := q5.NewSemanticComparison(root, limits)
				f := s.Begin()
				q12.BridgeCompareLPPaMeasurementQuantitiesItem(&v, &s)
				s.End(f, root, false)
				return s.
					Plan()
			}
			*q12.BridgeMeasurementQuantitiesItemValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
				sealed := q4.BridgeCodecContext{}
				*q4.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementQuantitiesItem"
				return sealed
			}()
			return sealed
		}()
		*q12.BridgeMeasurementQuantitiesItemMeasurementQuantitiesItemIEBindingFieldInject(&sealed) = func(value q12.MeasurementQuantitiesItem) q12.MeasurementQuantitiesItemIEValue {
			return func() q12.MeasurementQuantitiesItemIEValue {
				sealed := q12.MeasurementQuantitiesItemIEValue{}
				*q12.BridgeMeasurementQuantitiesItemIEValueFieldId(&sealed) = q4.ProtocolIEID(11)
				*q12.BridgeMeasurementQuantitiesItemIEValueFieldRowMeasurementQuantitiesItem(&sealed) = &value
				return sealed
			}()
		}
		*q12.BridgeMeasurementQuantitiesItemMeasurementQuantitiesItemIEBindingFieldGet(&sealed) = func(value *q12.MeasurementQuantitiesItemIEValue) (*q12.MeasurementQuantitiesItem, bool) {
			return value.AsMeasurementQuantitiesItem()
		}
		return sealed
	}()
}
func (t MeasurementQuantitiesItemIETable) NewOpaque(id q4.ProtocolIEID, criticality q4.Criticality, data []byte) (q12.MeasurementQuantitiesItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return q12.MeasurementQuantitiesItemIEField{}, q5.OperationError(q6.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q4.ProtocolIEID(11):
		return q12.MeasurementQuantitiesItemIEField{}, q5.OperationError(q6.Errorf("known IE id-MeasurementQuantities-Item requires its typed binding"), "Opaque")
	default:
		budget, err := q5.BuildBudget()
		if err != nil {
			return q12.MeasurementQuantitiesItemIEField{}, q5.OperationError(err, "Opaque")
		}
		opaque, err := q5.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return q12.MeasurementQuantitiesItemIEField{}, q5.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return q12.MeasurementQuantitiesItemIEField{}, q5.OperationError(err, "Opaque")
		}
		return q12.MeasurementQuantitiesItemIEField{Id: id, Criticality: criticality, Value: func() q12.MeasurementQuantitiesItemIEValue {
			sealed := q12.MeasurementQuantitiesItemIEValue{}
			*q12.BridgeMeasurementQuantitiesItemIEValueFieldId(&sealed) = id
			*q12.BridgeMeasurementQuantitiesItemIEValueFieldOpaque(&sealed) = retained
			*q12.BridgeMeasurementQuantitiesItemIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, q5.OperationError(nil, "Opaque")
	}
}

type OTDOAInformationTypeIETable struct{}

func OTDOAInformationTypeIEs() OTDOAInformationTypeIETable { return OTDOAInformationTypeIETable{} }
func (OTDOAInformationTypeIETable) ID() q4.TableID {
	return func() q4.TableID {
		sealed := q4.TableID{}
		*q4.BridgeTableIDFieldSource(&sealed) = q5.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOA-Information-TypeIEs"}
		return sealed
	}()
}
func (OTDOAInformationTypeIETable) infoOTDOAInformationTypeItem() q4.FieldInfo {
	return q4.FieldInfo{Table: OTDOAInformationTypeIEs().ID(), ID: q4.ProtocolIEID(10), Criticality: q4.CriticalityReject, Presence: q4.PresenceMandatory, ValueType: func() q4.TypeID {
		sealed := q4.TypeID{}
		*q4.BridgeTypeIDFieldSource(&sealed) = q5.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOAInformationTypeItem"}
		return sealed
	}(), Rule: q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOA-Information-TypeIEs", Row: "id-OTDOA-Information-Type-Item"}}}
}
func (t OTDOAInformationTypeIETable) OTDOAInformationTypeItem() OTDOAInformationTypeOTDOAInformationTypeItemIEBinding {
	return OTDOAInformationTypeOTDOAInformationTypeItemIEBinding{info: t.infoOTDOAInformationTypeItem(), codec: OTDOAInformationTypeItemValueCodec{path: "OTDOAInformationTypeItem",
		decode: func(data []byte, options q5.DecodeState) (OTDOAInformationTypeItem, error) {
			raw, err := q5.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty OTDOAInformationTypeItem
				return empty, err
			}
			var zero OTDOAInformationTypeIEValue
			decoded, err := zero.decode(q4.ProtocolIEID(10), raw)
			if err != nil {
				var empty OTDOAInformationTypeItem
				return empty, err
			}
			value, ok := decoded.AsOTDOAInformationTypeItem()
			if !ok {
				var empty OTDOAInformationTypeItem
				return empty, q6.Errorf("binding OTDOA-Information-TypeIEs.id-OTDOA-Information-Type-Item: no selected value")
			}
			return *value, nil
		},
		encode: func(value OTDOAInformationTypeItem, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
			return (OTDOAInformationTypeIEValue{id: q4.ProtocolIEID(10), rowOTDOAInformationTypeItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v OTDOAInformationTypeItem, options q5.DecodeState) (OTDOAInformationTypeItem, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureLPPaOTDOAInformationTypeItem(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}, compare: func(v OTDOAInformationTypeItem, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaOTDOAInformationTypeItem(&v, &s)
			s.End(f, root, false)
			return s.
				Plan()
		}, context: func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOAInformationTypeItem"
			return sealed
		}(),
	}, inject: func(value OTDOAInformationTypeItem) OTDOAInformationTypeIEValue {
		return OTDOAInformationTypeIEValue{id: q4.ProtocolIEID(10), rowOTDOAInformationTypeItem: &value}
	}, get: func(value *OTDOAInformationTypeIEValue) (*OTDOAInformationTypeItem, bool) {
		return value.AsOTDOAInformationTypeItem()
	}}
}
func (t OTDOAInformationTypeIETable) NewOpaque(id q4.ProtocolIEID, criticality q4.Criticality, data []byte) (OTDOAInformationTypeIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return OTDOAInformationTypeIEField{}, q5.OperationError(q6.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q4.ProtocolIEID(10):
		return OTDOAInformationTypeIEField{}, q5.OperationError(q6.Errorf("known IE id-OTDOA-Information-Type-Item requires its typed binding"), "Opaque")
	default:
		budget, err := q5.BuildBudget()
		if err != nil {
			return OTDOAInformationTypeIEField{}, q5.OperationError(err, "Opaque")
		}
		opaque, err := q5.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return OTDOAInformationTypeIEField{}, q5.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return OTDOAInformationTypeIEField{}, q5.OperationError(err, "Opaque")
		}
		return OTDOAInformationTypeIEField{Id: id, Criticality: criticality, Value: OTDOAInformationTypeIEValue{id: id, opaque: retained, isOpaque: true}}, q5.OperationError(nil, "Opaque")
	}
}

// MeasurementQuantitiesItemCodec binds the complete APER value type.
func MeasurementQuantitiesItemCodec() q12.MeasurementQuantitiesItemValueCodec {
	return MeasurementQuantitiesItemIEs().MeasurementQuantitiesItem().Codec()
}

// NPRSConfigurationCodec binds the complete source value type.
func NPRSConfigurationCodec() NPRSConfigurationValueCodec {
	return NPRSConfigurationValueCodec{path: "NPRSConfiguration", decode: func(data []byte, options q5.DecodeState) (NPRSConfiguration, error) {
		var value NPRSConfiguration
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return NPRSConfiguration{}, err
		}
		value.received = true
		value.receivedBytes = q5.OriginalWire(data)
		return value, nil
	}, encode: func(value NPRSConfiguration, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v NPRSConfiguration, options q5.DecodeState) (NPRSConfiguration, q5.Snapshot) {
		s := q5.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaNPRSConfiguration(&v, &s)
		var root q5.Snapshot
		s.OperationCounts()
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v NPRSConfiguration, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
		s := q5.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaNPRSConfiguration(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q4.BridgeCodecContext {
		sealed := q4.BridgeCodecContext{}
		*q4.BridgecodecContextFieldSource(&sealed) = "source-value:NPRSConfiguration"
		return sealed
	}(),
	}
}

// NPRSMutingConfigurationCodec binds the complete source value type.
func NPRSMutingConfigurationCodec() NPRSMutingConfigurationValueCodec {
	return NPRSMutingConfigurationValueCodec{path: "NPRSMutingConfiguration", decode: func(data []byte, options q5.DecodeState) (NPRSMutingConfiguration, error) {
		var value NPRSMutingConfiguration
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return NPRSMutingConfiguration{}, err
		}
		value.received = true
		value.receivedBytes = q5.OriginalWire(data)
		return value, nil
	}, encode: func(value NPRSMutingConfiguration, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v NPRSMutingConfiguration, options q5.DecodeState) (NPRSMutingConfiguration, q5.Snapshot) {
		s := q5.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaNPRSMutingConfiguration(&v, &s)
		var root q5.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v NPRSMutingConfiguration, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
		s := q5.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaNPRSMutingConfiguration(&v, &s)
		s.End(f, root, false)
		return s.
			Plan()
	}, context: func() q4.BridgeCodecContext {
		sealed := q4.BridgeCodecContext{}
		*q4.BridgecodecContextFieldSource(&sealed) = "source-value:NPRSMutingConfiguration"
		return sealed
	}(),
	}
}

// NPRSSubframePartACodec binds the complete source value type.
func NPRSSubframePartACodec() NPRSSubframePartAValueCodec {
	return NPRSSubframePartAValueCodec{path: "NPRSSubframePartA", decode: func(data []byte, options q5.DecodeState) (NPRSSubframePartA, error) {
		var value NPRSSubframePartA
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return NPRSSubframePartA{}, err
		}
		value.received = true
		value.receivedBytes = q5.OriginalWire(data)
		return value, nil
	}, encode: func(value NPRSSubframePartA, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v NPRSSubframePartA, options q5.DecodeState) (NPRSSubframePartA, q5.Snapshot) {
		s := q5.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaNPRSSubframePartA(&v, &s)
		var root q5.Snapshot
		s.OperationCounts()
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v NPRSSubframePartA, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
		s := q5.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaNPRSSubframePartA(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q4.BridgeCodecContext {
		sealed := q4.BridgeCodecContext{}
		*q4.BridgecodecContextFieldSource(&sealed) = "source-value:NPRSSubframePartA"
		return sealed
	}(),
	}
}

// NPRSSubframePartBCodec binds the complete source value type.
func NPRSSubframePartBCodec() NPRSSubframePartBValueCodec {
	return NPRSSubframePartBValueCodec{path: "NPRSSubframePartB", decode: func(data []byte, options q5.DecodeState) (NPRSSubframePartB, error) {
		var value NPRSSubframePartB
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return NPRSSubframePartB{}, err
		}
		value.received = true
		value.receivedBytes = q5.OriginalWire(data)
		return value, nil
	}, encode: func(value NPRSSubframePartB, fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v NPRSSubframePartB, options q5.DecodeState) (NPRSSubframePartB, q5.Snapshot) {
		s := q5.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaNPRSSubframePartB(&v, &s)
		var root q5.Snapshot
		s.OperationCounts()
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v NPRSSubframePartB, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
		s := q5.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaNPRSSubframePartB(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q4.BridgeCodecContext {
		sealed := q4.BridgeCodecContext{}
		*q4.BridgecodecContextFieldSource(&sealed) = "source-value:NPRSSubframePartB"
		return sealed
	}(),
	}
}

// OTDOAInformationTypeItemCodec binds the complete APER value type.
func OTDOAInformationTypeItemCodec() OTDOAInformationTypeItemValueCodec {
	return OTDOAInformationTypeIEs().OTDOAInformationTypeItem().Codec()
}
func BridgeMeasurementQuantitiesItemIETableMethodInfoMeasurementQuantitiesItem(v MeasurementQuantitiesItemIETable) q4.FieldInfo {
	return v.infoMeasurementQuantitiesItem()
}
func BridgeNPRSConfigurationAPERValueFieldContext(v *NPRSConfigurationAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeNPRSConfigurationAPERValueFieldReceived(v *NPRSConfigurationAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeNPRSConfigurationAPERValueFieldReplay(v *NPRSConfigurationAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeNPRSConfigurationAPERValueFieldWithoutReplay(v *NPRSConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNPRSConfigurationFieldExtCount(v *NPRSConfiguration) *int64   { return &v.extCount }
func BridgeNPRSConfigurationFieldExtData(v *NPRSConfiguration) *[][]byte { return &v.extData }
func BridgeNPRSConfigurationFieldExtOrigin(v *NPRSConfiguration) *[]q5.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeNPRSConfigurationFieldExtPresent(v *NPRSConfiguration) *[]bool     { return &v.extPresent }
func BridgeNPRSConfigurationFieldExtWire(v *NPRSConfiguration) *[]q5.WireSpan { return &v.extWire }
func BridgeNPRSConfigurationFieldPerExtPadding(v *NPRSConfiguration) *[]q5.CompletePadding {
	return &v.perExtPadding
}
func BridgeNPRSConfigurationFieldPerPadding(v *NPRSConfiguration) *q5.FinalPadding {
	return &v.perPadding
}
func BridgeNPRSConfigurationFieldReceived(v *NPRSConfiguration) *bool { return &v.received }
func BridgeNPRSConfigurationFieldReceivedBytes(v *NPRSConfiguration) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeNPRSConfigurationFieldReplay(v *NPRSConfiguration) *q5.Snapshot { return &v.replay }
func BridgeNPRSConfigurationFieldStream(v *NPRSConfiguration) *q5.WireSpan { return &v.stream }
func BridgeNPRSConfigurationFieldWithoutReplay(v *NPRSConfiguration) *bool { return &v.withoutReplay }
func BridgeNPRSConfigurationMethodMarshalAPERBudget(v *NPRSConfiguration, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNPRSConfigurationMethodMarshalAPERChanged(v *NPRSConfiguration, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNPRSConfigurationMethodMarshalAPERChangedValue(v *NPRSConfiguration, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNPRSConfigurationMethodMarshalAPERFreshValue(v *NPRSConfiguration, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeNPRSConfigurationMethodMarshalAPERLegacy(v *NPRSConfiguration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeNPRSConfigurationMethodMarshalAPERPlanned(v *NPRSConfiguration, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeNPRSConfigurationMethodMarshalAPERTo(v *NPRSConfiguration, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNPRSConfigurationMethodUnmarshalAPERFrom(v *NPRSConfiguration, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNPRSConfigurationMethodUnmarshalAPERLegacy(v *NPRSConfiguration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNPRSConfigurationMethodUnmarshalAPERWithOptions(v *NPRSConfiguration, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeNPRSConfigurationValueCodecFieldCapture(v *NPRSConfigurationValueCodec) *func(NPRSConfiguration, q5.DecodeState) (NPRSConfiguration, q5.Snapshot) {
	return &v.capture
}
func BridgeNPRSConfigurationValueCodecFieldCompare(v *NPRSConfigurationValueCodec) *func(NPRSConfiguration, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeNPRSConfigurationValueCodecFieldContext(v *NPRSConfigurationValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeNPRSConfigurationValueCodecFieldDecode(v *NPRSConfigurationValueCodec) *func([]byte, q5.DecodeState) (NPRSConfiguration, error) {
	return &v.decode
}
func BridgeNPRSConfigurationValueCodecFieldEncode(v *NPRSConfigurationValueCodec) *func(NPRSConfiguration, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNPRSConfigurationValueCodecFieldPath(v *NPRSConfigurationValueCodec) *q5.Path {
	return &v.path
}
func BridgeNPRSConfigurationValueCodecMethodEncodeBudget(v NPRSConfigurationValueCodec, a0 NPRSConfiguration, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNPRSConfigurationValueCodecMethodEncodeChanged(v NPRSConfigurationValueCodec, a0 NPRSConfiguration, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNPRSMutingConfigurationAPERValueFieldContext(v *NPRSMutingConfigurationAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeNPRSMutingConfigurationAPERValueFieldReceived(v *NPRSMutingConfigurationAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeNPRSMutingConfigurationAPERValueFieldReplay(v *NPRSMutingConfigurationAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeNPRSMutingConfigurationAPERValueFieldWithoutReplay(v *NPRSMutingConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNPRSMutingConfigurationFieldKnownOpenBytes(v *NPRSMutingConfiguration) *uint64 {
	return &v.knownOpenBytes
}
func BridgeNPRSMutingConfigurationFieldPerOpenTypePadding(v *NPRSMutingConfiguration) *q5.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeNPRSMutingConfigurationFieldPerPadding(v *NPRSMutingConfiguration) *q5.CompletePadding {
	return &v.perPadding
}
func BridgeNPRSMutingConfigurationFieldReceived(v *NPRSMutingConfiguration) *bool { return &v.received }
func BridgeNPRSMutingConfigurationFieldReceivedBytes(v *NPRSMutingConfiguration) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeNPRSMutingConfigurationFieldReplay(v *NPRSMutingConfiguration) *q5.Snapshot {
	return &v.replay
}
func BridgeNPRSMutingConfigurationFieldStream(v *NPRSMutingConfiguration) *q5.WireSpan {
	return &v.stream
}
func BridgeNPRSMutingConfigurationFieldWithoutReplay(v *NPRSMutingConfiguration) *bool {
	return &v.withoutReplay
}
func BridgeNPRSMutingConfigurationMethodMarshalAPERBudget(v *NPRSMutingConfiguration, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNPRSMutingConfigurationMethodMarshalAPERChanged(v *NPRSMutingConfiguration, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNPRSMutingConfigurationMethodMarshalAPERChangedValue(v *NPRSMutingConfiguration, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNPRSMutingConfigurationMethodMarshalAPERFreshValue(v *NPRSMutingConfiguration, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeNPRSMutingConfigurationMethodMarshalAPERLegacy(v *NPRSMutingConfiguration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeNPRSMutingConfigurationMethodMarshalAPERPlanned(v *NPRSMutingConfiguration, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeNPRSMutingConfigurationMethodMarshalAPERTo(v *NPRSMutingConfiguration, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNPRSMutingConfigurationMethodUnmarshalAPERFrom(v *NPRSMutingConfiguration, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNPRSMutingConfigurationMethodUnmarshalAPERLegacy(v *NPRSMutingConfiguration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNPRSMutingConfigurationMethodUnmarshalAPERWithOptions(v *NPRSMutingConfiguration, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeNPRSMutingConfigurationValueCodecFieldCapture(v *NPRSMutingConfigurationValueCodec) *func(NPRSMutingConfiguration, q5.DecodeState) (NPRSMutingConfiguration, q5.Snapshot) {
	return &v.capture
}
func BridgeNPRSMutingConfigurationValueCodecFieldCompare(v *NPRSMutingConfigurationValueCodec) *func(NPRSMutingConfiguration, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeNPRSMutingConfigurationValueCodecFieldContext(v *NPRSMutingConfigurationValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeNPRSMutingConfigurationValueCodecFieldDecode(v *NPRSMutingConfigurationValueCodec) *func([]byte, q5.DecodeState) (NPRSMutingConfiguration, error) {
	return &v.decode
}
func BridgeNPRSMutingConfigurationValueCodecFieldEncode(v *NPRSMutingConfigurationValueCodec) *func(NPRSMutingConfiguration, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNPRSMutingConfigurationValueCodecFieldPath(v *NPRSMutingConfigurationValueCodec) *q5.Path {
	return &v.path
}
func BridgeNPRSMutingConfigurationValueCodecMethodEncodeBudget(v NPRSMutingConfigurationValueCodec, a0 NPRSMutingConfiguration, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNPRSMutingConfigurationValueCodecMethodEncodeChanged(v NPRSMutingConfigurationValueCodec, a0 NPRSMutingConfiguration, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNPRSSubframePartAAPERValueFieldContext(v *NPRSSubframePartAAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeNPRSSubframePartAAPERValueFieldReceived(v *NPRSSubframePartAAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeNPRSSubframePartAAPERValueFieldReplay(v *NPRSSubframePartAAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeNPRSSubframePartAAPERValueFieldWithoutReplay(v *NPRSSubframePartAAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNPRSSubframePartAFieldExtCount(v *NPRSSubframePartA) *int64   { return &v.extCount }
func BridgeNPRSSubframePartAFieldExtData(v *NPRSSubframePartA) *[][]byte { return &v.extData }
func BridgeNPRSSubframePartAFieldExtOrigin(v *NPRSSubframePartA) *[]q5.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeNPRSSubframePartAFieldExtPresent(v *NPRSSubframePartA) *[]bool     { return &v.extPresent }
func BridgeNPRSSubframePartAFieldExtWire(v *NPRSSubframePartA) *[]q5.WireSpan { return &v.extWire }
func BridgeNPRSSubframePartAFieldPerExtPadding(v *NPRSSubframePartA) *[]q5.CompletePadding {
	return &v.perExtPadding
}
func BridgeNPRSSubframePartAFieldPerPadding(v *NPRSSubframePartA) *q5.FinalPadding {
	return &v.perPadding
}
func BridgeNPRSSubframePartAFieldReceived(v *NPRSSubframePartA) *bool { return &v.received }
func BridgeNPRSSubframePartAFieldReceivedBytes(v *NPRSSubframePartA) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeNPRSSubframePartAFieldReplay(v *NPRSSubframePartA) *q5.Snapshot { return &v.replay }
func BridgeNPRSSubframePartAFieldStream(v *NPRSSubframePartA) *q5.WireSpan { return &v.stream }
func BridgeNPRSSubframePartAFieldWithoutReplay(v *NPRSSubframePartA) *bool { return &v.withoutReplay }
func BridgeNPRSSubframePartAMethodMarshalAPERBudget(v *NPRSSubframePartA, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNPRSSubframePartAMethodMarshalAPERChanged(v *NPRSSubframePartA, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNPRSSubframePartAMethodMarshalAPERChangedValue(v *NPRSSubframePartA, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNPRSSubframePartAMethodMarshalAPERFreshValue(v *NPRSSubframePartA, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeNPRSSubframePartAMethodMarshalAPERLegacy(v *NPRSSubframePartA) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeNPRSSubframePartAMethodMarshalAPERPlanned(v *NPRSSubframePartA, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeNPRSSubframePartAMethodMarshalAPERTo(v *NPRSSubframePartA, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNPRSSubframePartAMethodUnmarshalAPERFrom(v *NPRSSubframePartA, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNPRSSubframePartAMethodUnmarshalAPERLegacy(v *NPRSSubframePartA, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNPRSSubframePartAMethodUnmarshalAPERWithOptions(v *NPRSSubframePartA, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeNPRSSubframePartAValueCodecFieldCapture(v *NPRSSubframePartAValueCodec) *func(NPRSSubframePartA, q5.DecodeState) (NPRSSubframePartA, q5.Snapshot) {
	return &v.capture
}
func BridgeNPRSSubframePartAValueCodecFieldCompare(v *NPRSSubframePartAValueCodec) *func(NPRSSubframePartA, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeNPRSSubframePartAValueCodecFieldContext(v *NPRSSubframePartAValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeNPRSSubframePartAValueCodecFieldDecode(v *NPRSSubframePartAValueCodec) *func([]byte, q5.DecodeState) (NPRSSubframePartA, error) {
	return &v.decode
}
func BridgeNPRSSubframePartAValueCodecFieldEncode(v *NPRSSubframePartAValueCodec) *func(NPRSSubframePartA, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNPRSSubframePartAValueCodecFieldPath(v *NPRSSubframePartAValueCodec) *q5.Path {
	return &v.path
}
func BridgeNPRSSubframePartAValueCodecMethodEncodeBudget(v NPRSSubframePartAValueCodec, a0 NPRSSubframePartA, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNPRSSubframePartAValueCodecMethodEncodeChanged(v NPRSSubframePartAValueCodec, a0 NPRSSubframePartA, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNPRSSubframePartBAPERValueFieldContext(v *NPRSSubframePartBAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeNPRSSubframePartBAPERValueFieldReceived(v *NPRSSubframePartBAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeNPRSSubframePartBAPERValueFieldReplay(v *NPRSSubframePartBAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeNPRSSubframePartBAPERValueFieldWithoutReplay(v *NPRSSubframePartBAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNPRSSubframePartBFieldExtCount(v *NPRSSubframePartB) *int64   { return &v.extCount }
func BridgeNPRSSubframePartBFieldExtData(v *NPRSSubframePartB) *[][]byte { return &v.extData }
func BridgeNPRSSubframePartBFieldExtOrigin(v *NPRSSubframePartB) *[]q5.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeNPRSSubframePartBFieldExtPresent(v *NPRSSubframePartB) *[]bool     { return &v.extPresent }
func BridgeNPRSSubframePartBFieldExtWire(v *NPRSSubframePartB) *[]q5.WireSpan { return &v.extWire }
func BridgeNPRSSubframePartBFieldKnownOpenBytes(v *NPRSSubframePartB) *uint64 {
	return &v.knownOpenBytes
}
func BridgeNPRSSubframePartBFieldPerExtPadding(v *NPRSSubframePartB) *[]q5.CompletePadding {
	return &v.perExtPadding
}
func BridgeNPRSSubframePartBFieldPerPadding(v *NPRSSubframePartB) *q5.FinalPadding {
	return &v.perPadding
}
func BridgeNPRSSubframePartBFieldReceived(v *NPRSSubframePartB) *bool { return &v.received }
func BridgeNPRSSubframePartBFieldReceivedBytes(v *NPRSSubframePartB) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeNPRSSubframePartBFieldReplay(v *NPRSSubframePartB) *q5.Snapshot { return &v.replay }
func BridgeNPRSSubframePartBFieldStream(v *NPRSSubframePartB) *q5.WireSpan { return &v.stream }
func BridgeNPRSSubframePartBFieldWithoutReplay(v *NPRSSubframePartB) *bool { return &v.withoutReplay }
func BridgeNPRSSubframePartBMethodMarshalAPERBudget(v *NPRSSubframePartB, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNPRSSubframePartBMethodMarshalAPERChanged(v *NPRSSubframePartB, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNPRSSubframePartBMethodMarshalAPERChangedValue(v *NPRSSubframePartB, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNPRSSubframePartBMethodMarshalAPERFreshValue(v *NPRSSubframePartB, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeNPRSSubframePartBMethodMarshalAPERLegacy(v *NPRSSubframePartB) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeNPRSSubframePartBMethodMarshalAPERPlanned(v *NPRSSubframePartB, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeNPRSSubframePartBMethodMarshalAPERTo(v *NPRSSubframePartB, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNPRSSubframePartBMethodUnmarshalAPERFrom(v *NPRSSubframePartB, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNPRSSubframePartBMethodUnmarshalAPERLegacy(v *NPRSSubframePartB, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNPRSSubframePartBMethodUnmarshalAPERWithOptions(v *NPRSSubframePartB, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeNPRSSubframePartBValueCodecFieldCapture(v *NPRSSubframePartBValueCodec) *func(NPRSSubframePartB, q5.DecodeState) (NPRSSubframePartB, q5.Snapshot) {
	return &v.capture
}
func BridgeNPRSSubframePartBValueCodecFieldCompare(v *NPRSSubframePartBValueCodec) *func(NPRSSubframePartB, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeNPRSSubframePartBValueCodecFieldContext(v *NPRSSubframePartBValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeNPRSSubframePartBValueCodecFieldDecode(v *NPRSSubframePartBValueCodec) *func([]byte, q5.DecodeState) (NPRSSubframePartB, error) {
	return &v.decode
}
func BridgeNPRSSubframePartBValueCodecFieldEncode(v *NPRSSubframePartBValueCodec) *func(NPRSSubframePartB, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNPRSSubframePartBValueCodecFieldPath(v *NPRSSubframePartBValueCodec) *q5.Path {
	return &v.path
}
func BridgeNPRSSubframePartBValueCodecMethodEncodeBudget(v NPRSSubframePartBValueCodec, a0 NPRSSubframePartB, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNPRSSubframePartBValueCodecMethodEncodeChanged(v NPRSSubframePartBValueCodec, a0 NPRSSubframePartB, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNRCGIAPERValueFieldContext(v *NRCGIAPERValue) *q4.BridgeCodecContext { return &v.context }
func BridgeNRCGIAPERValueFieldReceived(v *NRCGIAPERValue) *q5.WireSpan          { return &v.received }
func BridgeNRCGIAPERValueFieldReplay(v *NRCGIAPERValue) *q5.Snapshot            { return &v.replay }
func BridgeNRCGIAPERValueFieldWithoutReplay(v *NRCGIAPERValue) *bool            { return &v.withoutReplay }
func BridgeNRCGIFieldExtCount(v *NRCGI) *int64                                  { return &v.extCount }
func BridgeNRCGIFieldExtData(v *NRCGI) *[][]byte                                { return &v.extData }
func BridgeNRCGIFieldExtOrigin(v *NRCGI) *[]q5.OpaqueOrigin                     { return &v.extOrigin }
func BridgeNRCGIFieldExtPresent(v *NRCGI) *[]bool                               { return &v.extPresent }
func BridgeNRCGIFieldExtWire(v *NRCGI) *[]q5.WireSpan                           { return &v.extWire }
func BridgeNRCGIFieldIEExtensionsIndef(v *NRCGI) *bool                          { return &v.iEExtensionsIndef }
func BridgeNRCGIFieldPerExtPadding(v *NRCGI) *[]q5.CompletePadding              { return &v.perExtPadding }
func BridgeNRCGIFieldPerPadding(v *NRCGI) *q5.FinalPadding                      { return &v.perPadding }
func BridgeNRCGIFieldReceived(v *NRCGI) *bool                                   { return &v.received }
func BridgeNRCGIFieldReceivedBytes(v *NRCGI) *q5.WireSpan                       { return &v.receivedBytes }
func BridgeNRCGIFieldReplay(v *NRCGI) *q5.Snapshot                              { return &v.replay }
func BridgeNRCGIFieldStream(v *NRCGI) *q5.WireSpan                              { return &v.stream }
func BridgeNRCGIFieldWithoutReplay(v *NRCGI) *bool                              { return &v.withoutReplay }
func BridgeNRCGIMethodMarshalAPERBudget(v *NRCGI, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeNRCGIMethodMarshalAPERChanged(v *NRCGI, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeNRCGIMethodMarshalAPERChangedValue(v *NRCGI, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeNRCGIMethodMarshalAPERFreshValue(v *NRCGI, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeNRCGIMethodMarshalAPERLegacy(v *NRCGI) ([]byte, error) { return v.marshalAPERLegacy() }
func BridgeNRCGIMethodMarshalAPERPlanned(v *NRCGI, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeNRCGIMethodMarshalAPERTo(v *NRCGI, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeNRCGIMethodUnmarshalAPERFrom(v *NRCGI, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeNRCGIMethodUnmarshalAPERLegacy(v *NRCGI, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeNRCGIMethodUnmarshalAPERWithOptions(v *NRCGI, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeNRCGIValueCodecFieldCapture(v *NRCGIValueCodec) *func(NRCGI, q5.DecodeState) (NRCGI, q5.Snapshot) {
	return &v.capture
}
func BridgeNRCGIValueCodecFieldCompare(v *NRCGIValueCodec) *func(NRCGI, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeNRCGIValueCodecFieldContext(v *NRCGIValueCodec) *q4.BridgeCodecContext { return &v.context }
func BridgeNRCGIValueCodecFieldDecode(v *NRCGIValueCodec) *func([]byte, q5.DecodeState) (NRCGI, error) {
	return &v.decode
}
func BridgeNRCGIValueCodecFieldEncode(v *NRCGIValueCodec) *func(NRCGI, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRCGIValueCodecFieldPath(v *NRCGIValueCodec) *q5.Path { return &v.path }
func BridgeNRCGIValueCodecMethodEncodeBudget(v NRCGIValueCodec, a0 NRCGI, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNRCGIValueCodecMethodEncodeChanged(v NRCGIValueCodec, a0 NRCGI, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOAInformationTypeAPERValueFieldContext(v *OTDOAInformationTypeAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationTypeAPERValueFieldReceived(v *OTDOAInformationTypeAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationTypeAPERValueFieldReplay(v *OTDOAInformationTypeAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationTypeAPERValueFieldWithoutReplay(v *OTDOAInformationTypeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationTypeIEFieldFieldReceived(v *OTDOAInformationTypeIEField) *q5.CompletePadding {
	return &v.received
}
func BridgeOTDOAInformationTypeIEFieldFieldReplay(v *OTDOAInformationTypeIEField) *q5.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationTypeIEFieldFieldStream(v *OTDOAInformationTypeIEField) *q5.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationTypeIEFieldFieldWithoutReplay(v *OTDOAInformationTypeIEField) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationTypeIEFieldMethodMarshalAPERTo(v *OTDOAInformationTypeIEField, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationTypeIEFieldMethodUnmarshalAPERFrom(v *OTDOAInformationTypeIEField, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationTypeIETableMethodInfoOTDOAInformationTypeItem(v OTDOAInformationTypeIETable) q4.FieldInfo {
	return v.infoOTDOAInformationTypeItem()
}
func BridgeOTDOAInformationTypeIEValueFieldId(v *OTDOAInformationTypeIEValue) *q4.ProtocolIEID {
	return &v.id
}
func BridgeOTDOAInformationTypeIEValueFieldIsOpaque(v *OTDOAInformationTypeIEValue) *bool {
	return &v.isOpaque
}
func BridgeOTDOAInformationTypeIEValueFieldOpaque(v *OTDOAInformationTypeIEValue) **q5.OpaqueOpenType {
	return &v.opaque
}
func BridgeOTDOAInformationTypeIEValueFieldReceived(v *OTDOAInformationTypeIEValue) *q5.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationTypeIEValueFieldReplay(v *OTDOAInformationTypeIEValue) *q5.Snapshot {
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
func BridgeOTDOAInformationTypeIEValueMethodCaptureSemantics(v OTDOAInformationTypeIEValue, a0 q5.SemanticCapture) OTDOAInformationTypeIEValue {
	return v.captureSemantics(a0)
}
func BridgeOTDOAInformationTypeIEValueMethodCaptureSnapshot(v OTDOAInformationTypeIEValue) q5.Snapshot {
	return v.captureSnapshot()
}
func BridgeOTDOAInformationTypeIEValueMethodCompareSemantics(v OTDOAInformationTypeIEValue, a0 q5.SemanticComparison) q5.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeOTDOAInformationTypeIEValueMethodDecode(v OTDOAInformationTypeIEValue, a0 q4.ProtocolIEID, a1 q5.OpaqueOpenType) (OTDOAInformationTypeIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeOTDOAInformationTypeIEValueMethodEncode(v OTDOAInformationTypeIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeOTDOAInformationTypeIEValueMethodEncodeFresh(v OTDOAInformationTypeIEValue, a0 bool, a1 *q5.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeOTDOAInformationTypeIEValueMethodMatchesID(v OTDOAInformationTypeIEValue, a0 q4.ProtocolIEID, a1 *q5.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeOTDOAInformationTypeIEValueMethodReason(v OTDOAInformationTypeIEValue, a0 q4.ProtocolIEID) q5.OpaqueReason {
	return v.reason(a0)
}
func BridgeOTDOAInformationTypeIEValueMethodRule(v OTDOAInformationTypeIEValue) q5.SourceRule {
	return v.rule()
}
func BridgeOTDOAInformationTypeItemAPERValueFieldContext(v *OTDOAInformationTypeItemAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationTypeItemAPERValueFieldReceived(v *OTDOAInformationTypeItemAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationTypeItemAPERValueFieldReplay(v *OTDOAInformationTypeItemAPERValue) *q5.Snapshot {
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
func BridgeOTDOAInformationTypeItemFieldExtOrigin(v *OTDOAInformationTypeItem) *[]q5.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeOTDOAInformationTypeItemFieldExtPresent(v *OTDOAInformationTypeItem) *[]bool {
	return &v.extPresent
}
func BridgeOTDOAInformationTypeItemFieldExtWire(v *OTDOAInformationTypeItem) *[]q5.WireSpan {
	return &v.extWire
}
func BridgeOTDOAInformationTypeItemFieldIEExtensionsIndef(v *OTDOAInformationTypeItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeOTDOAInformationTypeItemFieldPerExtPadding(v *OTDOAInformationTypeItem) *[]q5.CompletePadding {
	return &v.perExtPadding
}
func BridgeOTDOAInformationTypeItemFieldPerPadding(v *OTDOAInformationTypeItem) *q5.FinalPadding {
	return &v.perPadding
}
func BridgeOTDOAInformationTypeItemFieldReceived(v *OTDOAInformationTypeItem) *bool {
	return &v.received
}
func BridgeOTDOAInformationTypeItemFieldReceivedBytes(v *OTDOAInformationTypeItem) *q5.WireSpan {
	return &v.receivedBytes
}
func BridgeOTDOAInformationTypeItemFieldReplay(v *OTDOAInformationTypeItem) *q5.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationTypeItemFieldStream(v *OTDOAInformationTypeItem) *q5.WireSpan {
	return &v.stream
}
func BridgeOTDOAInformationTypeItemFieldWithoutReplay(v *OTDOAInformationTypeItem) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationTypeItemMethodMarshalAPERBudget(v *OTDOAInformationTypeItem, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeOTDOAInformationTypeItemMethodMarshalAPERChanged(v *OTDOAInformationTypeItem, a0 *q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeOTDOAInformationTypeItemMethodMarshalAPERChangedValue(v *OTDOAInformationTypeItem, a0 q5.DecodeBudget, a1 bool, a2 q5.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeOTDOAInformationTypeItemMethodMarshalAPERFreshValue(v *OTDOAInformationTypeItem, a0 q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeOTDOAInformationTypeItemMethodMarshalAPERLegacy(v *OTDOAInformationTypeItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeOTDOAInformationTypeItemMethodMarshalAPERPlanned(v *OTDOAInformationTypeItem, a0 *q5.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeOTDOAInformationTypeItemMethodMarshalAPERTo(v *OTDOAInformationTypeItem, a0 *q5.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeOTDOAInformationTypeItemMethodUnmarshalAPERFrom(v *OTDOAInformationTypeItem, a0 *q5.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeOTDOAInformationTypeItemMethodUnmarshalAPERLegacy(v *OTDOAInformationTypeItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeOTDOAInformationTypeItemMethodUnmarshalAPERWithOptions(v *OTDOAInformationTypeItem, a0 []byte, a1 q5.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeOTDOAInformationTypeItemValueCodecFieldCapture(v *OTDOAInformationTypeItemValueCodec) *func(OTDOAInformationTypeItem, q5.DecodeState) (OTDOAInformationTypeItem, q5.Snapshot) {
	return &v.capture
}
func BridgeOTDOAInformationTypeItemValueCodecFieldCompare(v *OTDOAInformationTypeItemValueCodec) *func(OTDOAInformationTypeItem, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeOTDOAInformationTypeItemValueCodecFieldContext(v *OTDOAInformationTypeItemValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationTypeItemValueCodecFieldDecode(v *OTDOAInformationTypeItemValueCodec) *func([]byte, q5.DecodeState) (OTDOAInformationTypeItem, error) {
	return &v.decode
}
func BridgeOTDOAInformationTypeItemValueCodecFieldEncode(v *OTDOAInformationTypeItemValueCodec) *func(OTDOAInformationTypeItem, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOAInformationTypeItemValueCodecFieldPath(v *OTDOAInformationTypeItemValueCodec) *q5.Path {
	return &v.path
}
func BridgeOTDOAInformationTypeItemValueCodecMethodEncodeBudget(v OTDOAInformationTypeItemValueCodec, a0 OTDOAInformationTypeItem, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOAInformationTypeItemValueCodecMethodEncodeChanged(v OTDOAInformationTypeItemValueCodec, a0 OTDOAInformationTypeItem, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOAInformationTypeOTDOAInformationTypeItemIEBindingFieldCodec(v *OTDOAInformationTypeOTDOAInformationTypeItemIEBinding) *OTDOAInformationTypeItemValueCodec {
	return &v.codec
}
func BridgeOTDOAInformationTypeOTDOAInformationTypeItemIEBindingFieldGet(v *OTDOAInformationTypeOTDOAInformationTypeItemIEBinding) *func(*OTDOAInformationTypeIEValue) (*OTDOAInformationTypeItem, bool) {
	return &v.get
}
func BridgeOTDOAInformationTypeOTDOAInformationTypeItemIEBindingFieldInfo(v *OTDOAInformationTypeOTDOAInformationTypeItemIEBinding) *q4.FieldInfo {
	return &v.info
}
func BridgeOTDOAInformationTypeOTDOAInformationTypeItemIEBindingFieldInject(v *OTDOAInformationTypeOTDOAInformationTypeItemIEBinding) *func(OTDOAInformationTypeItem) OTDOAInformationTypeIEValue {
	return &v.inject
}
func BridgeOTDOAInformationTypeValueCodecFieldCapture(v *OTDOAInformationTypeValueCodec) *func(OTDOAInformationType, q5.DecodeState) (OTDOAInformationType, q5.Snapshot) {
	return &v.capture
}
func BridgeOTDOAInformationTypeValueCodecFieldCompare(v *OTDOAInformationTypeValueCodec) *func(OTDOAInformationType, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeOTDOAInformationTypeValueCodecFieldContext(v *OTDOAInformationTypeValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationTypeValueCodecFieldDecode(v *OTDOAInformationTypeValueCodec) *func([]byte, q5.DecodeState) (OTDOAInformationType, error) {
	return &v.decode
}
func BridgeOTDOAInformationTypeValueCodecFieldEncode(v *OTDOAInformationTypeValueCodec) *func(OTDOAInformationType, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOAInformationTypeValueCodecFieldPath(v *OTDOAInformationTypeValueCodec) *q5.Path {
	return &v.path
}
func BridgeOTDOAInformationTypeValueCodecMethodEncodeBudget(v OTDOAInformationTypeValueCodec, a0 OTDOAInformationType, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOAInformationTypeValueCodecMethodEncodeChanged(v OTDOAInformationTypeValueCodec, a0 OTDOAInformationType, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
