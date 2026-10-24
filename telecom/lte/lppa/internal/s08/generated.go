// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s08 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s08

import (
	q6 "fmt"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	q7 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q11 "math/big"
)

// PrivateMessageIEsValuePrivateIEContainer is the concrete PrivateIEContainer[PrivateMessageIEsValue].
type PrivateMessageIEsValuePrivateIEContainer []PrivateMessageIEsValuePrivateIEField

// PrivateMessageIEsValuePrivateIEField is the concrete PrivateIEField[PrivateMessageIEsValue].
type PrivateMessageIEsValuePrivateIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            PrivateIEID
	Criticality   q5.Criticality
	Value         PrivateMessageIEsValue

	received q4.CompletePadding
}

func (v PrivateMessageIEsValuePrivateIEField) WithoutReplay() PrivateMessageIEsValuePrivateIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *PrivateMessageIEsValuePrivateIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *PrivateMessageIEsValuePrivateIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.WrapDecodePath(q6.Errorf("%w: private field id does not match its value selector", q4.ErrInvalidValue), "PrivateIEField.Id")
	}
	if err := v.Id.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	return q4.EncodeOpenTypeAligned(bb, data)
}
func (v *PrivateMessageIEsValuePrivateIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil PrivateIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PrivateMessageIEsValuePrivateIEField{}
	if err := v.Id.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "Id")
	}
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q7.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero PrivateMessageIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, q4.UnknownSelector, zero.rule())
	if err != nil {
		return q7.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("PrivateIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return q7.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}

// RequestedSRSTransmissionCharacteristicsValueCodec is the concrete ValueCodec[RequestedSRSTransmissionCharacteristics].
type RequestedSRSTransmissionCharacteristicsValueCodec struct {
	context q5.BridgeCodecContext
	capture func(RequestedSRSTransmissionCharacteristics, q4.DecodeState,

	) (RequestedSRSTransmissionCharacteristics, q4.Snapshot,

	)
	compare func(RequestedSRSTransmissionCharacteristics, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (RequestedSRSTransmissionCharacteristics,

		error)
	encode func(RequestedSRSTransmissionCharacteristics,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c RequestedSRSTransmissionCharacteristicsValueCodec) New(value RequestedSRSTransmissionCharacteristics,

) (RequestedSRSTransmissionCharacteristicsAPERValue, error) {
	if c.encode == nil {
		return RequestedSRSTransmissionCharacteristicsAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return RequestedSRSTransmissionCharacteristicsAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RequestedSRSTransmissionCharacteristicsAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return RequestedSRSTransmissionCharacteristicsAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c RequestedSRSTransmissionCharacteristicsValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (RequestedSRSTransmissionCharacteristicsAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return RequestedSRSTransmissionCharacteristicsAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return RequestedSRSTransmissionCharacteristicsAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return RequestedSRSTransmissionCharacteristicsAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return RequestedSRSTransmissionCharacteristicsAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return RequestedSRSTransmissionCharacteristicsAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c RequestedSRSTransmissionCharacteristicsValueCodec) EncodeAPER(value RequestedSRSTransmissionCharacteristicsAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c RequestedSRSTransmissionCharacteristicsValueCodec) encodeBudget(value RequestedSRSTransmissionCharacteristics,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c RequestedSRSTransmissionCharacteristicsValueCodec) encodeChanged(value RequestedSRSTransmissionCharacteristics,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// PRSFrequencyHoppingConfigurationValueCodec is the concrete ValueCodec[PRSFrequencyHoppingConfiguration].
type PRSFrequencyHoppingConfigurationValueCodec struct {
	context q5.BridgeCodecContext
	capture func(PRSFrequencyHoppingConfiguration, q4.DecodeState,

	) (PRSFrequencyHoppingConfiguration, q4.Snapshot,

	)
	compare func(PRSFrequencyHoppingConfiguration, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (PRSFrequencyHoppingConfiguration,

		error)
	encode func(PRSFrequencyHoppingConfiguration,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c PRSFrequencyHoppingConfigurationValueCodec) New(value PRSFrequencyHoppingConfiguration,

) (PRSFrequencyHoppingConfigurationAPERValue, error) {
	if c.encode == nil {
		return PRSFrequencyHoppingConfigurationAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return PRSFrequencyHoppingConfigurationAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PRSFrequencyHoppingConfigurationAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return PRSFrequencyHoppingConfigurationAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c PRSFrequencyHoppingConfigurationValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (PRSFrequencyHoppingConfigurationAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PRSFrequencyHoppingConfigurationAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return PRSFrequencyHoppingConfigurationAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PRSFrequencyHoppingConfigurationAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return PRSFrequencyHoppingConfigurationAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return PRSFrequencyHoppingConfigurationAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PRSFrequencyHoppingConfigurationValueCodec) EncodeAPER(value PRSFrequencyHoppingConfigurationAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c PRSFrequencyHoppingConfigurationValueCodec) encodeBudget(value PRSFrequencyHoppingConfiguration,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PRSFrequencyHoppingConfigurationValueCodec) encodeChanged(value PRSFrequencyHoppingConfiguration,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// PRSMutingConfigurationValueCodec is the concrete ValueCodec[PRSMutingConfiguration].
type PRSMutingConfigurationValueCodec struct {
	context q5.BridgeCodecContext
	capture func(PRSMutingConfiguration, q4.DecodeState,

	) (PRSMutingConfiguration, q4.Snapshot,

	)
	compare func(PRSMutingConfiguration, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (PRSMutingConfiguration,

		error)
	encode func(PRSMutingConfiguration,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c PRSMutingConfigurationValueCodec) New(value PRSMutingConfiguration,

) (PRSMutingConfigurationAPERValue, error) {
	if c.encode == nil {
		return PRSMutingConfigurationAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return PRSMutingConfigurationAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PRSMutingConfigurationAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return PRSMutingConfigurationAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c PRSMutingConfigurationValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (PRSMutingConfigurationAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PRSMutingConfigurationAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return PRSMutingConfigurationAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PRSMutingConfigurationAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return PRSMutingConfigurationAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return PRSMutingConfigurationAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PRSMutingConfigurationValueCodec) EncodeAPER(value PRSMutingConfigurationAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c PRSMutingConfigurationValueCodec) encodeBudget(value PRSMutingConfiguration,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PRSMutingConfigurationValueCodec) encodeChanged(value PRSMutingConfiguration,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// PosSIBSegmentsValueCodec is the concrete ValueCodec[PosSIBSegments].
type PosSIBSegmentsValueCodec struct {
	context q5.BridgeCodecContext
	capture func(PosSIBSegments, q4.DecodeState,

	) (PosSIBSegments, q4.Snapshot,

	)
	compare func(PosSIBSegments, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (PosSIBSegments,

		error)
	encode func(PosSIBSegments,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c PosSIBSegmentsValueCodec) New(value PosSIBSegments,

) (PosSIBSegmentsAPERValue, error) {
	if c.encode == nil {
		return PosSIBSegmentsAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return PosSIBSegmentsAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PosSIBSegmentsAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return PosSIBSegmentsAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c PosSIBSegmentsValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (PosSIBSegmentsAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PosSIBSegmentsAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return PosSIBSegmentsAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PosSIBSegmentsAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return PosSIBSegmentsAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return PosSIBSegmentsAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PosSIBSegmentsValueCodec) EncodeAPER(value PosSIBSegmentsAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c PosSIBSegmentsValueCodec) encodeBudget(value PosSIBSegments,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PosSIBSegmentsValueCodec) encodeChanged(value PosSIBSegments,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// PosSIBSegmentsElemValueCodec is the concrete ValueCodec[PosSIBSegmentsElem].
type PosSIBSegmentsElemValueCodec struct {
	context q5.BridgeCodecContext
	capture func(PosSIBSegmentsElem, q4.DecodeState,

	) (PosSIBSegmentsElem, q4.Snapshot,

	)
	compare func(PosSIBSegmentsElem, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (PosSIBSegmentsElem,

		error)
	encode func(PosSIBSegmentsElem,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c PosSIBSegmentsElemValueCodec) New(value PosSIBSegmentsElem,

) (PosSIBSegmentsElemAPERValue, error) {
	if c.encode == nil {
		return PosSIBSegmentsElemAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return PosSIBSegmentsElemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PosSIBSegmentsElemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return PosSIBSegmentsElemAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c PosSIBSegmentsElemValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (PosSIBSegmentsElemAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PosSIBSegmentsElemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return PosSIBSegmentsElemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PosSIBSegmentsElemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return PosSIBSegmentsElemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return PosSIBSegmentsElemAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PosSIBSegmentsElemValueCodec) EncodeAPER(value PosSIBSegmentsElemAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c PosSIBSegmentsElemValueCodec) encodeBudget(value PosSIBSegmentsElem,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PosSIBSegmentsElemValueCodec) encodeChanged(value PosSIBSegmentsElem,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// PrivateIEIDValueCodec is the concrete ValueCodec[PrivateIEID].
type PrivateIEIDValueCodec struct {
	context q5.BridgeCodecContext
	capture func(PrivateIEID, q4.DecodeState,

	) (PrivateIEID, q4.Snapshot,

	)
	compare func(PrivateIEID, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (PrivateIEID,

		error)
	encode func(PrivateIEID,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c PrivateIEIDValueCodec) New(value PrivateIEID,

) (PrivateIEIDAPERValue, error) {
	if c.encode == nil {
		return PrivateIEIDAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return PrivateIEIDAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PrivateIEIDAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return PrivateIEIDAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c PrivateIEIDValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (PrivateIEIDAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PrivateIEIDAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return PrivateIEIDAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PrivateIEIDAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return PrivateIEIDAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return PrivateIEIDAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PrivateIEIDValueCodec) EncodeAPER(value PrivateIEIDAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c PrivateIEIDValueCodec) encodeBudget(value PrivateIEID,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PrivateIEIDValueCodec) encodeChanged(value PrivateIEID,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// ResultUTRANItemPhysCellIDUTRANValueCodec is the concrete ValueCodec[ResultUTRANItemPhysCellIDUTRAN].
type ResultUTRANItemPhysCellIDUTRANValueCodec struct {
	context q5.BridgeCodecContext
	capture func(ResultUTRANItemPhysCellIDUTRAN, q4.DecodeState,

	) (ResultUTRANItemPhysCellIDUTRAN, q4.Snapshot,

	)
	compare func(ResultUTRANItemPhysCellIDUTRAN, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (ResultUTRANItemPhysCellIDUTRAN,

		error)
	encode func(ResultUTRANItemPhysCellIDUTRAN,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c ResultUTRANItemPhysCellIDUTRANValueCodec) New(value ResultUTRANItemPhysCellIDUTRAN,

) (ResultUTRANItemPhysCellIDUTRANAPERValue, error) {
	if c.encode == nil {
		return ResultUTRANItemPhysCellIDUTRANAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ResultUTRANItemPhysCellIDUTRANAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultUTRANItemPhysCellIDUTRANAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return ResultUTRANItemPhysCellIDUTRANAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c ResultUTRANItemPhysCellIDUTRANValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (ResultUTRANItemPhysCellIDUTRANAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultUTRANItemPhysCellIDUTRANAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return ResultUTRANItemPhysCellIDUTRANAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultUTRANItemPhysCellIDUTRANAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return ResultUTRANItemPhysCellIDUTRANAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return ResultUTRANItemPhysCellIDUTRANAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ResultUTRANItemPhysCellIDUTRANValueCodec) EncodeAPER(value ResultUTRANItemPhysCellIDUTRANAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c ResultUTRANItemPhysCellIDUTRANValueCodec) encodeBudget(value ResultUTRANItemPhysCellIDUTRAN,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultUTRANItemPhysCellIDUTRANValueCodec) encodeChanged(value ResultUTRANItemPhysCellIDUTRAN,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// RequestedSRSTransmissionCharacteristicsAPERValue is the concrete APERValue[RequestedSRSTransmissionCharacteristics].
type RequestedSRSTransmissionCharacteristicsAPERValue struct {
	context q5.BridgeCodecContext
	Value   RequestedSRSTransmissionCharacteristics

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v RequestedSRSTransmissionCharacteristicsAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v RequestedSRSTransmissionCharacteristicsAPERValue) WithoutReplay() RequestedSRSTransmissionCharacteristicsAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// PRSFrequencyHoppingConfigurationAPERValue is the concrete APERValue[PRSFrequencyHoppingConfiguration].
type PRSFrequencyHoppingConfigurationAPERValue struct {
	context q5.BridgeCodecContext
	Value   PRSFrequencyHoppingConfiguration

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v PRSFrequencyHoppingConfigurationAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v PRSFrequencyHoppingConfigurationAPERValue) WithoutReplay() PRSFrequencyHoppingConfigurationAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// PRSMutingConfigurationAPERValue is the concrete APERValue[PRSMutingConfiguration].
type PRSMutingConfigurationAPERValue struct {
	context q5.BridgeCodecContext
	Value   PRSMutingConfiguration

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v PRSMutingConfigurationAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v PRSMutingConfigurationAPERValue) WithoutReplay() PRSMutingConfigurationAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// PosSIBSegmentsAPERValue is the concrete APERValue[PosSIBSegments].
type PosSIBSegmentsAPERValue struct {
	context q5.BridgeCodecContext
	Value   PosSIBSegments

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v PosSIBSegmentsAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v PosSIBSegmentsAPERValue) WithoutReplay() PosSIBSegmentsAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// PosSIBSegmentsElemAPERValue is the concrete APERValue[PosSIBSegmentsElem].
type PosSIBSegmentsElemAPERValue struct {
	context q5.BridgeCodecContext
	Value   PosSIBSegmentsElem

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v PosSIBSegmentsElemAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v PosSIBSegmentsElemAPERValue) WithoutReplay() PosSIBSegmentsElemAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// PrivateIEIDAPERValue is the concrete APERValue[PrivateIEID].
type PrivateIEIDAPERValue struct {
	context q5.BridgeCodecContext
	Value   PrivateIEID

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v PrivateIEIDAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v PrivateIEIDAPERValue) WithoutReplay() PrivateIEIDAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultUTRANItemPhysCellIDUTRANAPERValue is the concrete APERValue[ResultUTRANItemPhysCellIDUTRAN].
type ResultUTRANItemPhysCellIDUTRANAPERValue struct {
	context q5.BridgeCodecContext
	Value   ResultUTRANItemPhysCellIDUTRAN

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v ResultUTRANItemPhysCellIDUTRANAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v ResultUTRANItemPhysCellIDUTRANAPERValue) WithoutReplay() ResultUTRANItemPhysCellIDUTRANAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// PrivateIEID represents the ASN.1 CHOICE type PrivateIE-ID.
type PrivateIEID struct {
	replay             q4.Snapshot
	stream             q4.WireSpan
	withoutReplay      bool
	received           bool
	receivedBytes      q4.WireSpan
	Choice             int
	perPadding         q4.CompletePadding   `json:"-"`
	perOpenTypePadding q4.CompletePadding   `json:"-"`
	Local              *int64               `json:"Local,omitempty"`
	Global             *q7.ObjectIdentifier `json:"Global,omitempty"`
}

// MarshalAPER encodes PrivateIEID to APER format.
func (v *PrivateIEID) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *PrivateIEID) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) &&
		!v.withoutReplay {
		if ok, err := v.replay.ReplayTo(v.stream, bb); ok || err != nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.Choice < 1 {
		return q6.Errorf("%s choice %d must be positive", "PrivateIEID:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return q6.Errorf("choice index outside root")
	}
	if err := q4.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case q5.PrivateIEIDChoiceLocal:
		if v.Local == nil {
			return q6.Errorf("choice alternative local is nil")
		}
		if err := q4.EncodeIntegerAligned(bb, int64(*v.Local), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false); err != nil {
			return q6.Errorf("encoding local: %w", err)
		}
	case q5.PrivateIEIDChoiceGlobal:
		if v.Global == nil {
			return q6.Errorf("choice alternative global is nil")
		}
		if err := q4.EncodeObjectIdentifierAligned(bb, *v.Global); err != nil {
			return q6.Errorf("encoding global: %w", err)
		}
	default:
		return q6.Errorf("unknown PrivateIEID choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes PrivateIEID from APER format.
func (v *PrivateIEID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PrivateIEID with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PrivateIEID) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "PrivateIEID")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "PrivateIEID")
	}
	padding, err := q4.CaptureFinalBits(bb, "PrivateIEID")
	if err != nil {
		return q7.WrapDecodePath(err, "PrivateIEID")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *PrivateIEID) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PrivateIEID{}
	idx, err := q4.DecodeConstrainedWholeNumberAligned(bb, 0, 1)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return q6.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case q5.PrivateIEIDChoiceLocal:
		val_local, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false)
		if err != nil {
			return q7.WrapDecodePath(err, "Local")
		}
		if err := q4.ChargeValue(bb, val_local); err != nil {
			return err
		}
		v.Local = (*int64)(bb.OwnInt64(int64(val_local)))
	case q5.PrivateIEIDChoiceGlobal:
		val_global, err := q4.DecodeObjectIdentifierAligned(bb)
		if err != nil {
			return q7.WrapDecodePath(err, "Global")
		}
		tmp_global := val_global
		if err := q4.ChargeValue(bb, tmp_global); err != nil {
			return err
		}
		v.Global = &tmp_global
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PrivateIEID) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q9.BridgeReceivedFormAt(v.received, v.receivedBytes, "PrivateIEID", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PrivateIEID) WithoutReplay() PrivateIEID {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero PrivateIEID
	v.perPadding = zero.perPadding
	return v
}
func (v *PrivateIEID) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "PrivateIEID")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "PrivateIEID")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaPrivateIEID(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "PrivateIEID")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "PrivateIEID")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "PrivateIEID")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "PrivateIEID")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "PrivateIEID")
}
func (v *PrivateIEID) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *PrivateIEID) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *PrivateIEID) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaPrivateIEID(v, &s)
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
func (v *PrivateIEID) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *PrivateIEID) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *PrivateIEID) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "PrivateIEID")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded PrivateIEID
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaPrivateIEID(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = PrivateIEID{}
		return report, q4.OperationError(err, "PrivateIEID")
	}
	*v = decoded
	return report, q4.OperationError(nil, "PrivateIEID")
}

type PosSIBSegments = []PosSIBSegmentsElem

// PRSMutingConfiguration represents the ASN.1 CHOICE type PRSMutingConfiguration.
type PRSMutingConfiguration struct {
	knownOpenBytes           uint64
	replay                   q4.Snapshot
	stream                   q4.WireSpan
	withoutReplay            bool
	received                 bool
	receivedBytes            q4.WireSpan
	Choice                   int
	perPadding               q4.CompletePadding  `json:"-"`
	perOpenTypePadding       q4.CompletePadding  `json:"-"`
	UnknownExtension         *q4.ChoiceExtension `json:"UnknownExtension,omitempty"`
	Two                      *q7.BitString       `json:"Two,omitempty"`
	Four                     *q7.BitString       `json:"Four,omitempty"`
	Eight                    *q7.BitString       `json:"Eight,omitempty"`
	Sixteen                  *q7.BitString       `json:"Sixteen,omitempty"`
	ThirtyTwo                *q7.BitString       `json:"ThirtyTwo,omitempty"`
	SixtyFour                *q7.BitString       `json:"SixtyFour,omitempty"`
	OneHundredAndTwentyEight *q7.BitString       `json:"OneHundredAndTwentyEight,omitempty"`
	TwoHundredAndFiftySix    *q7.BitString       `json:"TwoHundredAndFiftySix,omitempty"`
	FiveHundredAndTwelve     *q7.BitString       `json:"FiveHundredAndTwelve,omitempty"`
	OneThousandAndTwentyFour *q7.BitString       `json:"OneThousandAndTwentyFour,omitempty"`
}

// PRSFrequencyHoppingConfiguration represents the ASN.1 type PRSFrequencyHoppingConfiguration (SEQUENCE).
type PRSFrequencyHoppingConfiguration struct {
	replay               q4.Snapshot
	stream               q4.WireSpan
	withoutReplay        bool
	received             bool
	receivedBytes        q4.WireSpan
	NoOfFreqHoppingBands q5.NumberOfFrequencyHoppingBands                        `asn1:"tag:0,context,implicit"`
	BandPositions        q5.PRSFrequencyHoppingConfigurationBandPositions        `asn1:"tag:1,context,implicit"`
	bandPositionsIndef   bool                                                    `asn1:"-" json:"-"`
	IEExtensions         q10.PRSFrequencyHoppingConfigurationItemIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef    bool                                                    `asn1:"-" json:"-"`
	extCount             int64                                                   `asn1:"-" json:"-"`
	extPresent           []bool                                                  `asn1:"-" json:"-"`
	extData              [][]byte                                                `asn1:"-" json:"-"`
	perPadding           q4.FinalPadding                                         `asn1:"-" json:"-"`
	perExtPadding        []q4.CompletePadding                                    `asn1:"-" json:"-"`
	extOrigin            []q4.OpaqueOrigin
	extWire              []q4.WireSpan
}

// RequestedSRSTransmissionCharacteristics represents the ASN.1 type RequestedSRSTransmissionCharacteristics (SEQUENCE).
type RequestedSRSTransmissionCharacteristics struct {
	replay                q4.Snapshot
	stream                q4.WireSpan
	withoutReplay         bool
	received              bool
	receivedBytes         q4.WireSpan
	NumberOfTransmissions *q11.Int             `asn1:"tag:0,context,implicit"`
	Bandwidth             *q11.Int             `asn1:"tag:1,context,implicit"`
	extCount              int64                `asn1:"-" json:"-"`
	extPresent            []bool               `asn1:"-" json:"-"`
	extData               [][]byte             `asn1:"-" json:"-"`
	perPadding            q4.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding         []q4.CompletePadding `asn1:"-" json:"-"`
	extOrigin             []q4.OpaqueOrigin
	extWire               []q4.WireSpan
}

// PosSIBSegmentsElem represents the ASN.1 type PosSIB-Segments-Elem (SEQUENCE).
type PosSIBSegmentsElem struct {
	replay                   q4.Snapshot
	stream                   q4.WireSpan
	withoutReplay            bool
	received                 bool
	receivedBytes            q4.WireSpan
	AssistanceDataSIBelement []byte                               `asn1:"tag:0,context,implicit"`
	IEExtensions             q10.PosSIBSegmentsExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef        bool                                 `asn1:"-" json:"-"`
	extCount                 int64                                `asn1:"-" json:"-"`
	extPresent               []bool                               `asn1:"-" json:"-"`
	extData                  [][]byte                             `asn1:"-" json:"-"`
	perPadding               q4.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding            []q4.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin                []q4.OpaqueOrigin
	extWire                  []q4.WireSpan
}

// ResultUTRANItemPhysCellIDUTRAN represents the ASN.1 CHOICE type ResultUTRAN-Item-physCellIDUTRAN.
type ResultUTRANItemPhysCellIDUTRAN struct {
	replay             q4.Snapshot
	stream             q4.WireSpan
	withoutReplay      bool
	received           bool
	receivedBytes      q4.WireSpan
	Choice             int
	perPadding         q4.CompletePadding   `json:"-"`
	perOpenTypePadding q4.CompletePadding   `json:"-"`
	PhysCellIDUTRAFDD  q5.PhysCellIDUTRAFDD `json:"PhysCellIDUTRAFDD,omitzero"`
	PhysCellIDUTRATDD  q5.PhysCellIDUTRATDD `json:"PhysCellIDUTRATDD,omitzero"`
}

// MarshalAPER encodes PRSMutingConfiguration to APER format.
func (v *PRSMutingConfiguration) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *PRSMutingConfiguration) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
			return q6.Errorf("%s known choice %d and unknown extension are both selected", "PRSMutingConfiguration:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return q6.Errorf("%s extension index %d must be non-negative", "PRSMutingConfiguration:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 6 {
			return q6.Errorf("%s extension index %d is known to this schema", "PRSMutingConfiguration:", v.UnknownExtension.Index())
		}
		if err := q4.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := q4.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index()); err != nil {
			return err
		}
		return v.UnknownExtension.EncodeTo(bb)
	}
	if v.Choice < 1 {
		return q6.Errorf("%s choice %d must be positive", "PRSMutingConfiguration:", v.Choice)
	}
	isExtension := v.Choice > 4
	if err := q4.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 4 {
			return q6.Errorf("extension choice index outside root")
		}
		if err := q4.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-4-1)); err != nil {
			return err
		}
		inner := q4.NewBudgetBuffer(bb.Budget())
		switch v.Choice {
		case q5.PRSMutingConfigurationChoiceThirtyTwo:
			if v.ThirtyTwo == nil {
				return q6.Errorf("choice alternative thirty-two is nil")
			}
			if err := q4.EncodeBitStringAligned(inner, v.ThirtyTwo.Bytes, v.ThirtyTwo.BitLength, 32, 32, true); err != nil {
				return q6.Errorf("encoding thirty-two: %w", err)
			}
		case q5.PRSMutingConfigurationChoiceSixtyFour:
			if v.SixtyFour == nil {
				return q6.Errorf("choice alternative sixty-four is nil")
			}
			if err := q4.EncodeBitStringAligned(inner, v.SixtyFour.Bytes, v.SixtyFour.BitLength, 64, 64, true); err != nil {
				return q6.Errorf("encoding sixty-four: %w", err)
			}
		case q5.PRSMutingConfigurationChoiceOneHundredAndTwentyEight:
			if v.OneHundredAndTwentyEight == nil {
				return q6.Errorf("choice alternative one-hundred-and-twenty-eight is nil")
			}
			if err := q4.EncodeBitStringAligned(inner, v.OneHundredAndTwentyEight.Bytes, v.OneHundredAndTwentyEight.BitLength, 128, 128, true); err != nil {
				return q6.Errorf("encoding one-hundred-and-twenty-eight: %w", err)
			}
		case q5.PRSMutingConfigurationChoiceTwoHundredAndFiftySix:
			if v.TwoHundredAndFiftySix == nil {
				return q6.Errorf("choice alternative two-hundred-and-fifty-six is nil")
			}
			if err := q4.EncodeBitStringAligned(inner, v.TwoHundredAndFiftySix.Bytes, v.TwoHundredAndFiftySix.BitLength, 256, 256, true); err != nil {
				return q6.Errorf("encoding two-hundred-and-fifty-six: %w", err)
			}
		case q5.PRSMutingConfigurationChoiceFiveHundredAndTwelve:
			if v.FiveHundredAndTwelve == nil {
				return q6.Errorf("choice alternative five-hundred-and-twelve is nil")
			}
			if err := q4.EncodeBitStringAligned(inner, v.FiveHundredAndTwelve.Bytes, v.FiveHundredAndTwelve.BitLength, 512, 512, true); err != nil {
				return q6.Errorf("encoding five-hundred-and-twelve: %w", err)
			}
		case q5.PRSMutingConfigurationChoiceOneThousandAndTwentyFour:
			if v.OneThousandAndTwentyFour == nil {
				return q6.Errorf("choice alternative one-thousand-and-twenty-four is nil")
			}
			if err := q4.EncodeBitStringAligned(inner, v.OneThousandAndTwentyFour.Bytes, v.OneThousandAndTwentyFour.BitLength, 1024, 1024, true); err != nil {
				return q6.Errorf("encoding one-thousand-and-twenty-four: %w", err)
			}
		default:
			return q6.Errorf("unknown PRSMutingConfiguration extension choice %d", v.Choice)
		}
		openBytes, err := inner.CompleteBytesWithPadding(v.perOpenTypePadding)
		if err != nil {
			return err
		}
		if err := q4.EncodeOpenTypeAligned(bb, openBytes); err != nil {
			return err
		}
		return nil
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return q6.Errorf("choice index outside root")
	}
	if err := q4.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 3); err != nil {
		return err
	}
	switch v.Choice {
	case q5.PRSMutingConfigurationChoiceTwo:
		if v.Two == nil {
			return q6.Errorf("choice alternative two is nil")
		}
		if err := q4.EncodeBitStringAligned(bb, v.Two.Bytes, v.Two.BitLength, 2, 2, true); err != nil {
			return q6.Errorf("encoding two: %w", err)
		}
	case q5.PRSMutingConfigurationChoiceFour:
		if v.Four == nil {
			return q6.Errorf("choice alternative four is nil")
		}
		if err := q4.EncodeBitStringAligned(bb, v.Four.Bytes, v.Four.BitLength, 4, 4, true); err != nil {
			return q6.Errorf("encoding four: %w", err)
		}
	case q5.PRSMutingConfigurationChoiceEight:
		if v.Eight == nil {
			return q6.Errorf("choice alternative eight is nil")
		}
		if err := q4.EncodeBitStringAligned(bb, v.Eight.Bytes, v.Eight.BitLength, 8, 8, true); err != nil {
			return q6.Errorf("encoding eight: %w", err)
		}
	case q5.PRSMutingConfigurationChoiceSixteen:
		if v.Sixteen == nil {
			return q6.Errorf("choice alternative sixteen is nil")
		}
		if err := q4.EncodeBitStringAligned(bb, v.Sixteen.Bytes, v.Sixteen.BitLength, 16, 16, true); err != nil {
			return q6.Errorf("encoding sixteen: %w", err)
		}
	default:
		return q6.Errorf("unknown PRSMutingConfiguration choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes PRSMutingConfiguration from APER format.
func (v *PRSMutingConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PRSMutingConfiguration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PRSMutingConfiguration) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "PRSMutingConfiguration")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "PRSMutingConfiguration")
	}
	padding, err := q4.CaptureFinalBits(bb, "PRSMutingConfiguration")
	if err != nil {
		return q7.WrapDecodePath(err, "PRSMutingConfiguration")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *PRSMutingConfiguration) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PRSMutingConfiguration{}
	isExtension, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := q4.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return q7.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := q4.DecodeChoiceExtensionAligned(bb, extIdx, 6)
		if extIdx < 6 {
			v.knownOpenBytes = max(v.knownOpenBytes, openExtension.ContentLength())
		}
		if err != nil {
			return q7.WrapDecodePath(err, "UnknownExtension")
		}
		if extIdx >= 6 {
			v.UnknownExtension = &openExtension
			v.stream = bb.CaptureWireSpan(replayStart)
			v.
				stream.RecordUsage(replayUsage,

				bb)

			return nil
		}
		inner := openExtension.ChildDecodeBuffer(bb)
		if err := inner.EnterOpenType(); err != nil {
			return err
		}
		defer inner.LeaveOpenType()
		// arithmetic pattern APER_CHOICE_EXT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:206
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(4) {
			return q6.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 4 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case q5.PRSMutingConfigurationChoiceThirtyTwo:
			extensionPath = "ThirtyTwo"
			bsBytes_thirtytwo, bsBitLen_thirtytwo, err := q4.DecodeBitStringAligned(inner, 32, 32, true)
			if err != nil {
				return q7.WrapDecodePath(err, "ThirtyTwo")
			}
			tmp_thirtytwo := q7.BitString{Bytes: bsBytes_thirtytwo, BitLength: bsBitLen_thirtytwo}
			if err := q4.ChargeValue(inner, tmp_thirtytwo); err != nil {
				return err
			}
			v.ThirtyTwo = &tmp_thirtytwo
		case q5.PRSMutingConfigurationChoiceSixtyFour:
			extensionPath = "SixtyFour"
			bsBytes_sixtyfour, bsBitLen_sixtyfour, err := q4.DecodeBitStringAligned(inner, 64, 64, true)
			if err != nil {
				return q7.WrapDecodePath(err, "SixtyFour")
			}
			tmp_sixtyfour := q7.BitString{Bytes: bsBytes_sixtyfour, BitLength: bsBitLen_sixtyfour}
			if err := q4.ChargeValue(inner, tmp_sixtyfour); err != nil {
				return err
			}
			v.SixtyFour = &tmp_sixtyfour
		case q5.PRSMutingConfigurationChoiceOneHundredAndTwentyEight:
			extensionPath = "OneHundredAndTwentyEight"
			bsBytes_onehundredandtwentyeight, bsBitLen_onehundredandtwentyeight, err := q4.DecodeBitStringAligned(inner, 128, 128, true)
			if err != nil {
				return q7.WrapDecodePath(err, "OneHundredAndTwentyEight")
			}
			tmp_onehundredandtwentyeight := q7.BitString{Bytes: bsBytes_onehundredandtwentyeight, BitLength: bsBitLen_onehundredandtwentyeight}
			if err := q4.ChargeValue(inner, tmp_onehundredandtwentyeight); err != nil {
				return err
			}
			v.OneHundredAndTwentyEight = &tmp_onehundredandtwentyeight
		case q5.PRSMutingConfigurationChoiceTwoHundredAndFiftySix:
			extensionPath = "TwoHundredAndFiftySix"
			bsBytes_twohundredandfiftysix, bsBitLen_twohundredandfiftysix, err := q4.DecodeBitStringAligned(inner, 256, 256, true)
			if err != nil {
				return q7.WrapDecodePath(err, "TwoHundredAndFiftySix")
			}
			tmp_twohundredandfiftysix := q7.BitString{Bytes: bsBytes_twohundredandfiftysix, BitLength: bsBitLen_twohundredandfiftysix}
			if err := q4.ChargeValue(inner, tmp_twohundredandfiftysix); err != nil {
				return err
			}
			v.TwoHundredAndFiftySix = &tmp_twohundredandfiftysix
		case q5.PRSMutingConfigurationChoiceFiveHundredAndTwelve:
			extensionPath = "FiveHundredAndTwelve"
			bsBytes_fivehundredandtwelve, bsBitLen_fivehundredandtwelve, err := q4.DecodeBitStringAligned(inner, 512, 512, true)
			if err != nil {
				return q7.WrapDecodePath(err, "FiveHundredAndTwelve")
			}
			tmp_fivehundredandtwelve := q7.BitString{Bytes: bsBytes_fivehundredandtwelve, BitLength: bsBitLen_fivehundredandtwelve}
			if err := q4.ChargeValue(inner, tmp_fivehundredandtwelve); err != nil {
				return err
			}
			v.FiveHundredAndTwelve = &tmp_fivehundredandtwelve
		case q5.PRSMutingConfigurationChoiceOneThousandAndTwentyFour:
			extensionPath = "OneThousandAndTwentyFour"
			bsBytes_onethousandandtwentyfour, bsBitLen_onethousandandtwentyfour, err := q4.DecodeBitStringAligned(inner, 1024, 1024, true)
			if err != nil {
				return q7.WrapDecodePath(err, "OneThousandAndTwentyFour")
			}
			tmp_onethousandandtwentyfour := q7.BitString{Bytes: bsBytes_onethousandandtwentyfour, BitLength: bsBitLen_onethousandandtwentyfour}
			if err := q4.ChargeValue(inner, tmp_onethousandandtwentyfour); err != nil {
				return err
			}
			v.OneThousandAndTwentyFour = &tmp_onethousandandtwentyfour
		}
		padding, err := q4.CaptureOpenTypePadding(inner)
		if err != nil {
			return q7.WrapDecodePath(err, extensionPath)
		}
		v.perOpenTypePadding = padding
		v.stream = bb.CaptureWireSpan(replayStart)
		v.
			stream.RecordUsage(replayUsage,

			bb)

		return nil
	}
	idx, err := q4.DecodeConstrainedWholeNumberAligned(bb, 0, 3)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return q6.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case q5.PRSMutingConfigurationChoiceTwo:
		bsBytes_two, bsBitLen_two, err := q4.DecodeBitStringAligned(bb, 2, 2, true)
		if err != nil {
			return q7.WrapDecodePath(err, "Two")
		}
		tmp_two := q7.BitString{Bytes: bsBytes_two, BitLength: bsBitLen_two}
		if err := q4.ChargeValue(bb, tmp_two); err != nil {
			return err
		}
		v.Two = &tmp_two
	case q5.PRSMutingConfigurationChoiceFour:
		bsBytes_four, bsBitLen_four, err := q4.DecodeBitStringAligned(bb, 4, 4, true)
		if err != nil {
			return q7.WrapDecodePath(err, "Four")
		}
		tmp_four := q7.BitString{Bytes: bsBytes_four, BitLength: bsBitLen_four}
		if err := q4.ChargeValue(bb, tmp_four); err != nil {
			return err
		}
		v.Four = &tmp_four
	case q5.PRSMutingConfigurationChoiceEight:
		bsBytes_eight, bsBitLen_eight, err := q4.DecodeBitStringAligned(bb, 8, 8, true)
		if err != nil {
			return q7.WrapDecodePath(err, "Eight")
		}
		tmp_eight := q7.BitString{Bytes: bsBytes_eight, BitLength: bsBitLen_eight}
		if err := q4.ChargeValue(bb, tmp_eight); err != nil {
			return err
		}
		v.Eight = &tmp_eight
	case q5.PRSMutingConfigurationChoiceSixteen:
		bsBytes_sixteen, bsBitLen_sixteen, err := q4.DecodeBitStringAligned(bb, 16, 16, true)
		if err != nil {
			return q7.WrapDecodePath(err, "Sixteen")
		}
		tmp_sixteen := q7.BitString{Bytes: bsBytes_sixteen, BitLength: bsBitLen_sixteen}
		if err := q4.ChargeValue(bb, tmp_sixteen); err != nil {
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

// MarshalAPER encodes PRSFrequencyHoppingConfiguration to APER format.
func (v *PRSFrequencyHoppingConfiguration) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PRSFrequencyHoppingConfiguration) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.NoOfFreqHoppingBands), 2, true); err != nil {
		return q6.Errorf("encoding noOfFreqHoppingBands: %w", err)
	}
	if err := q4.EncodeCollection(bb, int64(len(v.BandPositions)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 7, HasUpper: true}, true, func(fragmentOffset_bandpositions, fragmentLength_bandpositions int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_bandpositions < 0 || fragmentOffset_bandpositions > int64(len(v.BandPositions)) || fragmentLength_bandpositions < 0 || fragmentLength_bandpositions > int64(len(v.BandPositions[fragmentOffset_bandpositions:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.BandPositions[fragmentOffset_bandpositions : fragmentOffset_bandpositions+fragmentLength_bandpositions] {
			if err := q4.EncodeIntegerBigBoundsAligned(bb, elem, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound7, true); err != nil {
				return q6.Errorf("encoding bandPositions element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding bandPositions: %w", err)
	}
	if v.IEExtensions != nil {
		if err := q4.EncodeCollection(bb, int64(len(v.IEExtensions)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q10.BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes PRSFrequencyHoppingConfiguration from APER format.
func (v *PRSFrequencyHoppingConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PRSFrequencyHoppingConfiguration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PRSFrequencyHoppingConfiguration) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "PRSFrequencyHoppingConfiguration")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "PRSFrequencyHoppingConfiguration")
	}
	padding, err := q4.CaptureFinalBits(bb, "PRSFrequencyHoppingConfiguration")
	if err != nil {
		return q7.WrapDecodePath(err, "PRSFrequencyHoppingConfiguration")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PRSFrequencyHoppingConfiguration) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PRSFrequencyHoppingConfiguration{}
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
	val_nooffreqhoppingbands, err := q4.DecodeEnumeratedAligned(bb, 2, true, q4.EnumerationSource{KnownExtensions: 0, Path: "NoOfFreqHoppingBands"})
	if err != nil {
		return q7.WrapDecodePath(err, "NoOfFreqHoppingBands")
	}
	v.NoOfFreqHoppingBands = q5.NumberOfFrequencyHoppingBands(val_nooffreqhoppingbands)
	v.BandPositions = make(q5.PRSFrequencyHoppingConfigurationBandPositions, 0)
	_, errCollection_bandpositions := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 7, HasUpper: true}, true, func(fragmentOffset_bandpositions, fragmentLength_bandpositions int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_2: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1136
		if fragmentOffset_bandpositions < 0 || fragmentLength_bandpositions < 0 || fragmentLength_bandpositions > int64(^uint(0)>>1) || fragmentOffset_bandpositions > int64(^uint(0)>>1)-fragmentLength_bandpositions {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_bandpositions; i++ {
			val, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound7, true)
			if err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("BandPositions[%d]", fragmentOffset_bandpositions+i))
			}
			if next, err := q4.AppendValues(bb, v.BandPositions, val); err != nil {
				return err
			} else {
				v.BandPositions = next
			}
		}
		return nil
	})
	if errCollection_bandpositions != nil {
		return q7.WrapDecodePath(errCollection_bandpositions, "BandPositions")
	}
	if opt_ieextensions {
		tmp_ieextensions := make(q10.PRSFrequencyHoppingConfigurationItemIEsExtContainer, 0)
		_, errCollection_ieextensions := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q10.PRSFrequencyHoppingConfigurationItemIEsExtField
				if err := q10.BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes RequestedSRSTransmissionCharacteristics to APER format.
func (v *RequestedSRSTransmissionCharacteristics) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *RequestedSRSTransmissionCharacteristics) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if err := q4.EncodeIntegerBigBoundsAligned(bb, v.NumberOfTransmissions, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound16, true); err != nil {
		return q6.Errorf("encoding numberOfTransmissions: %w", err)
	}
	if err := q4.EncodeIntegerBigBoundsAligned(bb, v.Bandwidth, q5.BridgeAsn1IntegerBound2, q5.BridgeAsn1IntegerBound3, true); err != nil {
		return q6.Errorf("encoding bandwidth: %w", err)
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

// UnmarshalAPER decodes RequestedSRSTransmissionCharacteristics from APER format.
func (v *RequestedSRSTransmissionCharacteristics) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes RequestedSRSTransmissionCharacteristics with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *RequestedSRSTransmissionCharacteristics) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "RequestedSRSTransmissionCharacteristics")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "RequestedSRSTransmissionCharacteristics")
	}
	padding, err := q4.CaptureFinalBits(bb, "RequestedSRSTransmissionCharacteristics")
	if err != nil {
		return q7.WrapDecodePath(err, "RequestedSRSTransmissionCharacteristics")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *RequestedSRSTransmissionCharacteristics) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RequestedSRSTransmissionCharacteristics{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_numberoftransmissions, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound16, true)
	if err != nil {
		return q7.WrapDecodePath(err, "NumberOfTransmissions")
	}
	v.NumberOfTransmissions = val_numberoftransmissions
	val_bandwidth, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound2, q5.BridgeAsn1IntegerBound3, true)
	if err != nil {
		return q7.WrapDecodePath(err, "Bandwidth")
	}
	v.Bandwidth = val_bandwidth
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

// MarshalAPER encodes PosSIBSegmentsElem to APER format.
func (v *PosSIBSegmentsElem) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PosSIBSegmentsElem) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if err := q4.EncodeOctetStringAligned(bb, v.AssistanceDataSIBelement, 0, 0, false); err != nil {
		return q6.Errorf("encoding assistanceDataSIBelement: %w", err)
	}
	if v.IEExtensions != nil {
		if err := q4.EncodeCollection(bb, int64(len(v.IEExtensions)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q10.BridgePosSIBSegmentsExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes PosSIBSegmentsElem from APER format.
func (v *PosSIBSegmentsElem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PosSIBSegmentsElem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PosSIBSegmentsElem) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "PosSIBSegmentsElem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "PosSIBSegmentsElem")
	}
	padding, err := q4.CaptureFinalBits(bb, "PosSIBSegmentsElem")
	if err != nil {
		return q7.WrapDecodePath(err, "PosSIBSegmentsElem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PosSIBSegmentsElem) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PosSIBSegmentsElem{}
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
	val_assistancedatasibelement, err := q4.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return q7.WrapDecodePath(err, "AssistanceDataSIBelement")
	}
	v.AssistanceDataSIBelement = val_assistancedatasibelement
	if opt_ieextensions {
		tmp_ieextensions := make(q10.PosSIBSegmentsExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q10.PosSIBSegmentsExtIEsExtField
				if err := q10.BridgePosSIBSegmentsExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ResultUTRANItemPhysCellIDUTRAN to APER format.
func (v *ResultUTRANItemPhysCellIDUTRAN) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *ResultUTRANItemPhysCellIDUTRAN) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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

	if v.Choice < 1 {
		return q6.Errorf("%s choice %d must be positive", "ResultUTRANItemPhysCellIDUTRAN:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return q6.Errorf("choice index outside root")
	}
	if err := q4.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case q5.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRAFDD:
		if err := q4.EncodeIntegerBigBoundsAligned(bb, v.PhysCellIDUTRAFDD, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound18, true); err != nil {
			return q6.Errorf("encoding physCellIDUTRA-FDD: %w", err)
		}
	case q5.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRATDD:
		if err := q4.EncodeIntegerBigBoundsAligned(bb, v.PhysCellIDUTRATDD, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound5, true); err != nil {
			return q6.Errorf("encoding physCellIDUTRA-TDD: %w", err)
		}
	default:
		return q6.Errorf("unknown ResultUTRANItemPhysCellIDUTRAN choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes ResultUTRANItemPhysCellIDUTRAN from APER format.
func (v *ResultUTRANItemPhysCellIDUTRAN) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResultUTRANItemPhysCellIDUTRAN with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResultUTRANItemPhysCellIDUTRAN) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "ResultUTRANItemPhysCellIDUTRAN")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "ResultUTRANItemPhysCellIDUTRAN")
	}
	padding, err := q4.CaptureFinalBits(bb, "ResultUTRANItemPhysCellIDUTRAN")
	if err != nil {
		return q7.WrapDecodePath(err, "ResultUTRANItemPhysCellIDUTRAN")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *ResultUTRANItemPhysCellIDUTRAN) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultUTRANItemPhysCellIDUTRAN{}
	idx, err := q4.DecodeConstrainedWholeNumberAligned(bb, 0, 1)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return q6.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case q5.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRAFDD:
		val_physcellidutrafdd, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound18, true)
		if err != nil {
			return q7.WrapDecodePath(err, "PhysCellIDUTRAFDD")
		}
		v.PhysCellIDUTRAFDD = val_physcellidutrafdd
	case q5.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRATDD:
		val_physcellidutratdd, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound5, true)
		if err != nil {
			return q7.WrapDecodePath(err, "PhysCellIDUTRATDD")
		}
		v.PhysCellIDUTRATDD = val_physcellidutratdd
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PRSFrequencyHoppingConfiguration) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q9.BridgeReceivedFormAt(v.received, v.receivedBytes, "PRSFrequencyHoppingConfiguration", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PRSFrequencyHoppingConfiguration) WithoutReplay() PRSFrequencyHoppingConfiguration {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero PRSFrequencyHoppingConfiguration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PRSMutingConfiguration) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q9.BridgeReceivedFormAt(v.received, v.receivedBytes, "PRSMutingConfiguration", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PRSMutingConfiguration) WithoutReplay() PRSMutingConfiguration {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero PRSMutingConfiguration
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PosSIBSegmentsElem) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q9.BridgeReceivedFormAt(v.received, v.receivedBytes, "PosSIBSegmentsElem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PosSIBSegmentsElem) WithoutReplay() PosSIBSegmentsElem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero PosSIBSegmentsElem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *RequestedSRSTransmissionCharacteristics) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q9.BridgeReceivedFormAt(v.received, v.receivedBytes, "RequestedSRSTransmissionCharacteristics", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v RequestedSRSTransmissionCharacteristics) WithoutReplay() RequestedSRSTransmissionCharacteristics {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero RequestedSRSTransmissionCharacteristics
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultUTRANItemPhysCellIDUTRAN) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q9.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultUTRANItemPhysCellIDUTRAN", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultUTRANItemPhysCellIDUTRAN) WithoutReplay() ResultUTRANItemPhysCellIDUTRAN {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero ResultUTRANItemPhysCellIDUTRAN
	v.perPadding = zero.perPadding
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *PRSFrequencyHoppingConfiguration) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PRSFrequencyHoppingConfiguration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("PRSFrequencyHoppingConfiguration.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("PRSFrequencyHoppingConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PRSFrequencyHoppingConfiguration) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("PRSFrequencyHoppingConfiguration.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("PRSFrequencyHoppingConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *PosSIBSegmentsElem) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PosSIBSegmentsElem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("PosSIBSegmentsElem.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("PosSIBSegmentsElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PosSIBSegmentsElem) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("PosSIBSegmentsElem.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("PosSIBSegmentsElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *RequestedSRSTransmissionCharacteristics) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *RequestedSRSTransmissionCharacteristics) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("RequestedSRSTransmissionCharacteristics.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("RequestedSRSTransmissionCharacteristics.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *RequestedSRSTransmissionCharacteristics) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("RequestedSRSTransmissionCharacteristics.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("RequestedSRSTransmissionCharacteristics.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *PRSFrequencyHoppingConfiguration) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "PRSFrequencyHoppingConfiguration")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "PRSFrequencyHoppingConfiguration")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaPRSFrequencyHoppingConfiguration(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "PRSFrequencyHoppingConfiguration")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "PRSFrequencyHoppingConfiguration")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "PRSFrequencyHoppingConfiguration")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "PRSFrequencyHoppingConfiguration")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "PRSFrequencyHoppingConfiguration")
}
func (v *PRSFrequencyHoppingConfiguration) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *PRSFrequencyHoppingConfiguration) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *PRSFrequencyHoppingConfiguration) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaPRSFrequencyHoppingConfiguration(v, &s)
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
func (v *PRSFrequencyHoppingConfiguration) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *PRSFrequencyHoppingConfiguration) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *PRSMutingConfiguration) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "PRSMutingConfiguration")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "PRSMutingConfiguration")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaPRSMutingConfiguration(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "PRSMutingConfiguration")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "PRSMutingConfiguration")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "PRSMutingConfiguration")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "PRSMutingConfiguration")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "PRSMutingConfiguration")
}
func (v *PRSMutingConfiguration) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *PRSMutingConfiguration) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *PRSMutingConfiguration) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaPRSMutingConfiguration(v, &s)
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
func (v *PRSMutingConfiguration) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *PRSMutingConfiguration) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
	out, err := bb.CompleteBytesWithPadding(value.perPadding)
	if err != nil {
		return nil, err
	}
	if err := bb.CheckOutput(uint64(len(out))); err != nil {
		return nil, err
	}
	return out, nil
}
func (v *PosSIBSegmentsElem) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "PosSIBSegmentsElem")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "PosSIBSegmentsElem")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaPosSIBSegmentsElem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "PosSIBSegmentsElem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "PosSIBSegmentsElem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "PosSIBSegmentsElem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "PosSIBSegmentsElem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "PosSIBSegmentsElem")
}
func (v *PosSIBSegmentsElem) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *PosSIBSegmentsElem) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *PosSIBSegmentsElem) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaPosSIBSegmentsElem(v, &s)
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
func (v *PosSIBSegmentsElem) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *PosSIBSegmentsElem) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *RequestedSRSTransmissionCharacteristics) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "RequestedSRSTransmissionCharacteristics")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "RequestedSRSTransmissionCharacteristics")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaRequestedSRSTransmissionCharacteristics(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "RequestedSRSTransmissionCharacteristics")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "RequestedSRSTransmissionCharacteristics")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "RequestedSRSTransmissionCharacteristics")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "RequestedSRSTransmissionCharacteristics")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "RequestedSRSTransmissionCharacteristics")
}
func (v *RequestedSRSTransmissionCharacteristics) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *RequestedSRSTransmissionCharacteristics) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *RequestedSRSTransmissionCharacteristics) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaRequestedSRSTransmissionCharacteristics(v, &s)
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
func (v *RequestedSRSTransmissionCharacteristics) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *RequestedSRSTransmissionCharacteristics) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ResultUTRANItemPhysCellIDUTRAN) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "ResultUTRANItemPhysCellIDUTRAN")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "ResultUTRANItemPhysCellIDUTRAN")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaResultUTRANItemPhysCellIDUTRAN(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "ResultUTRANItemPhysCellIDUTRAN")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "ResultUTRANItemPhysCellIDUTRAN")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "ResultUTRANItemPhysCellIDUTRAN")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "ResultUTRANItemPhysCellIDUTRAN")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "ResultUTRANItemPhysCellIDUTRAN")
}
func (v *ResultUTRANItemPhysCellIDUTRAN) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultUTRANItemPhysCellIDUTRAN) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultUTRANItemPhysCellIDUTRAN) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaResultUTRANItemPhysCellIDUTRAN(v, &s)
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
func (v *ResultUTRANItemPhysCellIDUTRAN) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultUTRANItemPhysCellIDUTRAN) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *PRSFrequencyHoppingConfiguration) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "PRSFrequencyHoppingConfiguration")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded PRSFrequencyHoppingConfiguration
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaPRSFrequencyHoppingConfiguration(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = PRSFrequencyHoppingConfiguration{}
		return report, q4.OperationError(err, "PRSFrequencyHoppingConfiguration")
	}
	*v = decoded
	return report, q4.OperationError(nil, "PRSFrequencyHoppingConfiguration")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *PRSMutingConfiguration) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "PRSMutingConfiguration")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded PRSMutingConfiguration
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaPRSMutingConfiguration(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = PRSMutingConfiguration{}
		return report, q4.OperationError(err, "PRSMutingConfiguration")
	}
	*v = decoded
	return report, q4.OperationError(nil, "PRSMutingConfiguration")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *PosSIBSegmentsElem) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "PosSIBSegmentsElem")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded PosSIBSegmentsElem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaPosSIBSegmentsElem(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = PosSIBSegmentsElem{}
		return report, q4.OperationError(err, "PosSIBSegmentsElem")
	}
	*v = decoded
	return report, q4.OperationError(nil, "PosSIBSegmentsElem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *RequestedSRSTransmissionCharacteristics) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "RequestedSRSTransmissionCharacteristics")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded RequestedSRSTransmissionCharacteristics
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaRequestedSRSTransmissionCharacteristics(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = RequestedSRSTransmissionCharacteristics{}
		return report, q4.OperationError(err, "RequestedSRSTransmissionCharacteristics")
	}
	*v = decoded
	return report, q4.OperationError(nil, "RequestedSRSTransmissionCharacteristics")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultUTRANItemPhysCellIDUTRAN) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "ResultUTRANItemPhysCellIDUTRAN")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded ResultUTRANItemPhysCellIDUTRAN
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultUTRANItemPhysCellIDUTRAN(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = ResultUTRANItemPhysCellIDUTRAN{}
		return report, q4.OperationError(err, "ResultUTRANItemPhysCellIDUTRAN")
	}
	*v = decoded
	return report, q4.OperationError(nil, "ResultUTRANItemPhysCellIDUTRAN")
}

// NewPRSMutingConfigurationUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewPRSMutingConfigurationUnknownExtension(index uint64, contents []byte, options ...q4.BuildOption) (PRSMutingConfiguration, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return PRSMutingConfiguration{}, q4.OperationError(err, "PRSMutingConfigurationUnknownExtension")
	}
	extension, err := q4.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return PRSMutingConfiguration{}, q4.OperationError(err, "PRSMutingConfigurationUnknownExtension")
	}
	value := PRSMutingConfiguration{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return PRSMutingConfiguration{}, q4.OperationError(err, "PRSMutingConfigurationUnknownExtension")
	}
	return value, q4.OperationError(nil, "PRSMutingConfigurationUnknownExtension")
}
func BridgeCaptureLPPaPRSFrequencyHoppingConfiguration(v *PRSFrequencyHoppingConfiguration, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q5.BridgeCaptureLPPaNumberOfFrequencyHoppingBands(&v.NoOfFreqHoppingBands, s)
	q5.BridgeCaptureLPPaPRSFrequencyHoppingConfigurationBandPositions(&v.BandPositions, s)
	s.Bool(v.IEExtensions == nil)
	q9.BridgePRSFrequencyHoppingConfigurationItemIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaPRSFrequencyHoppingConfiguration(v *PRSFrequencyHoppingConfiguration, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q12.BridgeCompareLPPaNumberOfFrequencyHoppingBands(&v.NoOfFreqHoppingBands, s)
	q12.BridgeCompareLPPaPRSFrequencyHoppingConfigurationBandPositions(&v.BandPositions, s)
	s.Bool(v.IEExtensions == nil)
	q9.BridgePRSFrequencyHoppingConfigurationItemIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaPRSMutingConfiguration(v *PRSMutingConfiguration, s *q4.SemanticCapture) {
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
	case q5.PRSMutingConfigurationChoiceTwo:
		{
			f := s.Begin()
			s.Bool(v.Two == nil)
			if v.Two != nil {
				s.BitString((*v.Two).Bytes, (*v.Two).BitLength)
			}
			s.End(f, nil, false)
		}
	case q5.PRSMutingConfigurationChoiceFour:
		{
			f := s.Begin()
			s.Bool(v.Four == nil)
			if v.Four != nil {
				s.BitString((*v.Four).Bytes, (*v.Four).BitLength)
			}
			s.End(f, nil, false)
		}
	case q5.PRSMutingConfigurationChoiceEight:
		{
			f := s.Begin()
			s.Bool(v.Eight == nil)
			if v.Eight != nil {
				s.BitString((*v.Eight).Bytes, (*v.Eight).BitLength)
			}
			s.End(f, nil, false)
		}
	case q5.PRSMutingConfigurationChoiceSixteen:
		{
			f := s.Begin()
			s.Bool(v.Sixteen == nil)
			if v.Sixteen != nil {
				s.BitString((*v.Sixteen).Bytes, (*v.Sixteen).BitLength)
			}
			s.End(f, nil, false)
		}
	case q5.PRSMutingConfigurationChoiceThirtyTwo:
		{
			f := s.Begin()
			s.Bool(v.ThirtyTwo == nil)
			if v.ThirtyTwo != nil {
				s.BitString((*v.ThirtyTwo).Bytes, (*v.ThirtyTwo).BitLength)
			}
			s.End(f, nil, false)
		}
	case q5.PRSMutingConfigurationChoiceSixtyFour:
		{
			f := s.Begin()
			s.Bool(v.SixtyFour == nil)
			if v.SixtyFour != nil {
				s.BitString((*v.SixtyFour).Bytes, (*v.SixtyFour).BitLength)
			}
			s.End(f, nil, false)
		}
	case q5.PRSMutingConfigurationChoiceOneHundredAndTwentyEight:
		{
			f := s.Begin()
			s.Bool(v.OneHundredAndTwentyEight == nil)
			if v.OneHundredAndTwentyEight != nil {
				s.BitString((*v.OneHundredAndTwentyEight).Bytes, (*v.OneHundredAndTwentyEight).BitLength)
			}
			s.End(f, nil, false)
		}
	case q5.PRSMutingConfigurationChoiceTwoHundredAndFiftySix:
		{
			f := s.Begin()
			s.Bool(v.TwoHundredAndFiftySix == nil)
			if v.TwoHundredAndFiftySix != nil {
				s.BitString((*v.TwoHundredAndFiftySix).Bytes, (*v.TwoHundredAndFiftySix).BitLength)
			}
			s.End(f, nil, false)
		}
	case q5.PRSMutingConfigurationChoiceFiveHundredAndTwelve:
		{
			f := s.Begin()
			s.Bool(v.FiveHundredAndTwelve == nil)
			if v.FiveHundredAndTwelve != nil {
				s.BitString((*v.FiveHundredAndTwelve).Bytes, (*v.FiveHundredAndTwelve).BitLength)
			}
			s.End(f, nil, false)
		}
	case q5.PRSMutingConfigurationChoiceOneThousandAndTwentyFour:
		{
			f := s.Begin()
			s.Bool(v.OneThousandAndTwentyFour == nil)
			if v.OneThousandAndTwentyFour != nil {
				s.BitString((*v.OneThousandAndTwentyFour).Bytes, (*v.OneThousandAndTwentyFour).BitLength)
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaPRSMutingConfiguration(v *PRSMutingConfiguration, s *q4.SemanticComparison) {
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
		s.End(f, q4.Snapshot{}, false)
	}
	switch v.Choice {
	case q5.PRSMutingConfigurationChoiceTwo:
		{
			f := s.Begin()
			s.Bool(v.Two == nil)
			if v.Two != nil {
				s.BitString((*v.Two).Bytes, (*v.Two).BitLength)
			}
			s.End(f, q4.Snapshot{}, false)
		}
	case q5.PRSMutingConfigurationChoiceFour:
		{
			f := s.Begin()
			s.Bool(v.Four == nil)
			if v.Four != nil {
				s.BitString((*v.Four).Bytes, (*v.Four).BitLength)
			}
			s.End(f, q4.Snapshot{}, false)
		}
	case q5.PRSMutingConfigurationChoiceEight:
		{
			f := s.Begin()
			s.Bool(v.Eight == nil)
			if v.Eight != nil {
				s.BitString((*v.Eight).Bytes, (*v.Eight).BitLength)
			}
			s.End(f, q4.Snapshot{}, false)
		}
	case q5.PRSMutingConfigurationChoiceSixteen:
		{
			f := s.Begin()
			s.Bool(v.Sixteen == nil)
			if v.Sixteen != nil {
				s.BitString((*v.Sixteen).Bytes, (*v.Sixteen).BitLength)
			}
			s.End(f, q4.Snapshot{}, false)
		}
	case q5.PRSMutingConfigurationChoiceThirtyTwo:
		{
			f := s.Begin()
			s.Bool(v.ThirtyTwo == nil)
			if v.ThirtyTwo != nil {
				s.BitString((*v.ThirtyTwo).Bytes, (*v.ThirtyTwo).BitLength)
			}
			s.End(f, q4.Snapshot{}, false)
		}
	case q5.PRSMutingConfigurationChoiceSixtyFour:
		{
			f := s.Begin()
			s.Bool(v.SixtyFour == nil)
			if v.SixtyFour != nil {
				s.BitString((*v.SixtyFour).Bytes, (*v.SixtyFour).BitLength)
			}
			s.End(f, q4.Snapshot{}, false)
		}
	case q5.PRSMutingConfigurationChoiceOneHundredAndTwentyEight:
		{
			f := s.Begin()
			s.Bool(v.OneHundredAndTwentyEight == nil)
			if v.OneHundredAndTwentyEight != nil {
				s.BitString((*v.OneHundredAndTwentyEight).Bytes, (*v.OneHundredAndTwentyEight).BitLength)
			}
			s.End(f, q4.Snapshot{}, false)
		}
	case q5.PRSMutingConfigurationChoiceTwoHundredAndFiftySix:
		{
			f := s.Begin()
			s.Bool(v.TwoHundredAndFiftySix == nil)
			if v.TwoHundredAndFiftySix != nil {
				s.BitString((*v.TwoHundredAndFiftySix).Bytes, (*v.TwoHundredAndFiftySix).BitLength)
			}
			s.End(f, q4.Snapshot{}, false)
		}
	case q5.PRSMutingConfigurationChoiceFiveHundredAndTwelve:
		{
			f := s.Begin()
			s.Bool(v.FiveHundredAndTwelve == nil)
			if v.FiveHundredAndTwelve != nil {
				s.BitString((*v.FiveHundredAndTwelve).Bytes, (*v.FiveHundredAndTwelve).BitLength)
			}
			s.End(f, q4.Snapshot{}, false)
		}
	case q5.PRSMutingConfigurationChoiceOneThousandAndTwentyFour:
		{
			f := s.Begin()
			s.Bool(v.OneThousandAndTwentyFour == nil)
			if v.OneThousandAndTwentyFour != nil {
				s.BitString((*v.OneThousandAndTwentyFour).Bytes, (*v.OneThousandAndTwentyFour).BitLength)
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaPosSIBSegmentsElem(v *PosSIBSegmentsElem, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s.Bytes(v.AssistanceDataSIBelement)
	s.Bool(v.IEExtensions == nil)
	q9.BridgePosSIBSegmentsExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaPosSIBSegmentsElem(v *PosSIBSegmentsElem, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

	s.Bytes(v.AssistanceDataSIBelement)
	s.Bool(v.IEExtensions == nil)
	q9.BridgePosSIBSegmentsExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaPrivateIEID(v *PrivateIEID, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s.Int(int64(v.Choice))
	switch v.Choice {
	case q5.PrivateIEIDChoiceLocal:
		{
			f := s.Begin()
			s.Bool(v.Local == nil)
			if v.Local != nil {
				s.Int(int64((*v.Local)))
			}
			s.End(f, nil, false)
		}
	case q5.PrivateIEIDChoiceGlobal:
		{
			f := s.Begin()
			s.Bool(v.Global == nil)
			if v.Global != nil {
				s.String((*v.Global).Encoded())
			}
			s.End(f, nil, false)
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaPrivateIEID(v *PrivateIEID, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

	s.Int(int64(v.Choice))
	switch v.Choice {
	case q5.PrivateIEIDChoiceLocal:
		{
			f := s.Begin()
			s.Bool(v.Local == nil)
			if v.Local != nil {
				s.Int(int64((*v.Local)))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	case q5.PrivateIEIDChoiceGlobal:
		{
			f := s.Begin()
			s.Bool(v.Global == nil)
			if v.Global != nil {
				s.String((*v.Global).Encoded())
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaPrivateMessageIEsValue(v *PrivateMessageIEsValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Int(int64(v.idChoice))
	s.Int(int64(v.idLocal))
	s.String(v.idGlobal)
	if v.valid {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, nil, false)
		}
	}
	s.Bool(v.valid)
	s.End(f, &v.replay, v.withoutReplay)
}
func (v PrivateMessageIEsValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v PrivateMessageIEsValue) captureFraming() uint64 {
	if v.opaque == nil {
		return 0
	}
	return v.opaque.ContentLength()
}
func (v PrivateMessageIEsValue) captureSemantics(s q4.SemanticCapture) PrivateMessageIEsValue {
	BridgeCaptureLPPaPrivateMessageIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaPrivateMessageIEsValue(v *PrivateMessageIEsValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Int(int64(v.idChoice))
	s.Int(int64(v.idLocal))
	s.String(v.idGlobal)
	if v.valid {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.Bool(v.valid)
	s.End(f, v.replay, v.withoutReplay)
}
func (v PrivateMessageIEsValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaPrivateMessageIEsValue(&v, &s)
	return s
}
func (v PrivateMessageIEsValue) WithoutReplay() PrivateMessageIEsValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCaptureLPPaRequestedSRSTransmissionCharacteristics(v *RequestedSRSTransmissionCharacteristics, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	{
		f := s.Begin()
		s.BigInt(v.NumberOfTransmissions)
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.BigInt(v.Bandwidth)
		s.End(f, nil, false)
	}
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaRequestedSRSTransmissionCharacteristics(v *RequestedSRSTransmissionCharacteristics, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

	{
		f := s.Begin()
		s.BigInt(v.NumberOfTransmissions)
		s.End(f, q4.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.BigInt(v.Bandwidth)
		s.End(f, q4.Snapshot{}, false)
	}
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultUTRANItemPhysCellIDUTRAN(v *ResultUTRANItemPhysCellIDUTRAN, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s.Int(int64(v.Choice))
	switch v.Choice {
	case q5.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRAFDD:
		q5.BridgeCaptureLPPaPhysCellIDUTRAFDD(&v.PhysCellIDUTRAFDD, s)
	case q5.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRATDD:
		q5.BridgeCaptureLPPaPhysCellIDUTRATDD(&v.PhysCellIDUTRATDD, s)
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultUTRANItemPhysCellIDUTRAN(v *ResultUTRANItemPhysCellIDUTRAN, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

	s.Int(int64(v.Choice))
	switch v.Choice {
	case q5.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRAFDD:
		q12.BridgeCompareLPPaPhysCellIDUTRAFDD(&v.PhysCellIDUTRAFDD, s)
	case q5.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRATDD:
		q12.BridgeCompareLPPaPhysCellIDUTRATDD(&v.PhysCellIDUTRATDD, s)
	}
	s.End(f, v.replay, v.withoutReplay)
}

type PrivateMessageIEsValue struct {
	withoutReplay bool
	replay        q4.Snapshot
	idChoice      int
	idLocal       int64
	idGlobal      string
	opaque        *q4.OpaqueOpenType
	valid         bool
}

// TS 36.455 V19.0.0 §9.3.8 binds the scalar or OID private identity.
func BridgePrivateValue(id PrivateIEID, raw *q4.OpaqueOpenType) PrivateMessageIEsValue {
	v := PrivateMessageIEsValue{idChoice: id.Choice, opaque: raw}
	switch id.Choice {
	case q5.PrivateIEIDChoiceLocal:
		if id.Local != nil {
			v.idLocal = *id.Local
			v.valid = true
		}
	case q5.PrivateIEIDChoiceGlobal:
		if id.Global != nil {
			v.idGlobal = id.Global.Encoded()
			v.valid = true
		}
	}
	return v
}
func (v PrivateMessageIEsValue) matchesID(id PrivateIEID, _ *q4.DecodeBudget) bool {
	if !v.valid || v.opaque == nil || v.idChoice != id.Choice {
		return false
	}
	switch id.Choice {
	case q5.PrivateIEIDChoiceLocal:
		return id.Local != nil && v.idLocal == *id.Local
	case q5.PrivateIEIDChoiceGlobal:
		return id.Global != nil && v.idGlobal == id.Global.Encoded()
	default:
		return false
	}
}
func (PrivateMessageIEsValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "PrivateMessage-IEs"}}
}
func (PrivateMessageIEsValue) decode(id PrivateIEID, raw q4.OpaqueOpenType) (PrivateMessageIEsValue, error) {
	if err := raw.Observe(q4.UnknownIE); err != nil {
		return PrivateMessageIEsValue{}, err
	}
	retained, err := raw.Retained()
	if err != nil {
		return PrivateMessageIEsValue{}, err
	}
	return BridgePrivateValue(id, retained), nil
}
func (v PrivateMessageIEsValue) encode() ([]byte, error) {
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v PrivateMessageIEsValue) encodeFresh(_ bool, budget *q4.DecodeBudget) ([]byte, error) {
	if !v.valid || v.opaque == nil {
		return nil, q6.Errorf("%s missing opaque value", "PrivateMessage-IEs:")
	}
	return v.opaque.EncodeBytes(budget)
}
func (v *PrivateMessageIEsValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.valid || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}

type PrivateMessageIETable struct{}

func PrivateMessageIEs() PrivateMessageIETable { return PrivateMessageIETable{} }
func (PrivateMessageIETable) NewOpaque(id PrivateIEID, criticality q5.Criticality, data []byte) (PrivateMessageIEsValuePrivateIEField, error) {
	budget, err := q4.BuildBudget()
	if err != nil {
		return PrivateMessageIEsValuePrivateIEField{}, q4.OperationError(err, "Opaque")
	}
	if _, err := id.marshalAPERBudget(budget, true); err != nil {
		return PrivateMessageIEsValuePrivateIEField{}, q4.OperationError(err, "Opaque")
	}
	if criticality < 0 || criticality > 2 {
		return PrivateMessageIEsValuePrivateIEField{}, q4.OperationError(q6.Errorf("invalid private IE criticality %d", criticality), "Opaque")
	}
	opaque, err := q4.BuildOpaqueOpenType(data, budget)
	if err != nil {
		return PrivateMessageIEsValuePrivateIEField{}, q4.OperationError(err, "Opaque")
	}
	retained, err := opaque.Retained(budget)
	if err != nil {
		return PrivateMessageIEsValuePrivateIEField{}, q4.OperationError(err, "Opaque")
	}
	return PrivateMessageIEsValuePrivateIEField{Id: id, Criticality: criticality, Value: BridgePrivateValue(id, retained)}, q4.OperationError(nil, "Opaque")
}

// PRSFrequencyHoppingConfigurationCodec binds the complete source value type.
func PRSFrequencyHoppingConfigurationCodec() PRSFrequencyHoppingConfigurationValueCodec {
	return PRSFrequencyHoppingConfigurationValueCodec{path: "PRSFrequencyHoppingConfiguration", decode: func(data []byte, options q4.DecodeState) (PRSFrequencyHoppingConfiguration, error) {
		var value PRSFrequencyHoppingConfiguration
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return PRSFrequencyHoppingConfiguration{}, err
		}
		value.received = true
		value.receivedBytes = q4.OriginalWire(data)
		return value, nil
	}, encode: func(value PRSFrequencyHoppingConfiguration, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v PRSFrequencyHoppingConfiguration, options q4.DecodeState) (PRSFrequencyHoppingConfiguration, q4.Snapshot,
	) {
		s := q4.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaPRSFrequencyHoppingConfiguration(&v, &s)
		var root q4.Snapshot

		s.OperationCounts()
		s.End(f, &root, false)

		return v, root
	}, compare: func(v PRSFrequencyHoppingConfiguration, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
		s := q4.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaPRSFrequencyHoppingConfiguration(&v, &s)
		s.End(f, root,

			false,
		)
		return s.Plan()
	}, context: func() q5.BridgeCodecContext {
		sealed := q5.BridgeCodecContext{}
		*q5.BridgecodecContextFieldSource(&sealed) = "source-value:PRSFrequencyHoppingConfiguration"
		return sealed
	}(),
	}
}

// PRSMutingConfigurationCodec binds the complete source value type.
func PRSMutingConfigurationCodec() PRSMutingConfigurationValueCodec {
	return PRSMutingConfigurationValueCodec{path: "PRSMutingConfiguration", decode: func(data []byte, options q4.DecodeState) (PRSMutingConfiguration, error) {
		var value PRSMutingConfiguration
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return PRSMutingConfiguration{}, err
		}
		value.received = true
		value.receivedBytes = q4.OriginalWire(data)
		return value, nil
	}, encode: func(value PRSMutingConfiguration, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v PRSMutingConfiguration, options q4.DecodeState) (PRSMutingConfiguration, q4.Snapshot,

	) {
		s := q4.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaPRSMutingConfiguration(&v, &s)
		var root q4.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v PRSMutingConfiguration, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
		s := q4.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaPRSMutingConfiguration(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q5.BridgeCodecContext {
		sealed := q5.BridgeCodecContext{}
		*q5.BridgecodecContextFieldSource(&sealed) = "source-value:PRSMutingConfiguration"
		return sealed
	}(),
	}
}

// PosSIBSegmentsElemCodec binds the complete source value type.
func PosSIBSegmentsElemCodec() PosSIBSegmentsElemValueCodec {
	return PosSIBSegmentsElemValueCodec{path: "PosSIBSegmentsElem", decode: func(data []byte, options q4.DecodeState) (PosSIBSegmentsElem, error) {
		var value PosSIBSegmentsElem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return PosSIBSegmentsElem{}, err
		}
		value.received = true
		value.receivedBytes = q4.OriginalWire(data)
		return value, nil
	}, encode: func(value PosSIBSegmentsElem, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v PosSIBSegmentsElem, options q4.DecodeState) (PosSIBSegmentsElem, q4.Snapshot) {
		s := q4.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaPosSIBSegmentsElem(&v, &s)
		var root q4.Snapshot
		s.OperationCounts()
		s.End(f,
			&root,
			false)
		return v, root
	}, compare: func(v PosSIBSegmentsElem, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
		s := q4.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaPosSIBSegmentsElem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q5.BridgeCodecContext {
		sealed := q5.BridgeCodecContext{}
		*q5.BridgecodecContextFieldSource(&sealed) = "source-value:PosSIBSegmentsElem"
		return sealed
	}(),
	}
}

// PrivateIEIDCodec binds the complete source value type.
func PrivateIEIDCodec() PrivateIEIDValueCodec {
	return PrivateIEIDValueCodec{path: "PrivateIEID", decode: func(data []byte, options q4.DecodeState) (PrivateIEID, error) {
		var value PrivateIEID
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return PrivateIEID{}, err
		}
		value.received = true
		value.receivedBytes = q4.OriginalWire(data)
		return value, nil
	}, encode: func(value PrivateIEID, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v PrivateIEID, options q4.DecodeState) (PrivateIEID, q4.Snapshot) {
		s := q4.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaPrivateIEID(&v, &s)
		var root q4.Snapshot

		s.OperationCounts()
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v PrivateIEID, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
		s := q4.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaPrivateIEID(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q5.BridgeCodecContext {
		sealed := q5.BridgeCodecContext{}
		*q5.BridgecodecContextFieldSource(&sealed) = "source-value:PrivateIEID"
		return sealed
	}(),
	}
}

// ResultUTRANItemPhysCellIDUTRANCodec binds the complete source value type.
func ResultUTRANItemPhysCellIDUTRANCodec() ResultUTRANItemPhysCellIDUTRANValueCodec {
	return ResultUTRANItemPhysCellIDUTRANValueCodec{path: "ResultUTRANItemPhysCellIDUTRAN", decode: func(data []byte, options q4.DecodeState) (ResultUTRANItemPhysCellIDUTRAN, error) {
		var value ResultUTRANItemPhysCellIDUTRAN
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ResultUTRANItemPhysCellIDUTRAN{}, err
		}
		value.received = true
		value.receivedBytes = q4.OriginalWire(data)
		return value, nil
	}, encode: func(value ResultUTRANItemPhysCellIDUTRAN, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ResultUTRANItemPhysCellIDUTRAN, options q4.DecodeState) (ResultUTRANItemPhysCellIDUTRAN, q4.Snapshot) {
		s := q4.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaResultUTRANItemPhysCellIDUTRAN(&v, &s)
		var root q4.Snapshot

		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResultUTRANItemPhysCellIDUTRAN, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
		s := q4.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaResultUTRANItemPhysCellIDUTRAN(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q5.BridgeCodecContext {
		sealed := q5.BridgeCodecContext{}
		*q5.BridgecodecContextFieldSource(&sealed) = "source-value:ResultUTRANItemPhysCellIDUTRAN"
		return sealed
	}(),
	}
}
func BridgePRSFrequencyHoppingConfigurationAPERValueFieldContext(v *PRSFrequencyHoppingConfigurationAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgePRSFrequencyHoppingConfigurationAPERValueFieldReceived(v *PRSFrequencyHoppingConfigurationAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgePRSFrequencyHoppingConfigurationAPERValueFieldReplay(v *PRSFrequencyHoppingConfigurationAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgePRSFrequencyHoppingConfigurationAPERValueFieldWithoutReplay(v *PRSFrequencyHoppingConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePRSFrequencyHoppingConfigurationFieldBandPositionsIndef(v *PRSFrequencyHoppingConfiguration) *bool {
	return &v.bandPositionsIndef
}
func BridgePRSFrequencyHoppingConfigurationFieldExtCount(v *PRSFrequencyHoppingConfiguration) *int64 {
	return &v.extCount
}
func BridgePRSFrequencyHoppingConfigurationFieldExtData(v *PRSFrequencyHoppingConfiguration) *[][]byte {
	return &v.extData
}
func BridgePRSFrequencyHoppingConfigurationFieldExtOrigin(v *PRSFrequencyHoppingConfiguration) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgePRSFrequencyHoppingConfigurationFieldExtPresent(v *PRSFrequencyHoppingConfiguration) *[]bool {
	return &v.extPresent
}
func BridgePRSFrequencyHoppingConfigurationFieldExtWire(v *PRSFrequencyHoppingConfiguration) *[]q4.WireSpan {
	return &v.extWire
}
func BridgePRSFrequencyHoppingConfigurationFieldIEExtensionsIndef(v *PRSFrequencyHoppingConfiguration) *bool {
	return &v.iEExtensionsIndef
}
func BridgePRSFrequencyHoppingConfigurationFieldPerExtPadding(v *PRSFrequencyHoppingConfiguration) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgePRSFrequencyHoppingConfigurationFieldPerPadding(v *PRSFrequencyHoppingConfiguration) *q4.FinalPadding {
	return &v.perPadding
}
func BridgePRSFrequencyHoppingConfigurationFieldReceived(v *PRSFrequencyHoppingConfiguration) *bool {
	return &v.received
}
func BridgePRSFrequencyHoppingConfigurationFieldReceivedBytes(v *PRSFrequencyHoppingConfiguration) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgePRSFrequencyHoppingConfigurationFieldReplay(v *PRSFrequencyHoppingConfiguration) *q4.Snapshot {
	return &v.replay
}
func BridgePRSFrequencyHoppingConfigurationFieldStream(v *PRSFrequencyHoppingConfiguration) *q4.WireSpan {
	return &v.stream
}
func BridgePRSFrequencyHoppingConfigurationFieldWithoutReplay(v *PRSFrequencyHoppingConfiguration) *bool {
	return &v.withoutReplay
}
func BridgePRSFrequencyHoppingConfigurationMethodMarshalAPERBudget(v *PRSFrequencyHoppingConfiguration, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationMethodMarshalAPERChanged(v *PRSFrequencyHoppingConfiguration, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePRSFrequencyHoppingConfigurationMethodMarshalAPERChangedValue(v *PRSFrequencyHoppingConfiguration, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePRSFrequencyHoppingConfigurationMethodMarshalAPERFreshValue(v *PRSFrequencyHoppingConfiguration, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationMethodMarshalAPERLegacy(v *PRSFrequencyHoppingConfiguration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePRSFrequencyHoppingConfigurationMethodMarshalAPERPlanned(v *PRSFrequencyHoppingConfiguration, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationMethodMarshalAPERTo(v *PRSFrequencyHoppingConfiguration, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePRSFrequencyHoppingConfigurationMethodUnmarshalAPERFrom(v *PRSFrequencyHoppingConfiguration, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePRSFrequencyHoppingConfigurationMethodUnmarshalAPERLegacy(v *PRSFrequencyHoppingConfiguration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePRSFrequencyHoppingConfigurationMethodUnmarshalAPERWithOptions(v *PRSFrequencyHoppingConfiguration, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationValueCodecFieldCapture(v *PRSFrequencyHoppingConfigurationValueCodec) *func(PRSFrequencyHoppingConfiguration, q4.DecodeState) (PRSFrequencyHoppingConfiguration, q4.Snapshot) {
	return &v.capture
}
func BridgePRSFrequencyHoppingConfigurationValueCodecFieldCompare(v *PRSFrequencyHoppingConfigurationValueCodec) *func(PRSFrequencyHoppingConfiguration, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgePRSFrequencyHoppingConfigurationValueCodecFieldContext(v *PRSFrequencyHoppingConfigurationValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgePRSFrequencyHoppingConfigurationValueCodecFieldDecode(v *PRSFrequencyHoppingConfigurationValueCodec) *func([]byte, q4.DecodeState) (PRSFrequencyHoppingConfiguration, error) {
	return &v.decode
}
func BridgePRSFrequencyHoppingConfigurationValueCodecFieldEncode(v *PRSFrequencyHoppingConfigurationValueCodec) *func(PRSFrequencyHoppingConfiguration, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePRSFrequencyHoppingConfigurationValueCodecFieldPath(v *PRSFrequencyHoppingConfigurationValueCodec) *q4.Path {
	return &v.path
}
func BridgePRSFrequencyHoppingConfigurationValueCodecMethodEncodeBudget(v PRSFrequencyHoppingConfigurationValueCodec, a0 PRSFrequencyHoppingConfiguration, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePRSFrequencyHoppingConfigurationValueCodecMethodEncodeChanged(v PRSFrequencyHoppingConfigurationValueCodec, a0 PRSFrequencyHoppingConfiguration, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePRSMutingConfigurationAPERValueFieldContext(v *PRSMutingConfigurationAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgePRSMutingConfigurationAPERValueFieldReceived(v *PRSMutingConfigurationAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgePRSMutingConfigurationAPERValueFieldReplay(v *PRSMutingConfigurationAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgePRSMutingConfigurationAPERValueFieldWithoutReplay(v *PRSMutingConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePRSMutingConfigurationFieldKnownOpenBytes(v *PRSMutingConfiguration) *uint64 {
	return &v.knownOpenBytes
}
func BridgePRSMutingConfigurationFieldPerOpenTypePadding(v *PRSMutingConfiguration) *q4.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgePRSMutingConfigurationFieldPerPadding(v *PRSMutingConfiguration) *q4.CompletePadding {
	return &v.perPadding
}
func BridgePRSMutingConfigurationFieldReceived(v *PRSMutingConfiguration) *bool { return &v.received }
func BridgePRSMutingConfigurationFieldReceivedBytes(v *PRSMutingConfiguration) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgePRSMutingConfigurationFieldReplay(v *PRSMutingConfiguration) *q4.Snapshot {
	return &v.replay
}
func BridgePRSMutingConfigurationFieldStream(v *PRSMutingConfiguration) *q4.WireSpan {
	return &v.stream
}
func BridgePRSMutingConfigurationFieldWithoutReplay(v *PRSMutingConfiguration) *bool {
	return &v.withoutReplay
}
func BridgePRSMutingConfigurationMethodMarshalAPERBudget(v *PRSMutingConfiguration, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePRSMutingConfigurationMethodMarshalAPERChanged(v *PRSMutingConfiguration, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePRSMutingConfigurationMethodMarshalAPERChangedValue(v *PRSMutingConfiguration, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePRSMutingConfigurationMethodMarshalAPERFreshValue(v *PRSMutingConfiguration, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgePRSMutingConfigurationMethodMarshalAPERLegacy(v *PRSMutingConfiguration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePRSMutingConfigurationMethodMarshalAPERPlanned(v *PRSMutingConfiguration, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgePRSMutingConfigurationMethodMarshalAPERTo(v *PRSMutingConfiguration, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePRSMutingConfigurationMethodUnmarshalAPERFrom(v *PRSMutingConfiguration, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePRSMutingConfigurationMethodUnmarshalAPERLegacy(v *PRSMutingConfiguration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePRSMutingConfigurationMethodUnmarshalAPERWithOptions(v *PRSMutingConfiguration, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePRSMutingConfigurationValueCodecFieldCapture(v *PRSMutingConfigurationValueCodec) *func(PRSMutingConfiguration, q4.DecodeState) (PRSMutingConfiguration, q4.Snapshot) {
	return &v.capture
}
func BridgePRSMutingConfigurationValueCodecFieldCompare(v *PRSMutingConfigurationValueCodec) *func(PRSMutingConfiguration, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgePRSMutingConfigurationValueCodecFieldContext(v *PRSMutingConfigurationValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgePRSMutingConfigurationValueCodecFieldDecode(v *PRSMutingConfigurationValueCodec) *func([]byte, q4.DecodeState) (PRSMutingConfiguration, error) {
	return &v.decode
}
func BridgePRSMutingConfigurationValueCodecFieldEncode(v *PRSMutingConfigurationValueCodec) *func(PRSMutingConfiguration, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePRSMutingConfigurationValueCodecFieldPath(v *PRSMutingConfigurationValueCodec) *q4.Path {
	return &v.path
}
func BridgePRSMutingConfigurationValueCodecMethodEncodeBudget(v PRSMutingConfigurationValueCodec, a0 PRSMutingConfiguration, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePRSMutingConfigurationValueCodecMethodEncodeChanged(v PRSMutingConfigurationValueCodec, a0 PRSMutingConfiguration, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePosSIBSegmentsAPERValueFieldContext(v *PosSIBSegmentsAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBSegmentsAPERValueFieldReceived(v *PosSIBSegmentsAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgePosSIBSegmentsAPERValueFieldReplay(v *PosSIBSegmentsAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgePosSIBSegmentsAPERValueFieldWithoutReplay(v *PosSIBSegmentsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePosSIBSegmentsElemAPERValueFieldContext(v *PosSIBSegmentsElemAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBSegmentsElemAPERValueFieldReceived(v *PosSIBSegmentsElemAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgePosSIBSegmentsElemAPERValueFieldReplay(v *PosSIBSegmentsElemAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgePosSIBSegmentsElemAPERValueFieldWithoutReplay(v *PosSIBSegmentsElemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePosSIBSegmentsElemFieldExtCount(v *PosSIBSegmentsElem) *int64   { return &v.extCount }
func BridgePosSIBSegmentsElemFieldExtData(v *PosSIBSegmentsElem) *[][]byte { return &v.extData }
func BridgePosSIBSegmentsElemFieldExtOrigin(v *PosSIBSegmentsElem) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgePosSIBSegmentsElemFieldExtPresent(v *PosSIBSegmentsElem) *[]bool     { return &v.extPresent }
func BridgePosSIBSegmentsElemFieldExtWire(v *PosSIBSegmentsElem) *[]q4.WireSpan { return &v.extWire }
func BridgePosSIBSegmentsElemFieldIEExtensionsIndef(v *PosSIBSegmentsElem) *bool {
	return &v.iEExtensionsIndef
}
func BridgePosSIBSegmentsElemFieldPerExtPadding(v *PosSIBSegmentsElem) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgePosSIBSegmentsElemFieldPerPadding(v *PosSIBSegmentsElem) *q4.FinalPadding {
	return &v.perPadding
}
func BridgePosSIBSegmentsElemFieldReceived(v *PosSIBSegmentsElem) *bool { return &v.received }
func BridgePosSIBSegmentsElemFieldReceivedBytes(v *PosSIBSegmentsElem) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgePosSIBSegmentsElemFieldReplay(v *PosSIBSegmentsElem) *q4.Snapshot { return &v.replay }
func BridgePosSIBSegmentsElemFieldStream(v *PosSIBSegmentsElem) *q4.WireSpan { return &v.stream }
func BridgePosSIBSegmentsElemFieldWithoutReplay(v *PosSIBSegmentsElem) *bool { return &v.withoutReplay }
func BridgePosSIBSegmentsElemMethodMarshalAPERBudget(v *PosSIBSegmentsElem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePosSIBSegmentsElemMethodMarshalAPERChanged(v *PosSIBSegmentsElem, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePosSIBSegmentsElemMethodMarshalAPERChangedValue(v *PosSIBSegmentsElem, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePosSIBSegmentsElemMethodMarshalAPERFreshValue(v *PosSIBSegmentsElem, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgePosSIBSegmentsElemMethodMarshalAPERLegacy(v *PosSIBSegmentsElem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePosSIBSegmentsElemMethodMarshalAPERPlanned(v *PosSIBSegmentsElem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgePosSIBSegmentsElemMethodMarshalAPERTo(v *PosSIBSegmentsElem, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePosSIBSegmentsElemMethodUnmarshalAPERFrom(v *PosSIBSegmentsElem, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePosSIBSegmentsElemMethodUnmarshalAPERLegacy(v *PosSIBSegmentsElem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePosSIBSegmentsElemMethodUnmarshalAPERWithOptions(v *PosSIBSegmentsElem, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePosSIBSegmentsElemValueCodecFieldCapture(v *PosSIBSegmentsElemValueCodec) *func(PosSIBSegmentsElem, q4.DecodeState) (PosSIBSegmentsElem, q4.Snapshot) {
	return &v.capture
}
func BridgePosSIBSegmentsElemValueCodecFieldCompare(v *PosSIBSegmentsElemValueCodec) *func(PosSIBSegmentsElem, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgePosSIBSegmentsElemValueCodecFieldContext(v *PosSIBSegmentsElemValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBSegmentsElemValueCodecFieldDecode(v *PosSIBSegmentsElemValueCodec) *func([]byte, q4.DecodeState) (PosSIBSegmentsElem, error) {
	return &v.decode
}
func BridgePosSIBSegmentsElemValueCodecFieldEncode(v *PosSIBSegmentsElemValueCodec) *func(PosSIBSegmentsElem, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePosSIBSegmentsElemValueCodecFieldPath(v *PosSIBSegmentsElemValueCodec) *q4.Path {
	return &v.path
}
func BridgePosSIBSegmentsElemValueCodecMethodEncodeBudget(v PosSIBSegmentsElemValueCodec, a0 PosSIBSegmentsElem, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePosSIBSegmentsElemValueCodecMethodEncodeChanged(v PosSIBSegmentsElemValueCodec, a0 PosSIBSegmentsElem, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePosSIBSegmentsValueCodecFieldCapture(v *PosSIBSegmentsValueCodec) *func(PosSIBSegments, q4.DecodeState) (PosSIBSegments, q4.Snapshot) {
	return &v.capture
}
func BridgePosSIBSegmentsValueCodecFieldCompare(v *PosSIBSegmentsValueCodec) *func(PosSIBSegments, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgePosSIBSegmentsValueCodecFieldContext(v *PosSIBSegmentsValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBSegmentsValueCodecFieldDecode(v *PosSIBSegmentsValueCodec) *func([]byte, q4.DecodeState) (PosSIBSegments, error) {
	return &v.decode
}
func BridgePosSIBSegmentsValueCodecFieldEncode(v *PosSIBSegmentsValueCodec) *func(PosSIBSegments, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePosSIBSegmentsValueCodecFieldPath(v *PosSIBSegmentsValueCodec) *q4.Path { return &v.path }
func BridgePosSIBSegmentsValueCodecMethodEncodeBudget(v PosSIBSegmentsValueCodec, a0 PosSIBSegments, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePosSIBSegmentsValueCodecMethodEncodeChanged(v PosSIBSegmentsValueCodec, a0 PosSIBSegments, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePrivateIEIDAPERValueFieldContext(v *PrivateIEIDAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgePrivateIEIDAPERValueFieldReceived(v *PrivateIEIDAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgePrivateIEIDAPERValueFieldReplay(v *PrivateIEIDAPERValue) *q4.Snapshot { return &v.replay }
func BridgePrivateIEIDAPERValueFieldWithoutReplay(v *PrivateIEIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePrivateIEIDFieldPerOpenTypePadding(v *PrivateIEID) *q4.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgePrivateIEIDFieldPerPadding(v *PrivateIEID) *q4.CompletePadding { return &v.perPadding }
func BridgePrivateIEIDFieldReceived(v *PrivateIEID) *bool                 { return &v.received }
func BridgePrivateIEIDFieldReceivedBytes(v *PrivateIEID) *q4.WireSpan     { return &v.receivedBytes }
func BridgePrivateIEIDFieldReplay(v *PrivateIEID) *q4.Snapshot            { return &v.replay }
func BridgePrivateIEIDFieldStream(v *PrivateIEID) *q4.WireSpan            { return &v.stream }
func BridgePrivateIEIDFieldWithoutReplay(v *PrivateIEID) *bool            { return &v.withoutReplay }
func BridgePrivateIEIDMethodMarshalAPERBudget(v *PrivateIEID, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePrivateIEIDMethodMarshalAPERChanged(v *PrivateIEID, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePrivateIEIDMethodMarshalAPERChangedValue(v *PrivateIEID, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePrivateIEIDMethodMarshalAPERFreshValue(v *PrivateIEID, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgePrivateIEIDMethodMarshalAPERLegacy(v *PrivateIEID) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePrivateIEIDMethodMarshalAPERPlanned(v *PrivateIEID, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgePrivateIEIDMethodMarshalAPERTo(v *PrivateIEID, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePrivateIEIDMethodUnmarshalAPERFrom(v *PrivateIEID, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePrivateIEIDMethodUnmarshalAPERLegacy(v *PrivateIEID, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePrivateIEIDMethodUnmarshalAPERWithOptions(v *PrivateIEID, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePrivateIEIDValueCodecFieldCapture(v *PrivateIEIDValueCodec) *func(PrivateIEID, q4.DecodeState) (PrivateIEID, q4.Snapshot) {
	return &v.capture
}
func BridgePrivateIEIDValueCodecFieldCompare(v *PrivateIEIDValueCodec) *func(PrivateIEID, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgePrivateIEIDValueCodecFieldContext(v *PrivateIEIDValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgePrivateIEIDValueCodecFieldDecode(v *PrivateIEIDValueCodec) *func([]byte, q4.DecodeState) (PrivateIEID, error) {
	return &v.decode
}
func BridgePrivateIEIDValueCodecFieldEncode(v *PrivateIEIDValueCodec) *func(PrivateIEID, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePrivateIEIDValueCodecFieldPath(v *PrivateIEIDValueCodec) *q4.Path { return &v.path }
func BridgePrivateIEIDValueCodecMethodEncodeBudget(v PrivateIEIDValueCodec, a0 PrivateIEID, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePrivateIEIDValueCodecMethodEncodeChanged(v PrivateIEIDValueCodec, a0 PrivateIEID, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePrivateMessageIEsValueFieldIdChoice(v *PrivateMessageIEsValue) *int    { return &v.idChoice }
func BridgePrivateMessageIEsValueFieldIdGlobal(v *PrivateMessageIEsValue) *string { return &v.idGlobal }
func BridgePrivateMessageIEsValueFieldIdLocal(v *PrivateMessageIEsValue) *int64   { return &v.idLocal }
func BridgePrivateMessageIEsValueFieldOpaque(v *PrivateMessageIEsValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgePrivateMessageIEsValueFieldReplay(v *PrivateMessageIEsValue) *q4.Snapshot {
	return &v.replay
}
func BridgePrivateMessageIEsValueFieldValid(v *PrivateMessageIEsValue) *bool { return &v.valid }
func BridgePrivateMessageIEsValueFieldWithoutReplay(v *PrivateMessageIEsValue) *bool {
	return &v.withoutReplay
}
func BridgePrivateMessageIEsValueMethodCaptureFraming(v PrivateMessageIEsValue) uint64 {
	return v.captureFraming()
}
func BridgePrivateMessageIEsValueMethodCaptureSemantics(v PrivateMessageIEsValue, a0 q4.SemanticCapture) PrivateMessageIEsValue {
	return v.captureSemantics(a0)
}
func BridgePrivateMessageIEsValueMethodCaptureSnapshot(v PrivateMessageIEsValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgePrivateMessageIEsValueMethodCompareSemantics(v PrivateMessageIEsValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgePrivateMessageIEsValueMethodDecode(v PrivateMessageIEsValue, a0 PrivateIEID, a1 q4.OpaqueOpenType) (PrivateMessageIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgePrivateMessageIEsValueMethodEncode(v PrivateMessageIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgePrivateMessageIEsValueMethodEncodeFresh(v PrivateMessageIEsValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgePrivateMessageIEsValueMethodMatchesID(v PrivateMessageIEsValue, a0 PrivateIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgePrivateMessageIEsValueMethodRule(v PrivateMessageIEsValue) q4.SourceRule { return v.rule() }
func BridgePrivateMessageIEsValuePrivateIEFieldFieldReceived(v *PrivateMessageIEsValuePrivateIEField) *q4.CompletePadding {
	return &v.received
}
func BridgePrivateMessageIEsValuePrivateIEFieldFieldReplay(v *PrivateMessageIEsValuePrivateIEField) *q4.Snapshot {
	return &v.replay
}
func BridgePrivateMessageIEsValuePrivateIEFieldFieldStream(v *PrivateMessageIEsValuePrivateIEField) *q4.WireSpan {
	return &v.stream
}
func BridgePrivateMessageIEsValuePrivateIEFieldFieldWithoutReplay(v *PrivateMessageIEsValuePrivateIEField) *bool {
	return &v.withoutReplay
}
func BridgePrivateMessageIEsValuePrivateIEFieldMethodMarshalAPERTo(v *PrivateMessageIEsValuePrivateIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePrivateMessageIEsValuePrivateIEFieldMethodUnmarshalAPERFrom(v *PrivateMessageIEsValuePrivateIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRequestedSRSTransmissionCharacteristicsAPERValueFieldContext(v *RequestedSRSTransmissionCharacteristicsAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeRequestedSRSTransmissionCharacteristicsAPERValueFieldReceived(v *RequestedSRSTransmissionCharacteristicsAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeRequestedSRSTransmissionCharacteristicsAPERValueFieldReplay(v *RequestedSRSTransmissionCharacteristicsAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeRequestedSRSTransmissionCharacteristicsAPERValueFieldWithoutReplay(v *RequestedSRSTransmissionCharacteristicsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldExtCount(v *RequestedSRSTransmissionCharacteristics) *int64 {
	return &v.extCount
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldExtData(v *RequestedSRSTransmissionCharacteristics) *[][]byte {
	return &v.extData
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldExtOrigin(v *RequestedSRSTransmissionCharacteristics) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldExtPresent(v *RequestedSRSTransmissionCharacteristics) *[]bool {
	return &v.extPresent
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldExtWire(v *RequestedSRSTransmissionCharacteristics) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldPerExtPadding(v *RequestedSRSTransmissionCharacteristics) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldPerPadding(v *RequestedSRSTransmissionCharacteristics) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldReceived(v *RequestedSRSTransmissionCharacteristics) *bool {
	return &v.received
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldReceivedBytes(v *RequestedSRSTransmissionCharacteristics) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldReplay(v *RequestedSRSTransmissionCharacteristics) *q4.Snapshot {
	return &v.replay
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldStream(v *RequestedSRSTransmissionCharacteristics) *q4.WireSpan {
	return &v.stream
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldWithoutReplay(v *RequestedSRSTransmissionCharacteristics) *bool {
	return &v.withoutReplay
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodMarshalAPERBudget(v *RequestedSRSTransmissionCharacteristics, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodMarshalAPERChanged(v *RequestedSRSTransmissionCharacteristics, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodMarshalAPERChangedValue(v *RequestedSRSTransmissionCharacteristics, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodMarshalAPERFreshValue(v *RequestedSRSTransmissionCharacteristics, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodMarshalAPERLegacy(v *RequestedSRSTransmissionCharacteristics) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodMarshalAPERPlanned(v *RequestedSRSTransmissionCharacteristics, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodMarshalAPERTo(v *RequestedSRSTransmissionCharacteristics, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodUnmarshalAPERFrom(v *RequestedSRSTransmissionCharacteristics, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodUnmarshalAPERLegacy(v *RequestedSRSTransmissionCharacteristics, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodUnmarshalAPERWithOptions(v *RequestedSRSTransmissionCharacteristics, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldCapture(v *RequestedSRSTransmissionCharacteristicsValueCodec) *func(RequestedSRSTransmissionCharacteristics, q4.DecodeState) (RequestedSRSTransmissionCharacteristics, q4.Snapshot) {
	return &v.capture
}
func BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldCompare(v *RequestedSRSTransmissionCharacteristicsValueCodec) *func(RequestedSRSTransmissionCharacteristics, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldContext(v *RequestedSRSTransmissionCharacteristicsValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldDecode(v *RequestedSRSTransmissionCharacteristicsValueCodec) *func([]byte, q4.DecodeState) (RequestedSRSTransmissionCharacteristics, error) {
	return &v.decode
}
func BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldEncode(v *RequestedSRSTransmissionCharacteristicsValueCodec) *func(RequestedSRSTransmissionCharacteristics, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldPath(v *RequestedSRSTransmissionCharacteristicsValueCodec) *q4.Path {
	return &v.path
}
func BridgeRequestedSRSTransmissionCharacteristicsValueCodecMethodEncodeBudget(v RequestedSRSTransmissionCharacteristicsValueCodec, a0 RequestedSRSTransmissionCharacteristics, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeRequestedSRSTransmissionCharacteristicsValueCodecMethodEncodeChanged(v RequestedSRSTransmissionCharacteristicsValueCodec, a0 RequestedSRSTransmissionCharacteristics, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultUTRANItemPhysCellIDUTRANAPERValueFieldContext(v *ResultUTRANItemPhysCellIDUTRANAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeResultUTRANItemPhysCellIDUTRANAPERValueFieldReceived(v *ResultUTRANItemPhysCellIDUTRANAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeResultUTRANItemPhysCellIDUTRANAPERValueFieldReplay(v *ResultUTRANItemPhysCellIDUTRANAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeResultUTRANItemPhysCellIDUTRANAPERValueFieldWithoutReplay(v *ResultUTRANItemPhysCellIDUTRANAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultUTRANItemPhysCellIDUTRANFieldPerOpenTypePadding(v *ResultUTRANItemPhysCellIDUTRAN) *q4.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeResultUTRANItemPhysCellIDUTRANFieldPerPadding(v *ResultUTRANItemPhysCellIDUTRAN) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeResultUTRANItemPhysCellIDUTRANFieldReceived(v *ResultUTRANItemPhysCellIDUTRAN) *bool {
	return &v.received
}
func BridgeResultUTRANItemPhysCellIDUTRANFieldReceivedBytes(v *ResultUTRANItemPhysCellIDUTRAN) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeResultUTRANItemPhysCellIDUTRANFieldReplay(v *ResultUTRANItemPhysCellIDUTRAN) *q4.Snapshot {
	return &v.replay
}
func BridgeResultUTRANItemPhysCellIDUTRANFieldStream(v *ResultUTRANItemPhysCellIDUTRAN) *q4.WireSpan {
	return &v.stream
}
func BridgeResultUTRANItemPhysCellIDUTRANFieldWithoutReplay(v *ResultUTRANItemPhysCellIDUTRAN) *bool {
	return &v.withoutReplay
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERBudget(v *ResultUTRANItemPhysCellIDUTRAN, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERChanged(v *ResultUTRANItemPhysCellIDUTRAN, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERChangedValue(v *ResultUTRANItemPhysCellIDUTRAN, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERFreshValue(v *ResultUTRANItemPhysCellIDUTRAN, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERLegacy(v *ResultUTRANItemPhysCellIDUTRAN) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERPlanned(v *ResultUTRANItemPhysCellIDUTRAN, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERTo(v *ResultUTRANItemPhysCellIDUTRAN, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodUnmarshalAPERFrom(v *ResultUTRANItemPhysCellIDUTRAN, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodUnmarshalAPERLegacy(v *ResultUTRANItemPhysCellIDUTRAN, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodUnmarshalAPERWithOptions(v *ResultUTRANItemPhysCellIDUTRAN, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultUTRANItemPhysCellIDUTRANValueCodecFieldCapture(v *ResultUTRANItemPhysCellIDUTRANValueCodec) *func(ResultUTRANItemPhysCellIDUTRAN, q4.DecodeState) (ResultUTRANItemPhysCellIDUTRAN, q4.Snapshot) {
	return &v.capture
}
func BridgeResultUTRANItemPhysCellIDUTRANValueCodecFieldCompare(v *ResultUTRANItemPhysCellIDUTRANValueCodec) *func(ResultUTRANItemPhysCellIDUTRAN, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeResultUTRANItemPhysCellIDUTRANValueCodecFieldContext(v *ResultUTRANItemPhysCellIDUTRANValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeResultUTRANItemPhysCellIDUTRANValueCodecFieldDecode(v *ResultUTRANItemPhysCellIDUTRANValueCodec) *func([]byte, q4.DecodeState) (ResultUTRANItemPhysCellIDUTRAN, error) {
	return &v.decode
}
func BridgeResultUTRANItemPhysCellIDUTRANValueCodecFieldEncode(v *ResultUTRANItemPhysCellIDUTRANValueCodec) *func(ResultUTRANItemPhysCellIDUTRAN, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultUTRANItemPhysCellIDUTRANValueCodecFieldPath(v *ResultUTRANItemPhysCellIDUTRANValueCodec) *q4.Path {
	return &v.path
}
func BridgeResultUTRANItemPhysCellIDUTRANValueCodecMethodEncodeBudget(v ResultUTRANItemPhysCellIDUTRANValueCodec, a0 ResultUTRANItemPhysCellIDUTRAN, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultUTRANItemPhysCellIDUTRANValueCodecMethodEncodeChanged(v ResultUTRANItemPhysCellIDUTRANValueCodec, a0 ResultUTRANItemPhysCellIDUTRAN, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
