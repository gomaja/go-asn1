// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s00 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s00

import (
	q4 "fmt"
	q7 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	q6 "math/big"
)

// APERValue carries a source value and private replay state.
type BridgeCodecContext struct{ source string }

func BridgeCheckLPPaTransactionID(value LPPATransactionID) error {
	// 3GPP TS 36.455 V19.0.0 §9.3.6: LPPATransactionID ::= INTEGER (0..32767).
	if value < 0 || value > 32767 {
		return q4.Errorf("lppatransactionID: value %d outside 0..32767", value)
	}
	return nil
}

// BroadcastValueCodec is the concrete ValueCodec[Broadcast].
type BroadcastValueCodec struct {
	context BridgeCodecContext
	capture func(Broadcast, q5.DecodeState,

	) (Broadcast, q5.Snapshot,

	)
	compare func(Broadcast, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (Broadcast,

		error)
	encode func(Broadcast,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c BroadcastValueCodec) New(value Broadcast,

) (BroadcastAPERValue, error) {
	if c.encode == nil {
		return BroadcastAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return BroadcastAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BroadcastAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return BroadcastAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c BroadcastValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (BroadcastAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return BroadcastAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return BroadcastAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return BroadcastAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return BroadcastAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return BroadcastAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c BroadcastValueCodec) EncodeAPER(value BroadcastAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c BroadcastValueCodec) encodeBudget(value Broadcast,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c BroadcastValueCodec) encodeChanged(value Broadcast,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// MeasurementIDValueCodec is the concrete ValueCodec[MeasurementID].
type MeasurementIDValueCodec struct {
	context BridgeCodecContext
	capture func(MeasurementID, q5.DecodeState,

	) (MeasurementID, q5.Snapshot,

	)
	compare func(MeasurementID, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (MeasurementID,

		error)
	encode func(MeasurementID,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c MeasurementIDValueCodec) New(value MeasurementID,

) (MeasurementIDAPERValue, error) {
	if c.encode == nil {
		return MeasurementIDAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return MeasurementIDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MeasurementIDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return MeasurementIDAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c MeasurementIDValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (MeasurementIDAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return MeasurementIDAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return MeasurementIDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return MeasurementIDAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return MeasurementIDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return MeasurementIDAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c MeasurementIDValueCodec) EncodeAPER(value MeasurementIDAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c MeasurementIDValueCodec) encodeBudget(value MeasurementID,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c MeasurementIDValueCodec) encodeChanged(value MeasurementID,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// MeasurementPeriodicityValueCodec is the concrete ValueCodec[MeasurementPeriodicity].
type MeasurementPeriodicityValueCodec struct {
	context BridgeCodecContext
	capture func(MeasurementPeriodicity, q5.DecodeState,

	) (MeasurementPeriodicity, q5.Snapshot,

	)
	compare func(MeasurementPeriodicity, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (MeasurementPeriodicity,

		error)
	encode func(MeasurementPeriodicity,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c MeasurementPeriodicityValueCodec) New(value MeasurementPeriodicity,

) (MeasurementPeriodicityAPERValue, error) {
	if c.encode == nil {
		return MeasurementPeriodicityAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return MeasurementPeriodicityAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MeasurementPeriodicityAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return MeasurementPeriodicityAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c MeasurementPeriodicityValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (MeasurementPeriodicityAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return MeasurementPeriodicityAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return MeasurementPeriodicityAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return MeasurementPeriodicityAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return MeasurementPeriodicityAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return MeasurementPeriodicityAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c MeasurementPeriodicityValueCodec) EncodeAPER(value MeasurementPeriodicityAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c MeasurementPeriodicityValueCodec) encodeBudget(value MeasurementPeriodicity,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c MeasurementPeriodicityValueCodec) encodeChanged(value MeasurementPeriodicity,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// CellPortionIDValueCodec is the concrete ValueCodec[CellPortionID].
type CellPortionIDValueCodec struct {
	context BridgeCodecContext
	capture func(CellPortionID, q5.DecodeState,

	) (CellPortionID, q5.Snapshot,

	)
	compare func(CellPortionID, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (CellPortionID,

		error)
	encode func(CellPortionID,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c CellPortionIDValueCodec) New(value CellPortionID,

) (CellPortionIDAPERValue, error) {
	if c.encode == nil {
		return CellPortionIDAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return CellPortionIDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CellPortionIDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return CellPortionIDAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c CellPortionIDValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (CellPortionIDAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return CellPortionIDAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return CellPortionIDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return CellPortionIDAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return CellPortionIDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return CellPortionIDAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c CellPortionIDValueCodec) EncodeAPER(value CellPortionIDAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c CellPortionIDValueCodec) encodeBudget(value CellPortionID,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c CellPortionIDValueCodec) encodeChanged(value CellPortionID,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// BCCHValueCodec is the concrete ValueCodec[BCCH].
type BCCHValueCodec struct {
	context BridgeCodecContext
	capture func(BCCH, q5.DecodeState,

	) (BCCH, q5.Snapshot,

	)
	compare func(BCCH, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (BCCH,

		error)
	encode func(BCCH,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c BCCHValueCodec) New(value BCCH,

) (BCCHAPERValue, error) {
	if c.encode == nil {
		return BCCHAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return BCCHAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BCCHAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return BCCHAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c BCCHValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (BCCHAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return BCCHAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return BCCHAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return BCCHAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return BCCHAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return BCCHAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c BCCHValueCodec) EncodeAPER(value BCCHAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c BCCHValueCodec) encodeBudget(value BCCH,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c BCCHValueCodec) encodeChanged(value BCCH,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// BSSIDValueCodec is the concrete ValueCodec[BSSID].
type BSSIDValueCodec struct {
	context BridgeCodecContext
	capture func(BSSID, q5.DecodeState,

	) (BSSID, q5.Snapshot,

	)
	compare func(BSSID, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (BSSID,

		error)
	encode func(BSSID,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c BSSIDValueCodec) New(value BSSID,

) (BSSIDAPERValue, error) {
	if c.encode == nil {
		return BSSIDAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return BSSIDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BSSIDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return BSSIDAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c BSSIDValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (BSSIDAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return BSSIDAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return BSSIDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return BSSIDAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return BSSIDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return BSSIDAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c BSSIDValueCodec) EncodeAPER(value BSSIDAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c BSSIDValueCodec) encodeBudget(value BSSID,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c BSSIDValueCodec) encodeChanged(value BSSID,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// BroadcastPeriodicityValueCodec is the concrete ValueCodec[BroadcastPeriodicity].
type BroadcastPeriodicityValueCodec struct {
	context BridgeCodecContext
	capture func(BroadcastPeriodicity, q5.DecodeState,

	) (BroadcastPeriodicity, q5.Snapshot,

	)
	compare func(BroadcastPeriodicity, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (BroadcastPeriodicity,

		error)
	encode func(BroadcastPeriodicity,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c BroadcastPeriodicityValueCodec) New(value BroadcastPeriodicity,

) (BroadcastPeriodicityAPERValue, error) {
	if c.encode == nil {
		return BroadcastPeriodicityAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return BroadcastPeriodicityAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return BroadcastPeriodicityAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return BroadcastPeriodicityAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c BroadcastPeriodicityValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (BroadcastPeriodicityAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return BroadcastPeriodicityAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return BroadcastPeriodicityAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return BroadcastPeriodicityAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return BroadcastPeriodicityAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return BroadcastPeriodicityAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c BroadcastPeriodicityValueCodec) EncodeAPER(value BroadcastPeriodicityAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c BroadcastPeriodicityValueCodec) encodeBudget(value BroadcastPeriodicity,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c BroadcastPeriodicityValueCodec) encodeChanged(value BroadcastPeriodicity,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// CPLengthValueCodec is the concrete ValueCodec[CPLength].
type CPLengthValueCodec struct {
	context BridgeCodecContext
	capture func(CPLength, q5.DecodeState,

	) (CPLength, q5.Snapshot,

	)
	compare func(CPLength, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (CPLength,

		error)
	encode func(CPLength,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c CPLengthValueCodec) New(value CPLength,

) (CPLengthAPERValue, error) {
	if c.encode == nil {
		return CPLengthAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return CPLengthAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CPLengthAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return CPLengthAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c CPLengthValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (CPLengthAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return CPLengthAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return CPLengthAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return CPLengthAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return CPLengthAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return CPLengthAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c CPLengthValueCodec) EncodeAPER(value CPLengthAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c CPLengthValueCodec) encodeBudget(value CPLength,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c CPLengthValueCodec) encodeChanged(value CPLength,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// CauseMiscValueCodec is the concrete ValueCodec[CauseMisc].
type CauseMiscValueCodec struct {
	context BridgeCodecContext
	capture func(CauseMisc, q5.DecodeState,

	) (CauseMisc, q5.Snapshot,

	)
	compare func(CauseMisc, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (CauseMisc,

		error)
	encode func(CauseMisc,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c CauseMiscValueCodec) New(value CauseMisc,

) (CauseMiscAPERValue, error) {
	if c.encode == nil {
		return CauseMiscAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return CauseMiscAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CauseMiscAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return CauseMiscAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c CauseMiscValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (CauseMiscAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return CauseMiscAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return CauseMiscAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return CauseMiscAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return CauseMiscAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return CauseMiscAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c CauseMiscValueCodec) EncodeAPER(value CauseMiscAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c CauseMiscValueCodec) encodeBudget(value CauseMisc,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c CauseMiscValueCodec) encodeChanged(value CauseMisc,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// CauseProtocolValueCodec is the concrete ValueCodec[CauseProtocol].
type CauseProtocolValueCodec struct {
	context BridgeCodecContext
	capture func(CauseProtocol, q5.DecodeState,

	) (CauseProtocol, q5.Snapshot,

	)
	compare func(CauseProtocol, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (CauseProtocol,

		error)
	encode func(CauseProtocol,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c CauseProtocolValueCodec) New(value CauseProtocol,

) (CauseProtocolAPERValue, error) {
	if c.encode == nil {
		return CauseProtocolAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return CauseProtocolAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CauseProtocolAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return CauseProtocolAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c CauseProtocolValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (CauseProtocolAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return CauseProtocolAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return CauseProtocolAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return CauseProtocolAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return CauseProtocolAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return CauseProtocolAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c CauseProtocolValueCodec) EncodeAPER(value CauseProtocolAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c CauseProtocolValueCodec) encodeBudget(value CauseProtocol,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c CauseProtocolValueCodec) encodeChanged(value CauseProtocol,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// CauseRadioNetworkValueCodec is the concrete ValueCodec[CauseRadioNetwork].
type CauseRadioNetworkValueCodec struct {
	context BridgeCodecContext
	capture func(CauseRadioNetwork, q5.DecodeState,

	) (CauseRadioNetwork, q5.Snapshot,

	)
	compare func(CauseRadioNetwork, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (CauseRadioNetwork,

		error)
	encode func(CauseRadioNetwork,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c CauseRadioNetworkValueCodec) New(value CauseRadioNetwork,

) (CauseRadioNetworkAPERValue, error) {
	if c.encode == nil {
		return CauseRadioNetworkAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return CauseRadioNetworkAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CauseRadioNetworkAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return CauseRadioNetworkAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c CauseRadioNetworkValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (CauseRadioNetworkAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return CauseRadioNetworkAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return CauseRadioNetworkAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return CauseRadioNetworkAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return CauseRadioNetworkAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return CauseRadioNetworkAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c CauseRadioNetworkValueCodec) EncodeAPER(value CauseRadioNetworkAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c CauseRadioNetworkValueCodec) encodeBudget(value CauseRadioNetwork,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c CauseRadioNetworkValueCodec) encodeChanged(value CauseRadioNetwork,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// CriticalityValueCodec is the concrete ValueCodec[Criticality].
type CriticalityValueCodec struct {
	context BridgeCodecContext
	capture func(Criticality, q5.DecodeState,

	) (Criticality, q5.Snapshot,

	)
	compare func(Criticality, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (Criticality,

		error)
	encode func(Criticality,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c CriticalityValueCodec) New(value Criticality,

) (CriticalityAPERValue, error) {
	if c.encode == nil {
		return CriticalityAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return CriticalityAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return CriticalityAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return CriticalityAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c CriticalityValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (CriticalityAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return CriticalityAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return CriticalityAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return CriticalityAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return CriticalityAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return CriticalityAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c CriticalityValueCodec) EncodeAPER(value CriticalityAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c CriticalityValueCodec) encodeBudget(value Criticality,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c CriticalityValueCodec) encodeChanged(value Criticality,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// DLBandwidthValueCodec is the concrete ValueCodec[DLBandwidth].
type DLBandwidthValueCodec struct {
	context BridgeCodecContext
	capture func(DLBandwidth, q5.DecodeState,

	) (DLBandwidth, q5.Snapshot,

	)
	compare func(DLBandwidth, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (DLBandwidth,

		error)
	encode func(DLBandwidth,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c DLBandwidthValueCodec) New(value DLBandwidth,

) (DLBandwidthAPERValue, error) {
	if c.encode == nil {
		return DLBandwidthAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return DLBandwidthAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return DLBandwidthAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return DLBandwidthAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c DLBandwidthValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (DLBandwidthAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return DLBandwidthAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return DLBandwidthAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return DLBandwidthAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return DLBandwidthAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return DLBandwidthAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c DLBandwidthValueCodec) EncodeAPER(value DLBandwidthAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c DLBandwidthValueCodec) encodeBudget(value DLBandwidth,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c DLBandwidthValueCodec) encodeChanged(value DLBandwidth,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// EARFCNValueCodec is the concrete ValueCodec[EARFCN].
type EARFCNValueCodec struct {
	context BridgeCodecContext
	capture func(EARFCN, q5.DecodeState,

	) (EARFCN, q5.Snapshot,

	)
	compare func(EARFCN, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (EARFCN,

		error)
	encode func(EARFCN,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c EARFCNValueCodec) New(value EARFCN,

) (EARFCNAPERValue, error) {
	if c.encode == nil {
		return EARFCNAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return EARFCNAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EARFCNAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return EARFCNAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c EARFCNValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (EARFCNAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return EARFCNAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return EARFCNAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return EARFCNAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return EARFCNAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return EARFCNAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c EARFCNValueCodec) EncodeAPER(value EARFCNAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c EARFCNValueCodec) encodeBudget(value EARFCN,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c EARFCNValueCodec) encodeChanged(value EARFCN,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// EUTRANCellIdentifierValueCodec is the concrete ValueCodec[EUTRANCellIdentifier].
type EUTRANCellIdentifierValueCodec struct {
	context BridgeCodecContext
	capture func(EUTRANCellIdentifier, q5.DecodeState,

	) (EUTRANCellIdentifier, q5.Snapshot,

	)
	compare func(EUTRANCellIdentifier, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (EUTRANCellIdentifier,

		error)
	encode func(EUTRANCellIdentifier,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c EUTRANCellIdentifierValueCodec) New(value EUTRANCellIdentifier,

) (EUTRANCellIdentifierAPERValue, error) {
	if c.encode == nil {
		return EUTRANCellIdentifierAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return EUTRANCellIdentifierAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return EUTRANCellIdentifierAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return EUTRANCellIdentifierAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c EUTRANCellIdentifierValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (EUTRANCellIdentifierAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return EUTRANCellIdentifierAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return EUTRANCellIdentifierAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return EUTRANCellIdentifierAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return EUTRANCellIdentifierAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return EUTRANCellIdentifierAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c EUTRANCellIdentifierValueCodec) EncodeAPER(value EUTRANCellIdentifierAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c EUTRANCellIdentifierValueCodec) encodeBudget(value EUTRANCellIdentifier,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c EUTRANCellIdentifierValueCodec) encodeChanged(value EUTRANCellIdentifier,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// HESSIDValueCodec is the concrete ValueCodec[HESSID].
type HESSIDValueCodec struct {
	context BridgeCodecContext
	capture func(HESSID, q5.DecodeState,

	) (HESSID, q5.Snapshot,

	)
	compare func(HESSID, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (HESSID,

		error)
	encode func(HESSID,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c HESSIDValueCodec) New(value HESSID,

) (HESSIDAPERValue, error) {
	if c.encode == nil {
		return HESSIDAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return HESSIDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HESSIDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return HESSIDAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c HESSIDValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (HESSIDAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return HESSIDAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return HESSIDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return HESSIDAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return HESSIDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return HESSIDAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c HESSIDValueCodec) EncodeAPER(value HESSIDAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c HESSIDValueCodec) encodeBudget(value HESSID,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c HESSIDValueCodec) encodeChanged(value HESSID,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// InterRATMeasurementQuantitiesValueValueCodec is the concrete ValueCodec[InterRATMeasurementQuantitiesValue].
type InterRATMeasurementQuantitiesValueValueCodec struct {
	context BridgeCodecContext
	capture func(InterRATMeasurementQuantitiesValue, q5.DecodeState,

	) (InterRATMeasurementQuantitiesValue, q5.Snapshot,

	)
	compare func(InterRATMeasurementQuantitiesValue, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (InterRATMeasurementQuantitiesValue,

		error)
	encode func(InterRATMeasurementQuantitiesValue,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c InterRATMeasurementQuantitiesValueValueCodec) New(value InterRATMeasurementQuantitiesValue,

) (InterRATMeasurementQuantitiesValueAPERValue, error) {
	if c.encode == nil {
		return InterRATMeasurementQuantitiesValueAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return InterRATMeasurementQuantitiesValueAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InterRATMeasurementQuantitiesValueAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return InterRATMeasurementQuantitiesValueAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c InterRATMeasurementQuantitiesValueValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (InterRATMeasurementQuantitiesValueAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return InterRATMeasurementQuantitiesValueAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return InterRATMeasurementQuantitiesValueAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return InterRATMeasurementQuantitiesValueAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return InterRATMeasurementQuantitiesValueAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return InterRATMeasurementQuantitiesValueAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c InterRATMeasurementQuantitiesValueValueCodec) EncodeAPER(value InterRATMeasurementQuantitiesValueAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c InterRATMeasurementQuantitiesValueValueCodec) encodeBudget(value InterRATMeasurementQuantitiesValue,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c InterRATMeasurementQuantitiesValueValueCodec) encodeChanged(value InterRATMeasurementQuantitiesValue,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// LPPATransactionIDValueCodec is the concrete ValueCodec[LPPATransactionID].
type LPPATransactionIDValueCodec struct {
	context BridgeCodecContext
	capture func(LPPATransactionID, q5.DecodeState,

	) (LPPATransactionID, q5.Snapshot,

	)
	compare func(LPPATransactionID, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (LPPATransactionID,

		error)
	encode func(LPPATransactionID,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c LPPATransactionIDValueCodec) New(value LPPATransactionID,

) (LPPATransactionIDAPERValue, error) {
	if c.encode == nil {
		return LPPATransactionIDAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return LPPATransactionIDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LPPATransactionIDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return LPPATransactionIDAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c LPPATransactionIDValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (LPPATransactionIDAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return LPPATransactionIDAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return LPPATransactionIDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return LPPATransactionIDAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return LPPATransactionIDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return LPPATransactionIDAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c LPPATransactionIDValueCodec) EncodeAPER(value LPPATransactionIDAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c LPPATransactionIDValueCodec) encodeBudget(value LPPATransactionID,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c LPPATransactionIDValueCodec) encodeChanged(value LPPATransactionID,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// MeasurementQuantitiesValueValueCodec is the concrete ValueCodec[MeasurementQuantitiesValue].
type MeasurementQuantitiesValueValueCodec struct {
	context BridgeCodecContext
	capture func(MeasurementQuantitiesValue, q5.DecodeState,

	) (MeasurementQuantitiesValue, q5.Snapshot,

	)
	compare func(MeasurementQuantitiesValue, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (MeasurementQuantitiesValue,

		error)
	encode func(MeasurementQuantitiesValue,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c MeasurementQuantitiesValueValueCodec) New(value MeasurementQuantitiesValue,

) (MeasurementQuantitiesValueAPERValue, error) {
	if c.encode == nil {
		return MeasurementQuantitiesValueAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return MeasurementQuantitiesValueAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MeasurementQuantitiesValueAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return MeasurementQuantitiesValueAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c MeasurementQuantitiesValueValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (MeasurementQuantitiesValueAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return MeasurementQuantitiesValueAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return MeasurementQuantitiesValueAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return MeasurementQuantitiesValueAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return MeasurementQuantitiesValueAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return MeasurementQuantitiesValueAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c MeasurementQuantitiesValueValueCodec) EncodeAPER(value MeasurementQuantitiesValueAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c MeasurementQuantitiesValueValueCodec) encodeBudget(value MeasurementQuantitiesValue,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c MeasurementQuantitiesValueValueCodec) encodeChanged(value MeasurementQuantitiesValue,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// NPRSSequenceInfoValueCodec is the concrete ValueCodec[NPRSSequenceInfo].
type NPRSSequenceInfoValueCodec struct {
	context BridgeCodecContext
	capture func(NPRSSequenceInfo, q5.DecodeState,

	) (NPRSSequenceInfo, q5.Snapshot,

	)
	compare func(NPRSSequenceInfo, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (NPRSSequenceInfo,

		error)
	encode func(NPRSSequenceInfo,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c NPRSSequenceInfoValueCodec) New(value NPRSSequenceInfo,

) (NPRSSequenceInfoAPERValue, error) {
	if c.encode == nil {
		return NPRSSequenceInfoAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return NPRSSequenceInfoAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NPRSSequenceInfoAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return NPRSSequenceInfoAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c NPRSSequenceInfoValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (NPRSSequenceInfoAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NPRSSequenceInfoAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return NPRSSequenceInfoAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NPRSSequenceInfoAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return NPRSSequenceInfoAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return NPRSSequenceInfoAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c NPRSSequenceInfoValueCodec) EncodeAPER(value NPRSSequenceInfoAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c NPRSSequenceInfoValueCodec) encodeBudget(value NPRSSequenceInfo,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NPRSSequenceInfoValueCodec) encodeChanged(value NPRSSequenceInfo,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// NRARFCNValueCodec is the concrete ValueCodec[NRARFCN].
type NRARFCNValueCodec struct {
	context BridgeCodecContext
	capture func(NRARFCN, q5.DecodeState,

	) (NRARFCN, q5.Snapshot,

	)
	compare func(NRARFCN, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (NRARFCN,

		error)
	encode func(NRARFCN,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c NRARFCNValueCodec) New(value NRARFCN,

) (NRARFCNAPERValue, error) {
	if c.encode == nil {
		return NRARFCNAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return NRARFCNAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRARFCNAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return NRARFCNAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c NRARFCNValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (NRARFCNAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NRARFCNAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return NRARFCNAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NRARFCNAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return NRARFCNAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return NRARFCNAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c NRARFCNValueCodec) EncodeAPER(value NRARFCNAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c NRARFCNValueCodec) encodeBudget(value NRARFCN,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NRARFCNValueCodec) encodeChanged(value NRARFCN,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// NRCellIdentityValueCodec is the concrete ValueCodec[NRCellIdentity].
type NRCellIdentityValueCodec struct {
	context BridgeCodecContext
	capture func(NRCellIdentity, q5.DecodeState,

	) (NRCellIdentity, q5.Snapshot,

	)
	compare func(NRCellIdentity, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (NRCellIdentity,

		error)
	encode func(NRCellIdentity,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c NRCellIdentityValueCodec) New(value NRCellIdentity,

) (NRCellIdentityAPERValue, error) {
	if c.encode == nil {
		return NRCellIdentityAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return NRCellIdentityAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRCellIdentityAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return NRCellIdentityAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c NRCellIdentityValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (NRCellIdentityAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NRCellIdentityAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return NRCellIdentityAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NRCellIdentityAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return NRCellIdentityAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return NRCellIdentityAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c NRCellIdentityValueCodec) EncodeAPER(value NRCellIdentityAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c NRCellIdentityValueCodec) encodeBudget(value NRCellIdentity,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NRCellIdentityValueCodec) encodeChanged(value NRCellIdentity,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// NRPCIValueCodec is the concrete ValueCodec[NRPCI].
type NRPCIValueCodec struct {
	context BridgeCodecContext
	capture func(NRPCI, q5.DecodeState,

	) (NRPCI, q5.Snapshot,

	)
	compare func(NRPCI, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (NRPCI,

		error)
	encode func(NRPCI,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c NRPCIValueCodec) New(value NRPCI,

) (NRPCIAPERValue, error) {
	if c.encode == nil {
		return NRPCIAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return NRPCIAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRPCIAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return NRPCIAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c NRPCIValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (NRPCIAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NRPCIAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return NRPCIAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NRPCIAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return NRPCIAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return NRPCIAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c NRPCIValueCodec) EncodeAPER(value NRPCIAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c NRPCIValueCodec) encodeBudget(value NRPCI,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NRPCIValueCodec) encodeChanged(value NRPCI,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// NarrowBandIndexValueCodec is the concrete ValueCodec[NarrowBandIndex].
type NarrowBandIndexValueCodec struct {
	context BridgeCodecContext
	capture func(NarrowBandIndex, q5.DecodeState,

	) (NarrowBandIndex, q5.Snapshot,

	)
	compare func(NarrowBandIndex, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (NarrowBandIndex,

		error)
	encode func(NarrowBandIndex,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c NarrowBandIndexValueCodec) New(value NarrowBandIndex,

) (NarrowBandIndexAPERValue, error) {
	if c.encode == nil {
		return NarrowBandIndexAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return NarrowBandIndexAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NarrowBandIndexAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return NarrowBandIndexAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c NarrowBandIndexValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (NarrowBandIndexAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NarrowBandIndexAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return NarrowBandIndexAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NarrowBandIndexAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return NarrowBandIndexAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return NarrowBandIndexAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c NarrowBandIndexValueCodec) EncodeAPER(value NarrowBandIndexAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c NarrowBandIndexValueCodec) encodeBudget(value NarrowBandIndex,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NarrowBandIndexValueCodec) encodeChanged(value NarrowBandIndex,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// NumberOfAntennaPortsValueCodec is the concrete ValueCodec[NumberOfAntennaPorts].
type NumberOfAntennaPortsValueCodec struct {
	context BridgeCodecContext
	capture func(NumberOfAntennaPorts, q5.DecodeState,

	) (NumberOfAntennaPorts, q5.Snapshot,

	)
	compare func(NumberOfAntennaPorts, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (NumberOfAntennaPorts,

		error)
	encode func(NumberOfAntennaPorts,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c NumberOfAntennaPortsValueCodec) New(value NumberOfAntennaPorts,

) (NumberOfAntennaPortsAPERValue, error) {
	if c.encode == nil {
		return NumberOfAntennaPortsAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return NumberOfAntennaPortsAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NumberOfAntennaPortsAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return NumberOfAntennaPortsAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c NumberOfAntennaPortsValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (NumberOfAntennaPortsAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NumberOfAntennaPortsAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return NumberOfAntennaPortsAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NumberOfAntennaPortsAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return NumberOfAntennaPortsAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return NumberOfAntennaPortsAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c NumberOfAntennaPortsValueCodec) EncodeAPER(value NumberOfAntennaPortsAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c NumberOfAntennaPortsValueCodec) encodeBudget(value NumberOfAntennaPorts,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NumberOfAntennaPortsValueCodec) encodeChanged(value NumberOfAntennaPorts,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// NumberOfDlFramesValueCodec is the concrete ValueCodec[NumberOfDlFrames].
type NumberOfDlFramesValueCodec struct {
	context BridgeCodecContext
	capture func(NumberOfDlFrames, q5.DecodeState,

	) (NumberOfDlFrames, q5.Snapshot,

	)
	compare func(NumberOfDlFrames, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (NumberOfDlFrames,

		error)
	encode func(NumberOfDlFrames,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c NumberOfDlFramesValueCodec) New(value NumberOfDlFrames,

) (NumberOfDlFramesAPERValue, error) {
	if c.encode == nil {
		return NumberOfDlFramesAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return NumberOfDlFramesAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NumberOfDlFramesAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return NumberOfDlFramesAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c NumberOfDlFramesValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (NumberOfDlFramesAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NumberOfDlFramesAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return NumberOfDlFramesAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NumberOfDlFramesAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return NumberOfDlFramesAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return NumberOfDlFramesAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c NumberOfDlFramesValueCodec) EncodeAPER(value NumberOfDlFramesAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c NumberOfDlFramesValueCodec) encodeBudget(value NumberOfDlFrames,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NumberOfDlFramesValueCodec) encodeChanged(value NumberOfDlFrames,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// NumberOfDlFramesExtendedValueCodec is the concrete ValueCodec[NumberOfDlFramesExtended].
type NumberOfDlFramesExtendedValueCodec struct {
	context BridgeCodecContext
	capture func(NumberOfDlFramesExtended, q5.DecodeState,

	) (NumberOfDlFramesExtended, q5.Snapshot,

	)
	compare func(NumberOfDlFramesExtended, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (NumberOfDlFramesExtended,

		error)
	encode func(NumberOfDlFramesExtended,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c NumberOfDlFramesExtendedValueCodec) New(value NumberOfDlFramesExtended,

) (NumberOfDlFramesExtendedAPERValue, error) {
	if c.encode == nil {
		return NumberOfDlFramesExtendedAPERValue{}, q5.OperationError(q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return NumberOfDlFramesExtendedAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NumberOfDlFramesExtendedAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return NumberOfDlFramesExtendedAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c NumberOfDlFramesExtendedValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (NumberOfDlFramesExtendedAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NumberOfDlFramesExtendedAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return NumberOfDlFramesExtendedAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NumberOfDlFramesExtendedAPERValue{}, q5.DecodeReport{}, q4.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return NumberOfDlFramesExtendedAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return NumberOfDlFramesExtendedAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c NumberOfDlFramesExtendedValueCodec) EncodeAPER(value NumberOfDlFramesExtendedAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q4.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c NumberOfDlFramesExtendedValueCodec) encodeBudget(value NumberOfDlFramesExtended,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NumberOfDlFramesExtendedValueCodec) encodeChanged(value NumberOfDlFramesExtended,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// BroadcastAPERValue is the concrete APERValue[Broadcast].
type BroadcastAPERValue struct {
	context BridgeCodecContext
	Value   Broadcast

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v BroadcastAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v BroadcastAPERValue) WithoutReplay() BroadcastAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasurementIDAPERValue is the concrete APERValue[MeasurementID].
type MeasurementIDAPERValue struct {
	context BridgeCodecContext
	Value   MeasurementID

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v MeasurementIDAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v MeasurementIDAPERValue) WithoutReplay() MeasurementIDAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasurementPeriodicityAPERValue is the concrete APERValue[MeasurementPeriodicity].
type MeasurementPeriodicityAPERValue struct {
	context BridgeCodecContext
	Value   MeasurementPeriodicity

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v MeasurementPeriodicityAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v MeasurementPeriodicityAPERValue) WithoutReplay() MeasurementPeriodicityAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// CellPortionIDAPERValue is the concrete APERValue[CellPortionID].
type CellPortionIDAPERValue struct {
	context BridgeCodecContext
	Value   CellPortionID

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v CellPortionIDAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v CellPortionIDAPERValue) WithoutReplay() CellPortionIDAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// BCCHAPERValue is the concrete APERValue[BCCH].
type BCCHAPERValue struct {
	context BridgeCodecContext
	Value   BCCH

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v BCCHAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v BCCHAPERValue) WithoutReplay() BCCHAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// BSSIDAPERValue is the concrete APERValue[BSSID].
type BSSIDAPERValue struct {
	context BridgeCodecContext
	Value   BSSID

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v BSSIDAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v BSSIDAPERValue) WithoutReplay() BSSIDAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// BroadcastPeriodicityAPERValue is the concrete APERValue[BroadcastPeriodicity].
type BroadcastPeriodicityAPERValue struct {
	context BridgeCodecContext
	Value   BroadcastPeriodicity

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v BroadcastPeriodicityAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v BroadcastPeriodicityAPERValue) WithoutReplay() BroadcastPeriodicityAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// CPLengthAPERValue is the concrete APERValue[CPLength].
type CPLengthAPERValue struct {
	context BridgeCodecContext
	Value   CPLength

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v CPLengthAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v CPLengthAPERValue) WithoutReplay() CPLengthAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// CauseMiscAPERValue is the concrete APERValue[CauseMisc].
type CauseMiscAPERValue struct {
	context BridgeCodecContext
	Value   CauseMisc

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v CauseMiscAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v CauseMiscAPERValue) WithoutReplay() CauseMiscAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// CauseProtocolAPERValue is the concrete APERValue[CauseProtocol].
type CauseProtocolAPERValue struct {
	context BridgeCodecContext
	Value   CauseProtocol

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v CauseProtocolAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v CauseProtocolAPERValue) WithoutReplay() CauseProtocolAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// CauseRadioNetworkAPERValue is the concrete APERValue[CauseRadioNetwork].
type CauseRadioNetworkAPERValue struct {
	context BridgeCodecContext
	Value   CauseRadioNetwork

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v CauseRadioNetworkAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v CauseRadioNetworkAPERValue) WithoutReplay() CauseRadioNetworkAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// CriticalityAPERValue is the concrete APERValue[Criticality].
type CriticalityAPERValue struct {
	context BridgeCodecContext
	Value   Criticality

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v CriticalityAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v CriticalityAPERValue) WithoutReplay() CriticalityAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// DLBandwidthAPERValue is the concrete APERValue[DLBandwidth].
type DLBandwidthAPERValue struct {
	context BridgeCodecContext
	Value   DLBandwidth

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v DLBandwidthAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v DLBandwidthAPERValue) WithoutReplay() DLBandwidthAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// EARFCNAPERValue is the concrete APERValue[EARFCN].
type EARFCNAPERValue struct {
	context BridgeCodecContext
	Value   EARFCN

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v EARFCNAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v EARFCNAPERValue) WithoutReplay() EARFCNAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// EUTRANCellIdentifierAPERValue is the concrete APERValue[EUTRANCellIdentifier].
type EUTRANCellIdentifierAPERValue struct {
	context BridgeCodecContext
	Value   EUTRANCellIdentifier

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v EUTRANCellIdentifierAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v EUTRANCellIdentifierAPERValue) WithoutReplay() EUTRANCellIdentifierAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// HESSIDAPERValue is the concrete APERValue[HESSID].
type HESSIDAPERValue struct {
	context BridgeCodecContext
	Value   HESSID

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v HESSIDAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v HESSIDAPERValue) WithoutReplay() HESSIDAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// InterRATMeasurementQuantitiesValueAPERValue is the concrete APERValue[InterRATMeasurementQuantitiesValue].
type InterRATMeasurementQuantitiesValueAPERValue struct {
	context BridgeCodecContext
	Value   InterRATMeasurementQuantitiesValue

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v InterRATMeasurementQuantitiesValueAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v InterRATMeasurementQuantitiesValueAPERValue) WithoutReplay() InterRATMeasurementQuantitiesValueAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// LPPATransactionIDAPERValue is the concrete APERValue[LPPATransactionID].
type LPPATransactionIDAPERValue struct {
	context BridgeCodecContext
	Value   LPPATransactionID

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v LPPATransactionIDAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v LPPATransactionIDAPERValue) WithoutReplay() LPPATransactionIDAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasurementQuantitiesValueAPERValue is the concrete APERValue[MeasurementQuantitiesValue].
type MeasurementQuantitiesValueAPERValue struct {
	context BridgeCodecContext
	Value   MeasurementQuantitiesValue

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v MeasurementQuantitiesValueAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v MeasurementQuantitiesValueAPERValue) WithoutReplay() MeasurementQuantitiesValueAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// NPRSSequenceInfoAPERValue is the concrete APERValue[NPRSSequenceInfo].
type NPRSSequenceInfoAPERValue struct {
	context BridgeCodecContext
	Value   NPRSSequenceInfo

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v NPRSSequenceInfoAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v NPRSSequenceInfoAPERValue) WithoutReplay() NPRSSequenceInfoAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRARFCNAPERValue is the concrete APERValue[NRARFCN].
type NRARFCNAPERValue struct {
	context BridgeCodecContext
	Value   NRARFCN

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v NRARFCNAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v NRARFCNAPERValue) WithoutReplay() NRARFCNAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRCellIdentityAPERValue is the concrete APERValue[NRCellIdentity].
type NRCellIdentityAPERValue struct {
	context BridgeCodecContext
	Value   NRCellIdentity

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v NRCellIdentityAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v NRCellIdentityAPERValue) WithoutReplay() NRCellIdentityAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRPCIAPERValue is the concrete APERValue[NRPCI].
type NRPCIAPERValue struct {
	context BridgeCodecContext
	Value   NRPCI

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v NRPCIAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v NRPCIAPERValue) WithoutReplay() NRPCIAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// NarrowBandIndexAPERValue is the concrete APERValue[NarrowBandIndex].
type NarrowBandIndexAPERValue struct {
	context BridgeCodecContext
	Value   NarrowBandIndex

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v NarrowBandIndexAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v NarrowBandIndexAPERValue) WithoutReplay() NarrowBandIndexAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// NumberOfAntennaPortsAPERValue is the concrete APERValue[NumberOfAntennaPorts].
type NumberOfAntennaPortsAPERValue struct {
	context BridgeCodecContext
	Value   NumberOfAntennaPorts

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v NumberOfAntennaPortsAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v NumberOfAntennaPortsAPERValue) WithoutReplay() NumberOfAntennaPortsAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// NumberOfDlFramesAPERValue is the concrete APERValue[NumberOfDlFrames].
type NumberOfDlFramesAPERValue struct {
	context BridgeCodecContext
	Value   NumberOfDlFrames

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v NumberOfDlFramesAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v NumberOfDlFramesAPERValue) WithoutReplay() NumberOfDlFramesAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// NumberOfDlFramesExtendedAPERValue is the concrete APERValue[NumberOfDlFramesExtended].
type NumberOfDlFramesExtendedAPERValue struct {
	context BridgeCodecContext
	Value   NumberOfDlFramesExtended

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v NumberOfDlFramesExtendedAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v NumberOfDlFramesExtendedAPERValue) WithoutReplay() NumberOfDlFramesExtendedAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

const (

	// MaxPrivateIEs is the integer constant for maxPrivateIEs.
	MaxPrivateIEs int64 = 65535

	// MaxProtocolExtensions is the integer constant for maxProtocolExtensions.
	MaxProtocolExtensions int64 = 65535

	// MaxProtocolIEs is the integer constant for maxProtocolIEs.
	MaxProtocolIEs int64 = 65535
)

// Criticality represents the ASN.1 ENUMERATED type Criticality.
type Criticality int64

const (
	CriticalityReject Criticality = 0
	CriticalityIgnore Criticality = 1
	CriticalityNotify Criticality = 2
)

func (v Criticality) String() string {
	switch v {
	case CriticalityReject:
		return "reject"
	case CriticalityIgnore:
		return "ignore"
	case CriticalityNotify:
		return "notify"
	default:
		return "unknown"
	}
}

// LPPATransactionID represents the ASN.1 type LPPATransactionID (INTEGER).
type LPPATransactionID = int64

// Presence represents the ASN.1 ENUMERATED type Presence.
type Presence int64

const (
	PresenceOptional    Presence = 0
	PresenceConditional Presence = 1
	PresenceMandatory   Presence = 2
)

func (v Presence) String() string {
	switch v {
	case PresenceOptional:
		return "optional"
	case PresenceConditional:
		return "conditional"
	case PresenceMandatory:
		return "mandatory"
	default:
		return "unknown"
	}
}

// PrivateIEID choice constants.
const (
	PrivateIEIDChoiceLocal  = 1
	PrivateIEIDChoiceGlobal = 2
)

// ProcedureCode represents the ASN.1 type ProcedureCode (INTEGER).
type ProcedureCode = int64

// ProtocolIEID represents the ASN.1 type ProtocolIE-ID (INTEGER).
type ProtocolIEID = int64

// TriggeringMessage represents the ASN.1 ENUMERATED type TriggeringMessage.
type TriggeringMessage int64

const (
	TriggeringMessageInitiatingMessage   TriggeringMessage = 0
	TriggeringMessageSuccessfulOutcome   TriggeringMessage = 1
	TriggeringMessageUnsuccessfulOutcome TriggeringMessage = 2
)

func (v TriggeringMessage) String() string {
	switch v {
	case TriggeringMessageInitiatingMessage:
		return "initiating-message"
	case TriggeringMessageSuccessfulOutcome:
		return "successful-outcome"
	case TriggeringMessageUnsuccessfulOutcome:
		return "unsuccessful-outcome"
	default:
		return "unknown"
	}
}

const (

	// IdErrorIndication is the integer constant for id-errorIndication.
	IdErrorIndication int64 = 0

	// IdPrivateMessage is the integer constant for id-privateMessage.
	IdPrivateMessage int64 = 1

	// IdECIDMeasurementInitiation is the integer constant for id-e-CIDMeasurementInitiation.
	IdECIDMeasurementInitiation int64 = 2

	// IdECIDMeasurementFailureIndication is the integer constant for id-e-CIDMeasurementFailureIndication.
	IdECIDMeasurementFailureIndication int64 = 3

	// IdECIDMeasurementReport is the integer constant for id-e-CIDMeasurementReport.
	IdECIDMeasurementReport int64 = 4

	// IdECIDMeasurementTermination is the integer constant for id-e-CIDMeasurementTermination.
	IdECIDMeasurementTermination int64 = 5

	// IdOTDOAInformationExchange is the integer constant for id-oTDOAInformationExchange.
	IdOTDOAInformationExchange int64 = 6

	// IdUTDOAInformationExchange is the integer constant for id-uTDOAInformationExchange.
	IdUTDOAInformationExchange int64 = 7

	// IdUTDOAInformationUpdate is the integer constant for id-uTDOAInformationUpdate.
	IdUTDOAInformationUpdate int64 = 8

	// IdAssistanceInformationControl is the integer constant for id-assistanceInformationControl.
	IdAssistanceInformationControl int64 = 9

	// IdAssistanceInformationFeedback is the integer constant for id-assistanceInformationFeedback.
	IdAssistanceInformationFeedback int64 = 10

	// MaxNrOfErrors is the integer constant for maxNrOfErrors.
	MaxNrOfErrors int64 = 256

	// MaxCellineNB is the integer constant for maxCellineNB.
	MaxCellineNB int64 = 256

	// MaxNoMeas is the integer constant for maxNoMeas.
	MaxNoMeas int64 = 63

	// MaxCellReport is the integer constant for maxCellReport.
	MaxCellReport int64 = 9

	// MaxnoOTDOAtypes is the integer constant for maxnoOTDOAtypes.
	MaxnoOTDOAtypes int64 = 63

	// MaxServCell is the integer constant for maxServCell.
	MaxServCell int64 = 5

	// MaxGERANMeas is the integer constant for maxGERANMeas.
	MaxGERANMeas int64 = 8

	// MaxUTRANMeas is the integer constant for maxUTRANMeas.
	MaxUTRANMeas int64 = 8

	// MaxCellineNBExt is the integer constant for maxCellineNB-ext.
	MaxCellineNBExt int64 = 3840

	// MaxMBSFNAllocations is the integer constant for maxMBSFN-Allocations.
	MaxMBSFNAllocations int64 = 8

	// MaxWLANchannels is the integer constant for maxWLANchannels.
	MaxWLANchannels int64 = 16

	// MaxnoFreqHoppingBandsMinusOne is the integer constant for maxnoFreqHoppingBandsMinusOne.
	MaxnoFreqHoppingBandsMinusOne int64 = 7

	// MaxNrOfPosSImessage is the integer constant for maxNrOfPosSImessage.
	MaxNrOfPosSImessage int64 = 32

	// MaxnoAssistInfoFailureListItems is the integer constant for maxnoAssistInfoFailureListItems.
	MaxnoAssistInfoFailureListItems int64 = 32

	// MaxNrOfSegments is the integer constant for maxNrOfSegments.
	MaxNrOfSegments int64 = 64

	// MaxNrOfPosSIBs is the integer constant for maxNrOfPosSIBs.
	MaxNrOfPosSIBs int64 = 32

	// MaxNRmeas is the integer constant for maxNRmeas.
	MaxNRmeas int64 = 32

	// MaxResultsPerSSBIndex is the integer constant for maxResultsPerSSBIndex.
	MaxResultsPerSSBIndex int64 = 64

	// IdCause is the integer constant for id-Cause.
	IdCause int64 = 0

	// IdCriticalityDiagnostics is the integer constant for id-CriticalityDiagnostics.
	IdCriticalityDiagnostics int64 = 1

	// IdESMLCUEMeasurementID is the integer constant for id-E-SMLC-UE-Measurement-ID.
	IdESMLCUEMeasurementID int64 = 2

	// IdReportCharacteristics is the integer constant for id-ReportCharacteristics.
	IdReportCharacteristics int64 = 3

	// IdMeasurementPeriodicity is the integer constant for id-MeasurementPeriodicity.
	IdMeasurementPeriodicity int64 = 4

	// IdMeasurementQuantities is the integer constant for id-MeasurementQuantities.
	IdMeasurementQuantities int64 = 5

	// IdENBUEMeasurementID is the integer constant for id-eNB-UE-Measurement-ID.
	IdENBUEMeasurementID int64 = 6

	// IdECIDMeasurementResult is the integer constant for id-E-CID-MeasurementResult.
	IdECIDMeasurementResult int64 = 7

	// IdOTDOACells is the integer constant for id-OTDOACells.
	IdOTDOACells int64 = 8

	// IdOTDOAInformationTypeGroup is the integer constant for id-OTDOA-Information-Type-Group.
	IdOTDOAInformationTypeGroup int64 = 9

	// IdOTDOAInformationTypeItem is the integer constant for id-OTDOA-Information-Type-Item.
	IdOTDOAInformationTypeItem int64 = 10

	// IdMeasurementQuantitiesItem is the integer constant for id-MeasurementQuantities-Item.
	IdMeasurementQuantitiesItem int64 = 11

	// IdRequestedSRSTransmissionCharacteristics is the integer constant for id-RequestedSRSTransmissionCharacteristics.
	IdRequestedSRSTransmissionCharacteristics int64 = 12

	// IdULConfiguration is the integer constant for id-ULConfiguration.
	IdULConfiguration int64 = 13

	// IdCellPortionID is the integer constant for id-Cell-Portion-ID.
	IdCellPortionID int64 = 14

	// IdInterRATMeasurementQuantities is the integer constant for id-InterRATMeasurementQuantities.
	IdInterRATMeasurementQuantities int64 = 15

	// IdInterRATMeasurementQuantitiesItem is the integer constant for id-InterRATMeasurementQuantities-Item.
	IdInterRATMeasurementQuantitiesItem int64 = 16

	// IdInterRATMeasurementResult is the integer constant for id-InterRATMeasurementResult.
	IdInterRATMeasurementResult int64 = 17

	// IdAddOTDOACells is the integer constant for id-AddOTDOACells.
	IdAddOTDOACells int64 = 18

	// IdWLANMeasurementQuantities is the integer constant for id-WLANMeasurementQuantities.
	IdWLANMeasurementQuantities int64 = 19

	// IdWLANMeasurementQuantitiesItem is the integer constant for id-WLANMeasurementQuantities-Item.
	IdWLANMeasurementQuantitiesItem int64 = 20

	// IdWLANMeasurementResult is the integer constant for id-WLANMeasurementResult.
	IdWLANMeasurementResult int64 = 21

	// IdAssistanceInformation is the integer constant for id-Assistance-Information.
	IdAssistanceInformation int64 = 22

	// IdBroadcast is the integer constant for id-Broadcast.
	IdBroadcast int64 = 23

	// IdAssistanceInformationFailureList is the integer constant for id-AssistanceInformationFailureList.
	IdAssistanceInformationFailureList int64 = 24

	// IdResultsPerSSBIndexList is the integer constant for id-ResultsPerSSB-Index-List.
	IdResultsPerSSBIndexList int64 = 25

	// IdResultsPerSSBIndexItem is the integer constant for id-ResultsPerSSB-Index-Item.
	IdResultsPerSSBIndexItem int64 = 26

	// IdNRCGI is the integer constant for id-NR-CGI.
	IdNRCGI int64 = 27
)

// BCCH represents the ASN.1 type BCCH (INTEGER).
type BCCH = *q6.Int

// BitmapsforNPRS choice constants.
const (
	BitmapsforNPRSChoiceTen      = 1
	BitmapsforNPRSChoiceForty    = 2
	BitmapsforNPRSChoiceTenTdd   = 3
	BitmapsforNPRSChoiceFortyTdd = 4
)

// Broadcast represents the ASN.1 ENUMERATED type Broadcast.
type Broadcast int64

const (
	BroadcastStart Broadcast = 0
	BroadcastStop  Broadcast = 1
)

func (v Broadcast) String() string {
	switch v {
	case BroadcastStart:
		return "start"
	case BroadcastStop:
		return "stop"
	default:
		return "unknown"
	}
}

// BroadcastPeriodicity represents the ASN.1 ENUMERATED type BroadcastPeriodicity.
type BroadcastPeriodicity int64

const (
	BroadcastPeriodicityMs80   BroadcastPeriodicity = 0
	BroadcastPeriodicityMs160  BroadcastPeriodicity = 1
	BroadcastPeriodicityMs320  BroadcastPeriodicity = 2
	BroadcastPeriodicityMs640  BroadcastPeriodicity = 3
	BroadcastPeriodicityMs1280 BroadcastPeriodicity = 4
	BroadcastPeriodicityMs2560 BroadcastPeriodicity = 5
	BroadcastPeriodicityMs5120 BroadcastPeriodicity = 6
)

func (v BroadcastPeriodicity) String() string {
	switch v {
	case BroadcastPeriodicityMs80:
		return "ms80"
	case BroadcastPeriodicityMs160:
		return "ms160"
	case BroadcastPeriodicityMs320:
		return "ms320"
	case BroadcastPeriodicityMs640:
		return "ms640"
	case BroadcastPeriodicityMs1280:
		return "ms1280"
	case BroadcastPeriodicityMs2560:
		return "ms2560"
	case BroadcastPeriodicityMs5120:
		return "ms5120"
	default:
		return "unknown"
	}
}

// BSSID represents the ASN.1 type BSSID (OCTET_STRING).
type BSSID = []byte

// Cause choice constants.
const (
	CauseChoiceRadioNetwork = 1
	CauseChoiceProtocol     = 2
	CauseChoiceMisc         = 3
)

// CauseMisc represents the ASN.1 ENUMERATED type CauseMisc.
type CauseMisc int64

const (
	CauseMiscUnspecified CauseMisc = 0
)

func (v CauseMisc) String() string {
	switch v {
	case CauseMiscUnspecified:
		return "unspecified"
	default:
		return "unknown"
	}
}

// CauseProtocol represents the ASN.1 ENUMERATED type CauseProtocol.
type CauseProtocol int64

const (
	CauseProtocolTransferSyntaxError                          CauseProtocol = 0
	CauseProtocolAbstractSyntaxErrorReject                    CauseProtocol = 1
	CauseProtocolAbstractSyntaxErrorIgnoreAndNotify           CauseProtocol = 2
	CauseProtocolMessageNotCompatibleWithReceiverState        CauseProtocol = 3
	CauseProtocolSemanticError                                CauseProtocol = 4
	CauseProtocolUnspecified                                  CauseProtocol = 5
	CauseProtocolAbstractSyntaxErrorFalselyConstructedMessage CauseProtocol = 6
)

func (v CauseProtocol) String() string {
	switch v {
	case CauseProtocolTransferSyntaxError:
		return "transfer-syntax-error"
	case CauseProtocolAbstractSyntaxErrorReject:
		return "abstract-syntax-error-reject"
	case CauseProtocolAbstractSyntaxErrorIgnoreAndNotify:
		return "abstract-syntax-error-ignore-and-notify"
	case CauseProtocolMessageNotCompatibleWithReceiverState:
		return "message-not-compatible-with-receiver-state"
	case CauseProtocolSemanticError:
		return "semantic-error"
	case CauseProtocolUnspecified:
		return "unspecified"
	case CauseProtocolAbstractSyntaxErrorFalselyConstructedMessage:
		return "abstract-syntax-error-falsely-constructed-message"
	default:
		return "unknown"
	}
}

// CauseRadioNetwork represents the ASN.1 ENUMERATED type CauseRadioNetwork.
type CauseRadioNetwork int64

const (
	CauseRadioNetworkUnspecified                          CauseRadioNetwork = 0
	CauseRadioNetworkRequestedItemNotSupported            CauseRadioNetwork = 1
	CauseRadioNetworkRequestedItemTemporarilyNotAvailable CauseRadioNetwork = 2
)

func (v CauseRadioNetwork) String() string {
	switch v {
	case CauseRadioNetworkUnspecified:
		return "unspecified"
	case CauseRadioNetworkRequestedItemNotSupported:
		return "requested-item-not-supported"
	case CauseRadioNetworkRequestedItemTemporarilyNotAvailable:
		return "requested-item-temporarily-not-available"
	default:
		return "unknown"
	}
}

// CellPortionID represents the ASN.1 type Cell-Portion-ID (INTEGER).
type CellPortionID = *q6.Int

// CPLength represents the ASN.1 ENUMERATED type CPLength.
type CPLength int64

const (
	CPLengthNormal   CPLength = 0
	CPLengthExtended CPLength = 1
)

func (v CPLength) String() string {
	switch v {
	case CPLengthNormal:
		return "normal"
	case CPLengthExtended:
		return "extended"
	default:
		return "unknown"
	}
}

// DLBandwidth represents the ASN.1 ENUMERATED type DL-Bandwidth.
type DLBandwidth int64

const (
	DLBandwidthBw6   DLBandwidth = 0
	DLBandwidthBw15  DLBandwidth = 1
	DLBandwidthBw25  DLBandwidth = 2
	DLBandwidthBw50  DLBandwidth = 3
	DLBandwidthBw75  DLBandwidth = 4
	DLBandwidthBw100 DLBandwidth = 5
)

func (v DLBandwidth) String() string {
	switch v {
	case DLBandwidthBw6:
		return "bw6"
	case DLBandwidthBw15:
		return "bw15"
	case DLBandwidthBw25:
		return "bw25"
	case DLBandwidthBw50:
		return "bw50"
	case DLBandwidthBw75:
		return "bw75"
	case DLBandwidthBw100:
		return "bw100"
	default:
		return "unknown"
	}
}

// EUTRANCellIdentifier represents the ASN.1 type EUTRANCellIdentifier (BIT_STRING).
type EUTRANCellIdentifier = q7.BitString

// EARFCN represents the ASN.1 type EARFCN (INTEGER).
type EARFCN = *q6.Int

// HESSID represents the ASN.1 type HESSID (OCTET_STRING).
type HESSID = []byte

// InterRATMeasurementQuantitiesValue represents the ASN.1 ENUMERATED type InterRATMeasurementQuantitiesValue.
type InterRATMeasurementQuantitiesValue int64

const (
	InterRATMeasurementQuantitiesValueGeran InterRATMeasurementQuantitiesValue = 0
	InterRATMeasurementQuantitiesValueUtran InterRATMeasurementQuantitiesValue = 1
	InterRATMeasurementQuantitiesValueNr    InterRATMeasurementQuantitiesValue = 2
)

func (v InterRATMeasurementQuantitiesValue) String() string {
	switch v {
	case InterRATMeasurementQuantitiesValueGeran:
		return "geran"
	case InterRATMeasurementQuantitiesValueUtran:
		return "utran"
	case InterRATMeasurementQuantitiesValueNr:
		return "nr"
	default:
		return "unknown"
	}
}

// InterRATMeasuredResultsValue choice constants.
const (
	InterRATMeasuredResultsValueChoiceResultGERAN = 1
	InterRATMeasuredResultsValueChoiceResultUTRAN = 2
	InterRATMeasuredResultsValueChoiceResultNR    = 3
)

// MeasurementID represents the ASN.1 type Measurement-ID (INTEGER).
type MeasurementID = *q6.Int

// MeasurementPeriodicity represents the ASN.1 ENUMERATED type MeasurementPeriodicity.
type MeasurementPeriodicity int64

const (
	MeasurementPeriodicityMs120   MeasurementPeriodicity = 0
	MeasurementPeriodicityMs240   MeasurementPeriodicity = 1
	MeasurementPeriodicityMs480   MeasurementPeriodicity = 2
	MeasurementPeriodicityMs640   MeasurementPeriodicity = 3
	MeasurementPeriodicityMs1024  MeasurementPeriodicity = 4
	MeasurementPeriodicityMs2048  MeasurementPeriodicity = 5
	MeasurementPeriodicityMs5120  MeasurementPeriodicity = 6
	MeasurementPeriodicityMs10240 MeasurementPeriodicity = 7
	MeasurementPeriodicityMin1    MeasurementPeriodicity = 8
	MeasurementPeriodicityMin6    MeasurementPeriodicity = 9
	MeasurementPeriodicityMin12   MeasurementPeriodicity = 10
	MeasurementPeriodicityMin30   MeasurementPeriodicity = 11
	MeasurementPeriodicityMin60   MeasurementPeriodicity = 12
)

func (v MeasurementPeriodicity) String() string {
	switch v {
	case MeasurementPeriodicityMs120:
		return "ms120"
	case MeasurementPeriodicityMs240:
		return "ms240"
	case MeasurementPeriodicityMs480:
		return "ms480"
	case MeasurementPeriodicityMs640:
		return "ms640"
	case MeasurementPeriodicityMs1024:
		return "ms1024"
	case MeasurementPeriodicityMs2048:
		return "ms2048"
	case MeasurementPeriodicityMs5120:
		return "ms5120"
	case MeasurementPeriodicityMs10240:
		return "ms10240"
	case MeasurementPeriodicityMin1:
		return "min1"
	case MeasurementPeriodicityMin6:
		return "min6"
	case MeasurementPeriodicityMin12:
		return "min12"
	case MeasurementPeriodicityMin30:
		return "min30"
	case MeasurementPeriodicityMin60:
		return "min60"
	default:
		return "unknown"
	}
}

// MeasurementQuantitiesValue represents the ASN.1 ENUMERATED type MeasurementQuantitiesValue.
type MeasurementQuantitiesValue int64

const (
	MeasurementQuantitiesValueCellID             MeasurementQuantitiesValue = 0
	MeasurementQuantitiesValueAngleOfArrival     MeasurementQuantitiesValue = 1
	MeasurementQuantitiesValueTimingAdvanceType1 MeasurementQuantitiesValue = 2
	MeasurementQuantitiesValueTimingAdvanceType2 MeasurementQuantitiesValue = 3
	MeasurementQuantitiesValueRSRP               MeasurementQuantitiesValue = 4
	MeasurementQuantitiesValueRSRQ               MeasurementQuantitiesValue = 5
)

func (v MeasurementQuantitiesValue) String() string {
	switch v {
	case MeasurementQuantitiesValueCellID:
		return "cell-ID"
	case MeasurementQuantitiesValueAngleOfArrival:
		return "angleOfArrival"
	case MeasurementQuantitiesValueTimingAdvanceType1:
		return "timingAdvanceType1"
	case MeasurementQuantitiesValueTimingAdvanceType2:
		return "timingAdvanceType2"
	case MeasurementQuantitiesValueRSRP:
		return "rSRP"
	case MeasurementQuantitiesValueRSRQ:
		return "rSRQ"
	default:
		return "unknown"
	}
}

// MeasuredResultsValue choice constants.
const (
	MeasuredResultsValueChoiceValueAngleOfArrival     = 1
	MeasuredResultsValueChoiceValueTimingAdvanceType1 = 2
	MeasuredResultsValueChoiceValueTimingAdvanceType2 = 3
	MeasuredResultsValueChoiceResultRSRP              = 4
	MeasuredResultsValueChoiceResultRSRQ              = 5
)

// NarrowBandIndex represents the ASN.1 type NarrowBandIndex (INTEGER).
type NarrowBandIndex = *q6.Int

// NRCellIdentity represents the ASN.1 type NRCellIdentity (BIT_STRING).
type NRCellIdentity = q7.BitString

// NPRSMutingConfiguration choice constants.
const (
	NPRSMutingConfigurationChoiceTwo     = 1
	NPRSMutingConfigurationChoiceFour    = 2
	NPRSMutingConfigurationChoiceEight   = 3
	NPRSMutingConfigurationChoiceSixteen = 4
)

// NumberOfAntennaPorts represents the ASN.1 ENUMERATED type NumberOfAntennaPorts.
type NumberOfAntennaPorts int64

const (
	NumberOfAntennaPortsN1OrN2 NumberOfAntennaPorts = 0
	NumberOfAntennaPortsN4     NumberOfAntennaPorts = 1
)

func (v NumberOfAntennaPorts) String() string {
	switch v {
	case NumberOfAntennaPortsN1OrN2:
		return "n1-or-n2"
	case NumberOfAntennaPortsN4:
		return "n4"
	default:
		return "unknown"
	}
}

// NumberOfDlFrames represents the ASN.1 ENUMERATED type NumberOfDlFrames.
type NumberOfDlFrames int64

const (
	NumberOfDlFramesSf1 NumberOfDlFrames = 0
	NumberOfDlFramesSf2 NumberOfDlFrames = 1
	NumberOfDlFramesSf4 NumberOfDlFrames = 2
	NumberOfDlFramesSf6 NumberOfDlFrames = 3
)

func (v NumberOfDlFrames) String() string {
	switch v {
	case NumberOfDlFramesSf1:
		return "sf1"
	case NumberOfDlFramesSf2:
		return "sf2"
	case NumberOfDlFramesSf4:
		return "sf4"
	case NumberOfDlFramesSf6:
		return "sf6"
	default:
		return "unknown"
	}
}

// NumberOfDlFramesExtended represents the ASN.1 type NumberOfDlFrames-Extended (INTEGER).
type NumberOfDlFramesExtended = *q6.Int

// NumberOfFrequencyHoppingBands represents the ASN.1 ENUMERATED type NumberOfFrequencyHoppingBands.
type NumberOfFrequencyHoppingBands int64

const (
	NumberOfFrequencyHoppingBandsTwobands  NumberOfFrequencyHoppingBands = 0
	NumberOfFrequencyHoppingBandsFourbands NumberOfFrequencyHoppingBands = 1
)

func (v NumberOfFrequencyHoppingBands) String() string {
	switch v {
	case NumberOfFrequencyHoppingBandsTwobands:
		return "twobands"
	case NumberOfFrequencyHoppingBandsFourbands:
		return "fourbands"
	default:
		return "unknown"
	}
}

// NPRSSequenceInfo represents the ASN.1 type NPRSSequenceInfo (INTEGER).
type NPRSSequenceInfo = *q6.Int

// NRARFCN represents the ASN.1 type NRARFCN (INTEGER).
type NRARFCN = int64

// NRPCI represents the ASN.1 type NRPCI (INTEGER).
type NRPCI = int64

// OffsetNBChanneltoEARFCN represents the ASN.1 ENUMERATED type OffsetNBChanneltoEARFCN.
type OffsetNBChanneltoEARFCN int64

const (
	OffsetNBChanneltoEARFCNMinusTen         OffsetNBChanneltoEARFCN = 0
	OffsetNBChanneltoEARFCNMinusNine        OffsetNBChanneltoEARFCN = 1
	OffsetNBChanneltoEARFCNMinusEight       OffsetNBChanneltoEARFCN = 2
	OffsetNBChanneltoEARFCNMinusSeven       OffsetNBChanneltoEARFCN = 3
	OffsetNBChanneltoEARFCNMinusSix         OffsetNBChanneltoEARFCN = 4
	OffsetNBChanneltoEARFCNMinusFive        OffsetNBChanneltoEARFCN = 5
	OffsetNBChanneltoEARFCNMinusFour        OffsetNBChanneltoEARFCN = 6
	OffsetNBChanneltoEARFCNMinusThree       OffsetNBChanneltoEARFCN = 7
	OffsetNBChanneltoEARFCNMinusTwo         OffsetNBChanneltoEARFCN = 8
	OffsetNBChanneltoEARFCNMinusOne         OffsetNBChanneltoEARFCN = 9
	OffsetNBChanneltoEARFCNMinusZeroDotFive OffsetNBChanneltoEARFCN = 10
	OffsetNBChanneltoEARFCNZero             OffsetNBChanneltoEARFCN = 11
	OffsetNBChanneltoEARFCNOne              OffsetNBChanneltoEARFCN = 12
	OffsetNBChanneltoEARFCNTwo              OffsetNBChanneltoEARFCN = 13
	OffsetNBChanneltoEARFCNThree            OffsetNBChanneltoEARFCN = 14
	OffsetNBChanneltoEARFCNFour             OffsetNBChanneltoEARFCN = 15
	OffsetNBChanneltoEARFCNFive             OffsetNBChanneltoEARFCN = 16
	OffsetNBChanneltoEARFCNSix              OffsetNBChanneltoEARFCN = 17
	OffsetNBChanneltoEARFCNSeven            OffsetNBChanneltoEARFCN = 18
	OffsetNBChanneltoEARFCNEight            OffsetNBChanneltoEARFCN = 19
	OffsetNBChanneltoEARFCNNine             OffsetNBChanneltoEARFCN = 20
)

func (v OffsetNBChanneltoEARFCN) String() string {
	switch v {
	case OffsetNBChanneltoEARFCNMinusTen:
		return "minusTen"
	case OffsetNBChanneltoEARFCNMinusNine:
		return "minusNine"
	case OffsetNBChanneltoEARFCNMinusEight:
		return "minusEight"
	case OffsetNBChanneltoEARFCNMinusSeven:
		return "minusSeven"
	case OffsetNBChanneltoEARFCNMinusSix:
		return "minusSix"
	case OffsetNBChanneltoEARFCNMinusFive:
		return "minusFive"
	case OffsetNBChanneltoEARFCNMinusFour:
		return "minusFour"
	case OffsetNBChanneltoEARFCNMinusThree:
		return "minusThree"
	case OffsetNBChanneltoEARFCNMinusTwo:
		return "minusTwo"
	case OffsetNBChanneltoEARFCNMinusOne:
		return "minusOne"
	case OffsetNBChanneltoEARFCNMinusZeroDotFive:
		return "minusZeroDotFive"
	case OffsetNBChanneltoEARFCNZero:
		return "zero"
	case OffsetNBChanneltoEARFCNOne:
		return "one"
	case OffsetNBChanneltoEARFCNTwo:
		return "two"
	case OffsetNBChanneltoEARFCNThree:
		return "three"
	case OffsetNBChanneltoEARFCNFour:
		return "four"
	case OffsetNBChanneltoEARFCNFive:
		return "five"
	case OffsetNBChanneltoEARFCNSix:
		return "six"
	case OffsetNBChanneltoEARFCNSeven:
		return "seven"
	case OffsetNBChanneltoEARFCNEight:
		return "eight"
	case OffsetNBChanneltoEARFCNNine:
		return "nine"
	default:
		return "unknown"
	}
}

// OperationModeInfo represents the ASN.1 ENUMERATED type OperationModeInfo.
type OperationModeInfo int64

const (
	OperationModeInfoInband     OperationModeInfo = 0
	OperationModeInfoGuardband  OperationModeInfo = 1
	OperationModeInfoStandalone OperationModeInfo = 2
)

func (v OperationModeInfo) String() string {
	switch v {
	case OperationModeInfoInband:
		return "inband"
	case OperationModeInfoGuardband:
		return "guardband"
	case OperationModeInfoStandalone:
		return "standalone"
	default:
		return "unknown"
	}
}

// OTDOACellInformationItem choice constants.
const (
	OTDOACellInformationItemChoicePCI                        = 1
	OTDOACellInformationItemChoiceCellId                     = 2
	OTDOACellInformationItemChoiceTAC                        = 3
	OTDOACellInformationItemChoiceEARFCN                     = 4
	OTDOACellInformationItemChoicePRSBandwidth               = 5
	OTDOACellInformationItemChoicePRSConfigurationIndex      = 6
	OTDOACellInformationItemChoiceCPLength                   = 7
	OTDOACellInformationItemChoiceNumberOfDlFrames           = 8
	OTDOACellInformationItemChoiceNumberOfAntennaPorts       = 9
	OTDOACellInformationItemChoiceSFNInitialisationTime      = 10
	OTDOACellInformationItemChoiceEUTRANAccessPointPosition  = 11
	OTDOACellInformationItemChoicePRSMutingConfiguration     = 12
	OTDOACellInformationItemChoicePrsid                      = 13
	OTDOACellInformationItemChoiceTpid                       = 14
	OTDOACellInformationItemChoiceTpType                     = 15
	OTDOACellInformationItemChoiceNumberOfDlFramesExtended   = 16
	OTDOACellInformationItemChoiceCrsCPlength                = 17
	OTDOACellInformationItemChoiceMBSFNsubframeConfiguration = 18
	OTDOACellInformationItemChoiceNPRSConfiguration          = 19
	OTDOACellInformationItemChoiceOffsetNBChanneltoEARFCN    = 20
	OTDOACellInformationItemChoiceOperationModeInfo          = 21
	OTDOACellInformationItemChoiceNPRSID                     = 22
	OTDOACellInformationItemChoiceDLBandwidth                = 23
	OTDOACellInformationItemChoicePRSOccasionGroup           = 24
	OTDOACellInformationItemChoicePRSFreqHoppingConfig       = 25
	OTDOACellInformationItemChoiceRepetitionNumberofSIB1NB   = 26
	OTDOACellInformationItemChoiceNPRSSequenceInfo           = 27
	OTDOACellInformationItemChoiceNPRSType2                  = 28
	OTDOACellInformationItemChoiceTddConfiguration           = 29
)

// OTDOAInformationItem represents the ASN.1 ENUMERATED type OTDOA-Information-Item.
type OTDOAInformationItem int64

const (
	OTDOAInformationItemPci                              OTDOAInformationItem = 0
	OTDOAInformationItemCellid                           OTDOAInformationItem = 1
	OTDOAInformationItemTac                              OTDOAInformationItem = 2
	OTDOAInformationItemEarfcn                           OTDOAInformationItem = 3
	OTDOAInformationItemPrsBandwidth                     OTDOAInformationItem = 4
	OTDOAInformationItemPrsConfigIndex                   OTDOAInformationItem = 5
	OTDOAInformationItemCpLength                         OTDOAInformationItem = 6
	OTDOAInformationItemNoDlFrames                       OTDOAInformationItem = 7
	OTDOAInformationItemNoAntennaPorts                   OTDOAInformationItem = 8
	OTDOAInformationItemSFNInitTime                      OTDOAInformationItem = 9
	OTDOAInformationItemEUTRANAccessPointPosition        OTDOAInformationItem = 10
	OTDOAInformationItemPrsmutingconfiguration           OTDOAInformationItem = 11
	OTDOAInformationItemPrsid                            OTDOAInformationItem = 12
	OTDOAInformationItemTpid                             OTDOAInformationItem = 13
	OTDOAInformationItemTpType                           OTDOAInformationItem = 14
	OTDOAInformationItemCrsCPlength                      OTDOAInformationItem = 15
	OTDOAInformationItemMBSFNsubframeConfiguration       OTDOAInformationItem = 16
	OTDOAInformationItemNPRSConfiguration                OTDOAInformationItem = 17
	OTDOAInformationItemOffsetNBChannelNumbertoEARFCN    OTDOAInformationItem = 18
	OTDOAInformationItemOperationModeInfo                OTDOAInformationItem = 19
	OTDOAInformationItemNPRSID                           OTDOAInformationItem = 20
	OTDOAInformationItemDlBandwidth                      OTDOAInformationItem = 21
	OTDOAInformationItemMultipleprsConfigurationsperCell OTDOAInformationItem = 22
	OTDOAInformationItemPrsOccasionGroup                 OTDOAInformationItem = 23
	OTDOAInformationItemPrsFrequencyHoppingConfiguration OTDOAInformationItem = 24
	OTDOAInformationItemRepetitionNumberofSIB1NB         OTDOAInformationItem = 25
	OTDOAInformationItemNPRSSequenceInfo                 OTDOAInformationItem = 26
	OTDOAInformationItemNPRSType2                        OTDOAInformationItem = 27
	OTDOAInformationItemTddConfig                        OTDOAInformationItem = 28
)

func (v OTDOAInformationItem) String() string {
	switch v {
	case OTDOAInformationItemPci:
		return "pci"
	case OTDOAInformationItemCellid:
		return "cellid"
	case OTDOAInformationItemTac:
		return "tac"
	case OTDOAInformationItemEarfcn:
		return "earfcn"
	case OTDOAInformationItemPrsBandwidth:
		return "prsBandwidth"
	case OTDOAInformationItemPrsConfigIndex:
		return "prsConfigIndex"
	case OTDOAInformationItemCpLength:
		return "cpLength"
	case OTDOAInformationItemNoDlFrames:
		return "noDlFrames"
	case OTDOAInformationItemNoAntennaPorts:
		return "noAntennaPorts"
	case OTDOAInformationItemSFNInitTime:
		return "sFNInitTime"
	case OTDOAInformationItemEUTRANAccessPointPosition:
		return "e-UTRANAccessPointPosition"
	case OTDOAInformationItemPrsmutingconfiguration:
		return "prsmutingconfiguration"
	case OTDOAInformationItemPrsid:
		return "prsid"
	case OTDOAInformationItemTpid:
		return "tpid"
	case OTDOAInformationItemTpType:
		return "tpType"
	case OTDOAInformationItemCrsCPlength:
		return "crsCPlength"
	case OTDOAInformationItemMBSFNsubframeConfiguration:
		return "mBSFNsubframeConfiguration"
	case OTDOAInformationItemNPRSConfiguration:
		return "nPRSConfiguration"
	case OTDOAInformationItemOffsetNBChannelNumbertoEARFCN:
		return "offsetNBChannelNumbertoEARFCN"
	case OTDOAInformationItemOperationModeInfo:
		return "operationModeInfo"
	case OTDOAInformationItemNPRSID:
		return "nPRS-ID"
	case OTDOAInformationItemDlBandwidth:
		return "dlBandwidth"
	case OTDOAInformationItemMultipleprsConfigurationsperCell:
		return "multipleprsConfigurationsperCell"
	case OTDOAInformationItemPrsOccasionGroup:
		return "prsOccasionGroup"
	case OTDOAInformationItemPrsFrequencyHoppingConfiguration:
		return "prsFrequencyHoppingConfiguration"
	case OTDOAInformationItemRepetitionNumberofSIB1NB:
		return "repetitionNumberofSIB1-NB"
	case OTDOAInformationItemNPRSSequenceInfo:
		return "nPRSSequenceInfo"
	case OTDOAInformationItemNPRSType2:
		return "nPRSType2"
	case OTDOAInformationItemTddConfig:
		return "tddConfig"
	default:
		return "unknown"
	}
}

// Outcome represents the ASN.1 ENUMERATED type Outcome.
type Outcome int64

const (
	OutcomeFailed Outcome = 0
)

func (v Outcome) String() string {
	switch v {
	case OutcomeFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// PCI represents the ASN.1 type PCI (INTEGER).
type PCI = *q6.Int

// PhysCellIDGERAN represents the ASN.1 type PhysCellIDGERAN (INTEGER).
type PhysCellIDGERAN = *q6.Int

// PhysCellIDUTRAFDD represents the ASN.1 type PhysCellIDUTRA-FDD (INTEGER).
type PhysCellIDUTRAFDD = *q6.Int

// PhysCellIDUTRATDD represents the ASN.1 type PhysCellIDUTRA-TDD (INTEGER).
type PhysCellIDUTRATDD = *q6.Int

// PLMNIdentity represents the ASN.1 type PLMN-Identity (OCTET_STRING).
type PLMNIdentity = []byte

// PosSIBType represents the ASN.1 ENUMERATED type PosSIB-Type.
type PosSIBType int64

const (
	PosSIBTypePosSibType11  PosSIBType = 0
	PosSIBTypePosSibType12  PosSIBType = 1
	PosSIBTypePosSibType13  PosSIBType = 2
	PosSIBTypePosSibType14  PosSIBType = 3
	PosSIBTypePosSibType15  PosSIBType = 4
	PosSIBTypePosSibType16  PosSIBType = 5
	PosSIBTypePosSibType17  PosSIBType = 6
	PosSIBTypePosSibType21  PosSIBType = 7
	PosSIBTypePosSibType22  PosSIBType = 8
	PosSIBTypePosSibType23  PosSIBType = 9
	PosSIBTypePosSibType24  PosSIBType = 10
	PosSIBTypePosSibType25  PosSIBType = 11
	PosSIBTypePosSibType26  PosSIBType = 12
	PosSIBTypePosSibType27  PosSIBType = 13
	PosSIBTypePosSibType28  PosSIBType = 14
	PosSIBTypePosSibType29  PosSIBType = 15
	PosSIBTypePosSibType210 PosSIBType = 16
	PosSIBTypePosSibType211 PosSIBType = 17
	PosSIBTypePosSibType212 PosSIBType = 18
	PosSIBTypePosSibType213 PosSIBType = 19
	PosSIBTypePosSibType214 PosSIBType = 20
	PosSIBTypePosSibType215 PosSIBType = 21
	PosSIBTypePosSibType216 PosSIBType = 22
	PosSIBTypePosSibType217 PosSIBType = 23
	PosSIBTypePosSibType218 PosSIBType = 24
	PosSIBTypePosSibType219 PosSIBType = 25
	PosSIBTypePosSibType31  PosSIBType = 26
	PosSIBTypePosSibType41  PosSIBType = 27
	PosSIBTypePosSibType51  PosSIBType = 28
	PosSIBTypePosSibType224 PosSIBType = 29
	PosSIBTypePosSibType225 PosSIBType = 30
)

func (v PosSIBType) String() string {
	switch v {
	case PosSIBTypePosSibType11:
		return "posSibType1-1"
	case PosSIBTypePosSibType12:
		return "posSibType1-2"
	case PosSIBTypePosSibType13:
		return "posSibType1-3"
	case PosSIBTypePosSibType14:
		return "posSibType1-4"
	case PosSIBTypePosSibType15:
		return "posSibType1-5"
	case PosSIBTypePosSibType16:
		return "posSibType1-6"
	case PosSIBTypePosSibType17:
		return "posSibType1-7"
	case PosSIBTypePosSibType21:
		return "posSibType2-1"
	case PosSIBTypePosSibType22:
		return "posSibType2-2"
	case PosSIBTypePosSibType23:
		return "posSibType2-3"
	case PosSIBTypePosSibType24:
		return "posSibType2-4"
	case PosSIBTypePosSibType25:
		return "posSibType2-5"
	case PosSIBTypePosSibType26:
		return "posSibType2-6"
	case PosSIBTypePosSibType27:
		return "posSibType2-7"
	case PosSIBTypePosSibType28:
		return "posSibType2-8"
	case PosSIBTypePosSibType29:
		return "posSibType2-9"
	case PosSIBTypePosSibType210:
		return "posSibType2-10"
	case PosSIBTypePosSibType211:
		return "posSibType2-11"
	case PosSIBTypePosSibType212:
		return "posSibType2-12"
	case PosSIBTypePosSibType213:
		return "posSibType2-13"
	case PosSIBTypePosSibType214:
		return "posSibType2-14"
	case PosSIBTypePosSibType215:
		return "posSibType2-15"
	case PosSIBTypePosSibType216:
		return "posSibType2-16"
	case PosSIBTypePosSibType217:
		return "posSibType2-17"
	case PosSIBTypePosSibType218:
		return "posSibType2-18"
	case PosSIBTypePosSibType219:
		return "posSibType2-19"
	case PosSIBTypePosSibType31:
		return "posSibType3-1"
	case PosSIBTypePosSibType41:
		return "posSibType4-1"
	case PosSIBTypePosSibType51:
		return "posSibType5-1"
	case PosSIBTypePosSibType224:
		return "posSibType2-24"
	case PosSIBTypePosSibType225:
		return "posSibType2-25"
	default:
		return "unknown"
	}
}

// PRSBandwidth represents the ASN.1 ENUMERATED type PRS-Bandwidth.
type PRSBandwidth int64

const (
	PRSBandwidthBw6   PRSBandwidth = 0
	PRSBandwidthBw15  PRSBandwidth = 1
	PRSBandwidthBw25  PRSBandwidth = 2
	PRSBandwidthBw50  PRSBandwidth = 3
	PRSBandwidthBw75  PRSBandwidth = 4
	PRSBandwidthBw100 PRSBandwidth = 5
)

func (v PRSBandwidth) String() string {
	switch v {
	case PRSBandwidthBw6:
		return "bw6"
	case PRSBandwidthBw15:
		return "bw15"
	case PRSBandwidthBw25:
		return "bw25"
	case PRSBandwidthBw50:
		return "bw50"
	case PRSBandwidthBw75:
		return "bw75"
	case PRSBandwidthBw100:
		return "bw100"
	default:
		return "unknown"
	}
}

// PRSConfigurationIndex represents the ASN.1 type PRS-Configuration-Index (INTEGER).
type PRSConfigurationIndex = *q6.Int

// PRSID represents the ASN.1 type PRS-ID (INTEGER).
type PRSID = *q6.Int

// PRSMutingConfiguration choice constants.
const (
	PRSMutingConfigurationChoiceTwo                      = 1
	PRSMutingConfigurationChoiceFour                     = 2
	PRSMutingConfigurationChoiceEight                    = 3
	PRSMutingConfigurationChoiceSixteen                  = 4
	PRSMutingConfigurationChoiceThirtyTwo                = 5
	PRSMutingConfigurationChoiceSixtyFour                = 6
	PRSMutingConfigurationChoiceOneHundredAndTwentyEight = 7
	PRSMutingConfigurationChoiceTwoHundredAndFiftySix    = 8
	PRSMutingConfigurationChoiceFiveHundredAndTwelve     = 9
	PRSMutingConfigurationChoiceOneThousandAndTwentyFour = 10
)

// PRSOccasionGroup represents the ASN.1 ENUMERATED type PRSOccasionGroup.
type PRSOccasionGroup int64

const (
	PRSOccasionGroupOg2   PRSOccasionGroup = 0
	PRSOccasionGroupOg4   PRSOccasionGroup = 1
	PRSOccasionGroupOg8   PRSOccasionGroup = 2
	PRSOccasionGroupOg16  PRSOccasionGroup = 3
	PRSOccasionGroupOg32  PRSOccasionGroup = 4
	PRSOccasionGroupOg64  PRSOccasionGroup = 5
	PRSOccasionGroupOg128 PRSOccasionGroup = 6
)

func (v PRSOccasionGroup) String() string {
	switch v {
	case PRSOccasionGroupOg2:
		return "og2"
	case PRSOccasionGroupOg4:
		return "og4"
	case PRSOccasionGroupOg8:
		return "og8"
	case PRSOccasionGroupOg16:
		return "og16"
	case PRSOccasionGroupOg32:
		return "og32"
	case PRSOccasionGroupOg64:
		return "og64"
	case PRSOccasionGroupOg128:
		return "og128"
	default:
		return "unknown"
	}
}

// RepetitionNumberofSIB1NB represents the ASN.1 ENUMERATED type RepetitionNumberofSIB1-NB.
type RepetitionNumberofSIB1NB int64

const (
	RepetitionNumberofSIB1NBR4  RepetitionNumberofSIB1NB = 0
	RepetitionNumberofSIB1NBR8  RepetitionNumberofSIB1NB = 1
	RepetitionNumberofSIB1NBR16 RepetitionNumberofSIB1NB = 2
)

func (v RepetitionNumberofSIB1NB) String() string {
	switch v {
	case RepetitionNumberofSIB1NBR4:
		return "r4"
	case RepetitionNumberofSIB1NBR8:
		return "r8"
	case RepetitionNumberofSIB1NBR16:
		return "r16"
	default:
		return "unknown"
	}
}

// ReportCharacteristics represents the ASN.1 ENUMERATED type ReportCharacteristics.
type ReportCharacteristics int64

const (
	ReportCharacteristicsOnDemand ReportCharacteristics = 0
	ReportCharacteristicsPeriodic ReportCharacteristics = 1
)

func (v ReportCharacteristics) String() string {
	switch v {
	case ReportCharacteristicsOnDemand:
		return "onDemand"
	case ReportCharacteristicsPeriodic:
		return "periodic"
	default:
		return "unknown"
	}
}

// RSSI represents the ASN.1 type RSSI (INTEGER).
type RSSI = *q6.Int

// SFNInitialisationTime represents the ASN.1 type SFNInitialisationTime (BIT_STRING).
type SFNInitialisationTime = q7.BitString

// Subframeallocation choice constants.
const (
	SubframeallocationChoiceOneFrame   = 1
	SubframeallocationChoiceFourFrames = 2
)

// SSNRRSRP represents the ASN.1 type SS-NRRSRP (INTEGER).
type SSNRRSRP = int64

// SSNRRSRQ represents the ASN.1 type SS-NRRSRQ (INTEGER).
type SSNRRSRQ = int64

// SSBIndex represents the ASN.1 type SSB-Index (INTEGER).
type SSBIndex = int64

// SSID represents the ASN.1 type SSID (OCTET_STRING).
type SSID = []byte

// TAC represents the ASN.1 type TAC (OCTET_STRING).
type TAC = []byte

// TPID represents the ASN.1 type TP-ID (INTEGER).
type TPID = *q6.Int

// TPType represents the ASN.1 ENUMERATED type TP-Type.
type TPType int64

const (
	TPTypePrsOnlyTp TPType = 0
)

func (v TPType) String() string {
	switch v {
	case TPTypePrsOnlyTp:
		return "prs-only-tp"
	default:
		return "unknown"
	}
}

// TypeOfError represents the ASN.1 ENUMERATED type TypeOfError.
type TypeOfError int64

const (
	TypeOfErrorNotUnderstood TypeOfError = 0
	TypeOfErrorMissing       TypeOfError = 1
)

func (v TypeOfError) String() string {
	switch v {
	case TypeOfErrorNotUnderstood:
		return "not-understood"
	case TypeOfErrorMissing:
		return "missing"
	default:
		return "unknown"
	}
}

// UARFCN represents the ASN.1 type UARFCN (INTEGER).
type UARFCN = *q6.Int

// UTRAEcN0 represents the ASN.1 type UTRA-EcN0 (INTEGER).
type UTRAEcN0 = *q6.Int

// UTRARSCP represents the ASN.1 type UTRA-RSCP (INTEGER).
type UTRARSCP = *q6.Int

// ValueRSRP represents the ASN.1 type ValueRSRP (INTEGER).
type ValueRSRP = *q6.Int

// ValueRSRQ represents the ASN.1 type ValueRSRQ (INTEGER).
type ValueRSRQ = *q6.Int

// WLANMeasurementQuantitiesValue represents the ASN.1 ENUMERATED type WLANMeasurementQuantitiesValue.
type WLANMeasurementQuantitiesValue int64

const (
	WLANMeasurementQuantitiesValueWlan WLANMeasurementQuantitiesValue = 0
)

func (v WLANMeasurementQuantitiesValue) String() string {
	switch v {
	case WLANMeasurementQuantitiesValueWlan:
		return "wlan"
	default:
		return "unknown"
	}
}

// WLANRSSI represents the ASN.1 type WLAN-RSSI (INTEGER).
type WLANRSSI = *q6.Int

// WLANBand represents the ASN.1 ENUMERATED type WLANBand.
type WLANBand int64

const (
	WLANBandBand2dot4 WLANBand = 0
	WLANBandBand5     WLANBand = 1
)

func (v WLANBand) String() string {
	switch v {
	case WLANBandBand2dot4:
		return "band2dot4"
	case WLANBandBand5:
		return "band5"
	default:
		return "unknown"
	}
}

type WLANChannelList = []WLANChannel

// WLANChannel represents the ASN.1 type WLANChannel (INTEGER).
type WLANChannel = int64

// WLANCountryCode represents the ASN.1 ENUMERATED type WLANCountryCode.
type WLANCountryCode int64

const (
	WLANCountryCodeUnitedStates WLANCountryCode = 0
	WLANCountryCodeEurope       WLANCountryCode = 1
	WLANCountryCodeJapan        WLANCountryCode = 2
	WLANCountryCodeGlobal       WLANCountryCode = 3
)

func (v WLANCountryCode) String() string {
	switch v {
	case WLANCountryCodeUnitedStates:
		return "unitedStates"
	case WLANCountryCodeEurope:
		return "europe"
	case WLANCountryCodeJapan:
		return "japan"
	case WLANCountryCodeGlobal:
		return "global"
	default:
		return "unknown"
	}
}

// WLANOperatingClass represents the ASN.1 type WLANOperatingClass (INTEGER).
type WLANOperatingClass = int64
type PRSFrequencyHoppingConfigurationBandPositions = []NarrowBandIndex

// ResultUTRANItemPhysCellIDUTRAN choice constants.
const (
	ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRAFDD = 1
	ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRATDD = 2
)

type BridgeAsn1cAPERWLANChannelListListValue struct{ Value WLANChannelList }
type BridgeAsn1cAPERPRSFrequencyHoppingConfigurationBandPositionsListValue struct {
	Value PRSFrequencyHoppingConfigurationBandPositions
}

var (
	BridgeAsn1IntegerBound0  = q7.MustParseBigIntDecimal("-5")
	BridgeAsn1IntegerBound1  = q7.MustParseBigIntDecimal("0")
	BridgeAsn1IntegerBound2  = q7.MustParseBigIntDecimal("1")
	BridgeAsn1IntegerBound3  = q7.MustParseBigIntDecimal("100")
	BridgeAsn1IntegerBound4  = q7.MustParseBigIntDecimal("1023")
	BridgeAsn1IntegerBound5  = q7.MustParseBigIntDecimal("127")
	BridgeAsn1IntegerBound6  = q7.MustParseBigIntDecimal("141")
	BridgeAsn1IntegerBound7  = q7.MustParseBigIntDecimal("15")
	BridgeAsn1IntegerBound8  = q7.MustParseBigIntDecimal("16")
	BridgeAsn1IntegerBound9  = q7.MustParseBigIntDecimal("160")
	BridgeAsn1IntegerBound10 = q7.MustParseBigIntDecimal("16383")
	BridgeAsn1IntegerBound11 = q7.MustParseBigIntDecimal("174")
	BridgeAsn1IntegerBound12 = q7.MustParseBigIntDecimal("255")
	BridgeAsn1IntegerBound13 = q7.MustParseBigIntDecimal("34")
	BridgeAsn1IntegerBound14 = q7.MustParseBigIntDecimal("4095")
	BridgeAsn1IntegerBound15 = q7.MustParseBigIntDecimal("49")
	BridgeAsn1IntegerBound16 = q7.MustParseBigIntDecimal("500")
	BridgeAsn1IntegerBound17 = q7.MustParseBigIntDecimal("503")
	BridgeAsn1IntegerBound18 = q7.MustParseBigIntDecimal("511")
	BridgeAsn1IntegerBound19 = q7.MustParseBigIntDecimal("63")
	BridgeAsn1IntegerBound20 = q7.MustParseBigIntDecimal("65535")
	BridgeAsn1IntegerBound21 = q7.MustParseBigIntDecimal("91")
	BridgeAsn1IntegerBound22 = q7.MustParseBigIntDecimal("97")
)

// LPPAPDU choice constants.
const (
	LPPAPDUChoiceInitiatingMessage   = 1
	LPPAPDUChoiceSuccessfulOutcome   = 2
	LPPAPDUChoiceUnsuccessfulOutcome = 3
)

// PayloadLimits bound a single call across a foreign byte boundary.
// Zero fields select finite defaults; the foreign callback applies its own
// schema and work/depth accounting.
type PayloadLimits struct {
	MaxInputBytes     uint64
	MaxOutputBytes    uint64
	MaxDepth          uint64
	MaxElements       uint64
	MaxWork           uint64
	MaxAllocatedBytes uint64
	MaxReports        uint64
}
type PayloadDeviation struct {
	ByteOffset uint64
	BitOffset  uint8
	Path       string
	Document   string
	Clause     string
}
type PayloadReport struct{ Deviations []PayloadDeviation }

func InitiatingReason(code ProcedureCode) q5.OpaqueReason {
	switch code {
	default:
		return q5.UnknownSelector
	}
}
func SuccessfulReason(code ProcedureCode) q5.OpaqueReason {
	switch code {
	case ProcedureCode(0):
		return q5.OutcomeNotInTable
	case ProcedureCode(1):
		return q5.OutcomeNotInTable
	case ProcedureCode(3):
		return q5.OutcomeNotInTable
	case ProcedureCode(4):
		return q5.OutcomeNotInTable
	case ProcedureCode(5):
		return q5.OutcomeNotInTable
	case ProcedureCode(8):
		return q5.OutcomeNotInTable
	case ProcedureCode(9):
		return q5.OutcomeNotInTable
	case ProcedureCode(10):
		return q5.OutcomeNotInTable
	default:
		return q5.UnknownSelector
	}
}
func UnsuccessfulReason(code ProcedureCode) q5.OpaqueReason {
	switch code {
	case ProcedureCode(0):
		return q5.OutcomeNotInTable
	case ProcedureCode(1):
		return q5.OutcomeNotInTable
	case ProcedureCode(3):
		return q5.OutcomeNotInTable
	case ProcedureCode(4):
		return q5.OutcomeNotInTable
	case ProcedureCode(5):
		return q5.OutcomeNotInTable
	case ProcedureCode(8):
		return q5.OutcomeNotInTable
	case ProcedureCode(9):
		return q5.OutcomeNotInTable
	case ProcedureCode(10):
		return q5.OutcomeNotInTable
	default:
		return q5.UnknownSelector
	}
}
func BridgeCaptureLPPaBCCH(v *BCCH, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaBSSID(v *BSSID, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Bytes((*v))
}
func BridgeCaptureLPPaBroadcast(v *Broadcast, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaBroadcastPeriodicity(v *BroadcastPeriodicity, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaCPLength(v *CPLength, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaCauseMisc(v *CauseMisc, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaCauseProtocol(v *CauseProtocol, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaCauseRadioNetwork(v *CauseRadioNetwork, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaCellPortionID(v *CellPortionID, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaCriticality(v *Criticality, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaDLBandwidth(v *DLBandwidth, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaEARFCN(v *EARFCN, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaEUTRANCellIdentifier(v *EUTRANCellIdentifier, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.BitString((*v).Bytes, (*v).BitLength)
}
func BridgeCaptureLPPaHESSID(v *HESSID, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Bytes((*v))
}
func BridgeCaptureLPPaInterRATMeasurementQuantitiesValue(v *InterRATMeasurementQuantitiesValue, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaLPPATransactionID(v *LPPATransactionID, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaMeasurementID(v *MeasurementID, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaMeasurementPeriodicity(v *MeasurementPeriodicity, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaMeasurementQuantitiesValue(v *MeasurementQuantitiesValue, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaNPRSSequenceInfo(v *NPRSSequenceInfo, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaNRARFCN(v *NRARFCN, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaNRCellIdentity(v *NRCellIdentity, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.BitString((*v).Bytes, (*v).BitLength)
}
func BridgeCaptureLPPaNRPCI(v *NRPCI, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaNarrowBandIndex(v *NarrowBandIndex, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaNumberOfAntennaPorts(v *NumberOfAntennaPorts, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaNumberOfDlFrames(v *NumberOfDlFrames, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaNumberOfDlFramesExtended(v *NumberOfDlFramesExtended, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaNumberOfFrequencyHoppingBands(v *NumberOfFrequencyHoppingBands, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaOTDOAInformationItem(v *OTDOAInformationItem, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaOffsetNBChanneltoEARFCN(v *OffsetNBChanneltoEARFCN, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaOperationModeInfo(v *OperationModeInfo, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaOutcome(v *Outcome, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaPCI(v *PCI, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaPLMNIdentity(v *PLMNIdentity, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Bytes((*v))
}
func BridgeCaptureLPPaPRSBandwidth(v *PRSBandwidth, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaPRSConfigurationIndex(v *PRSConfigurationIndex, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaPRSFrequencyHoppingConfigurationBandPositions(v *PRSFrequencyHoppingConfigurationBandPositions, s *q5.SemanticCapture) {
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
			BridgeCaptureLPPaNarrowBandIndex(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureLPPaPRSID(v *PRSID, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaPRSOccasionGroup(v *PRSOccasionGroup, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaPhysCellIDGERAN(v *PhysCellIDGERAN, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaPhysCellIDUTRAFDD(v *PhysCellIDUTRAFDD, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaPhysCellIDUTRATDD(v *PhysCellIDUTRATDD, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaPosSIBType(v *PosSIBType, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaPresence(v *Presence, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaProcedureCode(v *ProcedureCode, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaProtocolIEID(v *ProtocolIEID, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaRSSI(v *RSSI, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaRepetitionNumberofSIB1NB(v *RepetitionNumberofSIB1NB, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaReportCharacteristics(v *ReportCharacteristics, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaSFNInitialisationTime(v *SFNInitialisationTime, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.BitString((*v).Bytes, (*v).BitLength)
}
func BridgeCaptureLPPaSSBIndex(v *SSBIndex, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaSSID(v *SSID, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Bytes((*v))
}
func BridgeCaptureLPPaSSNRRSRP(v *SSNRRSRP, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaSSNRRSRQ(v *SSNRRSRQ, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaTAC(v *TAC, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Bytes((*v))
}
func BridgeCaptureLPPaTPID(v *TPID, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaTPType(v *TPType, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaTriggeringMessage(v *TriggeringMessage, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaTypeOfError(v *TypeOfError, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaUARFCN(v *UARFCN, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaUTRAEcN0(v *UTRAEcN0, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaUTRARSCP(v *UTRARSCP, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaValueRSRP(v *ValueRSRP, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaValueRSRQ(v *ValueRSRQ, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}
func BridgeCaptureLPPaWLANBand(v *WLANBand, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaWLANChannel(v *WLANChannel, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaWLANChannelList(v *WLANChannelList, s *q5.SemanticCapture) {
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
			BridgeCaptureLPPaWLANChannel(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCaptureLPPaWLANCountryCode(v *WLANCountryCode, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaWLANMeasurementQuantitiesValue(v *WLANMeasurementQuantitiesValue, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaWLANOperatingClass(v *WLANOperatingClass, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaWLANRSSI(v *WLANRSSI, s *q5.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, nil, false)
	}
}

type TableID struct{ source q5.SourceAssignment }

func (id TableID) Source() q5.SourceAssignment { return id.source }

type TypeID struct{ source q5.SourceAssignment }

func (id TypeID) Source() q5.SourceAssignment { return id.source }

type ProcedureInfo struct {
	Code                   ProcedureCode
	Criticality            Criticality
	HasSuccessfulOutcome   bool
	HasUnsuccessfulOutcome bool
	Rule                   q5.SourceRule
}
type FieldInfo struct {
	Table       TableID
	ID          ProtocolIEID
	Criticality Criticality
	Presence    Presence
	ValueType   TypeID
	Rule        q5.SourceRule
}
type ValidationCode uint8

const (
	MissingMandatory ValidationCode = iota + 1
	NotAllowed
	WrongCriticality
	RepeatedIE
	WrongOrder
	UnknownProcedure
	UnavailableOutcome
	ValueIDMismatch
)

type ValidationSeverity uint8

const (
	ValidationSeverityError ValidationSeverity = iota + 1
	ValidationSeverityUnrecognized
	ValidationSeverityInformational
)

type DeferredCondition struct {
	Location q5.Location
	Table    TableID
	IEID     ProtocolIEID
	Rule     q5.SourceRule
}

func BridgeBCCHAPERValueFieldContext(v *BCCHAPERValue) *BridgeCodecContext { return &v.context }
func BridgeBCCHAPERValueFieldReceived(v *BCCHAPERValue) *q5.WireSpan       { return &v.received }
func BridgeBCCHAPERValueFieldReplay(v *BCCHAPERValue) *q5.Snapshot         { return &v.replay }
func BridgeBCCHAPERValueFieldWithoutReplay(v *BCCHAPERValue) *bool         { return &v.withoutReplay }
func BridgeBCCHValueCodecFieldCapture(v *BCCHValueCodec) *func(BCCH, q5.DecodeState) (BCCH, q5.Snapshot) {
	return &v.capture
}
func BridgeBCCHValueCodecFieldCompare(v *BCCHValueCodec) *func(BCCH, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeBCCHValueCodecFieldContext(v *BCCHValueCodec) *BridgeCodecContext { return &v.context }
func BridgeBCCHValueCodecFieldDecode(v *BCCHValueCodec) *func([]byte, q5.DecodeState) (BCCH, error) {
	return &v.decode
}
func BridgeBCCHValueCodecFieldEncode(v *BCCHValueCodec) *func(BCCH, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBCCHValueCodecFieldPath(v *BCCHValueCodec) *q5.Path { return &v.path }
func BridgeBCCHValueCodecMethodEncodeBudget(v BCCHValueCodec, a0 BCCH, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeBCCHValueCodecMethodEncodeChanged(v BCCHValueCodec, a0 BCCH, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBSSIDAPERValueFieldContext(v *BSSIDAPERValue) *BridgeCodecContext { return &v.context }
func BridgeBSSIDAPERValueFieldReceived(v *BSSIDAPERValue) *q5.WireSpan       { return &v.received }
func BridgeBSSIDAPERValueFieldReplay(v *BSSIDAPERValue) *q5.Snapshot         { return &v.replay }
func BridgeBSSIDAPERValueFieldWithoutReplay(v *BSSIDAPERValue) *bool         { return &v.withoutReplay }
func BridgeBSSIDValueCodecFieldCapture(v *BSSIDValueCodec) *func(BSSID, q5.DecodeState) (BSSID, q5.Snapshot) {
	return &v.capture
}
func BridgeBSSIDValueCodecFieldCompare(v *BSSIDValueCodec) *func(BSSID, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeBSSIDValueCodecFieldContext(v *BSSIDValueCodec) *BridgeCodecContext { return &v.context }
func BridgeBSSIDValueCodecFieldDecode(v *BSSIDValueCodec) *func([]byte, q5.DecodeState) (BSSID, error) {
	return &v.decode
}
func BridgeBSSIDValueCodecFieldEncode(v *BSSIDValueCodec) *func(BSSID, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBSSIDValueCodecFieldPath(v *BSSIDValueCodec) *q5.Path { return &v.path }
func BridgeBSSIDValueCodecMethodEncodeBudget(v BSSIDValueCodec, a0 BSSID, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeBSSIDValueCodecMethodEncodeChanged(v BSSIDValueCodec, a0 BSSID, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBroadcastAPERValueFieldContext(v *BroadcastAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeBroadcastAPERValueFieldReceived(v *BroadcastAPERValue) *q5.WireSpan { return &v.received }
func BridgeBroadcastAPERValueFieldReplay(v *BroadcastAPERValue) *q5.Snapshot   { return &v.replay }
func BridgeBroadcastAPERValueFieldWithoutReplay(v *BroadcastAPERValue) *bool   { return &v.withoutReplay }
func BridgeBroadcastPeriodicityAPERValueFieldContext(v *BroadcastPeriodicityAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeBroadcastPeriodicityAPERValueFieldReceived(v *BroadcastPeriodicityAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeBroadcastPeriodicityAPERValueFieldReplay(v *BroadcastPeriodicityAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeBroadcastPeriodicityAPERValueFieldWithoutReplay(v *BroadcastPeriodicityAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeBroadcastPeriodicityValueCodecFieldCapture(v *BroadcastPeriodicityValueCodec) *func(BroadcastPeriodicity, q5.DecodeState) (BroadcastPeriodicity, q5.Snapshot) {
	return &v.capture
}
func BridgeBroadcastPeriodicityValueCodecFieldCompare(v *BroadcastPeriodicityValueCodec) *func(BroadcastPeriodicity, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeBroadcastPeriodicityValueCodecFieldContext(v *BroadcastPeriodicityValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeBroadcastPeriodicityValueCodecFieldDecode(v *BroadcastPeriodicityValueCodec) *func([]byte, q5.DecodeState) (BroadcastPeriodicity, error) {
	return &v.decode
}
func BridgeBroadcastPeriodicityValueCodecFieldEncode(v *BroadcastPeriodicityValueCodec) *func(BroadcastPeriodicity, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBroadcastPeriodicityValueCodecFieldPath(v *BroadcastPeriodicityValueCodec) *q5.Path {
	return &v.path
}
func BridgeBroadcastPeriodicityValueCodecMethodEncodeBudget(v BroadcastPeriodicityValueCodec, a0 BroadcastPeriodicity, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeBroadcastPeriodicityValueCodecMethodEncodeChanged(v BroadcastPeriodicityValueCodec, a0 BroadcastPeriodicity, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeBroadcastValueCodecFieldCapture(v *BroadcastValueCodec) *func(Broadcast, q5.DecodeState) (Broadcast, q5.Snapshot) {
	return &v.capture
}
func BridgeBroadcastValueCodecFieldCompare(v *BroadcastValueCodec) *func(Broadcast, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeBroadcastValueCodecFieldContext(v *BroadcastValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeBroadcastValueCodecFieldDecode(v *BroadcastValueCodec) *func([]byte, q5.DecodeState) (Broadcast, error) {
	return &v.decode
}
func BridgeBroadcastValueCodecFieldEncode(v *BroadcastValueCodec) *func(Broadcast, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeBroadcastValueCodecFieldPath(v *BroadcastValueCodec) *q5.Path { return &v.path }
func BridgeBroadcastValueCodecMethodEncodeBudget(v BroadcastValueCodec, a0 Broadcast, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeBroadcastValueCodecMethodEncodeChanged(v BroadcastValueCodec, a0 Broadcast, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCPLengthAPERValueFieldContext(v *CPLengthAPERValue) *BridgeCodecContext { return &v.context }
func BridgeCPLengthAPERValueFieldReceived(v *CPLengthAPERValue) *q5.WireSpan       { return &v.received }
func BridgeCPLengthAPERValueFieldReplay(v *CPLengthAPERValue) *q5.Snapshot         { return &v.replay }
func BridgeCPLengthAPERValueFieldWithoutReplay(v *CPLengthAPERValue) *bool         { return &v.withoutReplay }
func BridgeCPLengthValueCodecFieldCapture(v *CPLengthValueCodec) *func(CPLength, q5.DecodeState) (CPLength, q5.Snapshot) {
	return &v.capture
}
func BridgeCPLengthValueCodecFieldCompare(v *CPLengthValueCodec) *func(CPLength, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeCPLengthValueCodecFieldContext(v *CPLengthValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeCPLengthValueCodecFieldDecode(v *CPLengthValueCodec) *func([]byte, q5.DecodeState) (CPLength, error) {
	return &v.decode
}
func BridgeCPLengthValueCodecFieldEncode(v *CPLengthValueCodec) *func(CPLength, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCPLengthValueCodecFieldPath(v *CPLengthValueCodec) *q5.Path { return &v.path }
func BridgeCPLengthValueCodecMethodEncodeBudget(v CPLengthValueCodec, a0 CPLength, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeCPLengthValueCodecMethodEncodeChanged(v CPLengthValueCodec, a0 CPLength, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCauseMiscAPERValueFieldContext(v *CauseMiscAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeCauseMiscAPERValueFieldReceived(v *CauseMiscAPERValue) *q5.WireSpan { return &v.received }
func BridgeCauseMiscAPERValueFieldReplay(v *CauseMiscAPERValue) *q5.Snapshot   { return &v.replay }
func BridgeCauseMiscAPERValueFieldWithoutReplay(v *CauseMiscAPERValue) *bool   { return &v.withoutReplay }
func BridgeCauseMiscValueCodecFieldCapture(v *CauseMiscValueCodec) *func(CauseMisc, q5.DecodeState) (CauseMisc, q5.Snapshot) {
	return &v.capture
}
func BridgeCauseMiscValueCodecFieldCompare(v *CauseMiscValueCodec) *func(CauseMisc, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeCauseMiscValueCodecFieldContext(v *CauseMiscValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeCauseMiscValueCodecFieldDecode(v *CauseMiscValueCodec) *func([]byte, q5.DecodeState) (CauseMisc, error) {
	return &v.decode
}
func BridgeCauseMiscValueCodecFieldEncode(v *CauseMiscValueCodec) *func(CauseMisc, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCauseMiscValueCodecFieldPath(v *CauseMiscValueCodec) *q5.Path { return &v.path }
func BridgeCauseMiscValueCodecMethodEncodeBudget(v CauseMiscValueCodec, a0 CauseMisc, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeCauseMiscValueCodecMethodEncodeChanged(v CauseMiscValueCodec, a0 CauseMisc, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCauseProtocolAPERValueFieldContext(v *CauseProtocolAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeCauseProtocolAPERValueFieldReceived(v *CauseProtocolAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeCauseProtocolAPERValueFieldReplay(v *CauseProtocolAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeCauseProtocolAPERValueFieldWithoutReplay(v *CauseProtocolAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCauseProtocolValueCodecFieldCapture(v *CauseProtocolValueCodec) *func(CauseProtocol, q5.DecodeState) (CauseProtocol, q5.Snapshot) {
	return &v.capture
}
func BridgeCauseProtocolValueCodecFieldCompare(v *CauseProtocolValueCodec) *func(CauseProtocol, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeCauseProtocolValueCodecFieldContext(v *CauseProtocolValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeCauseProtocolValueCodecFieldDecode(v *CauseProtocolValueCodec) *func([]byte, q5.DecodeState) (CauseProtocol, error) {
	return &v.decode
}
func BridgeCauseProtocolValueCodecFieldEncode(v *CauseProtocolValueCodec) *func(CauseProtocol, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCauseProtocolValueCodecFieldPath(v *CauseProtocolValueCodec) *q5.Path { return &v.path }
func BridgeCauseProtocolValueCodecMethodEncodeBudget(v CauseProtocolValueCodec, a0 CauseProtocol, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeCauseProtocolValueCodecMethodEncodeChanged(v CauseProtocolValueCodec, a0 CauseProtocol, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCauseRadioNetworkAPERValueFieldContext(v *CauseRadioNetworkAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeCauseRadioNetworkAPERValueFieldReceived(v *CauseRadioNetworkAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeCauseRadioNetworkAPERValueFieldReplay(v *CauseRadioNetworkAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeCauseRadioNetworkAPERValueFieldWithoutReplay(v *CauseRadioNetworkAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCauseRadioNetworkValueCodecFieldCapture(v *CauseRadioNetworkValueCodec) *func(CauseRadioNetwork, q5.DecodeState) (CauseRadioNetwork, q5.Snapshot) {
	return &v.capture
}
func BridgeCauseRadioNetworkValueCodecFieldCompare(v *CauseRadioNetworkValueCodec) *func(CauseRadioNetwork, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeCauseRadioNetworkValueCodecFieldContext(v *CauseRadioNetworkValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeCauseRadioNetworkValueCodecFieldDecode(v *CauseRadioNetworkValueCodec) *func([]byte, q5.DecodeState) (CauseRadioNetwork, error) {
	return &v.decode
}
func BridgeCauseRadioNetworkValueCodecFieldEncode(v *CauseRadioNetworkValueCodec) *func(CauseRadioNetwork, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCauseRadioNetworkValueCodecFieldPath(v *CauseRadioNetworkValueCodec) *q5.Path {
	return &v.path
}
func BridgeCauseRadioNetworkValueCodecMethodEncodeBudget(v CauseRadioNetworkValueCodec, a0 CauseRadioNetwork, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeCauseRadioNetworkValueCodecMethodEncodeChanged(v CauseRadioNetworkValueCodec, a0 CauseRadioNetwork, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCellPortionIDAPERValueFieldContext(v *CellPortionIDAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeCellPortionIDAPERValueFieldReceived(v *CellPortionIDAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeCellPortionIDAPERValueFieldReplay(v *CellPortionIDAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeCellPortionIDAPERValueFieldWithoutReplay(v *CellPortionIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCellPortionIDValueCodecFieldCapture(v *CellPortionIDValueCodec) *func(CellPortionID, q5.DecodeState) (CellPortionID, q5.Snapshot) {
	return &v.capture
}
func BridgeCellPortionIDValueCodecFieldCompare(v *CellPortionIDValueCodec) *func(CellPortionID, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeCellPortionIDValueCodecFieldContext(v *CellPortionIDValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeCellPortionIDValueCodecFieldDecode(v *CellPortionIDValueCodec) *func([]byte, q5.DecodeState) (CellPortionID, error) {
	return &v.decode
}
func BridgeCellPortionIDValueCodecFieldEncode(v *CellPortionIDValueCodec) *func(CellPortionID, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCellPortionIDValueCodecFieldPath(v *CellPortionIDValueCodec) *q5.Path { return &v.path }
func BridgeCellPortionIDValueCodecMethodEncodeBudget(v CellPortionIDValueCodec, a0 CellPortionID, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeCellPortionIDValueCodecMethodEncodeChanged(v CellPortionIDValueCodec, a0 CellPortionID, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeCriticalityAPERValueFieldContext(v *CriticalityAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityAPERValueFieldReceived(v *CriticalityAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeCriticalityAPERValueFieldReplay(v *CriticalityAPERValue) *q5.Snapshot { return &v.replay }
func BridgeCriticalityAPERValueFieldWithoutReplay(v *CriticalityAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityValueCodecFieldCapture(v *CriticalityValueCodec) *func(Criticality, q5.DecodeState) (Criticality, q5.Snapshot) {
	return &v.capture
}
func BridgeCriticalityValueCodecFieldCompare(v *CriticalityValueCodec) *func(Criticality, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeCriticalityValueCodecFieldContext(v *CriticalityValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeCriticalityValueCodecFieldDecode(v *CriticalityValueCodec) *func([]byte, q5.DecodeState) (Criticality, error) {
	return &v.decode
}
func BridgeCriticalityValueCodecFieldEncode(v *CriticalityValueCodec) *func(Criticality, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeCriticalityValueCodecFieldPath(v *CriticalityValueCodec) *q5.Path { return &v.path }
func BridgeCriticalityValueCodecMethodEncodeBudget(v CriticalityValueCodec, a0 Criticality, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeCriticalityValueCodecMethodEncodeChanged(v CriticalityValueCodec, a0 Criticality, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeDLBandwidthAPERValueFieldContext(v *DLBandwidthAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeDLBandwidthAPERValueFieldReceived(v *DLBandwidthAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeDLBandwidthAPERValueFieldReplay(v *DLBandwidthAPERValue) *q5.Snapshot { return &v.replay }
func BridgeDLBandwidthAPERValueFieldWithoutReplay(v *DLBandwidthAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeDLBandwidthValueCodecFieldCapture(v *DLBandwidthValueCodec) *func(DLBandwidth, q5.DecodeState) (DLBandwidth, q5.Snapshot) {
	return &v.capture
}
func BridgeDLBandwidthValueCodecFieldCompare(v *DLBandwidthValueCodec) *func(DLBandwidth, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeDLBandwidthValueCodecFieldContext(v *DLBandwidthValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeDLBandwidthValueCodecFieldDecode(v *DLBandwidthValueCodec) *func([]byte, q5.DecodeState) (DLBandwidth, error) {
	return &v.decode
}
func BridgeDLBandwidthValueCodecFieldEncode(v *DLBandwidthValueCodec) *func(DLBandwidth, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeDLBandwidthValueCodecFieldPath(v *DLBandwidthValueCodec) *q5.Path { return &v.path }
func BridgeDLBandwidthValueCodecMethodEncodeBudget(v DLBandwidthValueCodec, a0 DLBandwidth, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeDLBandwidthValueCodecMethodEncodeChanged(v DLBandwidthValueCodec, a0 DLBandwidth, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeEARFCNAPERValueFieldContext(v *EARFCNAPERValue) *BridgeCodecContext { return &v.context }
func BridgeEARFCNAPERValueFieldReceived(v *EARFCNAPERValue) *q5.WireSpan       { return &v.received }
func BridgeEARFCNAPERValueFieldReplay(v *EARFCNAPERValue) *q5.Snapshot         { return &v.replay }
func BridgeEARFCNAPERValueFieldWithoutReplay(v *EARFCNAPERValue) *bool         { return &v.withoutReplay }
func BridgeEARFCNValueCodecFieldCapture(v *EARFCNValueCodec) *func(EARFCN, q5.DecodeState) (EARFCN, q5.Snapshot) {
	return &v.capture
}
func BridgeEARFCNValueCodecFieldCompare(v *EARFCNValueCodec) *func(EARFCN, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeEARFCNValueCodecFieldContext(v *EARFCNValueCodec) *BridgeCodecContext { return &v.context }
func BridgeEARFCNValueCodecFieldDecode(v *EARFCNValueCodec) *func([]byte, q5.DecodeState) (EARFCN, error) {
	return &v.decode
}
func BridgeEARFCNValueCodecFieldEncode(v *EARFCNValueCodec) *func(EARFCN, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEARFCNValueCodecFieldPath(v *EARFCNValueCodec) *q5.Path { return &v.path }
func BridgeEARFCNValueCodecMethodEncodeBudget(v EARFCNValueCodec, a0 EARFCN, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeEARFCNValueCodecMethodEncodeChanged(v EARFCNValueCodec, a0 EARFCN, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeEUTRANCellIdentifierAPERValueFieldContext(v *EUTRANCellIdentifierAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeEUTRANCellIdentifierAPERValueFieldReceived(v *EUTRANCellIdentifierAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeEUTRANCellIdentifierAPERValueFieldReplay(v *EUTRANCellIdentifierAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeEUTRANCellIdentifierAPERValueFieldWithoutReplay(v *EUTRANCellIdentifierAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeEUTRANCellIdentifierValueCodecFieldCapture(v *EUTRANCellIdentifierValueCodec) *func(EUTRANCellIdentifier, q5.DecodeState) (EUTRANCellIdentifier, q5.Snapshot) {
	return &v.capture
}
func BridgeEUTRANCellIdentifierValueCodecFieldCompare(v *EUTRANCellIdentifierValueCodec) *func(EUTRANCellIdentifier, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeEUTRANCellIdentifierValueCodecFieldContext(v *EUTRANCellIdentifierValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeEUTRANCellIdentifierValueCodecFieldDecode(v *EUTRANCellIdentifierValueCodec) *func([]byte, q5.DecodeState) (EUTRANCellIdentifier, error) {
	return &v.decode
}
func BridgeEUTRANCellIdentifierValueCodecFieldEncode(v *EUTRANCellIdentifierValueCodec) *func(EUTRANCellIdentifier, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeEUTRANCellIdentifierValueCodecFieldPath(v *EUTRANCellIdentifierValueCodec) *q5.Path {
	return &v.path
}
func BridgeEUTRANCellIdentifierValueCodecMethodEncodeBudget(v EUTRANCellIdentifierValueCodec, a0 EUTRANCellIdentifier, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeEUTRANCellIdentifierValueCodecMethodEncodeChanged(v EUTRANCellIdentifierValueCodec, a0 EUTRANCellIdentifier, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeHESSIDAPERValueFieldContext(v *HESSIDAPERValue) *BridgeCodecContext { return &v.context }
func BridgeHESSIDAPERValueFieldReceived(v *HESSIDAPERValue) *q5.WireSpan       { return &v.received }
func BridgeHESSIDAPERValueFieldReplay(v *HESSIDAPERValue) *q5.Snapshot         { return &v.replay }
func BridgeHESSIDAPERValueFieldWithoutReplay(v *HESSIDAPERValue) *bool         { return &v.withoutReplay }
func BridgeHESSIDValueCodecFieldCapture(v *HESSIDValueCodec) *func(HESSID, q5.DecodeState) (HESSID, q5.Snapshot) {
	return &v.capture
}
func BridgeHESSIDValueCodecFieldCompare(v *HESSIDValueCodec) *func(HESSID, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeHESSIDValueCodecFieldContext(v *HESSIDValueCodec) *BridgeCodecContext { return &v.context }
func BridgeHESSIDValueCodecFieldDecode(v *HESSIDValueCodec) *func([]byte, q5.DecodeState) (HESSID, error) {
	return &v.decode
}
func BridgeHESSIDValueCodecFieldEncode(v *HESSIDValueCodec) *func(HESSID, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHESSIDValueCodecFieldPath(v *HESSIDValueCodec) *q5.Path { return &v.path }
func BridgeHESSIDValueCodecMethodEncodeBudget(v HESSIDValueCodec, a0 HESSID, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeHESSIDValueCodecMethodEncodeChanged(v HESSIDValueCodec, a0 HESSID, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInterRATMeasurementQuantitiesValueAPERValueFieldContext(v *InterRATMeasurementQuantitiesValueAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeInterRATMeasurementQuantitiesValueAPERValueFieldReceived(v *InterRATMeasurementQuantitiesValueAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeInterRATMeasurementQuantitiesValueAPERValueFieldReplay(v *InterRATMeasurementQuantitiesValueAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementQuantitiesValueAPERValueFieldWithoutReplay(v *InterRATMeasurementQuantitiesValueAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementQuantitiesValueValueCodecFieldCapture(v *InterRATMeasurementQuantitiesValueValueCodec) *func(InterRATMeasurementQuantitiesValue, q5.DecodeState) (InterRATMeasurementQuantitiesValue, q5.Snapshot) {
	return &v.capture
}
func BridgeInterRATMeasurementQuantitiesValueValueCodecFieldCompare(v *InterRATMeasurementQuantitiesValueValueCodec) *func(InterRATMeasurementQuantitiesValue, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeInterRATMeasurementQuantitiesValueValueCodecFieldContext(v *InterRATMeasurementQuantitiesValueValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeInterRATMeasurementQuantitiesValueValueCodecFieldDecode(v *InterRATMeasurementQuantitiesValueValueCodec) *func([]byte, q5.DecodeState) (InterRATMeasurementQuantitiesValue, error) {
	return &v.decode
}
func BridgeInterRATMeasurementQuantitiesValueValueCodecFieldEncode(v *InterRATMeasurementQuantitiesValueValueCodec) *func(InterRATMeasurementQuantitiesValue, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInterRATMeasurementQuantitiesValueValueCodecFieldPath(v *InterRATMeasurementQuantitiesValueValueCodec) *q5.Path {
	return &v.path
}
func BridgeInterRATMeasurementQuantitiesValueValueCodecMethodEncodeBudget(v InterRATMeasurementQuantitiesValueValueCodec, a0 InterRATMeasurementQuantitiesValue, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeInterRATMeasurementQuantitiesValueValueCodecMethodEncodeChanged(v InterRATMeasurementQuantitiesValueValueCodec, a0 InterRATMeasurementQuantitiesValue, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeLPPATransactionIDAPERValueFieldContext(v *LPPATransactionIDAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeLPPATransactionIDAPERValueFieldReceived(v *LPPATransactionIDAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeLPPATransactionIDAPERValueFieldReplay(v *LPPATransactionIDAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeLPPATransactionIDAPERValueFieldWithoutReplay(v *LPPATransactionIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeLPPATransactionIDValueCodecFieldCapture(v *LPPATransactionIDValueCodec) *func(LPPATransactionID, q5.DecodeState) (LPPATransactionID, q5.Snapshot) {
	return &v.capture
}
func BridgeLPPATransactionIDValueCodecFieldCompare(v *LPPATransactionIDValueCodec) *func(LPPATransactionID, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeLPPATransactionIDValueCodecFieldContext(v *LPPATransactionIDValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeLPPATransactionIDValueCodecFieldDecode(v *LPPATransactionIDValueCodec) *func([]byte, q5.DecodeState) (LPPATransactionID, error) {
	return &v.decode
}
func BridgeLPPATransactionIDValueCodecFieldEncode(v *LPPATransactionIDValueCodec) *func(LPPATransactionID, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLPPATransactionIDValueCodecFieldPath(v *LPPATransactionIDValueCodec) *q5.Path {
	return &v.path
}
func BridgeLPPATransactionIDValueCodecMethodEncodeBudget(v LPPATransactionIDValueCodec, a0 LPPATransactionID, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeLPPATransactionIDValueCodecMethodEncodeChanged(v LPPATransactionIDValueCodec, a0 LPPATransactionID, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMeasurementIDAPERValueFieldContext(v *MeasurementIDAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementIDAPERValueFieldReceived(v *MeasurementIDAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeMeasurementIDAPERValueFieldReplay(v *MeasurementIDAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeMeasurementIDAPERValueFieldWithoutReplay(v *MeasurementIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementIDValueCodecFieldCapture(v *MeasurementIDValueCodec) *func(MeasurementID, q5.DecodeState) (MeasurementID, q5.Snapshot) {
	return &v.capture
}
func BridgeMeasurementIDValueCodecFieldCompare(v *MeasurementIDValueCodec) *func(MeasurementID, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeMeasurementIDValueCodecFieldContext(v *MeasurementIDValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementIDValueCodecFieldDecode(v *MeasurementIDValueCodec) *func([]byte, q5.DecodeState) (MeasurementID, error) {
	return &v.decode
}
func BridgeMeasurementIDValueCodecFieldEncode(v *MeasurementIDValueCodec) *func(MeasurementID, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMeasurementIDValueCodecFieldPath(v *MeasurementIDValueCodec) *q5.Path { return &v.path }
func BridgeMeasurementIDValueCodecMethodEncodeBudget(v MeasurementIDValueCodec, a0 MeasurementID, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeMeasurementIDValueCodecMethodEncodeChanged(v MeasurementIDValueCodec, a0 MeasurementID, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMeasurementPeriodicityAPERValueFieldContext(v *MeasurementPeriodicityAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementPeriodicityAPERValueFieldReceived(v *MeasurementPeriodicityAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeMeasurementPeriodicityAPERValueFieldReplay(v *MeasurementPeriodicityAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeMeasurementPeriodicityAPERValueFieldWithoutReplay(v *MeasurementPeriodicityAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementPeriodicityValueCodecFieldCapture(v *MeasurementPeriodicityValueCodec) *func(MeasurementPeriodicity, q5.DecodeState) (MeasurementPeriodicity, q5.Snapshot) {
	return &v.capture
}
func BridgeMeasurementPeriodicityValueCodecFieldCompare(v *MeasurementPeriodicityValueCodec) *func(MeasurementPeriodicity, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeMeasurementPeriodicityValueCodecFieldContext(v *MeasurementPeriodicityValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementPeriodicityValueCodecFieldDecode(v *MeasurementPeriodicityValueCodec) *func([]byte, q5.DecodeState) (MeasurementPeriodicity, error) {
	return &v.decode
}
func BridgeMeasurementPeriodicityValueCodecFieldEncode(v *MeasurementPeriodicityValueCodec) *func(MeasurementPeriodicity, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMeasurementPeriodicityValueCodecFieldPath(v *MeasurementPeriodicityValueCodec) *q5.Path {
	return &v.path
}
func BridgeMeasurementPeriodicityValueCodecMethodEncodeBudget(v MeasurementPeriodicityValueCodec, a0 MeasurementPeriodicity, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeMeasurementPeriodicityValueCodecMethodEncodeChanged(v MeasurementPeriodicityValueCodec, a0 MeasurementPeriodicity, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMeasurementQuantitiesValueAPERValueFieldContext(v *MeasurementQuantitiesValueAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementQuantitiesValueAPERValueFieldReceived(v *MeasurementQuantitiesValueAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeMeasurementQuantitiesValueAPERValueFieldReplay(v *MeasurementQuantitiesValueAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeMeasurementQuantitiesValueAPERValueFieldWithoutReplay(v *MeasurementQuantitiesValueAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementQuantitiesValueValueCodecFieldCapture(v *MeasurementQuantitiesValueValueCodec) *func(MeasurementQuantitiesValue, q5.DecodeState) (MeasurementQuantitiesValue, q5.Snapshot) {
	return &v.capture
}
func BridgeMeasurementQuantitiesValueValueCodecFieldCompare(v *MeasurementQuantitiesValueValueCodec) *func(MeasurementQuantitiesValue, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeMeasurementQuantitiesValueValueCodecFieldContext(v *MeasurementQuantitiesValueValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementQuantitiesValueValueCodecFieldDecode(v *MeasurementQuantitiesValueValueCodec) *func([]byte, q5.DecodeState) (MeasurementQuantitiesValue, error) {
	return &v.decode
}
func BridgeMeasurementQuantitiesValueValueCodecFieldEncode(v *MeasurementQuantitiesValueValueCodec) *func(MeasurementQuantitiesValue, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMeasurementQuantitiesValueValueCodecFieldPath(v *MeasurementQuantitiesValueValueCodec) *q5.Path {
	return &v.path
}
func BridgeMeasurementQuantitiesValueValueCodecMethodEncodeBudget(v MeasurementQuantitiesValueValueCodec, a0 MeasurementQuantitiesValue, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeMeasurementQuantitiesValueValueCodecMethodEncodeChanged(v MeasurementQuantitiesValueValueCodec, a0 MeasurementQuantitiesValue, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNPRSSequenceInfoAPERValueFieldContext(v *NPRSSequenceInfoAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeNPRSSequenceInfoAPERValueFieldReceived(v *NPRSSequenceInfoAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeNPRSSequenceInfoAPERValueFieldReplay(v *NPRSSequenceInfoAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeNPRSSequenceInfoAPERValueFieldWithoutReplay(v *NPRSSequenceInfoAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNPRSSequenceInfoValueCodecFieldCapture(v *NPRSSequenceInfoValueCodec) *func(NPRSSequenceInfo, q5.DecodeState) (NPRSSequenceInfo, q5.Snapshot) {
	return &v.capture
}
func BridgeNPRSSequenceInfoValueCodecFieldCompare(v *NPRSSequenceInfoValueCodec) *func(NPRSSequenceInfo, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeNPRSSequenceInfoValueCodecFieldContext(v *NPRSSequenceInfoValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeNPRSSequenceInfoValueCodecFieldDecode(v *NPRSSequenceInfoValueCodec) *func([]byte, q5.DecodeState) (NPRSSequenceInfo, error) {
	return &v.decode
}
func BridgeNPRSSequenceInfoValueCodecFieldEncode(v *NPRSSequenceInfoValueCodec) *func(NPRSSequenceInfo, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNPRSSequenceInfoValueCodecFieldPath(v *NPRSSequenceInfoValueCodec) *q5.Path {
	return &v.path
}
func BridgeNPRSSequenceInfoValueCodecMethodEncodeBudget(v NPRSSequenceInfoValueCodec, a0 NPRSSequenceInfo, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNPRSSequenceInfoValueCodecMethodEncodeChanged(v NPRSSequenceInfoValueCodec, a0 NPRSSequenceInfo, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNRARFCNAPERValueFieldContext(v *NRARFCNAPERValue) *BridgeCodecContext { return &v.context }
func BridgeNRARFCNAPERValueFieldReceived(v *NRARFCNAPERValue) *q5.WireSpan       { return &v.received }
func BridgeNRARFCNAPERValueFieldReplay(v *NRARFCNAPERValue) *q5.Snapshot         { return &v.replay }
func BridgeNRARFCNAPERValueFieldWithoutReplay(v *NRARFCNAPERValue) *bool         { return &v.withoutReplay }
func BridgeNRARFCNValueCodecFieldCapture(v *NRARFCNValueCodec) *func(NRARFCN, q5.DecodeState) (NRARFCN, q5.Snapshot) {
	return &v.capture
}
func BridgeNRARFCNValueCodecFieldCompare(v *NRARFCNValueCodec) *func(NRARFCN, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeNRARFCNValueCodecFieldContext(v *NRARFCNValueCodec) *BridgeCodecContext { return &v.context }
func BridgeNRARFCNValueCodecFieldDecode(v *NRARFCNValueCodec) *func([]byte, q5.DecodeState) (NRARFCN, error) {
	return &v.decode
}
func BridgeNRARFCNValueCodecFieldEncode(v *NRARFCNValueCodec) *func(NRARFCN, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRARFCNValueCodecFieldPath(v *NRARFCNValueCodec) *q5.Path { return &v.path }
func BridgeNRARFCNValueCodecMethodEncodeBudget(v NRARFCNValueCodec, a0 NRARFCN, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNRARFCNValueCodecMethodEncodeChanged(v NRARFCNValueCodec, a0 NRARFCN, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNRCellIdentityAPERValueFieldContext(v *NRCellIdentityAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeNRCellIdentityAPERValueFieldReceived(v *NRCellIdentityAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeNRCellIdentityAPERValueFieldReplay(v *NRCellIdentityAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeNRCellIdentityAPERValueFieldWithoutReplay(v *NRCellIdentityAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNRCellIdentityValueCodecFieldCapture(v *NRCellIdentityValueCodec) *func(NRCellIdentity, q5.DecodeState) (NRCellIdentity, q5.Snapshot) {
	return &v.capture
}
func BridgeNRCellIdentityValueCodecFieldCompare(v *NRCellIdentityValueCodec) *func(NRCellIdentity, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeNRCellIdentityValueCodecFieldContext(v *NRCellIdentityValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeNRCellIdentityValueCodecFieldDecode(v *NRCellIdentityValueCodec) *func([]byte, q5.DecodeState) (NRCellIdentity, error) {
	return &v.decode
}
func BridgeNRCellIdentityValueCodecFieldEncode(v *NRCellIdentityValueCodec) *func(NRCellIdentity, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRCellIdentityValueCodecFieldPath(v *NRCellIdentityValueCodec) *q5.Path { return &v.path }
func BridgeNRCellIdentityValueCodecMethodEncodeBudget(v NRCellIdentityValueCodec, a0 NRCellIdentity, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNRCellIdentityValueCodecMethodEncodeChanged(v NRCellIdentityValueCodec, a0 NRCellIdentity, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNRPCIAPERValueFieldContext(v *NRPCIAPERValue) *BridgeCodecContext { return &v.context }
func BridgeNRPCIAPERValueFieldReceived(v *NRPCIAPERValue) *q5.WireSpan       { return &v.received }
func BridgeNRPCIAPERValueFieldReplay(v *NRPCIAPERValue) *q5.Snapshot         { return &v.replay }
func BridgeNRPCIAPERValueFieldWithoutReplay(v *NRPCIAPERValue) *bool         { return &v.withoutReplay }
func BridgeNRPCIValueCodecFieldCapture(v *NRPCIValueCodec) *func(NRPCI, q5.DecodeState) (NRPCI, q5.Snapshot) {
	return &v.capture
}
func BridgeNRPCIValueCodecFieldCompare(v *NRPCIValueCodec) *func(NRPCI, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeNRPCIValueCodecFieldContext(v *NRPCIValueCodec) *BridgeCodecContext { return &v.context }
func BridgeNRPCIValueCodecFieldDecode(v *NRPCIValueCodec) *func([]byte, q5.DecodeState) (NRPCI, error) {
	return &v.decode
}
func BridgeNRPCIValueCodecFieldEncode(v *NRPCIValueCodec) *func(NRPCI, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRPCIValueCodecFieldPath(v *NRPCIValueCodec) *q5.Path { return &v.path }
func BridgeNRPCIValueCodecMethodEncodeBudget(v NRPCIValueCodec, a0 NRPCI, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNRPCIValueCodecMethodEncodeChanged(v NRPCIValueCodec, a0 NRPCI, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNarrowBandIndexAPERValueFieldContext(v *NarrowBandIndexAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeNarrowBandIndexAPERValueFieldReceived(v *NarrowBandIndexAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeNarrowBandIndexAPERValueFieldReplay(v *NarrowBandIndexAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeNarrowBandIndexAPERValueFieldWithoutReplay(v *NarrowBandIndexAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNarrowBandIndexValueCodecFieldCapture(v *NarrowBandIndexValueCodec) *func(NarrowBandIndex, q5.DecodeState) (NarrowBandIndex, q5.Snapshot) {
	return &v.capture
}
func BridgeNarrowBandIndexValueCodecFieldCompare(v *NarrowBandIndexValueCodec) *func(NarrowBandIndex, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeNarrowBandIndexValueCodecFieldContext(v *NarrowBandIndexValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeNarrowBandIndexValueCodecFieldDecode(v *NarrowBandIndexValueCodec) *func([]byte, q5.DecodeState) (NarrowBandIndex, error) {
	return &v.decode
}
func BridgeNarrowBandIndexValueCodecFieldEncode(v *NarrowBandIndexValueCodec) *func(NarrowBandIndex, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNarrowBandIndexValueCodecFieldPath(v *NarrowBandIndexValueCodec) *q5.Path { return &v.path }
func BridgeNarrowBandIndexValueCodecMethodEncodeBudget(v NarrowBandIndexValueCodec, a0 NarrowBandIndex, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNarrowBandIndexValueCodecMethodEncodeChanged(v NarrowBandIndexValueCodec, a0 NarrowBandIndex, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNumberOfAntennaPortsAPERValueFieldContext(v *NumberOfAntennaPortsAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeNumberOfAntennaPortsAPERValueFieldReceived(v *NumberOfAntennaPortsAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeNumberOfAntennaPortsAPERValueFieldReplay(v *NumberOfAntennaPortsAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeNumberOfAntennaPortsAPERValueFieldWithoutReplay(v *NumberOfAntennaPortsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNumberOfAntennaPortsValueCodecFieldCapture(v *NumberOfAntennaPortsValueCodec) *func(NumberOfAntennaPorts, q5.DecodeState) (NumberOfAntennaPorts, q5.Snapshot) {
	return &v.capture
}
func BridgeNumberOfAntennaPortsValueCodecFieldCompare(v *NumberOfAntennaPortsValueCodec) *func(NumberOfAntennaPorts, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeNumberOfAntennaPortsValueCodecFieldContext(v *NumberOfAntennaPortsValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeNumberOfAntennaPortsValueCodecFieldDecode(v *NumberOfAntennaPortsValueCodec) *func([]byte, q5.DecodeState) (NumberOfAntennaPorts, error) {
	return &v.decode
}
func BridgeNumberOfAntennaPortsValueCodecFieldEncode(v *NumberOfAntennaPortsValueCodec) *func(NumberOfAntennaPorts, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNumberOfAntennaPortsValueCodecFieldPath(v *NumberOfAntennaPortsValueCodec) *q5.Path {
	return &v.path
}
func BridgeNumberOfAntennaPortsValueCodecMethodEncodeBudget(v NumberOfAntennaPortsValueCodec, a0 NumberOfAntennaPorts, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNumberOfAntennaPortsValueCodecMethodEncodeChanged(v NumberOfAntennaPortsValueCodec, a0 NumberOfAntennaPorts, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNumberOfDlFramesAPERValueFieldContext(v *NumberOfDlFramesAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeNumberOfDlFramesAPERValueFieldReceived(v *NumberOfDlFramesAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeNumberOfDlFramesAPERValueFieldReplay(v *NumberOfDlFramesAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeNumberOfDlFramesAPERValueFieldWithoutReplay(v *NumberOfDlFramesAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNumberOfDlFramesExtendedAPERValueFieldContext(v *NumberOfDlFramesExtendedAPERValue) *BridgeCodecContext {
	return &v.context
}
func BridgeNumberOfDlFramesExtendedAPERValueFieldReceived(v *NumberOfDlFramesExtendedAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeNumberOfDlFramesExtendedAPERValueFieldReplay(v *NumberOfDlFramesExtendedAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeNumberOfDlFramesExtendedAPERValueFieldWithoutReplay(v *NumberOfDlFramesExtendedAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNumberOfDlFramesExtendedValueCodecFieldCapture(v *NumberOfDlFramesExtendedValueCodec) *func(NumberOfDlFramesExtended, q5.DecodeState) (NumberOfDlFramesExtended, q5.Snapshot) {
	return &v.capture
}
func BridgeNumberOfDlFramesExtendedValueCodecFieldCompare(v *NumberOfDlFramesExtendedValueCodec) *func(NumberOfDlFramesExtended, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeNumberOfDlFramesExtendedValueCodecFieldContext(v *NumberOfDlFramesExtendedValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeNumberOfDlFramesExtendedValueCodecFieldDecode(v *NumberOfDlFramesExtendedValueCodec) *func([]byte, q5.DecodeState) (NumberOfDlFramesExtended, error) {
	return &v.decode
}
func BridgeNumberOfDlFramesExtendedValueCodecFieldEncode(v *NumberOfDlFramesExtendedValueCodec) *func(NumberOfDlFramesExtended, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNumberOfDlFramesExtendedValueCodecFieldPath(v *NumberOfDlFramesExtendedValueCodec) *q5.Path {
	return &v.path
}
func BridgeNumberOfDlFramesExtendedValueCodecMethodEncodeBudget(v NumberOfDlFramesExtendedValueCodec, a0 NumberOfDlFramesExtended, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNumberOfDlFramesExtendedValueCodecMethodEncodeChanged(v NumberOfDlFramesExtendedValueCodec, a0 NumberOfDlFramesExtended, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeNumberOfDlFramesValueCodecFieldCapture(v *NumberOfDlFramesValueCodec) *func(NumberOfDlFrames, q5.DecodeState) (NumberOfDlFrames, q5.Snapshot) {
	return &v.capture
}
func BridgeNumberOfDlFramesValueCodecFieldCompare(v *NumberOfDlFramesValueCodec) *func(NumberOfDlFrames, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeNumberOfDlFramesValueCodecFieldContext(v *NumberOfDlFramesValueCodec) *BridgeCodecContext {
	return &v.context
}
func BridgeNumberOfDlFramesValueCodecFieldDecode(v *NumberOfDlFramesValueCodec) *func([]byte, q5.DecodeState) (NumberOfDlFrames, error) {
	return &v.decode
}
func BridgeNumberOfDlFramesValueCodecFieldEncode(v *NumberOfDlFramesValueCodec) *func(NumberOfDlFrames, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNumberOfDlFramesValueCodecFieldPath(v *NumberOfDlFramesValueCodec) *q5.Path {
	return &v.path
}
func BridgeNumberOfDlFramesValueCodecMethodEncodeBudget(v NumberOfDlFramesValueCodec, a0 NumberOfDlFrames, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNumberOfDlFramesValueCodecMethodEncodeChanged(v NumberOfDlFramesValueCodec, a0 NumberOfDlFrames, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTableIDFieldSource(v *TableID) *q5.SourceAssignment    { return &v.source }
func BridgeTypeIDFieldSource(v *TypeID) *q5.SourceAssignment      { return &v.source }
func BridgecodecContextFieldSource(v *BridgeCodecContext) *string { return &v.source }
