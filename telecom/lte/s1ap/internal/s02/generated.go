// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s02 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s02

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// TransportLayerAddressValueCodec is the concrete ValueCodec[TransportLayerAddress].
type TransportLayerAddressValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TransportLayerAddress,

		error)
	encode func(s00.TransportLayerAddress,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TransportLayerAddress, aper.DecodeState,

	) (s00.TransportLayerAddress, aper.Snapshot,

	)
	compare func(s00.TransportLayerAddress, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TransportLayerAddressValueCodec) New(value s00.TransportLayerAddress,

) (TransportLayerAddressAPERValue, error) {
	if c.encode == nil {
		return TransportLayerAddressAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TransportLayerAddressAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TransportLayerAddressAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TransportLayerAddressAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TransportLayerAddressValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TransportLayerAddressAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TransportLayerAddressAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TransportLayerAddressAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TransportLayerAddressAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TransportLayerAddressAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TransportLayerAddressValueCodec) EncodeAPER(value TransportLayerAddressAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TransportLayerAddressValueCodec) encodeBudgetValue(value s00.TransportLayerAddress,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TransportLayerAddressValueCodec) encodeChanged(value s00.TransportLayerAddress,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UnlicensedSpectrumRestrictionValueCodec is the concrete ValueCodec[UnlicensedSpectrumRestriction].
type UnlicensedSpectrumRestrictionValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.UnlicensedSpectrumRestriction,

		error)
	encode func(s00.UnlicensedSpectrumRestriction,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.UnlicensedSpectrumRestriction, aper.DecodeState,

	) (s00.UnlicensedSpectrumRestriction, aper.Snapshot,

	)
	compare func(s00.UnlicensedSpectrumRestriction, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UnlicensedSpectrumRestrictionValueCodec) New(value s00.UnlicensedSpectrumRestriction,

) (UnlicensedSpectrumRestrictionAPERValue, error) {
	if c.encode == nil {
		return UnlicensedSpectrumRestrictionAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UnlicensedSpectrumRestrictionAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UnlicensedSpectrumRestrictionAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UnlicensedSpectrumRestrictionAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UnlicensedSpectrumRestrictionValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UnlicensedSpectrumRestrictionAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UnlicensedSpectrumRestrictionAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UnlicensedSpectrumRestrictionAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UnlicensedSpectrumRestrictionAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UnlicensedSpectrumRestrictionAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UnlicensedSpectrumRestrictionValueCodec) EncodeAPER(value UnlicensedSpectrumRestrictionAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UnlicensedSpectrumRestrictionValueCodec) encodeBudgetValue(value s00.UnlicensedSpectrumRestriction,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UnlicensedSpectrumRestrictionValueCodec) encodeChanged(value s00.UnlicensedSpectrumRestriction,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TimeUEStayedInCellEnhancedGranularityValueCodec is the concrete ValueCodec[TimeUEStayedInCellEnhancedGranularity].
type TimeUEStayedInCellEnhancedGranularityValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TimeUEStayedInCellEnhancedGranularity,

		error)
	encode func(s00.TimeUEStayedInCellEnhancedGranularity,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TimeUEStayedInCellEnhancedGranularity, aper.DecodeState,

	) (s00.TimeUEStayedInCellEnhancedGranularity, aper.Snapshot,

	)
	compare func(s00.TimeUEStayedInCellEnhancedGranularity, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TimeUEStayedInCellEnhancedGranularityValueCodec) New(value s00.TimeUEStayedInCellEnhancedGranularity,

) (TimeUEStayedInCellEnhancedGranularityAPERValue, error) {
	if c.encode == nil {
		return TimeUEStayedInCellEnhancedGranularityAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TimeUEStayedInCellEnhancedGranularityAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TimeUEStayedInCellEnhancedGranularityAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TimeUEStayedInCellEnhancedGranularityAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TimeUEStayedInCellEnhancedGranularityValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TimeUEStayedInCellEnhancedGranularityAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TimeUEStayedInCellEnhancedGranularityAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TimeUEStayedInCellEnhancedGranularityAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TimeUEStayedInCellEnhancedGranularityAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TimeUEStayedInCellEnhancedGranularityAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TimeUEStayedInCellEnhancedGranularityValueCodec) EncodeAPER(value TimeUEStayedInCellEnhancedGranularityAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TimeUEStayedInCellEnhancedGranularityValueCodec) encodeBudgetValue(value s00.TimeUEStayedInCellEnhancedGranularity,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TimeUEStayedInCellEnhancedGranularityValueCodec) encodeChanged(value s00.TimeUEStayedInCellEnhancedGranularity,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEHistoryInformationFromTheUEValueCodec is the concrete ValueCodec[UEHistoryInformationFromTheUE].
type UEHistoryInformationFromTheUEValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.UEHistoryInformationFromTheUE,

		error)
	encode func(s00.UEHistoryInformationFromTheUE,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.UEHistoryInformationFromTheUE, aper.DecodeState,

	) (s00.UEHistoryInformationFromTheUE, aper.Snapshot,

	)
	compare func(s00.UEHistoryInformationFromTheUE, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEHistoryInformationFromTheUEValueCodec) New(value s00.UEHistoryInformationFromTheUE,

) (UEHistoryInformationFromTheUEAPERValue, error) {
	if c.encode == nil {
		return UEHistoryInformationFromTheUEAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEHistoryInformationFromTheUEAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEHistoryInformationFromTheUEAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEHistoryInformationFromTheUEAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEHistoryInformationFromTheUEValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEHistoryInformationFromTheUEAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEHistoryInformationFromTheUEAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEHistoryInformationFromTheUEAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEHistoryInformationFromTheUEAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEHistoryInformationFromTheUEAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEHistoryInformationFromTheUEValueCodec) EncodeAPER(value UEHistoryInformationFromTheUEAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEHistoryInformationFromTheUEValueCodec) encodeBudgetValue(value s00.UEHistoryInformationFromTheUE,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEHistoryInformationFromTheUEValueCodec) encodeChanged(value s00.UEHistoryInformationFromTheUE,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// URIAddressValueCodec is the concrete ValueCodec[URIAddress].
type URIAddressValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.URIAddress,

		error)
	encode func(s00.URIAddress,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.URIAddress, aper.DecodeState,

	) (s00.URIAddress, aper.Snapshot,

	)
	compare func(s00.URIAddress, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c URIAddressValueCodec) New(value s00.URIAddress,

) (URIAddressAPERValue, error) {
	if c.encode == nil {
		return URIAddressAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return URIAddressAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return URIAddressAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return URIAddressAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c URIAddressValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (URIAddressAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return URIAddressAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return URIAddressAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return URIAddressAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return URIAddressAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c URIAddressValueCodec) EncodeAPER(value URIAddressAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c URIAddressValueCodec) encodeBudgetValue(value s00.URIAddress,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c URIAddressValueCodec) encodeChanged(value s00.URIAddress,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityValueCodec is the concrete ValueCodec[UERadioCapability].
type UERadioCapabilityValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.UERadioCapability,

		error)
	encode func(s00.UERadioCapability,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.UERadioCapability, aper.DecodeState,

	) (s00.UERadioCapability, aper.Snapshot,

	)
	compare func(s00.UERadioCapability, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityValueCodec) New(value s00.UERadioCapability,

) (UERadioCapabilityAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityValueCodec) EncodeAPER(value UERadioCapabilityAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERadioCapabilityValueCodec) encodeBudgetValue(value s00.UERadioCapability,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityValueCodec) encodeChanged(value s00.UERadioCapability,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityIDValueCodec is the concrete ValueCodec[UERadioCapabilityID].
type UERadioCapabilityIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.UERadioCapabilityID,

		error)
	encode func(s00.UERadioCapabilityID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.UERadioCapabilityID, aper.DecodeState,

	) (s00.UERadioCapabilityID, aper.Snapshot,

	)
	compare func(s00.UERadioCapabilityID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityIDValueCodec) New(value s00.UERadioCapabilityID,

) (UERadioCapabilityIDAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityIDValueCodec) EncodeAPER(value UERadioCapabilityIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERadioCapabilityIDValueCodec) encodeBudgetValue(value s00.UERadioCapabilityID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityIDValueCodec) encodeChanged(value s00.UERadioCapabilityID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UECapabilityInfoRequestValueCodec is the concrete ValueCodec[UECapabilityInfoRequest].
type UECapabilityInfoRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.UECapabilityInfoRequest,

		error)
	encode func(s00.UECapabilityInfoRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.UECapabilityInfoRequest, aper.DecodeState,

	) (s00.UECapabilityInfoRequest, aper.Snapshot,

	)
	compare func(s00.UECapabilityInfoRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UECapabilityInfoRequestValueCodec) New(value s00.UECapabilityInfoRequest,

) (UECapabilityInfoRequestAPERValue, error) {
	if c.encode == nil {
		return UECapabilityInfoRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UECapabilityInfoRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UECapabilityInfoRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UECapabilityInfoRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UECapabilityInfoRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UECapabilityInfoRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UECapabilityInfoRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UECapabilityInfoRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UECapabilityInfoRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UECapabilityInfoRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UECapabilityInfoRequestValueCodec) EncodeAPER(value UECapabilityInfoRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UECapabilityInfoRequestValueCodec) encodeBudgetValue(value s00.UECapabilityInfoRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UECapabilityInfoRequestValueCodec) encodeChanged(value s00.UECapabilityInfoRequest,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TimeToWaitValueCodec is the concrete ValueCodec[TimeToWait].
type TimeToWaitValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TimeToWait,

		error)
	encode func(s00.TimeToWait,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TimeToWait, aper.DecodeState,

	) (s00.TimeToWait, aper.Snapshot,

	)
	compare func(s00.TimeToWait, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TimeToWaitValueCodec) New(value s00.TimeToWait,

) (TimeToWaitAPERValue, error) {
	if c.encode == nil {
		return TimeToWaitAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TimeToWaitAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TimeToWaitAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TimeToWaitAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TimeToWaitValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TimeToWaitAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TimeToWaitAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TimeToWaitAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TimeToWaitAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TimeToWaitAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TimeToWaitValueCodec) EncodeAPER(value TimeToWaitAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TimeToWaitValueCodec) encodeBudgetValue(value s00.TimeToWait,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TimeToWaitValueCodec) encodeChanged(value s00.TimeToWait,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEUserPlaneCIoTSupportIndicatorValueCodec is the concrete ValueCodec[UEUserPlaneCIoTSupportIndicator].
type UEUserPlaneCIoTSupportIndicatorValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.UEUserPlaneCIoTSupportIndicator,

		error)
	encode func(s00.UEUserPlaneCIoTSupportIndicator,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.UEUserPlaneCIoTSupportIndicator, aper.DecodeState,

	) (s00.UEUserPlaneCIoTSupportIndicator, aper.Snapshot,

	)
	compare func(s00.UEUserPlaneCIoTSupportIndicator, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEUserPlaneCIoTSupportIndicatorValueCodec) New(value s00.UEUserPlaneCIoTSupportIndicator,

) (UEUserPlaneCIoTSupportIndicatorAPERValue, error) {
	if c.encode == nil {
		return UEUserPlaneCIoTSupportIndicatorAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEUserPlaneCIoTSupportIndicatorAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEUserPlaneCIoTSupportIndicatorAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEUserPlaneCIoTSupportIndicatorAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEUserPlaneCIoTSupportIndicatorValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEUserPlaneCIoTSupportIndicatorAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEUserPlaneCIoTSupportIndicatorAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEUserPlaneCIoTSupportIndicatorAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEUserPlaneCIoTSupportIndicatorAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEUserPlaneCIoTSupportIndicatorAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEUserPlaneCIoTSupportIndicatorValueCodec) EncodeAPER(value UEUserPlaneCIoTSupportIndicatorAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEUserPlaneCIoTSupportIndicatorValueCodec) encodeBudgetValue(value s00.UEUserPlaneCIoTSupportIndicator,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEUserPlaneCIoTSupportIndicatorValueCodec) encodeChanged(value s00.UEUserPlaneCIoTSupportIndicator,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TimeRefDistributionValueCodec is the concrete ValueCodec[TimeRefDistribution].
type TimeRefDistributionValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TimeRefDistribution,

		error)
	encode func(s00.TimeRefDistribution,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TimeRefDistribution, aper.DecodeState,

	) (s00.TimeRefDistribution, aper.Snapshot,

	)
	compare func(s00.TimeRefDistribution, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TimeRefDistributionValueCodec) New(value s00.TimeRefDistribution,

) (TimeRefDistributionAPERValue, error) {
	if c.encode == nil {
		return TimeRefDistributionAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TimeRefDistributionAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TimeRefDistributionAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TimeRefDistributionAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TimeRefDistributionValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TimeRefDistributionAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TimeRefDistributionAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TimeRefDistributionAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TimeRefDistributionAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TimeRefDistributionAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TimeRefDistributionValueCodec) EncodeAPER(value TimeRefDistributionAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TimeRefDistributionValueCodec) encodeBudgetValue(value s00.TimeRefDistribution,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TimeRefDistributionValueCodec) encodeChanged(value s00.TimeRefDistribution,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEUsageTypeValueCodec is the concrete ValueCodec[UEUsageType].
type UEUsageTypeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.UEUsageType,

		error)
	encode func(s00.UEUsageType,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.UEUsageType, aper.DecodeState,

	) (s00.UEUsageType, aper.Snapshot,

	)
	compare func(s00.UEUsageType, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEUsageTypeValueCodec) New(value s00.UEUsageType,

) (UEUsageTypeAPERValue, error) {
	if c.encode == nil {
		return UEUsageTypeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEUsageTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEUsageTypeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEUsageTypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEUsageTypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEUsageTypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEUsageTypeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEUsageTypeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEUsageTypeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEUsageTypeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEUsageTypeValueCodec) EncodeAPER(value UEUsageTypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEUsageTypeValueCodec) encodeBudgetValue(value s00.UEUsageType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEUsageTypeValueCodec) encodeChanged(value s00.UEUsageType,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEApplicationLayerMeasurementCapabilityValueCodec is the concrete ValueCodec[UEApplicationLayerMeasurementCapability].
type UEApplicationLayerMeasurementCapabilityValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.UEApplicationLayerMeasurementCapability,

		error)
	encode func(s00.UEApplicationLayerMeasurementCapability,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.UEApplicationLayerMeasurementCapability, aper.DecodeState,

	) (s00.UEApplicationLayerMeasurementCapability, aper.Snapshot,

	)
	compare func(s00.UEApplicationLayerMeasurementCapability, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEApplicationLayerMeasurementCapabilityValueCodec) New(value s00.UEApplicationLayerMeasurementCapability,

) (UEApplicationLayerMeasurementCapabilityAPERValue, error) {
	if c.encode == nil {
		return UEApplicationLayerMeasurementCapabilityAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEApplicationLayerMeasurementCapabilityAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEApplicationLayerMeasurementCapabilityAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEApplicationLayerMeasurementCapabilityAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEApplicationLayerMeasurementCapabilityValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEApplicationLayerMeasurementCapabilityAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEApplicationLayerMeasurementCapabilityAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEApplicationLayerMeasurementCapabilityAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEApplicationLayerMeasurementCapabilityAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEApplicationLayerMeasurementCapabilityAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEApplicationLayerMeasurementCapabilityValueCodec) EncodeAPER(value UEApplicationLayerMeasurementCapabilityAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEApplicationLayerMeasurementCapabilityValueCodec) encodeBudgetValue(value s00.UEApplicationLayerMeasurementCapability,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEApplicationLayerMeasurementCapabilityValueCodec) encodeChanged(value s00.UEApplicationLayerMeasurementCapability,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TrafficLoadReductionIndicationValueCodec is the concrete ValueCodec[TrafficLoadReductionIndication].
type TrafficLoadReductionIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TrafficLoadReductionIndication,

		error)
	encode func(s00.TrafficLoadReductionIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TrafficLoadReductionIndication, aper.DecodeState,

	) (s00.TrafficLoadReductionIndication, aper.Snapshot,

	)
	compare func(s00.TrafficLoadReductionIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TrafficLoadReductionIndicationValueCodec) New(value s00.TrafficLoadReductionIndication,

) (TrafficLoadReductionIndicationAPERValue, error) {
	if c.encode == nil {
		return TrafficLoadReductionIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TrafficLoadReductionIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TrafficLoadReductionIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TrafficLoadReductionIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TrafficLoadReductionIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TrafficLoadReductionIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TrafficLoadReductionIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TrafficLoadReductionIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TrafficLoadReductionIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TrafficLoadReductionIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TrafficLoadReductionIndicationValueCodec) EncodeAPER(value TrafficLoadReductionIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TrafficLoadReductionIndicationValueCodec) encodeBudgetValue(value s00.TrafficLoadReductionIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TrafficLoadReductionIndicationValueCodec) encodeChanged(value s00.TrafficLoadReductionIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UEIdentityIndexValueValueCodec is the concrete ValueCodec[UEIdentityIndexValue].
type UEIdentityIndexValueValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.UEIdentityIndexValue,

		error)
	encode func(s00.UEIdentityIndexValue,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.UEIdentityIndexValue, aper.DecodeState,

	) (s00.UEIdentityIndexValue, aper.Snapshot,

	)
	compare func(s00.UEIdentityIndexValue, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UEIdentityIndexValueValueCodec) New(value s00.UEIdentityIndexValue,

) (UEIdentityIndexValueAPERValue, error) {
	if c.encode == nil {
		return UEIdentityIndexValueAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UEIdentityIndexValueAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UEIdentityIndexValueAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UEIdentityIndexValueAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UEIdentityIndexValueValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UEIdentityIndexValueAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UEIdentityIndexValueAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UEIdentityIndexValueAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UEIdentityIndexValueAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UEIdentityIndexValueAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UEIdentityIndexValueValueCodec) EncodeAPER(value UEIdentityIndexValueAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UEIdentityIndexValueValueCodec) encodeBudgetValue(value s00.UEIdentityIndexValue,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UEIdentityIndexValueValueCodec) encodeChanged(value s00.UEIdentityIndexValue,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERadioCapabilityForPagingValueCodec is the concrete ValueCodec[UERadioCapabilityForPaging].
type UERadioCapabilityForPagingValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.UERadioCapabilityForPaging,

		error)
	encode func(s00.UERadioCapabilityForPaging,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.UERadioCapabilityForPaging, aper.DecodeState,

	) (s00.UERadioCapabilityForPaging, aper.Snapshot,

	)
	compare func(s00.UERadioCapabilityForPaging, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERadioCapabilityForPagingValueCodec) New(value s00.UERadioCapabilityForPaging,

) (UERadioCapabilityForPagingAPERValue, error) {
	if c.encode == nil {
		return UERadioCapabilityForPagingAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERadioCapabilityForPagingAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERadioCapabilityForPagingAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERadioCapabilityForPagingAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERadioCapabilityForPagingValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERadioCapabilityForPagingAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERadioCapabilityForPagingAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERadioCapabilityForPagingAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERadioCapabilityForPagingAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERadioCapabilityForPagingAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERadioCapabilityForPagingValueCodec) EncodeAPER(value UERadioCapabilityForPagingAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERadioCapabilityForPagingValueCodec) encodeBudgetValue(value s00.UERadioCapabilityForPaging,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERadioCapabilityForPagingValueCodec) encodeChanged(value s00.UERadioCapabilityForPaging,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERetentionInformationValueCodec is the concrete ValueCodec[UERetentionInformation].
type UERetentionInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.UERetentionInformation,

		error)
	encode func(s00.UERetentionInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.UERetentionInformation, aper.DecodeState,

	) (s00.UERetentionInformation, aper.Snapshot,

	)
	compare func(s00.UERetentionInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERetentionInformationValueCodec) New(value s00.UERetentionInformation,

) (UERetentionInformationAPERValue, error) {
	if c.encode == nil {
		return UERetentionInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERetentionInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERetentionInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERetentionInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERetentionInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERetentionInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERetentionInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERetentionInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERetentionInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERetentionInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERetentionInformationValueCodec) EncodeAPER(value UERetentionInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERetentionInformationValueCodec) encodeBudgetValue(value s00.UERetentionInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERetentionInformationValueCodec) encodeChanged(value s00.UERetentionInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TimeSinceSecondaryNodeReleaseValueCodec is the concrete ValueCodec[TimeSinceSecondaryNodeRelease].
type TimeSinceSecondaryNodeReleaseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TimeSinceSecondaryNodeRelease,

		error)
	encode func(s00.TimeSinceSecondaryNodeRelease,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TimeSinceSecondaryNodeRelease, aper.DecodeState,

	) (s00.TimeSinceSecondaryNodeRelease, aper.Snapshot,

	)
	compare func(s00.TimeSinceSecondaryNodeRelease, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TimeSinceSecondaryNodeReleaseValueCodec) New(value s00.TimeSinceSecondaryNodeRelease,

) (TimeSinceSecondaryNodeReleaseAPERValue, error) {
	if c.encode == nil {
		return TimeSinceSecondaryNodeReleaseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TimeSinceSecondaryNodeReleaseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TimeSinceSecondaryNodeReleaseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TimeSinceSecondaryNodeReleaseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TimeSinceSecondaryNodeReleaseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TimeSinceSecondaryNodeReleaseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TimeSinceSecondaryNodeReleaseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TimeSinceSecondaryNodeReleaseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TimeSinceSecondaryNodeReleaseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TimeSinceSecondaryNodeReleaseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TimeSinceSecondaryNodeReleaseValueCodec) EncodeAPER(value TimeSinceSecondaryNodeReleaseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TimeSinceSecondaryNodeReleaseValueCodec) encodeBudgetValue(value s00.TimeSinceSecondaryNodeRelease,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TimeSinceSecondaryNodeReleaseValueCodec) encodeChanged(value s00.TimeSinceSecondaryNodeRelease,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// VoiceSupportMatchIndicatorValueCodec is the concrete ValueCodec[VoiceSupportMatchIndicator].
type VoiceSupportMatchIndicatorValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.VoiceSupportMatchIndicator,

		error)
	encode func(s00.VoiceSupportMatchIndicator,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.VoiceSupportMatchIndicator, aper.DecodeState,

	) (s00.VoiceSupportMatchIndicator, aper.Snapshot,

	)
	compare func(s00.VoiceSupportMatchIndicator, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c VoiceSupportMatchIndicatorValueCodec) New(value s00.VoiceSupportMatchIndicator,

) (VoiceSupportMatchIndicatorAPERValue, error) {
	if c.encode == nil {
		return VoiceSupportMatchIndicatorAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return VoiceSupportMatchIndicatorAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return VoiceSupportMatchIndicatorAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return VoiceSupportMatchIndicatorAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c VoiceSupportMatchIndicatorValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (VoiceSupportMatchIndicatorAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return VoiceSupportMatchIndicatorAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return VoiceSupportMatchIndicatorAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return VoiceSupportMatchIndicatorAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return VoiceSupportMatchIndicatorAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c VoiceSupportMatchIndicatorValueCodec) EncodeAPER(value VoiceSupportMatchIndicatorAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c VoiceSupportMatchIndicatorValueCodec) encodeBudgetValue(value s00.VoiceSupportMatchIndicator,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c VoiceSupportMatchIndicatorValueCodec) encodeChanged(value s00.VoiceSupportMatchIndicator,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WarningTypeValueCodec is the concrete ValueCodec[WarningType].
type WarningTypeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.WarningType,

		error)
	encode func(s00.WarningType,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.WarningType, aper.DecodeState,

	) (s00.WarningType, aper.Snapshot,

	)
	compare func(s00.WarningType, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WarningTypeValueCodec) New(value s00.WarningType,

) (WarningTypeAPERValue, error) {
	if c.encode == nil {
		return WarningTypeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WarningTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WarningTypeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WarningTypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WarningTypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WarningTypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WarningTypeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WarningTypeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WarningTypeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WarningTypeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WarningTypeValueCodec) EncodeAPER(value WarningTypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WarningTypeValueCodec) encodeBudgetValue(value s00.WarningType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WarningTypeValueCodec) encodeChanged(value s00.WarningType,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WarningSecurityInfoValueCodec is the concrete ValueCodec[WarningSecurityInfo].
type WarningSecurityInfoValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.WarningSecurityInfo,

		error)
	encode func(s00.WarningSecurityInfo,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.WarningSecurityInfo, aper.DecodeState,

	) (s00.WarningSecurityInfo, aper.Snapshot,

	)
	compare func(s00.WarningSecurityInfo, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WarningSecurityInfoValueCodec) New(value s00.WarningSecurityInfo,

) (WarningSecurityInfoAPERValue, error) {
	if c.encode == nil {
		return WarningSecurityInfoAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WarningSecurityInfoAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WarningSecurityInfoAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WarningSecurityInfoAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WarningSecurityInfoValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WarningSecurityInfoAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WarningSecurityInfoAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WarningSecurityInfoAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WarningSecurityInfoAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WarningSecurityInfoAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WarningSecurityInfoValueCodec) EncodeAPER(value WarningSecurityInfoAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WarningSecurityInfoValueCodec) encodeBudgetValue(value s00.WarningSecurityInfo,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WarningSecurityInfoValueCodec) encodeChanged(value s00.WarningSecurityInfo,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WarningMessageContentsValueCodec is the concrete ValueCodec[WarningMessageContents].
type WarningMessageContentsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.WarningMessageContents,

		error)
	encode func(s00.WarningMessageContents,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.WarningMessageContents, aper.DecodeState,

	) (s00.WarningMessageContents, aper.Snapshot,

	)
	compare func(s00.WarningMessageContents, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WarningMessageContentsValueCodec) New(value s00.WarningMessageContents,

) (WarningMessageContentsAPERValue, error) {
	if c.encode == nil {
		return WarningMessageContentsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WarningMessageContentsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WarningMessageContentsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WarningMessageContentsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WarningMessageContentsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WarningMessageContentsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WarningMessageContentsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WarningMessageContentsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WarningMessageContentsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WarningMessageContentsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WarningMessageContentsValueCodec) EncodeAPER(value WarningMessageContentsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WarningMessageContentsValueCodec) encodeBudgetValue(value s00.WarningMessageContents,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WarningMessageContentsValueCodec) encodeChanged(value s00.WarningMessageContents,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WarningAreaCoordinatesValueCodec is the concrete ValueCodec[WarningAreaCoordinates].
type WarningAreaCoordinatesValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.WarningAreaCoordinates,

		error)
	encode func(s00.WarningAreaCoordinates,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.WarningAreaCoordinates, aper.DecodeState,

	) (s00.WarningAreaCoordinates, aper.Snapshot,

	)
	compare func(s00.WarningAreaCoordinates, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WarningAreaCoordinatesValueCodec) New(value s00.WarningAreaCoordinates,

) (WarningAreaCoordinatesAPERValue, error) {
	if c.encode == nil {
		return WarningAreaCoordinatesAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WarningAreaCoordinatesAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WarningAreaCoordinatesAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WarningAreaCoordinatesAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WarningAreaCoordinatesValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WarningAreaCoordinatesAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WarningAreaCoordinatesAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WarningAreaCoordinatesAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WarningAreaCoordinatesAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WarningAreaCoordinatesAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WarningAreaCoordinatesValueCodec) EncodeAPER(value WarningAreaCoordinatesAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WarningAreaCoordinatesValueCodec) encodeBudgetValue(value s00.WarningAreaCoordinates,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WarningAreaCoordinatesValueCodec) encodeChanged(value s00.WarningAreaCoordinates,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ThresholdRSRPValueCodec is the concrete ValueCodec[ThresholdRSRP].
type ThresholdRSRPValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ThresholdRSRP,

		error)
	encode func(s00.ThresholdRSRP,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ThresholdRSRP, aper.DecodeState,

	) (s00.ThresholdRSRP, aper.Snapshot,

	)
	compare func(s00.ThresholdRSRP, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ThresholdRSRPValueCodec) New(value s00.ThresholdRSRP,

) (s01.ThresholdRSRPAPERValue, error) {
	if c.encode == nil {
		return s01.ThresholdRSRPAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s01.ThresholdRSRPAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return s01.ThresholdRSRPAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return s01.ThresholdRSRPAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ThresholdRSRPValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (s01.ThresholdRSRPAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return s01.ThresholdRSRPAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return s01.ThresholdRSRPAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return func() s01.ThresholdRSRPAPERValue {
			sealed := s01.ThresholdRSRPAPERValue{Value: value}
			*s01.BridgeThresholdRSRPAPERValueFieldReceived(&sealed) = aper.OriginalWire(data)
			*s01.BridgeThresholdRSRPAPERValueFieldReplay(&sealed) = replay
			*s01.BridgeThresholdRSRPAPERValueFieldContext(&sealed) = c.context
			return sealed
		}(), report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return s01.ThresholdRSRPAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ThresholdRSRPValueCodec) EncodeAPER(value s01.ThresholdRSRPAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := *s01.BridgeThresholdRSRPAPERValueFieldWithoutReplay(&value) || aper.EncodeWithoutReplay(options...)
	if *s01.BridgeThresholdRSRPAPERValueFieldContext(&value) == c.context && !fresh && (*s01.BridgeThresholdRSRPAPERValueFieldReplay(&value)).Present() {
		plan, next := c.compare(value.Value, *s01.BridgeThresholdRSRPAPERValueFieldReplay(&value), budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(*s01.BridgeThresholdRSRPAPERValueFieldReplay(&value)) {
			out, err := aper.CopyReplay(*s01.BridgeThresholdRSRPAPERValueFieldReceived(&value), &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ThresholdRSRPValueCodec) encodeBudgetValue(value s00.ThresholdRSRP,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ThresholdRSRPValueCodec) encodeChanged(value s00.ThresholdRSRP,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ThresholdRSRQValueCodec is the concrete ValueCodec[ThresholdRSRQ].
type ThresholdRSRQValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ThresholdRSRQ,

		error)
	encode func(s00.ThresholdRSRQ,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ThresholdRSRQ, aper.DecodeState,

	) (s00.ThresholdRSRQ, aper.Snapshot,

	)
	compare func(s00.ThresholdRSRQ, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ThresholdRSRQValueCodec) New(value s00.ThresholdRSRQ,

) (ThresholdRSRQAPERValue, error) {
	if c.encode == nil {
		return ThresholdRSRQAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ThresholdRSRQAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ThresholdRSRQAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ThresholdRSRQAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ThresholdRSRQValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ThresholdRSRQAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ThresholdRSRQAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ThresholdRSRQAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ThresholdRSRQAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ThresholdRSRQAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ThresholdRSRQValueCodec) EncodeAPER(value ThresholdRSRQAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ThresholdRSRQValueCodec) encodeBudgetValue(value s00.ThresholdRSRQ,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ThresholdRSRQValueCodec) encodeChanged(value s00.ThresholdRSRQ,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TimeToTriggerValueCodec is the concrete ValueCodec[TimeToTrigger].
type TimeToTriggerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TimeToTrigger,

		error)
	encode func(s00.TimeToTrigger,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TimeToTrigger, aper.DecodeState,

	) (s00.TimeToTrigger, aper.Snapshot,

	)
	compare func(s00.TimeToTrigger, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TimeToTriggerValueCodec) New(value s00.TimeToTrigger,

) (TimeToTriggerAPERValue, error) {
	if c.encode == nil {
		return TimeToTriggerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TimeToTriggerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TimeToTriggerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TimeToTriggerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TimeToTriggerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TimeToTriggerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TimeToTriggerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TimeToTriggerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TimeToTriggerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TimeToTriggerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TimeToTriggerValueCodec) EncodeAPER(value TimeToTriggerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TimeToTriggerValueCodec) encodeBudgetValue(value s00.TimeToTrigger,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TimeToTriggerValueCodec) encodeChanged(value s00.TimeToTrigger,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TimeUEStayedInCellValueCodec is the concrete ValueCodec[TimeUEStayedInCell].
type TimeUEStayedInCellValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TimeUEStayedInCell,

		error)
	encode func(s00.TimeUEStayedInCell,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TimeUEStayedInCell, aper.DecodeState,

	) (s00.TimeUEStayedInCell, aper.Snapshot,

	)
	compare func(s00.TimeUEStayedInCell, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TimeUEStayedInCellValueCodec) New(value s00.TimeUEStayedInCell,

) (TimeUEStayedInCellAPERValue, error) {
	if c.encode == nil {
		return TimeUEStayedInCellAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TimeUEStayedInCellAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TimeUEStayedInCellAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TimeUEStayedInCellAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TimeUEStayedInCellValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TimeUEStayedInCellAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TimeUEStayedInCellAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TimeUEStayedInCellAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TimeUEStayedInCellAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TimeUEStayedInCellAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TimeUEStayedInCellValueCodec) EncodeAPER(value TimeUEStayedInCellAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TimeUEStayedInCellValueCodec) encodeBudgetValue(value s00.TimeUEStayedInCell,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TimeUEStayedInCellValueCodec) encodeChanged(value s00.TimeUEStayedInCell,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TraceDepthValueCodec is the concrete ValueCodec[TraceDepth].
type TraceDepthValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TraceDepth,

		error)
	encode func(s00.TraceDepth,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TraceDepth, aper.DecodeState,

	) (s00.TraceDepth, aper.Snapshot,

	)
	compare func(s00.TraceDepth, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TraceDepthValueCodec) New(value s00.TraceDepth,

) (TraceDepthAPERValue, error) {
	if c.encode == nil {
		return TraceDepthAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceDepthAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TraceDepthAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TraceDepthAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TraceDepthValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TraceDepthAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TraceDepthAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TraceDepthAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TraceDepthAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TraceDepthAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TraceDepthValueCodec) EncodeAPER(value TraceDepthAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TraceDepthValueCodec) encodeBudgetValue(value s00.TraceDepth,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TraceDepthValueCodec) encodeChanged(value s00.TraceDepth,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TriggeringMessageValueCodec is the concrete ValueCodec[TriggeringMessage].
type TriggeringMessageValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TriggeringMessage,

		error)
	encode func(s00.TriggeringMessage,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TriggeringMessage, aper.DecodeState,

	) (s00.TriggeringMessage, aper.Snapshot,

	)
	compare func(s00.TriggeringMessage, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TriggeringMessageValueCodec) New(value s00.TriggeringMessage,

) (TriggeringMessageAPERValue, error) {
	if c.encode == nil {
		return TriggeringMessageAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TriggeringMessageAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TriggeringMessageAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TriggeringMessageAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TriggeringMessageValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TriggeringMessageAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TriggeringMessageAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TriggeringMessageAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TriggeringMessageAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TriggeringMessageAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TriggeringMessageValueCodec) EncodeAPER(value TriggeringMessageAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TriggeringMessageValueCodec) encodeBudgetValue(value s00.TriggeringMessage,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TriggeringMessageValueCodec) encodeChanged(value s00.TriggeringMessage,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TypeOfErrorValueCodec is the concrete ValueCodec[TypeOfError].
type TypeOfErrorValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TypeOfError,

		error)
	encode func(s00.TypeOfError,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TypeOfError, aper.DecodeState,

	) (s00.TypeOfError, aper.Snapshot,

	)
	compare func(s00.TypeOfError, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TypeOfErrorValueCodec) New(value s00.TypeOfError,

) (TypeOfErrorAPERValue, error) {
	if c.encode == nil {
		return TypeOfErrorAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TypeOfErrorAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TypeOfErrorAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TypeOfErrorAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TypeOfErrorValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TypeOfErrorAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TypeOfErrorAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TypeOfErrorAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TypeOfErrorAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TypeOfErrorAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TypeOfErrorValueCodec) EncodeAPER(value TypeOfErrorAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TypeOfErrorValueCodec) encodeBudgetValue(value s00.TypeOfError,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TypeOfErrorValueCodec) encodeChanged(value s00.TypeOfError,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERLFReportContainerValueCodec is the concrete ValueCodec[UERLFReportContainer].
type UERLFReportContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.UERLFReportContainer,

		error)
	encode func(s00.UERLFReportContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.UERLFReportContainer, aper.DecodeState,

	) (s00.UERLFReportContainer, aper.Snapshot,

	)
	compare func(s00.UERLFReportContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERLFReportContainerValueCodec) New(value s00.UERLFReportContainer,

) (UERLFReportContainerAPERValue, error) {
	if c.encode == nil {
		return UERLFReportContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERLFReportContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERLFReportContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERLFReportContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERLFReportContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERLFReportContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERLFReportContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERLFReportContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERLFReportContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERLFReportContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERLFReportContainerValueCodec) EncodeAPER(value UERLFReportContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERLFReportContainerValueCodec) encodeBudgetValue(value s00.UERLFReportContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERLFReportContainerValueCodec) encodeChanged(value s00.UERLFReportContainer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// UERLFReportContainerForExtendedBandsValueCodec is the concrete ValueCodec[UERLFReportContainerForExtendedBands].
type UERLFReportContainerForExtendedBandsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.UERLFReportContainerForExtendedBands,

		error)
	encode func(s00.UERLFReportContainerForExtendedBands,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.UERLFReportContainerForExtendedBands, aper.DecodeState,

	) (s00.UERLFReportContainerForExtendedBands, aper.Snapshot,

	)
	compare func(s00.UERLFReportContainerForExtendedBands, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c UERLFReportContainerForExtendedBandsValueCodec) New(value s00.UERLFReportContainerForExtendedBands,

) (UERLFReportContainerForExtendedBandsAPERValue, error) {
	if c.encode == nil {
		return UERLFReportContainerForExtendedBandsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UERLFReportContainerForExtendedBandsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UERLFReportContainerForExtendedBandsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return UERLFReportContainerForExtendedBandsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c UERLFReportContainerForExtendedBandsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UERLFReportContainerForExtendedBandsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return UERLFReportContainerForExtendedBandsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return UERLFReportContainerForExtendedBandsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return UERLFReportContainerForExtendedBandsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return UERLFReportContainerForExtendedBandsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c UERLFReportContainerForExtendedBandsValueCodec) EncodeAPER(value UERLFReportContainerForExtendedBandsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c UERLFReportContainerForExtendedBandsValueCodec) encodeBudgetValue(value s00.UERLFReportContainerForExtendedBands,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c UERLFReportContainerForExtendedBandsValueCodec) encodeChanged(value s00.UERLFReportContainerForExtendedBands,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ULNASCountValueCodec is the concrete ValueCodec[ULNASCount].
type ULNASCountValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ULNASCount,

		error)
	encode func(s00.ULNASCount,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ULNASCount, aper.DecodeState,

	) (s00.ULNASCount, aper.Snapshot,

	)
	compare func(s00.ULNASCount, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ULNASCountValueCodec) New(value s00.ULNASCount,

) (ULNASCountAPERValue, error) {
	if c.encode == nil {
		return ULNASCountAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ULNASCountAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ULNASCountAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ULNASCountAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ULNASCountValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ULNASCountAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ULNASCountAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ULNASCountAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ULNASCountAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ULNASCountAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ULNASCountValueCodec) EncodeAPER(value ULNASCountAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ULNASCountValueCodec) encodeBudgetValue(value s00.ULNASCount,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ULNASCountValueCodec) encodeChanged(value s00.ULNASCount,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ULNASMACValueCodec is the concrete ValueCodec[ULNASMAC].
type ULNASMACValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ULNASMAC,

		error)
	encode func(s00.ULNASMAC,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ULNASMAC, aper.DecodeState,

	) (s00.ULNASMAC, aper.Snapshot,

	)
	compare func(s00.ULNASMAC, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ULNASMACValueCodec) New(value s00.ULNASMAC,

) (ULNASMACAPERValue, error) {
	if c.encode == nil {
		return ULNASMACAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ULNASMACAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ULNASMACAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ULNASMACAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ULNASMACValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ULNASMACAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ULNASMACAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ULNASMACAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ULNASMACAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ULNASMACAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ULNASMACValueCodec) EncodeAPER(value ULNASMACAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ULNASMACValueCodec) encodeBudgetValue(value s00.ULNASMAC,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ULNASMACValueCodec) encodeChanged(value s00.ULNASMAC,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// VehicleUEValueCodec is the concrete ValueCodec[VehicleUE].
type VehicleUEValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.VehicleUE,

		error)
	encode func(s00.VehicleUE,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.VehicleUE, aper.DecodeState,

	) (s00.VehicleUE, aper.Snapshot,

	)
	compare func(s00.VehicleUE, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c VehicleUEValueCodec) New(value s00.VehicleUE,

) (VehicleUEAPERValue, error) {
	if c.encode == nil {
		return VehicleUEAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return VehicleUEAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return VehicleUEAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return VehicleUEAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c VehicleUEValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (VehicleUEAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return VehicleUEAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return VehicleUEAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return VehicleUEAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return VehicleUEAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c VehicleUEValueCodec) EncodeAPER(value VehicleUEAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c VehicleUEValueCodec) encodeBudgetValue(value s00.VehicleUE,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c VehicleUEValueCodec) encodeChanged(value s00.VehicleUE,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WLANMeasConfigValueCodec is the concrete ValueCodec[WLANMeasConfig].
type WLANMeasConfigValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.WLANMeasConfig,

		error)
	encode func(s00.WLANMeasConfig,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.WLANMeasConfig, aper.DecodeState,

	) (s00.WLANMeasConfig, aper.Snapshot,

	)
	compare func(s00.WLANMeasConfig, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WLANMeasConfigValueCodec) New(value s00.WLANMeasConfig,

) (WLANMeasConfigAPERValue, error) {
	if c.encode == nil {
		return WLANMeasConfigAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WLANMeasConfigAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANMeasConfigAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WLANMeasConfigAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WLANMeasConfigValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WLANMeasConfigAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WLANMeasConfigAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WLANMeasConfigAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WLANMeasConfigAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WLANMeasConfigAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WLANMeasConfigValueCodec) EncodeAPER(value WLANMeasConfigAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WLANMeasConfigValueCodec) encodeBudgetValue(value s00.WLANMeasConfig,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WLANMeasConfigValueCodec) encodeChanged(value s00.WLANMeasConfig,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WLANMeasConfigNameListValueCodec is the concrete ValueCodec[WLANMeasConfigNameList].
type WLANMeasConfigNameListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.WLANMeasConfigNameList,

		error)
	encode func(s00.WLANMeasConfigNameList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.WLANMeasConfigNameList, aper.DecodeState,

	) (s00.WLANMeasConfigNameList, aper.Snapshot,

	)
	compare func(s00.WLANMeasConfigNameList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WLANMeasConfigNameListValueCodec) New(value s00.WLANMeasConfigNameList,

) (WLANMeasConfigNameListAPERValue, error) {
	if c.encode == nil {
		return WLANMeasConfigNameListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WLANMeasConfigNameListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANMeasConfigNameListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WLANMeasConfigNameListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WLANMeasConfigNameListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WLANMeasConfigNameListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WLANMeasConfigNameListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WLANMeasConfigNameListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WLANMeasConfigNameListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WLANMeasConfigNameListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WLANMeasConfigNameListValueCodec) EncodeAPER(value WLANMeasConfigNameListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WLANMeasConfigNameListValueCodec) encodeBudgetValue(value s00.WLANMeasConfigNameList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WLANMeasConfigNameListValueCodec) encodeChanged(value s00.WLANMeasConfigNameList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// WLANNameValueCodec is the concrete ValueCodec[WLANName].
type WLANNameValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.WLANName,

		error)
	encode func(s00.WLANName,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.WLANName, aper.DecodeState,

	) (s00.WLANName, aper.Snapshot,

	)
	compare func(s00.WLANName, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c WLANNameValueCodec) New(value s00.WLANName,

) (WLANNameAPERValue, error) {
	if c.encode == nil {
		return WLANNameAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WLANNameAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANNameAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return WLANNameAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c WLANNameValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WLANNameAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return WLANNameAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return WLANNameAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return WLANNameAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return WLANNameAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c WLANNameValueCodec) EncodeAPER(value WLANNameAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c WLANNameValueCodec) encodeBudgetValue(value s00.WLANName,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c WLANNameValueCodec) encodeChanged(value s00.WLANName,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TransportLayerAddressAPERValue is the concrete APERValue[TransportLayerAddress].
type TransportLayerAddressAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TransportLayerAddress

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TransportLayerAddressAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TransportLayerAddressAPERValue) WithoutReplay() TransportLayerAddressAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UnlicensedSpectrumRestrictionAPERValue is the concrete APERValue[UnlicensedSpectrumRestriction].
type UnlicensedSpectrumRestrictionAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.UnlicensedSpectrumRestriction

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UnlicensedSpectrumRestrictionAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UnlicensedSpectrumRestrictionAPERValue) WithoutReplay() UnlicensedSpectrumRestrictionAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TimeUEStayedInCellEnhancedGranularityAPERValue is the concrete APERValue[TimeUEStayedInCellEnhancedGranularity].
type TimeUEStayedInCellEnhancedGranularityAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TimeUEStayedInCellEnhancedGranularity

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TimeUEStayedInCellEnhancedGranularityAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TimeUEStayedInCellEnhancedGranularityAPERValue) WithoutReplay() TimeUEStayedInCellEnhancedGranularityAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEHistoryInformationFromTheUEAPERValue is the concrete APERValue[UEHistoryInformationFromTheUE].
type UEHistoryInformationFromTheUEAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.UEHistoryInformationFromTheUE

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEHistoryInformationFromTheUEAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEHistoryInformationFromTheUEAPERValue) WithoutReplay() UEHistoryInformationFromTheUEAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// URIAddressAPERValue is the concrete APERValue[URIAddress].
type URIAddressAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.URIAddress

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v URIAddressAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v URIAddressAPERValue) WithoutReplay() URIAddressAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityAPERValue is the concrete APERValue[UERadioCapability].
type UERadioCapabilityAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.UERadioCapability

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityAPERValue) WithoutReplay() UERadioCapabilityAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityIDAPERValue is the concrete APERValue[UERadioCapabilityID].
type UERadioCapabilityIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.UERadioCapabilityID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityIDAPERValue) WithoutReplay() UERadioCapabilityIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UECapabilityInfoRequestAPERValue is the concrete APERValue[UECapabilityInfoRequest].
type UECapabilityInfoRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.UECapabilityInfoRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UECapabilityInfoRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UECapabilityInfoRequestAPERValue) WithoutReplay() UECapabilityInfoRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TimeToWaitAPERValue is the concrete APERValue[TimeToWait].
type TimeToWaitAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TimeToWait

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TimeToWaitAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TimeToWaitAPERValue) WithoutReplay() TimeToWaitAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEUserPlaneCIoTSupportIndicatorAPERValue is the concrete APERValue[UEUserPlaneCIoTSupportIndicator].
type UEUserPlaneCIoTSupportIndicatorAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.UEUserPlaneCIoTSupportIndicator

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEUserPlaneCIoTSupportIndicatorAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEUserPlaneCIoTSupportIndicatorAPERValue) WithoutReplay() UEUserPlaneCIoTSupportIndicatorAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TimeRefDistributionAPERValue is the concrete APERValue[TimeRefDistribution].
type TimeRefDistributionAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TimeRefDistribution

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TimeRefDistributionAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TimeRefDistributionAPERValue) WithoutReplay() TimeRefDistributionAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEUsageTypeAPERValue is the concrete APERValue[UEUsageType].
type UEUsageTypeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.UEUsageType

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEUsageTypeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEUsageTypeAPERValue) WithoutReplay() UEUsageTypeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEApplicationLayerMeasurementCapabilityAPERValue is the concrete APERValue[UEApplicationLayerMeasurementCapability].
type UEApplicationLayerMeasurementCapabilityAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.UEApplicationLayerMeasurementCapability

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEApplicationLayerMeasurementCapabilityAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEApplicationLayerMeasurementCapabilityAPERValue) WithoutReplay() UEApplicationLayerMeasurementCapabilityAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TrafficLoadReductionIndicationAPERValue is the concrete APERValue[TrafficLoadReductionIndication].
type TrafficLoadReductionIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TrafficLoadReductionIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TrafficLoadReductionIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TrafficLoadReductionIndicationAPERValue) WithoutReplay() TrafficLoadReductionIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UEIdentityIndexValueAPERValue is the concrete APERValue[UEIdentityIndexValue].
type UEIdentityIndexValueAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.UEIdentityIndexValue

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UEIdentityIndexValueAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UEIdentityIndexValueAPERValue) WithoutReplay() UEIdentityIndexValueAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERadioCapabilityForPagingAPERValue is the concrete APERValue[UERadioCapabilityForPaging].
type UERadioCapabilityForPagingAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.UERadioCapabilityForPaging

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERadioCapabilityForPagingAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERadioCapabilityForPagingAPERValue) WithoutReplay() UERadioCapabilityForPagingAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERetentionInformationAPERValue is the concrete APERValue[UERetentionInformation].
type UERetentionInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.UERetentionInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERetentionInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERetentionInformationAPERValue) WithoutReplay() UERetentionInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TimeSinceSecondaryNodeReleaseAPERValue is the concrete APERValue[TimeSinceSecondaryNodeRelease].
type TimeSinceSecondaryNodeReleaseAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TimeSinceSecondaryNodeRelease

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TimeSinceSecondaryNodeReleaseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TimeSinceSecondaryNodeReleaseAPERValue) WithoutReplay() TimeSinceSecondaryNodeReleaseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// VoiceSupportMatchIndicatorAPERValue is the concrete APERValue[VoiceSupportMatchIndicator].
type VoiceSupportMatchIndicatorAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.VoiceSupportMatchIndicator

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v VoiceSupportMatchIndicatorAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v VoiceSupportMatchIndicatorAPERValue) WithoutReplay() VoiceSupportMatchIndicatorAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WarningTypeAPERValue is the concrete APERValue[WarningType].
type WarningTypeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.WarningType

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WarningTypeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WarningTypeAPERValue) WithoutReplay() WarningTypeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WarningSecurityInfoAPERValue is the concrete APERValue[WarningSecurityInfo].
type WarningSecurityInfoAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.WarningSecurityInfo

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WarningSecurityInfoAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WarningSecurityInfoAPERValue) WithoutReplay() WarningSecurityInfoAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WarningMessageContentsAPERValue is the concrete APERValue[WarningMessageContents].
type WarningMessageContentsAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.WarningMessageContents

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WarningMessageContentsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WarningMessageContentsAPERValue) WithoutReplay() WarningMessageContentsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WarningAreaCoordinatesAPERValue is the concrete APERValue[WarningAreaCoordinates].
type WarningAreaCoordinatesAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.WarningAreaCoordinates

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WarningAreaCoordinatesAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WarningAreaCoordinatesAPERValue) WithoutReplay() WarningAreaCoordinatesAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ThresholdRSRQAPERValue is the concrete APERValue[ThresholdRSRQ].
type ThresholdRSRQAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ThresholdRSRQ

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ThresholdRSRQAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ThresholdRSRQAPERValue) WithoutReplay() ThresholdRSRQAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TimeToTriggerAPERValue is the concrete APERValue[TimeToTrigger].
type TimeToTriggerAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TimeToTrigger

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TimeToTriggerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TimeToTriggerAPERValue) WithoutReplay() TimeToTriggerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TimeUEStayedInCellAPERValue is the concrete APERValue[TimeUEStayedInCell].
type TimeUEStayedInCellAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TimeUEStayedInCell

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TimeUEStayedInCellAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TimeUEStayedInCellAPERValue) WithoutReplay() TimeUEStayedInCellAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TraceDepthAPERValue is the concrete APERValue[TraceDepth].
type TraceDepthAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TraceDepth

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TraceDepthAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceDepthAPERValue) WithoutReplay() TraceDepthAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TriggeringMessageAPERValue is the concrete APERValue[TriggeringMessage].
type TriggeringMessageAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TriggeringMessage

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TriggeringMessageAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TriggeringMessageAPERValue) WithoutReplay() TriggeringMessageAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TypeOfErrorAPERValue is the concrete APERValue[TypeOfError].
type TypeOfErrorAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TypeOfError

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TypeOfErrorAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TypeOfErrorAPERValue) WithoutReplay() TypeOfErrorAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERLFReportContainerAPERValue is the concrete APERValue[UERLFReportContainer].
type UERLFReportContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.UERLFReportContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERLFReportContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERLFReportContainerAPERValue) WithoutReplay() UERLFReportContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UERLFReportContainerForExtendedBandsAPERValue is the concrete APERValue[UERLFReportContainerForExtendedBands].
type UERLFReportContainerForExtendedBandsAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.UERLFReportContainerForExtendedBands

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v UERLFReportContainerForExtendedBandsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v UERLFReportContainerForExtendedBandsAPERValue) WithoutReplay() UERLFReportContainerForExtendedBandsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ULNASCountAPERValue is the concrete APERValue[ULNASCount].
type ULNASCountAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ULNASCount

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ULNASCountAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ULNASCountAPERValue) WithoutReplay() ULNASCountAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ULNASMACAPERValue is the concrete APERValue[ULNASMAC].
type ULNASMACAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ULNASMAC

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ULNASMACAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ULNASMACAPERValue) WithoutReplay() ULNASMACAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// VehicleUEAPERValue is the concrete APERValue[VehicleUE].
type VehicleUEAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.VehicleUE

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v VehicleUEAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v VehicleUEAPERValue) WithoutReplay() VehicleUEAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WLANMeasConfigAPERValue is the concrete APERValue[WLANMeasConfig].
type WLANMeasConfigAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.WLANMeasConfig

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WLANMeasConfigAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WLANMeasConfigAPERValue) WithoutReplay() WLANMeasConfigAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WLANMeasConfigNameListAPERValue is the concrete APERValue[WLANMeasConfigNameList].
type WLANMeasConfigNameListAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.WLANMeasConfigNameList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WLANMeasConfigNameListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WLANMeasConfigNameListAPERValue) WithoutReplay() WLANMeasConfigNameListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WLANNameAPERValue is the concrete APERValue[WLANName].
type WLANNameAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.WLANName

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v WLANNameAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v WLANNameAPERValue) WithoutReplay() WLANNameAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCompareS1APAdditionalCSFallbackIndicator(v *s00.AdditionalCSFallbackIndicator, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APAdditionalGUTIExtIEsValue(v *AdditionalGUTIExtIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v AdditionalGUTIExtIEsValue) captureSemantics(s aper.SemanticCapture) AdditionalGUTIExtIEsValue {
	BridgeCaptureS1APAdditionalGUTIExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APAdditionalGUTIExtIEsValue(v *AdditionalGUTIExtIEsValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v AdditionalGUTIExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APAdditionalGUTIExtIEsValue(&v, &s)
	return s
}
func BridgeCompareS1APAdditionalRRMPriorityIndex(v *s00.AdditionalRRMPriorityIndex, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APAerialUEsubscriptionInformation(v *s00.AerialUEsubscriptionInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APAllocationAndRetentionPriorityExtIEsValue(v *AllocationAndRetentionPriorityExtIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v AllocationAndRetentionPriorityExtIEsValue) captureSemantics(s aper.SemanticCapture) AllocationAndRetentionPriorityExtIEsValue {
	BridgeCaptureS1APAllocationAndRetentionPriorityExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APAllocationAndRetentionPriorityExtIEsValue(v *AllocationAndRetentionPriorityExtIEsValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v AllocationAndRetentionPriorityExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APAllocationAndRetentionPriorityExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APAssistanceDataForPagingExtIEsValue(v *AssistanceDataForPagingExtIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v AssistanceDataForPagingExtIEsValue) captureSemantics(s aper.SemanticCapture) AssistanceDataForPagingExtIEsValue {
	BridgeCaptureS1APAssistanceDataForPagingExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APAssistanceDataForPagingExtIEsValue(v *AssistanceDataForPagingExtIEsValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v AssistanceDataForPagingExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APAssistanceDataForPagingExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APAssistanceDataForRecommendedCellsExtIEsValue(v *AssistanceDataForRecommendedCellsExtIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v AssistanceDataForRecommendedCellsExtIEsValue) captureSemantics(s aper.SemanticCapture) AssistanceDataForRecommendedCellsExtIEsValue {
	BridgeCaptureS1APAssistanceDataForRecommendedCellsExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APAssistanceDataForRecommendedCellsExtIEsValue(v *AssistanceDataForRecommendedCellsExtIEsValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v AssistanceDataForRecommendedCellsExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APAssistanceDataForRecommendedCellsExtIEsValue(&v, &s)
	return s
}
func BridgeCompareS1APBearerType(v *s00.BearerType, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APBearersSubjectToDLDiscardingItemExtIEsValue(v *BearersSubjectToDLDiscardingItemExtIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v BearersSubjectToDLDiscardingItemExtIEsValue) captureSemantics(s aper.SemanticCapture) BearersSubjectToDLDiscardingItemExtIEsValue {
	BridgeCaptureS1APBearersSubjectToDLDiscardingItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APBearersSubjectToDLDiscardingItemExtIEsValue(v *BearersSubjectToDLDiscardingItemExtIEsValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v BearersSubjectToDLDiscardingItemExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APBearersSubjectToDLDiscardingItemExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APBearersSubjectToEarlyStatusTransferItemExtIEsValue(v *BearersSubjectToEarlyStatusTransferItemExtIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v BearersSubjectToEarlyStatusTransferItemExtIEsValue) captureSemantics(s aper.SemanticCapture) BearersSubjectToEarlyStatusTransferItemExtIEsValue {
	BridgeCaptureS1APBearersSubjectToEarlyStatusTransferItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APBearersSubjectToEarlyStatusTransferItemExtIEsValue(v *BearersSubjectToEarlyStatusTransferItemExtIEsValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v BearersSubjectToEarlyStatusTransferItemExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APBearersSubjectToEarlyStatusTransferItemExtIEsValue(&v, &s)
	return s
}
func BridgeCompareS1APBitRate(v *s00.BitRate, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APBluetoothMeasConfig(v *s00.BluetoothMeasConfig, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APBluetoothMeasConfigNameList(v *s00.BluetoothMeasConfigNameList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCompareS1APBluetoothName(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APBluetoothMeasurementConfigurationExtIEsValue(v *BluetoothMeasurementConfigurationExtIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v BluetoothMeasurementConfigurationExtIEsValue) captureSemantics(s aper.SemanticCapture) BluetoothMeasurementConfigurationExtIEsValue {
	BridgeCaptureS1APBluetoothMeasurementConfigurationExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APBluetoothMeasurementConfigurationExtIEsValue(v *BluetoothMeasurementConfigurationExtIEsValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v BluetoothMeasurementConfigurationExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APBluetoothMeasurementConfigurationExtIEsValue(&v, &s)
	return s
}
func BridgeCompareS1APBluetoothName(v *s00.BluetoothName, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCELevel(v *s00.CELevel, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCEModeBRestricted(v *s00.CEModeBRestricted, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCEModeBSupportIndicator(v *s00.CEModeBSupportIndicator, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APCGIExtIEsValue(v *CGIExtIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v CGIExtIEsValue) captureSemantics(s aper.SemanticCapture) CGIExtIEsValue {
	BridgeCaptureS1APCGIExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APCGIExtIEsValue(v *CGIExtIEsValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v CGIExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APCGIExtIEsValue(&v, &s)
	return s
}
func BridgeCompareS1APCI(v *s00.CI, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCNDomain(v *s00.CNDomain, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCNType(v *s00.CNType, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APCNTypeRestrictionsItemExtIEsValue(v *CNTypeRestrictionsItemExtIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v CNTypeRestrictionsItemExtIEsValue) captureSemantics(s aper.SemanticCapture) CNTypeRestrictionsItemExtIEsValue {
	BridgeCaptureS1APCNTypeRestrictionsItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APCNTypeRestrictionsItemExtIEsValue(v *CNTypeRestrictionsItemExtIEsValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v CNTypeRestrictionsItemExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APCNTypeRestrictionsItemExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APCOUNTValueExtendedExtIEsValue(v *COUNTValueExtendedExtIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v COUNTValueExtendedExtIEsValue) captureSemantics(s aper.SemanticCapture) COUNTValueExtendedExtIEsValue {
	BridgeCaptureS1APCOUNTValueExtendedExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APCOUNTValueExtendedExtIEsValue(v *COUNTValueExtendedExtIEsValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v COUNTValueExtendedExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APCOUNTValueExtendedExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APCOUNTvalueExtIEsValue(v *COUNTvalueExtIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v COUNTvalueExtIEsValue) captureSemantics(s aper.SemanticCapture) COUNTvalueExtIEsValue {
	BridgeCaptureS1APCOUNTvalueExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APCOUNTvalueExtIEsValue(v *COUNTvalueExtIEsValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v COUNTvalueExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APCOUNTvalueExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APCOUNTvaluePDCPSNlength18ExtIEsValue(v *COUNTvaluePDCPSNlength18ExtIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v COUNTvaluePDCPSNlength18ExtIEsValue) captureSemantics(s aper.SemanticCapture) COUNTvaluePDCPSNlength18ExtIEsValue {
	BridgeCaptureS1APCOUNTvaluePDCPSNlength18ExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APCOUNTvaluePDCPSNlength18ExtIEsValue(v *COUNTvaluePDCPSNlength18ExtIEsValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v COUNTvaluePDCPSNlength18ExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APCOUNTvaluePDCPSNlength18ExtIEsValue(&v, &s)
	return s
}
func BridgeCompareS1APCSFallbackIndicator(v *s00.CSFallbackIndicator, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCSGId(v *s00.CSGId, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APCSGIdListItemExtIEsValue(v *CSGIdListItemExtIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v CSGIdListItemExtIEsValue) captureSemantics(s aper.SemanticCapture) CSGIdListItemExtIEsValue {
	BridgeCaptureS1APCSGIdListItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APCSGIdListItemExtIEsValue(v *CSGIdListItemExtIEsValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v CSGIdListItemExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APCSGIdListItemExtIEsValue(&v, &s)
	return s
}
func BridgeCaptureS1APCSGMembershipInfoExtIEsValue(v *CSGMembershipInfoExtIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v CSGMembershipInfoExtIEsValue) captureSemantics(s aper.SemanticCapture) CSGMembershipInfoExtIEsValue {
	BridgeCaptureS1APCSGMembershipInfoExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APCSGMembershipInfoExtIEsValue(v *CSGMembershipInfoExtIEsValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v CSGMembershipInfoExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APCSGMembershipInfoExtIEsValue(&v, &s)
	return s
}
func BridgeCompareS1APCSGMembershipStatus(v *s00.CSGMembershipStatus, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureS1APCancelledCellinEAIItemExtIEsValue(v *CancelledCellinEAIItemExtIEsValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v CancelledCellinEAIItemExtIEsValue) captureSemantics(s aper.SemanticCapture) CancelledCellinEAIItemExtIEsValue {
	BridgeCaptureS1APCancelledCellinEAIItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareS1APCancelledCellinEAIItemExtIEsValue(v *CancelledCellinEAIItemExtIEsValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v CancelledCellinEAIItemExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APCancelledCellinEAIItemExtIEsValue(&v, &s)
	return s
}
func BridgeCompareS1APCauseMisc(v *s00.CauseMisc, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCauseNas(v *s00.CauseNas, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCauseProtocol(v *s00.CauseProtocol, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCauseRadioNetwork(v *s00.CauseRadioNetwork, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCauseTransport(v *s00.CauseTransport, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCdma2000HORequiredIndication(v *s00.Cdma2000HORequiredIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCdma2000HOStatus(v *s00.Cdma2000HOStatus, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCdma2000OneXMEID(v *s00.Cdma2000OneXMEID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCdma2000OneXMSI(v *s00.Cdma2000OneXMSI, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCdma2000OneXPilot(v *s00.Cdma2000OneXPilot, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCdma2000OneXRAND(v *s00.Cdma2000OneXRAND, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCdma2000PDU(v *s00.Cdma2000PDU, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCdma2000RATType(v *s00.Cdma2000RATType, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCdma2000SectorID(v *s00.Cdma2000SectorID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCellAccessMode(v *s00.CellAccessMode, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCellActivationCause(v *s00.CellActivationCause, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCellIdentity(v *s00.CellIdentity, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCellLoadReportingCause(v *s00.CellLoadReportingCause, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCellSize(v *s00.CellSize, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCellStateIndicationCause(v *s00.CellStateIndicationCause, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCoarseUELocation(v *s00.CoarseUELocation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCoarseUELocationRequested(v *s00.CoarseUELocationRequested, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCompositeAvailableCapacityGroup(v *s00.CompositeAvailableCapacityGroup, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APConcurrentWarningMessageIndicator(v *s00.ConcurrentWarningMessageIndicator, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCorrelationID(v *s00.CorrelationID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCoverageLevel(v *s00.CoverageLevel, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APCriticality(v *s00.Criticality, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APDCNID(v *s00.DCNID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APDLForwarding(v *s00.DLForwarding, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APDLNASMAC(v *s00.DLNASMAC, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APDLNASPDUDeliveryAckRequest(v *s00.DLNASPDUDeliveryAckRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APDataCodingScheme(v *s00.DataCodingScheme, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APDataForwardingNotPossible(v *s00.DataForwardingNotPossible, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APDataSize(v *s00.DataSize, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APDirectForwardingPathAvailability(v *s00.DirectForwardingPathAvailability, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEARFCN(v *s00.EARFCN, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEDTSession(v *s00.EDTSession, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEHRPDCapacityValue(v *s00.EHRPDCapacityValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEHRPDSectorCapacityClassValue(v *s00.EHRPDSectorCapacityClassValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEHRPDSectorID(v *s00.EHRPDSectorID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APENBUES1APID(v *s00.ENBUES1APID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APENBname(v *s00.ENBname, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.String((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APERABID(v *s00.ERABID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEUTRANRoundTripDelayEstimationInfo(v *s00.EUTRANRoundTripDelayEstimationInfo, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEUTRANTraceID(v *s00.EUTRANTraceID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEmergencyAreaID(v *s00.EmergencyAreaID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEmergencyAreaIDList(v *s00.EmergencyAreaIDList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCompareS1APEmergencyAreaID(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEmergencyAreaIDListForRestart(v *s00.EmergencyAreaIDListForRestart, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCompareS1APEmergencyAreaID(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEmergencyIndicator(v *s00.EmergencyIndicator, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEnGNBID(v *s00.EnGNBID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEncryptionAlgorithms(v *s00.EncryptionAlgorithms, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEndIndication(v *s00.EndIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEnhancedCoverageRestricted(v *s00.EnhancedCoverageRestricted, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEthernetType(v *s00.EthernetType, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APEventType(v *s00.EventType, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APExpectedActivityPeriod(v *s00.ExpectedActivityPeriod, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APExpectedHOInterval(v *s00.ExpectedHOInterval, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APExpectedIdlePeriod(v *s00.ExpectedIdlePeriod, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APExtendedBitRate(v *s00.ExtendedBitRate, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APExtendedRNCID(v *s00.ExtendedRNCID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APExtendedRepetitionPeriod(v *s00.ExtendedRepetitionPeriod, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APExtendedUEIdentityIndexValue(v *s00.ExtendedUEIdentityIndexValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APFailureEventReportingCause(v *s00.FailureEventReportingCause, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APFiveGSTAC(v *s00.FiveGSTAC, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APFiveQI(v *s00.FiveQI, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APForbiddenInterRATs(v *s00.ForbiddenInterRATs, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APForbiddenLACs(v *s00.ForbiddenLACs, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeCompareS1APLAC(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APGNBID(v *s00.GNBID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APGTPTEID(v *s00.GTPTEID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APGUMMEIType(v *s00.GUMMEIType, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APGWContextReleaseIndication(v *s00.GWContextReleaseIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APHFN(v *s00.HFN, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APHFNModified(v *s00.HFNModified, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APHFNforPDCPSNlength18(v *s00.HFNforPDCPSNlength18, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APHOReportingCause(v *s00.HOReportingCause, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APHandoverFlag(v *s00.HandoverFlag, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APHandoverType(v *s00.HandoverType, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APHandoverWindowDuration(v *s00.HandoverWindowDuration, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APHandoverWindowStart(v *s00.HandoverWindowStart, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APHoReportType(v *s00.HoReportType, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APHoType(v *s00.HoType, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APHysteresis(v *s00.Hysteresis, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APIABAuthorized(v *s00.IABAuthorized, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APIABNodeIndication(v *s00.IABNodeIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APIABSupported(v *s00.IABSupported, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APIMSI(v *s00.IMSI, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APIMSvoiceEPSfallbackfrom5G(v *s00.IMSvoiceEPSfallbackfrom5G, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APIntegrityProtectionAlgorithms(v *s00.IntegrityProtectionAlgorithms, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APIntegrityProtectionIndication(v *s00.IntegrityProtectionIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APIntegrityProtectionResult(v *s00.IntegrityProtectionResult, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APIntendedNumberOfPagingAttempts(v *s00.IntendedNumberOfPagingAttempts, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APInterfacesToTrace(v *s00.InterfacesToTrace, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APIntersystemSONConfigurationTransfer(v *s00.IntersystemSONConfigurationTransfer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APKillAllWarningMessages(v *s00.KillAllWarningMessages, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APL3Information(v *s00.L3Information, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APLAC(v *s00.LAC, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APLHNID(v *s00.LHNID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APLPPaPDU(v *s00.LPPaPDU, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APLTEMIndication(v *s00.LTEMIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APLastVisitedNGRANCellInformation(v *s00.LastVisitedNGRANCellInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APLastVisitedUTRANCellInformation(v *s00.LastVisitedUTRANCellInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APLinksToLog(v *s00.LinksToLog, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APLoggingDuration(v *s00.LoggingDuration, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APLoggingInterval(v *s00.LoggingInterval, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APM1ReportingTrigger(v *s00.M1ReportingTrigger, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APM3period(v *s00.M3period, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APM4ReportAmountMDT(v *s00.M4ReportAmountMDT, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APM4period(v *s00.M4period, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APM5ReportAmountMDT(v *s00.M5ReportAmountMDT, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APM5period(v *s00.M5period, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APM6ReportAmountMDT(v *s00.M6ReportAmountMDT, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APM6delayThreshold(v *s00.M6delayThreshold, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APM6reportInterval(v *s00.M6reportInterval, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APM7ReportAmountMDT(v *s00.M7ReportAmountMDT, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APM7period(v *s00.M7period, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APMDTActivation(v *s00.MDTActivation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APMDTConfigurationNR(v *s00.MDTConfigurationNR, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APMDTLocationInfo(v *s00.MDTLocationInfo, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APMMECode(v *s00.MMECode, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APMMEGroupID(v *s00.MMEGroupID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APMMERelaySupportIndicator(v *s00.MMERelaySupportIndicator, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APMMEUES1APID(v *s00.MMEUES1APID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APMMEname(v *s00.MMEname, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.String((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APMSClassmark2(v *s00.MSClassmark2, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APMSClassmark3(v *s00.MSClassmark3, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APMTMSI(v *s00.MTMSI, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APManagementBasedMDTAllowed(v *s00.ManagementBasedMDTAllowed, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APMaskedIMEISV(v *s00.MaskedIMEISV, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APMeasurementsToActivate(v *s00.MeasurementsToActivate, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APMessageIdentifier(v *s00.MessageIdentifier, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APMutingAvailabilityIndication(v *s00.MutingAvailabilityIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNASPDU(v *s00.NASPDU, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNASSecurityParametersfromEUTRAN(v *s00.NASSecurityParametersfromEUTRAN, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNASSecurityParameterstoEUTRAN(v *s00.NASSecurityParameterstoEUTRAN, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNBIoTDefaultPagingDRX(v *s00.NBIoTDefaultPagingDRX, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNBIoTPagingDRX(v *s00.NBIoTPagingDRX, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNBIoTPagingEDRXCycle(v *s00.NBIoTPagingEDRXCycle, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNBIoTPagingTimeWindow(v *s00.NBIoTPagingTimeWindow, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNBIoTRLFReportContainer(v *s00.NBIoTRLFReportContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNBIoTUEIdentityIndexValue(v *s00.NBIoTUEIdentityIndexValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNRCellIdentity(v *s00.NRCellIdentity, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNRencryptionAlgorithms(v *s00.NRencryptionAlgorithms, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNRintegrityProtectionAlgorithms(v *s00.NRintegrityProtectionAlgorithms, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.BitString((*v).Bytes, (*v).BitLength)
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNRrestrictionin5GS(v *s00.NRrestrictionin5GS, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNRrestrictioninEPSasSecondaryRAT(v *s00.NRrestrictioninEPSasSecondaryRAT, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNextPagingAreaScope(v *s00.NextPagingAreaScope, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNotifyFlag(v *s00.NotifyFlag, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNotifySourceeNB(v *s00.NotifySourceeNB, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNumberOfBroadcasts(v *s00.NumberOfBroadcasts, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNumberOfMeasurementReportingLevels(v *s00.NumberOfMeasurementReportingLevels, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APNumberofBroadcastRequest(v *s00.NumberofBroadcastRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APOldBSSToNewBSSInformation(v *s00.OldBSSToNewBSSInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APOverloadAction(v *s00.OverloadAction, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APOverloadFlag(v *s00.OverloadFlag, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPDCPSN(v *s00.PDCPSN, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPDCPSNExtended(v *s00.PDCPSNExtended, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPDCPSNlength18(v *s00.PDCPSNlength18, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPSServiceNotAvailable(v *s00.PSServiceNotAvailable, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPacketLossRate(v *s00.PacketLossRate, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPagingAttemptCount(v *s00.PagingAttemptCount, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPagingCause(v *s00.PagingCause, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPagingDRX(v *s00.PagingDRX, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPagingEDRXCycle(v *s00.PagingEDRXCycle, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPagingPriority(v *s00.PagingPriority, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPagingProbabilityInformation(v *s00.PagingProbabilityInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPagingTimeWindow(v *s00.PagingTimeWindow, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPedestrianUE(v *s00.PedestrianUE, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPendingDataIndication(v *s00.PendingDataIndication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPortNumber(v *s00.PortNumber, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Bytes((*v))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPreEmptionCapability(v *s00.PreEmptionCapability, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPreEmptionVulnerability(v *s00.PreEmptionVulnerability, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPresence(v *s00.Presence, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPriorityLevel(v *s00.PriorityLevel, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APPrivacyIndicator(v *s00.PrivacyIndicator, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APProSeDirectCommunication(v *s00.ProSeDirectCommunication, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APProSeDirectDiscovery(v *s00.ProSeDirectDiscovery, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APProSeUEtoNetworkRelaying(v *s00.ProSeUEtoNetworkRelaying, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APProcedureCode(v *s00.ProcedureCode, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APProtocolExtensionID(v *s00.ProtocolExtensionID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCompareS1APProtocolIEID(v *s00.ProtocolIEID, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
}

type AdditionalGUTIExtIEsValue struct {
	id       s00.ProtocolIEID
	received aper.WireSpan
	replay   aper.Snapshot
	opaque   aper.OpaqueOpenType
	isOpaque bool
}

func (v AdditionalGUTIExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	}
	return false
}
func (v *AdditionalGUTIExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (AdditionalGUTIExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Additional-GUTI-ExtIEs"}}
}
func (AdditionalGUTIExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
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
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(41):
		return aper.NotInTable
	case s00.ProtocolIEID(43):
		return aper.NotInTable
	case s00.ProtocolIEID(44):
		return aper.NotInTable
	case s00.ProtocolIEID(46):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(66):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(73):
		return aper.NotInTable
	case s00.ProtocolIEID(74):
		return aper.NotInTable
	case s00.ProtocolIEID(75):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(80):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(106):
		return aper.NotInTable
	case s00.ProtocolIEID(107):
		return aper.NotInTable
	case s00.ProtocolIEID(108):
		return aper.NotInTable
	case s00.ProtocolIEID(109):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(124):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(146):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(151):
		return aper.NotInTable
	case s00.ProtocolIEID(152):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(165):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(177):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(179):
		return aper.NotInTable
	case s00.ProtocolIEID(180):
		return aper.NotInTable
	case s00.ProtocolIEID(181):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(187):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(192):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(195):
		return aper.NotInTable
	case s00.ProtocolIEID(196):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(198):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(211):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(217):
		return aper.NotInTable
	case s00.ProtocolIEID(218):
		return aper.NotInTable
	case s00.ProtocolIEID(219):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(239):
		return aper.NotInTable
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(251):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(269):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(271):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
		return aper.NotInTable
	case s00.ProtocolIEID(278):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(299):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(301):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(306):
		return aper.NotInTable
	case s00.ProtocolIEID(307):
		return aper.NotInTable
	case s00.ProtocolIEID(308):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(314):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(323):
		return aper.NotInTable
	case s00.ProtocolIEID(324):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v AdditionalGUTIExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (AdditionalGUTIExtIEsValue, error) {
	out := AdditionalGUTIExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v AdditionalGUTIExtIEsValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v AdditionalGUTIExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "AdditionalGUTIExtIEsValue:", v.id)
	}
}

type AllocationAndRetentionPriorityExtIEsValue struct {
	id       s00.ProtocolIEID
	received aper.WireSpan
	replay   aper.Snapshot
	opaque   aper.OpaqueOpenType
	isOpaque bool
}

func (v AllocationAndRetentionPriorityExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	}
	return false
}
func (v *AllocationAndRetentionPriorityExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (AllocationAndRetentionPriorityExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AllocationAndRetentionPriority-ExtIEs"}}
}
func (AllocationAndRetentionPriorityExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
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
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(41):
		return aper.NotInTable
	case s00.ProtocolIEID(43):
		return aper.NotInTable
	case s00.ProtocolIEID(44):
		return aper.NotInTable
	case s00.ProtocolIEID(46):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(66):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(73):
		return aper.NotInTable
	case s00.ProtocolIEID(74):
		return aper.NotInTable
	case s00.ProtocolIEID(75):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(80):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(106):
		return aper.NotInTable
	case s00.ProtocolIEID(107):
		return aper.NotInTable
	case s00.ProtocolIEID(108):
		return aper.NotInTable
	case s00.ProtocolIEID(109):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(124):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(146):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(151):
		return aper.NotInTable
	case s00.ProtocolIEID(152):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(165):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(177):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(179):
		return aper.NotInTable
	case s00.ProtocolIEID(180):
		return aper.NotInTable
	case s00.ProtocolIEID(181):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(187):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(192):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(195):
		return aper.NotInTable
	case s00.ProtocolIEID(196):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(198):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(211):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(217):
		return aper.NotInTable
	case s00.ProtocolIEID(218):
		return aper.NotInTable
	case s00.ProtocolIEID(219):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(239):
		return aper.NotInTable
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(251):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(269):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(271):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
		return aper.NotInTable
	case s00.ProtocolIEID(278):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(299):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(301):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(306):
		return aper.NotInTable
	case s00.ProtocolIEID(307):
		return aper.NotInTable
	case s00.ProtocolIEID(308):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(314):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(323):
		return aper.NotInTable
	case s00.ProtocolIEID(324):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v AllocationAndRetentionPriorityExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (AllocationAndRetentionPriorityExtIEsValue, error) {
	out := AllocationAndRetentionPriorityExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v AllocationAndRetentionPriorityExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v AllocationAndRetentionPriorityExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "AllocationAndRetentionPriorityExtIEsValue:", v.id)
	}
}

type AssistanceDataForPagingExtIEsValue struct {
	id       s00.ProtocolIEID
	received aper.WireSpan
	replay   aper.Snapshot
	opaque   aper.OpaqueOpenType
	isOpaque bool
}

func (v AssistanceDataForPagingExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	}
	return false
}
func (v *AssistanceDataForPagingExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (AssistanceDataForPagingExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AssistanceDataForPaging-ExtIEs"}}
}
func (AssistanceDataForPagingExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
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
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(41):
		return aper.NotInTable
	case s00.ProtocolIEID(43):
		return aper.NotInTable
	case s00.ProtocolIEID(44):
		return aper.NotInTable
	case s00.ProtocolIEID(46):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(66):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(73):
		return aper.NotInTable
	case s00.ProtocolIEID(74):
		return aper.NotInTable
	case s00.ProtocolIEID(75):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(80):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(106):
		return aper.NotInTable
	case s00.ProtocolIEID(107):
		return aper.NotInTable
	case s00.ProtocolIEID(108):
		return aper.NotInTable
	case s00.ProtocolIEID(109):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(124):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(146):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(151):
		return aper.NotInTable
	case s00.ProtocolIEID(152):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(165):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(177):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(179):
		return aper.NotInTable
	case s00.ProtocolIEID(180):
		return aper.NotInTable
	case s00.ProtocolIEID(181):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(187):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(192):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(195):
		return aper.NotInTable
	case s00.ProtocolIEID(196):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(198):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(211):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(217):
		return aper.NotInTable
	case s00.ProtocolIEID(218):
		return aper.NotInTable
	case s00.ProtocolIEID(219):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(239):
		return aper.NotInTable
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(251):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(269):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(271):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
		return aper.NotInTable
	case s00.ProtocolIEID(278):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(299):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(301):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(306):
		return aper.NotInTable
	case s00.ProtocolIEID(307):
		return aper.NotInTable
	case s00.ProtocolIEID(308):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(314):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(323):
		return aper.NotInTable
	case s00.ProtocolIEID(324):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v AssistanceDataForPagingExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (AssistanceDataForPagingExtIEsValue, error) {
	out := AssistanceDataForPagingExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v AssistanceDataForPagingExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v AssistanceDataForPagingExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "AssistanceDataForPagingExtIEsValue:", v.id)
	}
}

type AssistanceDataForRecommendedCellsExtIEsValue struct {
	id       s00.ProtocolIEID
	received aper.WireSpan
	replay   aper.Snapshot
	opaque   aper.OpaqueOpenType
	isOpaque bool
}

func (v AssistanceDataForRecommendedCellsExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	}
	return false
}
func (v *AssistanceDataForRecommendedCellsExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (AssistanceDataForRecommendedCellsExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AssistanceDataForRecommendedCells-ExtIEs"}}
}
func (AssistanceDataForRecommendedCellsExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
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
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(41):
		return aper.NotInTable
	case s00.ProtocolIEID(43):
		return aper.NotInTable
	case s00.ProtocolIEID(44):
		return aper.NotInTable
	case s00.ProtocolIEID(46):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(66):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(73):
		return aper.NotInTable
	case s00.ProtocolIEID(74):
		return aper.NotInTable
	case s00.ProtocolIEID(75):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(80):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(106):
		return aper.NotInTable
	case s00.ProtocolIEID(107):
		return aper.NotInTable
	case s00.ProtocolIEID(108):
		return aper.NotInTable
	case s00.ProtocolIEID(109):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(124):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(146):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(151):
		return aper.NotInTable
	case s00.ProtocolIEID(152):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(165):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(177):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(179):
		return aper.NotInTable
	case s00.ProtocolIEID(180):
		return aper.NotInTable
	case s00.ProtocolIEID(181):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(187):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(192):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(195):
		return aper.NotInTable
	case s00.ProtocolIEID(196):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(198):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(211):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(217):
		return aper.NotInTable
	case s00.ProtocolIEID(218):
		return aper.NotInTable
	case s00.ProtocolIEID(219):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(239):
		return aper.NotInTable
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(251):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(269):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(271):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
		return aper.NotInTable
	case s00.ProtocolIEID(278):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(299):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(301):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(306):
		return aper.NotInTable
	case s00.ProtocolIEID(307):
		return aper.NotInTable
	case s00.ProtocolIEID(308):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(314):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(323):
		return aper.NotInTable
	case s00.ProtocolIEID(324):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v AssistanceDataForRecommendedCellsExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (AssistanceDataForRecommendedCellsExtIEsValue, error) {
	out := AssistanceDataForRecommendedCellsExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v AssistanceDataForRecommendedCellsExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v AssistanceDataForRecommendedCellsExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "AssistanceDataForRecommendedCellsExtIEsValue:", v.id)
	}
}

type BearersSubjectToDLDiscardingItemExtIEsValue struct {
	id       s00.ProtocolIEID
	received aper.WireSpan
	replay   aper.Snapshot
	opaque   aper.OpaqueOpenType
	isOpaque bool
}

func (v BearersSubjectToDLDiscardingItemExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	}
	return false
}
func (v *BearersSubjectToDLDiscardingItemExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (BearersSubjectToDLDiscardingItemExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToDLDiscarding-ItemExtIEs"}}
}
func (BearersSubjectToDLDiscardingItemExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
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
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(41):
		return aper.NotInTable
	case s00.ProtocolIEID(43):
		return aper.NotInTable
	case s00.ProtocolIEID(44):
		return aper.NotInTable
	case s00.ProtocolIEID(46):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(66):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(73):
		return aper.NotInTable
	case s00.ProtocolIEID(74):
		return aper.NotInTable
	case s00.ProtocolIEID(75):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(80):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(106):
		return aper.NotInTable
	case s00.ProtocolIEID(107):
		return aper.NotInTable
	case s00.ProtocolIEID(108):
		return aper.NotInTable
	case s00.ProtocolIEID(109):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(124):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(146):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(151):
		return aper.NotInTable
	case s00.ProtocolIEID(152):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(165):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(177):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(179):
		return aper.NotInTable
	case s00.ProtocolIEID(180):
		return aper.NotInTable
	case s00.ProtocolIEID(181):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(187):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(192):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(195):
		return aper.NotInTable
	case s00.ProtocolIEID(196):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(198):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(211):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(217):
		return aper.NotInTable
	case s00.ProtocolIEID(218):
		return aper.NotInTable
	case s00.ProtocolIEID(219):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(239):
		return aper.NotInTable
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(251):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(269):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(271):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
		return aper.NotInTable
	case s00.ProtocolIEID(278):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(299):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(301):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(306):
		return aper.NotInTable
	case s00.ProtocolIEID(307):
		return aper.NotInTable
	case s00.ProtocolIEID(308):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(314):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(323):
		return aper.NotInTable
	case s00.ProtocolIEID(324):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v BearersSubjectToDLDiscardingItemExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (BearersSubjectToDLDiscardingItemExtIEsValue, error) {
	out := BearersSubjectToDLDiscardingItemExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v BearersSubjectToDLDiscardingItemExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v BearersSubjectToDLDiscardingItemExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "BearersSubjectToDLDiscardingItemExtIEsValue:", v.id)
	}
}

type BearersSubjectToEarlyStatusTransferItemExtIEsValue struct {
	id       s00.ProtocolIEID
	received aper.WireSpan
	replay   aper.Snapshot
	opaque   aper.OpaqueOpenType
	isOpaque bool
}

func (v BearersSubjectToEarlyStatusTransferItemExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	}
	return false
}
func (v *BearersSubjectToEarlyStatusTransferItemExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (BearersSubjectToEarlyStatusTransferItemExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Bearers-SubjectToEarlyStatusTransfer-ItemExtIEs"}}
}
func (BearersSubjectToEarlyStatusTransferItemExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
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
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(41):
		return aper.NotInTable
	case s00.ProtocolIEID(43):
		return aper.NotInTable
	case s00.ProtocolIEID(44):
		return aper.NotInTable
	case s00.ProtocolIEID(46):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(66):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(73):
		return aper.NotInTable
	case s00.ProtocolIEID(74):
		return aper.NotInTable
	case s00.ProtocolIEID(75):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(80):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(106):
		return aper.NotInTable
	case s00.ProtocolIEID(107):
		return aper.NotInTable
	case s00.ProtocolIEID(108):
		return aper.NotInTable
	case s00.ProtocolIEID(109):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(124):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(146):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(151):
		return aper.NotInTable
	case s00.ProtocolIEID(152):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(165):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(177):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(179):
		return aper.NotInTable
	case s00.ProtocolIEID(180):
		return aper.NotInTable
	case s00.ProtocolIEID(181):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(187):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(192):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(195):
		return aper.NotInTable
	case s00.ProtocolIEID(196):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(198):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(211):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(217):
		return aper.NotInTable
	case s00.ProtocolIEID(218):
		return aper.NotInTable
	case s00.ProtocolIEID(219):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(239):
		return aper.NotInTable
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(251):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(269):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(271):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
		return aper.NotInTable
	case s00.ProtocolIEID(278):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(299):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(301):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(306):
		return aper.NotInTable
	case s00.ProtocolIEID(307):
		return aper.NotInTable
	case s00.ProtocolIEID(308):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(314):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(323):
		return aper.NotInTable
	case s00.ProtocolIEID(324):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v BearersSubjectToEarlyStatusTransferItemExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (BearersSubjectToEarlyStatusTransferItemExtIEsValue, error) {
	out := BearersSubjectToEarlyStatusTransferItemExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v BearersSubjectToEarlyStatusTransferItemExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v BearersSubjectToEarlyStatusTransferItemExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "BearersSubjectToEarlyStatusTransferItemExtIEsValue:", v.id)
	}
}

type BluetoothMeasurementConfigurationExtIEsValue struct {
	id       s00.ProtocolIEID
	received aper.WireSpan
	replay   aper.Snapshot
	opaque   aper.OpaqueOpenType
	isOpaque bool
}

func (v BluetoothMeasurementConfigurationExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	}
	return false
}
func (v *BluetoothMeasurementConfigurationExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (BluetoothMeasurementConfigurationExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "BluetoothMeasurementConfiguration-ExtIEs"}}
}
func (BluetoothMeasurementConfigurationExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
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
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(41):
		return aper.NotInTable
	case s00.ProtocolIEID(43):
		return aper.NotInTable
	case s00.ProtocolIEID(44):
		return aper.NotInTable
	case s00.ProtocolIEID(46):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(66):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(73):
		return aper.NotInTable
	case s00.ProtocolIEID(74):
		return aper.NotInTable
	case s00.ProtocolIEID(75):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(80):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(106):
		return aper.NotInTable
	case s00.ProtocolIEID(107):
		return aper.NotInTable
	case s00.ProtocolIEID(108):
		return aper.NotInTable
	case s00.ProtocolIEID(109):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(124):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(146):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(151):
		return aper.NotInTable
	case s00.ProtocolIEID(152):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(165):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(177):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(179):
		return aper.NotInTable
	case s00.ProtocolIEID(180):
		return aper.NotInTable
	case s00.ProtocolIEID(181):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(187):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(192):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(195):
		return aper.NotInTable
	case s00.ProtocolIEID(196):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(198):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(211):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(217):
		return aper.NotInTable
	case s00.ProtocolIEID(218):
		return aper.NotInTable
	case s00.ProtocolIEID(219):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(239):
		return aper.NotInTable
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(251):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(269):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(271):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
		return aper.NotInTable
	case s00.ProtocolIEID(278):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(299):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(301):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(306):
		return aper.NotInTable
	case s00.ProtocolIEID(307):
		return aper.NotInTable
	case s00.ProtocolIEID(308):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(314):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(323):
		return aper.NotInTable
	case s00.ProtocolIEID(324):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v BluetoothMeasurementConfigurationExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (BluetoothMeasurementConfigurationExtIEsValue, error) {
	out := BluetoothMeasurementConfigurationExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v BluetoothMeasurementConfigurationExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v BluetoothMeasurementConfigurationExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "BluetoothMeasurementConfigurationExtIEsValue:", v.id)
	}
}

type CGIExtIEsValue struct {
	id       s00.ProtocolIEID
	received aper.WireSpan
	replay   aper.Snapshot
	opaque   aper.OpaqueOpenType
	isOpaque bool
}

func (v CGIExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	}
	return false
}
func (v *CGIExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (CGIExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CGI-ExtIEs"}}
}
func (CGIExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
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
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(41):
		return aper.NotInTable
	case s00.ProtocolIEID(43):
		return aper.NotInTable
	case s00.ProtocolIEID(44):
		return aper.NotInTable
	case s00.ProtocolIEID(46):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(66):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(73):
		return aper.NotInTable
	case s00.ProtocolIEID(74):
		return aper.NotInTable
	case s00.ProtocolIEID(75):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(80):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(106):
		return aper.NotInTable
	case s00.ProtocolIEID(107):
		return aper.NotInTable
	case s00.ProtocolIEID(108):
		return aper.NotInTable
	case s00.ProtocolIEID(109):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(124):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(146):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(151):
		return aper.NotInTable
	case s00.ProtocolIEID(152):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(165):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(177):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(179):
		return aper.NotInTable
	case s00.ProtocolIEID(180):
		return aper.NotInTable
	case s00.ProtocolIEID(181):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(187):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(192):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(195):
		return aper.NotInTable
	case s00.ProtocolIEID(196):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(198):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(211):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(217):
		return aper.NotInTable
	case s00.ProtocolIEID(218):
		return aper.NotInTable
	case s00.ProtocolIEID(219):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(239):
		return aper.NotInTable
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(251):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(269):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(271):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
		return aper.NotInTable
	case s00.ProtocolIEID(278):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(299):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(301):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(306):
		return aper.NotInTable
	case s00.ProtocolIEID(307):
		return aper.NotInTable
	case s00.ProtocolIEID(308):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(314):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(323):
		return aper.NotInTable
	case s00.ProtocolIEID(324):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v CGIExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (CGIExtIEsValue, error) {
	out := CGIExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v CGIExtIEsValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v CGIExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "CGIExtIEsValue:", v.id)
	}
}

type CNTypeRestrictionsItemExtIEsValue struct {
	id       s00.ProtocolIEID
	received aper.WireSpan
	replay   aper.Snapshot
	opaque   aper.OpaqueOpenType
	isOpaque bool
}

func (v CNTypeRestrictionsItemExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	}
	return false
}
func (v *CNTypeRestrictionsItemExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (CNTypeRestrictionsItemExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CNTypeRestrictions-Item-ExtIEs"}}
}
func (CNTypeRestrictionsItemExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
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
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(41):
		return aper.NotInTable
	case s00.ProtocolIEID(43):
		return aper.NotInTable
	case s00.ProtocolIEID(44):
		return aper.NotInTable
	case s00.ProtocolIEID(46):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(66):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(73):
		return aper.NotInTable
	case s00.ProtocolIEID(74):
		return aper.NotInTable
	case s00.ProtocolIEID(75):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(80):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(106):
		return aper.NotInTable
	case s00.ProtocolIEID(107):
		return aper.NotInTable
	case s00.ProtocolIEID(108):
		return aper.NotInTable
	case s00.ProtocolIEID(109):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(124):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(146):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(151):
		return aper.NotInTable
	case s00.ProtocolIEID(152):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(165):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(177):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(179):
		return aper.NotInTable
	case s00.ProtocolIEID(180):
		return aper.NotInTable
	case s00.ProtocolIEID(181):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(187):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(192):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(195):
		return aper.NotInTable
	case s00.ProtocolIEID(196):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(198):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(211):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(217):
		return aper.NotInTable
	case s00.ProtocolIEID(218):
		return aper.NotInTable
	case s00.ProtocolIEID(219):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(239):
		return aper.NotInTable
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(251):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(269):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(271):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
		return aper.NotInTable
	case s00.ProtocolIEID(278):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(299):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(301):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(306):
		return aper.NotInTable
	case s00.ProtocolIEID(307):
		return aper.NotInTable
	case s00.ProtocolIEID(308):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(314):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(323):
		return aper.NotInTable
	case s00.ProtocolIEID(324):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v CNTypeRestrictionsItemExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (CNTypeRestrictionsItemExtIEsValue, error) {
	out := CNTypeRestrictionsItemExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v CNTypeRestrictionsItemExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v CNTypeRestrictionsItemExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "CNTypeRestrictionsItemExtIEsValue:", v.id)
	}
}

type COUNTValueExtendedExtIEsValue struct {
	id       s00.ProtocolIEID
	received aper.WireSpan
	replay   aper.Snapshot
	opaque   aper.OpaqueOpenType
	isOpaque bool
}

func (v COUNTValueExtendedExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	}
	return false
}
func (v *COUNTValueExtendedExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (COUNTValueExtendedExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "COUNTValueExtended-ExtIEs"}}
}
func (COUNTValueExtendedExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
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
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(41):
		return aper.NotInTable
	case s00.ProtocolIEID(43):
		return aper.NotInTable
	case s00.ProtocolIEID(44):
		return aper.NotInTable
	case s00.ProtocolIEID(46):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(66):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(73):
		return aper.NotInTable
	case s00.ProtocolIEID(74):
		return aper.NotInTable
	case s00.ProtocolIEID(75):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(80):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(106):
		return aper.NotInTable
	case s00.ProtocolIEID(107):
		return aper.NotInTable
	case s00.ProtocolIEID(108):
		return aper.NotInTable
	case s00.ProtocolIEID(109):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(124):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(146):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(151):
		return aper.NotInTable
	case s00.ProtocolIEID(152):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(165):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(177):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(179):
		return aper.NotInTable
	case s00.ProtocolIEID(180):
		return aper.NotInTable
	case s00.ProtocolIEID(181):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(187):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(192):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(195):
		return aper.NotInTable
	case s00.ProtocolIEID(196):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(198):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(211):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(217):
		return aper.NotInTable
	case s00.ProtocolIEID(218):
		return aper.NotInTable
	case s00.ProtocolIEID(219):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(239):
		return aper.NotInTable
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(251):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(269):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(271):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
		return aper.NotInTable
	case s00.ProtocolIEID(278):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(299):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(301):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(306):
		return aper.NotInTable
	case s00.ProtocolIEID(307):
		return aper.NotInTable
	case s00.ProtocolIEID(308):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(314):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(323):
		return aper.NotInTable
	case s00.ProtocolIEID(324):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v COUNTValueExtendedExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (COUNTValueExtendedExtIEsValue, error) {
	out := COUNTValueExtendedExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v COUNTValueExtendedExtIEsValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v COUNTValueExtendedExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "COUNTValueExtendedExtIEsValue:", v.id)
	}
}

type COUNTvalueExtIEsValue struct {
	id       s00.ProtocolIEID
	received aper.WireSpan
	replay   aper.Snapshot
	opaque   aper.OpaqueOpenType
	isOpaque bool
}

func (v COUNTvalueExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	}
	return false
}
func (v *COUNTvalueExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (COUNTvalueExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "COUNTvalue-ExtIEs"}}
}
func (COUNTvalueExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
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
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(41):
		return aper.NotInTable
	case s00.ProtocolIEID(43):
		return aper.NotInTable
	case s00.ProtocolIEID(44):
		return aper.NotInTable
	case s00.ProtocolIEID(46):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(66):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(73):
		return aper.NotInTable
	case s00.ProtocolIEID(74):
		return aper.NotInTable
	case s00.ProtocolIEID(75):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(80):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(106):
		return aper.NotInTable
	case s00.ProtocolIEID(107):
		return aper.NotInTable
	case s00.ProtocolIEID(108):
		return aper.NotInTable
	case s00.ProtocolIEID(109):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(124):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(146):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(151):
		return aper.NotInTable
	case s00.ProtocolIEID(152):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(165):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(177):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(179):
		return aper.NotInTable
	case s00.ProtocolIEID(180):
		return aper.NotInTable
	case s00.ProtocolIEID(181):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(187):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(192):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(195):
		return aper.NotInTable
	case s00.ProtocolIEID(196):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(198):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(211):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(217):
		return aper.NotInTable
	case s00.ProtocolIEID(218):
		return aper.NotInTable
	case s00.ProtocolIEID(219):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(239):
		return aper.NotInTable
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(251):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(269):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(271):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
		return aper.NotInTable
	case s00.ProtocolIEID(278):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(299):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(301):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(306):
		return aper.NotInTable
	case s00.ProtocolIEID(307):
		return aper.NotInTable
	case s00.ProtocolIEID(308):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(314):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(323):
		return aper.NotInTable
	case s00.ProtocolIEID(324):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v COUNTvalueExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (COUNTvalueExtIEsValue, error) {
	out := COUNTvalueExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v COUNTvalueExtIEsValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v COUNTvalueExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "COUNTvalueExtIEsValue:", v.id)
	}
}

type COUNTvaluePDCPSNlength18ExtIEsValue struct {
	id       s00.ProtocolIEID
	received aper.WireSpan
	replay   aper.Snapshot
	opaque   aper.OpaqueOpenType
	isOpaque bool
}

func (v COUNTvaluePDCPSNlength18ExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	}
	return false
}
func (v *COUNTvaluePDCPSNlength18ExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (COUNTvaluePDCPSNlength18ExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "COUNTvaluePDCP-SNlength18-ExtIEs"}}
}
func (COUNTvaluePDCPSNlength18ExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
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
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(41):
		return aper.NotInTable
	case s00.ProtocolIEID(43):
		return aper.NotInTable
	case s00.ProtocolIEID(44):
		return aper.NotInTable
	case s00.ProtocolIEID(46):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(66):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(73):
		return aper.NotInTable
	case s00.ProtocolIEID(74):
		return aper.NotInTable
	case s00.ProtocolIEID(75):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(80):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(106):
		return aper.NotInTable
	case s00.ProtocolIEID(107):
		return aper.NotInTable
	case s00.ProtocolIEID(108):
		return aper.NotInTable
	case s00.ProtocolIEID(109):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(124):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(146):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(151):
		return aper.NotInTable
	case s00.ProtocolIEID(152):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(165):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(177):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(179):
		return aper.NotInTable
	case s00.ProtocolIEID(180):
		return aper.NotInTable
	case s00.ProtocolIEID(181):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(187):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(192):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(195):
		return aper.NotInTable
	case s00.ProtocolIEID(196):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(198):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(211):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(217):
		return aper.NotInTable
	case s00.ProtocolIEID(218):
		return aper.NotInTable
	case s00.ProtocolIEID(219):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(239):
		return aper.NotInTable
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(251):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(269):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(271):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
		return aper.NotInTable
	case s00.ProtocolIEID(278):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(299):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(301):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(306):
		return aper.NotInTable
	case s00.ProtocolIEID(307):
		return aper.NotInTable
	case s00.ProtocolIEID(308):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(314):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(323):
		return aper.NotInTable
	case s00.ProtocolIEID(324):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v COUNTvaluePDCPSNlength18ExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (COUNTvaluePDCPSNlength18ExtIEsValue, error) {
	out := COUNTvaluePDCPSNlength18ExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v COUNTvaluePDCPSNlength18ExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v COUNTvaluePDCPSNlength18ExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "COUNTvaluePDCPSNlength18ExtIEsValue:", v.id)
	}
}

type CSGIdListItemExtIEsValue struct {
	id       s00.ProtocolIEID
	received aper.WireSpan
	replay   aper.Snapshot
	opaque   aper.OpaqueOpenType
	isOpaque bool
}

func (v CSGIdListItemExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	}
	return false
}
func (v *CSGIdListItemExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (CSGIdListItemExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSG-IdList-Item-ExtIEs"}}
}
func (CSGIdListItemExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
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
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(41):
		return aper.NotInTable
	case s00.ProtocolIEID(43):
		return aper.NotInTable
	case s00.ProtocolIEID(44):
		return aper.NotInTable
	case s00.ProtocolIEID(46):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(66):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(73):
		return aper.NotInTable
	case s00.ProtocolIEID(74):
		return aper.NotInTable
	case s00.ProtocolIEID(75):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(80):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(106):
		return aper.NotInTable
	case s00.ProtocolIEID(107):
		return aper.NotInTable
	case s00.ProtocolIEID(108):
		return aper.NotInTable
	case s00.ProtocolIEID(109):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(124):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(146):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(151):
		return aper.NotInTable
	case s00.ProtocolIEID(152):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(165):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(177):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(179):
		return aper.NotInTable
	case s00.ProtocolIEID(180):
		return aper.NotInTable
	case s00.ProtocolIEID(181):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(187):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(192):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(195):
		return aper.NotInTable
	case s00.ProtocolIEID(196):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(198):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(211):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(217):
		return aper.NotInTable
	case s00.ProtocolIEID(218):
		return aper.NotInTable
	case s00.ProtocolIEID(219):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(239):
		return aper.NotInTable
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(251):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(269):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(271):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
		return aper.NotInTable
	case s00.ProtocolIEID(278):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(299):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(301):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(306):
		return aper.NotInTable
	case s00.ProtocolIEID(307):
		return aper.NotInTable
	case s00.ProtocolIEID(308):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(314):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(323):
		return aper.NotInTable
	case s00.ProtocolIEID(324):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v CSGIdListItemExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (CSGIdListItemExtIEsValue, error) {
	out := CSGIdListItemExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v CSGIdListItemExtIEsValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v CSGIdListItemExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "CSGIdListItemExtIEsValue:", v.id)
	}
}

type CancelledCellinEAIItemExtIEsValue struct {
	id       s00.ProtocolIEID
	received aper.WireSpan
	replay   aper.Snapshot
	opaque   aper.OpaqueOpenType
	isOpaque bool
}

func (v CancelledCellinEAIItemExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	}
	return false
}
func (v *CancelledCellinEAIItemExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (CancelledCellinEAIItemExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CancelledCellinEAI-Item-ExtIEs"}}
}
func (CancelledCellinEAIItemExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
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
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(41):
		return aper.NotInTable
	case s00.ProtocolIEID(43):
		return aper.NotInTable
	case s00.ProtocolIEID(44):
		return aper.NotInTable
	case s00.ProtocolIEID(46):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(66):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(73):
		return aper.NotInTable
	case s00.ProtocolIEID(74):
		return aper.NotInTable
	case s00.ProtocolIEID(75):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(80):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(106):
		return aper.NotInTable
	case s00.ProtocolIEID(107):
		return aper.NotInTable
	case s00.ProtocolIEID(108):
		return aper.NotInTable
	case s00.ProtocolIEID(109):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(124):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(146):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(151):
		return aper.NotInTable
	case s00.ProtocolIEID(152):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(165):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(177):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(179):
		return aper.NotInTable
	case s00.ProtocolIEID(180):
		return aper.NotInTable
	case s00.ProtocolIEID(181):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(187):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(192):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(195):
		return aper.NotInTable
	case s00.ProtocolIEID(196):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(198):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(211):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(217):
		return aper.NotInTable
	case s00.ProtocolIEID(218):
		return aper.NotInTable
	case s00.ProtocolIEID(219):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(239):
		return aper.NotInTable
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(251):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(269):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(271):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
		return aper.NotInTable
	case s00.ProtocolIEID(278):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(299):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(301):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(306):
		return aper.NotInTable
	case s00.ProtocolIEID(307):
		return aper.NotInTable
	case s00.ProtocolIEID(308):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(314):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(323):
		return aper.NotInTable
	case s00.ProtocolIEID(324):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v CancelledCellinEAIItemExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (CancelledCellinEAIItemExtIEsValue, error) {
	out := CancelledCellinEAIItemExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v CancelledCellinEAIItemExtIEsValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v CancelledCellinEAIItemExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "CancelledCellinEAIItemExtIEsValue:", v.id)
	}
}

type CSGMembershipInfoExtIEsValue struct {
	id       s00.ProtocolIEID
	received aper.WireSpan
	replay   aper.Snapshot
	opaque   aper.OpaqueOpenType
	isOpaque bool
}

func (v CSGMembershipInfoExtIEsValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	}
	return false
}
func (v *CSGMembershipInfoExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (CSGMembershipInfoExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "CSGMembershipInfo-ExtIEs"}}
}
func (CSGMembershipInfoExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
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
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(41):
		return aper.NotInTable
	case s00.ProtocolIEID(43):
		return aper.NotInTable
	case s00.ProtocolIEID(44):
		return aper.NotInTable
	case s00.ProtocolIEID(46):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(66):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(73):
		return aper.NotInTable
	case s00.ProtocolIEID(74):
		return aper.NotInTable
	case s00.ProtocolIEID(75):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(80):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(106):
		return aper.NotInTable
	case s00.ProtocolIEID(107):
		return aper.NotInTable
	case s00.ProtocolIEID(108):
		return aper.NotInTable
	case s00.ProtocolIEID(109):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(124):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(146):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(151):
		return aper.NotInTable
	case s00.ProtocolIEID(152):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(165):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(177):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(179):
		return aper.NotInTable
	case s00.ProtocolIEID(180):
		return aper.NotInTable
	case s00.ProtocolIEID(181):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(187):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(192):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(195):
		return aper.NotInTable
	case s00.ProtocolIEID(196):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(198):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(211):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(217):
		return aper.NotInTable
	case s00.ProtocolIEID(218):
		return aper.NotInTable
	case s00.ProtocolIEID(219):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(239):
		return aper.NotInTable
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(251):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(269):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(271):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
		return aper.NotInTable
	case s00.ProtocolIEID(278):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(299):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(301):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(306):
		return aper.NotInTable
	case s00.ProtocolIEID(307):
		return aper.NotInTable
	case s00.ProtocolIEID(308):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(314):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(323):
		return aper.NotInTable
	case s00.ProtocolIEID(324):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}
func (v CSGMembershipInfoExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (CSGMembershipInfoExtIEsValue, error) {
	out := CSGMembershipInfoExtIEsValue{id: id}
	switch id {
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v CSGMembershipInfoExtIEsValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v CSGMembershipInfoExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	default:
		return nil, fmt.Errorf("%s id %d has no value", "CSGMembershipInfoExtIEsValue:", v.id)
	}
}

// BluetoothMeasConfigCodec binds the complete source value type.
func BluetoothMeasConfigCodec() s00.BluetoothMeasConfigValueCodec {
	return func() s00.BluetoothMeasConfigValueCodec {
		sealed := s00.BluetoothMeasConfigValueCodec{}
		*s00.BridgeBluetoothMeasConfigValueCodecFieldPath(&sealed) = "BluetoothMeasConfig"
		*s00.BridgeBluetoothMeasConfigValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.BluetoothMeasConfig, error) {
			var zero s00.BluetoothMeasConfig
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.BluetoothMeasConfig, error) {
				var v struct{ Value s00.BluetoothMeasConfig }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.BluetoothMeasConfig(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "BluetoothMeasConfig"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeBluetoothMeasConfigValueCodecFieldEncode(&sealed) = func(value s00.BluetoothMeasConfig, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.BluetoothMeasConfig, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.BluetoothMeasConfig }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 1, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeBluetoothMeasConfigValueCodecFieldCapture(&sealed) = func(v s00.BluetoothMeasConfig, options aper.DecodeState) (s00.BluetoothMeasConfig, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APBluetoothMeasConfig(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeBluetoothMeasConfigValueCodecFieldCompare(&sealed) = func(v s00.BluetoothMeasConfig, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APBluetoothMeasConfig(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeBluetoothMeasConfigValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BluetoothMeasConfig"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// BluetoothNameCodec binds the complete source value type.
func BluetoothNameCodec() s00.BluetoothNameValueCodec {
	return func() s00.BluetoothNameValueCodec {
		sealed := s00.BluetoothNameValueCodec{}
		*s00.BridgeBluetoothNameValueCodecFieldPath(&sealed) = "BluetoothName"
		*s00.BridgeBluetoothNameValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.BluetoothName, error) {
			var zero s00.BluetoothName
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.BluetoothName, error) {
				var v struct{ Value s00.BluetoothName }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 1, 248, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.BluetoothName(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "BluetoothName"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeBluetoothNameValueCodecFieldEncode(&sealed) = func(value s00.BluetoothName, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.BluetoothName, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.BluetoothName }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 1, 248, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeBluetoothNameValueCodecFieldCapture(&sealed) = func(v s00.BluetoothName, options aper.DecodeState) (s00.BluetoothName, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APBluetoothName(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeBluetoothNameValueCodecFieldCompare(&sealed) = func(v s00.BluetoothName, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APBluetoothName(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s00.BridgeBluetoothNameValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BluetoothName"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CELevelCodec binds the complete source value type.
func CELevelCodec() s00.CELevelValueCodec {
	return func() s00.CELevelValueCodec {
		sealed := s00.CELevelValueCodec{}
		*s00.BridgeCELevelValueCodecFieldPath(&sealed) = "CELevel"
		*s00.BridgeCELevelValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CELevel, error) {
			var zero s00.CELevel
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.CELevel, error) {
				var v struct{ Value s00.CELevel }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.CELevel(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "CELevel"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeCELevelValueCodecFieldEncode(&sealed) = func(value s00.CELevel, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.CELevel, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.CELevel }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 0, 0, false); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeCELevelValueCodecFieldCapture(&sealed) = func(v s00.CELevel, options aper.DecodeState) (s00.CELevel, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APCELevel(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s00.BridgeCELevelValueCodecFieldCompare(&sealed) = func(v s00.CELevel, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCELevel(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCELevelValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CELevel"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CICodec binds the complete source value type.
func CICodec() s00.CIValueCodec {
	return func() s00.CIValueCodec {
		sealed := s00.CIValueCodec{}
		*s00.BridgeCIValueCodecFieldPath(&sealed) = "CI"
		*s00.BridgeCIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CI, error) {
			var zero s00.CI
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.CI, error) {
				var v struct{ Value s00.CI }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.CI(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "CI"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeCIValueCodecFieldEncode(&sealed) = func(value s00.CI, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.CI, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.CI }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 2, 2, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeCIValueCodecFieldCapture(&sealed) = func(v s00.CI, options aper.DecodeState) (s00.CI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=

				s.Begin()
			s00.BridgeCaptureS1APCI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCIValueCodecFieldCompare(&sealed) = func(v s00.CI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCI(&v,
				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CNTypeCodec binds the complete source value type.
func CNTypeCodec() s00.CNTypeValueCodec {
	return func() s00.CNTypeValueCodec {
		sealed := s00.CNTypeValueCodec{}
		*s00.BridgeCNTypeValueCodecFieldPath(&sealed) = "CNType"
		*s00.BridgeCNTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CNType, error) {
			var zero s00.CNType
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.CNType, error) {
				var v struct{ Value s00.CNType }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 1, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.CNType(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "CNType"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeCNTypeValueCodecFieldEncode(&sealed) = func(value s00.CNType, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.CNType, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.CNType }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 1, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeCNTypeValueCodecFieldCapture(&sealed) = func(v s00.CNType, options aper.DecodeState) (s00.CNType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APCNType(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCNTypeValueCodecFieldCompare(&sealed) = func(v s00.CNType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCNType(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCNTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CNType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CauseMiscCodec binds the complete source value type.
func CauseMiscCodec() s00.CauseMiscValueCodec {
	return func() s00.CauseMiscValueCodec {
		sealed := s00.CauseMiscValueCodec{}
		*s00.BridgeCauseMiscValueCodecFieldPath(&sealed) = "CauseMisc"
		*s00.BridgeCauseMiscValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CauseMisc, error) {
			var zero s00.CauseMisc
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.CauseMisc, error) {
				var v struct{ Value s00.CauseMisc }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 6, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.CauseMisc(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "CauseMisc"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeCauseMiscValueCodecFieldEncode(&sealed) = func(value s00.CauseMisc, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.CauseMisc, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.CauseMisc }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 6, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeCauseMiscValueCodecFieldCapture(&sealed) = func(v s00.CauseMisc, options aper.DecodeState) (s00.CauseMisc, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APCauseMisc(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCauseMiscValueCodecFieldCompare(&sealed) = func(v s00.CauseMisc, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCauseMisc(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCauseMiscValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CauseMisc"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CauseNasCodec binds the complete source value type.
func CauseNasCodec() s00.CauseNasValueCodec {
	return func() s00.CauseNasValueCodec {
		sealed := s00.CauseNasValueCodec{}
		*s00.BridgeCauseNasValueCodecFieldPath(&sealed) = "CauseNas"
		*s00.BridgeCauseNasValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CauseNas, error) {
			var zero s00.CauseNas
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.CauseNas, error) {
				var v struct{ Value s00.CauseNas }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 3, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.CauseNas(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "CauseNas"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeCauseNasValueCodecFieldEncode(&sealed) = func(value s00.CauseNas, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.CauseNas, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.CauseNas }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 4, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeCauseNasValueCodecFieldCapture(&sealed) = func(v s00.CauseNas, options aper.DecodeState) (s00.CauseNas, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APCauseNas(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCauseNasValueCodecFieldCompare(&sealed) = func(v s00.CauseNas, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCauseNas(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCauseNasValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CauseNas"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CauseProtocolCodec binds the complete source value type.
func CauseProtocolCodec() s00.CauseProtocolValueCodec {
	return func() s00.CauseProtocolValueCodec {
		sealed := s00.CauseProtocolValueCodec{}
		*s00.BridgeCauseProtocolValueCodecFieldPath(&sealed) = "CauseProtocol"
		*s00.BridgeCauseProtocolValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CauseProtocol, error) {
			var zero s00.CauseProtocol
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.CauseProtocol, error) {
				var v struct{ Value s00.CauseProtocol }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 7, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.CauseProtocol(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "CauseProtocol"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeCauseProtocolValueCodecFieldEncode(&sealed) = func(value s00.CauseProtocol, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.CauseProtocol, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.CauseProtocol }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 7, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeCauseProtocolValueCodecFieldCapture(&sealed) = func(v s00.CauseProtocol, options aper.DecodeState) (s00.CauseProtocol, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCauseProtocol(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCauseProtocolValueCodecFieldCompare(&sealed) = func(v s00.CauseProtocol, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCauseProtocol(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s00.BridgeCauseProtocolValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CauseProtocol"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CauseRadioNetworkCodec binds the complete source value type.
func CauseRadioNetworkCodec() s00.CauseRadioNetworkValueCodec {
	return func() s00.CauseRadioNetworkValueCodec {
		sealed := s00.CauseRadioNetworkValueCodec{}
		*s00.BridgeCauseRadioNetworkValueCodecFieldPath(&sealed) = "CauseRadioNetwork"
		*s00.BridgeCauseRadioNetworkValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CauseRadioNetwork, error) {
			var zero s00.CauseRadioNetwork
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.CauseRadioNetwork, error) {
				var v struct{ Value s00.CauseRadioNetwork }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 36, true, aper.EnumerationSource{KnownExtensions: 9, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.CauseRadioNetwork(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "CauseRadioNetwork"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeCauseRadioNetworkValueCodecFieldEncode(&sealed) = func(value s00.CauseRadioNetwork, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.CauseRadioNetwork, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.CauseRadioNetwork }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 36, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeCauseRadioNetworkValueCodecFieldCapture(&sealed) = func(v s00.CauseRadioNetwork, options aper.DecodeState) (s00.CauseRadioNetwork, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCauseRadioNetwork(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s00.BridgeCauseRadioNetworkValueCodecFieldCompare(&sealed) = func(v s00.CauseRadioNetwork, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCauseRadioNetwork(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeCauseRadioNetworkValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CauseRadioNetwork"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CauseTransportCodec binds the complete source value type.
func CauseTransportCodec() s00.CauseTransportValueCodec {
	return func() s00.CauseTransportValueCodec {
		sealed := s00.CauseTransportValueCodec{}
		*s00.BridgeCauseTransportValueCodecFieldPath(&sealed) = "CauseTransport"
		*s00.BridgeCauseTransportValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CauseTransport, error) {
			var zero s00.CauseTransport
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.CauseTransport, error) {
				var v struct{ Value s00.CauseTransport }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.CauseTransport(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "CauseTransport"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeCauseTransportValueCodecFieldEncode(&sealed) = func(value s00.CauseTransport, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.CauseTransport, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.CauseTransport }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 2, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeCauseTransportValueCodecFieldCapture(&sealed) = func(v s00.CauseTransport, options aper.DecodeState) (s00.CauseTransport, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCauseTransport(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCauseTransportValueCodecFieldCompare(&sealed) = func(v s00.CauseTransport, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCauseTransport(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCauseTransportValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CauseTransport"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Cdma2000OneXMEIDCodec binds the complete source value type.
func Cdma2000OneXMEIDCodec() s00.Cdma2000OneXMEIDValueCodec {
	return func() s00.Cdma2000OneXMEIDValueCodec {
		sealed := s00.Cdma2000OneXMEIDValueCodec{}
		*s00.BridgeCdma2000OneXMEIDValueCodecFieldPath(&sealed) = "Cdma2000OneXMEID"
		*s00.BridgeCdma2000OneXMEIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Cdma2000OneXMEID, error) {
			var zero s00.Cdma2000OneXMEID
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.Cdma2000OneXMEID, error) {
				var v struct{ Value s00.Cdma2000OneXMEID }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.Cdma2000OneXMEID(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "Cdma2000OneXMEID"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeCdma2000OneXMEIDValueCodecFieldEncode(&sealed) = func(value s00.Cdma2000OneXMEID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.Cdma2000OneXMEID, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.Cdma2000OneXMEID }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 0, 0, false); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeCdma2000OneXMEIDValueCodecFieldCapture(&sealed) = func(v s00.Cdma2000OneXMEID, options aper.DecodeState) (s00.Cdma2000OneXMEID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APCdma2000OneXMEID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCdma2000OneXMEIDValueCodecFieldCompare(&sealed) = func(v s00.Cdma2000OneXMEID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCdma2000OneXMEID(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeCdma2000OneXMEIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cdma2000OneXMEID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Cdma2000OneXMSICodec binds the complete source value type.
func Cdma2000OneXMSICodec() s00.Cdma2000OneXMSIValueCodec {
	return func() s00.Cdma2000OneXMSIValueCodec {
		sealed := s00.Cdma2000OneXMSIValueCodec{}
		*s00.BridgeCdma2000OneXMSIValueCodecFieldPath(&sealed) = "Cdma2000OneXMSI"
		*s00.BridgeCdma2000OneXMSIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Cdma2000OneXMSI, error) {
			var zero s00.Cdma2000OneXMSI
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.Cdma2000OneXMSI, error) {
				var v struct{ Value s00.Cdma2000OneXMSI }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.Cdma2000OneXMSI(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "Cdma2000OneXMSI"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeCdma2000OneXMSIValueCodecFieldEncode(&sealed) = func(value s00.Cdma2000OneXMSI, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.Cdma2000OneXMSI, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.Cdma2000OneXMSI }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 0, 0, false); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeCdma2000OneXMSIValueCodecFieldCapture(&sealed) = func(v s00.Cdma2000OneXMSI, options aper.DecodeState) (s00.Cdma2000OneXMSI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCdma2000OneXMSI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCdma2000OneXMSIValueCodecFieldCompare(&sealed) = func(v s00.Cdma2000OneXMSI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCdma2000OneXMSI(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeCdma2000OneXMSIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cdma2000OneXMSI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// Cdma2000OneXPilotCodec binds the complete source value type.
func Cdma2000OneXPilotCodec() s00.Cdma2000OneXPilotValueCodec {
	return func() s00.Cdma2000OneXPilotValueCodec {
		sealed := s00.Cdma2000OneXPilotValueCodec{}
		*s00.BridgeCdma2000OneXPilotValueCodecFieldPath(&sealed) = "Cdma2000OneXPilot"
		*s00.BridgeCdma2000OneXPilotValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Cdma2000OneXPilot, error) {
			var zero s00.Cdma2000OneXPilot
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.Cdma2000OneXPilot, error) {
				var v struct{ Value s00.Cdma2000OneXPilot }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.Cdma2000OneXPilot(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "Cdma2000OneXPilot"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeCdma2000OneXPilotValueCodecFieldEncode(&sealed) = func(value s00.Cdma2000OneXPilot, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.Cdma2000OneXPilot, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.Cdma2000OneXPilot }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 0, 0, false); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeCdma2000OneXPilotValueCodecFieldCapture(&sealed) = func(v s00.Cdma2000OneXPilot, options aper.DecodeState) (s00.Cdma2000OneXPilot, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCdma2000OneXPilot(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s00.BridgeCdma2000OneXPilotValueCodecFieldCompare(&sealed) = func(v s00.Cdma2000OneXPilot, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCdma2000OneXPilot(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeCdma2000OneXPilotValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cdma2000OneXPilot"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CellActivationCauseCodec binds the complete source value type.
func CellActivationCauseCodec() s00.CellActivationCauseValueCodec {
	return func() s00.CellActivationCauseValueCodec {
		sealed := s00.CellActivationCauseValueCodec{}
		*s00.BridgeCellActivationCauseValueCodecFieldPath(&sealed) = "CellActivationCause"
		*s00.BridgeCellActivationCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CellActivationCause, error) {
			var zero s00.CellActivationCause
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.CellActivationCause, error) {
				var v struct{ Value s00.CellActivationCause }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.CellActivationCause(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "CellActivationCause"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeCellActivationCauseValueCodecFieldEncode(&sealed) = func(value s00.CellActivationCause, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.CellActivationCause, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.CellActivationCause }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 3, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeCellActivationCauseValueCodecFieldCapture(&sealed) = func(v s00.CellActivationCause, options aper.DecodeState) (s00.CellActivationCause, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCellActivationCause(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCellActivationCauseValueCodecFieldCompare(&sealed) = func(v s00.CellActivationCause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCellActivationCause(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCellActivationCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellActivationCause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CellIdentityCodec binds the complete source value type.
func CellIdentityCodec() s00.CellIdentityValueCodec {
	return func() s00.CellIdentityValueCodec {
		sealed := s00.CellIdentityValueCodec{}
		*s00.BridgeCellIdentityValueCodecFieldPath(&sealed) = "CellIdentity"
		*s00.BridgeCellIdentityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CellIdentity, error) {
			var zero s00.CellIdentity
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.CellIdentity, error) {
				var v struct{ Value s00.CellIdentity }
				err := func() error {
					bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 28, 28, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "CellIdentity"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeCellIdentityValueCodecFieldEncode(&sealed) = func(value s00.CellIdentity, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.CellIdentity, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.CellIdentity }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 28, 28, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeCellIdentityValueCodecFieldCapture(&sealed) = func(v s00.CellIdentity, options aper.DecodeState) (s00.CellIdentity, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCellIdentity(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCellIdentityValueCodecFieldCompare(&sealed) = func(v s00.CellIdentity, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCellIdentity(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s00.BridgeCellIdentityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellIdentity"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CellLoadReportingCauseCodec binds the complete source value type.
func CellLoadReportingCauseCodec() s00.CellLoadReportingCauseValueCodec {
	return func() s00.CellLoadReportingCauseValueCodec {
		sealed := s00.CellLoadReportingCauseValueCodec{}
		*s00.BridgeCellLoadReportingCauseValueCodecFieldPath(&sealed) = "CellLoadReportingCause"
		*s00.BridgeCellLoadReportingCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CellLoadReportingCause, error) {
			var zero s00.CellLoadReportingCause
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.CellLoadReportingCause, error) {
				var v struct{ Value s00.CellLoadReportingCause }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.CellLoadReportingCause(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "CellLoadReportingCause"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeCellLoadReportingCauseValueCodecFieldEncode(&sealed) = func(value s00.CellLoadReportingCause, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.CellLoadReportingCause, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.CellLoadReportingCause }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 3, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeCellLoadReportingCauseValueCodecFieldCapture(&sealed) = func(v s00.CellLoadReportingCause, options aper.DecodeState) (s00.CellLoadReportingCause, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCellLoadReportingCause(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCellLoadReportingCauseValueCodecFieldCompare(&sealed) = func(v s00.CellLoadReportingCause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCellLoadReportingCause(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCellLoadReportingCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellLoadReportingCause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CellSizeCodec binds the complete source value type.
func CellSizeCodec() s00.CellSizeValueCodec {
	return func() s00.CellSizeValueCodec {
		sealed := s00.CellSizeValueCodec{}
		*s00.BridgeCellSizeValueCodecFieldPath(&sealed) = "CellSize"
		*s00.BridgeCellSizeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CellSize, error) {
			var zero s00.CellSize
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.CellSize, error) {
				var v struct{ Value s00.CellSize }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.CellSize(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "CellSize"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeCellSizeValueCodecFieldEncode(&sealed) = func(value s00.CellSize, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.CellSize, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.CellSize }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 4, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeCellSizeValueCodecFieldCapture(&sealed) = func(v s00.CellSize, options aper.DecodeState) (s00.CellSize, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APCellSize(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCellSizeValueCodecFieldCompare(&sealed) = func(v s00.CellSize, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCellSize(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCellSizeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellSize"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CellStateIndicationCauseCodec binds the complete source value type.
func CellStateIndicationCauseCodec() s00.CellStateIndicationCauseValueCodec {
	return func() s00.CellStateIndicationCauseValueCodec {
		sealed := s00.CellStateIndicationCauseValueCodec{}
		*s00.BridgeCellStateIndicationCauseValueCodecFieldPath(&sealed) = "CellStateIndicationCause"
		*s00.BridgeCellStateIndicationCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CellStateIndicationCause, error) {
			var zero s00.CellStateIndicationCause
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.CellStateIndicationCause, error) {
				var v struct{ Value s00.CellStateIndicationCause }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.CellStateIndicationCause(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "CellStateIndicationCause"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeCellStateIndicationCauseValueCodecFieldEncode(&sealed) = func(value s00.CellStateIndicationCause, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.CellStateIndicationCause, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.CellStateIndicationCause }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 3, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeCellStateIndicationCauseValueCodecFieldCapture(&sealed) = func(v s00.CellStateIndicationCause, options aper.DecodeState) (s00.CellStateIndicationCause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCellStateIndicationCause(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s00.BridgeCellStateIndicationCauseValueCodecFieldCompare(&sealed) = func(v s00.CellStateIndicationCause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCellStateIndicationCause(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCellStateIndicationCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellStateIndicationCause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CompositeAvailableCapacityGroupCodec binds the complete source value type.
func CompositeAvailableCapacityGroupCodec() s00.CompositeAvailableCapacityGroupValueCodec {
	return func() s00.CompositeAvailableCapacityGroupValueCodec {
		sealed := s00.CompositeAvailableCapacityGroupValueCodec{}
		*s00.BridgeCompositeAvailableCapacityGroupValueCodecFieldPath(&sealed) = "CompositeAvailableCapacityGroup"
		*s00.BridgeCompositeAvailableCapacityGroupValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CompositeAvailableCapacityGroup, error) {
			var zero s00.CompositeAvailableCapacityGroup
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.CompositeAvailableCapacityGroup, error) {
				var v struct {
					Value s00.CompositeAvailableCapacityGroup
				}
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.CompositeAvailableCapacityGroup(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "CompositeAvailableCapacityGroup"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeCompositeAvailableCapacityGroupValueCodecFieldEncode(&sealed) = func(value s00.CompositeAvailableCapacityGroup, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.CompositeAvailableCapacityGroup, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.CompositeAvailableCapacityGroup
				}{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 0, 0, false); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeCompositeAvailableCapacityGroupValueCodecFieldCapture(&sealed) = func(v s00.CompositeAvailableCapacityGroup, options aper.DecodeState) (s00.CompositeAvailableCapacityGroup, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCompositeAvailableCapacityGroup(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCompositeAvailableCapacityGroupValueCodecFieldCompare(&sealed) = func(v s00.CompositeAvailableCapacityGroup, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCompositeAvailableCapacityGroup(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCompositeAvailableCapacityGroupValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CompositeAvailableCapacityGroup"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// CriticalityCodec binds the complete source value type.
func CriticalityCodec() s00.CriticalityValueCodec {
	return func() s00.CriticalityValueCodec {
		sealed := s00.CriticalityValueCodec{}
		*s00.BridgeCriticalityValueCodecFieldPath(&sealed) = "Criticality"
		*s00.BridgeCriticalityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Criticality, error) {
			var zero s00.Criticality
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.Criticality, error) {
				var v struct{ Value s00.Criticality }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.Criticality(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "Criticality"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeCriticalityValueCodecFieldEncode(&sealed) = func(value s00.Criticality, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.Criticality, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.Criticality }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 3, false); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeCriticalityValueCodecFieldCapture(&sealed) = func(v s00.Criticality, options aper.DecodeState) (s00.Criticality, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCriticality(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCriticalityValueCodecFieldCompare(&sealed) = func(v s00.Criticality, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APCriticality(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s00.BridgeCriticalityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Criticality"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// DLForwardingCodec binds the complete source value type.
func DLForwardingCodec() s00.DLForwardingValueCodec {
	return func() s00.DLForwardingValueCodec {
		sealed := s00.DLForwardingValueCodec{}
		*s00.BridgeDLForwardingValueCodecFieldPath(&sealed) = "DLForwarding"
		*s00.BridgeDLForwardingValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.DLForwarding, error) {
			var zero s00.DLForwarding
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.DLForwarding, error) {
				var v struct{ Value s00.DLForwarding }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.DLForwarding(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "DLForwarding"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeDLForwardingValueCodecFieldEncode(&sealed) = func(value s00.DLForwarding, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.DLForwarding, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.DLForwarding }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 1, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeDLForwardingValueCodecFieldCapture(&sealed) = func(v s00.DLForwarding, options aper.DecodeState) (s00.DLForwarding, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APDLForwarding(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeDLForwardingValueCodecFieldCompare(&sealed) = func(v s00.DLForwarding, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APDLForwarding(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s00.BridgeDLForwardingValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DLForwarding"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// DLNASMACCodec binds the complete source value type.
func DLNASMACCodec() s00.DLNASMACValueCodec {
	return func() s00.DLNASMACValueCodec {
		sealed := s00.DLNASMACValueCodec{}
		*s00.BridgeDLNASMACValueCodecFieldPath(&sealed) = "DLNASMAC"
		*s00.BridgeDLNASMACValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.DLNASMAC, error) {
			var zero s00.DLNASMAC
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.DLNASMAC, error) {
				var v struct{ Value s00.DLNASMAC }
				err := func() error {
					bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 16, 16, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "DLNASMAC"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeDLNASMACValueCodecFieldEncode(&sealed) = func(value s00.DLNASMAC, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.DLNASMAC, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.DLNASMAC }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 16, 16, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeDLNASMACValueCodecFieldCapture(&sealed) = func(v s00.DLNASMAC, options aper.DecodeState) (s00.DLNASMAC, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APDLNASMAC(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeDLNASMACValueCodecFieldCompare(&sealed) = func(v s00.DLNASMAC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APDLNASMAC(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeDLNASMACValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DLNASMAC"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// EARFCNCodec binds the complete source value type.
func EARFCNCodec() s00.EARFCNValueCodec {
	return func() s00.EARFCNValueCodec {
		sealed := s00.EARFCNValueCodec{}
		*s00.BridgeEARFCNValueCodecFieldPath(&sealed) = "EARFCN"
		*s00.BridgeEARFCNValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EARFCN, error) {
			var zero s00.EARFCN
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.EARFCN, error) {
				var v struct{ Value s00.EARFCN }
				err := func() error {
					val_value, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound8, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = val_value
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "EARFCN"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeEARFCNValueCodecFieldEncode(&sealed) = func(value s00.EARFCN, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.EARFCN, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.EARFCN }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerBigBoundsAligned(bb, v.Value, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound8, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeEARFCNValueCodecFieldCapture(&sealed) = func(v s00.EARFCN, options aper.DecodeState) (s00.EARFCN, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APEARFCN(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeEARFCNValueCodecFieldCompare(&sealed) = func(v s00.EARFCN, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APEARFCN(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeEARFCNValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EARFCN"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// EHRPDSectorCapacityClassValueCodec binds the complete source value type.
func EHRPDSectorCapacityClassValueCodec() s00.EHRPDSectorCapacityClassValueValueCodec {
	return func() s00.EHRPDSectorCapacityClassValueValueCodec {
		sealed := s00.EHRPDSectorCapacityClassValueValueCodec{}
		*s00.BridgeEHRPDSectorCapacityClassValueValueCodecFieldPath(&sealed) = "EHRPDSectorCapacityClassValue"
		*s00.BridgeEHRPDSectorCapacityClassValueValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EHRPDSectorCapacityClassValue, error) {
			var zero s00.EHRPDSectorCapacityClassValue
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.EHRPDSectorCapacityClassValue, error) {
				var v struct {
					Value s00.EHRPDSectorCapacityClassValue
				}
				err := func() error {
					val_value, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound2, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = val_value
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "EHRPDSectorCapacityClassValue"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeEHRPDSectorCapacityClassValueValueCodecFieldEncode(&sealed) = func(value s00.EHRPDSectorCapacityClassValue, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.EHRPDSectorCapacityClassValue, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.EHRPDSectorCapacityClassValue
				}{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerBigBoundsAligned(bb, v.Value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound2, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeEHRPDSectorCapacityClassValueValueCodecFieldCapture(&sealed) = func(v s00.EHRPDSectorCapacityClassValue, options aper.DecodeState) (s00.EHRPDSectorCapacityClassValue, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APEHRPDSectorCapacityClassValue(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeEHRPDSectorCapacityClassValueValueCodecFieldCompare(&sealed) = func(v s00.EHRPDSectorCapacityClassValue, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCompareS1APEHRPDSectorCapacityClassValue(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeEHRPDSectorCapacityClassValueValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EHRPDSectorCapacityClassValue"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// EHRPDSectorIDCodec binds the complete source value type.
func EHRPDSectorIDCodec() s00.EHRPDSectorIDValueCodec {
	return func() s00.EHRPDSectorIDValueCodec {
		sealed := s00.EHRPDSectorIDValueCodec{}
		*s00.BridgeEHRPDSectorIDValueCodecFieldPath(&sealed) = "EHRPDSectorID"
		*s00.BridgeEHRPDSectorIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EHRPDSectorID, error) {
			var zero s00.EHRPDSectorID
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.EHRPDSectorID, error) {
				var v struct{ Value s00.EHRPDSectorID }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 16, 16, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.EHRPDSectorID(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "EHRPDSectorID"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeEHRPDSectorIDValueCodecFieldEncode(&sealed) = func(value s00.EHRPDSectorID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.EHRPDSectorID, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.EHRPDSectorID }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 16, 16, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeEHRPDSectorIDValueCodecFieldCapture(&sealed) = func(v s00.EHRPDSectorID, options aper.DecodeState) (s00.EHRPDSectorID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APEHRPDSectorID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeEHRPDSectorIDValueCodecFieldCompare(&sealed) = func(v s00.EHRPDSectorID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APEHRPDSectorID(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s00.BridgeEHRPDSectorIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EHRPDSectorID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ERABIDCodec binds the complete source value type.
func ERABIDCodec() s00.ERABIDValueCodec {
	return func() s00.ERABIDValueCodec {
		sealed := s00.ERABIDValueCodec{}
		*s00.BridgeERABIDValueCodecFieldPath(&sealed) = "ERABID"
		*s00.BridgeERABIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ERABID, error) {
			var zero s00.ERABID
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.ERABID, error) {
				var v struct{ Value s00.ERABID }
				err := func() error {
					val_value, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = val_value
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ERABID"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeERABIDValueCodecFieldEncode(&sealed) = func(value s00.ERABID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ERABID, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ERABID }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerBigBoundsAligned(bb, v.Value, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound5, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeERABIDValueCodecFieldCapture(&sealed) = func(v s00.ERABID, options aper.DecodeState) (s00.ERABID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APERABID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeERABIDValueCodecFieldCompare(&sealed) = func(v s00.ERABID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APERABID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeERABIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// EmergencyAreaIDCodec binds the complete source value type.
func EmergencyAreaIDCodec() s00.EmergencyAreaIDValueCodec {
	return func() s00.EmergencyAreaIDValueCodec {
		sealed := s00.EmergencyAreaIDValueCodec{}
		*s00.BridgeEmergencyAreaIDValueCodecFieldPath(&sealed) = "EmergencyAreaID"
		*s00.BridgeEmergencyAreaIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EmergencyAreaID, error) {
			var zero s00.EmergencyAreaID
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.EmergencyAreaID, error) {
				var v struct{ Value s00.EmergencyAreaID }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.EmergencyAreaID(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "EmergencyAreaID"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeEmergencyAreaIDValueCodecFieldEncode(&sealed) = func(value s00.EmergencyAreaID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.EmergencyAreaID, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.EmergencyAreaID }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 3, 3, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeEmergencyAreaIDValueCodecFieldCapture(&sealed) = func(v s00.EmergencyAreaID, options aper.DecodeState) (s00.EmergencyAreaID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APEmergencyAreaID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeEmergencyAreaIDValueCodecFieldCompare(&sealed) = func(v s00.EmergencyAreaID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APEmergencyAreaID(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeEmergencyAreaIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EmergencyAreaID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// EnGNBIDCodec binds the complete source value type.
func EnGNBIDCodec() s00.EnGNBIDValueCodec {
	return func() s00.EnGNBIDValueCodec {
		sealed := s00.EnGNBIDValueCodec{}
		*s00.BridgeEnGNBIDValueCodecFieldPath(&sealed) = "EnGNBID"
		*s00.BridgeEnGNBIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EnGNBID, error) {
			var zero s00.EnGNBID
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.EnGNBID, error) {
				var v struct{ Value s00.EnGNBID }
				err := func() error {
					bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAlignedExt(bb, 22, 32, true, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "EnGNBID"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeEnGNBIDValueCodecFieldEncode(&sealed) = func(value s00.EnGNBID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.EnGNBID, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.EnGNBID }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeBitStringAlignedExt(bb, v.Value.Bytes, v.Value.BitLength, 22, 32, true, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeEnGNBIDValueCodecFieldCapture(&sealed) = func(v s00.EnGNBID, options aper.DecodeState) (s00.EnGNBID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APEnGNBID(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s00.BridgeEnGNBIDValueCodecFieldCompare(&sealed) = func(v s00.EnGNBID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APEnGNBID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeEnGNBIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EnGNBID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// EncryptionAlgorithmsCodec binds the complete source value type.
func EncryptionAlgorithmsCodec() s00.EncryptionAlgorithmsValueCodec {
	return func() s00.EncryptionAlgorithmsValueCodec {
		sealed := s00.EncryptionAlgorithmsValueCodec{}
		*s00.BridgeEncryptionAlgorithmsValueCodecFieldPath(&sealed) = "EncryptionAlgorithms"
		*s00.BridgeEncryptionAlgorithmsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EncryptionAlgorithms, error) {
			var zero s00.EncryptionAlgorithms
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.EncryptionAlgorithms, error) {
				var v struct{ Value s00.EncryptionAlgorithms }
				err := func() error {
					bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAlignedExt(bb, 16, 16, true, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "EncryptionAlgorithms"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeEncryptionAlgorithmsValueCodecFieldEncode(&sealed) = func(value s00.EncryptionAlgorithms, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.EncryptionAlgorithms, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.EncryptionAlgorithms }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeBitStringAlignedExt(bb, v.Value.Bytes, v.Value.BitLength, 16, 16, true, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeEncryptionAlgorithmsValueCodecFieldCapture(&sealed) = func(v s00.EncryptionAlgorithms, options aper.DecodeState) (s00.EncryptionAlgorithms, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APEncryptionAlgorithms(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeEncryptionAlgorithmsValueCodecFieldCompare(&sealed) = func(v s00.EncryptionAlgorithms, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APEncryptionAlgorithms(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeEncryptionAlgorithmsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EncryptionAlgorithms"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// EventTypeCodec binds the complete source value type.
func EventTypeCodec() s00.EventTypeValueCodec {
	return func() s00.EventTypeValueCodec {
		sealed := s00.EventTypeValueCodec{}
		*s00.BridgeEventTypeValueCodecFieldPath(&sealed) = "EventType"
		*s00.BridgeEventTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EventType, error) {
			var zero s00.EventType
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.EventType, error) {
				var v struct{ Value s00.EventType }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.EventType(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "EventType"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeEventTypeValueCodecFieldEncode(&sealed) = func(value s00.EventType, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.EventType, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.EventType }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 3, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeEventTypeValueCodecFieldCapture(&sealed) = func(v s00.EventType, options aper.DecodeState) (s00.EventType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APEventType(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeEventTypeValueCodecFieldCompare(&sealed) = func(v s00.EventType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APEventType(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeEventTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EventType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ExpectedActivityPeriodCodec binds the complete source value type.
func ExpectedActivityPeriodCodec() s00.ExpectedActivityPeriodValueCodec {
	return func() s00.ExpectedActivityPeriodValueCodec {
		sealed := s00.ExpectedActivityPeriodValueCodec{}
		*s00.BridgeExpectedActivityPeriodValueCodecFieldPath(&sealed) = "ExpectedActivityPeriod"
		*s00.BridgeExpectedActivityPeriodValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ExpectedActivityPeriod, error) {
			var zero s00.ExpectedActivityPeriod
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.ExpectedActivityPeriod, error) {
				var v struct{ Value s00.ExpectedActivityPeriod }
				err := func() error {
					val_value, err := aper.DecodeIntegerValueSetBigAligned(bb, []aper.IntegerRange{{Min: 1, Max: 30}, {Min: 40, Max: 40}, {Min: 50, Max: 50}, {Min: 60, Max: 60}, {Min: 80, Max: 80}, {Min: 100, Max: 100}, {Min: 120, Max: 120}, {Min: 150, Max: 150}, {Min: 180, Max: 181}}, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = val_value
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ExpectedActivityPeriod"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeExpectedActivityPeriodValueCodecFieldEncode(&sealed) = func(value s00.ExpectedActivityPeriod, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ExpectedActivityPeriod, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ExpectedActivityPeriod }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerValueSetBigAligned(bb, v.Value, []aper.IntegerRange{{Min: 1, Max: 30}, {Min: 40, Max: 40}, {Min: 50, Max: 50}, {Min: 60, Max: 60}, {Min: 80, Max: 80}, {Min: 100, Max: 100}, {Min: 120, Max: 120}, {Min: 150, Max: 150}, {Min: 180, Max: 181}}, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeExpectedActivityPeriodValueCodecFieldCapture(&sealed) = func(v s00.ExpectedActivityPeriod, options aper.DecodeState) (s00.ExpectedActivityPeriod, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APExpectedActivityPeriod(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeExpectedActivityPeriodValueCodecFieldCompare(&sealed) = func(v s00.ExpectedActivityPeriod, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APExpectedActivityPeriod(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeExpectedActivityPeriodValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ExpectedActivityPeriod"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ExpectedHOIntervalCodec binds the complete source value type.
func ExpectedHOIntervalCodec() s00.ExpectedHOIntervalValueCodec {
	return func() s00.ExpectedHOIntervalValueCodec {
		sealed := s00.ExpectedHOIntervalValueCodec{}
		*s00.BridgeExpectedHOIntervalValueCodecFieldPath(&sealed) = "ExpectedHOInterval"
		*s00.BridgeExpectedHOIntervalValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ExpectedHOInterval, error) {
			var zero s00.ExpectedHOInterval
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.ExpectedHOInterval, error) {
				var v struct{ Value s00.ExpectedHOInterval }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 7, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.ExpectedHOInterval(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ExpectedHOInterval"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeExpectedHOIntervalValueCodecFieldEncode(&sealed) = func(value s00.ExpectedHOInterval, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ExpectedHOInterval, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ExpectedHOInterval }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 7, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeExpectedHOIntervalValueCodecFieldCapture(&sealed) = func(v s00.ExpectedHOInterval, options aper.DecodeState) (s00.ExpectedHOInterval, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APExpectedHOInterval(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s00.BridgeExpectedHOIntervalValueCodecFieldCompare(&sealed) = func(v s00.ExpectedHOInterval, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APExpectedHOInterval(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeExpectedHOIntervalValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ExpectedHOInterval"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ExpectedIdlePeriodCodec binds the complete source value type.
func ExpectedIdlePeriodCodec() s00.ExpectedIdlePeriodValueCodec {
	return func() s00.ExpectedIdlePeriodValueCodec {
		sealed := s00.ExpectedIdlePeriodValueCodec{}
		*s00.BridgeExpectedIdlePeriodValueCodecFieldPath(&sealed) = "ExpectedIdlePeriod"
		*s00.BridgeExpectedIdlePeriodValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ExpectedIdlePeriod, error) {
			var zero s00.ExpectedIdlePeriod
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.ExpectedIdlePeriod, error) {
				var v struct{ Value s00.ExpectedIdlePeriod }
				err := func() error {
					val_value, err := aper.DecodeIntegerValueSetBigAligned(bb, []aper.IntegerRange{{Min: 1, Max: 30}, {Min: 40, Max: 40}, {Min: 50, Max: 50}, {Min: 60, Max: 60}, {Min: 80, Max: 80}, {Min: 100, Max: 100}, {Min: 120, Max: 120}, {Min: 150, Max: 150}, {Min: 180, Max: 181}}, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = val_value
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ExpectedIdlePeriod"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeExpectedIdlePeriodValueCodecFieldEncode(&sealed) = func(value s00.ExpectedIdlePeriod, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ExpectedIdlePeriod, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ExpectedIdlePeriod }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerValueSetBigAligned(bb, v.Value, []aper.IntegerRange{{Min: 1, Max: 30}, {Min: 40, Max: 40}, {Min: 50, Max: 50}, {Min: 60, Max: 60}, {Min: 80, Max: 80}, {Min: 100, Max: 100}, {Min: 120, Max: 120}, {Min: 150, Max: 150}, {Min: 180, Max: 181}}, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeExpectedIdlePeriodValueCodecFieldCapture(&sealed) = func(v s00.ExpectedIdlePeriod, options aper.DecodeState) (s00.ExpectedIdlePeriod, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APExpectedIdlePeriod(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s00.BridgeExpectedIdlePeriodValueCodecFieldCompare(&sealed) = func(v s00.ExpectedIdlePeriod, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APExpectedIdlePeriod(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeExpectedIdlePeriodValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ExpectedIdlePeriod"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// FailureEventReportingCauseCodec binds the complete source value type.
func FailureEventReportingCauseCodec() s00.FailureEventReportingCauseValueCodec {
	return func() s00.FailureEventReportingCauseValueCodec {
		sealed := s00.FailureEventReportingCauseValueCodec{}
		*s00.BridgeFailureEventReportingCauseValueCodecFieldPath(&sealed) = "FailureEventReportingCause"
		*s00.BridgeFailureEventReportingCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.FailureEventReportingCause, error) {
			var zero s00.FailureEventReportingCause
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.FailureEventReportingCause, error) {
				var v struct {
					Value s00.FailureEventReportingCause
				}
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.FailureEventReportingCause(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "FailureEventReportingCause"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeFailureEventReportingCauseValueCodecFieldEncode(&sealed) = func(value s00.FailureEventReportingCause, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.FailureEventReportingCause, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.FailureEventReportingCause
				}{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 3, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeFailureEventReportingCauseValueCodecFieldCapture(&sealed) = func(v s00.FailureEventReportingCause, options aper.DecodeState) (s00.FailureEventReportingCause, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APFailureEventReportingCause(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s00.BridgeFailureEventReportingCauseValueCodecFieldCompare(&sealed) = func(v s00.FailureEventReportingCause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APFailureEventReportingCause(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeFailureEventReportingCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:FailureEventReportingCause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// FiveGSTACCodec binds the complete source value type.
func FiveGSTACCodec() s00.FiveGSTACValueCodec {
	return func() s00.FiveGSTACValueCodec {
		sealed := s00.FiveGSTACValueCodec{}
		*s00.BridgeFiveGSTACValueCodecFieldPath(&sealed) = "FiveGSTAC"
		*s00.BridgeFiveGSTACValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.FiveGSTAC, error) {
			var zero s00.FiveGSTAC
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.FiveGSTAC, error) {
				var v struct{ Value s00.FiveGSTAC }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.FiveGSTAC(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "FiveGSTAC"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeFiveGSTACValueCodecFieldEncode(&sealed) = func(value s00.FiveGSTAC, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.FiveGSTAC, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.FiveGSTAC }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 3, 3, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeFiveGSTACValueCodecFieldCapture(&sealed) = func(v s00.FiveGSTAC, options aper.DecodeState) (s00.FiveGSTAC, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APFiveGSTAC(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeFiveGSTACValueCodecFieldCompare(&sealed) = func(v s00.FiveGSTAC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APFiveGSTAC(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeFiveGSTACValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:FiveGSTAC"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// FiveQICodec binds the complete source value type.
func FiveQICodec() s00.FiveQIValueCodec {
	return func() s00.FiveQIValueCodec {
		sealed := s00.FiveQIValueCodec{}
		*s00.BridgeFiveQIValueCodecFieldPath(&sealed) = "FiveQI"
		*s00.BridgeFiveQIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.FiveQI, error) {
			var zero s00.FiveQI
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.FiveQI, error) {
				var v struct{ Value s00.FiveQI }
				err := func() error {
					val_value, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound7, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = val_value
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "FiveQI"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeFiveQIValueCodecFieldEncode(&sealed) = func(value s00.FiveQI, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.FiveQI, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.FiveQI }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerBigBoundsAligned(bb, v.Value, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound7, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeFiveQIValueCodecFieldCapture(&sealed) = func(v s00.FiveQI, options aper.DecodeState) (s00.FiveQI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APFiveQI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeFiveQIValueCodecFieldCompare(&sealed) = func(v s00.FiveQI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APFiveQI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeFiveQIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:FiveQI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ForbiddenInterRATsCodec binds the complete source value type.
func ForbiddenInterRATsCodec() s00.ForbiddenInterRATsValueCodec {
	return func() s00.ForbiddenInterRATsValueCodec {
		sealed := s00.ForbiddenInterRATsValueCodec{}
		*s00.BridgeForbiddenInterRATsValueCodecFieldPath(&sealed) = "ForbiddenInterRATs"
		*s00.BridgeForbiddenInterRATsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ForbiddenInterRATs, error) {
			var zero s00.ForbiddenInterRATs
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.ForbiddenInterRATs, error) {
				var v struct{ Value s00.ForbiddenInterRATs }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 2, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.ForbiddenInterRATs(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ForbiddenInterRATs"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeForbiddenInterRATsValueCodecFieldEncode(&sealed) = func(value s00.ForbiddenInterRATs, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ForbiddenInterRATs, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ForbiddenInterRATs }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 4, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeForbiddenInterRATsValueCodecFieldCapture(&sealed) = func(v s00.ForbiddenInterRATs, options aper.DecodeState) (s00.ForbiddenInterRATs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APForbiddenInterRATs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s00.BridgeForbiddenInterRATsValueCodecFieldCompare(&sealed) = func(v s00.ForbiddenInterRATs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APForbiddenInterRATs(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeForbiddenInterRATsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ForbiddenInterRATs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// GNBIDCodec binds the complete source value type.
func GNBIDCodec() s00.GNBIDValueCodec {
	return func() s00.GNBIDValueCodec {
		sealed := s00.GNBIDValueCodec{}
		*s00.BridgeGNBIDValueCodecFieldPath(&sealed) = "GNBID"
		*s00.BridgeGNBIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.GNBID, error) {
			var zero s00.GNBID
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.GNBID, error) {
				var v struct{ Value s00.GNBID }
				err := func() error {
					bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 22, 32, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "GNBID"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeGNBIDValueCodecFieldEncode(&sealed) = func(value s00.GNBID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.GNBID, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.GNBID }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 22, 32, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeGNBIDValueCodecFieldCapture(&sealed) = func(v s00.GNBID, options aper.DecodeState) (s00.GNBID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APGNBID(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s00.BridgeGNBIDValueCodecFieldCompare(&sealed) = func(v s00.GNBID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APGNBID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeGNBIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GNBID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// GTPTEIDCodec binds the complete source value type.
func GTPTEIDCodec() s00.GTPTEIDValueCodec {
	return func() s00.GTPTEIDValueCodec {
		sealed := s00.GTPTEIDValueCodec{}
		*s00.BridgeGTPTEIDValueCodecFieldPath(&sealed) = "GTPTEID"
		*s00.BridgeGTPTEIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.GTPTEID, error) {
			var zero s00.GTPTEID
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.GTPTEID, error) {
				var v struct{ Value s00.GTPTEID }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.GTPTEID(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "GTPTEID"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeGTPTEIDValueCodecFieldEncode(&sealed) = func(value s00.GTPTEID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.GTPTEID, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.GTPTEID }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 4, 4, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeGTPTEIDValueCodecFieldCapture(&sealed) = func(v s00.GTPTEID, options aper.DecodeState) (s00.GTPTEID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APGTPTEID(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s00.BridgeGTPTEIDValueCodecFieldCompare(&sealed) = func(v s00.GTPTEID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APGTPTEID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeGTPTEIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GTPTEID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HOReportingCauseCodec binds the complete source value type.
func HOReportingCauseCodec() s00.HOReportingCauseValueCodec {
	return func() s00.HOReportingCauseValueCodec {
		sealed := s00.HOReportingCauseValueCodec{}
		*s00.BridgeHOReportingCauseValueCodecFieldPath(&sealed) = "HOReportingCause"
		*s00.BridgeHOReportingCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.HOReportingCause, error) {
			var zero s00.HOReportingCause
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.HOReportingCause, error) {
				var v struct{ Value s00.HOReportingCause }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.HOReportingCause(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "HOReportingCause"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeHOReportingCauseValueCodecFieldEncode(&sealed) = func(value s00.HOReportingCause, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.HOReportingCause, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.HOReportingCause }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 3, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeHOReportingCauseValueCodecFieldCapture(&sealed) = func(v s00.HOReportingCause, options aper.DecodeState) (s00.HOReportingCause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APHOReportingCause(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeHOReportingCauseValueCodecFieldCompare(&sealed) = func(v s00.HOReportingCause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APHOReportingCause(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeHOReportingCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HOReportingCause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HoReportTypeCodec binds the complete source value type.
func HoReportTypeCodec() s00.HoReportTypeValueCodec {
	return func() s00.HoReportTypeValueCodec {
		sealed := s00.HoReportTypeValueCodec{}
		*s00.BridgeHoReportTypeValueCodecFieldPath(&sealed) = "HoReportType"
		*s00.BridgeHoReportTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.HoReportType, error) {
			var zero s00.HoReportType
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.HoReportType, error) {
				var v struct{ Value s00.HoReportType }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 1, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.HoReportType(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "HoReportType"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeHoReportTypeValueCodecFieldEncode(&sealed) = func(value s00.HoReportType, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.HoReportType, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.HoReportType }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 1, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeHoReportTypeValueCodecFieldCapture(&sealed) = func(v s00.HoReportType, options aper.DecodeState) (s00.HoReportType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APHoReportType(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeHoReportTypeValueCodecFieldCompare(&sealed) = func(v s00.HoReportType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APHoReportType(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s00.BridgeHoReportTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HoReportType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HoTypeCodec binds the complete source value type.
func HoTypeCodec() s00.HoTypeValueCodec {
	return func() s00.HoTypeValueCodec {
		sealed := s00.HoTypeValueCodec{}
		*s00.BridgeHoTypeValueCodecFieldPath(&sealed) = "HoType"
		*s00.BridgeHoTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.HoType, error) {
			var zero s00.HoType
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.HoType, error) {
				var v struct{ Value s00.HoType }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.HoType(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "HoType"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s00.BridgeHoTypeValueCodecFieldEncode(&sealed) = func(value s00.HoType, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.HoType, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.HoType }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 2, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s00.BridgeHoTypeValueCodecFieldCapture(&sealed) = func(v s00.HoType, options aper.DecodeState) (s00.HoType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APHoType(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeHoTypeValueCodecFieldCompare(&sealed) = func(v s00.HoType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APHoType(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeHoTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HoType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// IMSICodec binds the complete source value type.
func IMSICodec() s01.IMSIValueCodec {
	return func() s01.IMSIValueCodec {
		sealed := s01.IMSIValueCodec{}
		*s01.BridgeIMSIValueCodecFieldPath(&sealed) = "IMSI"
		*s01.BridgeIMSIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.IMSI, error) {
			var zero s00.IMSI
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.IMSI, error) {
				var v struct{ Value s00.IMSI }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 3, 8, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.IMSI(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "IMSI"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeIMSIValueCodecFieldEncode(&sealed) = func(value s00.IMSI, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.IMSI, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.IMSI }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 3, 8, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeIMSIValueCodecFieldCapture(&sealed) = func(v s00.IMSI, options aper.DecodeState) (s00.IMSI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APIMSI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s01.BridgeIMSIValueCodecFieldCompare(&sealed) = func(v s00.IMSI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APIMSI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeIMSIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:IMSI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// IntegrityProtectionAlgorithmsCodec binds the complete source value type.
func IntegrityProtectionAlgorithmsCodec() s01.IntegrityProtectionAlgorithmsValueCodec {
	return func() s01.IntegrityProtectionAlgorithmsValueCodec {
		sealed := s01.IntegrityProtectionAlgorithmsValueCodec{}
		*s01.BridgeIntegrityProtectionAlgorithmsValueCodecFieldPath(&sealed) = "IntegrityProtectionAlgorithms"
		*s01.BridgeIntegrityProtectionAlgorithmsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.IntegrityProtectionAlgorithms, error) {
			var zero s00.IntegrityProtectionAlgorithms
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.IntegrityProtectionAlgorithms, error) {
				var v struct {
					Value s00.IntegrityProtectionAlgorithms
				}
				err := func() error {
					bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAlignedExt(bb, 16, 16, true, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "IntegrityProtectionAlgorithms"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeIntegrityProtectionAlgorithmsValueCodecFieldEncode(&sealed) = func(value s00.IntegrityProtectionAlgorithms, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.IntegrityProtectionAlgorithms, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.IntegrityProtectionAlgorithms
				}{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeBitStringAlignedExt(bb, v.Value.Bytes, v.Value.BitLength, 16, 16, true, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeIntegrityProtectionAlgorithmsValueCodecFieldCapture(&sealed) = func(v s00.IntegrityProtectionAlgorithms, options aper.DecodeState) (s00.IntegrityProtectionAlgorithms, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APIntegrityProtectionAlgorithms(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeIntegrityProtectionAlgorithmsValueCodecFieldCompare(&sealed) = func(v s00.IntegrityProtectionAlgorithms, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCompareS1APIntegrityProtectionAlgorithms(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeIntegrityProtectionAlgorithmsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:IntegrityProtectionAlgorithms"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// IntegrityProtectionIndicationCodec binds the complete source value type.
func IntegrityProtectionIndicationCodec() s01.IntegrityProtectionIndicationValueCodec {
	return func() s01.IntegrityProtectionIndicationValueCodec {
		sealed := s01.IntegrityProtectionIndicationValueCodec{}
		*s01.BridgeIntegrityProtectionIndicationValueCodecFieldPath(&sealed) = "IntegrityProtectionIndication"
		*s01.BridgeIntegrityProtectionIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.IntegrityProtectionIndication, error) {
			var zero s00.IntegrityProtectionIndication
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.IntegrityProtectionIndication, error) {
				var v struct {
					Value s00.IntegrityProtectionIndication
				}
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.IntegrityProtectionIndication(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "IntegrityProtectionIndication"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeIntegrityProtectionIndicationValueCodecFieldEncode(&sealed) = func(value s00.IntegrityProtectionIndication, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.IntegrityProtectionIndication, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.IntegrityProtectionIndication
				}{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 3, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeIntegrityProtectionIndicationValueCodecFieldCapture(&sealed) = func(v s00.IntegrityProtectionIndication, options aper.DecodeState) (s00.IntegrityProtectionIndication, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APIntegrityProtectionIndication(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeIntegrityProtectionIndicationValueCodecFieldCompare(&sealed) = func(v s00.IntegrityProtectionIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCompareS1APIntegrityProtectionIndication(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeIntegrityProtectionIndicationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:IntegrityProtectionIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// IntegrityProtectionResultCodec binds the complete source value type.
func IntegrityProtectionResultCodec() s01.IntegrityProtectionResultValueCodec {
	return func() s01.IntegrityProtectionResultValueCodec {
		sealed := s01.IntegrityProtectionResultValueCodec{}
		*s01.BridgeIntegrityProtectionResultValueCodecFieldPath(&sealed) = "IntegrityProtectionResult"
		*s01.BridgeIntegrityProtectionResultValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.IntegrityProtectionResult, error) {
			var zero s00.IntegrityProtectionResult
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.IntegrityProtectionResult, error) {
				var v struct{ Value s00.IntegrityProtectionResult }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.IntegrityProtectionResult(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "IntegrityProtectionResult"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeIntegrityProtectionResultValueCodecFieldEncode(&sealed) = func(value s00.IntegrityProtectionResult, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.IntegrityProtectionResult, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.IntegrityProtectionResult }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 2, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeIntegrityProtectionResultValueCodecFieldCapture(&sealed) = func(v s00.IntegrityProtectionResult, options aper.DecodeState) (s00.IntegrityProtectionResult, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APIntegrityProtectionResult(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s01.BridgeIntegrityProtectionResultValueCodecFieldCompare(&sealed) = func(v s00.IntegrityProtectionResult, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APIntegrityProtectionResult(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeIntegrityProtectionResultValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:IntegrityProtectionResult"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// IntendedNumberOfPagingAttemptsCodec binds the complete source value type.
func IntendedNumberOfPagingAttemptsCodec() s01.IntendedNumberOfPagingAttemptsValueCodec {
	return func() s01.IntendedNumberOfPagingAttemptsValueCodec {
		sealed := s01.IntendedNumberOfPagingAttemptsValueCodec{}
		*s01.BridgeIntendedNumberOfPagingAttemptsValueCodecFieldPath(&sealed) = "IntendedNumberOfPagingAttempts"
		*s01.BridgeIntendedNumberOfPagingAttemptsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.IntendedNumberOfPagingAttempts, error) {
			var zero s00.IntendedNumberOfPagingAttempts
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.IntendedNumberOfPagingAttempts, error) {
				var v struct {
					Value s00.IntendedNumberOfPagingAttempts
				}
				err := func() error {
					val_value, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound6, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = val_value
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "IntendedNumberOfPagingAttempts"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeIntendedNumberOfPagingAttemptsValueCodecFieldEncode(&sealed) = func(value s00.IntendedNumberOfPagingAttempts, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.IntendedNumberOfPagingAttempts, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.IntendedNumberOfPagingAttempts
				}{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerBigBoundsAligned(bb, v.Value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound6, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeIntendedNumberOfPagingAttemptsValueCodecFieldCapture(&sealed) = func(v s00.IntendedNumberOfPagingAttempts, options aper.DecodeState) (s00.IntendedNumberOfPagingAttempts, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APIntendedNumberOfPagingAttempts(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeIntendedNumberOfPagingAttemptsValueCodecFieldCompare(&sealed) = func(v s00.IntendedNumberOfPagingAttempts, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeCompareS1APIntendedNumberOfPagingAttempts(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeIntendedNumberOfPagingAttemptsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:IntendedNumberOfPagingAttempts"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// InterfacesToTraceCodec binds the complete source value type.
func InterfacesToTraceCodec() s01.InterfacesToTraceValueCodec {
	return func() s01.InterfacesToTraceValueCodec {
		sealed := s01.InterfacesToTraceValueCodec{}
		*s01.BridgeInterfacesToTraceValueCodecFieldPath(&sealed) = "InterfacesToTrace"
		*s01.BridgeInterfacesToTraceValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.InterfacesToTrace, error) {
			var zero s00.InterfacesToTrace
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.InterfacesToTrace, error) {
				var v struct{ Value s00.InterfacesToTrace }
				err := func() error {
					bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 8, 8, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "InterfacesToTrace"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeInterfacesToTraceValueCodecFieldEncode(&sealed) = func(value s00.InterfacesToTrace, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.InterfacesToTrace, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.InterfacesToTrace }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 8, 8, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeInterfacesToTraceValueCodecFieldCapture(&sealed) = func(v s00.InterfacesToTrace, options aper.DecodeState) (s00.InterfacesToTrace, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APInterfacesToTrace(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s01.BridgeInterfacesToTraceValueCodecFieldCompare(&sealed) = func(v s00.InterfacesToTrace, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APInterfacesToTrace(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgeInterfacesToTraceValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InterfacesToTrace"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// L3InformationCodec binds the complete source value type.
func L3InformationCodec() s01.L3InformationValueCodec {
	return func() s01.L3InformationValueCodec {
		sealed := s01.L3InformationValueCodec{}
		*s01.BridgeL3InformationValueCodecFieldPath(&sealed) = "L3Information"
		*s01.BridgeL3InformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.L3Information, error) {
			var zero s00.L3Information
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.L3Information, error) {
				var v struct{ Value s00.L3Information }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.L3Information(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "L3Information"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeL3InformationValueCodecFieldEncode(&sealed) = func(value s00.L3Information, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.L3Information, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.L3Information }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 0, 0, false); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeL3InformationValueCodecFieldCapture(&sealed) = func(v s00.L3Information, options aper.DecodeState) (s00.L3Information, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APL3Information(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeL3InformationValueCodecFieldCompare(&sealed) = func(v s00.L3Information, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APL3Information(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s01.BridgeL3InformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:L3Information"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// LACCodec binds the complete source value type.
func LACCodec() s01.LACValueCodec {
	return func() s01.LACValueCodec {
		sealed := s01.LACValueCodec{}
		*s01.BridgeLACValueCodecFieldPath(&sealed) = "LAC"
		*s01.BridgeLACValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.LAC, error) {
			var zero s00.LAC
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.LAC, error) {
				var v struct{ Value s00.LAC }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.LAC(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "LAC"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeLACValueCodecFieldEncode(&sealed) = func(value s00.LAC, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.LAC, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.LAC }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 2, 2, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeLACValueCodecFieldCapture(&sealed) = func(v s00.LAC, options aper.DecodeState) (s00.LAC, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APLAC(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s01.BridgeLACValueCodecFieldCompare(&sealed) = func(v s00.LAC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APLAC(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeLACValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LAC"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// LastVisitedNGRANCellInformationCodec binds the complete source value type.
func LastVisitedNGRANCellInformationCodec() s01.LastVisitedNGRANCellInformationValueCodec {
	return func() s01.LastVisitedNGRANCellInformationValueCodec {
		sealed := s01.LastVisitedNGRANCellInformationValueCodec{}
		*s01.BridgeLastVisitedNGRANCellInformationValueCodecFieldPath(&sealed) = "LastVisitedNGRANCellInformation"
		*s01.BridgeLastVisitedNGRANCellInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.LastVisitedNGRANCellInformation, error) {
			var zero s00.LastVisitedNGRANCellInformation
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.LastVisitedNGRANCellInformation, error) {
				var v struct {
					Value s00.LastVisitedNGRANCellInformation
				}
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.LastVisitedNGRANCellInformation(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "LastVisitedNGRANCellInformation"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeLastVisitedNGRANCellInformationValueCodecFieldEncode(&sealed) = func(value s00.LastVisitedNGRANCellInformation, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.LastVisitedNGRANCellInformation, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.LastVisitedNGRANCellInformation
				}{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 0, 0, false); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeLastVisitedNGRANCellInformationValueCodecFieldCapture(&sealed) = func(v s00.LastVisitedNGRANCellInformation, options aper.DecodeState) (s00.LastVisitedNGRANCellInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APLastVisitedNGRANCellInformation(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeLastVisitedNGRANCellInformationValueCodecFieldCompare(&sealed) = func(v s00.LastVisitedNGRANCellInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APLastVisitedNGRANCellInformation(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeLastVisitedNGRANCellInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LastVisitedNGRANCellInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// LastVisitedUTRANCellInformationCodec binds the complete source value type.
func LastVisitedUTRANCellInformationCodec() s01.LastVisitedUTRANCellInformationValueCodec {
	return func() s01.LastVisitedUTRANCellInformationValueCodec {
		sealed := s01.LastVisitedUTRANCellInformationValueCodec{}
		*s01.BridgeLastVisitedUTRANCellInformationValueCodecFieldPath(&sealed) = "LastVisitedUTRANCellInformation"
		*s01.BridgeLastVisitedUTRANCellInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.LastVisitedUTRANCellInformation, error) {
			var zero s00.LastVisitedUTRANCellInformation
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.LastVisitedUTRANCellInformation, error) {
				var v struct {
					Value s00.LastVisitedUTRANCellInformation
				}
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.LastVisitedUTRANCellInformation(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "LastVisitedUTRANCellInformation"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeLastVisitedUTRANCellInformationValueCodecFieldEncode(&sealed) = func(value s00.LastVisitedUTRANCellInformation, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.LastVisitedUTRANCellInformation, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.LastVisitedUTRANCellInformation
				}{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 0, 0, false); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeLastVisitedUTRANCellInformationValueCodecFieldCapture(&sealed) = func(v s00.LastVisitedUTRANCellInformation, options aper.DecodeState) (s00.LastVisitedUTRANCellInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APLastVisitedUTRANCellInformation(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeLastVisitedUTRANCellInformationValueCodecFieldCompare(&sealed) = func(v s00.LastVisitedUTRANCellInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APLastVisitedUTRANCellInformation(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeLastVisitedUTRANCellInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LastVisitedUTRANCellInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// LinksToLogCodec binds the complete source value type.
func LinksToLogCodec() s01.LinksToLogValueCodec {
	return func() s01.LinksToLogValueCodec {
		sealed := s01.LinksToLogValueCodec{}
		*s01.BridgeLinksToLogValueCodecFieldPath(&sealed) = "LinksToLog"
		*s01.BridgeLinksToLogValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.LinksToLog, error) {
			var zero s00.LinksToLog
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.LinksToLog, error) {
				var v struct{ Value s00.LinksToLog }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.LinksToLog(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "LinksToLog"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeLinksToLogValueCodecFieldEncode(&sealed) = func(value s00.LinksToLog, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.LinksToLog, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.LinksToLog }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 3, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeLinksToLogValueCodecFieldCapture(&sealed) = func(v s00.LinksToLog, options aper.DecodeState) (s00.LinksToLog, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APLinksToLog(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeLinksToLogValueCodecFieldCompare(&sealed) = func(v s00.LinksToLog, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APLinksToLog(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeLinksToLogValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LinksToLog"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// LoggingDurationCodec binds the complete source value type.
func LoggingDurationCodec() s01.LoggingDurationValueCodec {
	return func() s01.LoggingDurationValueCodec {
		sealed := s01.LoggingDurationValueCodec{}
		*s01.BridgeLoggingDurationValueCodecFieldPath(&sealed) = "LoggingDuration"
		*s01.BridgeLoggingDurationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.LoggingDuration, error) {
			var zero s00.LoggingDuration
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.LoggingDuration, error) {
				var v struct{ Value s00.LoggingDuration }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 6, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.LoggingDuration(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "LoggingDuration"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeLoggingDurationValueCodecFieldEncode(&sealed) = func(value s00.LoggingDuration, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.LoggingDuration, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.LoggingDuration }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 6, false); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeLoggingDurationValueCodecFieldCapture(&sealed) = func(v s00.LoggingDuration, options aper.DecodeState) (s00.LoggingDuration, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APLoggingDuration(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeLoggingDurationValueCodecFieldCompare(&sealed) = func(v s00.LoggingDuration, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APLoggingDuration(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgeLoggingDurationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LoggingDuration"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// LoggingIntervalCodec binds the complete source value type.
func LoggingIntervalCodec() s01.LoggingIntervalValueCodec {
	return func() s01.LoggingIntervalValueCodec {
		sealed := s01.LoggingIntervalValueCodec{}
		*s01.BridgeLoggingIntervalValueCodecFieldPath(&sealed) = "LoggingInterval"
		*s01.BridgeLoggingIntervalValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.LoggingInterval, error) {
			var zero s00.LoggingInterval
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.LoggingInterval, error) {
				var v struct{ Value s00.LoggingInterval }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 8, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.LoggingInterval(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "LoggingInterval"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeLoggingIntervalValueCodecFieldEncode(&sealed) = func(value s00.LoggingInterval, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.LoggingInterval, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.LoggingInterval }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 8, false); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeLoggingIntervalValueCodecFieldCapture(&sealed) = func(v s00.LoggingInterval, options aper.DecodeState) (s00.LoggingInterval, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APLoggingInterval(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeLoggingIntervalValueCodecFieldCompare(&sealed) = func(v s00.LoggingInterval, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APLoggingInterval(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgeLoggingIntervalValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LoggingInterval"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// M1ReportingTriggerCodec binds the complete source value type.
func M1ReportingTriggerCodec() s01.M1ReportingTriggerValueCodec {
	return func() s01.M1ReportingTriggerValueCodec {
		sealed := s01.M1ReportingTriggerValueCodec{}
		*s01.BridgeM1ReportingTriggerValueCodecFieldPath(&sealed) = "M1ReportingTrigger"
		*s01.BridgeM1ReportingTriggerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.M1ReportingTrigger, error) {
			var zero s00.M1ReportingTrigger
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.M1ReportingTrigger, error) {
				var v struct{ Value s00.M1ReportingTrigger }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 1, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.M1ReportingTrigger(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "M1ReportingTrigger"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeM1ReportingTriggerValueCodecFieldEncode(&sealed) = func(value s00.M1ReportingTrigger, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.M1ReportingTrigger, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.M1ReportingTrigger }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 2, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeM1ReportingTriggerValueCodecFieldCapture(&sealed) = func(v s00.M1ReportingTrigger, options aper.DecodeState) (s00.M1ReportingTrigger, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APM1ReportingTrigger(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s01.BridgeM1ReportingTriggerValueCodecFieldCompare(&sealed) = func(v s00.M1ReportingTrigger, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APM1ReportingTrigger(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeM1ReportingTriggerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:M1ReportingTrigger"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// M3periodCodec binds the complete source value type.
func M3periodCodec() s01.M3periodValueCodec {
	return func() s01.M3periodValueCodec {
		sealed := s01.M3periodValueCodec{}
		*s01.BridgeM3periodValueCodecFieldPath(&sealed) = "M3period"
		*s01.BridgeM3periodValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.M3period, error) {
			var zero s00.M3period
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.M3period, error) {
				var v struct{ Value s00.M3period }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 7, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.M3period(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "M3period"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeM3periodValueCodecFieldEncode(&sealed) = func(value s00.M3period, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.M3period, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.M3period }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 3, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeM3periodValueCodecFieldCapture(&sealed) = func(v s00.M3period, options aper.DecodeState) (s00.M3period, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APM3period(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeM3periodValueCodecFieldCompare(&sealed) = func(v s00.M3period, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APM3period(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeM3periodValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:M3period"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// M4periodCodec binds the complete source value type.
func M4periodCodec() s01.M4periodValueCodec {
	return func() s01.M4periodValueCodec {
		sealed := s01.M4periodValueCodec{}
		*s01.BridgeM4periodValueCodecFieldPath(&sealed) = "M4period"
		*s01.BridgeM4periodValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.M4period, error) {
			var zero s00.M4period
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.M4period, error) {
				var v struct{ Value s00.M4period }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 5, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.M4period(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "M4period"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeM4periodValueCodecFieldEncode(&sealed) = func(value s00.M4period, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.M4period, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.M4period }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 5, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeM4periodValueCodecFieldCapture(&sealed) = func(v s00.M4period, options aper.DecodeState) (s00.M4period, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APM4period(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeM4periodValueCodecFieldCompare(&sealed) = func(v s00.M4period, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APM4period(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeM4periodValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:M4period"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// M5periodCodec binds the complete source value type.
func M5periodCodec() s01.M5periodValueCodec {
	return func() s01.M5periodValueCodec {
		sealed := s01.M5periodValueCodec{}
		*s01.BridgeM5periodValueCodecFieldPath(&sealed) = "M5period"
		*s01.BridgeM5periodValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.M5period, error) {
			var zero s00.M5period
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.M5period, error) {
				var v struct{ Value s00.M5period }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 5, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.M5period(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "M5period"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeM5periodValueCodecFieldEncode(&sealed) = func(value s00.M5period, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.M5period, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.M5period }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 5, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeM5periodValueCodecFieldCapture(&sealed) = func(v s00.M5period, options aper.DecodeState) (s00.M5period, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APM5period(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeM5periodValueCodecFieldCompare(&sealed) = func(v s00.M5period, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APM5period(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeM5periodValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:M5period"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// M6delayThresholdCodec binds the complete source value type.
func M6delayThresholdCodec() s01.M6delayThresholdValueCodec {
	return func() s01.M6delayThresholdValueCodec {
		sealed := s01.M6delayThresholdValueCodec{}
		*s01.BridgeM6delayThresholdValueCodecFieldPath(&sealed) = "M6delayThreshold"
		*s01.BridgeM6delayThresholdValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.M6delayThreshold, error) {
			var zero s00.M6delayThreshold
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.M6delayThreshold, error) {
				var v struct{ Value s00.M6delayThreshold }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 12, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.M6delayThreshold(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "M6delayThreshold"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeM6delayThresholdValueCodecFieldEncode(&sealed) = func(value s00.M6delayThreshold, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.M6delayThreshold, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.M6delayThreshold }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 12, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeM6delayThresholdValueCodecFieldCapture(&sealed) = func(v s00.M6delayThreshold, options aper.DecodeState) (s00.M6delayThreshold, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APM6delayThreshold(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeM6delayThresholdValueCodecFieldCompare(&sealed) = func(v s00.M6delayThreshold, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APM6delayThreshold(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgeM6delayThresholdValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:M6delayThreshold"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// M6reportIntervalCodec binds the complete source value type.
func M6reportIntervalCodec() s01.M6reportIntervalValueCodec {
	return func() s01.M6reportIntervalValueCodec {
		sealed := s01.M6reportIntervalValueCodec{}
		*s01.BridgeM6reportIntervalValueCodecFieldPath(&sealed) = "M6reportInterval"
		*s01.BridgeM6reportIntervalValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.M6reportInterval, error) {
			var zero s00.M6reportInterval
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.M6reportInterval, error) {
				var v struct{ Value s00.M6reportInterval }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.M6reportInterval(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "M6reportInterval"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeM6reportIntervalValueCodecFieldEncode(&sealed) = func(value s00.M6reportInterval, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.M6reportInterval, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.M6reportInterval }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 4, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeM6reportIntervalValueCodecFieldCapture(&sealed) = func(v s00.M6reportInterval, options aper.DecodeState) (s00.M6reportInterval, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APM6reportInterval(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeM6reportIntervalValueCodecFieldCompare(&sealed) = func(v s00.M6reportInterval, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APM6reportInterval(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgeM6reportIntervalValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:M6reportInterval"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// M7periodCodec binds the complete source value type.
func M7periodCodec() s01.M7periodValueCodec {
	return func() s01.M7periodValueCodec {
		sealed := s01.M7periodValueCodec{}
		*s01.BridgeM7periodValueCodecFieldPath(&sealed) = "M7period"
		*s01.BridgeM7periodValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.M7period, error) {
			var zero s00.M7period
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.M7period, error) {
				var v struct{ Value s00.M7period }
				err := func() error {
					val_value, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound13, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = val_value
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "M7period"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeM7periodValueCodecFieldEncode(&sealed) = func(value s00.M7period, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.M7period, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.M7period }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerBigBoundsAligned(bb, v.Value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound13, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeM7periodValueCodecFieldCapture(&sealed) = func(v s00.M7period, options aper.DecodeState) (s00.M7period, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APM7period(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeM7periodValueCodecFieldCompare(&sealed) = func(v s00.M7period, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APM7period(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeM7periodValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:M7period"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MDTActivationCodec binds the complete source value type.
func MDTActivationCodec() s01.MDTActivationValueCodec {
	return func() s01.MDTActivationValueCodec {
		sealed := s01.MDTActivationValueCodec{}
		*s01.BridgeMDTActivationValueCodecFieldPath(&sealed) = "MDTActivation"
		*s01.BridgeMDTActivationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MDTActivation, error) {
			var zero s00.MDTActivation
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.MDTActivation, error) {
				var v struct{ Value s00.MDTActivation }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 1, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.MDTActivation(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "MDTActivation"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeMDTActivationValueCodecFieldEncode(&sealed) = func(value s00.MDTActivation, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.MDTActivation, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.MDTActivation }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 3, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeMDTActivationValueCodecFieldCapture(&sealed) = func(v s00.MDTActivation, options aper.DecodeState) (s00.MDTActivation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APMDTActivation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeMDTActivationValueCodecFieldCompare(&sealed) = func(v s00.MDTActivation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APMDTActivation(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s01.BridgeMDTActivationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MDTActivation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MMECodeCodec binds the complete source value type.
func MMECodeCodec() s01.MMECodeValueCodec {
	return func() s01.MMECodeValueCodec {
		sealed := s01.MMECodeValueCodec{}
		*s01.BridgeMMECodeValueCodecFieldPath(&sealed) = "MMECode"
		*s01.BridgeMMECodeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMECode, error) {
			var zero s00.MMECode
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.MMECode, error) {
				var v struct{ Value s00.MMECode }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 1, 1, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.MMECode(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "MMECode"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeMMECodeValueCodecFieldEncode(&sealed) = func(value s00.MMECode, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.MMECode, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.MMECode }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 1, 1, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeMMECodeValueCodecFieldCapture(&sealed) = func(v s00.MMECode, options aper.DecodeState) (s00.MMECode, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APMMECode(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s01.BridgeMMECodeValueCodecFieldCompare(&sealed) = func(v s00.MMECode, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APMMECode(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeMMECodeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMECode"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MTMSICodec binds the complete source value type.
func MTMSICodec() s01.MTMSIValueCodec {
	return func() s01.MTMSIValueCodec {
		sealed := s01.MTMSIValueCodec{}
		*s01.BridgeMTMSIValueCodecFieldPath(&sealed) = "MTMSI"
		*s01.BridgeMTMSIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MTMSI, error) {
			var zero s00.MTMSI
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.MTMSI, error) {
				var v struct{ Value s00.MTMSI }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 4, 4, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.MTMSI(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "MTMSI"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeMTMSIValueCodecFieldEncode(&sealed) = func(value s00.MTMSI, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.MTMSI, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.MTMSI }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 4, 4, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeMTMSIValueCodecFieldCapture(&sealed) = func(v s00.MTMSI, options aper.DecodeState) (s00.MTMSI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APMTMSI(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s01.BridgeMTMSIValueCodecFieldCompare(&sealed) = func(v s00.MTMSI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APMTMSI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeMTMSIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MTMSI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// MeasurementsToActivateCodec binds the complete source value type.
func MeasurementsToActivateCodec() s01.MeasurementsToActivateValueCodec {
	return func() s01.MeasurementsToActivateValueCodec {
		sealed := s01.MeasurementsToActivateValueCodec{}
		*s01.BridgeMeasurementsToActivateValueCodecFieldPath(&sealed) = "MeasurementsToActivate"
		*s01.BridgeMeasurementsToActivateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MeasurementsToActivate, error) {
			var zero s00.MeasurementsToActivate
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.MeasurementsToActivate, error) {
				var v struct{ Value s00.MeasurementsToActivate }
				err := func() error {
					bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 8, 8, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "MeasurementsToActivate"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeMeasurementsToActivateValueCodecFieldEncode(&sealed) = func(value s00.MeasurementsToActivate, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.MeasurementsToActivate, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.MeasurementsToActivate }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 8, 8, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeMeasurementsToActivateValueCodecFieldCapture(&sealed) = func(v s00.MeasurementsToActivate, options aper.DecodeState) (s00.MeasurementsToActivate, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APMeasurementsToActivate(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeMeasurementsToActivateValueCodecFieldCompare(&sealed) = func(v s00.MeasurementsToActivate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APMeasurementsToActivate(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeMeasurementsToActivateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementsToActivate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NBIoTPagingEDRXCycleCodec binds the complete source value type.
func NBIoTPagingEDRXCycleCodec() s01.NBIoTPagingEDRXCycleValueCodec {
	return func() s01.NBIoTPagingEDRXCycleValueCodec {
		sealed := s01.NBIoTPagingEDRXCycleValueCodec{}
		*s01.BridgeNBIoTPagingEDRXCycleValueCodecFieldPath(&sealed) = "NBIoTPagingEDRXCycle"
		*s01.BridgeNBIoTPagingEDRXCycleValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NBIoTPagingEDRXCycle, error) {
			var zero s00.NBIoTPagingEDRXCycle
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.NBIoTPagingEDRXCycle, error) {
				var v struct{ Value s00.NBIoTPagingEDRXCycle }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 14, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.NBIoTPagingEDRXCycle(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "NBIoTPagingEDRXCycle"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeNBIoTPagingEDRXCycleValueCodecFieldEncode(&sealed) = func(value s00.NBIoTPagingEDRXCycle, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.NBIoTPagingEDRXCycle, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.NBIoTPagingEDRXCycle }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 14, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeNBIoTPagingEDRXCycleValueCodecFieldCapture(&sealed) = func(v s00.NBIoTPagingEDRXCycle, options aper.DecodeState) (s00.NBIoTPagingEDRXCycle, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNBIoTPagingEDRXCycle(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeNBIoTPagingEDRXCycleValueCodecFieldCompare(&sealed) = func(v s00.NBIoTPagingEDRXCycle, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APNBIoTPagingEDRXCycle(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNBIoTPagingEDRXCycleValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NBIoTPagingEDRXCycle"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NBIoTPagingTimeWindowCodec binds the complete source value type.
func NBIoTPagingTimeWindowCodec() s01.NBIoTPagingTimeWindowValueCodec {
	return func() s01.NBIoTPagingTimeWindowValueCodec {
		sealed := s01.NBIoTPagingTimeWindowValueCodec{}
		*s01.BridgeNBIoTPagingTimeWindowValueCodecFieldPath(&sealed) = "NBIoTPagingTimeWindow"
		*s01.BridgeNBIoTPagingTimeWindowValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NBIoTPagingTimeWindow, error) {
			var zero s00.NBIoTPagingTimeWindow
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.NBIoTPagingTimeWindow, error) {
				var v struct{ Value s00.NBIoTPagingTimeWindow }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 16, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.NBIoTPagingTimeWindow(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "NBIoTPagingTimeWindow"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeNBIoTPagingTimeWindowValueCodecFieldEncode(&sealed) = func(value s00.NBIoTPagingTimeWindow, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.NBIoTPagingTimeWindow, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.NBIoTPagingTimeWindow }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 16, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeNBIoTPagingTimeWindowValueCodecFieldCapture(&sealed) = func(v s00.NBIoTPagingTimeWindow, options aper.DecodeState) (s00.NBIoTPagingTimeWindow, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNBIoTPagingTimeWindow(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s01.BridgeNBIoTPagingTimeWindowValueCodecFieldCompare(&sealed) = func(v s00.NBIoTPagingTimeWindow, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APNBIoTPagingTimeWindow(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNBIoTPagingTimeWindowValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NBIoTPagingTimeWindow"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NRCellIdentityCodec binds the complete source value type.
func NRCellIdentityCodec() s01.NRCellIdentityValueCodec {
	return func() s01.NRCellIdentityValueCodec {
		sealed := s01.NRCellIdentityValueCodec{}
		*s01.BridgeNRCellIdentityValueCodecFieldPath(&sealed) = "NRCellIdentity"
		*s01.BridgeNRCellIdentityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NRCellIdentity, error) {
			var zero s00.NRCellIdentity
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.NRCellIdentity, error) {
				var v struct{ Value s00.NRCellIdentity }
				err := func() error {
					bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 36, 36, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "NRCellIdentity"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeNRCellIdentityValueCodecFieldEncode(&sealed) = func(value s00.NRCellIdentity, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.NRCellIdentity, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.NRCellIdentity }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 36, 36, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeNRCellIdentityValueCodecFieldCapture(&sealed) = func(v s00.NRCellIdentity, options aper.DecodeState) (s00.NRCellIdentity, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNRCellIdentity(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeNRCellIdentityValueCodecFieldCompare(&sealed) = func(v s00.NRCellIdentity, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APNRCellIdentity(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNRCellIdentityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRCellIdentity"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NRencryptionAlgorithmsCodec binds the complete source value type.
func NRencryptionAlgorithmsCodec() s01.NRencryptionAlgorithmsValueCodec {
	return func() s01.NRencryptionAlgorithmsValueCodec {
		sealed := s01.NRencryptionAlgorithmsValueCodec{}
		*s01.BridgeNRencryptionAlgorithmsValueCodecFieldPath(&sealed) = "NRencryptionAlgorithms"
		*s01.BridgeNRencryptionAlgorithmsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NRencryptionAlgorithms, error) {
			var zero s00.NRencryptionAlgorithms
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.NRencryptionAlgorithms, error) {
				var v struct{ Value s00.NRencryptionAlgorithms }
				err := func() error {
					bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAlignedExt(bb, 16, 16, true, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "NRencryptionAlgorithms"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeNRencryptionAlgorithmsValueCodecFieldEncode(&sealed) = func(value s00.NRencryptionAlgorithms, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.NRencryptionAlgorithms, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.NRencryptionAlgorithms }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeBitStringAlignedExt(bb, v.Value.Bytes, v.Value.BitLength, 16, 16, true, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeNRencryptionAlgorithmsValueCodecFieldCapture(&sealed) = func(v s00.NRencryptionAlgorithms, options aper.DecodeState) (s00.NRencryptionAlgorithms, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNRencryptionAlgorithms(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeNRencryptionAlgorithmsValueCodecFieldCompare(&sealed) = func(v s00.NRencryptionAlgorithms, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APNRencryptionAlgorithms(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNRencryptionAlgorithmsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRencryptionAlgorithms"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NRintegrityProtectionAlgorithmsCodec binds the complete source value type.
func NRintegrityProtectionAlgorithmsCodec() s01.NRintegrityProtectionAlgorithmsValueCodec {
	return func() s01.NRintegrityProtectionAlgorithmsValueCodec {
		sealed := s01.NRintegrityProtectionAlgorithmsValueCodec{}
		*s01.BridgeNRintegrityProtectionAlgorithmsValueCodecFieldPath(&sealed) = "NRintegrityProtectionAlgorithms"
		*s01.BridgeNRintegrityProtectionAlgorithmsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NRintegrityProtectionAlgorithms, error) {
			var zero s00.NRintegrityProtectionAlgorithms
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.NRintegrityProtectionAlgorithms, error) {
				var v struct {
					Value s00.NRintegrityProtectionAlgorithms
				}
				err := func() error {
					bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAlignedExt(bb, 16, 16, true, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "NRintegrityProtectionAlgorithms"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeNRintegrityProtectionAlgorithmsValueCodecFieldEncode(&sealed) = func(value s00.NRintegrityProtectionAlgorithms, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.NRintegrityProtectionAlgorithms, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.NRintegrityProtectionAlgorithms
				}{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeBitStringAlignedExt(bb, v.Value.Bytes, v.Value.BitLength, 16, 16, true, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeNRintegrityProtectionAlgorithmsValueCodecFieldCapture(&sealed) = func(v s00.NRintegrityProtectionAlgorithms, options aper.DecodeState) (s00.NRintegrityProtectionAlgorithms, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNRintegrityProtectionAlgorithms(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeNRintegrityProtectionAlgorithmsValueCodecFieldCompare(&sealed) = func(v s00.NRintegrityProtectionAlgorithms, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APNRintegrityProtectionAlgorithms(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNRintegrityProtectionAlgorithmsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRintegrityProtectionAlgorithms"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NextPagingAreaScopeCodec binds the complete source value type.
func NextPagingAreaScopeCodec() s01.NextPagingAreaScopeValueCodec {
	return func() s01.NextPagingAreaScopeValueCodec {
		sealed := s01.NextPagingAreaScopeValueCodec{}
		*s01.BridgeNextPagingAreaScopeValueCodecFieldPath(&sealed) = "NextPagingAreaScope"
		*s01.BridgeNextPagingAreaScopeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NextPagingAreaScope, error) {
			var zero s00.NextPagingAreaScope
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.NextPagingAreaScope, error) {
				var v struct{ Value s00.NextPagingAreaScope }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.NextPagingAreaScope(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "NextPagingAreaScope"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeNextPagingAreaScopeValueCodecFieldEncode(&sealed) = func(value s00.NextPagingAreaScope, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.NextPagingAreaScope, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.NextPagingAreaScope }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 2, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeNextPagingAreaScopeValueCodecFieldCapture(&sealed) = func(v s00.NextPagingAreaScope, options aper.DecodeState) (s00.NextPagingAreaScope, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNextPagingAreaScope(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeNextPagingAreaScopeValueCodecFieldCompare(&sealed) = func(v s00.NextPagingAreaScope, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APNextPagingAreaScope(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNextPagingAreaScopeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NextPagingAreaScope"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NotifyFlagCodec binds the complete source value type.
func NotifyFlagCodec() s01.NotifyFlagValueCodec {
	return func() s01.NotifyFlagValueCodec {
		sealed := s01.NotifyFlagValueCodec{}
		*s01.BridgeNotifyFlagValueCodecFieldPath(&sealed) = "NotifyFlag"
		*s01.BridgeNotifyFlagValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NotifyFlag, error) {
			var zero s00.NotifyFlag
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.NotifyFlag, error) {
				var v struct{ Value s00.NotifyFlag }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.NotifyFlag(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "NotifyFlag"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeNotifyFlagValueCodecFieldEncode(&sealed) = func(value s00.NotifyFlag, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.NotifyFlag, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.NotifyFlag }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 2, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeNotifyFlagValueCodecFieldCapture(&sealed) = func(v s00.NotifyFlag, options aper.DecodeState) (s00.NotifyFlag, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APNotifyFlag(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeNotifyFlagValueCodecFieldCompare(&sealed) = func(v s00.NotifyFlag, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APNotifyFlag(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNotifyFlagValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NotifyFlag"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// NumberOfMeasurementReportingLevelsCodec binds the complete source value type.
func NumberOfMeasurementReportingLevelsCodec() s01.NumberOfMeasurementReportingLevelsValueCodec {
	return func() s01.NumberOfMeasurementReportingLevelsValueCodec {
		sealed := s01.NumberOfMeasurementReportingLevelsValueCodec{}
		*s01.BridgeNumberOfMeasurementReportingLevelsValueCodecFieldPath(&sealed) = "NumberOfMeasurementReportingLevels"
		*s01.BridgeNumberOfMeasurementReportingLevelsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NumberOfMeasurementReportingLevels, error) {
			var zero s00.NumberOfMeasurementReportingLevels
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.NumberOfMeasurementReportingLevels, error) {
				var v struct {
					Value s00.NumberOfMeasurementReportingLevels
				}
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 5, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.NumberOfMeasurementReportingLevels(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "NumberOfMeasurementReportingLevels"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeNumberOfMeasurementReportingLevelsValueCodecFieldEncode(&sealed) = func(value s00.NumberOfMeasurementReportingLevels, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.NumberOfMeasurementReportingLevels, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.NumberOfMeasurementReportingLevels
				}{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 5, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeNumberOfMeasurementReportingLevelsValueCodecFieldCapture(&sealed) = func(v s00.NumberOfMeasurementReportingLevels, options aper.DecodeState) (s00.NumberOfMeasurementReportingLevels, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APNumberOfMeasurementReportingLevels(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeNumberOfMeasurementReportingLevelsValueCodecFieldCompare(&sealed) = func(v s00.NumberOfMeasurementReportingLevels, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APNumberOfMeasurementReportingLevels(
				&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeNumberOfMeasurementReportingLevelsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NumberOfMeasurementReportingLevels"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// OldBSSToNewBSSInformationCodec binds the complete source value type.
func OldBSSToNewBSSInformationCodec() s01.OldBSSToNewBSSInformationValueCodec {
	return func() s01.OldBSSToNewBSSInformationValueCodec {
		sealed := s01.OldBSSToNewBSSInformationValueCodec{}
		*s01.BridgeOldBSSToNewBSSInformationValueCodecFieldPath(&sealed) = "OldBSSToNewBSSInformation"
		*s01.BridgeOldBSSToNewBSSInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.OldBSSToNewBSSInformation, error) {
			var zero s00.OldBSSToNewBSSInformation
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.OldBSSToNewBSSInformation, error) {
				var v struct{ Value s00.OldBSSToNewBSSInformation }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.OldBSSToNewBSSInformation(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "OldBSSToNewBSSInformation"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeOldBSSToNewBSSInformationValueCodecFieldEncode(&sealed) = func(value s00.OldBSSToNewBSSInformation, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.OldBSSToNewBSSInformation, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.OldBSSToNewBSSInformation }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 0, 0, false); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeOldBSSToNewBSSInformationValueCodecFieldCapture(&sealed) = func(v s00.OldBSSToNewBSSInformation, options aper.DecodeState) (s00.OldBSSToNewBSSInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APOldBSSToNewBSSInformation(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s01.BridgeOldBSSToNewBSSInformationValueCodecFieldCompare(&sealed) = func(v s00.OldBSSToNewBSSInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APOldBSSToNewBSSInformation(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeOldBSSToNewBSSInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:OldBSSToNewBSSInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// OverloadActionCodec binds the complete source value type.
func OverloadActionCodec() s01.OverloadActionValueCodec {
	return func() s01.OverloadActionValueCodec {
		sealed := s01.OverloadActionValueCodec{}
		*s01.BridgeOverloadActionValueCodecFieldPath(&sealed) = "OverloadAction"
		*s01.BridgeOverloadActionValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.OverloadAction, error) {
			var zero s00.OverloadAction
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.OverloadAction, error) {
				var v struct{ Value s00.OverloadAction }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 4, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.OverloadAction(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "OverloadAction"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeOverloadActionValueCodecFieldEncode(&sealed) = func(value s00.OverloadAction, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.OverloadAction, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.OverloadAction }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 3, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeOverloadActionValueCodecFieldCapture(&sealed) = func(v s00.OverloadAction, options aper.DecodeState) (s00.OverloadAction, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APOverloadAction(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeOverloadActionValueCodecFieldCompare(&sealed) = func(v s00.OverloadAction, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APOverloadAction(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeOverloadActionValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:OverloadAction"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// OverloadFlagCodec binds the complete source value type.
func OverloadFlagCodec() s01.OverloadFlagValueCodec {
	return func() s01.OverloadFlagValueCodec {
		sealed := s01.OverloadFlagValueCodec{}
		*s01.BridgeOverloadFlagValueCodecFieldPath(&sealed) = "OverloadFlag"
		*s01.BridgeOverloadFlagValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.OverloadFlag, error) {
			var zero s00.OverloadFlag
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.OverloadFlag, error) {
				var v struct{ Value s00.OverloadFlag }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.OverloadFlag(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "OverloadFlag"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeOverloadFlagValueCodecFieldEncode(&sealed) = func(value s00.OverloadFlag, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.OverloadFlag, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.OverloadFlag }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 1, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeOverloadFlagValueCodecFieldCapture(&sealed) = func(v s00.OverloadFlag, options aper.DecodeState) (s00.OverloadFlag, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APOverloadFlag(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeOverloadFlagValueCodecFieldCompare(&sealed) = func(v s00.OverloadFlag, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APOverloadFlag(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s01.BridgeOverloadFlagValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:OverloadFlag"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PagingAttemptCountCodec binds the complete source value type.
func PagingAttemptCountCodec() s01.PagingAttemptCountValueCodec {
	return func() s01.PagingAttemptCountValueCodec {
		sealed := s01.PagingAttemptCountValueCodec{}
		*s01.BridgePagingAttemptCountValueCodecFieldPath(&sealed) = "PagingAttemptCount"
		*s01.BridgePagingAttemptCountValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PagingAttemptCount, error) {
			var zero s00.PagingAttemptCount
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.PagingAttemptCount, error) {
				var v struct{ Value s00.PagingAttemptCount }
				err := func() error {
					val_value, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound6, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = val_value
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PagingAttemptCount"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgePagingAttemptCountValueCodecFieldEncode(&sealed) = func(value s00.PagingAttemptCount, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.PagingAttemptCount, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.PagingAttemptCount }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeIntegerBigBoundsAligned(bb, v.Value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound6, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgePagingAttemptCountValueCodecFieldCapture(&sealed) = func(v s00.PagingAttemptCount, options aper.DecodeState) (s00.PagingAttemptCount, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPagingAttemptCount(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s01.BridgePagingAttemptCountValueCodecFieldCompare(&sealed) = func(v s00.PagingAttemptCount, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APPagingAttemptCount(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePagingAttemptCountValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PagingAttemptCount"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PagingEDRXCycleCodec binds the complete source value type.
func PagingEDRXCycleCodec() s01.PagingEDRXCycleValueCodec {
	return func() s01.PagingEDRXCycleValueCodec {
		sealed := s01.PagingEDRXCycleValueCodec{}
		*s01.BridgePagingEDRXCycleValueCodecFieldPath(&sealed) = "PagingEDRXCycle"
		*s01.BridgePagingEDRXCycleValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PagingEDRXCycle, error) {
			var zero s00.PagingEDRXCycle
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.PagingEDRXCycle, error) {
				var v struct{ Value s00.PagingEDRXCycle }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 14, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.PagingEDRXCycle(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PagingEDRXCycle"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgePagingEDRXCycleValueCodecFieldEncode(&sealed) = func(value s00.PagingEDRXCycle, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.PagingEDRXCycle, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.PagingEDRXCycle }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 14, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgePagingEDRXCycleValueCodecFieldCapture(&sealed) = func(v s00.PagingEDRXCycle, options aper.DecodeState) (s00.PagingEDRXCycle, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPagingEDRXCycle(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePagingEDRXCycleValueCodecFieldCompare(&sealed) = func(v s00.PagingEDRXCycle, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APPagingEDRXCycle(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgePagingEDRXCycleValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PagingEDRXCycle"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PagingProbabilityInformationCodec binds the complete source value type.
func PagingProbabilityInformationCodec() s01.PagingProbabilityInformationValueCodec {
	return func() s01.PagingProbabilityInformationValueCodec {
		sealed := s01.PagingProbabilityInformationValueCodec{}
		*s01.BridgePagingProbabilityInformationValueCodecFieldPath(&sealed) = "PagingProbabilityInformation"
		*s01.BridgePagingProbabilityInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PagingProbabilityInformation, error) {
			var zero s00.PagingProbabilityInformation
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.PagingProbabilityInformation, error) {
				var v struct {
					Value s00.PagingProbabilityInformation
				}
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 21, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.PagingProbabilityInformation(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PagingProbabilityInformation"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgePagingProbabilityInformationValueCodecFieldEncode(&sealed) = func(value s00.PagingProbabilityInformation, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.PagingProbabilityInformation, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct {
					Value s00.PagingProbabilityInformation
				}{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 21, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgePagingProbabilityInformationValueCodecFieldCapture(&sealed) = func(v s00.PagingProbabilityInformation, options aper.DecodeState) (s00.PagingProbabilityInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPagingProbabilityInformation(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePagingProbabilityInformationValueCodecFieldCompare(&sealed) = func(v s00.PagingProbabilityInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.
				Begin()
			BridgeCompareS1APPagingProbabilityInformation(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePagingProbabilityInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PagingProbabilityInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PagingTimeWindowCodec binds the complete source value type.
func PagingTimeWindowCodec() s01.PagingTimeWindowValueCodec {
	return func() s01.PagingTimeWindowValueCodec {
		sealed := s01.PagingTimeWindowValueCodec{}
		*s01.BridgePagingTimeWindowValueCodecFieldPath(&sealed) = "PagingTimeWindow"
		*s01.BridgePagingTimeWindowValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PagingTimeWindow, error) {
			var zero s00.PagingTimeWindow
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.PagingTimeWindow, error) {
				var v struct{ Value s00.PagingTimeWindow }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 16, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.PagingTimeWindow(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PagingTimeWindow"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgePagingTimeWindowValueCodecFieldEncode(&sealed) = func(value s00.PagingTimeWindow, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.PagingTimeWindow, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.PagingTimeWindow }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 16, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgePagingTimeWindowValueCodecFieldCapture(&sealed) = func(v s00.PagingTimeWindow, options aper.DecodeState) (s00.PagingTimeWindow, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APPagingTimeWindow(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePagingTimeWindowValueCodecFieldCompare(&sealed) = func(v s00.PagingTimeWindow, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APPagingTimeWindow(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgePagingTimeWindowValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PagingTimeWindow"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PedestrianUECodec binds the complete source value type.
func PedestrianUECodec() s01.PedestrianUEValueCodec {
	return func() s01.PedestrianUEValueCodec {
		sealed := s01.PedestrianUEValueCodec{}
		*s01.BridgePedestrianUEValueCodecFieldPath(&sealed) = "PedestrianUE"
		*s01.BridgePedestrianUEValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PedestrianUE, error) {
			var zero s00.PedestrianUE
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.PedestrianUE, error) {
				var v struct{ Value s00.PedestrianUE }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.PedestrianUE(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PedestrianUE"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgePedestrianUEValueCodecFieldEncode(&sealed) = func(value s00.PedestrianUE, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.PedestrianUE, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.PedestrianUE }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 2, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgePedestrianUEValueCodecFieldCapture(&sealed) = func(v s00.PedestrianUE, options aper.DecodeState) (s00.PedestrianUE, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPedestrianUE(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePedestrianUEValueCodecFieldCompare(&sealed) = func(v s00.PedestrianUE, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APPedestrianUE(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s01.BridgePedestrianUEValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PedestrianUE"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PortNumberCodec binds the complete source value type.
func PortNumberCodec() s01.PortNumberValueCodec {
	return func() s01.PortNumberValueCodec {
		sealed := s01.PortNumberValueCodec{}
		*s01.BridgePortNumberValueCodecFieldPath(&sealed) = "PortNumber"
		*s01.BridgePortNumberValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PortNumber, error) {
			var zero s00.PortNumber
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.PortNumber, error) {
				var v struct{ Value s00.PortNumber }
				err := func() error {
					val_value, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.PortNumber(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PortNumber"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgePortNumberValueCodecFieldEncode(&sealed) = func(value s00.PortNumber, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.PortNumber, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.PortNumber }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 2, 2, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgePortNumberValueCodecFieldCapture(&sealed) = func(v s00.PortNumber, options aper.DecodeState) (s00.PortNumber, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APPortNumber(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePortNumberValueCodecFieldCompare(&sealed) = func(v s00.PortNumber, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APPortNumber(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePortNumberValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PortNumber"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PreEmptionCapabilityCodec binds the complete source value type.
func PreEmptionCapabilityCodec() s01.PreEmptionCapabilityValueCodec {
	return func() s01.PreEmptionCapabilityValueCodec {
		sealed := s01.PreEmptionCapabilityValueCodec{}
		*s01.BridgePreEmptionCapabilityValueCodecFieldPath(&sealed) = "PreEmptionCapability"
		*s01.BridgePreEmptionCapabilityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PreEmptionCapability, error) {
			var zero s00.PreEmptionCapability
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.PreEmptionCapability, error) {
				var v struct{ Value s00.PreEmptionCapability }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 2, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.PreEmptionCapability(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PreEmptionCapability"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgePreEmptionCapabilityValueCodecFieldEncode(&sealed) = func(value s00.PreEmptionCapability, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.PreEmptionCapability, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.PreEmptionCapability }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 2, false); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgePreEmptionCapabilityValueCodecFieldCapture(&sealed) = func(v s00.PreEmptionCapability, options aper.DecodeState) (s00.PreEmptionCapability, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPreEmptionCapability(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePreEmptionCapabilityValueCodecFieldCompare(&sealed) = func(v s00.PreEmptionCapability, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APPreEmptionCapability(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePreEmptionCapabilityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PreEmptionCapability"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PreEmptionVulnerabilityCodec binds the complete source value type.
func PreEmptionVulnerabilityCodec() s01.PreEmptionVulnerabilityValueCodec {
	return func() s01.PreEmptionVulnerabilityValueCodec {
		sealed := s01.PreEmptionVulnerabilityValueCodec{}
		*s01.BridgePreEmptionVulnerabilityValueCodecFieldPath(&sealed) = "PreEmptionVulnerability"
		*s01.BridgePreEmptionVulnerabilityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PreEmptionVulnerability, error) {
			var zero s00.PreEmptionVulnerability
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.PreEmptionVulnerability, error) {
				var v struct{ Value s00.PreEmptionVulnerability }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 2, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.PreEmptionVulnerability(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PreEmptionVulnerability"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgePreEmptionVulnerabilityValueCodecFieldEncode(&sealed) = func(value s00.PreEmptionVulnerability, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.PreEmptionVulnerability, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.PreEmptionVulnerability }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 2, false); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgePreEmptionVulnerabilityValueCodecFieldCapture(&sealed) = func(v s00.PreEmptionVulnerability, options aper.DecodeState) (s00.PreEmptionVulnerability, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPreEmptionVulnerability(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s01.BridgePreEmptionVulnerabilityValueCodecFieldCompare(&sealed) = func(v s00.PreEmptionVulnerability, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APPreEmptionVulnerability(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePreEmptionVulnerabilityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PreEmptionVulnerability"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// PresenceCodec binds the complete source value type.
func PresenceCodec() s01.PresenceValueCodec {
	return func() s01.PresenceValueCodec {
		sealed := s01.PresenceValueCodec{}
		*s01.BridgePresenceValueCodecFieldPath(&sealed) = "Presence"
		*s01.BridgePresenceValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Presence, error) {
			var zero s00.Presence
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.Presence, error) {
				var v struct{ Value s00.Presence }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.Presence(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "Presence"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgePresenceValueCodecFieldEncode(&sealed) = func(value s00.Presence, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.Presence, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.Presence }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 3, false); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgePresenceValueCodecFieldCapture(&sealed) = func(v s00.Presence, options aper.DecodeState) (s00.Presence, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APPresence(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePresenceValueCodecFieldCompare(&sealed) = func(v s00.Presence, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APPresence(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePresenceValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Presence"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ProSeDirectCommunicationCodec binds the complete source value type.
func ProSeDirectCommunicationCodec() s01.ProSeDirectCommunicationValueCodec {
	return func() s01.ProSeDirectCommunicationValueCodec {
		sealed := s01.ProSeDirectCommunicationValueCodec{}
		*s01.BridgeProSeDirectCommunicationValueCodecFieldPath(&sealed) = "ProSeDirectCommunication"
		*s01.BridgeProSeDirectCommunicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ProSeDirectCommunication, error) {
			var zero s00.ProSeDirectCommunication
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.ProSeDirectCommunication, error) {
				var v struct{ Value s00.ProSeDirectCommunication }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.ProSeDirectCommunication(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProSeDirectCommunication"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeProSeDirectCommunicationValueCodecFieldEncode(&sealed) = func(value s00.ProSeDirectCommunication, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ProSeDirectCommunication, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ProSeDirectCommunication }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 2, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeProSeDirectCommunicationValueCodecFieldCapture(&sealed) = func(v s00.ProSeDirectCommunication, options aper.DecodeState) (s00.ProSeDirectCommunication, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APProSeDirectCommunication(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s01.BridgeProSeDirectCommunicationValueCodecFieldCompare(&sealed) = func(v s00.ProSeDirectCommunication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APProSeDirectCommunication(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeProSeDirectCommunicationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProSeDirectCommunication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ProSeDirectDiscoveryCodec binds the complete source value type.
func ProSeDirectDiscoveryCodec() s01.ProSeDirectDiscoveryValueCodec {
	return func() s01.ProSeDirectDiscoveryValueCodec {
		sealed := s01.ProSeDirectDiscoveryValueCodec{}
		*s01.BridgeProSeDirectDiscoveryValueCodecFieldPath(&sealed) = "ProSeDirectDiscovery"
		*s01.BridgeProSeDirectDiscoveryValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ProSeDirectDiscovery, error) {
			var zero s00.ProSeDirectDiscovery
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			value, err := (func(bb *aper.BitBuffer) (s00.ProSeDirectDiscovery, error) {
				var v struct{ Value s00.ProSeDirectDiscovery }
				err := func() error {
					val_value, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Value"})
					if err != nil {
						return runtime.WrapDecodePath(err, "Value")
					}
					v.Value = s00.ProSeDirectDiscovery(val_value)
					return nil
				}()
				return v.Value, err
			})(bb)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "ProSeDirectDiscovery"); err != nil {
				return zero, err
			}
			return value, nil
		}
		*s01.BridgeProSeDirectDiscoveryValueCodecFieldEncode(&sealed) = func(value s00.ProSeDirectDiscovery, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (func(value s00.ProSeDirectDiscovery, budget *aper.DecodeBudget) ([]byte, error) {
				bb := aper.NewBudgetBuffer(budget)
				v := struct{ Value s00.ProSeDirectDiscovery }{Value: value}
				_ = v
				err := func() error {
					if err := aper.EncodeEnumeratedAligned(bb, int64(v.Value), 2, true); err != nil {
						return fmt.Errorf("encoding value: %w", err)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
				return bb.CompleteBytes(), nil
			})(value, budget)
		}
		*s01.BridgeProSeDirectDiscoveryValueCodecFieldCapture(&sealed) = func(v s00.ProSeDirectDiscovery, options aper.DecodeState) (s00.ProSeDirectDiscovery, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APProSeDirectDiscovery(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeProSeDirectDiscoveryValueCodecFieldCompare(&sealed) = func(v s00.ProSeDirectDiscovery, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APProSeDirectDiscovery(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeProSeDirectDiscoveryValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProSeDirectDiscovery"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}
func BridgeAdditionalGUTIExtIEsValueFieldId(v *AdditionalGUTIExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeAdditionalGUTIExtIEsValueFieldIsOpaque(v *AdditionalGUTIExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeAdditionalGUTIExtIEsValueFieldOpaque(v *AdditionalGUTIExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeAdditionalGUTIExtIEsValueFieldReceived(v *AdditionalGUTIExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeAdditionalGUTIExtIEsValueFieldReplay(v *AdditionalGUTIExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAdditionalGUTIExtIEsValueMethodCaptureSemantics(v AdditionalGUTIExtIEsValue, a0 aper.SemanticCapture) AdditionalGUTIExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeAdditionalGUTIExtIEsValueMethodCompareSemantics(v AdditionalGUTIExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeAdditionalGUTIExtIEsValueMethodDecode(v AdditionalGUTIExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (AdditionalGUTIExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeAdditionalGUTIExtIEsValueMethodEncode(v AdditionalGUTIExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeAdditionalGUTIExtIEsValueMethodEncodeFresh(v AdditionalGUTIExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeAdditionalGUTIExtIEsValueMethodMatchesID(v AdditionalGUTIExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeAdditionalGUTIExtIEsValueMethodReason(v AdditionalGUTIExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeAdditionalGUTIExtIEsValueMethodRule(v AdditionalGUTIExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeAllocationAndRetentionPriorityExtIEsValueFieldId(v *AllocationAndRetentionPriorityExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeAllocationAndRetentionPriorityExtIEsValueFieldIsOpaque(v *AllocationAndRetentionPriorityExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeAllocationAndRetentionPriorityExtIEsValueFieldOpaque(v *AllocationAndRetentionPriorityExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeAllocationAndRetentionPriorityExtIEsValueFieldReceived(v *AllocationAndRetentionPriorityExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeAllocationAndRetentionPriorityExtIEsValueFieldReplay(v *AllocationAndRetentionPriorityExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAllocationAndRetentionPriorityExtIEsValueMethodCaptureSemantics(v AllocationAndRetentionPriorityExtIEsValue, a0 aper.SemanticCapture) AllocationAndRetentionPriorityExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeAllocationAndRetentionPriorityExtIEsValueMethodCompareSemantics(v AllocationAndRetentionPriorityExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeAllocationAndRetentionPriorityExtIEsValueMethodDecode(v AllocationAndRetentionPriorityExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (AllocationAndRetentionPriorityExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeAllocationAndRetentionPriorityExtIEsValueMethodEncode(v AllocationAndRetentionPriorityExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeAllocationAndRetentionPriorityExtIEsValueMethodEncodeFresh(v AllocationAndRetentionPriorityExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeAllocationAndRetentionPriorityExtIEsValueMethodMatchesID(v AllocationAndRetentionPriorityExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeAllocationAndRetentionPriorityExtIEsValueMethodReason(v AllocationAndRetentionPriorityExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeAllocationAndRetentionPriorityExtIEsValueMethodRule(v AllocationAndRetentionPriorityExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeAssistanceDataForPagingExtIEsValueFieldId(v *AssistanceDataForPagingExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeAssistanceDataForPagingExtIEsValueFieldIsOpaque(v *AssistanceDataForPagingExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeAssistanceDataForPagingExtIEsValueFieldOpaque(v *AssistanceDataForPagingExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeAssistanceDataForPagingExtIEsValueFieldReceived(v *AssistanceDataForPagingExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeAssistanceDataForPagingExtIEsValueFieldReplay(v *AssistanceDataForPagingExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceDataForPagingExtIEsValueMethodCaptureSemantics(v AssistanceDataForPagingExtIEsValue, a0 aper.SemanticCapture) AssistanceDataForPagingExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeAssistanceDataForPagingExtIEsValueMethodCompareSemantics(v AssistanceDataForPagingExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeAssistanceDataForPagingExtIEsValueMethodDecode(v AssistanceDataForPagingExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (AssistanceDataForPagingExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeAssistanceDataForPagingExtIEsValueMethodEncode(v AssistanceDataForPagingExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeAssistanceDataForPagingExtIEsValueMethodEncodeFresh(v AssistanceDataForPagingExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeAssistanceDataForPagingExtIEsValueMethodMatchesID(v AssistanceDataForPagingExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeAssistanceDataForPagingExtIEsValueMethodReason(v AssistanceDataForPagingExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeAssistanceDataForPagingExtIEsValueMethodRule(v AssistanceDataForPagingExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeAssistanceDataForRecommendedCellsExtIEsValueFieldId(v *AssistanceDataForRecommendedCellsExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeAssistanceDataForRecommendedCellsExtIEsValueFieldIsOpaque(v *AssistanceDataForRecommendedCellsExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeAssistanceDataForRecommendedCellsExtIEsValueFieldOpaque(v *AssistanceDataForRecommendedCellsExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeAssistanceDataForRecommendedCellsExtIEsValueFieldReceived(v *AssistanceDataForRecommendedCellsExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeAssistanceDataForRecommendedCellsExtIEsValueFieldReplay(v *AssistanceDataForRecommendedCellsExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodCaptureSemantics(v AssistanceDataForRecommendedCellsExtIEsValue, a0 aper.SemanticCapture) AssistanceDataForRecommendedCellsExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodCompareSemantics(v AssistanceDataForRecommendedCellsExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodDecode(v AssistanceDataForRecommendedCellsExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (AssistanceDataForRecommendedCellsExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodEncode(v AssistanceDataForRecommendedCellsExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodEncodeFresh(v AssistanceDataForRecommendedCellsExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodMatchesID(v AssistanceDataForRecommendedCellsExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodReason(v AssistanceDataForRecommendedCellsExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeAssistanceDataForRecommendedCellsExtIEsValueMethodRule(v AssistanceDataForRecommendedCellsExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsValueFieldId(v *BearersSubjectToDLDiscardingItemExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsValueFieldIsOpaque(v *BearersSubjectToDLDiscardingItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsValueFieldOpaque(v *BearersSubjectToDLDiscardingItemExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsValueFieldReceived(v *BearersSubjectToDLDiscardingItemExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsValueFieldReplay(v *BearersSubjectToDLDiscardingItemExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodCaptureSemantics(v BearersSubjectToDLDiscardingItemExtIEsValue, a0 aper.SemanticCapture) BearersSubjectToDLDiscardingItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodCompareSemantics(v BearersSubjectToDLDiscardingItemExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodDecode(v BearersSubjectToDLDiscardingItemExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (BearersSubjectToDLDiscardingItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodEncode(v BearersSubjectToDLDiscardingItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodEncodeFresh(v BearersSubjectToDLDiscardingItemExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodMatchesID(v BearersSubjectToDLDiscardingItemExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodReason(v BearersSubjectToDLDiscardingItemExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeBearersSubjectToDLDiscardingItemExtIEsValueMethodRule(v BearersSubjectToDLDiscardingItemExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueFieldId(v *BearersSubjectToEarlyStatusTransferItemExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueFieldIsOpaque(v *BearersSubjectToEarlyStatusTransferItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueFieldOpaque(v *BearersSubjectToEarlyStatusTransferItemExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueFieldReceived(v *BearersSubjectToEarlyStatusTransferItemExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueFieldReplay(v *BearersSubjectToEarlyStatusTransferItemExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodCaptureSemantics(v BearersSubjectToEarlyStatusTransferItemExtIEsValue, a0 aper.SemanticCapture) BearersSubjectToEarlyStatusTransferItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodCompareSemantics(v BearersSubjectToEarlyStatusTransferItemExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodDecode(v BearersSubjectToEarlyStatusTransferItemExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (BearersSubjectToEarlyStatusTransferItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodEncode(v BearersSubjectToEarlyStatusTransferItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodEncodeFresh(v BearersSubjectToEarlyStatusTransferItemExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodMatchesID(v BearersSubjectToEarlyStatusTransferItemExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodReason(v BearersSubjectToEarlyStatusTransferItemExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeBearersSubjectToEarlyStatusTransferItemExtIEsValueMethodRule(v BearersSubjectToEarlyStatusTransferItemExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeBluetoothMeasurementConfigurationExtIEsValueFieldId(v *BluetoothMeasurementConfigurationExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeBluetoothMeasurementConfigurationExtIEsValueFieldIsOpaque(v *BluetoothMeasurementConfigurationExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeBluetoothMeasurementConfigurationExtIEsValueFieldOpaque(v *BluetoothMeasurementConfigurationExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeBluetoothMeasurementConfigurationExtIEsValueFieldReceived(v *BluetoothMeasurementConfigurationExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeBluetoothMeasurementConfigurationExtIEsValueFieldReplay(v *BluetoothMeasurementConfigurationExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeBluetoothMeasurementConfigurationExtIEsValueMethodCaptureSemantics(v BluetoothMeasurementConfigurationExtIEsValue, a0 aper.SemanticCapture) BluetoothMeasurementConfigurationExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeBluetoothMeasurementConfigurationExtIEsValueMethodCompareSemantics(v BluetoothMeasurementConfigurationExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeBluetoothMeasurementConfigurationExtIEsValueMethodDecode(v BluetoothMeasurementConfigurationExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (BluetoothMeasurementConfigurationExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeBluetoothMeasurementConfigurationExtIEsValueMethodEncode(v BluetoothMeasurementConfigurationExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeBluetoothMeasurementConfigurationExtIEsValueMethodEncodeFresh(v BluetoothMeasurementConfigurationExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeBluetoothMeasurementConfigurationExtIEsValueMethodMatchesID(v BluetoothMeasurementConfigurationExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeBluetoothMeasurementConfigurationExtIEsValueMethodReason(v BluetoothMeasurementConfigurationExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeBluetoothMeasurementConfigurationExtIEsValueMethodRule(v BluetoothMeasurementConfigurationExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeCGIExtIEsValueFieldId(v *CGIExtIEsValue) *s00.ProtocolIEID        { return &v.id }
func BridgeCGIExtIEsValueFieldIsOpaque(v *CGIExtIEsValue) *bool              { return &v.isOpaque }
func BridgeCGIExtIEsValueFieldOpaque(v *CGIExtIEsValue) *aper.OpaqueOpenType { return &v.opaque }
func BridgeCGIExtIEsValueFieldReceived(v *CGIExtIEsValue) *aper.WireSpan     { return &v.received }
func BridgeCGIExtIEsValueFieldReplay(v *CGIExtIEsValue) *aper.Snapshot       { return &v.replay }
func BridgeCGIExtIEsValueMethodCaptureSemantics(v CGIExtIEsValue, a0 aper.SemanticCapture) CGIExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeCGIExtIEsValueMethodCompareSemantics(v CGIExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeCGIExtIEsValueMethodDecode(v CGIExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (CGIExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeCGIExtIEsValueMethodEncode(v CGIExtIEsValue) ([]byte, error) { return v.encode() }
func BridgeCGIExtIEsValueMethodEncodeFresh(v CGIExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeCGIExtIEsValueMethodMatchesID(v CGIExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeCGIExtIEsValueMethodReason(v CGIExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeCGIExtIEsValueMethodRule(v CGIExtIEsValue) aper.SourceRule { return v.rule() }
func BridgeCNTypeRestrictionsItemExtIEsValueFieldId(v *CNTypeRestrictionsItemExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeCNTypeRestrictionsItemExtIEsValueFieldIsOpaque(v *CNTypeRestrictionsItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeCNTypeRestrictionsItemExtIEsValueFieldOpaque(v *CNTypeRestrictionsItemExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeCNTypeRestrictionsItemExtIEsValueFieldReceived(v *CNTypeRestrictionsItemExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeCNTypeRestrictionsItemExtIEsValueFieldReplay(v *CNTypeRestrictionsItemExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCNTypeRestrictionsItemExtIEsValueMethodCaptureSemantics(v CNTypeRestrictionsItemExtIEsValue, a0 aper.SemanticCapture) CNTypeRestrictionsItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeCNTypeRestrictionsItemExtIEsValueMethodCompareSemantics(v CNTypeRestrictionsItemExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeCNTypeRestrictionsItemExtIEsValueMethodDecode(v CNTypeRestrictionsItemExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (CNTypeRestrictionsItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeCNTypeRestrictionsItemExtIEsValueMethodEncode(v CNTypeRestrictionsItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeCNTypeRestrictionsItemExtIEsValueMethodEncodeFresh(v CNTypeRestrictionsItemExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeCNTypeRestrictionsItemExtIEsValueMethodMatchesID(v CNTypeRestrictionsItemExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeCNTypeRestrictionsItemExtIEsValueMethodReason(v CNTypeRestrictionsItemExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeCNTypeRestrictionsItemExtIEsValueMethodRule(v CNTypeRestrictionsItemExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeCOUNTValueExtendedExtIEsValueFieldId(v *COUNTValueExtendedExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeCOUNTValueExtendedExtIEsValueFieldIsOpaque(v *COUNTValueExtendedExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeCOUNTValueExtendedExtIEsValueFieldOpaque(v *COUNTValueExtendedExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeCOUNTValueExtendedExtIEsValueFieldReceived(v *COUNTValueExtendedExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeCOUNTValueExtendedExtIEsValueFieldReplay(v *COUNTValueExtendedExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCOUNTValueExtendedExtIEsValueMethodCaptureSemantics(v COUNTValueExtendedExtIEsValue, a0 aper.SemanticCapture) COUNTValueExtendedExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeCOUNTValueExtendedExtIEsValueMethodCompareSemantics(v COUNTValueExtendedExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeCOUNTValueExtendedExtIEsValueMethodDecode(v COUNTValueExtendedExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (COUNTValueExtendedExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeCOUNTValueExtendedExtIEsValueMethodEncode(v COUNTValueExtendedExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeCOUNTValueExtendedExtIEsValueMethodEncodeFresh(v COUNTValueExtendedExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeCOUNTValueExtendedExtIEsValueMethodMatchesID(v COUNTValueExtendedExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeCOUNTValueExtendedExtIEsValueMethodReason(v COUNTValueExtendedExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeCOUNTValueExtendedExtIEsValueMethodRule(v COUNTValueExtendedExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeCOUNTvalueExtIEsValueFieldId(v *COUNTvalueExtIEsValue) *s00.ProtocolIEID { return &v.id }
func BridgeCOUNTvalueExtIEsValueFieldIsOpaque(v *COUNTvalueExtIEsValue) *bool       { return &v.isOpaque }
func BridgeCOUNTvalueExtIEsValueFieldOpaque(v *COUNTvalueExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeCOUNTvalueExtIEsValueFieldReceived(v *COUNTvalueExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeCOUNTvalueExtIEsValueFieldReplay(v *COUNTvalueExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCOUNTvalueExtIEsValueMethodCaptureSemantics(v COUNTvalueExtIEsValue, a0 aper.SemanticCapture) COUNTvalueExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeCOUNTvalueExtIEsValueMethodCompareSemantics(v COUNTvalueExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeCOUNTvalueExtIEsValueMethodDecode(v COUNTvalueExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (COUNTvalueExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeCOUNTvalueExtIEsValueMethodEncode(v COUNTvalueExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeCOUNTvalueExtIEsValueMethodEncodeFresh(v COUNTvalueExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeCOUNTvalueExtIEsValueMethodMatchesID(v COUNTvalueExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeCOUNTvalueExtIEsValueMethodReason(v COUNTvalueExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeCOUNTvalueExtIEsValueMethodRule(v COUNTvalueExtIEsValue) aper.SourceRule { return v.rule() }
func BridgeCOUNTvaluePDCPSNlength18ExtIEsValueFieldId(v *COUNTvaluePDCPSNlength18ExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsValueFieldIsOpaque(v *COUNTvaluePDCPSNlength18ExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsValueFieldOpaque(v *COUNTvaluePDCPSNlength18ExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsValueFieldReceived(v *COUNTvaluePDCPSNlength18ExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsValueFieldReplay(v *COUNTvaluePDCPSNlength18ExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodCaptureSemantics(v COUNTvaluePDCPSNlength18ExtIEsValue, a0 aper.SemanticCapture) COUNTvaluePDCPSNlength18ExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodCompareSemantics(v COUNTvaluePDCPSNlength18ExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodDecode(v COUNTvaluePDCPSNlength18ExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (COUNTvaluePDCPSNlength18ExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodEncode(v COUNTvaluePDCPSNlength18ExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodEncodeFresh(v COUNTvaluePDCPSNlength18ExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodMatchesID(v COUNTvaluePDCPSNlength18ExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodReason(v COUNTvaluePDCPSNlength18ExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeCOUNTvaluePDCPSNlength18ExtIEsValueMethodRule(v COUNTvaluePDCPSNlength18ExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeCSGIdListItemExtIEsValueFieldId(v *CSGIdListItemExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeCSGIdListItemExtIEsValueFieldIsOpaque(v *CSGIdListItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeCSGIdListItemExtIEsValueFieldOpaque(v *CSGIdListItemExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeCSGIdListItemExtIEsValueFieldReceived(v *CSGIdListItemExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeCSGIdListItemExtIEsValueFieldReplay(v *CSGIdListItemExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCSGIdListItemExtIEsValueMethodCaptureSemantics(v CSGIdListItemExtIEsValue, a0 aper.SemanticCapture) CSGIdListItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeCSGIdListItemExtIEsValueMethodCompareSemantics(v CSGIdListItemExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeCSGIdListItemExtIEsValueMethodDecode(v CSGIdListItemExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (CSGIdListItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeCSGIdListItemExtIEsValueMethodEncode(v CSGIdListItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeCSGIdListItemExtIEsValueMethodEncodeFresh(v CSGIdListItemExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeCSGIdListItemExtIEsValueMethodMatchesID(v CSGIdListItemExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeCSGIdListItemExtIEsValueMethodReason(v CSGIdListItemExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeCSGIdListItemExtIEsValueMethodRule(v CSGIdListItemExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeCSGMembershipInfoExtIEsValueFieldId(v *CSGMembershipInfoExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeCSGMembershipInfoExtIEsValueFieldIsOpaque(v *CSGMembershipInfoExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeCSGMembershipInfoExtIEsValueFieldOpaque(v *CSGMembershipInfoExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeCSGMembershipInfoExtIEsValueFieldReceived(v *CSGMembershipInfoExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeCSGMembershipInfoExtIEsValueFieldReplay(v *CSGMembershipInfoExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCSGMembershipInfoExtIEsValueMethodCaptureSemantics(v CSGMembershipInfoExtIEsValue, a0 aper.SemanticCapture) CSGMembershipInfoExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeCSGMembershipInfoExtIEsValueMethodCompareSemantics(v CSGMembershipInfoExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeCSGMembershipInfoExtIEsValueMethodDecode(v CSGMembershipInfoExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (CSGMembershipInfoExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeCSGMembershipInfoExtIEsValueMethodEncode(v CSGMembershipInfoExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeCSGMembershipInfoExtIEsValueMethodEncodeFresh(v CSGMembershipInfoExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeCSGMembershipInfoExtIEsValueMethodMatchesID(v CSGMembershipInfoExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeCSGMembershipInfoExtIEsValueMethodReason(v CSGMembershipInfoExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeCSGMembershipInfoExtIEsValueMethodRule(v CSGMembershipInfoExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeCancelledCellinEAIItemExtIEsValueFieldId(v *CancelledCellinEAIItemExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeCancelledCellinEAIItemExtIEsValueFieldIsOpaque(v *CancelledCellinEAIItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeCancelledCellinEAIItemExtIEsValueFieldOpaque(v *CancelledCellinEAIItemExtIEsValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeCancelledCellinEAIItemExtIEsValueFieldReceived(v *CancelledCellinEAIItemExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeCancelledCellinEAIItemExtIEsValueFieldReplay(v *CancelledCellinEAIItemExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCancelledCellinEAIItemExtIEsValueMethodCaptureSemantics(v CancelledCellinEAIItemExtIEsValue, a0 aper.SemanticCapture) CancelledCellinEAIItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeCancelledCellinEAIItemExtIEsValueMethodCompareSemantics(v CancelledCellinEAIItemExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeCancelledCellinEAIItemExtIEsValueMethodDecode(v CancelledCellinEAIItemExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (CancelledCellinEAIItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeCancelledCellinEAIItemExtIEsValueMethodEncode(v CancelledCellinEAIItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeCancelledCellinEAIItemExtIEsValueMethodEncodeFresh(v CancelledCellinEAIItemExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeCancelledCellinEAIItemExtIEsValueMethodMatchesID(v CancelledCellinEAIItemExtIEsValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeCancelledCellinEAIItemExtIEsValueMethodReason(v CancelledCellinEAIItemExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeCancelledCellinEAIItemExtIEsValueMethodRule(v CancelledCellinEAIItemExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeThresholdRSRPValueCodecFieldCapture(v *ThresholdRSRPValueCodec) *func(s00.ThresholdRSRP, aper.DecodeState) (s00.ThresholdRSRP, aper.Snapshot) {
	return &v.capture
}
func BridgeThresholdRSRPValueCodecFieldCompare(v *ThresholdRSRPValueCodec) *func(s00.ThresholdRSRP, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeThresholdRSRPValueCodecFieldContext(v *ThresholdRSRPValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeThresholdRSRPValueCodecFieldDecode(v *ThresholdRSRPValueCodec) *func([]byte, aper.DecodeState) (s00.ThresholdRSRP, error) {
	return &v.decode
}
func BridgeThresholdRSRPValueCodecFieldEncode(v *ThresholdRSRPValueCodec) *func(s00.ThresholdRSRP, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeThresholdRSRPValueCodecFieldPath(v *ThresholdRSRPValueCodec) *aper.Path { return &v.path }
func BridgeThresholdRSRPValueCodecMethodEncodeBudgetValue(v ThresholdRSRPValueCodec, a0 s00.ThresholdRSRP, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeThresholdRSRPValueCodecMethodEncodeChanged(v ThresholdRSRPValueCodec, a0 s00.ThresholdRSRP, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeThresholdRSRQAPERValueFieldContext(v *ThresholdRSRQAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeThresholdRSRQAPERValueFieldReceived(v *ThresholdRSRQAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeThresholdRSRQAPERValueFieldReplay(v *ThresholdRSRQAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeThresholdRSRQAPERValueFieldWithoutReplay(v *ThresholdRSRQAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeThresholdRSRQValueCodecFieldCapture(v *ThresholdRSRQValueCodec) *func(s00.ThresholdRSRQ, aper.DecodeState) (s00.ThresholdRSRQ, aper.Snapshot) {
	return &v.capture
}
func BridgeThresholdRSRQValueCodecFieldCompare(v *ThresholdRSRQValueCodec) *func(s00.ThresholdRSRQ, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeThresholdRSRQValueCodecFieldContext(v *ThresholdRSRQValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeThresholdRSRQValueCodecFieldDecode(v *ThresholdRSRQValueCodec) *func([]byte, aper.DecodeState) (s00.ThresholdRSRQ, error) {
	return &v.decode
}
func BridgeThresholdRSRQValueCodecFieldEncode(v *ThresholdRSRQValueCodec) *func(s00.ThresholdRSRQ, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeThresholdRSRQValueCodecFieldPath(v *ThresholdRSRQValueCodec) *aper.Path { return &v.path }
func BridgeThresholdRSRQValueCodecMethodEncodeBudgetValue(v ThresholdRSRQValueCodec, a0 s00.ThresholdRSRQ, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeThresholdRSRQValueCodecMethodEncodeChanged(v ThresholdRSRQValueCodec, a0 s00.ThresholdRSRQ, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTimeRefDistributionAPERValueFieldContext(v *TimeRefDistributionAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTimeRefDistributionAPERValueFieldReceived(v *TimeRefDistributionAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTimeRefDistributionAPERValueFieldReplay(v *TimeRefDistributionAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTimeRefDistributionAPERValueFieldWithoutReplay(v *TimeRefDistributionAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTimeRefDistributionValueCodecFieldCapture(v *TimeRefDistributionValueCodec) *func(s00.TimeRefDistribution, aper.DecodeState) (s00.TimeRefDistribution, aper.Snapshot) {
	return &v.capture
}
func BridgeTimeRefDistributionValueCodecFieldCompare(v *TimeRefDistributionValueCodec) *func(s00.TimeRefDistribution, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTimeRefDistributionValueCodecFieldContext(v *TimeRefDistributionValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTimeRefDistributionValueCodecFieldDecode(v *TimeRefDistributionValueCodec) *func([]byte, aper.DecodeState) (s00.TimeRefDistribution, error) {
	return &v.decode
}
func BridgeTimeRefDistributionValueCodecFieldEncode(v *TimeRefDistributionValueCodec) *func(s00.TimeRefDistribution, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTimeRefDistributionValueCodecFieldPath(v *TimeRefDistributionValueCodec) *aper.Path {
	return &v.path
}
func BridgeTimeRefDistributionValueCodecMethodEncodeBudgetValue(v TimeRefDistributionValueCodec, a0 s00.TimeRefDistribution, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTimeRefDistributionValueCodecMethodEncodeChanged(v TimeRefDistributionValueCodec, a0 s00.TimeRefDistribution, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTimeSinceSecondaryNodeReleaseAPERValueFieldContext(v *TimeSinceSecondaryNodeReleaseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTimeSinceSecondaryNodeReleaseAPERValueFieldReceived(v *TimeSinceSecondaryNodeReleaseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTimeSinceSecondaryNodeReleaseAPERValueFieldReplay(v *TimeSinceSecondaryNodeReleaseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTimeSinceSecondaryNodeReleaseAPERValueFieldWithoutReplay(v *TimeSinceSecondaryNodeReleaseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldCapture(v *TimeSinceSecondaryNodeReleaseValueCodec) *func(s00.TimeSinceSecondaryNodeRelease, aper.DecodeState) (s00.TimeSinceSecondaryNodeRelease, aper.Snapshot) {
	return &v.capture
}
func BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldCompare(v *TimeSinceSecondaryNodeReleaseValueCodec) *func(s00.TimeSinceSecondaryNodeRelease, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldContext(v *TimeSinceSecondaryNodeReleaseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldDecode(v *TimeSinceSecondaryNodeReleaseValueCodec) *func([]byte, aper.DecodeState) (s00.TimeSinceSecondaryNodeRelease, error) {
	return &v.decode
}
func BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldEncode(v *TimeSinceSecondaryNodeReleaseValueCodec) *func(s00.TimeSinceSecondaryNodeRelease, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTimeSinceSecondaryNodeReleaseValueCodecFieldPath(v *TimeSinceSecondaryNodeReleaseValueCodec) *aper.Path {
	return &v.path
}
func BridgeTimeSinceSecondaryNodeReleaseValueCodecMethodEncodeBudgetValue(v TimeSinceSecondaryNodeReleaseValueCodec, a0 s00.TimeSinceSecondaryNodeRelease, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTimeSinceSecondaryNodeReleaseValueCodecMethodEncodeChanged(v TimeSinceSecondaryNodeReleaseValueCodec, a0 s00.TimeSinceSecondaryNodeRelease, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTimeToTriggerAPERValueFieldContext(v *TimeToTriggerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTimeToTriggerAPERValueFieldReceived(v *TimeToTriggerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTimeToTriggerAPERValueFieldReplay(v *TimeToTriggerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTimeToTriggerAPERValueFieldWithoutReplay(v *TimeToTriggerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTimeToTriggerValueCodecFieldCapture(v *TimeToTriggerValueCodec) *func(s00.TimeToTrigger, aper.DecodeState) (s00.TimeToTrigger, aper.Snapshot) {
	return &v.capture
}
func BridgeTimeToTriggerValueCodecFieldCompare(v *TimeToTriggerValueCodec) *func(s00.TimeToTrigger, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTimeToTriggerValueCodecFieldContext(v *TimeToTriggerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTimeToTriggerValueCodecFieldDecode(v *TimeToTriggerValueCodec) *func([]byte, aper.DecodeState) (s00.TimeToTrigger, error) {
	return &v.decode
}
func BridgeTimeToTriggerValueCodecFieldEncode(v *TimeToTriggerValueCodec) *func(s00.TimeToTrigger, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTimeToTriggerValueCodecFieldPath(v *TimeToTriggerValueCodec) *aper.Path { return &v.path }
func BridgeTimeToTriggerValueCodecMethodEncodeBudgetValue(v TimeToTriggerValueCodec, a0 s00.TimeToTrigger, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTimeToTriggerValueCodecMethodEncodeChanged(v TimeToTriggerValueCodec, a0 s00.TimeToTrigger, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTimeToWaitAPERValueFieldContext(v *TimeToWaitAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTimeToWaitAPERValueFieldReceived(v *TimeToWaitAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTimeToWaitAPERValueFieldReplay(v *TimeToWaitAPERValue) *aper.Snapshot { return &v.replay }
func BridgeTimeToWaitAPERValueFieldWithoutReplay(v *TimeToWaitAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTimeToWaitValueCodecFieldCapture(v *TimeToWaitValueCodec) *func(s00.TimeToWait, aper.DecodeState) (s00.TimeToWait, aper.Snapshot) {
	return &v.capture
}
func BridgeTimeToWaitValueCodecFieldCompare(v *TimeToWaitValueCodec) *func(s00.TimeToWait, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTimeToWaitValueCodecFieldContext(v *TimeToWaitValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTimeToWaitValueCodecFieldDecode(v *TimeToWaitValueCodec) *func([]byte, aper.DecodeState) (s00.TimeToWait, error) {
	return &v.decode
}
func BridgeTimeToWaitValueCodecFieldEncode(v *TimeToWaitValueCodec) *func(s00.TimeToWait, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTimeToWaitValueCodecFieldPath(v *TimeToWaitValueCodec) *aper.Path { return &v.path }
func BridgeTimeToWaitValueCodecMethodEncodeBudgetValue(v TimeToWaitValueCodec, a0 s00.TimeToWait, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTimeToWaitValueCodecMethodEncodeChanged(v TimeToWaitValueCodec, a0 s00.TimeToWait, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTimeUEStayedInCellAPERValueFieldContext(v *TimeUEStayedInCellAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTimeUEStayedInCellAPERValueFieldReceived(v *TimeUEStayedInCellAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTimeUEStayedInCellAPERValueFieldReplay(v *TimeUEStayedInCellAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTimeUEStayedInCellAPERValueFieldWithoutReplay(v *TimeUEStayedInCellAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTimeUEStayedInCellEnhancedGranularityAPERValueFieldContext(v *TimeUEStayedInCellEnhancedGranularityAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTimeUEStayedInCellEnhancedGranularityAPERValueFieldReceived(v *TimeUEStayedInCellEnhancedGranularityAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTimeUEStayedInCellEnhancedGranularityAPERValueFieldReplay(v *TimeUEStayedInCellEnhancedGranularityAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTimeUEStayedInCellEnhancedGranularityAPERValueFieldWithoutReplay(v *TimeUEStayedInCellEnhancedGranularityAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTimeUEStayedInCellEnhancedGranularityValueCodecFieldCapture(v *TimeUEStayedInCellEnhancedGranularityValueCodec) *func(s00.TimeUEStayedInCellEnhancedGranularity, aper.DecodeState) (s00.TimeUEStayedInCellEnhancedGranularity, aper.Snapshot) {
	return &v.capture
}
func BridgeTimeUEStayedInCellEnhancedGranularityValueCodecFieldCompare(v *TimeUEStayedInCellEnhancedGranularityValueCodec) *func(s00.TimeUEStayedInCellEnhancedGranularity, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTimeUEStayedInCellEnhancedGranularityValueCodecFieldContext(v *TimeUEStayedInCellEnhancedGranularityValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTimeUEStayedInCellEnhancedGranularityValueCodecFieldDecode(v *TimeUEStayedInCellEnhancedGranularityValueCodec) *func([]byte, aper.DecodeState) (s00.TimeUEStayedInCellEnhancedGranularity, error) {
	return &v.decode
}
func BridgeTimeUEStayedInCellEnhancedGranularityValueCodecFieldEncode(v *TimeUEStayedInCellEnhancedGranularityValueCodec) *func(s00.TimeUEStayedInCellEnhancedGranularity, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTimeUEStayedInCellEnhancedGranularityValueCodecFieldPath(v *TimeUEStayedInCellEnhancedGranularityValueCodec) *aper.Path {
	return &v.path
}
func BridgeTimeUEStayedInCellEnhancedGranularityValueCodecMethodEncodeBudgetValue(v TimeUEStayedInCellEnhancedGranularityValueCodec, a0 s00.TimeUEStayedInCellEnhancedGranularity, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTimeUEStayedInCellEnhancedGranularityValueCodecMethodEncodeChanged(v TimeUEStayedInCellEnhancedGranularityValueCodec, a0 s00.TimeUEStayedInCellEnhancedGranularity, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTimeUEStayedInCellValueCodecFieldCapture(v *TimeUEStayedInCellValueCodec) *func(s00.TimeUEStayedInCell, aper.DecodeState) (s00.TimeUEStayedInCell, aper.Snapshot) {
	return &v.capture
}
func BridgeTimeUEStayedInCellValueCodecFieldCompare(v *TimeUEStayedInCellValueCodec) *func(s00.TimeUEStayedInCell, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTimeUEStayedInCellValueCodecFieldContext(v *TimeUEStayedInCellValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTimeUEStayedInCellValueCodecFieldDecode(v *TimeUEStayedInCellValueCodec) *func([]byte, aper.DecodeState) (s00.TimeUEStayedInCell, error) {
	return &v.decode
}
func BridgeTimeUEStayedInCellValueCodecFieldEncode(v *TimeUEStayedInCellValueCodec) *func(s00.TimeUEStayedInCell, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTimeUEStayedInCellValueCodecFieldPath(v *TimeUEStayedInCellValueCodec) *aper.Path {
	return &v.path
}
func BridgeTimeUEStayedInCellValueCodecMethodEncodeBudgetValue(v TimeUEStayedInCellValueCodec, a0 s00.TimeUEStayedInCell, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTimeUEStayedInCellValueCodecMethodEncodeChanged(v TimeUEStayedInCellValueCodec, a0 s00.TimeUEStayedInCell, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTraceDepthAPERValueFieldContext(v *TraceDepthAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceDepthAPERValueFieldReceived(v *TraceDepthAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTraceDepthAPERValueFieldReplay(v *TraceDepthAPERValue) *aper.Snapshot { return &v.replay }
func BridgeTraceDepthAPERValueFieldWithoutReplay(v *TraceDepthAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTraceDepthValueCodecFieldCapture(v *TraceDepthValueCodec) *func(s00.TraceDepth, aper.DecodeState) (s00.TraceDepth, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceDepthValueCodecFieldCompare(v *TraceDepthValueCodec) *func(s00.TraceDepth, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceDepthValueCodecFieldContext(v *TraceDepthValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceDepthValueCodecFieldDecode(v *TraceDepthValueCodec) *func([]byte, aper.DecodeState) (s00.TraceDepth, error) {
	return &v.decode
}
func BridgeTraceDepthValueCodecFieldEncode(v *TraceDepthValueCodec) *func(s00.TraceDepth, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceDepthValueCodecFieldPath(v *TraceDepthValueCodec) *aper.Path { return &v.path }
func BridgeTraceDepthValueCodecMethodEncodeBudgetValue(v TraceDepthValueCodec, a0 s00.TraceDepth, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTraceDepthValueCodecMethodEncodeChanged(v TraceDepthValueCodec, a0 s00.TraceDepth, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTrafficLoadReductionIndicationAPERValueFieldContext(v *TrafficLoadReductionIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTrafficLoadReductionIndicationAPERValueFieldReceived(v *TrafficLoadReductionIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTrafficLoadReductionIndicationAPERValueFieldReplay(v *TrafficLoadReductionIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTrafficLoadReductionIndicationAPERValueFieldWithoutReplay(v *TrafficLoadReductionIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTrafficLoadReductionIndicationValueCodecFieldCapture(v *TrafficLoadReductionIndicationValueCodec) *func(s00.TrafficLoadReductionIndication, aper.DecodeState) (s00.TrafficLoadReductionIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeTrafficLoadReductionIndicationValueCodecFieldCompare(v *TrafficLoadReductionIndicationValueCodec) *func(s00.TrafficLoadReductionIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTrafficLoadReductionIndicationValueCodecFieldContext(v *TrafficLoadReductionIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTrafficLoadReductionIndicationValueCodecFieldDecode(v *TrafficLoadReductionIndicationValueCodec) *func([]byte, aper.DecodeState) (s00.TrafficLoadReductionIndication, error) {
	return &v.decode
}
func BridgeTrafficLoadReductionIndicationValueCodecFieldEncode(v *TrafficLoadReductionIndicationValueCodec) *func(s00.TrafficLoadReductionIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTrafficLoadReductionIndicationValueCodecFieldPath(v *TrafficLoadReductionIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeTrafficLoadReductionIndicationValueCodecMethodEncodeBudgetValue(v TrafficLoadReductionIndicationValueCodec, a0 s00.TrafficLoadReductionIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTrafficLoadReductionIndicationValueCodecMethodEncodeChanged(v TrafficLoadReductionIndicationValueCodec, a0 s00.TrafficLoadReductionIndication, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTransportLayerAddressAPERValueFieldContext(v *TransportLayerAddressAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTransportLayerAddressAPERValueFieldReceived(v *TransportLayerAddressAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTransportLayerAddressAPERValueFieldReplay(v *TransportLayerAddressAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTransportLayerAddressAPERValueFieldWithoutReplay(v *TransportLayerAddressAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTransportLayerAddressValueCodecFieldCapture(v *TransportLayerAddressValueCodec) *func(s00.TransportLayerAddress, aper.DecodeState) (s00.TransportLayerAddress, aper.Snapshot) {
	return &v.capture
}
func BridgeTransportLayerAddressValueCodecFieldCompare(v *TransportLayerAddressValueCodec) *func(s00.TransportLayerAddress, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTransportLayerAddressValueCodecFieldContext(v *TransportLayerAddressValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTransportLayerAddressValueCodecFieldDecode(v *TransportLayerAddressValueCodec) *func([]byte, aper.DecodeState) (s00.TransportLayerAddress, error) {
	return &v.decode
}
func BridgeTransportLayerAddressValueCodecFieldEncode(v *TransportLayerAddressValueCodec) *func(s00.TransportLayerAddress, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTransportLayerAddressValueCodecFieldPath(v *TransportLayerAddressValueCodec) *aper.Path {
	return &v.path
}
func BridgeTransportLayerAddressValueCodecMethodEncodeBudgetValue(v TransportLayerAddressValueCodec, a0 s00.TransportLayerAddress, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTransportLayerAddressValueCodecMethodEncodeChanged(v TransportLayerAddressValueCodec, a0 s00.TransportLayerAddress, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTriggeringMessageAPERValueFieldContext(v *TriggeringMessageAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTriggeringMessageAPERValueFieldReceived(v *TriggeringMessageAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTriggeringMessageAPERValueFieldReplay(v *TriggeringMessageAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTriggeringMessageAPERValueFieldWithoutReplay(v *TriggeringMessageAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTriggeringMessageValueCodecFieldCapture(v *TriggeringMessageValueCodec) *func(s00.TriggeringMessage, aper.DecodeState) (s00.TriggeringMessage, aper.Snapshot) {
	return &v.capture
}
func BridgeTriggeringMessageValueCodecFieldCompare(v *TriggeringMessageValueCodec) *func(s00.TriggeringMessage, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTriggeringMessageValueCodecFieldContext(v *TriggeringMessageValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTriggeringMessageValueCodecFieldDecode(v *TriggeringMessageValueCodec) *func([]byte, aper.DecodeState) (s00.TriggeringMessage, error) {
	return &v.decode
}
func BridgeTriggeringMessageValueCodecFieldEncode(v *TriggeringMessageValueCodec) *func(s00.TriggeringMessage, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTriggeringMessageValueCodecFieldPath(v *TriggeringMessageValueCodec) *aper.Path {
	return &v.path
}
func BridgeTriggeringMessageValueCodecMethodEncodeBudgetValue(v TriggeringMessageValueCodec, a0 s00.TriggeringMessage, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTriggeringMessageValueCodecMethodEncodeChanged(v TriggeringMessageValueCodec, a0 s00.TriggeringMessage, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTypeOfErrorAPERValueFieldContext(v *TypeOfErrorAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTypeOfErrorAPERValueFieldReceived(v *TypeOfErrorAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTypeOfErrorAPERValueFieldReplay(v *TypeOfErrorAPERValue) *aper.Snapshot { return &v.replay }
func BridgeTypeOfErrorAPERValueFieldWithoutReplay(v *TypeOfErrorAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTypeOfErrorValueCodecFieldCapture(v *TypeOfErrorValueCodec) *func(s00.TypeOfError, aper.DecodeState) (s00.TypeOfError, aper.Snapshot) {
	return &v.capture
}
func BridgeTypeOfErrorValueCodecFieldCompare(v *TypeOfErrorValueCodec) *func(s00.TypeOfError, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTypeOfErrorValueCodecFieldContext(v *TypeOfErrorValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTypeOfErrorValueCodecFieldDecode(v *TypeOfErrorValueCodec) *func([]byte, aper.DecodeState) (s00.TypeOfError, error) {
	return &v.decode
}
func BridgeTypeOfErrorValueCodecFieldEncode(v *TypeOfErrorValueCodec) *func(s00.TypeOfError, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTypeOfErrorValueCodecFieldPath(v *TypeOfErrorValueCodec) *aper.Path { return &v.path }
func BridgeTypeOfErrorValueCodecMethodEncodeBudgetValue(v TypeOfErrorValueCodec, a0 s00.TypeOfError, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTypeOfErrorValueCodecMethodEncodeChanged(v TypeOfErrorValueCodec, a0 s00.TypeOfError, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEApplicationLayerMeasurementCapabilityAPERValueFieldContext(v *UEApplicationLayerMeasurementCapabilityAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEApplicationLayerMeasurementCapabilityAPERValueFieldReceived(v *UEApplicationLayerMeasurementCapabilityAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEApplicationLayerMeasurementCapabilityAPERValueFieldReplay(v *UEApplicationLayerMeasurementCapabilityAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEApplicationLayerMeasurementCapabilityAPERValueFieldWithoutReplay(v *UEApplicationLayerMeasurementCapabilityAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEApplicationLayerMeasurementCapabilityValueCodecFieldCapture(v *UEApplicationLayerMeasurementCapabilityValueCodec) *func(s00.UEApplicationLayerMeasurementCapability, aper.DecodeState) (s00.UEApplicationLayerMeasurementCapability, aper.Snapshot) {
	return &v.capture
}
func BridgeUEApplicationLayerMeasurementCapabilityValueCodecFieldCompare(v *UEApplicationLayerMeasurementCapabilityValueCodec) *func(s00.UEApplicationLayerMeasurementCapability, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEApplicationLayerMeasurementCapabilityValueCodecFieldContext(v *UEApplicationLayerMeasurementCapabilityValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEApplicationLayerMeasurementCapabilityValueCodecFieldDecode(v *UEApplicationLayerMeasurementCapabilityValueCodec) *func([]byte, aper.DecodeState) (s00.UEApplicationLayerMeasurementCapability, error) {
	return &v.decode
}
func BridgeUEApplicationLayerMeasurementCapabilityValueCodecFieldEncode(v *UEApplicationLayerMeasurementCapabilityValueCodec) *func(s00.UEApplicationLayerMeasurementCapability, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEApplicationLayerMeasurementCapabilityValueCodecFieldPath(v *UEApplicationLayerMeasurementCapabilityValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEApplicationLayerMeasurementCapabilityValueCodecMethodEncodeBudgetValue(v UEApplicationLayerMeasurementCapabilityValueCodec, a0 s00.UEApplicationLayerMeasurementCapability, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEApplicationLayerMeasurementCapabilityValueCodecMethodEncodeChanged(v UEApplicationLayerMeasurementCapabilityValueCodec, a0 s00.UEApplicationLayerMeasurementCapability, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUECapabilityInfoRequestAPERValueFieldContext(v *UECapabilityInfoRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUECapabilityInfoRequestAPERValueFieldReceived(v *UECapabilityInfoRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUECapabilityInfoRequestAPERValueFieldReplay(v *UECapabilityInfoRequestAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUECapabilityInfoRequestAPERValueFieldWithoutReplay(v *UECapabilityInfoRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUECapabilityInfoRequestValueCodecFieldCapture(v *UECapabilityInfoRequestValueCodec) *func(s00.UECapabilityInfoRequest, aper.DecodeState) (s00.UECapabilityInfoRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeUECapabilityInfoRequestValueCodecFieldCompare(v *UECapabilityInfoRequestValueCodec) *func(s00.UECapabilityInfoRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUECapabilityInfoRequestValueCodecFieldContext(v *UECapabilityInfoRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUECapabilityInfoRequestValueCodecFieldDecode(v *UECapabilityInfoRequestValueCodec) *func([]byte, aper.DecodeState) (s00.UECapabilityInfoRequest, error) {
	return &v.decode
}
func BridgeUECapabilityInfoRequestValueCodecFieldEncode(v *UECapabilityInfoRequestValueCodec) *func(s00.UECapabilityInfoRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUECapabilityInfoRequestValueCodecFieldPath(v *UECapabilityInfoRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeUECapabilityInfoRequestValueCodecMethodEncodeBudgetValue(v UECapabilityInfoRequestValueCodec, a0 s00.UECapabilityInfoRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUECapabilityInfoRequestValueCodecMethodEncodeChanged(v UECapabilityInfoRequestValueCodec, a0 s00.UECapabilityInfoRequest, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEHistoryInformationFromTheUEAPERValueFieldContext(v *UEHistoryInformationFromTheUEAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEHistoryInformationFromTheUEAPERValueFieldReceived(v *UEHistoryInformationFromTheUEAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEHistoryInformationFromTheUEAPERValueFieldReplay(v *UEHistoryInformationFromTheUEAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEHistoryInformationFromTheUEAPERValueFieldWithoutReplay(v *UEHistoryInformationFromTheUEAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEHistoryInformationFromTheUEValueCodecFieldCapture(v *UEHistoryInformationFromTheUEValueCodec) *func(s00.UEHistoryInformationFromTheUE, aper.DecodeState) (s00.UEHistoryInformationFromTheUE, aper.Snapshot) {
	return &v.capture
}
func BridgeUEHistoryInformationFromTheUEValueCodecFieldCompare(v *UEHistoryInformationFromTheUEValueCodec) *func(s00.UEHistoryInformationFromTheUE, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEHistoryInformationFromTheUEValueCodecFieldContext(v *UEHistoryInformationFromTheUEValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEHistoryInformationFromTheUEValueCodecFieldDecode(v *UEHistoryInformationFromTheUEValueCodec) *func([]byte, aper.DecodeState) (s00.UEHistoryInformationFromTheUE, error) {
	return &v.decode
}
func BridgeUEHistoryInformationFromTheUEValueCodecFieldEncode(v *UEHistoryInformationFromTheUEValueCodec) *func(s00.UEHistoryInformationFromTheUE, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEHistoryInformationFromTheUEValueCodecFieldPath(v *UEHistoryInformationFromTheUEValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEHistoryInformationFromTheUEValueCodecMethodEncodeBudgetValue(v UEHistoryInformationFromTheUEValueCodec, a0 s00.UEHistoryInformationFromTheUE, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEHistoryInformationFromTheUEValueCodecMethodEncodeChanged(v UEHistoryInformationFromTheUEValueCodec, a0 s00.UEHistoryInformationFromTheUE, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEIdentityIndexValueAPERValueFieldContext(v *UEIdentityIndexValueAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEIdentityIndexValueAPERValueFieldReceived(v *UEIdentityIndexValueAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEIdentityIndexValueAPERValueFieldReplay(v *UEIdentityIndexValueAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEIdentityIndexValueAPERValueFieldWithoutReplay(v *UEIdentityIndexValueAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEIdentityIndexValueValueCodecFieldCapture(v *UEIdentityIndexValueValueCodec) *func(s00.UEIdentityIndexValue, aper.DecodeState) (s00.UEIdentityIndexValue, aper.Snapshot) {
	return &v.capture
}
func BridgeUEIdentityIndexValueValueCodecFieldCompare(v *UEIdentityIndexValueValueCodec) *func(s00.UEIdentityIndexValue, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEIdentityIndexValueValueCodecFieldContext(v *UEIdentityIndexValueValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEIdentityIndexValueValueCodecFieldDecode(v *UEIdentityIndexValueValueCodec) *func([]byte, aper.DecodeState) (s00.UEIdentityIndexValue, error) {
	return &v.decode
}
func BridgeUEIdentityIndexValueValueCodecFieldEncode(v *UEIdentityIndexValueValueCodec) *func(s00.UEIdentityIndexValue, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEIdentityIndexValueValueCodecFieldPath(v *UEIdentityIndexValueValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEIdentityIndexValueValueCodecMethodEncodeBudgetValue(v UEIdentityIndexValueValueCodec, a0 s00.UEIdentityIndexValue, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEIdentityIndexValueValueCodecMethodEncodeChanged(v UEIdentityIndexValueValueCodec, a0 s00.UEIdentityIndexValue, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERLFReportContainerAPERValueFieldContext(v *UERLFReportContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERLFReportContainerAPERValueFieldReceived(v *UERLFReportContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERLFReportContainerAPERValueFieldReplay(v *UERLFReportContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERLFReportContainerAPERValueFieldWithoutReplay(v *UERLFReportContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERLFReportContainerForExtendedBandsAPERValueFieldContext(v *UERLFReportContainerForExtendedBandsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERLFReportContainerForExtendedBandsAPERValueFieldReceived(v *UERLFReportContainerForExtendedBandsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERLFReportContainerForExtendedBandsAPERValueFieldReplay(v *UERLFReportContainerForExtendedBandsAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERLFReportContainerForExtendedBandsAPERValueFieldWithoutReplay(v *UERLFReportContainerForExtendedBandsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERLFReportContainerForExtendedBandsValueCodecFieldCapture(v *UERLFReportContainerForExtendedBandsValueCodec) *func(s00.UERLFReportContainerForExtendedBands, aper.DecodeState) (s00.UERLFReportContainerForExtendedBands, aper.Snapshot) {
	return &v.capture
}
func BridgeUERLFReportContainerForExtendedBandsValueCodecFieldCompare(v *UERLFReportContainerForExtendedBandsValueCodec) *func(s00.UERLFReportContainerForExtendedBands, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERLFReportContainerForExtendedBandsValueCodecFieldContext(v *UERLFReportContainerForExtendedBandsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERLFReportContainerForExtendedBandsValueCodecFieldDecode(v *UERLFReportContainerForExtendedBandsValueCodec) *func([]byte, aper.DecodeState) (s00.UERLFReportContainerForExtendedBands, error) {
	return &v.decode
}
func BridgeUERLFReportContainerForExtendedBandsValueCodecFieldEncode(v *UERLFReportContainerForExtendedBandsValueCodec) *func(s00.UERLFReportContainerForExtendedBands, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERLFReportContainerForExtendedBandsValueCodecFieldPath(v *UERLFReportContainerForExtendedBandsValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERLFReportContainerForExtendedBandsValueCodecMethodEncodeBudgetValue(v UERLFReportContainerForExtendedBandsValueCodec, a0 s00.UERLFReportContainerForExtendedBands, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERLFReportContainerForExtendedBandsValueCodecMethodEncodeChanged(v UERLFReportContainerForExtendedBandsValueCodec, a0 s00.UERLFReportContainerForExtendedBands, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERLFReportContainerValueCodecFieldCapture(v *UERLFReportContainerValueCodec) *func(s00.UERLFReportContainer, aper.DecodeState) (s00.UERLFReportContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeUERLFReportContainerValueCodecFieldCompare(v *UERLFReportContainerValueCodec) *func(s00.UERLFReportContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERLFReportContainerValueCodecFieldContext(v *UERLFReportContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERLFReportContainerValueCodecFieldDecode(v *UERLFReportContainerValueCodec) *func([]byte, aper.DecodeState) (s00.UERLFReportContainer, error) {
	return &v.decode
}
func BridgeUERLFReportContainerValueCodecFieldEncode(v *UERLFReportContainerValueCodec) *func(s00.UERLFReportContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERLFReportContainerValueCodecFieldPath(v *UERLFReportContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERLFReportContainerValueCodecMethodEncodeBudgetValue(v UERLFReportContainerValueCodec, a0 s00.UERLFReportContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERLFReportContainerValueCodecMethodEncodeChanged(v UERLFReportContainerValueCodec, a0 s00.UERLFReportContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERadioCapabilityAPERValueFieldContext(v *UERadioCapabilityAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityAPERValueFieldReceived(v *UERadioCapabilityAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityAPERValueFieldReplay(v *UERadioCapabilityAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityAPERValueFieldWithoutReplay(v *UERadioCapabilityAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityForPagingAPERValueFieldContext(v *UERadioCapabilityForPagingAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityForPagingAPERValueFieldReceived(v *UERadioCapabilityForPagingAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityForPagingAPERValueFieldReplay(v *UERadioCapabilityForPagingAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityForPagingAPERValueFieldWithoutReplay(v *UERadioCapabilityForPagingAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityForPagingValueCodecFieldCapture(v *UERadioCapabilityForPagingValueCodec) *func(s00.UERadioCapabilityForPaging, aper.DecodeState) (s00.UERadioCapabilityForPaging, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityForPagingValueCodecFieldCompare(v *UERadioCapabilityForPagingValueCodec) *func(s00.UERadioCapabilityForPaging, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityForPagingValueCodecFieldContext(v *UERadioCapabilityForPagingValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityForPagingValueCodecFieldDecode(v *UERadioCapabilityForPagingValueCodec) *func([]byte, aper.DecodeState) (s00.UERadioCapabilityForPaging, error) {
	return &v.decode
}
func BridgeUERadioCapabilityForPagingValueCodecFieldEncode(v *UERadioCapabilityForPagingValueCodec) *func(s00.UERadioCapabilityForPaging, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityForPagingValueCodecFieldPath(v *UERadioCapabilityForPagingValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityForPagingValueCodecMethodEncodeBudgetValue(v UERadioCapabilityForPagingValueCodec, a0 s00.UERadioCapabilityForPaging, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERadioCapabilityForPagingValueCodecMethodEncodeChanged(v UERadioCapabilityForPagingValueCodec, a0 s00.UERadioCapabilityForPaging, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERadioCapabilityIDAPERValueFieldContext(v *UERadioCapabilityIDAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDAPERValueFieldReceived(v *UERadioCapabilityIDAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERadioCapabilityIDAPERValueFieldReplay(v *UERadioCapabilityIDAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERadioCapabilityIDAPERValueFieldWithoutReplay(v *UERadioCapabilityIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERadioCapabilityIDValueCodecFieldCapture(v *UERadioCapabilityIDValueCodec) *func(s00.UERadioCapabilityID, aper.DecodeState) (s00.UERadioCapabilityID, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityIDValueCodecFieldCompare(v *UERadioCapabilityIDValueCodec) *func(s00.UERadioCapabilityID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityIDValueCodecFieldContext(v *UERadioCapabilityIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityIDValueCodecFieldDecode(v *UERadioCapabilityIDValueCodec) *func([]byte, aper.DecodeState) (s00.UERadioCapabilityID, error) {
	return &v.decode
}
func BridgeUERadioCapabilityIDValueCodecFieldEncode(v *UERadioCapabilityIDValueCodec) *func(s00.UERadioCapabilityID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityIDValueCodecFieldPath(v *UERadioCapabilityIDValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityIDValueCodecMethodEncodeBudgetValue(v UERadioCapabilityIDValueCodec, a0 s00.UERadioCapabilityID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERadioCapabilityIDValueCodecMethodEncodeChanged(v UERadioCapabilityIDValueCodec, a0 s00.UERadioCapabilityID, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERadioCapabilityValueCodecFieldCapture(v *UERadioCapabilityValueCodec) *func(s00.UERadioCapability, aper.DecodeState) (s00.UERadioCapability, aper.Snapshot) {
	return &v.capture
}
func BridgeUERadioCapabilityValueCodecFieldCompare(v *UERadioCapabilityValueCodec) *func(s00.UERadioCapability, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERadioCapabilityValueCodecFieldContext(v *UERadioCapabilityValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERadioCapabilityValueCodecFieldDecode(v *UERadioCapabilityValueCodec) *func([]byte, aper.DecodeState) (s00.UERadioCapability, error) {
	return &v.decode
}
func BridgeUERadioCapabilityValueCodecFieldEncode(v *UERadioCapabilityValueCodec) *func(s00.UERadioCapability, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERadioCapabilityValueCodecFieldPath(v *UERadioCapabilityValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERadioCapabilityValueCodecMethodEncodeBudgetValue(v UERadioCapabilityValueCodec, a0 s00.UERadioCapability, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERadioCapabilityValueCodecMethodEncodeChanged(v UERadioCapabilityValueCodec, a0 s00.UERadioCapability, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUERetentionInformationAPERValueFieldContext(v *UERetentionInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERetentionInformationAPERValueFieldReceived(v *UERetentionInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUERetentionInformationAPERValueFieldReplay(v *UERetentionInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUERetentionInformationAPERValueFieldWithoutReplay(v *UERetentionInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUERetentionInformationValueCodecFieldCapture(v *UERetentionInformationValueCodec) *func(s00.UERetentionInformation, aper.DecodeState) (s00.UERetentionInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeUERetentionInformationValueCodecFieldCompare(v *UERetentionInformationValueCodec) *func(s00.UERetentionInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUERetentionInformationValueCodecFieldContext(v *UERetentionInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUERetentionInformationValueCodecFieldDecode(v *UERetentionInformationValueCodec) *func([]byte, aper.DecodeState) (s00.UERetentionInformation, error) {
	return &v.decode
}
func BridgeUERetentionInformationValueCodecFieldEncode(v *UERetentionInformationValueCodec) *func(s00.UERetentionInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUERetentionInformationValueCodecFieldPath(v *UERetentionInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeUERetentionInformationValueCodecMethodEncodeBudgetValue(v UERetentionInformationValueCodec, a0 s00.UERetentionInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUERetentionInformationValueCodecMethodEncodeChanged(v UERetentionInformationValueCodec, a0 s00.UERetentionInformation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEUsageTypeAPERValueFieldContext(v *UEUsageTypeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEUsageTypeAPERValueFieldReceived(v *UEUsageTypeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEUsageTypeAPERValueFieldReplay(v *UEUsageTypeAPERValue) *aper.Snapshot { return &v.replay }
func BridgeUEUsageTypeAPERValueFieldWithoutReplay(v *UEUsageTypeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEUsageTypeValueCodecFieldCapture(v *UEUsageTypeValueCodec) *func(s00.UEUsageType, aper.DecodeState) (s00.UEUsageType, aper.Snapshot) {
	return &v.capture
}
func BridgeUEUsageTypeValueCodecFieldCompare(v *UEUsageTypeValueCodec) *func(s00.UEUsageType, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEUsageTypeValueCodecFieldContext(v *UEUsageTypeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEUsageTypeValueCodecFieldDecode(v *UEUsageTypeValueCodec) *func([]byte, aper.DecodeState) (s00.UEUsageType, error) {
	return &v.decode
}
func BridgeUEUsageTypeValueCodecFieldEncode(v *UEUsageTypeValueCodec) *func(s00.UEUsageType, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEUsageTypeValueCodecFieldPath(v *UEUsageTypeValueCodec) *aper.Path { return &v.path }
func BridgeUEUsageTypeValueCodecMethodEncodeBudgetValue(v UEUsageTypeValueCodec, a0 s00.UEUsageType, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEUsageTypeValueCodecMethodEncodeChanged(v UEUsageTypeValueCodec, a0 s00.UEUsageType, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUEUserPlaneCIoTSupportIndicatorAPERValueFieldContext(v *UEUserPlaneCIoTSupportIndicatorAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEUserPlaneCIoTSupportIndicatorAPERValueFieldReceived(v *UEUserPlaneCIoTSupportIndicatorAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUEUserPlaneCIoTSupportIndicatorAPERValueFieldReplay(v *UEUserPlaneCIoTSupportIndicatorAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUEUserPlaneCIoTSupportIndicatorAPERValueFieldWithoutReplay(v *UEUserPlaneCIoTSupportIndicatorAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldCapture(v *UEUserPlaneCIoTSupportIndicatorValueCodec) *func(s00.UEUserPlaneCIoTSupportIndicator, aper.DecodeState) (s00.UEUserPlaneCIoTSupportIndicator, aper.Snapshot) {
	return &v.capture
}
func BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldCompare(v *UEUserPlaneCIoTSupportIndicatorValueCodec) *func(s00.UEUserPlaneCIoTSupportIndicator, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldContext(v *UEUserPlaneCIoTSupportIndicatorValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldDecode(v *UEUserPlaneCIoTSupportIndicatorValueCodec) *func([]byte, aper.DecodeState) (s00.UEUserPlaneCIoTSupportIndicator, error) {
	return &v.decode
}
func BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldEncode(v *UEUserPlaneCIoTSupportIndicatorValueCodec) *func(s00.UEUserPlaneCIoTSupportIndicator, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldPath(v *UEUserPlaneCIoTSupportIndicatorValueCodec) *aper.Path {
	return &v.path
}
func BridgeUEUserPlaneCIoTSupportIndicatorValueCodecMethodEncodeBudgetValue(v UEUserPlaneCIoTSupportIndicatorValueCodec, a0 s00.UEUserPlaneCIoTSupportIndicator, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUEUserPlaneCIoTSupportIndicatorValueCodecMethodEncodeChanged(v UEUserPlaneCIoTSupportIndicatorValueCodec, a0 s00.UEUserPlaneCIoTSupportIndicator, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeULNASCountAPERValueFieldContext(v *ULNASCountAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeULNASCountAPERValueFieldReceived(v *ULNASCountAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeULNASCountAPERValueFieldReplay(v *ULNASCountAPERValue) *aper.Snapshot { return &v.replay }
func BridgeULNASCountAPERValueFieldWithoutReplay(v *ULNASCountAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeULNASCountValueCodecFieldCapture(v *ULNASCountValueCodec) *func(s00.ULNASCount, aper.DecodeState) (s00.ULNASCount, aper.Snapshot) {
	return &v.capture
}
func BridgeULNASCountValueCodecFieldCompare(v *ULNASCountValueCodec) *func(s00.ULNASCount, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeULNASCountValueCodecFieldContext(v *ULNASCountValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeULNASCountValueCodecFieldDecode(v *ULNASCountValueCodec) *func([]byte, aper.DecodeState) (s00.ULNASCount, error) {
	return &v.decode
}
func BridgeULNASCountValueCodecFieldEncode(v *ULNASCountValueCodec) *func(s00.ULNASCount, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeULNASCountValueCodecFieldPath(v *ULNASCountValueCodec) *aper.Path { return &v.path }
func BridgeULNASCountValueCodecMethodEncodeBudgetValue(v ULNASCountValueCodec, a0 s00.ULNASCount, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeULNASCountValueCodecMethodEncodeChanged(v ULNASCountValueCodec, a0 s00.ULNASCount, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeULNASMACAPERValueFieldContext(v *ULNASMACAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeULNASMACAPERValueFieldReceived(v *ULNASMACAPERValue) *aper.WireSpan { return &v.received }
func BridgeULNASMACAPERValueFieldReplay(v *ULNASMACAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeULNASMACAPERValueFieldWithoutReplay(v *ULNASMACAPERValue) *bool     { return &v.withoutReplay }
func BridgeULNASMACValueCodecFieldCapture(v *ULNASMACValueCodec) *func(s00.ULNASMAC, aper.DecodeState) (s00.ULNASMAC, aper.Snapshot) {
	return &v.capture
}
func BridgeULNASMACValueCodecFieldCompare(v *ULNASMACValueCodec) *func(s00.ULNASMAC, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeULNASMACValueCodecFieldContext(v *ULNASMACValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeULNASMACValueCodecFieldDecode(v *ULNASMACValueCodec) *func([]byte, aper.DecodeState) (s00.ULNASMAC, error) {
	return &v.decode
}
func BridgeULNASMACValueCodecFieldEncode(v *ULNASMACValueCodec) *func(s00.ULNASMAC, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeULNASMACValueCodecFieldPath(v *ULNASMACValueCodec) *aper.Path { return &v.path }
func BridgeULNASMACValueCodecMethodEncodeBudgetValue(v ULNASMACValueCodec, a0 s00.ULNASMAC, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeULNASMACValueCodecMethodEncodeChanged(v ULNASMACValueCodec, a0 s00.ULNASMAC, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeURIAddressAPERValueFieldContext(v *URIAddressAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeURIAddressAPERValueFieldReceived(v *URIAddressAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeURIAddressAPERValueFieldReplay(v *URIAddressAPERValue) *aper.Snapshot { return &v.replay }
func BridgeURIAddressAPERValueFieldWithoutReplay(v *URIAddressAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeURIAddressValueCodecFieldCapture(v *URIAddressValueCodec) *func(s00.URIAddress, aper.DecodeState) (s00.URIAddress, aper.Snapshot) {
	return &v.capture
}
func BridgeURIAddressValueCodecFieldCompare(v *URIAddressValueCodec) *func(s00.URIAddress, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeURIAddressValueCodecFieldContext(v *URIAddressValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeURIAddressValueCodecFieldDecode(v *URIAddressValueCodec) *func([]byte, aper.DecodeState) (s00.URIAddress, error) {
	return &v.decode
}
func BridgeURIAddressValueCodecFieldEncode(v *URIAddressValueCodec) *func(s00.URIAddress, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeURIAddressValueCodecFieldPath(v *URIAddressValueCodec) *aper.Path { return &v.path }
func BridgeURIAddressValueCodecMethodEncodeBudgetValue(v URIAddressValueCodec, a0 s00.URIAddress, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeURIAddressValueCodecMethodEncodeChanged(v URIAddressValueCodec, a0 s00.URIAddress, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUnlicensedSpectrumRestrictionAPERValueFieldContext(v *UnlicensedSpectrumRestrictionAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUnlicensedSpectrumRestrictionAPERValueFieldReceived(v *UnlicensedSpectrumRestrictionAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeUnlicensedSpectrumRestrictionAPERValueFieldReplay(v *UnlicensedSpectrumRestrictionAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUnlicensedSpectrumRestrictionAPERValueFieldWithoutReplay(v *UnlicensedSpectrumRestrictionAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeUnlicensedSpectrumRestrictionValueCodecFieldCapture(v *UnlicensedSpectrumRestrictionValueCodec) *func(s00.UnlicensedSpectrumRestriction, aper.DecodeState) (s00.UnlicensedSpectrumRestriction, aper.Snapshot) {
	return &v.capture
}
func BridgeUnlicensedSpectrumRestrictionValueCodecFieldCompare(v *UnlicensedSpectrumRestrictionValueCodec) *func(s00.UnlicensedSpectrumRestriction, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeUnlicensedSpectrumRestrictionValueCodecFieldContext(v *UnlicensedSpectrumRestrictionValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUnlicensedSpectrumRestrictionValueCodecFieldDecode(v *UnlicensedSpectrumRestrictionValueCodec) *func([]byte, aper.DecodeState) (s00.UnlicensedSpectrumRestriction, error) {
	return &v.decode
}
func BridgeUnlicensedSpectrumRestrictionValueCodecFieldEncode(v *UnlicensedSpectrumRestrictionValueCodec) *func(s00.UnlicensedSpectrumRestriction, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUnlicensedSpectrumRestrictionValueCodecFieldPath(v *UnlicensedSpectrumRestrictionValueCodec) *aper.Path {
	return &v.path
}
func BridgeUnlicensedSpectrumRestrictionValueCodecMethodEncodeBudgetValue(v UnlicensedSpectrumRestrictionValueCodec, a0 s00.UnlicensedSpectrumRestriction, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeUnlicensedSpectrumRestrictionValueCodecMethodEncodeChanged(v UnlicensedSpectrumRestrictionValueCodec, a0 s00.UnlicensedSpectrumRestriction, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeVehicleUEAPERValueFieldContext(v *VehicleUEAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeVehicleUEAPERValueFieldReceived(v *VehicleUEAPERValue) *aper.WireSpan { return &v.received }
func BridgeVehicleUEAPERValueFieldReplay(v *VehicleUEAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeVehicleUEAPERValueFieldWithoutReplay(v *VehicleUEAPERValue) *bool     { return &v.withoutReplay }
func BridgeVehicleUEValueCodecFieldCapture(v *VehicleUEValueCodec) *func(s00.VehicleUE, aper.DecodeState) (s00.VehicleUE, aper.Snapshot) {
	return &v.capture
}
func BridgeVehicleUEValueCodecFieldCompare(v *VehicleUEValueCodec) *func(s00.VehicleUE, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeVehicleUEValueCodecFieldContext(v *VehicleUEValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeVehicleUEValueCodecFieldDecode(v *VehicleUEValueCodec) *func([]byte, aper.DecodeState) (s00.VehicleUE, error) {
	return &v.decode
}
func BridgeVehicleUEValueCodecFieldEncode(v *VehicleUEValueCodec) *func(s00.VehicleUE, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeVehicleUEValueCodecFieldPath(v *VehicleUEValueCodec) *aper.Path { return &v.path }
func BridgeVehicleUEValueCodecMethodEncodeBudgetValue(v VehicleUEValueCodec, a0 s00.VehicleUE, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeVehicleUEValueCodecMethodEncodeChanged(v VehicleUEValueCodec, a0 s00.VehicleUE, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeVoiceSupportMatchIndicatorAPERValueFieldContext(v *VoiceSupportMatchIndicatorAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeVoiceSupportMatchIndicatorAPERValueFieldReceived(v *VoiceSupportMatchIndicatorAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeVoiceSupportMatchIndicatorAPERValueFieldReplay(v *VoiceSupportMatchIndicatorAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeVoiceSupportMatchIndicatorAPERValueFieldWithoutReplay(v *VoiceSupportMatchIndicatorAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeVoiceSupportMatchIndicatorValueCodecFieldCapture(v *VoiceSupportMatchIndicatorValueCodec) *func(s00.VoiceSupportMatchIndicator, aper.DecodeState) (s00.VoiceSupportMatchIndicator, aper.Snapshot) {
	return &v.capture
}
func BridgeVoiceSupportMatchIndicatorValueCodecFieldCompare(v *VoiceSupportMatchIndicatorValueCodec) *func(s00.VoiceSupportMatchIndicator, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeVoiceSupportMatchIndicatorValueCodecFieldContext(v *VoiceSupportMatchIndicatorValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeVoiceSupportMatchIndicatorValueCodecFieldDecode(v *VoiceSupportMatchIndicatorValueCodec) *func([]byte, aper.DecodeState) (s00.VoiceSupportMatchIndicator, error) {
	return &v.decode
}
func BridgeVoiceSupportMatchIndicatorValueCodecFieldEncode(v *VoiceSupportMatchIndicatorValueCodec) *func(s00.VoiceSupportMatchIndicator, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeVoiceSupportMatchIndicatorValueCodecFieldPath(v *VoiceSupportMatchIndicatorValueCodec) *aper.Path {
	return &v.path
}
func BridgeVoiceSupportMatchIndicatorValueCodecMethodEncodeBudgetValue(v VoiceSupportMatchIndicatorValueCodec, a0 s00.VoiceSupportMatchIndicator, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeVoiceSupportMatchIndicatorValueCodecMethodEncodeChanged(v VoiceSupportMatchIndicatorValueCodec, a0 s00.VoiceSupportMatchIndicator, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANMeasConfigAPERValueFieldContext(v *WLANMeasConfigAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasConfigAPERValueFieldReceived(v *WLANMeasConfigAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWLANMeasConfigAPERValueFieldReplay(v *WLANMeasConfigAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasConfigAPERValueFieldWithoutReplay(v *WLANMeasConfigAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasConfigNameListAPERValueFieldContext(v *WLANMeasConfigNameListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasConfigNameListAPERValueFieldReceived(v *WLANMeasConfigNameListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWLANMeasConfigNameListAPERValueFieldReplay(v *WLANMeasConfigNameListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasConfigNameListAPERValueFieldWithoutReplay(v *WLANMeasConfigNameListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasConfigNameListValueCodecFieldCapture(v *WLANMeasConfigNameListValueCodec) *func(s00.WLANMeasConfigNameList, aper.DecodeState) (s00.WLANMeasConfigNameList, aper.Snapshot) {
	return &v.capture
}
func BridgeWLANMeasConfigNameListValueCodecFieldCompare(v *WLANMeasConfigNameListValueCodec) *func(s00.WLANMeasConfigNameList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWLANMeasConfigNameListValueCodecFieldContext(v *WLANMeasConfigNameListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasConfigNameListValueCodecFieldDecode(v *WLANMeasConfigNameListValueCodec) *func([]byte, aper.DecodeState) (s00.WLANMeasConfigNameList, error) {
	return &v.decode
}
func BridgeWLANMeasConfigNameListValueCodecFieldEncode(v *WLANMeasConfigNameListValueCodec) *func(s00.WLANMeasConfigNameList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANMeasConfigNameListValueCodecFieldPath(v *WLANMeasConfigNameListValueCodec) *aper.Path {
	return &v.path
}
func BridgeWLANMeasConfigNameListValueCodecMethodEncodeBudgetValue(v WLANMeasConfigNameListValueCodec, a0 s00.WLANMeasConfigNameList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWLANMeasConfigNameListValueCodecMethodEncodeChanged(v WLANMeasConfigNameListValueCodec, a0 s00.WLANMeasConfigNameList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANMeasConfigValueCodecFieldCapture(v *WLANMeasConfigValueCodec) *func(s00.WLANMeasConfig, aper.DecodeState) (s00.WLANMeasConfig, aper.Snapshot) {
	return &v.capture
}
func BridgeWLANMeasConfigValueCodecFieldCompare(v *WLANMeasConfigValueCodec) *func(s00.WLANMeasConfig, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWLANMeasConfigValueCodecFieldContext(v *WLANMeasConfigValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasConfigValueCodecFieldDecode(v *WLANMeasConfigValueCodec) *func([]byte, aper.DecodeState) (s00.WLANMeasConfig, error) {
	return &v.decode
}
func BridgeWLANMeasConfigValueCodecFieldEncode(v *WLANMeasConfigValueCodec) *func(s00.WLANMeasConfig, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANMeasConfigValueCodecFieldPath(v *WLANMeasConfigValueCodec) *aper.Path { return &v.path }
func BridgeWLANMeasConfigValueCodecMethodEncodeBudgetValue(v WLANMeasConfigValueCodec, a0 s00.WLANMeasConfig, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWLANMeasConfigValueCodecMethodEncodeChanged(v WLANMeasConfigValueCodec, a0 s00.WLANMeasConfig, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANNameAPERValueFieldContext(v *WLANNameAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANNameAPERValueFieldReceived(v *WLANNameAPERValue) *aper.WireSpan { return &v.received }
func BridgeWLANNameAPERValueFieldReplay(v *WLANNameAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeWLANNameAPERValueFieldWithoutReplay(v *WLANNameAPERValue) *bool     { return &v.withoutReplay }
func BridgeWLANNameValueCodecFieldCapture(v *WLANNameValueCodec) *func(s00.WLANName, aper.DecodeState) (s00.WLANName, aper.Snapshot) {
	return &v.capture
}
func BridgeWLANNameValueCodecFieldCompare(v *WLANNameValueCodec) *func(s00.WLANName, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWLANNameValueCodecFieldContext(v *WLANNameValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANNameValueCodecFieldDecode(v *WLANNameValueCodec) *func([]byte, aper.DecodeState) (s00.WLANName, error) {
	return &v.decode
}
func BridgeWLANNameValueCodecFieldEncode(v *WLANNameValueCodec) *func(s00.WLANName, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANNameValueCodecFieldPath(v *WLANNameValueCodec) *aper.Path { return &v.path }
func BridgeWLANNameValueCodecMethodEncodeBudgetValue(v WLANNameValueCodec, a0 s00.WLANName, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWLANNameValueCodecMethodEncodeChanged(v WLANNameValueCodec, a0 s00.WLANName, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWarningAreaCoordinatesAPERValueFieldContext(v *WarningAreaCoordinatesAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWarningAreaCoordinatesAPERValueFieldReceived(v *WarningAreaCoordinatesAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWarningAreaCoordinatesAPERValueFieldReplay(v *WarningAreaCoordinatesAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWarningAreaCoordinatesAPERValueFieldWithoutReplay(v *WarningAreaCoordinatesAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWarningAreaCoordinatesValueCodecFieldCapture(v *WarningAreaCoordinatesValueCodec) *func(s00.WarningAreaCoordinates, aper.DecodeState) (s00.WarningAreaCoordinates, aper.Snapshot) {
	return &v.capture
}
func BridgeWarningAreaCoordinatesValueCodecFieldCompare(v *WarningAreaCoordinatesValueCodec) *func(s00.WarningAreaCoordinates, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWarningAreaCoordinatesValueCodecFieldContext(v *WarningAreaCoordinatesValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWarningAreaCoordinatesValueCodecFieldDecode(v *WarningAreaCoordinatesValueCodec) *func([]byte, aper.DecodeState) (s00.WarningAreaCoordinates, error) {
	return &v.decode
}
func BridgeWarningAreaCoordinatesValueCodecFieldEncode(v *WarningAreaCoordinatesValueCodec) *func(s00.WarningAreaCoordinates, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWarningAreaCoordinatesValueCodecFieldPath(v *WarningAreaCoordinatesValueCodec) *aper.Path {
	return &v.path
}
func BridgeWarningAreaCoordinatesValueCodecMethodEncodeBudgetValue(v WarningAreaCoordinatesValueCodec, a0 s00.WarningAreaCoordinates, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWarningAreaCoordinatesValueCodecMethodEncodeChanged(v WarningAreaCoordinatesValueCodec, a0 s00.WarningAreaCoordinates, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWarningMessageContentsAPERValueFieldContext(v *WarningMessageContentsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWarningMessageContentsAPERValueFieldReceived(v *WarningMessageContentsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWarningMessageContentsAPERValueFieldReplay(v *WarningMessageContentsAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWarningMessageContentsAPERValueFieldWithoutReplay(v *WarningMessageContentsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWarningMessageContentsValueCodecFieldCapture(v *WarningMessageContentsValueCodec) *func(s00.WarningMessageContents, aper.DecodeState) (s00.WarningMessageContents, aper.Snapshot) {
	return &v.capture
}
func BridgeWarningMessageContentsValueCodecFieldCompare(v *WarningMessageContentsValueCodec) *func(s00.WarningMessageContents, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWarningMessageContentsValueCodecFieldContext(v *WarningMessageContentsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWarningMessageContentsValueCodecFieldDecode(v *WarningMessageContentsValueCodec) *func([]byte, aper.DecodeState) (s00.WarningMessageContents, error) {
	return &v.decode
}
func BridgeWarningMessageContentsValueCodecFieldEncode(v *WarningMessageContentsValueCodec) *func(s00.WarningMessageContents, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWarningMessageContentsValueCodecFieldPath(v *WarningMessageContentsValueCodec) *aper.Path {
	return &v.path
}
func BridgeWarningMessageContentsValueCodecMethodEncodeBudgetValue(v WarningMessageContentsValueCodec, a0 s00.WarningMessageContents, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWarningMessageContentsValueCodecMethodEncodeChanged(v WarningMessageContentsValueCodec, a0 s00.WarningMessageContents, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWarningSecurityInfoAPERValueFieldContext(v *WarningSecurityInfoAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWarningSecurityInfoAPERValueFieldReceived(v *WarningSecurityInfoAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWarningSecurityInfoAPERValueFieldReplay(v *WarningSecurityInfoAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWarningSecurityInfoAPERValueFieldWithoutReplay(v *WarningSecurityInfoAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWarningSecurityInfoValueCodecFieldCapture(v *WarningSecurityInfoValueCodec) *func(s00.WarningSecurityInfo, aper.DecodeState) (s00.WarningSecurityInfo, aper.Snapshot) {
	return &v.capture
}
func BridgeWarningSecurityInfoValueCodecFieldCompare(v *WarningSecurityInfoValueCodec) *func(s00.WarningSecurityInfo, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWarningSecurityInfoValueCodecFieldContext(v *WarningSecurityInfoValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWarningSecurityInfoValueCodecFieldDecode(v *WarningSecurityInfoValueCodec) *func([]byte, aper.DecodeState) (s00.WarningSecurityInfo, error) {
	return &v.decode
}
func BridgeWarningSecurityInfoValueCodecFieldEncode(v *WarningSecurityInfoValueCodec) *func(s00.WarningSecurityInfo, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWarningSecurityInfoValueCodecFieldPath(v *WarningSecurityInfoValueCodec) *aper.Path {
	return &v.path
}
func BridgeWarningSecurityInfoValueCodecMethodEncodeBudgetValue(v WarningSecurityInfoValueCodec, a0 s00.WarningSecurityInfo, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWarningSecurityInfoValueCodecMethodEncodeChanged(v WarningSecurityInfoValueCodec, a0 s00.WarningSecurityInfo, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWarningTypeAPERValueFieldContext(v *WarningTypeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWarningTypeAPERValueFieldReceived(v *WarningTypeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWarningTypeAPERValueFieldReplay(v *WarningTypeAPERValue) *aper.Snapshot { return &v.replay }
func BridgeWarningTypeAPERValueFieldWithoutReplay(v *WarningTypeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWarningTypeValueCodecFieldCapture(v *WarningTypeValueCodec) *func(s00.WarningType, aper.DecodeState) (s00.WarningType, aper.Snapshot) {
	return &v.capture
}
func BridgeWarningTypeValueCodecFieldCompare(v *WarningTypeValueCodec) *func(s00.WarningType, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeWarningTypeValueCodecFieldContext(v *WarningTypeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWarningTypeValueCodecFieldDecode(v *WarningTypeValueCodec) *func([]byte, aper.DecodeState) (s00.WarningType, error) {
	return &v.decode
}
func BridgeWarningTypeValueCodecFieldEncode(v *WarningTypeValueCodec) *func(s00.WarningType, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWarningTypeValueCodecFieldPath(v *WarningTypeValueCodec) *aper.Path { return &v.path }
func BridgeWarningTypeValueCodecMethodEncodeBudgetValue(v WarningTypeValueCodec, a0 s00.WarningType, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeWarningTypeValueCodecMethodEncodeChanged(v WarningTypeValueCodec, a0 s00.WarningType, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
