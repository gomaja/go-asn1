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

// RequestTypeAdditionalInfoValueCodec is the concrete ValueCodec[RequestTypeAdditionalInfo].
type RequestTypeAdditionalInfoValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.RequestTypeAdditionalInfo,

		error)
	encode func(s00.RequestTypeAdditionalInfo,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.RequestTypeAdditionalInfo, aper.DecodeState,

	) (s00.RequestTypeAdditionalInfo, aper.Snapshot,

	)
	compare func(s00.RequestTypeAdditionalInfo, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RequestTypeAdditionalInfoValueCodec) New(value s00.RequestTypeAdditionalInfo,

) (RequestTypeAdditionalInfoAPERValue, error) {
	if c.encode == nil {
		return RequestTypeAdditionalInfoAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RequestTypeAdditionalInfoAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RequestTypeAdditionalInfoAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RequestTypeAdditionalInfoAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RequestTypeAdditionalInfoValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RequestTypeAdditionalInfoAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RequestTypeAdditionalInfoAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RequestTypeAdditionalInfoAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RequestTypeAdditionalInfoAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RequestTypeAdditionalInfoAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RequestTypeAdditionalInfoValueCodec) EncodeAPER(value RequestTypeAdditionalInfoAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RequestTypeAdditionalInfoValueCodec) encodeBudgetValue(value s00.RequestTypeAdditionalInfo,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RequestTypeAdditionalInfoValueCodec) encodeChanged(value s00.RequestTypeAdditionalInfo,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// S1APIEsMobilityInformationValueCodec is the concrete ValueCodec[S1APIEsMobilityInformation].
type S1APIEsMobilityInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.S1APIEsMobilityInformation,

		error)
	encode func(s00.S1APIEsMobilityInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.S1APIEsMobilityInformation, aper.DecodeState,

	) (s00.S1APIEsMobilityInformation, aper.Snapshot,

	)
	compare func(s00.S1APIEsMobilityInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c S1APIEsMobilityInformationValueCodec) New(value s00.S1APIEsMobilityInformation,

) (S1APIEsMobilityInformationAPERValue, error) {
	if c.encode == nil {
		return S1APIEsMobilityInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return S1APIEsMobilityInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return S1APIEsMobilityInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return S1APIEsMobilityInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c S1APIEsMobilityInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (S1APIEsMobilityInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return S1APIEsMobilityInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return S1APIEsMobilityInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return S1APIEsMobilityInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return S1APIEsMobilityInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c S1APIEsMobilityInformationValueCodec) EncodeAPER(value S1APIEsMobilityInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c S1APIEsMobilityInformationValueCodec) encodeBudgetValue(value s00.S1APIEsMobilityInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c S1APIEsMobilityInformationValueCodec) encodeChanged(value s00.S1APIEsMobilityInformation,

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

// ServiceTypeValueCodec is the concrete ValueCodec[ServiceType].
type ServiceTypeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ServiceType,

		error)
	encode func(s00.ServiceType,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ServiceType, aper.DecodeState,

	) (s00.ServiceType, aper.Snapshot,

	)
	compare func(s00.ServiceType, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ServiceTypeValueCodec) New(value s00.ServiceType,

) (ServiceTypeAPERValue, error) {
	if c.encode == nil {
		return ServiceTypeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ServiceTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ServiceTypeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ServiceTypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ServiceTypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ServiceTypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ServiceTypeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ServiceTypeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ServiceTypeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ServiceTypeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ServiceTypeValueCodec) EncodeAPER(value ServiceTypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ServiceTypeValueCodec) encodeBudgetValue(value s00.ServiceType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ServiceTypeValueCodec) encodeChanged(value s00.ServiceType,

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

// SubscriberProfileIDforRFPValueCodec is the concrete ValueCodec[SubscriberProfileIDforRFP].
type SubscriberProfileIDforRFPValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.SubscriberProfileIDforRFP,

		error)
	encode func(s00.SubscriberProfileIDforRFP,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.SubscriberProfileIDforRFP, aper.DecodeState,

	) (s00.SubscriberProfileIDforRFP, aper.Snapshot,

	)
	compare func(s00.SubscriberProfileIDforRFP, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SubscriberProfileIDforRFPValueCodec) New(value s00.SubscriberProfileIDforRFP,

) (SubscriberProfileIDforRFPAPERValue, error) {
	if c.encode == nil {
		return SubscriberProfileIDforRFPAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SubscriberProfileIDforRFPAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SubscriberProfileIDforRFPAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SubscriberProfileIDforRFPAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SubscriberProfileIDforRFPValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SubscriberProfileIDforRFPAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SubscriberProfileIDforRFPAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SubscriberProfileIDforRFPAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SubscriberProfileIDforRFPAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SubscriberProfileIDforRFPAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SubscriberProfileIDforRFPValueCodec) EncodeAPER(value SubscriberProfileIDforRFPAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SubscriberProfileIDforRFPValueCodec) encodeBudgetValue(value s00.SubscriberProfileIDforRFP,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SubscriberProfileIDforRFPValueCodec) encodeChanged(value s00.SubscriberProfileIDforRFP,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SRVCCOperationPossibleValueCodec is the concrete ValueCodec[SRVCCOperationPossible].
type SRVCCOperationPossibleValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.SRVCCOperationPossible,

		error)
	encode func(s00.SRVCCOperationPossible,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.SRVCCOperationPossible, aper.DecodeState,

	) (s00.SRVCCOperationPossible, aper.Snapshot,

	)
	compare func(s00.SRVCCOperationPossible, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SRVCCOperationPossibleValueCodec) New(value s00.SRVCCOperationPossible,

) (SRVCCOperationPossibleAPERValue, error) {
	if c.encode == nil {
		return SRVCCOperationPossibleAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SRVCCOperationPossibleAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SRVCCOperationPossibleAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SRVCCOperationPossibleAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SRVCCOperationPossibleValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SRVCCOperationPossibleAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SRVCCOperationPossibleAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SRVCCOperationPossibleAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SRVCCOperationPossibleAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SRVCCOperationPossibleAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SRVCCOperationPossibleValueCodec) EncodeAPER(value SRVCCOperationPossibleAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SRVCCOperationPossibleValueCodec) encodeBudgetValue(value s00.SRVCCOperationPossible,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SRVCCOperationPossibleValueCodec) encodeChanged(value s00.SRVCCOperationPossible,

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

// RoutingIDValueCodec is the concrete ValueCodec[RoutingID].
type RoutingIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.RoutingID,

		error)
	encode func(s00.RoutingID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.RoutingID, aper.DecodeState,

	) (s00.RoutingID, aper.Snapshot,

	)
	compare func(s00.RoutingID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RoutingIDValueCodec) New(value s00.RoutingID,

) (RoutingIDAPERValue, error) {
	if c.encode == nil {
		return RoutingIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RoutingIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RoutingIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RoutingIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RoutingIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RoutingIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RoutingIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RoutingIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RoutingIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RoutingIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RoutingIDValueCodec) EncodeAPER(value RoutingIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RoutingIDValueCodec) encodeBudgetValue(value s00.RoutingID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RoutingIDValueCodec) encodeChanged(value s00.RoutingID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecondaryRATDataUsageRequestValueCodec is the concrete ValueCodec[SecondaryRATDataUsageRequest].
type SecondaryRATDataUsageRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.SecondaryRATDataUsageRequest,

		error)
	encode func(s00.SecondaryRATDataUsageRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.SecondaryRATDataUsageRequest, aper.DecodeState,

	) (s00.SecondaryRATDataUsageRequest, aper.Snapshot,

	)
	compare func(s00.SecondaryRATDataUsageRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecondaryRATDataUsageRequestValueCodec) New(value s00.SecondaryRATDataUsageRequest,

) (SecondaryRATDataUsageRequestAPERValue, error) {
	if c.encode == nil {
		return SecondaryRATDataUsageRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATDataUsageRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecondaryRATDataUsageRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecondaryRATDataUsageRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecondaryRATDataUsageRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecondaryRATDataUsageRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecondaryRATDataUsageRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecondaryRATDataUsageRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecondaryRATDataUsageRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecondaryRATDataUsageRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecondaryRATDataUsageRequestValueCodec) EncodeAPER(value SecondaryRATDataUsageRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SecondaryRATDataUsageRequestValueCodec) encodeBudgetValue(value s00.SecondaryRATDataUsageRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecondaryRATDataUsageRequestValueCodec) encodeChanged(value s00.SecondaryRATDataUsageRequest,

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

// TargetToSourceTransparentContainerValueCodec is the concrete ValueCodec[TargetToSourceTransparentContainer].
type TargetToSourceTransparentContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TargetToSourceTransparentContainer,

		error)
	encode func(s00.TargetToSourceTransparentContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TargetToSourceTransparentContainer, aper.DecodeState,

	) (s00.TargetToSourceTransparentContainer, aper.Snapshot,

	)
	compare func(s00.TargetToSourceTransparentContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TargetToSourceTransparentContainerValueCodec) New(value s00.TargetToSourceTransparentContainer,

) (TargetToSourceTransparentContainerAPERValue, error) {
	if c.encode == nil {
		return TargetToSourceTransparentContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargetToSourceTransparentContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TargetToSourceTransparentContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TargetToSourceTransparentContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TargetToSourceTransparentContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TargetToSourceTransparentContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TargetToSourceTransparentContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TargetToSourceTransparentContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TargetToSourceTransparentContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TargetToSourceTransparentContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TargetToSourceTransparentContainerValueCodec) EncodeAPER(value TargetToSourceTransparentContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TargetToSourceTransparentContainerValueCodec) encodeBudgetValue(value s00.TargetToSourceTransparentContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TargetToSourceTransparentContainerValueCodec) encodeChanged(value s00.TargetToSourceTransparentContainer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceToTargetTransparentContainerValueCodec is the concrete ValueCodec[SourceToTargetTransparentContainer].
type SourceToTargetTransparentContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.SourceToTargetTransparentContainer,

		error)
	encode func(s00.SourceToTargetTransparentContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.SourceToTargetTransparentContainer, aper.DecodeState,

	) (s00.SourceToTargetTransparentContainer, aper.Snapshot,

	)
	compare func(s00.SourceToTargetTransparentContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceToTargetTransparentContainerValueCodec) New(value s00.SourceToTargetTransparentContainer,

) (SourceToTargetTransparentContainerAPERValue, error) {
	if c.encode == nil {
		return SourceToTargetTransparentContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceToTargetTransparentContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceToTargetTransparentContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceToTargetTransparentContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceToTargetTransparentContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceToTargetTransparentContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceToTargetTransparentContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceToTargetTransparentContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceToTargetTransparentContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceToTargetTransparentContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceToTargetTransparentContainerValueCodec) EncodeAPER(value SourceToTargetTransparentContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SourceToTargetTransparentContainerValueCodec) encodeBudgetValue(value s00.SourceToTargetTransparentContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceToTargetTransparentContainerValueCodec) encodeChanged(value s00.SourceToTargetTransparentContainer,

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

// SRVCCHOIndicationValueCodec is the concrete ValueCodec[SRVCCHOIndication].
type SRVCCHOIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.SRVCCHOIndication,

		error)
	encode func(s00.SRVCCHOIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.SRVCCHOIndication, aper.DecodeState,

	) (s00.SRVCCHOIndication, aper.Snapshot,

	)
	compare func(s00.SRVCCHOIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SRVCCHOIndicationValueCodec) New(value s00.SRVCCHOIndication,

) (SRVCCHOIndicationAPERValue, error) {
	if c.encode == nil {
		return SRVCCHOIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SRVCCHOIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SRVCCHOIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SRVCCHOIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SRVCCHOIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SRVCCHOIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SRVCCHOIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SRVCCHOIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SRVCCHOIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SRVCCHOIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SRVCCHOIndicationValueCodec) EncodeAPER(value SRVCCHOIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SRVCCHOIndicationValueCodec) encodeBudgetValue(value s00.SRVCCHOIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SRVCCHOIndicationValueCodec) encodeChanged(value s00.SRVCCHOIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecurityKeyValueCodec is the concrete ValueCodec[SecurityKey].
type SecurityKeyValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.SecurityKey,

		error)
	encode func(s00.SecurityKey,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.SecurityKey, aper.DecodeState,

	) (s00.SecurityKey, aper.Snapshot,

	)
	compare func(s00.SecurityKey, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecurityKeyValueCodec) New(value s00.SecurityKey,

) (SecurityKeyAPERValue, error) {
	if c.encode == nil {
		return SecurityKeyAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecurityKeyAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecurityKeyAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecurityKeyAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecurityKeyValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecurityKeyAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecurityKeyAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecurityKeyAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecurityKeyAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecurityKeyAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecurityKeyValueCodec) EncodeAPER(value SecurityKeyAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SecurityKeyValueCodec) encodeBudgetValue(value s00.SecurityKey,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecurityKeyValueCodec) encodeChanged(value s00.SecurityKey,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RelayNodeIndicatorValueCodec is the concrete ValueCodec[RelayNodeIndicator].
type RelayNodeIndicatorValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.RelayNodeIndicator,

		error)
	encode func(s00.RelayNodeIndicator,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.RelayNodeIndicator, aper.DecodeState,

	) (s00.RelayNodeIndicator, aper.Snapshot,

	)
	compare func(s00.RelayNodeIndicator, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RelayNodeIndicatorValueCodec) New(value s00.RelayNodeIndicator,

) (RelayNodeIndicatorAPERValue, error) {
	if c.encode == nil {
		return RelayNodeIndicatorAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RelayNodeIndicatorAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RelayNodeIndicatorAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RelayNodeIndicatorAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RelayNodeIndicatorValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RelayNodeIndicatorAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RelayNodeIndicatorAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RelayNodeIndicatorAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RelayNodeIndicatorAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RelayNodeIndicatorAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RelayNodeIndicatorValueCodec) EncodeAPER(value RelayNodeIndicatorAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RelayNodeIndicatorValueCodec) encodeBudgetValue(value s00.RelayNodeIndicator,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RelayNodeIndicatorValueCodec) encodeChanged(value s00.RelayNodeIndicator,

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

// SerialNumberValueCodec is the concrete ValueCodec[SerialNumber].
type SerialNumberValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.SerialNumber,

		error)
	encode func(s00.SerialNumber,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.SerialNumber, aper.DecodeState,

	) (s00.SerialNumber, aper.Snapshot,

	)
	compare func(s00.SerialNumber, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SerialNumberValueCodec) New(value s00.SerialNumber,

) (SerialNumberAPERValue, error) {
	if c.encode == nil {
		return SerialNumberAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SerialNumberAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SerialNumberAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SerialNumberAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SerialNumberValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SerialNumberAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SerialNumberAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SerialNumberAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SerialNumberAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SerialNumberAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SerialNumberValueCodec) EncodeAPER(value SerialNumberAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SerialNumberValueCodec) encodeBudgetValue(value s00.SerialNumber,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SerialNumberValueCodec) encodeChanged(value s00.SerialNumber,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RelativeMMECapacityValueCodec is the concrete ValueCodec[RelativeMMECapacity].
type RelativeMMECapacityValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.RelativeMMECapacity,

		error)
	encode func(s00.RelativeMMECapacity,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.RelativeMMECapacity, aper.DecodeState,

	) (s00.RelativeMMECapacity, aper.Snapshot,

	)
	compare func(s00.RelativeMMECapacity, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RelativeMMECapacityValueCodec) New(value s00.RelativeMMECapacity,

) (RelativeMMECapacityAPERValue, error) {
	if c.encode == nil {
		return RelativeMMECapacityAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RelativeMMECapacityAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RelativeMMECapacityAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RelativeMMECapacityAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RelativeMMECapacityValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RelativeMMECapacityAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RelativeMMECapacityAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RelativeMMECapacityAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RelativeMMECapacityAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RelativeMMECapacityAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RelativeMMECapacityValueCodec) EncodeAPER(value RelativeMMECapacityAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RelativeMMECapacityValueCodec) encodeBudgetValue(value s00.RelativeMMECapacity,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RelativeMMECapacityValueCodec) encodeChanged(value s00.RelativeMMECapacity,

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

// SliceByteValueCodec is the concrete ValueCodec[[]byte].
type SliceByteValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) ([]byte,

		error)
	encode func([]byte,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func([]byte, aper.DecodeState,

	) ([]byte, aper.Snapshot,

	)
	compare func([]byte, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SliceByteValueCodec) New(value []byte,

) (SliceByteAPERValue, error) {
	if c.encode == nil {
		return SliceByteAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SliceByteAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SliceByteAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SliceByteAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SliceByteValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SliceByteAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SliceByteAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SliceByteAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SliceByteAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SliceByteAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SliceByteValueCodec) EncodeAPER(value SliceByteAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SliceByteValueCodec) encodeBudgetValue(value []byte,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SliceByteValueCodec) encodeChanged(value []byte,

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

// SRVCCOperationNotPossibleValueCodec is the concrete ValueCodec[SRVCCOperationNotPossible].
type SRVCCOperationNotPossibleValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.SRVCCOperationNotPossible,

		error)
	encode func(s00.SRVCCOperationNotPossible,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.SRVCCOperationNotPossible, aper.DecodeState,

	) (s00.SRVCCOperationNotPossible, aper.Snapshot,

	)
	compare func(s00.SRVCCOperationNotPossible, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SRVCCOperationNotPossibleValueCodec) New(value s00.SRVCCOperationNotPossible,

) (SRVCCOperationNotPossibleAPERValue, error) {
	if c.encode == nil {
		return SRVCCOperationNotPossibleAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SRVCCOperationNotPossibleAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SRVCCOperationNotPossibleAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SRVCCOperationNotPossibleAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SRVCCOperationNotPossibleValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SRVCCOperationNotPossibleAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SRVCCOperationNotPossibleAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SRVCCOperationNotPossibleAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SRVCCOperationNotPossibleAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SRVCCOperationNotPossibleAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SRVCCOperationNotPossibleValueCodec) EncodeAPER(value SRVCCOperationNotPossibleAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SRVCCOperationNotPossibleValueCodec) encodeBudgetValue(value s00.SRVCCOperationNotPossible,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SRVCCOperationNotPossibleValueCodec) encodeChanged(value s00.SRVCCOperationNotPossible,

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

// RepetitionPeriodValueCodec is the concrete ValueCodec[RepetitionPeriod].
type RepetitionPeriodValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.RepetitionPeriod,

		error)
	encode func(s00.RepetitionPeriod,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.RepetitionPeriod, aper.DecodeState,

	) (s00.RepetitionPeriod, aper.Snapshot,

	)
	compare func(s00.RepetitionPeriod, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RepetitionPeriodValueCodec) New(value s00.RepetitionPeriod,

) (RepetitionPeriodAPERValue, error) {
	if c.encode == nil {
		return RepetitionPeriodAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RepetitionPeriodAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RepetitionPeriodAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RepetitionPeriodAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RepetitionPeriodValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RepetitionPeriodAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RepetitionPeriodAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RepetitionPeriodAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RepetitionPeriodAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RepetitionPeriodAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RepetitionPeriodValueCodec) EncodeAPER(value RepetitionPeriodAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RepetitionPeriodValueCodec) encodeBudgetValue(value s00.RepetitionPeriod,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RepetitionPeriodValueCodec) encodeChanged(value s00.RepetitionPeriod,

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

// ReportAmountMDTValueCodec is the concrete ValueCodec[ReportAmountMDT].
type ReportAmountMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ReportAmountMDT,

		error)
	encode func(s00.ReportAmountMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ReportAmountMDT, aper.DecodeState,

	) (s00.ReportAmountMDT, aper.Snapshot,

	)
	compare func(s00.ReportAmountMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ReportAmountMDTValueCodec) New(value s00.ReportAmountMDT,

) (ReportAmountMDTAPERValue, error) {
	if c.encode == nil {
		return ReportAmountMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ReportAmountMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ReportAmountMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ReportAmountMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ReportAmountMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ReportAmountMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ReportAmountMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ReportAmountMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ReportAmountMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ReportAmountMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ReportAmountMDTValueCodec) EncodeAPER(value ReportAmountMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ReportAmountMDTValueCodec) encodeBudgetValue(value s00.ReportAmountMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ReportAmountMDTValueCodec) encodeChanged(value s00.ReportAmountMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ReportAreaValueCodec is the concrete ValueCodec[ReportArea].
type ReportAreaValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ReportArea,

		error)
	encode func(s00.ReportArea,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ReportArea, aper.DecodeState,

	) (s00.ReportArea, aper.Snapshot,

	)
	compare func(s00.ReportArea, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ReportAreaValueCodec) New(value s00.ReportArea,

) (ReportAreaAPERValue, error) {
	if c.encode == nil {
		return ReportAreaAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ReportAreaAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ReportAreaAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ReportAreaAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ReportAreaValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ReportAreaAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ReportAreaAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ReportAreaAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ReportAreaAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ReportAreaAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ReportAreaValueCodec) EncodeAPER(value ReportAreaAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ReportAreaValueCodec) encodeBudgetValue(value s00.ReportArea,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ReportAreaValueCodec) encodeChanged(value s00.ReportArea,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ReportIntervalMDTValueCodec is the concrete ValueCodec[ReportIntervalMDT].
type ReportIntervalMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ReportIntervalMDT,

		error)
	encode func(s00.ReportIntervalMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ReportIntervalMDT, aper.DecodeState,

	) (s00.ReportIntervalMDT, aper.Snapshot,

	)
	compare func(s00.ReportIntervalMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ReportIntervalMDTValueCodec) New(value s00.ReportIntervalMDT,

) (ReportIntervalMDTAPERValue, error) {
	if c.encode == nil {
		return ReportIntervalMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ReportIntervalMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ReportIntervalMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ReportIntervalMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ReportIntervalMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ReportIntervalMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ReportIntervalMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ReportIntervalMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ReportIntervalMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ReportIntervalMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ReportIntervalMDTValueCodec) EncodeAPER(value ReportIntervalMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ReportIntervalMDTValueCodec) encodeBudgetValue(value s00.ReportIntervalMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ReportIntervalMDTValueCodec) encodeChanged(value s00.ReportIntervalMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ResetAllValueCodec is the concrete ValueCodec[ResetAll].
type ResetAllValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ResetAll,

		error)
	encode func(s00.ResetAll,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ResetAll, aper.DecodeState,

	) (s00.ResetAll, aper.Snapshot,

	)
	compare func(s00.ResetAll, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ResetAllValueCodec) New(value s00.ResetAll,

) (ResetAllAPERValue, error) {
	if c.encode == nil {
		return ResetAllAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResetAllAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResetAllAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ResetAllAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ResetAllValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResetAllAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ResetAllAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ResetAllAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ResetAllAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ResetAllAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ResetAllValueCodec) EncodeAPER(value ResetAllAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResetAllValueCodec) encodeBudgetValue(value s00.ResetAll,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ResetAllValueCodec) encodeChanged(value s00.ResetAll,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONInformationRequestValueCodec is the concrete ValueCodec[SONInformationRequest].
type SONInformationRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.SONInformationRequest,

		error)
	encode func(s00.SONInformationRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.SONInformationRequest, aper.DecodeState,

	) (s00.SONInformationRequest, aper.Snapshot,

	)
	compare func(s00.SONInformationRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONInformationRequestValueCodec) New(value s00.SONInformationRequest,

) (SONInformationRequestAPERValue, error) {
	if c.encode == nil {
		return SONInformationRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONInformationRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONInformationRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONInformationRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONInformationRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONInformationRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONInformationRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONInformationRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONInformationRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONInformationRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONInformationRequestValueCodec) EncodeAPER(value SONInformationRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SONInformationRequestValueCodec) encodeBudgetValue(value s00.SONInformationRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONInformationRequestValueCodec) encodeChanged(value s00.SONInformationRequest,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SONtransferApplicationIdentityValueCodec is the concrete ValueCodec[SONtransferApplicationIdentity].
type SONtransferApplicationIdentityValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.SONtransferApplicationIdentity,

		error)
	encode func(s00.SONtransferApplicationIdentity,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.SONtransferApplicationIdentity, aper.DecodeState,

	) (s00.SONtransferApplicationIdentity, aper.Snapshot,

	)
	compare func(s00.SONtransferApplicationIdentity, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SONtransferApplicationIdentityValueCodec) New(value s00.SONtransferApplicationIdentity,

) (SONtransferApplicationIdentityAPERValue, error) {
	if c.encode == nil {
		return SONtransferApplicationIdentityAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SONtransferApplicationIdentityAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SONtransferApplicationIdentityAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SONtransferApplicationIdentityAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SONtransferApplicationIdentityValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SONtransferApplicationIdentityAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SONtransferApplicationIdentityAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SONtransferApplicationIdentityAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SONtransferApplicationIdentityAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SONtransferApplicationIdentityAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SONtransferApplicationIdentityValueCodec) EncodeAPER(value SONtransferApplicationIdentityAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SONtransferApplicationIdentityValueCodec) encodeBudgetValue(value s00.SONtransferApplicationIdentity,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SONtransferApplicationIdentityValueCodec) encodeChanged(value s00.SONtransferApplicationIdentity,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SecondaryRATTypeValueCodec is the concrete ValueCodec[SecondaryRATType].
type SecondaryRATTypeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.SecondaryRATType,

		error)
	encode func(s00.SecondaryRATType,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.SecondaryRATType, aper.DecodeState,

	) (s00.SecondaryRATType, aper.Snapshot,

	)
	compare func(s00.SecondaryRATType, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SecondaryRATTypeValueCodec) New(value s00.SecondaryRATType,

) (SecondaryRATTypeAPERValue, error) {
	if c.encode == nil {
		return SecondaryRATTypeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SecondaryRATTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SecondaryRATTypeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SecondaryRATTypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SecondaryRATTypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SecondaryRATTypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SecondaryRATTypeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SecondaryRATTypeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SecondaryRATTypeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SecondaryRATTypeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SecondaryRATTypeValueCodec) EncodeAPER(value SecondaryRATTypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SecondaryRATTypeValueCodec) encodeBudgetValue(value s00.SecondaryRATType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SecondaryRATTypeValueCodec) encodeChanged(value s00.SecondaryRATType,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SensorMeasConfigValueCodec is the concrete ValueCodec[SensorMeasConfig].
type SensorMeasConfigValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.SensorMeasConfig,

		error)
	encode func(s00.SensorMeasConfig,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.SensorMeasConfig, aper.DecodeState,

	) (s00.SensorMeasConfig, aper.Snapshot,

	)
	compare func(s00.SensorMeasConfig, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SensorMeasConfigValueCodec) New(value s00.SensorMeasConfig,

) (SensorMeasConfigAPERValue, error) {
	if c.encode == nil {
		return SensorMeasConfigAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SensorMeasConfigAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SensorMeasConfigAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SensorMeasConfigAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SensorMeasConfigValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SensorMeasConfigAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SensorMeasConfigAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SensorMeasConfigAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SensorMeasConfigAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SensorMeasConfigAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SensorMeasConfigValueCodec) EncodeAPER(value SensorMeasConfigAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SensorMeasConfigValueCodec) encodeBudgetValue(value s00.SensorMeasConfig,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SensorMeasConfigValueCodec) encodeChanged(value s00.SensorMeasConfig,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ServedGroupIDsValueCodec is the concrete ValueCodec[ServedGroupIDs].
type ServedGroupIDsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ServedGroupIDs,

		error)
	encode func(s00.ServedGroupIDs,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ServedGroupIDs, aper.DecodeState,

	) (s00.ServedGroupIDs, aper.Snapshot,

	)
	compare func(s00.ServedGroupIDs, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ServedGroupIDsValueCodec) New(value s00.ServedGroupIDs,

) (ServedGroupIDsAPERValue, error) {
	if c.encode == nil {
		return ServedGroupIDsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ServedGroupIDsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ServedGroupIDsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ServedGroupIDsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ServedGroupIDsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ServedGroupIDsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ServedGroupIDsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ServedGroupIDsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ServedGroupIDsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ServedGroupIDsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ServedGroupIDsValueCodec) EncodeAPER(value ServedGroupIDsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ServedGroupIDsValueCodec) encodeBudgetValue(value s00.ServedGroupIDs,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ServedGroupIDsValueCodec) encodeChanged(value s00.ServedGroupIDs,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ServedMMECsValueCodec is the concrete ValueCodec[ServedMMECs].
type ServedMMECsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ServedMMECs,

		error)
	encode func(s00.ServedMMECs,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ServedMMECs, aper.DecodeState,

	) (s00.ServedMMECs, aper.Snapshot,

	)
	compare func(s00.ServedMMECs, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ServedMMECsValueCodec) New(value s00.ServedMMECs,

) (ServedMMECsAPERValue, error) {
	if c.encode == nil {
		return ServedMMECsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ServedMMECsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ServedMMECsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ServedMMECsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ServedMMECsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ServedMMECsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ServedMMECsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ServedMMECsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ServedMMECsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ServedMMECsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ServedMMECsValueCodec) EncodeAPER(value ServedMMECsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ServedMMECsValueCodec) encodeBudgetValue(value s00.ServedMMECs,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ServedMMECsValueCodec) encodeChanged(value s00.ServedMMECs,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ServedPLMNsValueCodec is the concrete ValueCodec[ServedPLMNs].
type ServedPLMNsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ServedPLMNs,

		error)
	encode func(s00.ServedPLMNs,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ServedPLMNs, aper.DecodeState,

	) (s00.ServedPLMNs, aper.Snapshot,

	)
	compare func(s00.ServedPLMNs, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ServedPLMNsValueCodec) New(value s00.ServedPLMNs,

) (ServedPLMNsAPERValue, error) {
	if c.encode == nil {
		return ServedPLMNsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ServedPLMNsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ServedPLMNsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ServedPLMNsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ServedPLMNsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ServedPLMNsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ServedPLMNsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ServedPLMNsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ServedPLMNsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ServedPLMNsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ServedPLMNsValueCodec) EncodeAPER(value ServedPLMNsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ServedPLMNsValueCodec) encodeBudgetValue(value s00.ServedPLMNs,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ServedPLMNsValueCodec) encodeChanged(value s00.ServedPLMNs,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SonTransferIEsMobilityInformationValueCodec is the concrete ValueCodec[SonTransferIEsMobilityInformation].
type SonTransferIEsMobilityInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.SonTransferIEsMobilityInformation,

		error)
	encode func(s00.SonTransferIEsMobilityInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.SonTransferIEsMobilityInformation, aper.DecodeState,

	) (s00.SonTransferIEsMobilityInformation, aper.Snapshot,

	)
	compare func(s00.SonTransferIEsMobilityInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SonTransferIEsMobilityInformationValueCodec) New(value s00.SonTransferIEsMobilityInformation,

) (SonTransferIEsMobilityInformationAPERValue, error) {
	if c.encode == nil {
		return SonTransferIEsMobilityInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SonTransferIEsMobilityInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SonTransferIEsMobilityInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SonTransferIEsMobilityInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SonTransferIEsMobilityInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SonTransferIEsMobilityInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SonTransferIEsMobilityInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SonTransferIEsMobilityInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SonTransferIEsMobilityInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SonTransferIEsMobilityInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SonTransferIEsMobilityInformationValueCodec) EncodeAPER(value SonTransferIEsMobilityInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SonTransferIEsMobilityInformationValueCodec) encodeBudgetValue(value s00.SonTransferIEsMobilityInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SonTransferIEsMobilityInformationValueCodec) encodeChanged(value s00.SonTransferIEsMobilityInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceBSSToTargetBSSTransparentContainerValueCodec is the concrete ValueCodec[SourceBSSToTargetBSSTransparentContainer].
type SourceBSSToTargetBSSTransparentContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.SourceBSSToTargetBSSTransparentContainer,

		error)
	encode func(s00.SourceBSSToTargetBSSTransparentContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.SourceBSSToTargetBSSTransparentContainer, aper.DecodeState,

	) (s00.SourceBSSToTargetBSSTransparentContainer, aper.Snapshot,

	)
	compare func(s00.SourceBSSToTargetBSSTransparentContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceBSSToTargetBSSTransparentContainerValueCodec) New(value s00.SourceBSSToTargetBSSTransparentContainer,

) (SourceBSSToTargetBSSTransparentContainerAPERValue, error) {
	if c.encode == nil {
		return SourceBSSToTargetBSSTransparentContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceBSSToTargetBSSTransparentContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceBSSToTargetBSSTransparentContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceBSSToTargetBSSTransparentContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceBSSToTargetBSSTransparentContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceBSSToTargetBSSTransparentContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceBSSToTargetBSSTransparentContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceBSSToTargetBSSTransparentContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceBSSToTargetBSSTransparentContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceBSSToTargetBSSTransparentContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceBSSToTargetBSSTransparentContainerValueCodec) EncodeAPER(value SourceBSSToTargetBSSTransparentContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SourceBSSToTargetBSSTransparentContainerValueCodec) encodeBudgetValue(value s00.SourceBSSToTargetBSSTransparentContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceBSSToTargetBSSTransparentContainerValueCodec) encodeChanged(value s00.SourceBSSToTargetBSSTransparentContainer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodec is the concrete ValueCodec[SourceNgRanNodeToTargetNgRanNodeTransparentContainer].
type SourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer,

		error)
	encode func(s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer, aper.DecodeState,

	) (s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer, aper.Snapshot,

	)
	compare func(s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodec) New(value s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer,

) (SourceNgRanNodeToTargetNgRanNodeTransparentContainerAPERValue, error) {
	if c.encode == nil {
		return SourceNgRanNodeToTargetNgRanNodeTransparentContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceNgRanNodeToTargetNgRanNodeTransparentContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceNgRanNodeToTargetNgRanNodeTransparentContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceNgRanNodeToTargetNgRanNodeTransparentContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceNgRanNodeToTargetNgRanNodeTransparentContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceNgRanNodeToTargetNgRanNodeTransparentContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceNgRanNodeToTargetNgRanNodeTransparentContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceNgRanNodeToTargetNgRanNodeTransparentContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceNgRanNodeToTargetNgRanNodeTransparentContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodec) EncodeAPER(value SourceNgRanNodeToTargetNgRanNodeTransparentContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodec) encodeBudgetValue(value s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodec) encodeChanged(value s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceOfUEActivityBehaviourInformationValueCodec is the concrete ValueCodec[SourceOfUEActivityBehaviourInformation].
type SourceOfUEActivityBehaviourInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.SourceOfUEActivityBehaviourInformation,

		error)
	encode func(s00.SourceOfUEActivityBehaviourInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.SourceOfUEActivityBehaviourInformation, aper.DecodeState,

	) (s00.SourceOfUEActivityBehaviourInformation, aper.Snapshot,

	)
	compare func(s00.SourceOfUEActivityBehaviourInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceOfUEActivityBehaviourInformationValueCodec) New(value s00.SourceOfUEActivityBehaviourInformation,

) (SourceOfUEActivityBehaviourInformationAPERValue, error) {
	if c.encode == nil {
		return SourceOfUEActivityBehaviourInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceOfUEActivityBehaviourInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceOfUEActivityBehaviourInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceOfUEActivityBehaviourInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceOfUEActivityBehaviourInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceOfUEActivityBehaviourInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceOfUEActivityBehaviourInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceOfUEActivityBehaviourInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceOfUEActivityBehaviourInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceOfUEActivityBehaviourInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceOfUEActivityBehaviourInformationValueCodec) EncodeAPER(value SourceOfUEActivityBehaviourInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SourceOfUEActivityBehaviourInformationValueCodec) encodeBudgetValue(value s00.SourceOfUEActivityBehaviourInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceOfUEActivityBehaviourInformationValueCodec) encodeChanged(value s00.SourceOfUEActivityBehaviourInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SourceRNCToTargetRNCTransparentContainerValueCodec is the concrete ValueCodec[SourceRNCToTargetRNCTransparentContainer].
type SourceRNCToTargetRNCTransparentContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.SourceRNCToTargetRNCTransparentContainer,

		error)
	encode func(s00.SourceRNCToTargetRNCTransparentContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.SourceRNCToTargetRNCTransparentContainer, aper.DecodeState,

	) (s00.SourceRNCToTargetRNCTransparentContainer, aper.Snapshot,

	)
	compare func(s00.SourceRNCToTargetRNCTransparentContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SourceRNCToTargetRNCTransparentContainerValueCodec) New(value s00.SourceRNCToTargetRNCTransparentContainer,

) (SourceRNCToTargetRNCTransparentContainerAPERValue, error) {
	if c.encode == nil {
		return SourceRNCToTargetRNCTransparentContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SourceRNCToTargetRNCTransparentContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SourceRNCToTargetRNCTransparentContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SourceRNCToTargetRNCTransparentContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SourceRNCToTargetRNCTransparentContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SourceRNCToTargetRNCTransparentContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SourceRNCToTargetRNCTransparentContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SourceRNCToTargetRNCTransparentContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SourceRNCToTargetRNCTransparentContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SourceRNCToTargetRNCTransparentContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SourceRNCToTargetRNCTransparentContainerValueCodec) EncodeAPER(value SourceRNCToTargetRNCTransparentContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SourceRNCToTargetRNCTransparentContainerValueCodec) encodeBudgetValue(value s00.SourceRNCToTargetRNCTransparentContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SourceRNCToTargetRNCTransparentContainerValueCodec) encodeChanged(value s00.SourceRNCToTargetRNCTransparentContainer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// StratumLevelValueCodec is the concrete ValueCodec[StratumLevel].
type StratumLevelValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.StratumLevel,

		error)
	encode func(s00.StratumLevel,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.StratumLevel, aper.DecodeState,

	) (s00.StratumLevel, aper.Snapshot,

	)
	compare func(s00.StratumLevel, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c StratumLevelValueCodec) New(value s00.StratumLevel,

) (StratumLevelAPERValue, error) {
	if c.encode == nil {
		return StratumLevelAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return StratumLevelAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return StratumLevelAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return StratumLevelAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c StratumLevelValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (StratumLevelAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return StratumLevelAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return StratumLevelAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return StratumLevelAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return StratumLevelAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c StratumLevelValueCodec) EncodeAPER(value StratumLevelAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c StratumLevelValueCodec) encodeBudgetValue(value s00.StratumLevel,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c StratumLevelValueCodec) encodeChanged(value s00.StratumLevel,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// SynchronisationStatusValueCodec is the concrete ValueCodec[SynchronisationStatus].
type SynchronisationStatusValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.SynchronisationStatus,

		error)
	encode func(s00.SynchronisationStatus,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.SynchronisationStatus, aper.DecodeState,

	) (s00.SynchronisationStatus, aper.Snapshot,

	)
	compare func(s00.SynchronisationStatus, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c SynchronisationStatusValueCodec) New(value s00.SynchronisationStatus,

) (SynchronisationStatusAPERValue, error) {
	if c.encode == nil {
		return SynchronisationStatusAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SynchronisationStatusAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SynchronisationStatusAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return SynchronisationStatusAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c SynchronisationStatusValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SynchronisationStatusAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return SynchronisationStatusAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return SynchronisationStatusAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return SynchronisationStatusAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return SynchronisationStatusAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c SynchronisationStatusValueCodec) EncodeAPER(value SynchronisationStatusAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SynchronisationStatusValueCodec) encodeBudgetValue(value s00.SynchronisationStatus,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c SynchronisationStatusValueCodec) encodeChanged(value s00.SynchronisationStatus,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TACValueCodec is the concrete ValueCodec[TAC].
type TACValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TAC,

		error)
	encode func(s00.TAC,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TAC, aper.DecodeState,

	) (s00.TAC, aper.Snapshot,

	)
	compare func(s00.TAC, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TACValueCodec) New(value s00.TAC,

) (TACAPERValue, error) {
	if c.encode == nil {
		return TACAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TACAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TACAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TACAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TACValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TACAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TACAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TACAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TACAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TACAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TACValueCodec) EncodeAPER(value TACAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TACValueCodec) encodeBudgetValue(value s00.TAC,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TACValueCodec) encodeChanged(value s00.TAC,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TACListInLTENTNValueCodec is the concrete ValueCodec[TACListInLTENTN].
type TACListInLTENTNValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TACListInLTENTN,

		error)
	encode func(s00.TACListInLTENTN,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TACListInLTENTN, aper.DecodeState,

	) (s00.TACListInLTENTN, aper.Snapshot,

	)
	compare func(s00.TACListInLTENTN, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TACListInLTENTNValueCodec) New(value s00.TACListInLTENTN,

) (TACListInLTENTNAPERValue, error) {
	if c.encode == nil {
		return TACListInLTENTNAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TACListInLTENTNAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TACListInLTENTNAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TACListInLTENTNAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TACListInLTENTNValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TACListInLTENTNAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TACListInLTENTNAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TACListInLTENTNAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TACListInLTENTNAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TACListInLTENTNAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TACListInLTENTNValueCodec) EncodeAPER(value TACListInLTENTNAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TACListInLTENTNValueCodec) encodeBudgetValue(value s00.TACListInLTENTN,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TACListInLTENTNValueCodec) encodeChanged(value s00.TACListInLTENTN,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAListforMDTValueCodec is the concrete ValueCodec[TAListforMDT].
type TAListforMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TAListforMDT,

		error)
	encode func(s00.TAListforMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TAListforMDT, aper.DecodeState,

	) (s00.TAListforMDT, aper.Snapshot,

	)
	compare func(s00.TAListforMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAListforMDTValueCodec) New(value s00.TAListforMDT,

) (TAListforMDTAPERValue, error) {
	if c.encode == nil {
		return TAListforMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAListforMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAListforMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAListforMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAListforMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAListforMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAListforMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAListforMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAListforMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAListforMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAListforMDTValueCodec) EncodeAPER(value TAListforMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TAListforMDTValueCodec) encodeBudgetValue(value s00.TAListforMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAListforMDTValueCodec) encodeChanged(value s00.TAListforMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TAListforQMCValueCodec is the concrete ValueCodec[TAListforQMC].
type TAListforQMCValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TAListforQMC,

		error)
	encode func(s00.TAListforQMC,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TAListforQMC, aper.DecodeState,

	) (s00.TAListforQMC, aper.Snapshot,

	)
	compare func(s00.TAListforQMC, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TAListforQMCValueCodec) New(value s00.TAListforQMC,

) (TAListforQMCAPERValue, error) {
	if c.encode == nil {
		return TAListforQMCAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TAListforQMCAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TAListforQMCAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TAListforQMCAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TAListforQMCValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TAListforQMCAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TAListforQMCAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TAListforQMCAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TAListforQMCAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TAListforQMCAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TAListforQMCValueCodec) EncodeAPER(value TAListforQMCAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TAListforQMCValueCodec) encodeBudgetValue(value s00.TAListforQMC,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TAListforQMCValueCodec) encodeChanged(value s00.TAListforQMC,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TBCDSTRINGValueCodec is the concrete ValueCodec[TBCDSTRING].
type TBCDSTRINGValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TBCDSTRING,

		error)
	encode func(s00.TBCDSTRING,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TBCDSTRING, aper.DecodeState,

	) (s00.TBCDSTRING, aper.Snapshot,

	)
	compare func(s00.TBCDSTRING, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TBCDSTRINGValueCodec) New(value s00.TBCDSTRING,

) (TBCDSTRINGAPERValue, error) {
	if c.encode == nil {
		return TBCDSTRINGAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TBCDSTRINGAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TBCDSTRINGAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TBCDSTRINGAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TBCDSTRINGValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TBCDSTRINGAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TBCDSTRINGAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TBCDSTRINGAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TBCDSTRINGAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TBCDSTRINGAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TBCDSTRINGValueCodec) EncodeAPER(value TBCDSTRINGAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TBCDSTRINGValueCodec) encodeBudgetValue(value s00.TBCDSTRING,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TBCDSTRINGValueCodec) encodeChanged(value s00.TBCDSTRING,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TargetBSSToSourceBSSTransparentContainerValueCodec is the concrete ValueCodec[TargetBSSToSourceBSSTransparentContainer].
type TargetBSSToSourceBSSTransparentContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TargetBSSToSourceBSSTransparentContainer,

		error)
	encode func(s00.TargetBSSToSourceBSSTransparentContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TargetBSSToSourceBSSTransparentContainer, aper.DecodeState,

	) (s00.TargetBSSToSourceBSSTransparentContainer, aper.Snapshot,

	)
	compare func(s00.TargetBSSToSourceBSSTransparentContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TargetBSSToSourceBSSTransparentContainerValueCodec) New(value s00.TargetBSSToSourceBSSTransparentContainer,

) (TargetBSSToSourceBSSTransparentContainerAPERValue, error) {
	if c.encode == nil {
		return TargetBSSToSourceBSSTransparentContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargetBSSToSourceBSSTransparentContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TargetBSSToSourceBSSTransparentContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TargetBSSToSourceBSSTransparentContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TargetBSSToSourceBSSTransparentContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TargetBSSToSourceBSSTransparentContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TargetBSSToSourceBSSTransparentContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TargetBSSToSourceBSSTransparentContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TargetBSSToSourceBSSTransparentContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TargetBSSToSourceBSSTransparentContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TargetBSSToSourceBSSTransparentContainerValueCodec) EncodeAPER(value TargetBSSToSourceBSSTransparentContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TargetBSSToSourceBSSTransparentContainerValueCodec) encodeBudgetValue(value s00.TargetBSSToSourceBSSTransparentContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TargetBSSToSourceBSSTransparentContainerValueCodec) encodeChanged(value s00.TargetBSSToSourceBSSTransparentContainer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodec is the concrete ValueCodec[TargetNgRanNodeToSourceNgRanNodeTransparentContainer].
type TargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer,

		error)
	encode func(s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer, aper.DecodeState,

	) (s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer, aper.Snapshot,

	)
	compare func(s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodec) New(value s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer,

) (TargetNgRanNodeToSourceNgRanNodeTransparentContainerAPERValue, error) {
	if c.encode == nil {
		return TargetNgRanNodeToSourceNgRanNodeTransparentContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargetNgRanNodeToSourceNgRanNodeTransparentContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TargetNgRanNodeToSourceNgRanNodeTransparentContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TargetNgRanNodeToSourceNgRanNodeTransparentContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TargetNgRanNodeToSourceNgRanNodeTransparentContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TargetNgRanNodeToSourceNgRanNodeTransparentContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TargetNgRanNodeToSourceNgRanNodeTransparentContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TargetNgRanNodeToSourceNgRanNodeTransparentContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TargetNgRanNodeToSourceNgRanNodeTransparentContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodec) EncodeAPER(value TargetNgRanNodeToSourceNgRanNodeTransparentContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodec) encodeBudgetValue(value s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodec) encodeChanged(value s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TargetRNCToSourceRNCTransparentContainerValueCodec is the concrete ValueCodec[TargetRNCToSourceRNCTransparentContainer].
type TargetRNCToSourceRNCTransparentContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.TargetRNCToSourceRNCTransparentContainer,

		error)
	encode func(s00.TargetRNCToSourceRNCTransparentContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.TargetRNCToSourceRNCTransparentContainer, aper.DecodeState,

	) (s00.TargetRNCToSourceRNCTransparentContainer, aper.Snapshot,

	)
	compare func(s00.TargetRNCToSourceRNCTransparentContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TargetRNCToSourceRNCTransparentContainerValueCodec) New(value s00.TargetRNCToSourceRNCTransparentContainer,

) (TargetRNCToSourceRNCTransparentContainerAPERValue, error) {
	if c.encode == nil {
		return TargetRNCToSourceRNCTransparentContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TargetRNCToSourceRNCTransparentContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TargetRNCToSourceRNCTransparentContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TargetRNCToSourceRNCTransparentContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TargetRNCToSourceRNCTransparentContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TargetRNCToSourceRNCTransparentContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TargetRNCToSourceRNCTransparentContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TargetRNCToSourceRNCTransparentContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TargetRNCToSourceRNCTransparentContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TargetRNCToSourceRNCTransparentContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TargetRNCToSourceRNCTransparentContainerValueCodec) EncodeAPER(value TargetRNCToSourceRNCTransparentContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TargetRNCToSourceRNCTransparentContainerValueCodec) encodeBudgetValue(value s00.TargetRNCToSourceRNCTransparentContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TargetRNCToSourceRNCTransparentContainerValueCodec) encodeChanged(value s00.TargetRNCToSourceRNCTransparentContainer,

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

) (ThresholdRSRPAPERValue, error) {
	if c.encode == nil {
		return ThresholdRSRPAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ThresholdRSRPAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ThresholdRSRPAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ThresholdRSRPAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ThresholdRSRPValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ThresholdRSRPAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ThresholdRSRPAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ThresholdRSRPAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ThresholdRSRPAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ThresholdRSRPAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ThresholdRSRPValueCodec) EncodeAPER(value ThresholdRSRPAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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

// RequestTypeAdditionalInfoAPERValue is the concrete APERValue[RequestTypeAdditionalInfo].
type RequestTypeAdditionalInfoAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.RequestTypeAdditionalInfo

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RequestTypeAdditionalInfoAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RequestTypeAdditionalInfoAPERValue) WithoutReplay() RequestTypeAdditionalInfoAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// S1APIEsMobilityInformationAPERValue is the concrete APERValue[S1APIEsMobilityInformation].
type S1APIEsMobilityInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.S1APIEsMobilityInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v S1APIEsMobilityInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v S1APIEsMobilityInformationAPERValue) WithoutReplay() S1APIEsMobilityInformationAPERValue {
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

// ServiceTypeAPERValue is the concrete APERValue[ServiceType].
type ServiceTypeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ServiceType

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ServiceTypeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ServiceTypeAPERValue) WithoutReplay() ServiceTypeAPERValue {
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

// SubscriberProfileIDforRFPAPERValue is the concrete APERValue[SubscriberProfileIDforRFP].
type SubscriberProfileIDforRFPAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SubscriberProfileIDforRFP

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SubscriberProfileIDforRFPAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SubscriberProfileIDforRFPAPERValue) WithoutReplay() SubscriberProfileIDforRFPAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SRVCCOperationPossibleAPERValue is the concrete APERValue[SRVCCOperationPossible].
type SRVCCOperationPossibleAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SRVCCOperationPossible

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SRVCCOperationPossibleAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SRVCCOperationPossibleAPERValue) WithoutReplay() SRVCCOperationPossibleAPERValue {
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

// RoutingIDAPERValue is the concrete APERValue[RoutingID].
type RoutingIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.RoutingID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RoutingIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RoutingIDAPERValue) WithoutReplay() RoutingIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecondaryRATDataUsageRequestAPERValue is the concrete APERValue[SecondaryRATDataUsageRequest].
type SecondaryRATDataUsageRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SecondaryRATDataUsageRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecondaryRATDataUsageRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATDataUsageRequestAPERValue) WithoutReplay() SecondaryRATDataUsageRequestAPERValue {
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

// TargetToSourceTransparentContainerAPERValue is the concrete APERValue[TargetToSourceTransparentContainer].
type TargetToSourceTransparentContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TargetToSourceTransparentContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TargetToSourceTransparentContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargetToSourceTransparentContainerAPERValue) WithoutReplay() TargetToSourceTransparentContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceToTargetTransparentContainerAPERValue is the concrete APERValue[SourceToTargetTransparentContainer].
type SourceToTargetTransparentContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SourceToTargetTransparentContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceToTargetTransparentContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceToTargetTransparentContainerAPERValue) WithoutReplay() SourceToTargetTransparentContainerAPERValue {
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

// SRVCCHOIndicationAPERValue is the concrete APERValue[SRVCCHOIndication].
type SRVCCHOIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SRVCCHOIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SRVCCHOIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SRVCCHOIndicationAPERValue) WithoutReplay() SRVCCHOIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecurityKeyAPERValue is the concrete APERValue[SecurityKey].
type SecurityKeyAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SecurityKey

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecurityKeyAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecurityKeyAPERValue) WithoutReplay() SecurityKeyAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RelayNodeIndicatorAPERValue is the concrete APERValue[RelayNodeIndicator].
type RelayNodeIndicatorAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.RelayNodeIndicator

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RelayNodeIndicatorAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RelayNodeIndicatorAPERValue) WithoutReplay() RelayNodeIndicatorAPERValue {
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

// SerialNumberAPERValue is the concrete APERValue[SerialNumber].
type SerialNumberAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SerialNumber

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SerialNumberAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SerialNumberAPERValue) WithoutReplay() SerialNumberAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RelativeMMECapacityAPERValue is the concrete APERValue[RelativeMMECapacity].
type RelativeMMECapacityAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.RelativeMMECapacity

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RelativeMMECapacityAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RelativeMMECapacityAPERValue) WithoutReplay() RelativeMMECapacityAPERValue {
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

// SliceByteAPERValue is the concrete APERValue[[]byte].
type SliceByteAPERValue struct {
	context s00.BridgeCodecContext
	Value   []byte

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SliceByteAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SliceByteAPERValue) WithoutReplay() SliceByteAPERValue {
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

// SRVCCOperationNotPossibleAPERValue is the concrete APERValue[SRVCCOperationNotPossible].
type SRVCCOperationNotPossibleAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SRVCCOperationNotPossible

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SRVCCOperationNotPossibleAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SRVCCOperationNotPossibleAPERValue) WithoutReplay() SRVCCOperationNotPossibleAPERValue {
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

// RepetitionPeriodAPERValue is the concrete APERValue[RepetitionPeriod].
type RepetitionPeriodAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.RepetitionPeriod

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RepetitionPeriodAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RepetitionPeriodAPERValue) WithoutReplay() RepetitionPeriodAPERValue {
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

// ReportAmountMDTAPERValue is the concrete APERValue[ReportAmountMDT].
type ReportAmountMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ReportAmountMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ReportAmountMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ReportAmountMDTAPERValue) WithoutReplay() ReportAmountMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ReportAreaAPERValue is the concrete APERValue[ReportArea].
type ReportAreaAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ReportArea

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ReportAreaAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ReportAreaAPERValue) WithoutReplay() ReportAreaAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ReportIntervalMDTAPERValue is the concrete APERValue[ReportIntervalMDT].
type ReportIntervalMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ReportIntervalMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ReportIntervalMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ReportIntervalMDTAPERValue) WithoutReplay() ReportIntervalMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResetAllAPERValue is the concrete APERValue[ResetAll].
type ResetAllAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ResetAll

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ResetAllAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ResetAllAPERValue) WithoutReplay() ResetAllAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONInformationRequestAPERValue is the concrete APERValue[SONInformationRequest].
type SONInformationRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SONInformationRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONInformationRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONInformationRequestAPERValue) WithoutReplay() SONInformationRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SONtransferApplicationIdentityAPERValue is the concrete APERValue[SONtransferApplicationIdentity].
type SONtransferApplicationIdentityAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SONtransferApplicationIdentity

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SONtransferApplicationIdentityAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SONtransferApplicationIdentityAPERValue) WithoutReplay() SONtransferApplicationIdentityAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SecondaryRATTypeAPERValue is the concrete APERValue[SecondaryRATType].
type SecondaryRATTypeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SecondaryRATType

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SecondaryRATTypeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SecondaryRATTypeAPERValue) WithoutReplay() SecondaryRATTypeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SensorMeasConfigAPERValue is the concrete APERValue[SensorMeasConfig].
type SensorMeasConfigAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SensorMeasConfig

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SensorMeasConfigAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SensorMeasConfigAPERValue) WithoutReplay() SensorMeasConfigAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ServedGroupIDsAPERValue is the concrete APERValue[ServedGroupIDs].
type ServedGroupIDsAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ServedGroupIDs

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ServedGroupIDsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ServedGroupIDsAPERValue) WithoutReplay() ServedGroupIDsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ServedMMECsAPERValue is the concrete APERValue[ServedMMECs].
type ServedMMECsAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ServedMMECs

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ServedMMECsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ServedMMECsAPERValue) WithoutReplay() ServedMMECsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ServedPLMNsAPERValue is the concrete APERValue[ServedPLMNs].
type ServedPLMNsAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ServedPLMNs

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ServedPLMNsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ServedPLMNsAPERValue) WithoutReplay() ServedPLMNsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SonTransferIEsMobilityInformationAPERValue is the concrete APERValue[SonTransferIEsMobilityInformation].
type SonTransferIEsMobilityInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SonTransferIEsMobilityInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SonTransferIEsMobilityInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SonTransferIEsMobilityInformationAPERValue) WithoutReplay() SonTransferIEsMobilityInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceBSSToTargetBSSTransparentContainerAPERValue is the concrete APERValue[SourceBSSToTargetBSSTransparentContainer].
type SourceBSSToTargetBSSTransparentContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SourceBSSToTargetBSSTransparentContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceBSSToTargetBSSTransparentContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceBSSToTargetBSSTransparentContainerAPERValue) WithoutReplay() SourceBSSToTargetBSSTransparentContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceNgRanNodeToTargetNgRanNodeTransparentContainerAPERValue is the concrete APERValue[SourceNgRanNodeToTargetNgRanNodeTransparentContainer].
type SourceNgRanNodeToTargetNgRanNodeTransparentContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceNgRanNodeToTargetNgRanNodeTransparentContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceNgRanNodeToTargetNgRanNodeTransparentContainerAPERValue) WithoutReplay() SourceNgRanNodeToTargetNgRanNodeTransparentContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceOfUEActivityBehaviourInformationAPERValue is the concrete APERValue[SourceOfUEActivityBehaviourInformation].
type SourceOfUEActivityBehaviourInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SourceOfUEActivityBehaviourInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceOfUEActivityBehaviourInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceOfUEActivityBehaviourInformationAPERValue) WithoutReplay() SourceOfUEActivityBehaviourInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SourceRNCToTargetRNCTransparentContainerAPERValue is the concrete APERValue[SourceRNCToTargetRNCTransparentContainer].
type SourceRNCToTargetRNCTransparentContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SourceRNCToTargetRNCTransparentContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SourceRNCToTargetRNCTransparentContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SourceRNCToTargetRNCTransparentContainerAPERValue) WithoutReplay() SourceRNCToTargetRNCTransparentContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// StratumLevelAPERValue is the concrete APERValue[StratumLevel].
type StratumLevelAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.StratumLevel

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v StratumLevelAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v StratumLevelAPERValue) WithoutReplay() StratumLevelAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SynchronisationStatusAPERValue is the concrete APERValue[SynchronisationStatus].
type SynchronisationStatusAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SynchronisationStatus

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v SynchronisationStatusAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v SynchronisationStatusAPERValue) WithoutReplay() SynchronisationStatusAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TACAPERValue is the concrete APERValue[TAC].
type TACAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TAC

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TACAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TACAPERValue) WithoutReplay() TACAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TACListInLTENTNAPERValue is the concrete APERValue[TACListInLTENTN].
type TACListInLTENTNAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TACListInLTENTN

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TACListInLTENTNAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TACListInLTENTNAPERValue) WithoutReplay() TACListInLTENTNAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAListforMDTAPERValue is the concrete APERValue[TAListforMDT].
type TAListforMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TAListforMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAListforMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAListforMDTAPERValue) WithoutReplay() TAListforMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TAListforQMCAPERValue is the concrete APERValue[TAListforQMC].
type TAListforQMCAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TAListforQMC

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TAListforQMCAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TAListforQMCAPERValue) WithoutReplay() TAListforQMCAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TBCDSTRINGAPERValue is the concrete APERValue[TBCDSTRING].
type TBCDSTRINGAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TBCDSTRING

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TBCDSTRINGAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TBCDSTRINGAPERValue) WithoutReplay() TBCDSTRINGAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TargetBSSToSourceBSSTransparentContainerAPERValue is the concrete APERValue[TargetBSSToSourceBSSTransparentContainer].
type TargetBSSToSourceBSSTransparentContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TargetBSSToSourceBSSTransparentContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TargetBSSToSourceBSSTransparentContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargetBSSToSourceBSSTransparentContainerAPERValue) WithoutReplay() TargetBSSToSourceBSSTransparentContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TargetNgRanNodeToSourceNgRanNodeTransparentContainerAPERValue is the concrete APERValue[TargetNgRanNodeToSourceNgRanNodeTransparentContainer].
type TargetNgRanNodeToSourceNgRanNodeTransparentContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TargetNgRanNodeToSourceNgRanNodeTransparentContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargetNgRanNodeToSourceNgRanNodeTransparentContainerAPERValue) WithoutReplay() TargetNgRanNodeToSourceNgRanNodeTransparentContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TargetRNCToSourceRNCTransparentContainerAPERValue is the concrete APERValue[TargetRNCToSourceRNCTransparentContainer].
type TargetRNCToSourceRNCTransparentContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TargetRNCToSourceRNCTransparentContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TargetRNCToSourceRNCTransparentContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TargetRNCToSourceRNCTransparentContainerAPERValue) WithoutReplay() TargetRNCToSourceRNCTransparentContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ThresholdRSRPAPERValue is the concrete APERValue[ThresholdRSRP].
type ThresholdRSRPAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ThresholdRSRP

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ThresholdRSRPAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ThresholdRSRPAPERValue) WithoutReplay() ThresholdRSRPAPERValue {
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
func BridgeCompareS1APBearerType(v *s00.BearerType, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
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
func BridgeCompareS1APCSGMembershipStatus(v *s00.CSGMembershipStatus, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s.Int(int64((*v)))
	s.End(f, aper.Snapshot{}, false)
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
func FailureEventReportingCauseCodec() s01.FailureEventReportingCauseValueCodec {
	return func() s01.FailureEventReportingCauseValueCodec {
		sealed := s01.FailureEventReportingCauseValueCodec{}
		*s01.BridgeFailureEventReportingCauseValueCodecFieldPath(&sealed) = "FailureEventReportingCause"
		*s01.BridgeFailureEventReportingCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.FailureEventReportingCause, error) {
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
		*s01.BridgeFailureEventReportingCauseValueCodecFieldEncode(&sealed) = func(value s00.FailureEventReportingCause, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		*s01.BridgeFailureEventReportingCauseValueCodecFieldCapture(&sealed) = func(v s00.FailureEventReportingCause, options aper.DecodeState) (s00.FailureEventReportingCause, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APFailureEventReportingCause(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s01.BridgeFailureEventReportingCauseValueCodecFieldCompare(&sealed) = func(v s00.FailureEventReportingCause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APFailureEventReportingCause(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeFailureEventReportingCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:FailureEventReportingCause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// FiveGSTACCodec binds the complete source value type.
func FiveGSTACCodec() s01.FiveGSTACValueCodec {
	return func() s01.FiveGSTACValueCodec {
		sealed := s01.FiveGSTACValueCodec{}
		*s01.BridgeFiveGSTACValueCodecFieldPath(&sealed) = "FiveGSTAC"
		*s01.BridgeFiveGSTACValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.FiveGSTAC, error) {
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
		*s01.BridgeFiveGSTACValueCodecFieldEncode(&sealed) = func(value s00.FiveGSTAC, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		*s01.BridgeFiveGSTACValueCodecFieldCapture(&sealed) = func(v s00.FiveGSTAC, options aper.DecodeState) (s00.FiveGSTAC, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APFiveGSTAC(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeFiveGSTACValueCodecFieldCompare(&sealed) = func(v s00.FiveGSTAC, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APFiveGSTAC(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeFiveGSTACValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:FiveGSTAC"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// FiveQICodec binds the complete source value type.
func FiveQICodec() s01.FiveQIValueCodec {
	return func() s01.FiveQIValueCodec {
		sealed := s01.FiveQIValueCodec{}
		*s01.BridgeFiveQIValueCodecFieldPath(&sealed) = "FiveQI"
		*s01.BridgeFiveQIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.FiveQI, error) {
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
		*s01.BridgeFiveQIValueCodecFieldEncode(&sealed) = func(value s00.FiveQI, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		*s01.BridgeFiveQIValueCodecFieldCapture(&sealed) = func(v s00.FiveQI, options aper.DecodeState) (s00.FiveQI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APFiveQI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeFiveQIValueCodecFieldCompare(&sealed) = func(v s00.FiveQI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APFiveQI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeFiveQIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:FiveQI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// ForbiddenInterRATsCodec binds the complete source value type.
func ForbiddenInterRATsCodec() s01.ForbiddenInterRATsValueCodec {
	return func() s01.ForbiddenInterRATsValueCodec {
		sealed := s01.ForbiddenInterRATsValueCodec{}
		*s01.BridgeForbiddenInterRATsValueCodecFieldPath(&sealed) = "ForbiddenInterRATs"
		*s01.BridgeForbiddenInterRATsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ForbiddenInterRATs, error) {
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
		*s01.BridgeForbiddenInterRATsValueCodecFieldEncode(&sealed) = func(value s00.ForbiddenInterRATs, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		*s01.BridgeForbiddenInterRATsValueCodecFieldCapture(&sealed) = func(v s00.ForbiddenInterRATs, options aper.DecodeState) (s00.ForbiddenInterRATs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APForbiddenInterRATs(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,

				root
		}
		*s01.BridgeForbiddenInterRATsValueCodecFieldCompare(&sealed) = func(v s00.ForbiddenInterRATs, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APForbiddenInterRATs(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeForbiddenInterRATsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ForbiddenInterRATs"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// GNBIDCodec binds the complete source value type.
func GNBIDCodec() s01.GNBIDValueCodec {
	return func() s01.GNBIDValueCodec {
		sealed := s01.GNBIDValueCodec{}
		*s01.BridgeGNBIDValueCodecFieldPath(&sealed) = "GNBID"
		*s01.BridgeGNBIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.GNBID, error) {
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
		*s01.BridgeGNBIDValueCodecFieldEncode(&sealed) = func(value s00.GNBID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		*s01.BridgeGNBIDValueCodecFieldCapture(&sealed) = func(v s00.GNBID, options aper.DecodeState) (s00.GNBID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APGNBID(&v, &s)
			var root aper.Snapshot
			s.End(f,
				&root, false)
			return v, root
		}
		*s01.BridgeGNBIDValueCodecFieldCompare(&sealed) = func(v s00.GNBID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APGNBID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeGNBIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GNBID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// GTPTEIDCodec binds the complete source value type.
func GTPTEIDCodec() s01.GTPTEIDValueCodec {
	return func() s01.GTPTEIDValueCodec {
		sealed := s01.GTPTEIDValueCodec{}
		*s01.BridgeGTPTEIDValueCodecFieldPath(&sealed) = "GTPTEID"
		*s01.BridgeGTPTEIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.GTPTEID, error) {
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
		*s01.BridgeGTPTEIDValueCodecFieldEncode(&sealed) = func(value s00.GTPTEID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		*s01.BridgeGTPTEIDValueCodecFieldCapture(&sealed) = func(v s00.GTPTEID, options aper.DecodeState) (s00.GTPTEID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureS1APGTPTEID(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s01.BridgeGTPTEIDValueCodecFieldCompare(&sealed) = func(v s00.GTPTEID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APGTPTEID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeGTPTEIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GTPTEID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HOReportingCauseCodec binds the complete source value type.
func HOReportingCauseCodec() s01.HOReportingCauseValueCodec {
	return func() s01.HOReportingCauseValueCodec {
		sealed := s01.HOReportingCauseValueCodec{}
		*s01.BridgeHOReportingCauseValueCodecFieldPath(&sealed) = "HOReportingCause"
		*s01.BridgeHOReportingCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.HOReportingCause, error) {
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
		*s01.BridgeHOReportingCauseValueCodecFieldEncode(&sealed) = func(value s00.HOReportingCause, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		*s01.BridgeHOReportingCauseValueCodecFieldCapture(&sealed) = func(v s00.HOReportingCause, options aper.DecodeState) (s00.HOReportingCause, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APHOReportingCause(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeHOReportingCauseValueCodecFieldCompare(&sealed) = func(v s00.HOReportingCause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APHOReportingCause(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s01.BridgeHOReportingCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HOReportingCause"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HoReportTypeCodec binds the complete source value type.
func HoReportTypeCodec() s01.HoReportTypeValueCodec {
	return func() s01.HoReportTypeValueCodec {
		sealed := s01.HoReportTypeValueCodec{}
		*s01.BridgeHoReportTypeValueCodecFieldPath(&sealed) = "HoReportType"
		*s01.BridgeHoReportTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.HoReportType, error) {
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
		*s01.BridgeHoReportTypeValueCodecFieldEncode(&sealed) = func(value s00.HoReportType, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		*s01.BridgeHoReportTypeValueCodecFieldCapture(&sealed) = func(v s00.HoReportType, options aper.DecodeState) (s00.HoReportType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APHoReportType(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeHoReportTypeValueCodecFieldCompare(&sealed) = func(v s00.HoReportType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APHoReportType(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s01.BridgeHoReportTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HoReportType"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// HoTypeCodec binds the complete source value type.
func HoTypeCodec() s01.HoTypeValueCodec {
	return func() s01.HoTypeValueCodec {
		sealed := s01.HoTypeValueCodec{}
		*s01.BridgeHoTypeValueCodecFieldPath(&sealed) = "HoType"
		*s01.BridgeHoTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.HoType, error) {
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
		*s01.BridgeHoTypeValueCodecFieldEncode(&sealed) = func(value s00.HoType, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
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
		*s01.BridgeHoTypeValueCodecFieldCapture(&sealed) = func(v s00.HoType, options aper.DecodeState) (s00.HoType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureS1APHoType(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeHoTypeValueCodecFieldCompare(&sealed) = func(v s00.HoType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeCompareS1APHoType(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeHoTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
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
func BridgeRelativeMMECapacityValueCodecFieldCapture(v *RelativeMMECapacityValueCodec) *func(s00.RelativeMMECapacity, aper.DecodeState) (s00.RelativeMMECapacity, aper.Snapshot) {
	return &v.capture
}
func BridgeRelativeMMECapacityValueCodecFieldCompare(v *RelativeMMECapacityValueCodec) *func(s00.RelativeMMECapacity, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRelativeMMECapacityValueCodecFieldContext(v *RelativeMMECapacityValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRelativeMMECapacityValueCodecFieldDecode(v *RelativeMMECapacityValueCodec) *func([]byte, aper.DecodeState) (s00.RelativeMMECapacity, error) {
	return &v.decode
}
func BridgeRelativeMMECapacityValueCodecFieldEncode(v *RelativeMMECapacityValueCodec) *func(s00.RelativeMMECapacity, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRelativeMMECapacityValueCodecFieldPath(v *RelativeMMECapacityValueCodec) *aper.Path {
	return &v.path
}
func BridgeRelayNodeIndicatorValueCodecFieldCapture(v *RelayNodeIndicatorValueCodec) *func(s00.RelayNodeIndicator, aper.DecodeState) (s00.RelayNodeIndicator, aper.Snapshot) {
	return &v.capture
}
func BridgeRelayNodeIndicatorValueCodecFieldCompare(v *RelayNodeIndicatorValueCodec) *func(s00.RelayNodeIndicator, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRelayNodeIndicatorValueCodecFieldContext(v *RelayNodeIndicatorValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRelayNodeIndicatorValueCodecFieldDecode(v *RelayNodeIndicatorValueCodec) *func([]byte, aper.DecodeState) (s00.RelayNodeIndicator, error) {
	return &v.decode
}
func BridgeRelayNodeIndicatorValueCodecFieldEncode(v *RelayNodeIndicatorValueCodec) *func(s00.RelayNodeIndicator, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRelayNodeIndicatorValueCodecFieldPath(v *RelayNodeIndicatorValueCodec) *aper.Path {
	return &v.path
}
func BridgeRepetitionPeriodValueCodecFieldCapture(v *RepetitionPeriodValueCodec) *func(s00.RepetitionPeriod, aper.DecodeState) (s00.RepetitionPeriod, aper.Snapshot) {
	return &v.capture
}
func BridgeRepetitionPeriodValueCodecFieldCompare(v *RepetitionPeriodValueCodec) *func(s00.RepetitionPeriod, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRepetitionPeriodValueCodecFieldContext(v *RepetitionPeriodValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRepetitionPeriodValueCodecFieldDecode(v *RepetitionPeriodValueCodec) *func([]byte, aper.DecodeState) (s00.RepetitionPeriod, error) {
	return &v.decode
}
func BridgeRepetitionPeriodValueCodecFieldEncode(v *RepetitionPeriodValueCodec) *func(s00.RepetitionPeriod, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRepetitionPeriodValueCodecFieldPath(v *RepetitionPeriodValueCodec) *aper.Path {
	return &v.path
}
func BridgeReportAmountMDTValueCodecFieldCapture(v *ReportAmountMDTValueCodec) *func(s00.ReportAmountMDT, aper.DecodeState) (s00.ReportAmountMDT, aper.Snapshot) {
	return &v.capture
}
func BridgeReportAmountMDTValueCodecFieldCompare(v *ReportAmountMDTValueCodec) *func(s00.ReportAmountMDT, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeReportAmountMDTValueCodecFieldContext(v *ReportAmountMDTValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeReportAmountMDTValueCodecFieldDecode(v *ReportAmountMDTValueCodec) *func([]byte, aper.DecodeState) (s00.ReportAmountMDT, error) {
	return &v.decode
}
func BridgeReportAmountMDTValueCodecFieldEncode(v *ReportAmountMDTValueCodec) *func(s00.ReportAmountMDT, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeReportAmountMDTValueCodecFieldPath(v *ReportAmountMDTValueCodec) *aper.Path {
	return &v.path
}
func BridgeReportAreaValueCodecFieldCapture(v *ReportAreaValueCodec) *func(s00.ReportArea, aper.DecodeState) (s00.ReportArea, aper.Snapshot) {
	return &v.capture
}
func BridgeReportAreaValueCodecFieldCompare(v *ReportAreaValueCodec) *func(s00.ReportArea, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeReportAreaValueCodecFieldContext(v *ReportAreaValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeReportAreaValueCodecFieldDecode(v *ReportAreaValueCodec) *func([]byte, aper.DecodeState) (s00.ReportArea, error) {
	return &v.decode
}
func BridgeReportAreaValueCodecFieldEncode(v *ReportAreaValueCodec) *func(s00.ReportArea, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeReportAreaValueCodecFieldPath(v *ReportAreaValueCodec) *aper.Path { return &v.path }
func BridgeReportIntervalMDTValueCodecFieldCapture(v *ReportIntervalMDTValueCodec) *func(s00.ReportIntervalMDT, aper.DecodeState) (s00.ReportIntervalMDT, aper.Snapshot) {
	return &v.capture
}
func BridgeReportIntervalMDTValueCodecFieldCompare(v *ReportIntervalMDTValueCodec) *func(s00.ReportIntervalMDT, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeReportIntervalMDTValueCodecFieldContext(v *ReportIntervalMDTValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeReportIntervalMDTValueCodecFieldDecode(v *ReportIntervalMDTValueCodec) *func([]byte, aper.DecodeState) (s00.ReportIntervalMDT, error) {
	return &v.decode
}
func BridgeReportIntervalMDTValueCodecFieldEncode(v *ReportIntervalMDTValueCodec) *func(s00.ReportIntervalMDT, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeReportIntervalMDTValueCodecFieldPath(v *ReportIntervalMDTValueCodec) *aper.Path {
	return &v.path
}
func BridgeRequestTypeAdditionalInfoValueCodecFieldCapture(v *RequestTypeAdditionalInfoValueCodec) *func(s00.RequestTypeAdditionalInfo, aper.DecodeState) (s00.RequestTypeAdditionalInfo, aper.Snapshot) {
	return &v.capture
}
func BridgeRequestTypeAdditionalInfoValueCodecFieldCompare(v *RequestTypeAdditionalInfoValueCodec) *func(s00.RequestTypeAdditionalInfo, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRequestTypeAdditionalInfoValueCodecFieldContext(v *RequestTypeAdditionalInfoValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRequestTypeAdditionalInfoValueCodecFieldDecode(v *RequestTypeAdditionalInfoValueCodec) *func([]byte, aper.DecodeState) (s00.RequestTypeAdditionalInfo, error) {
	return &v.decode
}
func BridgeRequestTypeAdditionalInfoValueCodecFieldEncode(v *RequestTypeAdditionalInfoValueCodec) *func(s00.RequestTypeAdditionalInfo, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRequestTypeAdditionalInfoValueCodecFieldPath(v *RequestTypeAdditionalInfoValueCodec) *aper.Path {
	return &v.path
}
func BridgeResetAllValueCodecFieldCapture(v *ResetAllValueCodec) *func(s00.ResetAll, aper.DecodeState) (s00.ResetAll, aper.Snapshot) {
	return &v.capture
}
func BridgeResetAllValueCodecFieldCompare(v *ResetAllValueCodec) *func(s00.ResetAll, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeResetAllValueCodecFieldContext(v *ResetAllValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResetAllValueCodecFieldDecode(v *ResetAllValueCodec) *func([]byte, aper.DecodeState) (s00.ResetAll, error) {
	return &v.decode
}
func BridgeResetAllValueCodecFieldEncode(v *ResetAllValueCodec) *func(s00.ResetAll, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResetAllValueCodecFieldPath(v *ResetAllValueCodec) *aper.Path { return &v.path }
func BridgeRoutingIDValueCodecFieldCapture(v *RoutingIDValueCodec) *func(s00.RoutingID, aper.DecodeState) (s00.RoutingID, aper.Snapshot) {
	return &v.capture
}
func BridgeRoutingIDValueCodecFieldCompare(v *RoutingIDValueCodec) *func(s00.RoutingID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRoutingIDValueCodecFieldContext(v *RoutingIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRoutingIDValueCodecFieldDecode(v *RoutingIDValueCodec) *func([]byte, aper.DecodeState) (s00.RoutingID, error) {
	return &v.decode
}
func BridgeRoutingIDValueCodecFieldEncode(v *RoutingIDValueCodec) *func(s00.RoutingID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRoutingIDValueCodecFieldPath(v *RoutingIDValueCodec) *aper.Path { return &v.path }
func BridgeS1APIEsMobilityInformationValueCodecFieldCapture(v *S1APIEsMobilityInformationValueCodec) *func(s00.S1APIEsMobilityInformation, aper.DecodeState) (s00.S1APIEsMobilityInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeS1APIEsMobilityInformationValueCodecFieldCompare(v *S1APIEsMobilityInformationValueCodec) *func(s00.S1APIEsMobilityInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeS1APIEsMobilityInformationValueCodecFieldContext(v *S1APIEsMobilityInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeS1APIEsMobilityInformationValueCodecFieldDecode(v *S1APIEsMobilityInformationValueCodec) *func([]byte, aper.DecodeState) (s00.S1APIEsMobilityInformation, error) {
	return &v.decode
}
func BridgeS1APIEsMobilityInformationValueCodecFieldEncode(v *S1APIEsMobilityInformationValueCodec) *func(s00.S1APIEsMobilityInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeS1APIEsMobilityInformationValueCodecFieldPath(v *S1APIEsMobilityInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONInformationRequestValueCodecFieldCapture(v *SONInformationRequestValueCodec) *func(s00.SONInformationRequest, aper.DecodeState) (s00.SONInformationRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeSONInformationRequestValueCodecFieldCompare(v *SONInformationRequestValueCodec) *func(s00.SONInformationRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONInformationRequestValueCodecFieldContext(v *SONInformationRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONInformationRequestValueCodecFieldDecode(v *SONInformationRequestValueCodec) *func([]byte, aper.DecodeState) (s00.SONInformationRequest, error) {
	return &v.decode
}
func BridgeSONInformationRequestValueCodecFieldEncode(v *SONInformationRequestValueCodec) *func(s00.SONInformationRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONInformationRequestValueCodecFieldPath(v *SONInformationRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeSONtransferApplicationIdentityValueCodecFieldCapture(v *SONtransferApplicationIdentityValueCodec) *func(s00.SONtransferApplicationIdentity, aper.DecodeState) (s00.SONtransferApplicationIdentity, aper.Snapshot) {
	return &v.capture
}
func BridgeSONtransferApplicationIdentityValueCodecFieldCompare(v *SONtransferApplicationIdentityValueCodec) *func(s00.SONtransferApplicationIdentity, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSONtransferApplicationIdentityValueCodecFieldContext(v *SONtransferApplicationIdentityValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSONtransferApplicationIdentityValueCodecFieldDecode(v *SONtransferApplicationIdentityValueCodec) *func([]byte, aper.DecodeState) (s00.SONtransferApplicationIdentity, error) {
	return &v.decode
}
func BridgeSONtransferApplicationIdentityValueCodecFieldEncode(v *SONtransferApplicationIdentityValueCodec) *func(s00.SONtransferApplicationIdentity, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSONtransferApplicationIdentityValueCodecFieldPath(v *SONtransferApplicationIdentityValueCodec) *aper.Path {
	return &v.path
}
func BridgeSRVCCHOIndicationValueCodecFieldCapture(v *SRVCCHOIndicationValueCodec) *func(s00.SRVCCHOIndication, aper.DecodeState) (s00.SRVCCHOIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeSRVCCHOIndicationValueCodecFieldCompare(v *SRVCCHOIndicationValueCodec) *func(s00.SRVCCHOIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSRVCCHOIndicationValueCodecFieldContext(v *SRVCCHOIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSRVCCHOIndicationValueCodecFieldDecode(v *SRVCCHOIndicationValueCodec) *func([]byte, aper.DecodeState) (s00.SRVCCHOIndication, error) {
	return &v.decode
}
func BridgeSRVCCHOIndicationValueCodecFieldEncode(v *SRVCCHOIndicationValueCodec) *func(s00.SRVCCHOIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSRVCCHOIndicationValueCodecFieldPath(v *SRVCCHOIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeSRVCCOperationNotPossibleValueCodecFieldCapture(v *SRVCCOperationNotPossibleValueCodec) *func(s00.SRVCCOperationNotPossible, aper.DecodeState) (s00.SRVCCOperationNotPossible, aper.Snapshot) {
	return &v.capture
}
func BridgeSRVCCOperationNotPossibleValueCodecFieldCompare(v *SRVCCOperationNotPossibleValueCodec) *func(s00.SRVCCOperationNotPossible, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSRVCCOperationNotPossibleValueCodecFieldContext(v *SRVCCOperationNotPossibleValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSRVCCOperationNotPossibleValueCodecFieldDecode(v *SRVCCOperationNotPossibleValueCodec) *func([]byte, aper.DecodeState) (s00.SRVCCOperationNotPossible, error) {
	return &v.decode
}
func BridgeSRVCCOperationNotPossibleValueCodecFieldEncode(v *SRVCCOperationNotPossibleValueCodec) *func(s00.SRVCCOperationNotPossible, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSRVCCOperationNotPossibleValueCodecFieldPath(v *SRVCCOperationNotPossibleValueCodec) *aper.Path {
	return &v.path
}
func BridgeSRVCCOperationPossibleValueCodecFieldCapture(v *SRVCCOperationPossibleValueCodec) *func(s00.SRVCCOperationPossible, aper.DecodeState) (s00.SRVCCOperationPossible, aper.Snapshot) {
	return &v.capture
}
func BridgeSRVCCOperationPossibleValueCodecFieldCompare(v *SRVCCOperationPossibleValueCodec) *func(s00.SRVCCOperationPossible, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSRVCCOperationPossibleValueCodecFieldContext(v *SRVCCOperationPossibleValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSRVCCOperationPossibleValueCodecFieldDecode(v *SRVCCOperationPossibleValueCodec) *func([]byte, aper.DecodeState) (s00.SRVCCOperationPossible, error) {
	return &v.decode
}
func BridgeSRVCCOperationPossibleValueCodecFieldEncode(v *SRVCCOperationPossibleValueCodec) *func(s00.SRVCCOperationPossible, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSRVCCOperationPossibleValueCodecFieldPath(v *SRVCCOperationPossibleValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecondaryRATDataUsageRequestValueCodecFieldCapture(v *SecondaryRATDataUsageRequestValueCodec) *func(s00.SecondaryRATDataUsageRequest, aper.DecodeState) (s00.SecondaryRATDataUsageRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATDataUsageRequestValueCodecFieldCompare(v *SecondaryRATDataUsageRequestValueCodec) *func(s00.SecondaryRATDataUsageRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATDataUsageRequestValueCodecFieldContext(v *SecondaryRATDataUsageRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATDataUsageRequestValueCodecFieldDecode(v *SecondaryRATDataUsageRequestValueCodec) *func([]byte, aper.DecodeState) (s00.SecondaryRATDataUsageRequest, error) {
	return &v.decode
}
func BridgeSecondaryRATDataUsageRequestValueCodecFieldEncode(v *SecondaryRATDataUsageRequestValueCodec) *func(s00.SecondaryRATDataUsageRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATDataUsageRequestValueCodecFieldPath(v *SecondaryRATDataUsageRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecondaryRATTypeValueCodecFieldCapture(v *SecondaryRATTypeValueCodec) *func(s00.SecondaryRATType, aper.DecodeState) (s00.SecondaryRATType, aper.Snapshot) {
	return &v.capture
}
func BridgeSecondaryRATTypeValueCodecFieldCompare(v *SecondaryRATTypeValueCodec) *func(s00.SecondaryRATType, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecondaryRATTypeValueCodecFieldContext(v *SecondaryRATTypeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecondaryRATTypeValueCodecFieldDecode(v *SecondaryRATTypeValueCodec) *func([]byte, aper.DecodeState) (s00.SecondaryRATType, error) {
	return &v.decode
}
func BridgeSecondaryRATTypeValueCodecFieldEncode(v *SecondaryRATTypeValueCodec) *func(s00.SecondaryRATType, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecondaryRATTypeValueCodecFieldPath(v *SecondaryRATTypeValueCodec) *aper.Path {
	return &v.path
}
func BridgeSecurityKeyValueCodecFieldCapture(v *SecurityKeyValueCodec) *func(s00.SecurityKey, aper.DecodeState) (s00.SecurityKey, aper.Snapshot) {
	return &v.capture
}
func BridgeSecurityKeyValueCodecFieldCompare(v *SecurityKeyValueCodec) *func(s00.SecurityKey, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSecurityKeyValueCodecFieldContext(v *SecurityKeyValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSecurityKeyValueCodecFieldDecode(v *SecurityKeyValueCodec) *func([]byte, aper.DecodeState) (s00.SecurityKey, error) {
	return &v.decode
}
func BridgeSecurityKeyValueCodecFieldEncode(v *SecurityKeyValueCodec) *func(s00.SecurityKey, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSecurityKeyValueCodecFieldPath(v *SecurityKeyValueCodec) *aper.Path { return &v.path }
func BridgeSensorMeasConfigValueCodecFieldCapture(v *SensorMeasConfigValueCodec) *func(s00.SensorMeasConfig, aper.DecodeState) (s00.SensorMeasConfig, aper.Snapshot) {
	return &v.capture
}
func BridgeSensorMeasConfigValueCodecFieldCompare(v *SensorMeasConfigValueCodec) *func(s00.SensorMeasConfig, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSensorMeasConfigValueCodecFieldContext(v *SensorMeasConfigValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSensorMeasConfigValueCodecFieldDecode(v *SensorMeasConfigValueCodec) *func([]byte, aper.DecodeState) (s00.SensorMeasConfig, error) {
	return &v.decode
}
func BridgeSensorMeasConfigValueCodecFieldEncode(v *SensorMeasConfigValueCodec) *func(s00.SensorMeasConfig, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSensorMeasConfigValueCodecFieldPath(v *SensorMeasConfigValueCodec) *aper.Path {
	return &v.path
}
func BridgeSerialNumberValueCodecFieldCapture(v *SerialNumberValueCodec) *func(s00.SerialNumber, aper.DecodeState) (s00.SerialNumber, aper.Snapshot) {
	return &v.capture
}
func BridgeSerialNumberValueCodecFieldCompare(v *SerialNumberValueCodec) *func(s00.SerialNumber, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSerialNumberValueCodecFieldContext(v *SerialNumberValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSerialNumberValueCodecFieldDecode(v *SerialNumberValueCodec) *func([]byte, aper.DecodeState) (s00.SerialNumber, error) {
	return &v.decode
}
func BridgeSerialNumberValueCodecFieldEncode(v *SerialNumberValueCodec) *func(s00.SerialNumber, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSerialNumberValueCodecFieldPath(v *SerialNumberValueCodec) *aper.Path { return &v.path }
func BridgeServedGroupIDsValueCodecFieldCapture(v *ServedGroupIDsValueCodec) *func(s00.ServedGroupIDs, aper.DecodeState) (s00.ServedGroupIDs, aper.Snapshot) {
	return &v.capture
}
func BridgeServedGroupIDsValueCodecFieldCompare(v *ServedGroupIDsValueCodec) *func(s00.ServedGroupIDs, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeServedGroupIDsValueCodecFieldContext(v *ServedGroupIDsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeServedGroupIDsValueCodecFieldDecode(v *ServedGroupIDsValueCodec) *func([]byte, aper.DecodeState) (s00.ServedGroupIDs, error) {
	return &v.decode
}
func BridgeServedGroupIDsValueCodecFieldEncode(v *ServedGroupIDsValueCodec) *func(s00.ServedGroupIDs, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeServedGroupIDsValueCodecFieldPath(v *ServedGroupIDsValueCodec) *aper.Path { return &v.path }
func BridgeServedMMECsValueCodecFieldCapture(v *ServedMMECsValueCodec) *func(s00.ServedMMECs, aper.DecodeState) (s00.ServedMMECs, aper.Snapshot) {
	return &v.capture
}
func BridgeServedMMECsValueCodecFieldCompare(v *ServedMMECsValueCodec) *func(s00.ServedMMECs, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeServedMMECsValueCodecFieldContext(v *ServedMMECsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeServedMMECsValueCodecFieldDecode(v *ServedMMECsValueCodec) *func([]byte, aper.DecodeState) (s00.ServedMMECs, error) {
	return &v.decode
}
func BridgeServedMMECsValueCodecFieldEncode(v *ServedMMECsValueCodec) *func(s00.ServedMMECs, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeServedMMECsValueCodecFieldPath(v *ServedMMECsValueCodec) *aper.Path { return &v.path }
func BridgeServedPLMNsValueCodecFieldCapture(v *ServedPLMNsValueCodec) *func(s00.ServedPLMNs, aper.DecodeState) (s00.ServedPLMNs, aper.Snapshot) {
	return &v.capture
}
func BridgeServedPLMNsValueCodecFieldCompare(v *ServedPLMNsValueCodec) *func(s00.ServedPLMNs, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeServedPLMNsValueCodecFieldContext(v *ServedPLMNsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeServedPLMNsValueCodecFieldDecode(v *ServedPLMNsValueCodec) *func([]byte, aper.DecodeState) (s00.ServedPLMNs, error) {
	return &v.decode
}
func BridgeServedPLMNsValueCodecFieldEncode(v *ServedPLMNsValueCodec) *func(s00.ServedPLMNs, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeServedPLMNsValueCodecFieldPath(v *ServedPLMNsValueCodec) *aper.Path { return &v.path }
func BridgeServiceTypeValueCodecFieldCapture(v *ServiceTypeValueCodec) *func(s00.ServiceType, aper.DecodeState) (s00.ServiceType, aper.Snapshot) {
	return &v.capture
}
func BridgeServiceTypeValueCodecFieldCompare(v *ServiceTypeValueCodec) *func(s00.ServiceType, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeServiceTypeValueCodecFieldContext(v *ServiceTypeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeServiceTypeValueCodecFieldDecode(v *ServiceTypeValueCodec) *func([]byte, aper.DecodeState) (s00.ServiceType, error) {
	return &v.decode
}
func BridgeServiceTypeValueCodecFieldEncode(v *ServiceTypeValueCodec) *func(s00.ServiceType, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeServiceTypeValueCodecFieldPath(v *ServiceTypeValueCodec) *aper.Path { return &v.path }
func BridgeSliceByteValueCodecFieldCapture(v *SliceByteValueCodec) *func([]byte, aper.DecodeState) ([]byte, aper.Snapshot) {
	return &v.capture
}
func BridgeSliceByteValueCodecFieldCompare(v *SliceByteValueCodec) *func([]byte, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSliceByteValueCodecFieldContext(v *SliceByteValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSliceByteValueCodecFieldDecode(v *SliceByteValueCodec) *func([]byte, aper.DecodeState) ([]byte, error) {
	return &v.decode
}
func BridgeSliceByteValueCodecFieldEncode(v *SliceByteValueCodec) *func([]byte, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSliceByteValueCodecFieldPath(v *SliceByteValueCodec) *aper.Path { return &v.path }
func BridgeSonTransferIEsMobilityInformationValueCodecFieldCapture(v *SonTransferIEsMobilityInformationValueCodec) *func(s00.SonTransferIEsMobilityInformation, aper.DecodeState) (s00.SonTransferIEsMobilityInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeSonTransferIEsMobilityInformationValueCodecFieldCompare(v *SonTransferIEsMobilityInformationValueCodec) *func(s00.SonTransferIEsMobilityInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSonTransferIEsMobilityInformationValueCodecFieldContext(v *SonTransferIEsMobilityInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSonTransferIEsMobilityInformationValueCodecFieldDecode(v *SonTransferIEsMobilityInformationValueCodec) *func([]byte, aper.DecodeState) (s00.SonTransferIEsMobilityInformation, error) {
	return &v.decode
}
func BridgeSonTransferIEsMobilityInformationValueCodecFieldEncode(v *SonTransferIEsMobilityInformationValueCodec) *func(s00.SonTransferIEsMobilityInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSonTransferIEsMobilityInformationValueCodecFieldPath(v *SonTransferIEsMobilityInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceBSSToTargetBSSTransparentContainerValueCodecFieldCapture(v *SourceBSSToTargetBSSTransparentContainerValueCodec) *func(s00.SourceBSSToTargetBSSTransparentContainer, aper.DecodeState) (s00.SourceBSSToTargetBSSTransparentContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceBSSToTargetBSSTransparentContainerValueCodecFieldCompare(v *SourceBSSToTargetBSSTransparentContainerValueCodec) *func(s00.SourceBSSToTargetBSSTransparentContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceBSSToTargetBSSTransparentContainerValueCodecFieldContext(v *SourceBSSToTargetBSSTransparentContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceBSSToTargetBSSTransparentContainerValueCodecFieldDecode(v *SourceBSSToTargetBSSTransparentContainerValueCodec) *func([]byte, aper.DecodeState) (s00.SourceBSSToTargetBSSTransparentContainer, error) {
	return &v.decode
}
func BridgeSourceBSSToTargetBSSTransparentContainerValueCodecFieldEncode(v *SourceBSSToTargetBSSTransparentContainerValueCodec) *func(s00.SourceBSSToTargetBSSTransparentContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceBSSToTargetBSSTransparentContainerValueCodecFieldPath(v *SourceBSSToTargetBSSTransparentContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodecFieldCapture(v *SourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodec) *func(s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer, aper.DecodeState) (s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodecFieldCompare(v *SourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodec) *func(s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodecFieldContext(v *SourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodecFieldDecode(v *SourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodec) *func([]byte, aper.DecodeState) (s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer, error) {
	return &v.decode
}
func BridgeSourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodecFieldEncode(v *SourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodec) *func(s00.SourceNgRanNodeToTargetNgRanNodeTransparentContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodecFieldPath(v *SourceNgRanNodeToTargetNgRanNodeTransparentContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceOfUEActivityBehaviourInformationValueCodecFieldCapture(v *SourceOfUEActivityBehaviourInformationValueCodec) *func(s00.SourceOfUEActivityBehaviourInformation, aper.DecodeState) (s00.SourceOfUEActivityBehaviourInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceOfUEActivityBehaviourInformationValueCodecFieldCompare(v *SourceOfUEActivityBehaviourInformationValueCodec) *func(s00.SourceOfUEActivityBehaviourInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceOfUEActivityBehaviourInformationValueCodecFieldContext(v *SourceOfUEActivityBehaviourInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceOfUEActivityBehaviourInformationValueCodecFieldDecode(v *SourceOfUEActivityBehaviourInformationValueCodec) *func([]byte, aper.DecodeState) (s00.SourceOfUEActivityBehaviourInformation, error) {
	return &v.decode
}
func BridgeSourceOfUEActivityBehaviourInformationValueCodecFieldEncode(v *SourceOfUEActivityBehaviourInformationValueCodec) *func(s00.SourceOfUEActivityBehaviourInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceOfUEActivityBehaviourInformationValueCodecFieldPath(v *SourceOfUEActivityBehaviourInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceRNCToTargetRNCTransparentContainerValueCodecFieldCapture(v *SourceRNCToTargetRNCTransparentContainerValueCodec) *func(s00.SourceRNCToTargetRNCTransparentContainer, aper.DecodeState) (s00.SourceRNCToTargetRNCTransparentContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceRNCToTargetRNCTransparentContainerValueCodecFieldCompare(v *SourceRNCToTargetRNCTransparentContainerValueCodec) *func(s00.SourceRNCToTargetRNCTransparentContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceRNCToTargetRNCTransparentContainerValueCodecFieldContext(v *SourceRNCToTargetRNCTransparentContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceRNCToTargetRNCTransparentContainerValueCodecFieldDecode(v *SourceRNCToTargetRNCTransparentContainerValueCodec) *func([]byte, aper.DecodeState) (s00.SourceRNCToTargetRNCTransparentContainer, error) {
	return &v.decode
}
func BridgeSourceRNCToTargetRNCTransparentContainerValueCodecFieldEncode(v *SourceRNCToTargetRNCTransparentContainerValueCodec) *func(s00.SourceRNCToTargetRNCTransparentContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceRNCToTargetRNCTransparentContainerValueCodecFieldPath(v *SourceRNCToTargetRNCTransparentContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeSourceToTargetTransparentContainerValueCodecFieldCapture(v *SourceToTargetTransparentContainerValueCodec) *func(s00.SourceToTargetTransparentContainer, aper.DecodeState) (s00.SourceToTargetTransparentContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeSourceToTargetTransparentContainerValueCodecFieldCompare(v *SourceToTargetTransparentContainerValueCodec) *func(s00.SourceToTargetTransparentContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSourceToTargetTransparentContainerValueCodecFieldContext(v *SourceToTargetTransparentContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSourceToTargetTransparentContainerValueCodecFieldDecode(v *SourceToTargetTransparentContainerValueCodec) *func([]byte, aper.DecodeState) (s00.SourceToTargetTransparentContainer, error) {
	return &v.decode
}
func BridgeSourceToTargetTransparentContainerValueCodecFieldEncode(v *SourceToTargetTransparentContainerValueCodec) *func(s00.SourceToTargetTransparentContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSourceToTargetTransparentContainerValueCodecFieldPath(v *SourceToTargetTransparentContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeStratumLevelValueCodecFieldCapture(v *StratumLevelValueCodec) *func(s00.StratumLevel, aper.DecodeState) (s00.StratumLevel, aper.Snapshot) {
	return &v.capture
}
func BridgeStratumLevelValueCodecFieldCompare(v *StratumLevelValueCodec) *func(s00.StratumLevel, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeStratumLevelValueCodecFieldContext(v *StratumLevelValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeStratumLevelValueCodecFieldDecode(v *StratumLevelValueCodec) *func([]byte, aper.DecodeState) (s00.StratumLevel, error) {
	return &v.decode
}
func BridgeStratumLevelValueCodecFieldEncode(v *StratumLevelValueCodec) *func(s00.StratumLevel, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeStratumLevelValueCodecFieldPath(v *StratumLevelValueCodec) *aper.Path { return &v.path }
func BridgeSubscriberProfileIDforRFPValueCodecFieldCapture(v *SubscriberProfileIDforRFPValueCodec) *func(s00.SubscriberProfileIDforRFP, aper.DecodeState) (s00.SubscriberProfileIDforRFP, aper.Snapshot) {
	return &v.capture
}
func BridgeSubscriberProfileIDforRFPValueCodecFieldCompare(v *SubscriberProfileIDforRFPValueCodec) *func(s00.SubscriberProfileIDforRFP, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSubscriberProfileIDforRFPValueCodecFieldContext(v *SubscriberProfileIDforRFPValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSubscriberProfileIDforRFPValueCodecFieldDecode(v *SubscriberProfileIDforRFPValueCodec) *func([]byte, aper.DecodeState) (s00.SubscriberProfileIDforRFP, error) {
	return &v.decode
}
func BridgeSubscriberProfileIDforRFPValueCodecFieldEncode(v *SubscriberProfileIDforRFPValueCodec) *func(s00.SubscriberProfileIDforRFP, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSubscriberProfileIDforRFPValueCodecFieldPath(v *SubscriberProfileIDforRFPValueCodec) *aper.Path {
	return &v.path
}
func BridgeSynchronisationStatusValueCodecFieldCapture(v *SynchronisationStatusValueCodec) *func(s00.SynchronisationStatus, aper.DecodeState) (s00.SynchronisationStatus, aper.Snapshot) {
	return &v.capture
}
func BridgeSynchronisationStatusValueCodecFieldCompare(v *SynchronisationStatusValueCodec) *func(s00.SynchronisationStatus, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeSynchronisationStatusValueCodecFieldContext(v *SynchronisationStatusValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSynchronisationStatusValueCodecFieldDecode(v *SynchronisationStatusValueCodec) *func([]byte, aper.DecodeState) (s00.SynchronisationStatus, error) {
	return &v.decode
}
func BridgeSynchronisationStatusValueCodecFieldEncode(v *SynchronisationStatusValueCodec) *func(s00.SynchronisationStatus, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSynchronisationStatusValueCodecFieldPath(v *SynchronisationStatusValueCodec) *aper.Path {
	return &v.path
}
func BridgeTACListInLTENTNValueCodecFieldCapture(v *TACListInLTENTNValueCodec) *func(s00.TACListInLTENTN, aper.DecodeState) (s00.TACListInLTENTN, aper.Snapshot) {
	return &v.capture
}
func BridgeTACListInLTENTNValueCodecFieldCompare(v *TACListInLTENTNValueCodec) *func(s00.TACListInLTENTN, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTACListInLTENTNValueCodecFieldContext(v *TACListInLTENTNValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTACListInLTENTNValueCodecFieldDecode(v *TACListInLTENTNValueCodec) *func([]byte, aper.DecodeState) (s00.TACListInLTENTN, error) {
	return &v.decode
}
func BridgeTACListInLTENTNValueCodecFieldEncode(v *TACListInLTENTNValueCodec) *func(s00.TACListInLTENTN, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTACListInLTENTNValueCodecFieldPath(v *TACListInLTENTNValueCodec) *aper.Path {
	return &v.path
}
func BridgeTACValueCodecFieldCapture(v *TACValueCodec) *func(s00.TAC, aper.DecodeState) (s00.TAC, aper.Snapshot) {
	return &v.capture
}
func BridgeTACValueCodecFieldCompare(v *TACValueCodec) *func(s00.TAC, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTACValueCodecFieldContext(v *TACValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeTACValueCodecFieldDecode(v *TACValueCodec) *func([]byte, aper.DecodeState) (s00.TAC, error) {
	return &v.decode
}
func BridgeTACValueCodecFieldEncode(v *TACValueCodec) *func(s00.TAC, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTACValueCodecFieldPath(v *TACValueCodec) *aper.Path { return &v.path }
func BridgeTAListforMDTValueCodecFieldCapture(v *TAListforMDTValueCodec) *func(s00.TAListforMDT, aper.DecodeState) (s00.TAListforMDT, aper.Snapshot) {
	return &v.capture
}
func BridgeTAListforMDTValueCodecFieldCompare(v *TAListforMDTValueCodec) *func(s00.TAListforMDT, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAListforMDTValueCodecFieldContext(v *TAListforMDTValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAListforMDTValueCodecFieldDecode(v *TAListforMDTValueCodec) *func([]byte, aper.DecodeState) (s00.TAListforMDT, error) {
	return &v.decode
}
func BridgeTAListforMDTValueCodecFieldEncode(v *TAListforMDTValueCodec) *func(s00.TAListforMDT, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAListforMDTValueCodecFieldPath(v *TAListforMDTValueCodec) *aper.Path { return &v.path }
func BridgeTAListforQMCValueCodecFieldCapture(v *TAListforQMCValueCodec) *func(s00.TAListforQMC, aper.DecodeState) (s00.TAListforQMC, aper.Snapshot) {
	return &v.capture
}
func BridgeTAListforQMCValueCodecFieldCompare(v *TAListforQMCValueCodec) *func(s00.TAListforQMC, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTAListforQMCValueCodecFieldContext(v *TAListforQMCValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTAListforQMCValueCodecFieldDecode(v *TAListforQMCValueCodec) *func([]byte, aper.DecodeState) (s00.TAListforQMC, error) {
	return &v.decode
}
func BridgeTAListforQMCValueCodecFieldEncode(v *TAListforQMCValueCodec) *func(s00.TAListforQMC, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTAListforQMCValueCodecFieldPath(v *TAListforQMCValueCodec) *aper.Path { return &v.path }
func BridgeTBCDSTRINGValueCodecFieldCapture(v *TBCDSTRINGValueCodec) *func(s00.TBCDSTRING, aper.DecodeState) (s00.TBCDSTRING, aper.Snapshot) {
	return &v.capture
}
func BridgeTBCDSTRINGValueCodecFieldCompare(v *TBCDSTRINGValueCodec) *func(s00.TBCDSTRING, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTBCDSTRINGValueCodecFieldContext(v *TBCDSTRINGValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTBCDSTRINGValueCodecFieldDecode(v *TBCDSTRINGValueCodec) *func([]byte, aper.DecodeState) (s00.TBCDSTRING, error) {
	return &v.decode
}
func BridgeTBCDSTRINGValueCodecFieldEncode(v *TBCDSTRINGValueCodec) *func(s00.TBCDSTRING, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTBCDSTRINGValueCodecFieldPath(v *TBCDSTRINGValueCodec) *aper.Path { return &v.path }
func BridgeTargetBSSToSourceBSSTransparentContainerValueCodecFieldCapture(v *TargetBSSToSourceBSSTransparentContainerValueCodec) *func(s00.TargetBSSToSourceBSSTransparentContainer, aper.DecodeState) (s00.TargetBSSToSourceBSSTransparentContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTargetBSSToSourceBSSTransparentContainerValueCodecFieldCompare(v *TargetBSSToSourceBSSTransparentContainerValueCodec) *func(s00.TargetBSSToSourceBSSTransparentContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTargetBSSToSourceBSSTransparentContainerValueCodecFieldContext(v *TargetBSSToSourceBSSTransparentContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargetBSSToSourceBSSTransparentContainerValueCodecFieldDecode(v *TargetBSSToSourceBSSTransparentContainerValueCodec) *func([]byte, aper.DecodeState) (s00.TargetBSSToSourceBSSTransparentContainer, error) {
	return &v.decode
}
func BridgeTargetBSSToSourceBSSTransparentContainerValueCodecFieldEncode(v *TargetBSSToSourceBSSTransparentContainerValueCodec) *func(s00.TargetBSSToSourceBSSTransparentContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTargetBSSToSourceBSSTransparentContainerValueCodecFieldPath(v *TargetBSSToSourceBSSTransparentContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodecFieldCapture(v *TargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodec) *func(s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer, aper.DecodeState) (s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodecFieldCompare(v *TargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodec) *func(s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodecFieldContext(v *TargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodecFieldDecode(v *TargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodec) *func([]byte, aper.DecodeState) (s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer, error) {
	return &v.decode
}
func BridgeTargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodecFieldEncode(v *TargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodec) *func(s00.TargetNgRanNodeToSourceNgRanNodeTransparentContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodecFieldPath(v *TargetNgRanNodeToSourceNgRanNodeTransparentContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTargetRNCToSourceRNCTransparentContainerValueCodecFieldCapture(v *TargetRNCToSourceRNCTransparentContainerValueCodec) *func(s00.TargetRNCToSourceRNCTransparentContainer, aper.DecodeState) (s00.TargetRNCToSourceRNCTransparentContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTargetRNCToSourceRNCTransparentContainerValueCodecFieldCompare(v *TargetRNCToSourceRNCTransparentContainerValueCodec) *func(s00.TargetRNCToSourceRNCTransparentContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTargetRNCToSourceRNCTransparentContainerValueCodecFieldContext(v *TargetRNCToSourceRNCTransparentContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargetRNCToSourceRNCTransparentContainerValueCodecFieldDecode(v *TargetRNCToSourceRNCTransparentContainerValueCodec) *func([]byte, aper.DecodeState) (s00.TargetRNCToSourceRNCTransparentContainer, error) {
	return &v.decode
}
func BridgeTargetRNCToSourceRNCTransparentContainerValueCodecFieldEncode(v *TargetRNCToSourceRNCTransparentContainerValueCodec) *func(s00.TargetRNCToSourceRNCTransparentContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTargetRNCToSourceRNCTransparentContainerValueCodecFieldPath(v *TargetRNCToSourceRNCTransparentContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTargetToSourceTransparentContainerValueCodecFieldCapture(v *TargetToSourceTransparentContainerValueCodec) *func(s00.TargetToSourceTransparentContainer, aper.DecodeState) (s00.TargetToSourceTransparentContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTargetToSourceTransparentContainerValueCodecFieldCompare(v *TargetToSourceTransparentContainerValueCodec) *func(s00.TargetToSourceTransparentContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTargetToSourceTransparentContainerValueCodecFieldContext(v *TargetToSourceTransparentContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTargetToSourceTransparentContainerValueCodecFieldDecode(v *TargetToSourceTransparentContainerValueCodec) *func([]byte, aper.DecodeState) (s00.TargetToSourceTransparentContainer, error) {
	return &v.decode
}
func BridgeTargetToSourceTransparentContainerValueCodecFieldEncode(v *TargetToSourceTransparentContainerValueCodec) *func(s00.TargetToSourceTransparentContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTargetToSourceTransparentContainerValueCodecFieldPath(v *TargetToSourceTransparentContainerValueCodec) *aper.Path {
	return &v.path
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
