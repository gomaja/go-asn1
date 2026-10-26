// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s01 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s01

import (
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// ReceiveStatusOfULPDCPSDUsExtendedValueCodec is the concrete ValueCodec[ReceiveStatusOfULPDCPSDUsExtended].
type ReceiveStatusOfULPDCPSDUsExtendedValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ReceiveStatusOfULPDCPSDUsExtended,

		error)
	encode func(s00.ReceiveStatusOfULPDCPSDUsExtended,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ReceiveStatusOfULPDCPSDUsExtended, aper.DecodeState,

	) (s00.ReceiveStatusOfULPDCPSDUsExtended, aper.Snapshot,

	)
	compare func(s00.ReceiveStatusOfULPDCPSDUsExtended, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ReceiveStatusOfULPDCPSDUsExtendedValueCodec) New(value s00.ReceiveStatusOfULPDCPSDUsExtended,

) (ReceiveStatusOfULPDCPSDUsExtendedAPERValue, error) {
	if c.encode == nil {
		return ReceiveStatusOfULPDCPSDUsExtendedAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ReceiveStatusOfULPDCPSDUsExtendedAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ReceiveStatusOfULPDCPSDUsExtendedAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ReceiveStatusOfULPDCPSDUsExtendedAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ReceiveStatusOfULPDCPSDUsExtendedValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ReceiveStatusOfULPDCPSDUsExtendedAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ReceiveStatusOfULPDCPSDUsExtendedAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ReceiveStatusOfULPDCPSDUsExtendedAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ReceiveStatusOfULPDCPSDUsExtendedAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ReceiveStatusOfULPDCPSDUsExtendedAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ReceiveStatusOfULPDCPSDUsExtendedValueCodec) EncodeAPER(value ReceiveStatusOfULPDCPSDUsExtendedAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ReceiveStatusOfULPDCPSDUsExtendedValueCodec) encodeBudgetValue(value s00.ReceiveStatusOfULPDCPSDUsExtended,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ReceiveStatusOfULPDCPSDUsExtendedValueCodec) encodeChanged(value s00.ReceiveStatusOfULPDCPSDUsExtended,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec is the concrete ValueCodec[ReceiveStatusOfULPDCPSDUsPDCPSNlength18].
type ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18,

		error)
	encode func(s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, aper.DecodeState,

	) (s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, aper.Snapshot,

	)
	compare func(s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec) New(value s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18,

) (ReceiveStatusOfULPDCPSDUsPDCPSNlength18APERValue, error) {
	if c.encode == nil {
		return ReceiveStatusOfULPDCPSDUsPDCPSNlength18APERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ReceiveStatusOfULPDCPSDUsPDCPSNlength18APERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ReceiveStatusOfULPDCPSDUsPDCPSNlength18APERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ReceiveStatusOfULPDCPSDUsPDCPSNlength18APERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ReceiveStatusOfULPDCPSDUsPDCPSNlength18APERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ReceiveStatusOfULPDCPSDUsPDCPSNlength18APERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ReceiveStatusOfULPDCPSDUsPDCPSNlength18APERValue{}, report, aper.OperationError(err, c.path)
		}
		return ReceiveStatusOfULPDCPSDUsPDCPSNlength18APERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ReceiveStatusOfULPDCPSDUsPDCPSNlength18APERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec) EncodeAPER(value ReceiveStatusOfULPDCPSDUsPDCPSNlength18APERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec) encodeBudgetValue(value s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec) encodeChanged(value s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PacketLossRateValueCodec is the concrete ValueCodec[PacketLossRate].
type PacketLossRateValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PacketLossRate,

		error)
	encode func(s00.PacketLossRate,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PacketLossRate, aper.DecodeState,

	) (s00.PacketLossRate, aper.Snapshot,

	)
	compare func(s00.PacketLossRate, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PacketLossRateValueCodec) New(value s00.PacketLossRate,

) (PacketLossRateAPERValue, error) {
	if c.encode == nil {
		return PacketLossRateAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PacketLossRateAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PacketLossRateAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PacketLossRateAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PacketLossRateValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PacketLossRateAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PacketLossRateAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PacketLossRateAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PacketLossRateAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PacketLossRateAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PacketLossRateValueCodec) EncodeAPER(value PacketLossRateAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PacketLossRateValueCodec) encodeBudgetValue(value s00.PacketLossRate,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PacketLossRateValueCodec) encodeChanged(value s00.PacketLossRate,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NRrestrictioninEPSasSecondaryRATValueCodec is the concrete ValueCodec[NRrestrictioninEPSasSecondaryRAT].
type NRrestrictioninEPSasSecondaryRATValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NRrestrictioninEPSasSecondaryRAT,

		error)
	encode func(s00.NRrestrictioninEPSasSecondaryRAT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NRrestrictioninEPSasSecondaryRAT, aper.DecodeState,

	) (s00.NRrestrictioninEPSasSecondaryRAT, aper.Snapshot,

	)
	compare func(s00.NRrestrictioninEPSasSecondaryRAT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NRrestrictioninEPSasSecondaryRATValueCodec) New(value s00.NRrestrictioninEPSasSecondaryRAT,

) (NRrestrictioninEPSasSecondaryRATAPERValue, error) {
	if c.encode == nil {
		return NRrestrictioninEPSasSecondaryRATAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NRrestrictioninEPSasSecondaryRATAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRrestrictioninEPSasSecondaryRATAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NRrestrictioninEPSasSecondaryRATAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NRrestrictioninEPSasSecondaryRATValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NRrestrictioninEPSasSecondaryRATAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NRrestrictioninEPSasSecondaryRATAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NRrestrictioninEPSasSecondaryRATAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NRrestrictioninEPSasSecondaryRATAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NRrestrictioninEPSasSecondaryRATAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NRrestrictioninEPSasSecondaryRATValueCodec) EncodeAPER(value NRrestrictioninEPSasSecondaryRATAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NRrestrictioninEPSasSecondaryRATValueCodec) encodeBudgetValue(value s00.NRrestrictioninEPSasSecondaryRAT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NRrestrictioninEPSasSecondaryRATValueCodec) encodeChanged(value s00.NRrestrictioninEPSasSecondaryRAT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NRrestrictionin5GSValueCodec is the concrete ValueCodec[NRrestrictionin5GS].
type NRrestrictionin5GSValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NRrestrictionin5GS,

		error)
	encode func(s00.NRrestrictionin5GS,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NRrestrictionin5GS, aper.DecodeState,

	) (s00.NRrestrictionin5GS, aper.Snapshot,

	)
	compare func(s00.NRrestrictionin5GS, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NRrestrictionin5GSValueCodec) New(value s00.NRrestrictionin5GS,

) (NRrestrictionin5GSAPERValue, error) {
	if c.encode == nil {
		return NRrestrictionin5GSAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NRrestrictionin5GSAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRrestrictionin5GSAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NRrestrictionin5GSAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NRrestrictionin5GSValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NRrestrictionin5GSAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NRrestrictionin5GSAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NRrestrictionin5GSAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NRrestrictionin5GSAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NRrestrictionin5GSAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NRrestrictionin5GSValueCodec) EncodeAPER(value NRrestrictionin5GSAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NRrestrictionin5GSValueCodec) encodeBudgetValue(value s00.NRrestrictionin5GS,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NRrestrictionin5GSValueCodec) encodeChanged(value s00.NRrestrictionin5GS,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PLMNidentityValueCodec is the concrete ValueCodec[PLMNidentity].
type PLMNidentityValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PLMNidentity,

		error)
	encode func(s00.PLMNidentity,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PLMNidentity, aper.DecodeState,

	) (s00.PLMNidentity, aper.Snapshot,

	)
	compare func(s00.PLMNidentity, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PLMNidentityValueCodec) New(value s00.PLMNidentity,

) (PLMNidentityAPERValue, error) {
	if c.encode == nil {
		return PLMNidentityAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PLMNidentityAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PLMNidentityAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PLMNidentityAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PLMNidentityValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PLMNidentityAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PLMNidentityAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PLMNidentityAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PLMNidentityAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PLMNidentityAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PLMNidentityValueCodec) EncodeAPER(value PLMNidentityAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PLMNidentityValueCodec) encodeBudgetValue(value s00.PLMNidentity,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PLMNidentityValueCodec) encodeChanged(value s00.PLMNidentity,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MDTLocationInfoValueCodec is the concrete ValueCodec[MDTLocationInfo].
type MDTLocationInfoValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.MDTLocationInfo,

		error)
	encode func(s00.MDTLocationInfo,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.MDTLocationInfo, aper.DecodeState,

	) (s00.MDTLocationInfo, aper.Snapshot,

	)
	compare func(s00.MDTLocationInfo, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MDTLocationInfoValueCodec) New(value s00.MDTLocationInfo,

) (MDTLocationInfoAPERValue, error) {
	if c.encode == nil {
		return MDTLocationInfoAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTLocationInfoAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MDTLocationInfoAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MDTLocationInfoAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MDTLocationInfoValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MDTLocationInfoAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MDTLocationInfoAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MDTLocationInfoAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MDTLocationInfoAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MDTLocationInfoAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MDTLocationInfoValueCodec) EncodeAPER(value MDTLocationInfoAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MDTLocationInfoValueCodec) encodeBudgetValue(value s00.MDTLocationInfo,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MDTLocationInfoValueCodec) encodeChanged(value s00.MDTLocationInfo,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M4ReportAmountMDTValueCodec is the concrete ValueCodec[M4ReportAmountMDT].
type M4ReportAmountMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.M4ReportAmountMDT,

		error)
	encode func(s00.M4ReportAmountMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.M4ReportAmountMDT, aper.DecodeState,

	) (s00.M4ReportAmountMDT, aper.Snapshot,

	)
	compare func(s00.M4ReportAmountMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M4ReportAmountMDTValueCodec) New(value s00.M4ReportAmountMDT,

) (M4ReportAmountMDTAPERValue, error) {
	if c.encode == nil {
		return M4ReportAmountMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M4ReportAmountMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M4ReportAmountMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M4ReportAmountMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M4ReportAmountMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M4ReportAmountMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M4ReportAmountMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M4ReportAmountMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M4ReportAmountMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M4ReportAmountMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M4ReportAmountMDTValueCodec) EncodeAPER(value M4ReportAmountMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c M4ReportAmountMDTValueCodec) encodeBudgetValue(value s00.M4ReportAmountMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M4ReportAmountMDTValueCodec) encodeChanged(value s00.M4ReportAmountMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M5ReportAmountMDTValueCodec is the concrete ValueCodec[M5ReportAmountMDT].
type M5ReportAmountMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.M5ReportAmountMDT,

		error)
	encode func(s00.M5ReportAmountMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.M5ReportAmountMDT, aper.DecodeState,

	) (s00.M5ReportAmountMDT, aper.Snapshot,

	)
	compare func(s00.M5ReportAmountMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M5ReportAmountMDTValueCodec) New(value s00.M5ReportAmountMDT,

) (M5ReportAmountMDTAPERValue, error) {
	if c.encode == nil {
		return M5ReportAmountMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M5ReportAmountMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M5ReportAmountMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M5ReportAmountMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M5ReportAmountMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M5ReportAmountMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M5ReportAmountMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M5ReportAmountMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M5ReportAmountMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M5ReportAmountMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M5ReportAmountMDTValueCodec) EncodeAPER(value M5ReportAmountMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c M5ReportAmountMDTValueCodec) encodeBudgetValue(value s00.M5ReportAmountMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M5ReportAmountMDTValueCodec) encodeChanged(value s00.M5ReportAmountMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M6ReportAmountMDTValueCodec is the concrete ValueCodec[M6ReportAmountMDT].
type M6ReportAmountMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.M6ReportAmountMDT,

		error)
	encode func(s00.M6ReportAmountMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.M6ReportAmountMDT, aper.DecodeState,

	) (s00.M6ReportAmountMDT, aper.Snapshot,

	)
	compare func(s00.M6ReportAmountMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M6ReportAmountMDTValueCodec) New(value s00.M6ReportAmountMDT,

) (M6ReportAmountMDTAPERValue, error) {
	if c.encode == nil {
		return M6ReportAmountMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M6ReportAmountMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M6ReportAmountMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M6ReportAmountMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M6ReportAmountMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M6ReportAmountMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M6ReportAmountMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M6ReportAmountMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M6ReportAmountMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M6ReportAmountMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M6ReportAmountMDTValueCodec) EncodeAPER(value M6ReportAmountMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c M6ReportAmountMDTValueCodec) encodeBudgetValue(value s00.M6ReportAmountMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M6ReportAmountMDTValueCodec) encodeChanged(value s00.M6ReportAmountMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M7ReportAmountMDTValueCodec is the concrete ValueCodec[M7ReportAmountMDT].
type M7ReportAmountMDTValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.M7ReportAmountMDT,

		error)
	encode func(s00.M7ReportAmountMDT,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.M7ReportAmountMDT, aper.DecodeState,

	) (s00.M7ReportAmountMDT, aper.Snapshot,

	)
	compare func(s00.M7ReportAmountMDT, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M7ReportAmountMDTValueCodec) New(value s00.M7ReportAmountMDT,

) (M7ReportAmountMDTAPERValue, error) {
	if c.encode == nil {
		return M7ReportAmountMDTAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M7ReportAmountMDTAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M7ReportAmountMDTAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M7ReportAmountMDTAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M7ReportAmountMDTValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M7ReportAmountMDTAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M7ReportAmountMDTAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M7ReportAmountMDTAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M7ReportAmountMDTAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M7ReportAmountMDTAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M7ReportAmountMDTValueCodec) EncodeAPER(value M7ReportAmountMDTAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c M7ReportAmountMDTValueCodec) encodeBudgetValue(value s00.M7ReportAmountMDT,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M7ReportAmountMDTValueCodec) encodeChanged(value s00.M7ReportAmountMDT,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MDTPLMNListValueCodec is the concrete ValueCodec[MDTPLMNList].
type MDTPLMNListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.MDTPLMNList,

		error)
	encode func(s00.MDTPLMNList,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.MDTPLMNList, aper.DecodeState,

	) (s00.MDTPLMNList, aper.Snapshot,

	)
	compare func(s00.MDTPLMNList, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MDTPLMNListValueCodec) New(value s00.MDTPLMNList,

) (MDTPLMNListAPERValue, error) {
	if c.encode == nil {
		return MDTPLMNListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTPLMNListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MDTPLMNListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MDTPLMNListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MDTPLMNListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MDTPLMNListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MDTPLMNListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MDTPLMNListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MDTPLMNListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MDTPLMNListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MDTPLMNListValueCodec) EncodeAPER(value MDTPLMNListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MDTPLMNListValueCodec) encodeBudgetValue(value s00.MDTPLMNList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MDTPLMNListValueCodec) encodeChanged(value s00.MDTPLMNList,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ProSeUEtoNetworkRelayingValueCodec is the concrete ValueCodec[ProSeUEtoNetworkRelaying].
type ProSeUEtoNetworkRelayingValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ProSeUEtoNetworkRelaying,

		error)
	encode func(s00.ProSeUEtoNetworkRelaying,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ProSeUEtoNetworkRelaying, aper.DecodeState,

	) (s00.ProSeUEtoNetworkRelaying, aper.Snapshot,

	)
	compare func(s00.ProSeUEtoNetworkRelaying, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ProSeUEtoNetworkRelayingValueCodec) New(value s00.ProSeUEtoNetworkRelaying,

) (ProSeUEtoNetworkRelayingAPERValue, error) {
	if c.encode == nil {
		return ProSeUEtoNetworkRelayingAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ProSeUEtoNetworkRelayingAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ProSeUEtoNetworkRelayingAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ProSeUEtoNetworkRelayingAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ProSeUEtoNetworkRelayingValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ProSeUEtoNetworkRelayingAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ProSeUEtoNetworkRelayingAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ProSeUEtoNetworkRelayingAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ProSeUEtoNetworkRelayingAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ProSeUEtoNetworkRelayingAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ProSeUEtoNetworkRelayingValueCodec) EncodeAPER(value ProSeUEtoNetworkRelayingAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ProSeUEtoNetworkRelayingValueCodec) encodeBudgetValue(value s00.ProSeUEtoNetworkRelaying,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ProSeUEtoNetworkRelayingValueCodec) encodeChanged(value s00.ProSeUEtoNetworkRelaying,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NBIoTRLFReportContainerValueCodec is the concrete ValueCodec[NBIoTRLFReportContainer].
type NBIoTRLFReportContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NBIoTRLFReportContainer,

		error)
	encode func(s00.NBIoTRLFReportContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NBIoTRLFReportContainer, aper.DecodeState,

	) (s00.NBIoTRLFReportContainer, aper.Snapshot,

	)
	compare func(s00.NBIoTRLFReportContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NBIoTRLFReportContainerValueCodec) New(value s00.NBIoTRLFReportContainer,

) (NBIoTRLFReportContainerAPERValue, error) {
	if c.encode == nil {
		return NBIoTRLFReportContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NBIoTRLFReportContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NBIoTRLFReportContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NBIoTRLFReportContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NBIoTRLFReportContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NBIoTRLFReportContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NBIoTRLFReportContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NBIoTRLFReportContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NBIoTRLFReportContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NBIoTRLFReportContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NBIoTRLFReportContainerValueCodec) EncodeAPER(value NBIoTRLFReportContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NBIoTRLFReportContainerValueCodec) encodeBudgetValue(value s00.NBIoTRLFReportContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NBIoTRLFReportContainerValueCodec) encodeChanged(value s00.NBIoTRLFReportContainer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GUMMEITypeValueCodec is the concrete ValueCodec[GUMMEIType].
type GUMMEITypeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.GUMMEIType,

		error)
	encode func(s00.GUMMEIType,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.GUMMEIType, aper.DecodeState,

	) (s00.GUMMEIType, aper.Snapshot,

	)
	compare func(s00.GUMMEIType, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GUMMEITypeValueCodec) New(value s00.GUMMEIType,

) (GUMMEITypeAPERValue, error) {
	if c.encode == nil {
		return GUMMEITypeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GUMMEITypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GUMMEITypeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GUMMEITypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GUMMEITypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GUMMEITypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GUMMEITypeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GUMMEITypeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GUMMEITypeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GUMMEITypeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GUMMEITypeValueCodec) EncodeAPER(value GUMMEITypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c GUMMEITypeValueCodec) encodeBudgetValue(value s00.GUMMEIType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GUMMEITypeValueCodec) encodeChanged(value s00.GUMMEIType,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// IMSvoiceEPSfallbackfrom5GValueCodec is the concrete ValueCodec[IMSvoiceEPSfallbackfrom5G].
type IMSvoiceEPSfallbackfrom5GValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.IMSvoiceEPSfallbackfrom5G,

		error)
	encode func(s00.IMSvoiceEPSfallbackfrom5G,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.IMSvoiceEPSfallbackfrom5G, aper.DecodeState,

	) (s00.IMSvoiceEPSfallbackfrom5G, aper.Snapshot,

	)
	compare func(s00.IMSvoiceEPSfallbackfrom5G, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c IMSvoiceEPSfallbackfrom5GValueCodec) New(value s00.IMSvoiceEPSfallbackfrom5G,

) (IMSvoiceEPSfallbackfrom5GAPERValue, error) {
	if c.encode == nil {
		return IMSvoiceEPSfallbackfrom5GAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return IMSvoiceEPSfallbackfrom5GAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return IMSvoiceEPSfallbackfrom5GAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return IMSvoiceEPSfallbackfrom5GAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c IMSvoiceEPSfallbackfrom5GValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (IMSvoiceEPSfallbackfrom5GAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return IMSvoiceEPSfallbackfrom5GAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return IMSvoiceEPSfallbackfrom5GAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return IMSvoiceEPSfallbackfrom5GAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return IMSvoiceEPSfallbackfrom5GAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c IMSvoiceEPSfallbackfrom5GValueCodec) EncodeAPER(value IMSvoiceEPSfallbackfrom5GAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c IMSvoiceEPSfallbackfrom5GValueCodec) encodeBudgetValue(value s00.IMSvoiceEPSfallbackfrom5G,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c IMSvoiceEPSfallbackfrom5GValueCodec) encodeChanged(value s00.IMSvoiceEPSfallbackfrom5G,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RATTypeValueCodec is the concrete ValueCodec[RATType].
type RATTypeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.RATType,

		error)
	encode func(s00.RATType,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.RATType, aper.DecodeState,

	) (s00.RATType, aper.Snapshot,

	)
	compare func(s00.RATType, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RATTypeValueCodec) New(value s00.RATType,

) (RATTypeAPERValue, error) {
	if c.encode == nil {
		return RATTypeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RATTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RATTypeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RATTypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RATTypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RATTypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RATTypeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RATTypeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RATTypeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RATTypeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RATTypeValueCodec) EncodeAPER(value RATTypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RATTypeValueCodec) encodeBudgetValue(value s00.RATType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RATTypeValueCodec) encodeChanged(value s00.RATType,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RACSIndicationValueCodec is the concrete ValueCodec[RACSIndication].
type RACSIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.RACSIndication,

		error)
	encode func(s00.RACSIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.RACSIndication, aper.DecodeState,

	) (s00.RACSIndication, aper.Snapshot,

	)
	compare func(s00.RACSIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RACSIndicationValueCodec) New(value s00.RACSIndication,

) (RACSIndicationAPERValue, error) {
	if c.encode == nil {
		return RACSIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RACSIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RACSIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RACSIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RACSIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RACSIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RACSIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RACSIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RACSIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RACSIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RACSIndicationValueCodec) EncodeAPER(value RACSIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RACSIndicationValueCodec) encodeBudgetValue(value s00.RACSIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RACSIndicationValueCodec) encodeChanged(value s00.RACSIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MutingAvailabilityIndicationValueCodec is the concrete ValueCodec[MutingAvailabilityIndication].
type MutingAvailabilityIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.MutingAvailabilityIndication,

		error)
	encode func(s00.MutingAvailabilityIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.MutingAvailabilityIndication, aper.DecodeState,

	) (s00.MutingAvailabilityIndication, aper.Snapshot,

	)
	compare func(s00.MutingAvailabilityIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MutingAvailabilityIndicationValueCodec) New(value s00.MutingAvailabilityIndication,

) (MutingAvailabilityIndicationAPERValue, error) {
	if c.encode == nil {
		return MutingAvailabilityIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MutingAvailabilityIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MutingAvailabilityIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MutingAvailabilityIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MutingAvailabilityIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MutingAvailabilityIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MutingAvailabilityIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MutingAvailabilityIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MutingAvailabilityIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MutingAvailabilityIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MutingAvailabilityIndicationValueCodec) EncodeAPER(value MutingAvailabilityIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MutingAvailabilityIndicationValueCodec) encodeBudgetValue(value s00.MutingAvailabilityIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MutingAvailabilityIndicationValueCodec) encodeChanged(value s00.MutingAvailabilityIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MDTConfigurationNRValueCodec is the concrete ValueCodec[MDTConfigurationNR].
type MDTConfigurationNRValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.MDTConfigurationNR,

		error)
	encode func(s00.MDTConfigurationNR,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.MDTConfigurationNR, aper.DecodeState,

	) (s00.MDTConfigurationNR, aper.Snapshot,

	)
	compare func(s00.MDTConfigurationNR, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MDTConfigurationNRValueCodec) New(value s00.MDTConfigurationNR,

) (MDTConfigurationNRAPERValue, error) {
	if c.encode == nil {
		return MDTConfigurationNRAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTConfigurationNRAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MDTConfigurationNRAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MDTConfigurationNRAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MDTConfigurationNRValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MDTConfigurationNRAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MDTConfigurationNRAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MDTConfigurationNRAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MDTConfigurationNRAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MDTConfigurationNRAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MDTConfigurationNRValueCodec) EncodeAPER(value MDTConfigurationNRAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MDTConfigurationNRValueCodec) encodeBudgetValue(value s00.MDTConfigurationNR,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MDTConfigurationNRValueCodec) encodeChanged(value s00.MDTConfigurationNR,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEUES1APIDValueCodec is the concrete ValueCodec[MMEUES1APID].
type MMEUES1APIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.MMEUES1APID,

		error)
	encode func(s00.MMEUES1APID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.MMEUES1APID, aper.DecodeState,

	) (s00.MMEUES1APID, aper.Snapshot,

	)
	compare func(s00.MMEUES1APID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEUES1APIDValueCodec) New(value s00.MMEUES1APID,

) (MMEUES1APIDAPERValue, error) {
	if c.encode == nil {
		return MMEUES1APIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEUES1APIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEUES1APIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEUES1APIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEUES1APIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEUES1APIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEUES1APIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEUES1APIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEUES1APIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEUES1APIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEUES1APIDValueCodec) EncodeAPER(value MMEUES1APIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEUES1APIDValueCodec) encodeBudgetValue(value s00.MMEUES1APID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEUES1APIDValueCodec) encodeChanged(value s00.MMEUES1APID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PrivacyIndicatorValueCodec is the concrete ValueCodec[PrivacyIndicator].
type PrivacyIndicatorValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PrivacyIndicator,

		error)
	encode func(s00.PrivacyIndicator,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PrivacyIndicator, aper.DecodeState,

	) (s00.PrivacyIndicator, aper.Snapshot,

	)
	compare func(s00.PrivacyIndicator, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PrivacyIndicatorValueCodec) New(value s00.PrivacyIndicator,

) (PrivacyIndicatorAPERValue, error) {
	if c.encode == nil {
		return PrivacyIndicatorAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PrivacyIndicatorAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PrivacyIndicatorAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PrivacyIndicatorAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PrivacyIndicatorValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PrivacyIndicatorAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PrivacyIndicatorAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PrivacyIndicatorAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PrivacyIndicatorAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PrivacyIndicatorAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PrivacyIndicatorValueCodec) EncodeAPER(value PrivacyIndicatorAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PrivacyIndicatorValueCodec) encodeBudgetValue(value s00.PrivacyIndicator,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PrivacyIndicatorValueCodec) encodeChanged(value s00.PrivacyIndicator,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MaskedIMEISVValueCodec is the concrete ValueCodec[MaskedIMEISV].
type MaskedIMEISVValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.MaskedIMEISV,

		error)
	encode func(s00.MaskedIMEISV,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.MaskedIMEISV, aper.DecodeState,

	) (s00.MaskedIMEISV, aper.Snapshot,

	)
	compare func(s00.MaskedIMEISV, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MaskedIMEISVValueCodec) New(value s00.MaskedIMEISV,

) (MaskedIMEISVAPERValue, error) {
	if c.encode == nil {
		return MaskedIMEISVAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MaskedIMEISVAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MaskedIMEISVAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MaskedIMEISVAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MaskedIMEISVValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MaskedIMEISVAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MaskedIMEISVAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MaskedIMEISVAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MaskedIMEISVAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MaskedIMEISVAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MaskedIMEISVValueCodec) EncodeAPER(value MaskedIMEISVAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MaskedIMEISVValueCodec) encodeBudgetValue(value s00.MaskedIMEISV,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MaskedIMEISVValueCodec) encodeChanged(value s00.MaskedIMEISV,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NASPDUValueCodec is the concrete ValueCodec[NASPDU].
type NASPDUValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NASPDU,

		error)
	encode func(s00.NASPDU,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NASPDU, aper.DecodeState,

	) (s00.NASPDU, aper.Snapshot,

	)
	compare func(s00.NASPDU, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NASPDUValueCodec) New(value s00.NASPDU,

) (NASPDUAPERValue, error) {
	if c.encode == nil {
		return NASPDUAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASPDUAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NASPDUAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NASPDUAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NASPDUValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NASPDUAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NASPDUAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NASPDUAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NASPDUAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NASPDUAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NASPDUValueCodec) EncodeAPER(value NASPDUAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NASPDUValueCodec) encodeBudgetValue(value s00.NASPDU,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NASPDUValueCodec) encodeChanged(value s00.NASPDU,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PendingDataIndicationValueCodec is the concrete ValueCodec[PendingDataIndication].
type PendingDataIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PendingDataIndication,

		error)
	encode func(s00.PendingDataIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PendingDataIndication, aper.DecodeState,

	) (s00.PendingDataIndication, aper.Snapshot,

	)
	compare func(s00.PendingDataIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PendingDataIndicationValueCodec) New(value s00.PendingDataIndication,

) (PendingDataIndicationAPERValue, error) {
	if c.encode == nil {
		return PendingDataIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PendingDataIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PendingDataIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PendingDataIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PendingDataIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PendingDataIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PendingDataIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PendingDataIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PendingDataIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PendingDataIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PendingDataIndicationValueCodec) EncodeAPER(value PendingDataIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PendingDataIndicationValueCodec) encodeBudgetValue(value s00.PendingDataIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PendingDataIndicationValueCodec) encodeChanged(value s00.PendingDataIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LPPaPDUValueCodec is the concrete ValueCodec[LPPaPDU].
type LPPaPDUValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.LPPaPDU,

		error)
	encode func(s00.LPPaPDU,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.LPPaPDU, aper.DecodeState,

	) (s00.LPPaPDU, aper.Snapshot,

	)
	compare func(s00.LPPaPDU, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LPPaPDUValueCodec) New(value s00.LPPaPDU,

) (LPPaPDUAPERValue, error) {
	if c.encode == nil {
		return LPPaPDUAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LPPaPDUAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LPPaPDUAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LPPaPDUAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LPPaPDUValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LPPaPDUAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LPPaPDUAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LPPaPDUAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LPPaPDUAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LPPaPDUAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LPPaPDUValueCodec) EncodeAPER(value LPPaPDUAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LPPaPDUValueCodec) encodeBudgetValue(value s00.LPPaPDU,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LPPaPDUValueCodec) encodeChanged(value s00.LPPaPDU,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// IntersystemSONConfigurationTransferValueCodec is the concrete ValueCodec[IntersystemSONConfigurationTransfer].
type IntersystemSONConfigurationTransferValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.IntersystemSONConfigurationTransfer,

		error)
	encode func(s00.IntersystemSONConfigurationTransfer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.IntersystemSONConfigurationTransfer, aper.DecodeState,

	) (s00.IntersystemSONConfigurationTransfer, aper.Snapshot,

	)
	compare func(s00.IntersystemSONConfigurationTransfer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c IntersystemSONConfigurationTransferValueCodec) New(value s00.IntersystemSONConfigurationTransfer,

) (IntersystemSONConfigurationTransferAPERValue, error) {
	if c.encode == nil {
		return IntersystemSONConfigurationTransferAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return IntersystemSONConfigurationTransferAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return IntersystemSONConfigurationTransferAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return IntersystemSONConfigurationTransferAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c IntersystemSONConfigurationTransferValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (IntersystemSONConfigurationTransferAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return IntersystemSONConfigurationTransferAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return IntersystemSONConfigurationTransferAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return IntersystemSONConfigurationTransferAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return IntersystemSONConfigurationTransferAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c IntersystemSONConfigurationTransferValueCodec) EncodeAPER(value IntersystemSONConfigurationTransferAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c IntersystemSONConfigurationTransferValueCodec) encodeBudgetValue(value s00.IntersystemSONConfigurationTransfer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c IntersystemSONConfigurationTransferValueCodec) encodeChanged(value s00.IntersystemSONConfigurationTransfer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingDRXValueCodec is the concrete ValueCodec[PagingDRX].
type PagingDRXValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PagingDRX,

		error)
	encode func(s00.PagingDRX,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PagingDRX, aper.DecodeState,

	) (s00.PagingDRX, aper.Snapshot,

	)
	compare func(s00.PagingDRX, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingDRXValueCodec) New(value s00.PagingDRX,

) (PagingDRXAPERValue, error) {
	if c.encode == nil {
		return PagingDRXAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingDRXAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingDRXAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingDRXAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingDRXValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingDRXAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingDRXAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingDRXAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingDRXAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingDRXAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingDRXValueCodec) EncodeAPER(value PagingDRXAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PagingDRXValueCodec) encodeBudgetValue(value s00.PagingDRX,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingDRXValueCodec) encodeChanged(value s00.PagingDRX,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NBIoTDefaultPagingDRXValueCodec is the concrete ValueCodec[NBIoTDefaultPagingDRX].
type NBIoTDefaultPagingDRXValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NBIoTDefaultPagingDRX,

		error)
	encode func(s00.NBIoTDefaultPagingDRX,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NBIoTDefaultPagingDRX, aper.DecodeState,

	) (s00.NBIoTDefaultPagingDRX, aper.Snapshot,

	)
	compare func(s00.NBIoTDefaultPagingDRX, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NBIoTDefaultPagingDRXValueCodec) New(value s00.NBIoTDefaultPagingDRX,

) (NBIoTDefaultPagingDRXAPERValue, error) {
	if c.encode == nil {
		return NBIoTDefaultPagingDRXAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NBIoTDefaultPagingDRXAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NBIoTDefaultPagingDRXAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NBIoTDefaultPagingDRXAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NBIoTDefaultPagingDRXValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NBIoTDefaultPagingDRXAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NBIoTDefaultPagingDRXAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NBIoTDefaultPagingDRXAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NBIoTDefaultPagingDRXAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NBIoTDefaultPagingDRXAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NBIoTDefaultPagingDRXValueCodec) EncodeAPER(value NBIoTDefaultPagingDRXAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NBIoTDefaultPagingDRXValueCodec) encodeBudgetValue(value s00.NBIoTDefaultPagingDRX,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NBIoTDefaultPagingDRXValueCodec) encodeChanged(value s00.NBIoTDefaultPagingDRX,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverTypeValueCodec is the concrete ValueCodec[HandoverType].
type HandoverTypeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.HandoverType,

		error)
	encode func(s00.HandoverType,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.HandoverType, aper.DecodeState,

	) (s00.HandoverType, aper.Snapshot,

	)
	compare func(s00.HandoverType, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverTypeValueCodec) New(value s00.HandoverType,

) (HandoverTypeAPERValue, error) {
	if c.encode == nil {
		return HandoverTypeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverTypeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverTypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverTypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverTypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverTypeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverTypeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverTypeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverTypeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverTypeValueCodec) EncodeAPER(value HandoverTypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverTypeValueCodec) encodeBudgetValue(value s00.HandoverType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverTypeValueCodec) encodeChanged(value s00.HandoverType,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NASSecurityParametersfromEUTRANValueCodec is the concrete ValueCodec[NASSecurityParametersfromEUTRAN].
type NASSecurityParametersfromEUTRANValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NASSecurityParametersfromEUTRAN,

		error)
	encode func(s00.NASSecurityParametersfromEUTRAN,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NASSecurityParametersfromEUTRAN, aper.DecodeState,

	) (s00.NASSecurityParametersfromEUTRAN, aper.Snapshot,

	)
	compare func(s00.NASSecurityParametersfromEUTRAN, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NASSecurityParametersfromEUTRANValueCodec) New(value s00.NASSecurityParametersfromEUTRAN,

) (NASSecurityParametersfromEUTRANAPERValue, error) {
	if c.encode == nil {
		return NASSecurityParametersfromEUTRANAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASSecurityParametersfromEUTRANAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NASSecurityParametersfromEUTRANAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NASSecurityParametersfromEUTRANAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NASSecurityParametersfromEUTRANValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NASSecurityParametersfromEUTRANAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NASSecurityParametersfromEUTRANAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NASSecurityParametersfromEUTRANAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NASSecurityParametersfromEUTRANAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NASSecurityParametersfromEUTRANAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NASSecurityParametersfromEUTRANValueCodec) EncodeAPER(value NASSecurityParametersfromEUTRANAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NASSecurityParametersfromEUTRANValueCodec) encodeBudgetValue(value s00.NASSecurityParametersfromEUTRAN,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NASSecurityParametersfromEUTRANValueCodec) encodeChanged(value s00.NASSecurityParametersfromEUTRAN,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LHNIDValueCodec is the concrete ValueCodec[LHNID].
type LHNIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.LHNID,

		error)
	encode func(s00.LHNID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.LHNID, aper.DecodeState,

	) (s00.LHNID, aper.Snapshot,

	)
	compare func(s00.LHNID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LHNIDValueCodec) New(value s00.LHNID,

) (LHNIDAPERValue, error) {
	if c.encode == nil {
		return LHNIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LHNIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LHNIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LHNIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LHNIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LHNIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LHNIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LHNIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LHNIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LHNIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LHNIDValueCodec) EncodeAPER(value LHNIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LHNIDValueCodec) encodeBudgetValue(value s00.LHNID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LHNIDValueCodec) encodeChanged(value s00.LHNID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NotifySourceeNBValueCodec is the concrete ValueCodec[NotifySourceeNB].
type NotifySourceeNBValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NotifySourceeNB,

		error)
	encode func(s00.NotifySourceeNB,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NotifySourceeNB, aper.DecodeState,

	) (s00.NotifySourceeNB, aper.Snapshot,

	)
	compare func(s00.NotifySourceeNB, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NotifySourceeNBValueCodec) New(value s00.NotifySourceeNB,

) (NotifySourceeNBAPERValue, error) {
	if c.encode == nil {
		return NotifySourceeNBAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NotifySourceeNBAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NotifySourceeNBAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NotifySourceeNBAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NotifySourceeNBValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NotifySourceeNBAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NotifySourceeNBAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NotifySourceeNBAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NotifySourceeNBAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NotifySourceeNBAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NotifySourceeNBValueCodec) EncodeAPER(value NotifySourceeNBAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NotifySourceeNBValueCodec) encodeBudgetValue(value s00.NotifySourceeNB,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NotifySourceeNBValueCodec) encodeChanged(value s00.NotifySourceeNB,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NASSecurityParameterstoEUTRANValueCodec is the concrete ValueCodec[NASSecurityParameterstoEUTRAN].
type NASSecurityParameterstoEUTRANValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NASSecurityParameterstoEUTRAN,

		error)
	encode func(s00.NASSecurityParameterstoEUTRAN,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NASSecurityParameterstoEUTRAN, aper.DecodeState,

	) (s00.NASSecurityParameterstoEUTRAN, aper.Snapshot,

	)
	compare func(s00.NASSecurityParameterstoEUTRAN, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NASSecurityParameterstoEUTRANValueCodec) New(value s00.NASSecurityParameterstoEUTRAN,

) (NASSecurityParameterstoEUTRANAPERValue, error) {
	if c.encode == nil {
		return NASSecurityParameterstoEUTRANAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NASSecurityParameterstoEUTRANAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NASSecurityParameterstoEUTRANAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NASSecurityParameterstoEUTRANAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NASSecurityParameterstoEUTRANValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NASSecurityParameterstoEUTRANAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NASSecurityParameterstoEUTRANAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NASSecurityParameterstoEUTRANAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NASSecurityParameterstoEUTRANAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NASSecurityParameterstoEUTRANAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NASSecurityParameterstoEUTRANValueCodec) EncodeAPER(value NASSecurityParameterstoEUTRANAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NASSecurityParameterstoEUTRANValueCodec) encodeBudgetValue(value s00.NASSecurityParameterstoEUTRAN,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NASSecurityParameterstoEUTRANValueCodec) encodeChanged(value s00.NASSecurityParameterstoEUTRAN,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ManagementBasedMDTAllowedValueCodec is the concrete ValueCodec[ManagementBasedMDTAllowed].
type ManagementBasedMDTAllowedValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ManagementBasedMDTAllowed,

		error)
	encode func(s00.ManagementBasedMDTAllowed,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ManagementBasedMDTAllowed, aper.DecodeState,

	) (s00.ManagementBasedMDTAllowed, aper.Snapshot,

	)
	compare func(s00.ManagementBasedMDTAllowed, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ManagementBasedMDTAllowedValueCodec) New(value s00.ManagementBasedMDTAllowed,

) (ManagementBasedMDTAllowedAPERValue, error) {
	if c.encode == nil {
		return ManagementBasedMDTAllowedAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ManagementBasedMDTAllowedAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ManagementBasedMDTAllowedAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ManagementBasedMDTAllowedAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ManagementBasedMDTAllowedValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ManagementBasedMDTAllowedAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ManagementBasedMDTAllowedAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ManagementBasedMDTAllowedAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ManagementBasedMDTAllowedAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ManagementBasedMDTAllowedAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ManagementBasedMDTAllowedValueCodec) EncodeAPER(value ManagementBasedMDTAllowedAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ManagementBasedMDTAllowedValueCodec) encodeBudgetValue(value s00.ManagementBasedMDTAllowed,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ManagementBasedMDTAllowedValueCodec) encodeChanged(value s00.ManagementBasedMDTAllowed,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// IABAuthorizedValueCodec is the concrete ValueCodec[IABAuthorized].
type IABAuthorizedValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.IABAuthorized,

		error)
	encode func(s00.IABAuthorized,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.IABAuthorized, aper.DecodeState,

	) (s00.IABAuthorized, aper.Snapshot,

	)
	compare func(s00.IABAuthorized, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c IABAuthorizedValueCodec) New(value s00.IABAuthorized,

) (IABAuthorizedAPERValue, error) {
	if c.encode == nil {
		return IABAuthorizedAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return IABAuthorizedAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return IABAuthorizedAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return IABAuthorizedAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c IABAuthorizedValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (IABAuthorizedAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return IABAuthorizedAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return IABAuthorizedAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return IABAuthorizedAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return IABAuthorizedAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c IABAuthorizedValueCodec) EncodeAPER(value IABAuthorizedAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c IABAuthorizedValueCodec) encodeBudgetValue(value s00.IABAuthorized,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c IABAuthorizedValueCodec) encodeChanged(value s00.IABAuthorized,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MSClassmark2ValueCodec is the concrete ValueCodec[MSClassmark2].
type MSClassmark2ValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.MSClassmark2,

		error)
	encode func(s00.MSClassmark2,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.MSClassmark2, aper.DecodeState,

	) (s00.MSClassmark2, aper.Snapshot,

	)
	compare func(s00.MSClassmark2, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MSClassmark2ValueCodec) New(value s00.MSClassmark2,

) (MSClassmark2APERValue, error) {
	if c.encode == nil {
		return MSClassmark2APERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MSClassmark2APERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MSClassmark2APERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MSClassmark2APERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MSClassmark2ValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MSClassmark2APERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MSClassmark2APERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MSClassmark2APERValue{}, report, aper.OperationError(err, c.path)
		}
		return MSClassmark2APERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MSClassmark2APERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MSClassmark2ValueCodec) EncodeAPER(value MSClassmark2APERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MSClassmark2ValueCodec) encodeBudgetValue(value s00.MSClassmark2,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MSClassmark2ValueCodec) encodeChanged(value s00.MSClassmark2,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MSClassmark3ValueCodec is the concrete ValueCodec[MSClassmark3].
type MSClassmark3ValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.MSClassmark3,

		error)
	encode func(s00.MSClassmark3,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.MSClassmark3, aper.DecodeState,

	) (s00.MSClassmark3, aper.Snapshot,

	)
	compare func(s00.MSClassmark3, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MSClassmark3ValueCodec) New(value s00.MSClassmark3,

) (MSClassmark3APERValue, error) {
	if c.encode == nil {
		return MSClassmark3APERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MSClassmark3APERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MSClassmark3APERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MSClassmark3APERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MSClassmark3ValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MSClassmark3APERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MSClassmark3APERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MSClassmark3APERValue{}, report, aper.OperationError(err, c.path)
		}
		return MSClassmark3APERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MSClassmark3APERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MSClassmark3ValueCodec) EncodeAPER(value MSClassmark3APERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MSClassmark3ValueCodec) encodeBudgetValue(value s00.MSClassmark3,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MSClassmark3ValueCodec) encodeChanged(value s00.MSClassmark3,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PSServiceNotAvailableValueCodec is the concrete ValueCodec[PSServiceNotAvailable].
type PSServiceNotAvailableValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PSServiceNotAvailable,

		error)
	encode func(s00.PSServiceNotAvailable,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PSServiceNotAvailable, aper.DecodeState,

	) (s00.PSServiceNotAvailable, aper.Snapshot,

	)
	compare func(s00.PSServiceNotAvailable, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PSServiceNotAvailableValueCodec) New(value s00.PSServiceNotAvailable,

) (PSServiceNotAvailableAPERValue, error) {
	if c.encode == nil {
		return PSServiceNotAvailableAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PSServiceNotAvailableAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PSServiceNotAvailableAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PSServiceNotAvailableAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PSServiceNotAvailableValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PSServiceNotAvailableAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PSServiceNotAvailableAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PSServiceNotAvailableAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PSServiceNotAvailableAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PSServiceNotAvailableAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PSServiceNotAvailableValueCodec) EncodeAPER(value PSServiceNotAvailableAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PSServiceNotAvailableValueCodec) encodeBudgetValue(value s00.PSServiceNotAvailable,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PSServiceNotAvailableValueCodec) encodeChanged(value s00.PSServiceNotAvailable,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RRCEstablishmentCauseValueCodec is the concrete ValueCodec[RRCEstablishmentCause].
type RRCEstablishmentCauseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.RRCEstablishmentCause,

		error)
	encode func(s00.RRCEstablishmentCause,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.RRCEstablishmentCause, aper.DecodeState,

	) (s00.RRCEstablishmentCause, aper.Snapshot,

	)
	compare func(s00.RRCEstablishmentCause, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RRCEstablishmentCauseValueCodec) New(value s00.RRCEstablishmentCause,

) (RRCEstablishmentCauseAPERValue, error) {
	if c.encode == nil {
		return RRCEstablishmentCauseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RRCEstablishmentCauseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RRCEstablishmentCauseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RRCEstablishmentCauseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RRCEstablishmentCauseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RRCEstablishmentCauseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RRCEstablishmentCauseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RRCEstablishmentCauseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RRCEstablishmentCauseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RRCEstablishmentCauseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RRCEstablishmentCauseValueCodec) EncodeAPER(value RRCEstablishmentCauseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RRCEstablishmentCauseValueCodec) encodeBudgetValue(value s00.RRCEstablishmentCause,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RRCEstablishmentCauseValueCodec) encodeChanged(value s00.RRCEstablishmentCause,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEGroupIDValueCodec is the concrete ValueCodec[MMEGroupID].
type MMEGroupIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.MMEGroupID,

		error)
	encode func(s00.MMEGroupID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.MMEGroupID, aper.DecodeState,

	) (s00.MMEGroupID, aper.Snapshot,

	)
	compare func(s00.MMEGroupID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEGroupIDValueCodec) New(value s00.MMEGroupID,

) (MMEGroupIDAPERValue, error) {
	if c.encode == nil {
		return MMEGroupIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEGroupIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEGroupIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEGroupIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEGroupIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEGroupIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEGroupIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEGroupIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEGroupIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEGroupIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEGroupIDValueCodec) EncodeAPER(value MMEGroupIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEGroupIDValueCodec) encodeBudgetValue(value s00.MMEGroupID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEGroupIDValueCodec) encodeChanged(value s00.MMEGroupID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// IABNodeIndicationValueCodec is the concrete ValueCodec[IABNodeIndication].
type IABNodeIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.IABNodeIndication,

		error)
	encode func(s00.IABNodeIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.IABNodeIndication, aper.DecodeState,

	) (s00.IABNodeIndication, aper.Snapshot,

	)
	compare func(s00.IABNodeIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c IABNodeIndicationValueCodec) New(value s00.IABNodeIndication,

) (IABNodeIndicationAPERValue, error) {
	if c.encode == nil {
		return IABNodeIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return IABNodeIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return IABNodeIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return IABNodeIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c IABNodeIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (IABNodeIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return IABNodeIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return IABNodeIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return IABNodeIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return IABNodeIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c IABNodeIndicationValueCodec) EncodeAPER(value IABNodeIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c IABNodeIndicationValueCodec) encodeBudgetValue(value s00.IABNodeIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c IABNodeIndicationValueCodec) encodeChanged(value s00.IABNodeIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MessageIdentifierValueCodec is the concrete ValueCodec[MessageIdentifier].
type MessageIdentifierValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.MessageIdentifier,

		error)
	encode func(s00.MessageIdentifier,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.MessageIdentifier, aper.DecodeState,

	) (s00.MessageIdentifier, aper.Snapshot,

	)
	compare func(s00.MessageIdentifier, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MessageIdentifierValueCodec) New(value s00.MessageIdentifier,

) (MessageIdentifierAPERValue, error) {
	if c.encode == nil {
		return MessageIdentifierAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MessageIdentifierAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MessageIdentifierAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MessageIdentifierAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MessageIdentifierValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MessageIdentifierAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MessageIdentifierAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MessageIdentifierAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MessageIdentifierAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MessageIdentifierAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MessageIdentifierValueCodec) EncodeAPER(value MessageIdentifierAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MessageIdentifierValueCodec) encodeBudgetValue(value s00.MessageIdentifier,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MessageIdentifierValueCodec) encodeChanged(value s00.MessageIdentifier,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// KillAllWarningMessagesValueCodec is the concrete ValueCodec[KillAllWarningMessages].
type KillAllWarningMessagesValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.KillAllWarningMessages,

		error)
	encode func(s00.KillAllWarningMessages,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.KillAllWarningMessages, aper.DecodeState,

	) (s00.KillAllWarningMessages, aper.Snapshot,

	)
	compare func(s00.KillAllWarningMessages, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c KillAllWarningMessagesValueCodec) New(value s00.KillAllWarningMessages,

) (KillAllWarningMessagesAPERValue, error) {
	if c.encode == nil {
		return KillAllWarningMessagesAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return KillAllWarningMessagesAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return KillAllWarningMessagesAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return KillAllWarningMessagesAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c KillAllWarningMessagesValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (KillAllWarningMessagesAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return KillAllWarningMessagesAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return KillAllWarningMessagesAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return KillAllWarningMessagesAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return KillAllWarningMessagesAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c KillAllWarningMessagesValueCodec) EncodeAPER(value KillAllWarningMessagesAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c KillAllWarningMessagesValueCodec) encodeBudgetValue(value s00.KillAllWarningMessages,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c KillAllWarningMessagesValueCodec) encodeChanged(value s00.KillAllWarningMessages,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMEnameValueCodec is the concrete ValueCodec[MMEname].
type MMEnameValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.MMEname,

		error)
	encode func(s00.MMEname,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.MMEname, aper.DecodeState,

	) (s00.MMEname, aper.Snapshot,

	)
	compare func(s00.MMEname, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMEnameValueCodec) New(value s00.MMEname,

) (MMEnameAPERValue, error) {
	if c.encode == nil {
		return MMEnameAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMEnameAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMEnameAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMEnameAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMEnameValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMEnameAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMEnameAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMEnameAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMEnameAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMEnameAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMEnameValueCodec) EncodeAPER(value MMEnameAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMEnameValueCodec) encodeBudgetValue(value s00.MMEname,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMEnameValueCodec) encodeChanged(value s00.MMEname,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingPriorityValueCodec is the concrete ValueCodec[PagingPriority].
type PagingPriorityValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PagingPriority,

		error)
	encode func(s00.PagingPriority,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PagingPriority, aper.DecodeState,

	) (s00.PagingPriority, aper.Snapshot,

	)
	compare func(s00.PagingPriority, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingPriorityValueCodec) New(value s00.PagingPriority,

) (PagingPriorityAPERValue, error) {
	if c.encode == nil {
		return PagingPriorityAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingPriorityAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingPriorityAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingPriorityAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingPriorityValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingPriorityAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingPriorityAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingPriorityAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingPriorityAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingPriorityAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingPriorityValueCodec) EncodeAPER(value PagingPriorityAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PagingPriorityValueCodec) encodeBudgetValue(value s00.PagingPriority,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingPriorityValueCodec) encodeChanged(value s00.PagingPriority,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ExtendedUEIdentityIndexValueValueCodec is the concrete ValueCodec[ExtendedUEIdentityIndexValue].
type ExtendedUEIdentityIndexValueValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ExtendedUEIdentityIndexValue,

		error)
	encode func(s00.ExtendedUEIdentityIndexValue,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ExtendedUEIdentityIndexValue, aper.DecodeState,

	) (s00.ExtendedUEIdentityIndexValue, aper.Snapshot,

	)
	compare func(s00.ExtendedUEIdentityIndexValue, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ExtendedUEIdentityIndexValueValueCodec) New(value s00.ExtendedUEIdentityIndexValue,

) (s00.ExtendedUEIdentityIndexValueAPERValue, error) {
	if c.encode == nil {
		return s00.ExtendedUEIdentityIndexValueAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s00.ExtendedUEIdentityIndexValueAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return s00.ExtendedUEIdentityIndexValueAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return s00.ExtendedUEIdentityIndexValueAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ExtendedUEIdentityIndexValueValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (s00.ExtendedUEIdentityIndexValueAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return s00.ExtendedUEIdentityIndexValueAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return s00.ExtendedUEIdentityIndexValueAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return func() s00.ExtendedUEIdentityIndexValueAPERValue {
			sealed := s00.ExtendedUEIdentityIndexValueAPERValue{Value: value}
			*s00.BridgeExtendedUEIdentityIndexValueAPERValueFieldReceived(&sealed) = aper.OriginalWire(data)
			*s00.BridgeExtendedUEIdentityIndexValueAPERValueFieldReplay(&sealed) = replay
			*s00.BridgeExtendedUEIdentityIndexValueAPERValueFieldContext(&sealed) = c.context
			return sealed
		}(), report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return s00.ExtendedUEIdentityIndexValueAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ExtendedUEIdentityIndexValueValueCodec) EncodeAPER(value s00.ExtendedUEIdentityIndexValueAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := *s00.BridgeExtendedUEIdentityIndexValueAPERValueFieldWithoutReplay(&value) || aper.EncodeWithoutReplay(options...)
	if *s00.BridgeExtendedUEIdentityIndexValueAPERValueFieldContext(&value) == c.context && !fresh && (*s00.BridgeExtendedUEIdentityIndexValueAPERValueFieldReplay(&value)).Present() {
		plan, next := c.compare(value.Value, *s00.BridgeExtendedUEIdentityIndexValueAPERValueFieldReplay(&value), budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(*s00.BridgeExtendedUEIdentityIndexValueAPERValueFieldReplay(&value)) {
			out, err := aper.CopyReplay(*s00.BridgeExtendedUEIdentityIndexValueAPERValueFieldReceived(&value), &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c ExtendedUEIdentityIndexValueValueCodec) encodeBudgetValue(value s00.ExtendedUEIdentityIndexValue,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ExtendedUEIdentityIndexValueValueCodec) encodeChanged(value s00.ExtendedUEIdentityIndexValue,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NBIoTUEIdentityIndexValueValueCodec is the concrete ValueCodec[NBIoTUEIdentityIndexValue].
type NBIoTUEIdentityIndexValueValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NBIoTUEIdentityIndexValue,

		error)
	encode func(s00.NBIoTUEIdentityIndexValue,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NBIoTUEIdentityIndexValue, aper.DecodeState,

	) (s00.NBIoTUEIdentityIndexValue, aper.Snapshot,

	)
	compare func(s00.NBIoTUEIdentityIndexValue, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NBIoTUEIdentityIndexValueValueCodec) New(value s00.NBIoTUEIdentityIndexValue,

) (NBIoTUEIdentityIndexValueAPERValue, error) {
	if c.encode == nil {
		return NBIoTUEIdentityIndexValueAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NBIoTUEIdentityIndexValueAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NBIoTUEIdentityIndexValueAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NBIoTUEIdentityIndexValueAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NBIoTUEIdentityIndexValueValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NBIoTUEIdentityIndexValueAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NBIoTUEIdentityIndexValueAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NBIoTUEIdentityIndexValueAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NBIoTUEIdentityIndexValueAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NBIoTUEIdentityIndexValueAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NBIoTUEIdentityIndexValueValueCodec) EncodeAPER(value NBIoTUEIdentityIndexValueAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NBIoTUEIdentityIndexValueValueCodec) encodeBudgetValue(value s00.NBIoTUEIdentityIndexValue,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NBIoTUEIdentityIndexValueValueCodec) encodeChanged(value s00.NBIoTUEIdentityIndexValue,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NBIoTPagingDRXValueCodec is the concrete ValueCodec[NBIoTPagingDRX].
type NBIoTPagingDRXValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NBIoTPagingDRX,

		error)
	encode func(s00.NBIoTPagingDRX,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NBIoTPagingDRX, aper.DecodeState,

	) (s00.NBIoTPagingDRX, aper.Snapshot,

	)
	compare func(s00.NBIoTPagingDRX, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NBIoTPagingDRXValueCodec) New(value s00.NBIoTPagingDRX,

) (NBIoTPagingDRXAPERValue, error) {
	if c.encode == nil {
		return NBIoTPagingDRXAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NBIoTPagingDRXAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NBIoTPagingDRXAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NBIoTPagingDRXAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NBIoTPagingDRXValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NBIoTPagingDRXAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NBIoTPagingDRXAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NBIoTPagingDRXAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NBIoTPagingDRXAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NBIoTPagingDRXAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NBIoTPagingDRXValueCodec) EncodeAPER(value NBIoTPagingDRXAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NBIoTPagingDRXValueCodec) encodeBudgetValue(value s00.NBIoTPagingDRX,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NBIoTPagingDRXValueCodec) encodeChanged(value s00.NBIoTPagingDRX,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingCauseValueCodec is the concrete ValueCodec[PagingCause].
type PagingCauseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PagingCause,

		error)
	encode func(s00.PagingCause,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PagingCause, aper.DecodeState,

	) (s00.PagingCause, aper.Snapshot,

	)
	compare func(s00.PagingCause, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingCauseValueCodec) New(value s00.PagingCause,

) (PagingCauseAPERValue, error) {
	if c.encode == nil {
		return PagingCauseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingCauseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingCauseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingCauseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingCauseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingCauseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingCauseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingCauseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingCauseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingCauseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingCauseValueCodec) EncodeAPER(value PagingCauseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PagingCauseValueCodec) encodeBudgetValue(value s00.PagingCause,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingCauseValueCodec) encodeChanged(value s00.PagingCause,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMERelaySupportIndicatorValueCodec is the concrete ValueCodec[MMERelaySupportIndicator].
type MMERelaySupportIndicatorValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.MMERelaySupportIndicator,

		error)
	encode func(s00.MMERelaySupportIndicator,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.MMERelaySupportIndicator, aper.DecodeState,

	) (s00.MMERelaySupportIndicator, aper.Snapshot,

	)
	compare func(s00.MMERelaySupportIndicator, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMERelaySupportIndicatorValueCodec) New(value s00.MMERelaySupportIndicator,

) (MMERelaySupportIndicatorAPERValue, error) {
	if c.encode == nil {
		return MMERelaySupportIndicatorAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMERelaySupportIndicatorAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMERelaySupportIndicatorAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMERelaySupportIndicatorAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMERelaySupportIndicatorValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMERelaySupportIndicatorAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMERelaySupportIndicatorAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMERelaySupportIndicatorAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMERelaySupportIndicatorAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMERelaySupportIndicatorAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMERelaySupportIndicatorValueCodec) EncodeAPER(value MMERelaySupportIndicatorAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMERelaySupportIndicatorValueCodec) encodeBudgetValue(value s00.MMERelaySupportIndicator,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMERelaySupportIndicatorValueCodec) encodeChanged(value s00.MMERelaySupportIndicator,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// IABSupportedValueCodec is the concrete ValueCodec[IABSupported].
type IABSupportedValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.IABSupported,

		error)
	encode func(s00.IABSupported,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.IABSupported, aper.DecodeState,

	) (s00.IABSupported, aper.Snapshot,

	)
	compare func(s00.IABSupported, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c IABSupportedValueCodec) New(value s00.IABSupported,

) (IABSupportedAPERValue, error) {
	if c.encode == nil {
		return IABSupportedAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return IABSupportedAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return IABSupportedAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return IABSupportedAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c IABSupportedValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (IABSupportedAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return IABSupportedAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return IABSupportedAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return IABSupportedAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return IABSupportedAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c IABSupportedValueCodec) EncodeAPER(value IABSupportedAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c IABSupportedValueCodec) encodeBudgetValue(value s00.IABSupported,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c IABSupportedValueCodec) encodeChanged(value s00.IABSupported,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverFlagValueCodec is the concrete ValueCodec[HandoverFlag].
type HandoverFlagValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.HandoverFlag,

		error)
	encode func(s00.HandoverFlag,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.HandoverFlag, aper.DecodeState,

	) (s00.HandoverFlag, aper.Snapshot,

	)
	compare func(s00.HandoverFlag, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverFlagValueCodec) New(value s00.HandoverFlag,

) (HandoverFlagAPERValue, error) {
	if c.encode == nil {
		return HandoverFlagAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverFlagAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverFlagAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverFlagAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverFlagValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverFlagAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverFlagAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverFlagAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverFlagAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverFlagAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverFlagValueCodec) EncodeAPER(value HandoverFlagAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverFlagValueCodec) encodeBudgetValue(value s00.HandoverFlag,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverFlagValueCodec) encodeChanged(value s00.HandoverFlag,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LTEMIndicationValueCodec is the concrete ValueCodec[LTEMIndication].
type LTEMIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.LTEMIndication,

		error)
	encode func(s00.LTEMIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.LTEMIndication, aper.DecodeState,

	) (s00.LTEMIndication, aper.Snapshot,

	)
	compare func(s00.LTEMIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LTEMIndicationValueCodec) New(value s00.LTEMIndication,

) (LTEMIndicationAPERValue, error) {
	if c.encode == nil {
		return LTEMIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LTEMIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LTEMIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LTEMIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LTEMIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LTEMIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LTEMIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LTEMIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LTEMIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LTEMIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LTEMIndicationValueCodec) EncodeAPER(value LTEMIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LTEMIndicationValueCodec) encodeBudgetValue(value s00.LTEMIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LTEMIndicationValueCodec) encodeChanged(value s00.LTEMIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GWContextReleaseIndicationValueCodec is the concrete ValueCodec[GWContextReleaseIndication].
type GWContextReleaseIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.GWContextReleaseIndication,

		error)
	encode func(s00.GWContextReleaseIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.GWContextReleaseIndication, aper.DecodeState,

	) (s00.GWContextReleaseIndication, aper.Snapshot,

	)
	compare func(s00.GWContextReleaseIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GWContextReleaseIndicationValueCodec) New(value s00.GWContextReleaseIndication,

) (GWContextReleaseIndicationAPERValue, error) {
	if c.encode == nil {
		return GWContextReleaseIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GWContextReleaseIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GWContextReleaseIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GWContextReleaseIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GWContextReleaseIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GWContextReleaseIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GWContextReleaseIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GWContextReleaseIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GWContextReleaseIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GWContextReleaseIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GWContextReleaseIndicationValueCodec) EncodeAPER(value GWContextReleaseIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c GWContextReleaseIndicationValueCodec) encodeBudgetValue(value s00.GWContextReleaseIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GWContextReleaseIndicationValueCodec) encodeChanged(value s00.GWContextReleaseIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NumberofBroadcastRequestValueCodec is the concrete ValueCodec[NumberofBroadcastRequest].
type NumberofBroadcastRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NumberofBroadcastRequest,

		error)
	encode func(s00.NumberofBroadcastRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NumberofBroadcastRequest, aper.DecodeState,

	) (s00.NumberofBroadcastRequest, aper.Snapshot,

	)
	compare func(s00.NumberofBroadcastRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NumberofBroadcastRequestValueCodec) New(value s00.NumberofBroadcastRequest,

) (NumberofBroadcastRequestAPERValue, error) {
	if c.encode == nil {
		return NumberofBroadcastRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NumberofBroadcastRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NumberofBroadcastRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NumberofBroadcastRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NumberofBroadcastRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NumberofBroadcastRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NumberofBroadcastRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NumberofBroadcastRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NumberofBroadcastRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NumberofBroadcastRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NumberofBroadcastRequestValueCodec) EncodeAPER(value NumberofBroadcastRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NumberofBroadcastRequestValueCodec) encodeBudgetValue(value s00.NumberofBroadcastRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NumberofBroadcastRequestValueCodec) encodeChanged(value s00.NumberofBroadcastRequest,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// FailureEventReportingCauseValueCodec is the concrete ValueCodec[FailureEventReportingCause].
type FailureEventReportingCauseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.FailureEventReportingCause,

		error)
	encode func(s00.FailureEventReportingCause,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.FailureEventReportingCause, aper.DecodeState,

	) (s00.FailureEventReportingCause, aper.Snapshot,

	)
	compare func(s00.FailureEventReportingCause, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c FailureEventReportingCauseValueCodec) New(value s00.FailureEventReportingCause,

) (FailureEventReportingCauseAPERValue, error) {
	if c.encode == nil {
		return FailureEventReportingCauseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return FailureEventReportingCauseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return FailureEventReportingCauseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return FailureEventReportingCauseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c FailureEventReportingCauseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (FailureEventReportingCauseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return FailureEventReportingCauseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return FailureEventReportingCauseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return FailureEventReportingCauseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return FailureEventReportingCauseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c FailureEventReportingCauseValueCodec) EncodeAPER(value FailureEventReportingCauseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c FailureEventReportingCauseValueCodec) encodeBudgetValue(value s00.FailureEventReportingCause,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c FailureEventReportingCauseValueCodec) encodeChanged(value s00.FailureEventReportingCause,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// FiveGSTACValueCodec is the concrete ValueCodec[FiveGSTAC].
type FiveGSTACValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.FiveGSTAC,

		error)
	encode func(s00.FiveGSTAC,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.FiveGSTAC, aper.DecodeState,

	) (s00.FiveGSTAC, aper.Snapshot,

	)
	compare func(s00.FiveGSTAC, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c FiveGSTACValueCodec) New(value s00.FiveGSTAC,

) (FiveGSTACAPERValue, error) {
	if c.encode == nil {
		return FiveGSTACAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return FiveGSTACAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return FiveGSTACAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return FiveGSTACAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c FiveGSTACValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (FiveGSTACAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return FiveGSTACAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return FiveGSTACAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return FiveGSTACAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return FiveGSTACAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c FiveGSTACValueCodec) EncodeAPER(value FiveGSTACAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c FiveGSTACValueCodec) encodeBudgetValue(value s00.FiveGSTAC,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c FiveGSTACValueCodec) encodeChanged(value s00.FiveGSTAC,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// FiveQIValueCodec is the concrete ValueCodec[FiveQI].
type FiveQIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.FiveQI,

		error)
	encode func(s00.FiveQI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.FiveQI, aper.DecodeState,

	) (s00.FiveQI, aper.Snapshot,

	)
	compare func(s00.FiveQI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c FiveQIValueCodec) New(value s00.FiveQI,

) (FiveQIAPERValue, error) {
	if c.encode == nil {
		return FiveQIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return FiveQIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return FiveQIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return FiveQIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c FiveQIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (FiveQIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return FiveQIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return FiveQIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return FiveQIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return FiveQIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c FiveQIValueCodec) EncodeAPER(value FiveQIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c FiveQIValueCodec) encodeBudgetValue(value s00.FiveQI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c FiveQIValueCodec) encodeChanged(value s00.FiveQI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ForbiddenInterRATsValueCodec is the concrete ValueCodec[ForbiddenInterRATs].
type ForbiddenInterRATsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ForbiddenInterRATs,

		error)
	encode func(s00.ForbiddenInterRATs,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ForbiddenInterRATs, aper.DecodeState,

	) (s00.ForbiddenInterRATs, aper.Snapshot,

	)
	compare func(s00.ForbiddenInterRATs, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ForbiddenInterRATsValueCodec) New(value s00.ForbiddenInterRATs,

) (ForbiddenInterRATsAPERValue, error) {
	if c.encode == nil {
		return ForbiddenInterRATsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ForbiddenInterRATsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ForbiddenInterRATsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ForbiddenInterRATsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ForbiddenInterRATsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ForbiddenInterRATsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ForbiddenInterRATsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ForbiddenInterRATsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ForbiddenInterRATsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ForbiddenInterRATsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ForbiddenInterRATsValueCodec) EncodeAPER(value ForbiddenInterRATsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ForbiddenInterRATsValueCodec) encodeBudgetValue(value s00.ForbiddenInterRATs,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ForbiddenInterRATsValueCodec) encodeChanged(value s00.ForbiddenInterRATs,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ForbiddenLACsValueCodec is the concrete ValueCodec[ForbiddenLACs].
type ForbiddenLACsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ForbiddenLACs,

		error)
	encode func(s00.ForbiddenLACs,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ForbiddenLACs, aper.DecodeState,

	) (s00.ForbiddenLACs, aper.Snapshot,

	)
	compare func(s00.ForbiddenLACs, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ForbiddenLACsValueCodec) New(value s00.ForbiddenLACs,

) (ForbiddenLACsAPERValue, error) {
	if c.encode == nil {
		return ForbiddenLACsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ForbiddenLACsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ForbiddenLACsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ForbiddenLACsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ForbiddenLACsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ForbiddenLACsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ForbiddenLACsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ForbiddenLACsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ForbiddenLACsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ForbiddenLACsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ForbiddenLACsValueCodec) EncodeAPER(value ForbiddenLACsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ForbiddenLACsValueCodec) encodeBudgetValue(value s00.ForbiddenLACs,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ForbiddenLACsValueCodec) encodeChanged(value s00.ForbiddenLACs,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ForbiddenTACsValueCodec is the concrete ValueCodec[ForbiddenTACs].
type ForbiddenTACsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ForbiddenTACs,

		error)
	encode func(s00.ForbiddenTACs,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ForbiddenTACs, aper.DecodeState,

	) (s00.ForbiddenTACs, aper.Snapshot,

	)
	compare func(s00.ForbiddenTACs, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ForbiddenTACsValueCodec) New(value s00.ForbiddenTACs,

) (ForbiddenTACsAPERValue, error) {
	if c.encode == nil {
		return ForbiddenTACsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ForbiddenTACsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ForbiddenTACsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ForbiddenTACsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ForbiddenTACsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ForbiddenTACsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ForbiddenTACsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ForbiddenTACsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ForbiddenTACsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ForbiddenTACsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ForbiddenTACsValueCodec) EncodeAPER(value ForbiddenTACsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ForbiddenTACsValueCodec) encodeBudgetValue(value s00.ForbiddenTACs,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ForbiddenTACsValueCodec) encodeChanged(value s00.ForbiddenTACs,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GNBIDValueCodec is the concrete ValueCodec[GNBID].
type GNBIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.GNBID,

		error)
	encode func(s00.GNBID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.GNBID, aper.DecodeState,

	) (s00.GNBID, aper.Snapshot,

	)
	compare func(s00.GNBID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GNBIDValueCodec) New(value s00.GNBID,

) (GNBIDAPERValue, error) {
	if c.encode == nil {
		return GNBIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GNBIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GNBIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GNBIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GNBIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GNBIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GNBIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GNBIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GNBIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GNBIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GNBIDValueCodec) EncodeAPER(value GNBIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c GNBIDValueCodec) encodeBudgetValue(value s00.GNBID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GNBIDValueCodec) encodeChanged(value s00.GNBID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// GTPTEIDValueCodec is the concrete ValueCodec[GTPTEID].
type GTPTEIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.GTPTEID,

		error)
	encode func(s00.GTPTEID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.GTPTEID, aper.DecodeState,

	) (s00.GTPTEID, aper.Snapshot,

	)
	compare func(s00.GTPTEID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c GTPTEIDValueCodec) New(value s00.GTPTEID,

) (GTPTEIDAPERValue, error) {
	if c.encode == nil {
		return GTPTEIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return GTPTEIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return GTPTEIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return GTPTEIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c GTPTEIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (GTPTEIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return GTPTEIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return GTPTEIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return GTPTEIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return GTPTEIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c GTPTEIDValueCodec) EncodeAPER(value GTPTEIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c GTPTEIDValueCodec) encodeBudgetValue(value s00.GTPTEID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c GTPTEIDValueCodec) encodeChanged(value s00.GTPTEID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HFNValueCodec is the concrete ValueCodec[HFN].
type HFNValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.HFN,

		error)
	encode func(s00.HFN,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.HFN, aper.DecodeState,

	) (s00.HFN, aper.Snapshot,

	)
	compare func(s00.HFN, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HFNValueCodec) New(value s00.HFN,

) (HFNAPERValue, error) {
	if c.encode == nil {
		return HFNAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HFNAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HFNAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HFNAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HFNValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HFNAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HFNAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HFNAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HFNAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HFNAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HFNValueCodec) EncodeAPER(value HFNAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HFNValueCodec) encodeBudgetValue(value s00.HFN,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HFNValueCodec) encodeChanged(value s00.HFN,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HFNModifiedValueCodec is the concrete ValueCodec[HFNModified].
type HFNModifiedValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.HFNModified,

		error)
	encode func(s00.HFNModified,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.HFNModified, aper.DecodeState,

	) (s00.HFNModified, aper.Snapshot,

	)
	compare func(s00.HFNModified, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HFNModifiedValueCodec) New(value s00.HFNModified,

) (HFNModifiedAPERValue, error) {
	if c.encode == nil {
		return HFNModifiedAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HFNModifiedAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HFNModifiedAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HFNModifiedAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HFNModifiedValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HFNModifiedAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HFNModifiedAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HFNModifiedAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HFNModifiedAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HFNModifiedAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HFNModifiedValueCodec) EncodeAPER(value HFNModifiedAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HFNModifiedValueCodec) encodeBudgetValue(value s00.HFNModified,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HFNModifiedValueCodec) encodeChanged(value s00.HFNModified,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HFNforPDCPSNlength18ValueCodec is the concrete ValueCodec[HFNforPDCPSNlength18].
type HFNforPDCPSNlength18ValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.HFNforPDCPSNlength18,

		error)
	encode func(s00.HFNforPDCPSNlength18,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.HFNforPDCPSNlength18, aper.DecodeState,

	) (s00.HFNforPDCPSNlength18, aper.Snapshot,

	)
	compare func(s00.HFNforPDCPSNlength18, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HFNforPDCPSNlength18ValueCodec) New(value s00.HFNforPDCPSNlength18,

) (HFNforPDCPSNlength18APERValue, error) {
	if c.encode == nil {
		return HFNforPDCPSNlength18APERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HFNforPDCPSNlength18APERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HFNforPDCPSNlength18APERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HFNforPDCPSNlength18APERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HFNforPDCPSNlength18ValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HFNforPDCPSNlength18APERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HFNforPDCPSNlength18APERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HFNforPDCPSNlength18APERValue{}, report, aper.OperationError(err, c.path)
		}
		return HFNforPDCPSNlength18APERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HFNforPDCPSNlength18APERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HFNforPDCPSNlength18ValueCodec) EncodeAPER(value HFNforPDCPSNlength18APERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HFNforPDCPSNlength18ValueCodec) encodeBudgetValue(value s00.HFNforPDCPSNlength18,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HFNforPDCPSNlength18ValueCodec) encodeChanged(value s00.HFNforPDCPSNlength18,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HOReportingCauseValueCodec is the concrete ValueCodec[HOReportingCause].
type HOReportingCauseValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.HOReportingCause,

		error)
	encode func(s00.HOReportingCause,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.HOReportingCause, aper.DecodeState,

	) (s00.HOReportingCause, aper.Snapshot,

	)
	compare func(s00.HOReportingCause, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HOReportingCauseValueCodec) New(value s00.HOReportingCause,

) (HOReportingCauseAPERValue, error) {
	if c.encode == nil {
		return HOReportingCauseAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HOReportingCauseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HOReportingCauseAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HOReportingCauseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HOReportingCauseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HOReportingCauseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HOReportingCauseAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HOReportingCauseAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HOReportingCauseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HOReportingCauseAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HOReportingCauseValueCodec) EncodeAPER(value HOReportingCauseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HOReportingCauseValueCodec) encodeBudgetValue(value s00.HOReportingCause,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HOReportingCauseValueCodec) encodeChanged(value s00.HOReportingCause,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverWindowDurationValueCodec is the concrete ValueCodec[HandoverWindowDuration].
type HandoverWindowDurationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.HandoverWindowDuration,

		error)
	encode func(s00.HandoverWindowDuration,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.HandoverWindowDuration, aper.DecodeState,

	) (s00.HandoverWindowDuration, aper.Snapshot,

	)
	compare func(s00.HandoverWindowDuration, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverWindowDurationValueCodec) New(value s00.HandoverWindowDuration,

) (HandoverWindowDurationAPERValue, error) {
	if c.encode == nil {
		return HandoverWindowDurationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverWindowDurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverWindowDurationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverWindowDurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverWindowDurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverWindowDurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverWindowDurationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverWindowDurationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverWindowDurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverWindowDurationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverWindowDurationValueCodec) EncodeAPER(value HandoverWindowDurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverWindowDurationValueCodec) encodeBudgetValue(value s00.HandoverWindowDuration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverWindowDurationValueCodec) encodeChanged(value s00.HandoverWindowDuration,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HandoverWindowStartValueCodec is the concrete ValueCodec[HandoverWindowStart].
type HandoverWindowStartValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.HandoverWindowStart,

		error)
	encode func(s00.HandoverWindowStart,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.HandoverWindowStart, aper.DecodeState,

	) (s00.HandoverWindowStart, aper.Snapshot,

	)
	compare func(s00.HandoverWindowStart, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverWindowStartValueCodec) New(value s00.HandoverWindowStart,

) (HandoverWindowStartAPERValue, error) {
	if c.encode == nil {
		return HandoverWindowStartAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverWindowStartAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverWindowStartAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverWindowStartAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverWindowStartValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverWindowStartAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverWindowStartAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverWindowStartAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverWindowStartAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverWindowStartAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverWindowStartValueCodec) EncodeAPER(value HandoverWindowStartAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HandoverWindowStartValueCodec) encodeBudgetValue(value s00.HandoverWindowStart,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverWindowStartValueCodec) encodeChanged(value s00.HandoverWindowStart,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HoReportTypeValueCodec is the concrete ValueCodec[HoReportType].
type HoReportTypeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.HoReportType,

		error)
	encode func(s00.HoReportType,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.HoReportType, aper.DecodeState,

	) (s00.HoReportType, aper.Snapshot,

	)
	compare func(s00.HoReportType, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HoReportTypeValueCodec) New(value s00.HoReportType,

) (HoReportTypeAPERValue, error) {
	if c.encode == nil {
		return HoReportTypeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HoReportTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HoReportTypeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HoReportTypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HoReportTypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HoReportTypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HoReportTypeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HoReportTypeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HoReportTypeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HoReportTypeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HoReportTypeValueCodec) EncodeAPER(value HoReportTypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HoReportTypeValueCodec) encodeBudgetValue(value s00.HoReportType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HoReportTypeValueCodec) encodeChanged(value s00.HoReportType,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HoTypeValueCodec is the concrete ValueCodec[HoType].
type HoTypeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.HoType,

		error)
	encode func(s00.HoType,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.HoType, aper.DecodeState,

	) (s00.HoType, aper.Snapshot,

	)
	compare func(s00.HoType, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HoTypeValueCodec) New(value s00.HoType,

) (HoTypeAPERValue, error) {
	if c.encode == nil {
		return HoTypeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HoTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HoTypeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HoTypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HoTypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HoTypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HoTypeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HoTypeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HoTypeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HoTypeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HoTypeValueCodec) EncodeAPER(value HoTypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HoTypeValueCodec) encodeBudgetValue(value s00.HoType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HoTypeValueCodec) encodeChanged(value s00.HoType,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// HysteresisValueCodec is the concrete ValueCodec[Hysteresis].
type HysteresisValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.Hysteresis,

		error)
	encode func(s00.Hysteresis,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.Hysteresis, aper.DecodeState,

	) (s00.Hysteresis, aper.Snapshot,

	)
	compare func(s00.Hysteresis, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HysteresisValueCodec) New(value s00.Hysteresis,

) (HysteresisAPERValue, error) {
	if c.encode == nil {
		return HysteresisAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HysteresisAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HysteresisAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HysteresisAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HysteresisValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HysteresisAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HysteresisAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HysteresisAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HysteresisAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HysteresisAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HysteresisValueCodec) EncodeAPER(value HysteresisAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c HysteresisValueCodec) encodeBudgetValue(value s00.Hysteresis,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HysteresisValueCodec) encodeChanged(value s00.Hysteresis,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// IMSIValueCodec is the concrete ValueCodec[IMSI].
type IMSIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.IMSI,

		error)
	encode func(s00.IMSI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.IMSI, aper.DecodeState,

	) (s00.IMSI, aper.Snapshot,

	)
	compare func(s00.IMSI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c IMSIValueCodec) New(value s00.IMSI,

) (IMSIAPERValue, error) {
	if c.encode == nil {
		return IMSIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return IMSIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return IMSIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return IMSIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c IMSIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (IMSIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return IMSIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return IMSIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return IMSIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return IMSIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c IMSIValueCodec) EncodeAPER(value IMSIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c IMSIValueCodec) encodeBudgetValue(value s00.IMSI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c IMSIValueCodec) encodeChanged(value s00.IMSI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// IntegrityProtectionAlgorithmsValueCodec is the concrete ValueCodec[IntegrityProtectionAlgorithms].
type IntegrityProtectionAlgorithmsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.IntegrityProtectionAlgorithms,

		error)
	encode func(s00.IntegrityProtectionAlgorithms,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.IntegrityProtectionAlgorithms, aper.DecodeState,

	) (s00.IntegrityProtectionAlgorithms, aper.Snapshot,

	)
	compare func(s00.IntegrityProtectionAlgorithms, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c IntegrityProtectionAlgorithmsValueCodec) New(value s00.IntegrityProtectionAlgorithms,

) (IntegrityProtectionAlgorithmsAPERValue, error) {
	if c.encode == nil {
		return IntegrityProtectionAlgorithmsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return IntegrityProtectionAlgorithmsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return IntegrityProtectionAlgorithmsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return IntegrityProtectionAlgorithmsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c IntegrityProtectionAlgorithmsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (IntegrityProtectionAlgorithmsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return IntegrityProtectionAlgorithmsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return IntegrityProtectionAlgorithmsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return IntegrityProtectionAlgorithmsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return IntegrityProtectionAlgorithmsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c IntegrityProtectionAlgorithmsValueCodec) EncodeAPER(value IntegrityProtectionAlgorithmsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c IntegrityProtectionAlgorithmsValueCodec) encodeBudgetValue(value s00.IntegrityProtectionAlgorithms,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c IntegrityProtectionAlgorithmsValueCodec) encodeChanged(value s00.IntegrityProtectionAlgorithms,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// IntegrityProtectionIndicationValueCodec is the concrete ValueCodec[IntegrityProtectionIndication].
type IntegrityProtectionIndicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.IntegrityProtectionIndication,

		error)
	encode func(s00.IntegrityProtectionIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.IntegrityProtectionIndication, aper.DecodeState,

	) (s00.IntegrityProtectionIndication, aper.Snapshot,

	)
	compare func(s00.IntegrityProtectionIndication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c IntegrityProtectionIndicationValueCodec) New(value s00.IntegrityProtectionIndication,

) (IntegrityProtectionIndicationAPERValue, error) {
	if c.encode == nil {
		return IntegrityProtectionIndicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return IntegrityProtectionIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return IntegrityProtectionIndicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return IntegrityProtectionIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c IntegrityProtectionIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (IntegrityProtectionIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return IntegrityProtectionIndicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return IntegrityProtectionIndicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return IntegrityProtectionIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return IntegrityProtectionIndicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c IntegrityProtectionIndicationValueCodec) EncodeAPER(value IntegrityProtectionIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c IntegrityProtectionIndicationValueCodec) encodeBudgetValue(value s00.IntegrityProtectionIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c IntegrityProtectionIndicationValueCodec) encodeChanged(value s00.IntegrityProtectionIndication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// IntegrityProtectionResultValueCodec is the concrete ValueCodec[IntegrityProtectionResult].
type IntegrityProtectionResultValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.IntegrityProtectionResult,

		error)
	encode func(s00.IntegrityProtectionResult,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.IntegrityProtectionResult, aper.DecodeState,

	) (s00.IntegrityProtectionResult, aper.Snapshot,

	)
	compare func(s00.IntegrityProtectionResult, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c IntegrityProtectionResultValueCodec) New(value s00.IntegrityProtectionResult,

) (IntegrityProtectionResultAPERValue, error) {
	if c.encode == nil {
		return IntegrityProtectionResultAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return IntegrityProtectionResultAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return IntegrityProtectionResultAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return IntegrityProtectionResultAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c IntegrityProtectionResultValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (IntegrityProtectionResultAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return IntegrityProtectionResultAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return IntegrityProtectionResultAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return IntegrityProtectionResultAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return IntegrityProtectionResultAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c IntegrityProtectionResultValueCodec) EncodeAPER(value IntegrityProtectionResultAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c IntegrityProtectionResultValueCodec) encodeBudgetValue(value s00.IntegrityProtectionResult,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c IntegrityProtectionResultValueCodec) encodeChanged(value s00.IntegrityProtectionResult,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// IntendedNumberOfPagingAttemptsValueCodec is the concrete ValueCodec[IntendedNumberOfPagingAttempts].
type IntendedNumberOfPagingAttemptsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.IntendedNumberOfPagingAttempts,

		error)
	encode func(s00.IntendedNumberOfPagingAttempts,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.IntendedNumberOfPagingAttempts, aper.DecodeState,

	) (s00.IntendedNumberOfPagingAttempts, aper.Snapshot,

	)
	compare func(s00.IntendedNumberOfPagingAttempts, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c IntendedNumberOfPagingAttemptsValueCodec) New(value s00.IntendedNumberOfPagingAttempts,

) (IntendedNumberOfPagingAttemptsAPERValue, error) {
	if c.encode == nil {
		return IntendedNumberOfPagingAttemptsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return IntendedNumberOfPagingAttemptsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return IntendedNumberOfPagingAttemptsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return IntendedNumberOfPagingAttemptsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c IntendedNumberOfPagingAttemptsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (IntendedNumberOfPagingAttemptsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return IntendedNumberOfPagingAttemptsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return IntendedNumberOfPagingAttemptsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return IntendedNumberOfPagingAttemptsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return IntendedNumberOfPagingAttemptsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c IntendedNumberOfPagingAttemptsValueCodec) EncodeAPER(value IntendedNumberOfPagingAttemptsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c IntendedNumberOfPagingAttemptsValueCodec) encodeBudgetValue(value s00.IntendedNumberOfPagingAttempts,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c IntendedNumberOfPagingAttemptsValueCodec) encodeChanged(value s00.IntendedNumberOfPagingAttempts,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InterfacesToTraceValueCodec is the concrete ValueCodec[InterfacesToTrace].
type InterfacesToTraceValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.InterfacesToTrace,

		error)
	encode func(s00.InterfacesToTrace,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.InterfacesToTrace, aper.DecodeState,

	) (s00.InterfacesToTrace, aper.Snapshot,

	)
	compare func(s00.InterfacesToTrace, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InterfacesToTraceValueCodec) New(value s00.InterfacesToTrace,

) (InterfacesToTraceAPERValue, error) {
	if c.encode == nil {
		return InterfacesToTraceAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InterfacesToTraceAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InterfacesToTraceAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InterfacesToTraceAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InterfacesToTraceValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InterfacesToTraceAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InterfacesToTraceAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InterfacesToTraceAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InterfacesToTraceAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InterfacesToTraceAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InterfacesToTraceValueCodec) EncodeAPER(value InterfacesToTraceAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c InterfacesToTraceValueCodec) encodeBudgetValue(value s00.InterfacesToTrace,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InterfacesToTraceValueCodec) encodeChanged(value s00.InterfacesToTrace,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// L3InformationValueCodec is the concrete ValueCodec[L3Information].
type L3InformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.L3Information,

		error)
	encode func(s00.L3Information,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.L3Information, aper.DecodeState,

	) (s00.L3Information, aper.Snapshot,

	)
	compare func(s00.L3Information, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c L3InformationValueCodec) New(value s00.L3Information,

) (L3InformationAPERValue, error) {
	if c.encode == nil {
		return L3InformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return L3InformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return L3InformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return L3InformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c L3InformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (L3InformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return L3InformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return L3InformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return L3InformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return L3InformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c L3InformationValueCodec) EncodeAPER(value L3InformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c L3InformationValueCodec) encodeBudgetValue(value s00.L3Information,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c L3InformationValueCodec) encodeChanged(value s00.L3Information,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LACValueCodec is the concrete ValueCodec[LAC].
type LACValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.LAC,

		error)
	encode func(s00.LAC,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.LAC, aper.DecodeState,

	) (s00.LAC, aper.Snapshot,

	)
	compare func(s00.LAC, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LACValueCodec) New(value s00.LAC,

) (LACAPERValue, error) {
	if c.encode == nil {
		return LACAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LACAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LACAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LACAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LACValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LACAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LACAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LACAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LACAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LACAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LACValueCodec) EncodeAPER(value LACAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LACValueCodec) encodeBudgetValue(value s00.LAC,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LACValueCodec) encodeChanged(value s00.LAC,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LastVisitedNGRANCellInformationValueCodec is the concrete ValueCodec[LastVisitedNGRANCellInformation].
type LastVisitedNGRANCellInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.LastVisitedNGRANCellInformation,

		error)
	encode func(s00.LastVisitedNGRANCellInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.LastVisitedNGRANCellInformation, aper.DecodeState,

	) (s00.LastVisitedNGRANCellInformation, aper.Snapshot,

	)
	compare func(s00.LastVisitedNGRANCellInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LastVisitedNGRANCellInformationValueCodec) New(value s00.LastVisitedNGRANCellInformation,

) (LastVisitedNGRANCellInformationAPERValue, error) {
	if c.encode == nil {
		return LastVisitedNGRANCellInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LastVisitedNGRANCellInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LastVisitedNGRANCellInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LastVisitedNGRANCellInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LastVisitedNGRANCellInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LastVisitedNGRANCellInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LastVisitedNGRANCellInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LastVisitedNGRANCellInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LastVisitedNGRANCellInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LastVisitedNGRANCellInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LastVisitedNGRANCellInformationValueCodec) EncodeAPER(value LastVisitedNGRANCellInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LastVisitedNGRANCellInformationValueCodec) encodeBudgetValue(value s00.LastVisitedNGRANCellInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LastVisitedNGRANCellInformationValueCodec) encodeChanged(value s00.LastVisitedNGRANCellInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LastVisitedUTRANCellInformationValueCodec is the concrete ValueCodec[LastVisitedUTRANCellInformation].
type LastVisitedUTRANCellInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.LastVisitedUTRANCellInformation,

		error)
	encode func(s00.LastVisitedUTRANCellInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.LastVisitedUTRANCellInformation, aper.DecodeState,

	) (s00.LastVisitedUTRANCellInformation, aper.Snapshot,

	)
	compare func(s00.LastVisitedUTRANCellInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LastVisitedUTRANCellInformationValueCodec) New(value s00.LastVisitedUTRANCellInformation,

) (LastVisitedUTRANCellInformationAPERValue, error) {
	if c.encode == nil {
		return LastVisitedUTRANCellInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LastVisitedUTRANCellInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LastVisitedUTRANCellInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LastVisitedUTRANCellInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LastVisitedUTRANCellInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LastVisitedUTRANCellInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LastVisitedUTRANCellInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LastVisitedUTRANCellInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LastVisitedUTRANCellInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LastVisitedUTRANCellInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LastVisitedUTRANCellInformationValueCodec) EncodeAPER(value LastVisitedUTRANCellInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LastVisitedUTRANCellInformationValueCodec) encodeBudgetValue(value s00.LastVisitedUTRANCellInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LastVisitedUTRANCellInformationValueCodec) encodeChanged(value s00.LastVisitedUTRANCellInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LinksToLogValueCodec is the concrete ValueCodec[LinksToLog].
type LinksToLogValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.LinksToLog,

		error)
	encode func(s00.LinksToLog,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.LinksToLog, aper.DecodeState,

	) (s00.LinksToLog, aper.Snapshot,

	)
	compare func(s00.LinksToLog, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LinksToLogValueCodec) New(value s00.LinksToLog,

) (LinksToLogAPERValue, error) {
	if c.encode == nil {
		return LinksToLogAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LinksToLogAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LinksToLogAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LinksToLogAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LinksToLogValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LinksToLogAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LinksToLogAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LinksToLogAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LinksToLogAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LinksToLogAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LinksToLogValueCodec) EncodeAPER(value LinksToLogAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LinksToLogValueCodec) encodeBudgetValue(value s00.LinksToLog,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LinksToLogValueCodec) encodeChanged(value s00.LinksToLog,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LoggingDurationValueCodec is the concrete ValueCodec[LoggingDuration].
type LoggingDurationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.LoggingDuration,

		error)
	encode func(s00.LoggingDuration,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.LoggingDuration, aper.DecodeState,

	) (s00.LoggingDuration, aper.Snapshot,

	)
	compare func(s00.LoggingDuration, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LoggingDurationValueCodec) New(value s00.LoggingDuration,

) (LoggingDurationAPERValue, error) {
	if c.encode == nil {
		return LoggingDurationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LoggingDurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LoggingDurationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LoggingDurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LoggingDurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LoggingDurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LoggingDurationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LoggingDurationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LoggingDurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LoggingDurationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LoggingDurationValueCodec) EncodeAPER(value LoggingDurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LoggingDurationValueCodec) encodeBudgetValue(value s00.LoggingDuration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LoggingDurationValueCodec) encodeChanged(value s00.LoggingDuration,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// LoggingIntervalValueCodec is the concrete ValueCodec[LoggingInterval].
type LoggingIntervalValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.LoggingInterval,

		error)
	encode func(s00.LoggingInterval,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.LoggingInterval, aper.DecodeState,

	) (s00.LoggingInterval, aper.Snapshot,

	)
	compare func(s00.LoggingInterval, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c LoggingIntervalValueCodec) New(value s00.LoggingInterval,

) (LoggingIntervalAPERValue, error) {
	if c.encode == nil {
		return LoggingIntervalAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return LoggingIntervalAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return LoggingIntervalAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return LoggingIntervalAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c LoggingIntervalValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (LoggingIntervalAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return LoggingIntervalAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return LoggingIntervalAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return LoggingIntervalAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return LoggingIntervalAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c LoggingIntervalValueCodec) EncodeAPER(value LoggingIntervalAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c LoggingIntervalValueCodec) encodeBudgetValue(value s00.LoggingInterval,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c LoggingIntervalValueCodec) encodeChanged(value s00.LoggingInterval,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M1ReportingTriggerValueCodec is the concrete ValueCodec[M1ReportingTrigger].
type M1ReportingTriggerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.M1ReportingTrigger,

		error)
	encode func(s00.M1ReportingTrigger,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.M1ReportingTrigger, aper.DecodeState,

	) (s00.M1ReportingTrigger, aper.Snapshot,

	)
	compare func(s00.M1ReportingTrigger, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M1ReportingTriggerValueCodec) New(value s00.M1ReportingTrigger,

) (M1ReportingTriggerAPERValue, error) {
	if c.encode == nil {
		return M1ReportingTriggerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M1ReportingTriggerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M1ReportingTriggerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M1ReportingTriggerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M1ReportingTriggerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M1ReportingTriggerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M1ReportingTriggerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M1ReportingTriggerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M1ReportingTriggerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M1ReportingTriggerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M1ReportingTriggerValueCodec) EncodeAPER(value M1ReportingTriggerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c M1ReportingTriggerValueCodec) encodeBudgetValue(value s00.M1ReportingTrigger,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M1ReportingTriggerValueCodec) encodeChanged(value s00.M1ReportingTrigger,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M3periodValueCodec is the concrete ValueCodec[M3period].
type M3periodValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.M3period,

		error)
	encode func(s00.M3period,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.M3period, aper.DecodeState,

	) (s00.M3period, aper.Snapshot,

	)
	compare func(s00.M3period, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M3periodValueCodec) New(value s00.M3period,

) (M3periodAPERValue, error) {
	if c.encode == nil {
		return M3periodAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M3periodAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M3periodAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M3periodAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M3periodValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M3periodAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M3periodAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M3periodAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M3periodAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M3periodAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M3periodValueCodec) EncodeAPER(value M3periodAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c M3periodValueCodec) encodeBudgetValue(value s00.M3period,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M3periodValueCodec) encodeChanged(value s00.M3period,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M4periodValueCodec is the concrete ValueCodec[M4period].
type M4periodValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.M4period,

		error)
	encode func(s00.M4period,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.M4period, aper.DecodeState,

	) (s00.M4period, aper.Snapshot,

	)
	compare func(s00.M4period, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M4periodValueCodec) New(value s00.M4period,

) (M4periodAPERValue, error) {
	if c.encode == nil {
		return M4periodAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M4periodAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M4periodAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M4periodAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M4periodValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M4periodAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M4periodAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M4periodAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M4periodAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M4periodAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M4periodValueCodec) EncodeAPER(value M4periodAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c M4periodValueCodec) encodeBudgetValue(value s00.M4period,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M4periodValueCodec) encodeChanged(value s00.M4period,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M5periodValueCodec is the concrete ValueCodec[M5period].
type M5periodValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.M5period,

		error)
	encode func(s00.M5period,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.M5period, aper.DecodeState,

	) (s00.M5period, aper.Snapshot,

	)
	compare func(s00.M5period, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M5periodValueCodec) New(value s00.M5period,

) (M5periodAPERValue, error) {
	if c.encode == nil {
		return M5periodAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M5periodAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M5periodAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M5periodAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M5periodValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M5periodAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M5periodAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M5periodAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M5periodAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M5periodAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M5periodValueCodec) EncodeAPER(value M5periodAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c M5periodValueCodec) encodeBudgetValue(value s00.M5period,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M5periodValueCodec) encodeChanged(value s00.M5period,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M6delayThresholdValueCodec is the concrete ValueCodec[M6delayThreshold].
type M6delayThresholdValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.M6delayThreshold,

		error)
	encode func(s00.M6delayThreshold,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.M6delayThreshold, aper.DecodeState,

	) (s00.M6delayThreshold, aper.Snapshot,

	)
	compare func(s00.M6delayThreshold, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M6delayThresholdValueCodec) New(value s00.M6delayThreshold,

) (M6delayThresholdAPERValue, error) {
	if c.encode == nil {
		return M6delayThresholdAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M6delayThresholdAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M6delayThresholdAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M6delayThresholdAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M6delayThresholdValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M6delayThresholdAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M6delayThresholdAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M6delayThresholdAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M6delayThresholdAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M6delayThresholdAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M6delayThresholdValueCodec) EncodeAPER(value M6delayThresholdAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c M6delayThresholdValueCodec) encodeBudgetValue(value s00.M6delayThreshold,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M6delayThresholdValueCodec) encodeChanged(value s00.M6delayThreshold,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M6reportIntervalValueCodec is the concrete ValueCodec[M6reportInterval].
type M6reportIntervalValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.M6reportInterval,

		error)
	encode func(s00.M6reportInterval,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.M6reportInterval, aper.DecodeState,

	) (s00.M6reportInterval, aper.Snapshot,

	)
	compare func(s00.M6reportInterval, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M6reportIntervalValueCodec) New(value s00.M6reportInterval,

) (M6reportIntervalAPERValue, error) {
	if c.encode == nil {
		return M6reportIntervalAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M6reportIntervalAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M6reportIntervalAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M6reportIntervalAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M6reportIntervalValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M6reportIntervalAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M6reportIntervalAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M6reportIntervalAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M6reportIntervalAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M6reportIntervalAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M6reportIntervalValueCodec) EncodeAPER(value M6reportIntervalAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c M6reportIntervalValueCodec) encodeBudgetValue(value s00.M6reportInterval,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M6reportIntervalValueCodec) encodeChanged(value s00.M6reportInterval,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// M7periodValueCodec is the concrete ValueCodec[M7period].
type M7periodValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.M7period,

		error)
	encode func(s00.M7period,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.M7period, aper.DecodeState,

	) (s00.M7period, aper.Snapshot,

	)
	compare func(s00.M7period, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c M7periodValueCodec) New(value s00.M7period,

) (M7periodAPERValue, error) {
	if c.encode == nil {
		return M7periodAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return M7periodAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return M7periodAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return M7periodAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c M7periodValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (M7periodAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return M7periodAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return M7periodAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return M7periodAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return M7periodAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c M7periodValueCodec) EncodeAPER(value M7periodAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c M7periodValueCodec) encodeBudgetValue(value s00.M7period,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c M7periodValueCodec) encodeChanged(value s00.M7period,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MDTActivationValueCodec is the concrete ValueCodec[MDTActivation].
type MDTActivationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.MDTActivation,

		error)
	encode func(s00.MDTActivation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.MDTActivation, aper.DecodeState,

	) (s00.MDTActivation, aper.Snapshot,

	)
	compare func(s00.MDTActivation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MDTActivationValueCodec) New(value s00.MDTActivation,

) (MDTActivationAPERValue, error) {
	if c.encode == nil {
		return MDTActivationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MDTActivationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MDTActivationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MDTActivationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MDTActivationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MDTActivationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MDTActivationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MDTActivationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MDTActivationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MDTActivationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MDTActivationValueCodec) EncodeAPER(value MDTActivationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MDTActivationValueCodec) encodeBudgetValue(value s00.MDTActivation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MDTActivationValueCodec) encodeChanged(value s00.MDTActivation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MMECodeValueCodec is the concrete ValueCodec[MMECode].
type MMECodeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.MMECode,

		error)
	encode func(s00.MMECode,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.MMECode, aper.DecodeState,

	) (s00.MMECode, aper.Snapshot,

	)
	compare func(s00.MMECode, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MMECodeValueCodec) New(value s00.MMECode,

) (MMECodeAPERValue, error) {
	if c.encode == nil {
		return MMECodeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MMECodeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MMECodeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MMECodeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MMECodeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MMECodeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MMECodeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MMECodeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MMECodeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MMECodeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MMECodeValueCodec) EncodeAPER(value MMECodeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MMECodeValueCodec) encodeBudgetValue(value s00.MMECode,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MMECodeValueCodec) encodeChanged(value s00.MMECode,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MTMSIValueCodec is the concrete ValueCodec[MTMSI].
type MTMSIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.MTMSI,

		error)
	encode func(s00.MTMSI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.MTMSI, aper.DecodeState,

	) (s00.MTMSI, aper.Snapshot,

	)
	compare func(s00.MTMSI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MTMSIValueCodec) New(value s00.MTMSI,

) (MTMSIAPERValue, error) {
	if c.encode == nil {
		return MTMSIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MTMSIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MTMSIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MTMSIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MTMSIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MTMSIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MTMSIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MTMSIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MTMSIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MTMSIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MTMSIValueCodec) EncodeAPER(value MTMSIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MTMSIValueCodec) encodeBudgetValue(value s00.MTMSI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MTMSIValueCodec) encodeChanged(value s00.MTMSI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// MeasurementsToActivateValueCodec is the concrete ValueCodec[MeasurementsToActivate].
type MeasurementsToActivateValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.MeasurementsToActivate,

		error)
	encode func(s00.MeasurementsToActivate,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.MeasurementsToActivate, aper.DecodeState,

	) (s00.MeasurementsToActivate, aper.Snapshot,

	)
	compare func(s00.MeasurementsToActivate, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c MeasurementsToActivateValueCodec) New(value s00.MeasurementsToActivate,

) (MeasurementsToActivateAPERValue, error) {
	if c.encode == nil {
		return MeasurementsToActivateAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MeasurementsToActivateAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MeasurementsToActivateAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return MeasurementsToActivateAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c MeasurementsToActivateValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MeasurementsToActivateAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return MeasurementsToActivateAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return MeasurementsToActivateAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return MeasurementsToActivateAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return MeasurementsToActivateAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c MeasurementsToActivateValueCodec) EncodeAPER(value MeasurementsToActivateAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MeasurementsToActivateValueCodec) encodeBudgetValue(value s00.MeasurementsToActivate,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c MeasurementsToActivateValueCodec) encodeChanged(value s00.MeasurementsToActivate,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NBIoTPagingEDRXCycleValueCodec is the concrete ValueCodec[NBIoTPagingEDRXCycle].
type NBIoTPagingEDRXCycleValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NBIoTPagingEDRXCycle,

		error)
	encode func(s00.NBIoTPagingEDRXCycle,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NBIoTPagingEDRXCycle, aper.DecodeState,

	) (s00.NBIoTPagingEDRXCycle, aper.Snapshot,

	)
	compare func(s00.NBIoTPagingEDRXCycle, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NBIoTPagingEDRXCycleValueCodec) New(value s00.NBIoTPagingEDRXCycle,

) (NBIoTPagingEDRXCycleAPERValue, error) {
	if c.encode == nil {
		return NBIoTPagingEDRXCycleAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NBIoTPagingEDRXCycleAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NBIoTPagingEDRXCycleAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NBIoTPagingEDRXCycleAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NBIoTPagingEDRXCycleValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NBIoTPagingEDRXCycleAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NBIoTPagingEDRXCycleAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NBIoTPagingEDRXCycleAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NBIoTPagingEDRXCycleAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NBIoTPagingEDRXCycleAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NBIoTPagingEDRXCycleValueCodec) EncodeAPER(value NBIoTPagingEDRXCycleAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NBIoTPagingEDRXCycleValueCodec) encodeBudgetValue(value s00.NBIoTPagingEDRXCycle,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NBIoTPagingEDRXCycleValueCodec) encodeChanged(value s00.NBIoTPagingEDRXCycle,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NBIoTPagingTimeWindowValueCodec is the concrete ValueCodec[NBIoTPagingTimeWindow].
type NBIoTPagingTimeWindowValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NBIoTPagingTimeWindow,

		error)
	encode func(s00.NBIoTPagingTimeWindow,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NBIoTPagingTimeWindow, aper.DecodeState,

	) (s00.NBIoTPagingTimeWindow, aper.Snapshot,

	)
	compare func(s00.NBIoTPagingTimeWindow, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NBIoTPagingTimeWindowValueCodec) New(value s00.NBIoTPagingTimeWindow,

) (NBIoTPagingTimeWindowAPERValue, error) {
	if c.encode == nil {
		return NBIoTPagingTimeWindowAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NBIoTPagingTimeWindowAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NBIoTPagingTimeWindowAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NBIoTPagingTimeWindowAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NBIoTPagingTimeWindowValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NBIoTPagingTimeWindowAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NBIoTPagingTimeWindowAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NBIoTPagingTimeWindowAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NBIoTPagingTimeWindowAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NBIoTPagingTimeWindowAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NBIoTPagingTimeWindowValueCodec) EncodeAPER(value NBIoTPagingTimeWindowAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NBIoTPagingTimeWindowValueCodec) encodeBudgetValue(value s00.NBIoTPagingTimeWindow,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NBIoTPagingTimeWindowValueCodec) encodeChanged(value s00.NBIoTPagingTimeWindow,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NRCellIdentityValueCodec is the concrete ValueCodec[NRCellIdentity].
type NRCellIdentityValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NRCellIdentity,

		error)
	encode func(s00.NRCellIdentity,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NRCellIdentity, aper.DecodeState,

	) (s00.NRCellIdentity, aper.Snapshot,

	)
	compare func(s00.NRCellIdentity, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NRCellIdentityValueCodec) New(value s00.NRCellIdentity,

) (NRCellIdentityAPERValue, error) {
	if c.encode == nil {
		return NRCellIdentityAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NRCellIdentityAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRCellIdentityAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NRCellIdentityAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NRCellIdentityValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NRCellIdentityAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NRCellIdentityAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NRCellIdentityAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NRCellIdentityAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NRCellIdentityAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NRCellIdentityValueCodec) EncodeAPER(value NRCellIdentityAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NRCellIdentityValueCodec) encodeBudgetValue(value s00.NRCellIdentity,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NRCellIdentityValueCodec) encodeChanged(value s00.NRCellIdentity,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NRencryptionAlgorithmsValueCodec is the concrete ValueCodec[NRencryptionAlgorithms].
type NRencryptionAlgorithmsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NRencryptionAlgorithms,

		error)
	encode func(s00.NRencryptionAlgorithms,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NRencryptionAlgorithms, aper.DecodeState,

	) (s00.NRencryptionAlgorithms, aper.Snapshot,

	)
	compare func(s00.NRencryptionAlgorithms, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NRencryptionAlgorithmsValueCodec) New(value s00.NRencryptionAlgorithms,

) (NRencryptionAlgorithmsAPERValue, error) {
	if c.encode == nil {
		return NRencryptionAlgorithmsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NRencryptionAlgorithmsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRencryptionAlgorithmsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NRencryptionAlgorithmsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NRencryptionAlgorithmsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NRencryptionAlgorithmsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NRencryptionAlgorithmsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NRencryptionAlgorithmsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NRencryptionAlgorithmsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NRencryptionAlgorithmsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NRencryptionAlgorithmsValueCodec) EncodeAPER(value NRencryptionAlgorithmsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NRencryptionAlgorithmsValueCodec) encodeBudgetValue(value s00.NRencryptionAlgorithms,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NRencryptionAlgorithmsValueCodec) encodeChanged(value s00.NRencryptionAlgorithms,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NRintegrityProtectionAlgorithmsValueCodec is the concrete ValueCodec[NRintegrityProtectionAlgorithms].
type NRintegrityProtectionAlgorithmsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NRintegrityProtectionAlgorithms,

		error)
	encode func(s00.NRintegrityProtectionAlgorithms,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NRintegrityProtectionAlgorithms, aper.DecodeState,

	) (s00.NRintegrityProtectionAlgorithms, aper.Snapshot,

	)
	compare func(s00.NRintegrityProtectionAlgorithms, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NRintegrityProtectionAlgorithmsValueCodec) New(value s00.NRintegrityProtectionAlgorithms,

) (NRintegrityProtectionAlgorithmsAPERValue, error) {
	if c.encode == nil {
		return NRintegrityProtectionAlgorithmsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NRintegrityProtectionAlgorithmsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NRintegrityProtectionAlgorithmsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NRintegrityProtectionAlgorithmsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NRintegrityProtectionAlgorithmsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NRintegrityProtectionAlgorithmsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NRintegrityProtectionAlgorithmsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NRintegrityProtectionAlgorithmsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NRintegrityProtectionAlgorithmsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NRintegrityProtectionAlgorithmsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NRintegrityProtectionAlgorithmsValueCodec) EncodeAPER(value NRintegrityProtectionAlgorithmsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NRintegrityProtectionAlgorithmsValueCodec) encodeBudgetValue(value s00.NRintegrityProtectionAlgorithms,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NRintegrityProtectionAlgorithmsValueCodec) encodeChanged(value s00.NRintegrityProtectionAlgorithms,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NextPagingAreaScopeValueCodec is the concrete ValueCodec[NextPagingAreaScope].
type NextPagingAreaScopeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NextPagingAreaScope,

		error)
	encode func(s00.NextPagingAreaScope,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NextPagingAreaScope, aper.DecodeState,

	) (s00.NextPagingAreaScope, aper.Snapshot,

	)
	compare func(s00.NextPagingAreaScope, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NextPagingAreaScopeValueCodec) New(value s00.NextPagingAreaScope,

) (NextPagingAreaScopeAPERValue, error) {
	if c.encode == nil {
		return NextPagingAreaScopeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NextPagingAreaScopeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NextPagingAreaScopeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NextPagingAreaScopeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NextPagingAreaScopeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NextPagingAreaScopeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NextPagingAreaScopeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NextPagingAreaScopeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NextPagingAreaScopeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NextPagingAreaScopeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NextPagingAreaScopeValueCodec) EncodeAPER(value NextPagingAreaScopeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NextPagingAreaScopeValueCodec) encodeBudgetValue(value s00.NextPagingAreaScope,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NextPagingAreaScopeValueCodec) encodeChanged(value s00.NextPagingAreaScope,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NotifyFlagValueCodec is the concrete ValueCodec[NotifyFlag].
type NotifyFlagValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NotifyFlag,

		error)
	encode func(s00.NotifyFlag,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NotifyFlag, aper.DecodeState,

	) (s00.NotifyFlag, aper.Snapshot,

	)
	compare func(s00.NotifyFlag, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NotifyFlagValueCodec) New(value s00.NotifyFlag,

) (NotifyFlagAPERValue, error) {
	if c.encode == nil {
		return NotifyFlagAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NotifyFlagAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NotifyFlagAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NotifyFlagAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NotifyFlagValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NotifyFlagAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NotifyFlagAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NotifyFlagAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NotifyFlagAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NotifyFlagAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NotifyFlagValueCodec) EncodeAPER(value NotifyFlagAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NotifyFlagValueCodec) encodeBudgetValue(value s00.NotifyFlag,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NotifyFlagValueCodec) encodeChanged(value s00.NotifyFlag,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NumberOfBroadcastsValueCodec is the concrete ValueCodec[NumberOfBroadcasts].
type NumberOfBroadcastsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NumberOfBroadcasts,

		error)
	encode func(s00.NumberOfBroadcasts,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NumberOfBroadcasts, aper.DecodeState,

	) (s00.NumberOfBroadcasts, aper.Snapshot,

	)
	compare func(s00.NumberOfBroadcasts, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NumberOfBroadcastsValueCodec) New(value s00.NumberOfBroadcasts,

) (NumberOfBroadcastsAPERValue, error) {
	if c.encode == nil {
		return NumberOfBroadcastsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NumberOfBroadcastsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NumberOfBroadcastsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NumberOfBroadcastsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NumberOfBroadcastsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NumberOfBroadcastsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NumberOfBroadcastsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NumberOfBroadcastsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NumberOfBroadcastsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NumberOfBroadcastsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NumberOfBroadcastsValueCodec) EncodeAPER(value NumberOfBroadcastsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NumberOfBroadcastsValueCodec) encodeBudgetValue(value s00.NumberOfBroadcasts,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NumberOfBroadcastsValueCodec) encodeChanged(value s00.NumberOfBroadcasts,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// NumberOfMeasurementReportingLevelsValueCodec is the concrete ValueCodec[NumberOfMeasurementReportingLevels].
type NumberOfMeasurementReportingLevelsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.NumberOfMeasurementReportingLevels,

		error)
	encode func(s00.NumberOfMeasurementReportingLevels,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.NumberOfMeasurementReportingLevels, aper.DecodeState,

	) (s00.NumberOfMeasurementReportingLevels, aper.Snapshot,

	)
	compare func(s00.NumberOfMeasurementReportingLevels, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c NumberOfMeasurementReportingLevelsValueCodec) New(value s00.NumberOfMeasurementReportingLevels,

) (NumberOfMeasurementReportingLevelsAPERValue, error) {
	if c.encode == nil {
		return NumberOfMeasurementReportingLevelsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NumberOfMeasurementReportingLevelsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NumberOfMeasurementReportingLevelsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return NumberOfMeasurementReportingLevelsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c NumberOfMeasurementReportingLevelsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NumberOfMeasurementReportingLevelsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return NumberOfMeasurementReportingLevelsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return NumberOfMeasurementReportingLevelsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return NumberOfMeasurementReportingLevelsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return NumberOfMeasurementReportingLevelsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c NumberOfMeasurementReportingLevelsValueCodec) EncodeAPER(value NumberOfMeasurementReportingLevelsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NumberOfMeasurementReportingLevelsValueCodec) encodeBudgetValue(value s00.NumberOfMeasurementReportingLevels,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c NumberOfMeasurementReportingLevelsValueCodec) encodeChanged(value s00.NumberOfMeasurementReportingLevels,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// OldBSSToNewBSSInformationValueCodec is the concrete ValueCodec[OldBSSToNewBSSInformation].
type OldBSSToNewBSSInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.OldBSSToNewBSSInformation,

		error)
	encode func(s00.OldBSSToNewBSSInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.OldBSSToNewBSSInformation, aper.DecodeState,

	) (s00.OldBSSToNewBSSInformation, aper.Snapshot,

	)
	compare func(s00.OldBSSToNewBSSInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c OldBSSToNewBSSInformationValueCodec) New(value s00.OldBSSToNewBSSInformation,

) (OldBSSToNewBSSInformationAPERValue, error) {
	if c.encode == nil {
		return OldBSSToNewBSSInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OldBSSToNewBSSInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OldBSSToNewBSSInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return OldBSSToNewBSSInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c OldBSSToNewBSSInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OldBSSToNewBSSInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return OldBSSToNewBSSInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return OldBSSToNewBSSInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return OldBSSToNewBSSInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return OldBSSToNewBSSInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c OldBSSToNewBSSInformationValueCodec) EncodeAPER(value OldBSSToNewBSSInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OldBSSToNewBSSInformationValueCodec) encodeBudgetValue(value s00.OldBSSToNewBSSInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c OldBSSToNewBSSInformationValueCodec) encodeChanged(value s00.OldBSSToNewBSSInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// OverloadActionValueCodec is the concrete ValueCodec[OverloadAction].
type OverloadActionValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.OverloadAction,

		error)
	encode func(s00.OverloadAction,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.OverloadAction, aper.DecodeState,

	) (s00.OverloadAction, aper.Snapshot,

	)
	compare func(s00.OverloadAction, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c OverloadActionValueCodec) New(value s00.OverloadAction,

) (OverloadActionAPERValue, error) {
	if c.encode == nil {
		return OverloadActionAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OverloadActionAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OverloadActionAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return OverloadActionAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c OverloadActionValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OverloadActionAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return OverloadActionAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return OverloadActionAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return OverloadActionAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return OverloadActionAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c OverloadActionValueCodec) EncodeAPER(value OverloadActionAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OverloadActionValueCodec) encodeBudgetValue(value s00.OverloadAction,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c OverloadActionValueCodec) encodeChanged(value s00.OverloadAction,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// OverloadFlagValueCodec is the concrete ValueCodec[OverloadFlag].
type OverloadFlagValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.OverloadFlag,

		error)
	encode func(s00.OverloadFlag,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.OverloadFlag, aper.DecodeState,

	) (s00.OverloadFlag, aper.Snapshot,

	)
	compare func(s00.OverloadFlag, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c OverloadFlagValueCodec) New(value s00.OverloadFlag,

) (OverloadFlagAPERValue, error) {
	if c.encode == nil {
		return OverloadFlagAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OverloadFlagAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OverloadFlagAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return OverloadFlagAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c OverloadFlagValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OverloadFlagAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return OverloadFlagAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return OverloadFlagAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return OverloadFlagAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return OverloadFlagAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c OverloadFlagValueCodec) EncodeAPER(value OverloadFlagAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OverloadFlagValueCodec) encodeBudgetValue(value s00.OverloadFlag,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c OverloadFlagValueCodec) encodeChanged(value s00.OverloadFlag,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PDCPSNValueCodec is the concrete ValueCodec[PDCPSN].
type PDCPSNValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PDCPSN,

		error)
	encode func(s00.PDCPSN,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PDCPSN, aper.DecodeState,

	) (s00.PDCPSN, aper.Snapshot,

	)
	compare func(s00.PDCPSN, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PDCPSNValueCodec) New(value s00.PDCPSN,

) (PDCPSNAPERValue, error) {
	if c.encode == nil {
		return PDCPSNAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PDCPSNAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PDCPSNAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PDCPSNAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PDCPSNValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PDCPSNAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PDCPSNAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PDCPSNAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PDCPSNAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PDCPSNAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PDCPSNValueCodec) EncodeAPER(value PDCPSNAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PDCPSNValueCodec) encodeBudgetValue(value s00.PDCPSN,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PDCPSNValueCodec) encodeChanged(value s00.PDCPSN,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PDCPSNExtendedValueCodec is the concrete ValueCodec[PDCPSNExtended].
type PDCPSNExtendedValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PDCPSNExtended,

		error)
	encode func(s00.PDCPSNExtended,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PDCPSNExtended, aper.DecodeState,

	) (s00.PDCPSNExtended, aper.Snapshot,

	)
	compare func(s00.PDCPSNExtended, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PDCPSNExtendedValueCodec) New(value s00.PDCPSNExtended,

) (PDCPSNExtendedAPERValue, error) {
	if c.encode == nil {
		return PDCPSNExtendedAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PDCPSNExtendedAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PDCPSNExtendedAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PDCPSNExtendedAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PDCPSNExtendedValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PDCPSNExtendedAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PDCPSNExtendedAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PDCPSNExtendedAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PDCPSNExtendedAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PDCPSNExtendedAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PDCPSNExtendedValueCodec) EncodeAPER(value PDCPSNExtendedAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PDCPSNExtendedValueCodec) encodeBudgetValue(value s00.PDCPSNExtended,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PDCPSNExtendedValueCodec) encodeChanged(value s00.PDCPSNExtended,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PDCPSNlength18ValueCodec is the concrete ValueCodec[PDCPSNlength18].
type PDCPSNlength18ValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PDCPSNlength18,

		error)
	encode func(s00.PDCPSNlength18,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PDCPSNlength18, aper.DecodeState,

	) (s00.PDCPSNlength18, aper.Snapshot,

	)
	compare func(s00.PDCPSNlength18, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PDCPSNlength18ValueCodec) New(value s00.PDCPSNlength18,

) (PDCPSNlength18APERValue, error) {
	if c.encode == nil {
		return PDCPSNlength18APERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PDCPSNlength18APERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PDCPSNlength18APERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PDCPSNlength18APERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PDCPSNlength18ValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PDCPSNlength18APERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PDCPSNlength18APERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PDCPSNlength18APERValue{}, report, aper.OperationError(err, c.path)
		}
		return PDCPSNlength18APERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PDCPSNlength18APERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PDCPSNlength18ValueCodec) EncodeAPER(value PDCPSNlength18APERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PDCPSNlength18ValueCodec) encodeBudgetValue(value s00.PDCPSNlength18,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PDCPSNlength18ValueCodec) encodeChanged(value s00.PDCPSNlength18,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PLMNListforQMCValueCodec is the concrete ValueCodec[PLMNListforQMC].
type PLMNListforQMCValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PLMNListforQMC,

		error)
	encode func(s00.PLMNListforQMC,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PLMNListforQMC, aper.DecodeState,

	) (s00.PLMNListforQMC, aper.Snapshot,

	)
	compare func(s00.PLMNListforQMC, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PLMNListforQMCValueCodec) New(value s00.PLMNListforQMC,

) (PLMNListforQMCAPERValue, error) {
	if c.encode == nil {
		return PLMNListforQMCAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PLMNListforQMCAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PLMNListforQMCAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PLMNListforQMCAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PLMNListforQMCValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PLMNListforQMCAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PLMNListforQMCAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PLMNListforQMCAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PLMNListforQMCAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PLMNListforQMCAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PLMNListforQMCValueCodec) EncodeAPER(value PLMNListforQMCAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PLMNListforQMCValueCodec) encodeBudgetValue(value s00.PLMNListforQMC,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PLMNListforQMCValueCodec) encodeChanged(value s00.PLMNListforQMC,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingAttemptCountValueCodec is the concrete ValueCodec[PagingAttemptCount].
type PagingAttemptCountValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PagingAttemptCount,

		error)
	encode func(s00.PagingAttemptCount,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PagingAttemptCount, aper.DecodeState,

	) (s00.PagingAttemptCount, aper.Snapshot,

	)
	compare func(s00.PagingAttemptCount, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingAttemptCountValueCodec) New(value s00.PagingAttemptCount,

) (PagingAttemptCountAPERValue, error) {
	if c.encode == nil {
		return PagingAttemptCountAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingAttemptCountAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingAttemptCountAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingAttemptCountAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingAttemptCountValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingAttemptCountAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingAttemptCountAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingAttemptCountAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingAttemptCountAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingAttemptCountAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingAttemptCountValueCodec) EncodeAPER(value PagingAttemptCountAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PagingAttemptCountValueCodec) encodeBudgetValue(value s00.PagingAttemptCount,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingAttemptCountValueCodec) encodeChanged(value s00.PagingAttemptCount,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingEDRXCycleValueCodec is the concrete ValueCodec[PagingEDRXCycle].
type PagingEDRXCycleValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PagingEDRXCycle,

		error)
	encode func(s00.PagingEDRXCycle,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PagingEDRXCycle, aper.DecodeState,

	) (s00.PagingEDRXCycle, aper.Snapshot,

	)
	compare func(s00.PagingEDRXCycle, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingEDRXCycleValueCodec) New(value s00.PagingEDRXCycle,

) (PagingEDRXCycleAPERValue, error) {
	if c.encode == nil {
		return PagingEDRXCycleAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingEDRXCycleAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingEDRXCycleAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingEDRXCycleAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingEDRXCycleValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingEDRXCycleAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingEDRXCycleAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingEDRXCycleAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingEDRXCycleAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingEDRXCycleAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingEDRXCycleValueCodec) EncodeAPER(value PagingEDRXCycleAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PagingEDRXCycleValueCodec) encodeBudgetValue(value s00.PagingEDRXCycle,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingEDRXCycleValueCodec) encodeChanged(value s00.PagingEDRXCycle,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingProbabilityInformationValueCodec is the concrete ValueCodec[PagingProbabilityInformation].
type PagingProbabilityInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PagingProbabilityInformation,

		error)
	encode func(s00.PagingProbabilityInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PagingProbabilityInformation, aper.DecodeState,

	) (s00.PagingProbabilityInformation, aper.Snapshot,

	)
	compare func(s00.PagingProbabilityInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingProbabilityInformationValueCodec) New(value s00.PagingProbabilityInformation,

) (PagingProbabilityInformationAPERValue, error) {
	if c.encode == nil {
		return PagingProbabilityInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingProbabilityInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingProbabilityInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingProbabilityInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingProbabilityInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingProbabilityInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingProbabilityInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingProbabilityInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingProbabilityInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingProbabilityInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingProbabilityInformationValueCodec) EncodeAPER(value PagingProbabilityInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PagingProbabilityInformationValueCodec) encodeBudgetValue(value s00.PagingProbabilityInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingProbabilityInformationValueCodec) encodeChanged(value s00.PagingProbabilityInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PagingTimeWindowValueCodec is the concrete ValueCodec[PagingTimeWindow].
type PagingTimeWindowValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PagingTimeWindow,

		error)
	encode func(s00.PagingTimeWindow,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PagingTimeWindow, aper.DecodeState,

	) (s00.PagingTimeWindow, aper.Snapshot,

	)
	compare func(s00.PagingTimeWindow, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PagingTimeWindowValueCodec) New(value s00.PagingTimeWindow,

) (PagingTimeWindowAPERValue, error) {
	if c.encode == nil {
		return PagingTimeWindowAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PagingTimeWindowAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PagingTimeWindowAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PagingTimeWindowAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PagingTimeWindowValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PagingTimeWindowAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PagingTimeWindowAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PagingTimeWindowAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PagingTimeWindowAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PagingTimeWindowAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PagingTimeWindowValueCodec) EncodeAPER(value PagingTimeWindowAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PagingTimeWindowValueCodec) encodeBudgetValue(value s00.PagingTimeWindow,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PagingTimeWindowValueCodec) encodeChanged(value s00.PagingTimeWindow,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PedestrianUEValueCodec is the concrete ValueCodec[PedestrianUE].
type PedestrianUEValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PedestrianUE,

		error)
	encode func(s00.PedestrianUE,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PedestrianUE, aper.DecodeState,

	) (s00.PedestrianUE, aper.Snapshot,

	)
	compare func(s00.PedestrianUE, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PedestrianUEValueCodec) New(value s00.PedestrianUE,

) (PedestrianUEAPERValue, error) {
	if c.encode == nil {
		return PedestrianUEAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PedestrianUEAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PedestrianUEAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PedestrianUEAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PedestrianUEValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PedestrianUEAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PedestrianUEAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PedestrianUEAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PedestrianUEAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PedestrianUEAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PedestrianUEValueCodec) EncodeAPER(value PedestrianUEAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PedestrianUEValueCodec) encodeBudgetValue(value s00.PedestrianUE,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PedestrianUEValueCodec) encodeChanged(value s00.PedestrianUE,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PortNumberValueCodec is the concrete ValueCodec[PortNumber].
type PortNumberValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PortNumber,

		error)
	encode func(s00.PortNumber,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PortNumber, aper.DecodeState,

	) (s00.PortNumber, aper.Snapshot,

	)
	compare func(s00.PortNumber, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PortNumberValueCodec) New(value s00.PortNumber,

) (PortNumberAPERValue, error) {
	if c.encode == nil {
		return PortNumberAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PortNumberAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PortNumberAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PortNumberAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PortNumberValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PortNumberAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PortNumberAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PortNumberAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PortNumberAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PortNumberAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PortNumberValueCodec) EncodeAPER(value PortNumberAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PortNumberValueCodec) encodeBudgetValue(value s00.PortNumber,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PortNumberValueCodec) encodeChanged(value s00.PortNumber,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PreEmptionCapabilityValueCodec is the concrete ValueCodec[PreEmptionCapability].
type PreEmptionCapabilityValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PreEmptionCapability,

		error)
	encode func(s00.PreEmptionCapability,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PreEmptionCapability, aper.DecodeState,

	) (s00.PreEmptionCapability, aper.Snapshot,

	)
	compare func(s00.PreEmptionCapability, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PreEmptionCapabilityValueCodec) New(value s00.PreEmptionCapability,

) (PreEmptionCapabilityAPERValue, error) {
	if c.encode == nil {
		return PreEmptionCapabilityAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PreEmptionCapabilityAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PreEmptionCapabilityAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PreEmptionCapabilityAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PreEmptionCapabilityValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PreEmptionCapabilityAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PreEmptionCapabilityAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PreEmptionCapabilityAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PreEmptionCapabilityAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PreEmptionCapabilityAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PreEmptionCapabilityValueCodec) EncodeAPER(value PreEmptionCapabilityAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PreEmptionCapabilityValueCodec) encodeBudgetValue(value s00.PreEmptionCapability,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PreEmptionCapabilityValueCodec) encodeChanged(value s00.PreEmptionCapability,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PreEmptionVulnerabilityValueCodec is the concrete ValueCodec[PreEmptionVulnerability].
type PreEmptionVulnerabilityValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PreEmptionVulnerability,

		error)
	encode func(s00.PreEmptionVulnerability,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PreEmptionVulnerability, aper.DecodeState,

	) (s00.PreEmptionVulnerability, aper.Snapshot,

	)
	compare func(s00.PreEmptionVulnerability, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PreEmptionVulnerabilityValueCodec) New(value s00.PreEmptionVulnerability,

) (PreEmptionVulnerabilityAPERValue, error) {
	if c.encode == nil {
		return PreEmptionVulnerabilityAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PreEmptionVulnerabilityAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PreEmptionVulnerabilityAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PreEmptionVulnerabilityAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PreEmptionVulnerabilityValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PreEmptionVulnerabilityAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PreEmptionVulnerabilityAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PreEmptionVulnerabilityAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PreEmptionVulnerabilityAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PreEmptionVulnerabilityAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PreEmptionVulnerabilityValueCodec) EncodeAPER(value PreEmptionVulnerabilityAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PreEmptionVulnerabilityValueCodec) encodeBudgetValue(value s00.PreEmptionVulnerability,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PreEmptionVulnerabilityValueCodec) encodeChanged(value s00.PreEmptionVulnerability,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PresenceValueCodec is the concrete ValueCodec[Presence].
type PresenceValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.Presence,

		error)
	encode func(s00.Presence,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.Presence, aper.DecodeState,

	) (s00.Presence, aper.Snapshot,

	)
	compare func(s00.Presence, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PresenceValueCodec) New(value s00.Presence,

) (PresenceAPERValue, error) {
	if c.encode == nil {
		return PresenceAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PresenceAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PresenceAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PresenceAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PresenceValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PresenceAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PresenceAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PresenceAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PresenceAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PresenceAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PresenceValueCodec) EncodeAPER(value PresenceAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PresenceValueCodec) encodeBudgetValue(value s00.Presence,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PresenceValueCodec) encodeChanged(value s00.Presence,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// PriorityLevelValueCodec is the concrete ValueCodec[PriorityLevel].
type PriorityLevelValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.PriorityLevel,

		error)
	encode func(s00.PriorityLevel,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.PriorityLevel, aper.DecodeState,

	) (s00.PriorityLevel, aper.Snapshot,

	)
	compare func(s00.PriorityLevel, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c PriorityLevelValueCodec) New(value s00.PriorityLevel,

) (PriorityLevelAPERValue, error) {
	if c.encode == nil {
		return PriorityLevelAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PriorityLevelAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PriorityLevelAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return PriorityLevelAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c PriorityLevelValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PriorityLevelAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return PriorityLevelAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return PriorityLevelAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return PriorityLevelAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return PriorityLevelAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c PriorityLevelValueCodec) EncodeAPER(value PriorityLevelAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PriorityLevelValueCodec) encodeBudgetValue(value s00.PriorityLevel,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c PriorityLevelValueCodec) encodeChanged(value s00.PriorityLevel,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ProSeDirectCommunicationValueCodec is the concrete ValueCodec[ProSeDirectCommunication].
type ProSeDirectCommunicationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ProSeDirectCommunication,

		error)
	encode func(s00.ProSeDirectCommunication,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ProSeDirectCommunication, aper.DecodeState,

	) (s00.ProSeDirectCommunication, aper.Snapshot,

	)
	compare func(s00.ProSeDirectCommunication, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ProSeDirectCommunicationValueCodec) New(value s00.ProSeDirectCommunication,

) (ProSeDirectCommunicationAPERValue, error) {
	if c.encode == nil {
		return ProSeDirectCommunicationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ProSeDirectCommunicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ProSeDirectCommunicationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ProSeDirectCommunicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ProSeDirectCommunicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ProSeDirectCommunicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ProSeDirectCommunicationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ProSeDirectCommunicationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ProSeDirectCommunicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ProSeDirectCommunicationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ProSeDirectCommunicationValueCodec) EncodeAPER(value ProSeDirectCommunicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ProSeDirectCommunicationValueCodec) encodeBudgetValue(value s00.ProSeDirectCommunication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ProSeDirectCommunicationValueCodec) encodeChanged(value s00.ProSeDirectCommunication,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ProSeDirectDiscoveryValueCodec is the concrete ValueCodec[ProSeDirectDiscovery].
type ProSeDirectDiscoveryValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ProSeDirectDiscovery,

		error)
	encode func(s00.ProSeDirectDiscovery,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ProSeDirectDiscovery, aper.DecodeState,

	) (s00.ProSeDirectDiscovery, aper.Snapshot,

	)
	compare func(s00.ProSeDirectDiscovery, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ProSeDirectDiscoveryValueCodec) New(value s00.ProSeDirectDiscovery,

) (ProSeDirectDiscoveryAPERValue, error) {
	if c.encode == nil {
		return ProSeDirectDiscoveryAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ProSeDirectDiscoveryAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ProSeDirectDiscoveryAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ProSeDirectDiscoveryAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ProSeDirectDiscoveryValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ProSeDirectDiscoveryAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ProSeDirectDiscoveryAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ProSeDirectDiscoveryAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ProSeDirectDiscoveryAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ProSeDirectDiscoveryAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ProSeDirectDiscoveryValueCodec) EncodeAPER(value ProSeDirectDiscoveryAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ProSeDirectDiscoveryValueCodec) encodeBudgetValue(value s00.ProSeDirectDiscovery,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ProSeDirectDiscoveryValueCodec) encodeChanged(value s00.ProSeDirectDiscovery,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ProcedureCodeValueCodec is the concrete ValueCodec[ProcedureCode].
type ProcedureCodeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ProcedureCode,

		error)
	encode func(s00.ProcedureCode,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ProcedureCode, aper.DecodeState,

	) (s00.ProcedureCode, aper.Snapshot,

	)
	compare func(s00.ProcedureCode, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ProcedureCodeValueCodec) New(value s00.ProcedureCode,

) (ProcedureCodeAPERValue, error) {
	if c.encode == nil {
		return ProcedureCodeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ProcedureCodeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ProcedureCodeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ProcedureCodeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ProcedureCodeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ProcedureCodeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ProcedureCodeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ProcedureCodeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ProcedureCodeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ProcedureCodeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ProcedureCodeValueCodec) EncodeAPER(value ProcedureCodeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ProcedureCodeValueCodec) encodeBudgetValue(value s00.ProcedureCode,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ProcedureCodeValueCodec) encodeChanged(value s00.ProcedureCode,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ProtocolExtensionIDValueCodec is the concrete ValueCodec[ProtocolExtensionID].
type ProtocolExtensionIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ProtocolExtensionID,

		error)
	encode func(s00.ProtocolExtensionID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ProtocolExtensionID, aper.DecodeState,

	) (s00.ProtocolExtensionID, aper.Snapshot,

	)
	compare func(s00.ProtocolExtensionID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ProtocolExtensionIDValueCodec) New(value s00.ProtocolExtensionID,

) (ProtocolExtensionIDAPERValue, error) {
	if c.encode == nil {
		return ProtocolExtensionIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ProtocolExtensionIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ProtocolExtensionIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ProtocolExtensionIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ProtocolExtensionIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ProtocolExtensionIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ProtocolExtensionIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ProtocolExtensionIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ProtocolExtensionIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ProtocolExtensionIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ProtocolExtensionIDValueCodec) EncodeAPER(value ProtocolExtensionIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ProtocolExtensionIDValueCodec) encodeBudgetValue(value s00.ProtocolExtensionID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ProtocolExtensionIDValueCodec) encodeChanged(value s00.ProtocolExtensionID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ProtocolIEIDValueCodec is the concrete ValueCodec[ProtocolIEID].
type ProtocolIEIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ProtocolIEID,

		error)
	encode func(s00.ProtocolIEID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ProtocolIEID, aper.DecodeState,

	) (s00.ProtocolIEID, aper.Snapshot,

	)
	compare func(s00.ProtocolIEID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ProtocolIEIDValueCodec) New(value s00.ProtocolIEID,

) (ProtocolIEIDAPERValue, error) {
	if c.encode == nil {
		return ProtocolIEIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ProtocolIEIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ProtocolIEIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ProtocolIEIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ProtocolIEIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ProtocolIEIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ProtocolIEIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ProtocolIEIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ProtocolIEIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ProtocolIEIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ProtocolIEIDValueCodec) EncodeAPER(value ProtocolIEIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ProtocolIEIDValueCodec) encodeBudgetValue(value s00.ProtocolIEID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ProtocolIEIDValueCodec) encodeChanged(value s00.ProtocolIEID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// QCIValueCodec is the concrete ValueCodec[QCI].
type QCIValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.QCI,

		error)
	encode func(s00.QCI,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.QCI, aper.DecodeState,

	) (s00.QCI, aper.Snapshot,

	)
	compare func(s00.QCI, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c QCIValueCodec) New(value s00.QCI,

) (QCIAPERValue, error) {
	if c.encode == nil {
		return QCIAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return QCIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return QCIAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return QCIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c QCIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (QCIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return QCIAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return QCIAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return QCIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return QCIAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c QCIValueCodec) EncodeAPER(value QCIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c QCIValueCodec) encodeBudgetValue(value s00.QCI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c QCIValueCodec) encodeChanged(value s00.QCI,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RACValueCodec is the concrete ValueCodec[RAC].
type RACValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.RAC,

		error)
	encode func(s00.RAC,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.RAC, aper.DecodeState,

	) (s00.RAC, aper.Snapshot,

	)
	compare func(s00.RAC, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RACValueCodec) New(value s00.RAC,

) (RACAPERValue, error) {
	if c.encode == nil {
		return RACAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RACAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RACAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RACAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RACValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RACAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RACAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RACAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RACAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RACAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RACValueCodec) EncodeAPER(value RACAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RACValueCodec) encodeBudgetValue(value s00.RAC,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RACValueCodec) encodeChanged(value s00.RAC,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RANUENGAPIDValueCodec is the concrete ValueCodec[RANUENGAPID].
type RANUENGAPIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.RANUENGAPID,

		error)
	encode func(s00.RANUENGAPID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.RANUENGAPID, aper.DecodeState,

	) (s00.RANUENGAPID, aper.Snapshot,

	)
	compare func(s00.RANUENGAPID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RANUENGAPIDValueCodec) New(value s00.RANUENGAPID,

) (RANUENGAPIDAPERValue, error) {
	if c.encode == nil {
		return RANUENGAPIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RANUENGAPIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RANUENGAPIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RANUENGAPIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RANUENGAPIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RANUENGAPIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RANUENGAPIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RANUENGAPIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RANUENGAPIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RANUENGAPIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RANUENGAPIDValueCodec) EncodeAPER(value RANUENGAPIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RANUENGAPIDValueCodec) encodeBudgetValue(value s00.RANUENGAPID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RANUENGAPIDValueCodec) encodeChanged(value s00.RANUENGAPID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RIMInformationValueCodec is the concrete ValueCodec[RIMInformation].
type RIMInformationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.RIMInformation,

		error)
	encode func(s00.RIMInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.RIMInformation, aper.DecodeState,

	) (s00.RIMInformation, aper.Snapshot,

	)
	compare func(s00.RIMInformation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RIMInformationValueCodec) New(value s00.RIMInformation,

) (RIMInformationAPERValue, error) {
	if c.encode == nil {
		return RIMInformationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RIMInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RIMInformationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RIMInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RIMInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RIMInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RIMInformationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RIMInformationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RIMInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RIMInformationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RIMInformationValueCodec) EncodeAPER(value RIMInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RIMInformationValueCodec) encodeBudgetValue(value s00.RIMInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RIMInformationValueCodec) encodeChanged(value s00.RIMInformation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RNCIDValueCodec is the concrete ValueCodec[RNCID].
type RNCIDValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.RNCID,

		error)
	encode func(s00.RNCID,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.RNCID, aper.DecodeState,

	) (s00.RNCID, aper.Snapshot,

	)
	compare func(s00.RNCID, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RNCIDValueCodec) New(value s00.RNCID,

) (RNCIDAPERValue, error) {
	if c.encode == nil {
		return RNCIDAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RNCIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RNCIDAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RNCIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RNCIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RNCIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RNCIDAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RNCIDAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RNCIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RNCIDAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RNCIDValueCodec) EncodeAPER(value RNCIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RNCIDValueCodec) encodeBudgetValue(value s00.RNCID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RNCIDValueCodec) encodeChanged(value s00.RNCID,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RRCContainerValueCodec is the concrete ValueCodec[RRCContainer].
type RRCContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.RRCContainer,

		error)
	encode func(s00.RRCContainer,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.RRCContainer, aper.DecodeState,

	) (s00.RRCContainer, aper.Snapshot,

	)
	compare func(s00.RRCContainer, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RRCContainerValueCodec) New(value s00.RRCContainer,

) (RRCContainerAPERValue, error) {
	if c.encode == nil {
		return RRCContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RRCContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RRCContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RRCContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RRCContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RRCContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RRCContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RRCContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RRCContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RRCContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RRCContainerValueCodec) EncodeAPER(value RRCContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RRCContainerValueCodec) encodeBudgetValue(value s00.RRCContainer,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RRCContainerValueCodec) encodeChanged(value s00.RRCContainer,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// RangeValueCodec is the concrete ValueCodec[Range].
type RangeValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.Range,

		error)
	encode func(s00.Range,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.Range, aper.DecodeState,

	) (s00.Range, aper.Snapshot,

	)
	compare func(s00.Range, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c RangeValueCodec) New(value s00.Range,

) (RangeAPERValue, error) {
	if c.encode == nil {
		return RangeAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RangeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RangeAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return RangeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c RangeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RangeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return RangeAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return RangeAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return RangeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return RangeAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c RangeValueCodec) EncodeAPER(value RangeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RangeValueCodec) encodeBudgetValue(value s00.Range,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c RangeValueCodec) encodeChanged(value s00.Range,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ReceiveStatusofULPDCPSDUsValueCodec is the concrete ValueCodec[ReceiveStatusofULPDCPSDUs].
type ReceiveStatusofULPDCPSDUsValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s00.ReceiveStatusofULPDCPSDUs,

		error)
	encode func(s00.ReceiveStatusofULPDCPSDUs,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s00.ReceiveStatusofULPDCPSDUs, aper.DecodeState,

	) (s00.ReceiveStatusofULPDCPSDUs, aper.Snapshot,

	)
	compare func(s00.ReceiveStatusofULPDCPSDUs, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c ReceiveStatusofULPDCPSDUsValueCodec) New(value s00.ReceiveStatusofULPDCPSDUs,

) (ReceiveStatusofULPDCPSDUsAPERValue, error) {
	if c.encode == nil {
		return ReceiveStatusofULPDCPSDUsAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ReceiveStatusofULPDCPSDUsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ReceiveStatusofULPDCPSDUsAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return ReceiveStatusofULPDCPSDUsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c ReceiveStatusofULPDCPSDUsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ReceiveStatusofULPDCPSDUsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return ReceiveStatusofULPDCPSDUsAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return ReceiveStatusofULPDCPSDUsAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return ReceiveStatusofULPDCPSDUsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return ReceiveStatusofULPDCPSDUsAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c ReceiveStatusofULPDCPSDUsValueCodec) EncodeAPER(value ReceiveStatusofULPDCPSDUsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ReceiveStatusofULPDCPSDUsValueCodec) encodeBudgetValue(value s00.ReceiveStatusofULPDCPSDUs,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c ReceiveStatusofULPDCPSDUsValueCodec) encodeChanged(value s00.ReceiveStatusofULPDCPSDUs,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// ReceiveStatusOfULPDCPSDUsExtendedAPERValue is the concrete APERValue[ReceiveStatusOfULPDCPSDUsExtended].
type ReceiveStatusOfULPDCPSDUsExtendedAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ReceiveStatusOfULPDCPSDUsExtended

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ReceiveStatusOfULPDCPSDUsExtendedAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ReceiveStatusOfULPDCPSDUsExtendedAPERValue) WithoutReplay() ReceiveStatusOfULPDCPSDUsExtendedAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ReceiveStatusOfULPDCPSDUsPDCPSNlength18APERValue is the concrete APERValue[ReceiveStatusOfULPDCPSDUsPDCPSNlength18].
type ReceiveStatusOfULPDCPSDUsPDCPSNlength18APERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ReceiveStatusOfULPDCPSDUsPDCPSNlength18APERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ReceiveStatusOfULPDCPSDUsPDCPSNlength18APERValue) WithoutReplay() ReceiveStatusOfULPDCPSDUsPDCPSNlength18APERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PacketLossRateAPERValue is the concrete APERValue[PacketLossRate].
type PacketLossRateAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PacketLossRate

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PacketLossRateAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PacketLossRateAPERValue) WithoutReplay() PacketLossRateAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRrestrictioninEPSasSecondaryRATAPERValue is the concrete APERValue[NRrestrictioninEPSasSecondaryRAT].
type NRrestrictioninEPSasSecondaryRATAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NRrestrictioninEPSasSecondaryRAT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NRrestrictioninEPSasSecondaryRATAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRrestrictioninEPSasSecondaryRATAPERValue) WithoutReplay() NRrestrictioninEPSasSecondaryRATAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRrestrictionin5GSAPERValue is the concrete APERValue[NRrestrictionin5GS].
type NRrestrictionin5GSAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NRrestrictionin5GS

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NRrestrictionin5GSAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRrestrictionin5GSAPERValue) WithoutReplay() NRrestrictionin5GSAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PLMNidentityAPERValue is the concrete APERValue[PLMNidentity].
type PLMNidentityAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PLMNidentity

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PLMNidentityAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PLMNidentityAPERValue) WithoutReplay() PLMNidentityAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MDTLocationInfoAPERValue is the concrete APERValue[MDTLocationInfo].
type MDTLocationInfoAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.MDTLocationInfo

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MDTLocationInfoAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTLocationInfoAPERValue) WithoutReplay() MDTLocationInfoAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M4ReportAmountMDTAPERValue is the concrete APERValue[M4ReportAmountMDT].
type M4ReportAmountMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.M4ReportAmountMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M4ReportAmountMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M4ReportAmountMDTAPERValue) WithoutReplay() M4ReportAmountMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M5ReportAmountMDTAPERValue is the concrete APERValue[M5ReportAmountMDT].
type M5ReportAmountMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.M5ReportAmountMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M5ReportAmountMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M5ReportAmountMDTAPERValue) WithoutReplay() M5ReportAmountMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M6ReportAmountMDTAPERValue is the concrete APERValue[M6ReportAmountMDT].
type M6ReportAmountMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.M6ReportAmountMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M6ReportAmountMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M6ReportAmountMDTAPERValue) WithoutReplay() M6ReportAmountMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M7ReportAmountMDTAPERValue is the concrete APERValue[M7ReportAmountMDT].
type M7ReportAmountMDTAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.M7ReportAmountMDT

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M7ReportAmountMDTAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M7ReportAmountMDTAPERValue) WithoutReplay() M7ReportAmountMDTAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MDTPLMNListAPERValue is the concrete APERValue[MDTPLMNList].
type MDTPLMNListAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.MDTPLMNList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MDTPLMNListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTPLMNListAPERValue) WithoutReplay() MDTPLMNListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ProSeUEtoNetworkRelayingAPERValue is the concrete APERValue[ProSeUEtoNetworkRelaying].
type ProSeUEtoNetworkRelayingAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ProSeUEtoNetworkRelaying

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ProSeUEtoNetworkRelayingAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ProSeUEtoNetworkRelayingAPERValue) WithoutReplay() ProSeUEtoNetworkRelayingAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NBIoTRLFReportContainerAPERValue is the concrete APERValue[NBIoTRLFReportContainer].
type NBIoTRLFReportContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NBIoTRLFReportContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NBIoTRLFReportContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NBIoTRLFReportContainerAPERValue) WithoutReplay() NBIoTRLFReportContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GUMMEITypeAPERValue is the concrete APERValue[GUMMEIType].
type GUMMEITypeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.GUMMEIType

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GUMMEITypeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GUMMEITypeAPERValue) WithoutReplay() GUMMEITypeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// IMSvoiceEPSfallbackfrom5GAPERValue is the concrete APERValue[IMSvoiceEPSfallbackfrom5G].
type IMSvoiceEPSfallbackfrom5GAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.IMSvoiceEPSfallbackfrom5G

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v IMSvoiceEPSfallbackfrom5GAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v IMSvoiceEPSfallbackfrom5GAPERValue) WithoutReplay() IMSvoiceEPSfallbackfrom5GAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RATTypeAPERValue is the concrete APERValue[RATType].
type RATTypeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.RATType

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RATTypeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RATTypeAPERValue) WithoutReplay() RATTypeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RACSIndicationAPERValue is the concrete APERValue[RACSIndication].
type RACSIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.RACSIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RACSIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RACSIndicationAPERValue) WithoutReplay() RACSIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MutingAvailabilityIndicationAPERValue is the concrete APERValue[MutingAvailabilityIndication].
type MutingAvailabilityIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.MutingAvailabilityIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MutingAvailabilityIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MutingAvailabilityIndicationAPERValue) WithoutReplay() MutingAvailabilityIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MDTConfigurationNRAPERValue is the concrete APERValue[MDTConfigurationNR].
type MDTConfigurationNRAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.MDTConfigurationNR

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MDTConfigurationNRAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTConfigurationNRAPERValue) WithoutReplay() MDTConfigurationNRAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEUES1APIDAPERValue is the concrete APERValue[MMEUES1APID].
type MMEUES1APIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.MMEUES1APID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEUES1APIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEUES1APIDAPERValue) WithoutReplay() MMEUES1APIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PrivacyIndicatorAPERValue is the concrete APERValue[PrivacyIndicator].
type PrivacyIndicatorAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PrivacyIndicator

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PrivacyIndicatorAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PrivacyIndicatorAPERValue) WithoutReplay() PrivacyIndicatorAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MaskedIMEISVAPERValue is the concrete APERValue[MaskedIMEISV].
type MaskedIMEISVAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.MaskedIMEISV

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MaskedIMEISVAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MaskedIMEISVAPERValue) WithoutReplay() MaskedIMEISVAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NASPDUAPERValue is the concrete APERValue[NASPDU].
type NASPDUAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NASPDU

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NASPDUAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NASPDUAPERValue) WithoutReplay() NASPDUAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PendingDataIndicationAPERValue is the concrete APERValue[PendingDataIndication].
type PendingDataIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PendingDataIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PendingDataIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PendingDataIndicationAPERValue) WithoutReplay() PendingDataIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LPPaPDUAPERValue is the concrete APERValue[LPPaPDU].
type LPPaPDUAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.LPPaPDU

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LPPaPDUAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LPPaPDUAPERValue) WithoutReplay() LPPaPDUAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// IntersystemSONConfigurationTransferAPERValue is the concrete APERValue[IntersystemSONConfigurationTransfer].
type IntersystemSONConfigurationTransferAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.IntersystemSONConfigurationTransfer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v IntersystemSONConfigurationTransferAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v IntersystemSONConfigurationTransferAPERValue) WithoutReplay() IntersystemSONConfigurationTransferAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingDRXAPERValue is the concrete APERValue[PagingDRX].
type PagingDRXAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PagingDRX

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingDRXAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingDRXAPERValue) WithoutReplay() PagingDRXAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NBIoTDefaultPagingDRXAPERValue is the concrete APERValue[NBIoTDefaultPagingDRX].
type NBIoTDefaultPagingDRXAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NBIoTDefaultPagingDRX

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NBIoTDefaultPagingDRXAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NBIoTDefaultPagingDRXAPERValue) WithoutReplay() NBIoTDefaultPagingDRXAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverTypeAPERValue is the concrete APERValue[HandoverType].
type HandoverTypeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.HandoverType

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverTypeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverTypeAPERValue) WithoutReplay() HandoverTypeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NASSecurityParametersfromEUTRANAPERValue is the concrete APERValue[NASSecurityParametersfromEUTRAN].
type NASSecurityParametersfromEUTRANAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NASSecurityParametersfromEUTRAN

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NASSecurityParametersfromEUTRANAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NASSecurityParametersfromEUTRANAPERValue) WithoutReplay() NASSecurityParametersfromEUTRANAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LHNIDAPERValue is the concrete APERValue[LHNID].
type LHNIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.LHNID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LHNIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LHNIDAPERValue) WithoutReplay() LHNIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NotifySourceeNBAPERValue is the concrete APERValue[NotifySourceeNB].
type NotifySourceeNBAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NotifySourceeNB

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NotifySourceeNBAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NotifySourceeNBAPERValue) WithoutReplay() NotifySourceeNBAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NASSecurityParameterstoEUTRANAPERValue is the concrete APERValue[NASSecurityParameterstoEUTRAN].
type NASSecurityParameterstoEUTRANAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NASSecurityParameterstoEUTRAN

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NASSecurityParameterstoEUTRANAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NASSecurityParameterstoEUTRANAPERValue) WithoutReplay() NASSecurityParameterstoEUTRANAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ManagementBasedMDTAllowedAPERValue is the concrete APERValue[ManagementBasedMDTAllowed].
type ManagementBasedMDTAllowedAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ManagementBasedMDTAllowed

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ManagementBasedMDTAllowedAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ManagementBasedMDTAllowedAPERValue) WithoutReplay() ManagementBasedMDTAllowedAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// IABAuthorizedAPERValue is the concrete APERValue[IABAuthorized].
type IABAuthorizedAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.IABAuthorized

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v IABAuthorizedAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v IABAuthorizedAPERValue) WithoutReplay() IABAuthorizedAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MSClassmark2APERValue is the concrete APERValue[MSClassmark2].
type MSClassmark2APERValue struct {
	context s00.BridgeCodecContext
	Value   s00.MSClassmark2

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MSClassmark2APERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MSClassmark2APERValue) WithoutReplay() MSClassmark2APERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MSClassmark3APERValue is the concrete APERValue[MSClassmark3].
type MSClassmark3APERValue struct {
	context s00.BridgeCodecContext
	Value   s00.MSClassmark3

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MSClassmark3APERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MSClassmark3APERValue) WithoutReplay() MSClassmark3APERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PSServiceNotAvailableAPERValue is the concrete APERValue[PSServiceNotAvailable].
type PSServiceNotAvailableAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PSServiceNotAvailable

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PSServiceNotAvailableAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PSServiceNotAvailableAPERValue) WithoutReplay() PSServiceNotAvailableAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RRCEstablishmentCauseAPERValue is the concrete APERValue[RRCEstablishmentCause].
type RRCEstablishmentCauseAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.RRCEstablishmentCause

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RRCEstablishmentCauseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RRCEstablishmentCauseAPERValue) WithoutReplay() RRCEstablishmentCauseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEGroupIDAPERValue is the concrete APERValue[MMEGroupID].
type MMEGroupIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.MMEGroupID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEGroupIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEGroupIDAPERValue) WithoutReplay() MMEGroupIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// IABNodeIndicationAPERValue is the concrete APERValue[IABNodeIndication].
type IABNodeIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.IABNodeIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v IABNodeIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v IABNodeIndicationAPERValue) WithoutReplay() IABNodeIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MessageIdentifierAPERValue is the concrete APERValue[MessageIdentifier].
type MessageIdentifierAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.MessageIdentifier

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MessageIdentifierAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MessageIdentifierAPERValue) WithoutReplay() MessageIdentifierAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// KillAllWarningMessagesAPERValue is the concrete APERValue[KillAllWarningMessages].
type KillAllWarningMessagesAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.KillAllWarningMessages

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v KillAllWarningMessagesAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v KillAllWarningMessagesAPERValue) WithoutReplay() KillAllWarningMessagesAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMEnameAPERValue is the concrete APERValue[MMEname].
type MMEnameAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.MMEname

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMEnameAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMEnameAPERValue) WithoutReplay() MMEnameAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingPriorityAPERValue is the concrete APERValue[PagingPriority].
type PagingPriorityAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PagingPriority

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingPriorityAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingPriorityAPERValue) WithoutReplay() PagingPriorityAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NBIoTUEIdentityIndexValueAPERValue is the concrete APERValue[NBIoTUEIdentityIndexValue].
type NBIoTUEIdentityIndexValueAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NBIoTUEIdentityIndexValue

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NBIoTUEIdentityIndexValueAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NBIoTUEIdentityIndexValueAPERValue) WithoutReplay() NBIoTUEIdentityIndexValueAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NBIoTPagingDRXAPERValue is the concrete APERValue[NBIoTPagingDRX].
type NBIoTPagingDRXAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NBIoTPagingDRX

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NBIoTPagingDRXAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NBIoTPagingDRXAPERValue) WithoutReplay() NBIoTPagingDRXAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingCauseAPERValue is the concrete APERValue[PagingCause].
type PagingCauseAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PagingCause

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingCauseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingCauseAPERValue) WithoutReplay() PagingCauseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMERelaySupportIndicatorAPERValue is the concrete APERValue[MMERelaySupportIndicator].
type MMERelaySupportIndicatorAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.MMERelaySupportIndicator

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMERelaySupportIndicatorAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMERelaySupportIndicatorAPERValue) WithoutReplay() MMERelaySupportIndicatorAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// IABSupportedAPERValue is the concrete APERValue[IABSupported].
type IABSupportedAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.IABSupported

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v IABSupportedAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v IABSupportedAPERValue) WithoutReplay() IABSupportedAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverFlagAPERValue is the concrete APERValue[HandoverFlag].
type HandoverFlagAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.HandoverFlag

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverFlagAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverFlagAPERValue) WithoutReplay() HandoverFlagAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LTEMIndicationAPERValue is the concrete APERValue[LTEMIndication].
type LTEMIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.LTEMIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LTEMIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LTEMIndicationAPERValue) WithoutReplay() LTEMIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GWContextReleaseIndicationAPERValue is the concrete APERValue[GWContextReleaseIndication].
type GWContextReleaseIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.GWContextReleaseIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GWContextReleaseIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GWContextReleaseIndicationAPERValue) WithoutReplay() GWContextReleaseIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NumberofBroadcastRequestAPERValue is the concrete APERValue[NumberofBroadcastRequest].
type NumberofBroadcastRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NumberofBroadcastRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NumberofBroadcastRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NumberofBroadcastRequestAPERValue) WithoutReplay() NumberofBroadcastRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// FailureEventReportingCauseAPERValue is the concrete APERValue[FailureEventReportingCause].
type FailureEventReportingCauseAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.FailureEventReportingCause

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v FailureEventReportingCauseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v FailureEventReportingCauseAPERValue) WithoutReplay() FailureEventReportingCauseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// FiveGSTACAPERValue is the concrete APERValue[FiveGSTAC].
type FiveGSTACAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.FiveGSTAC

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v FiveGSTACAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v FiveGSTACAPERValue) WithoutReplay() FiveGSTACAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// FiveQIAPERValue is the concrete APERValue[FiveQI].
type FiveQIAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.FiveQI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v FiveQIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v FiveQIAPERValue) WithoutReplay() FiveQIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ForbiddenInterRATsAPERValue is the concrete APERValue[ForbiddenInterRATs].
type ForbiddenInterRATsAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ForbiddenInterRATs

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ForbiddenInterRATsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ForbiddenInterRATsAPERValue) WithoutReplay() ForbiddenInterRATsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ForbiddenLACsAPERValue is the concrete APERValue[ForbiddenLACs].
type ForbiddenLACsAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ForbiddenLACs

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ForbiddenLACsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ForbiddenLACsAPERValue) WithoutReplay() ForbiddenLACsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ForbiddenTACsAPERValue is the concrete APERValue[ForbiddenTACs].
type ForbiddenTACsAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ForbiddenTACs

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ForbiddenTACsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ForbiddenTACsAPERValue) WithoutReplay() ForbiddenTACsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GNBIDAPERValue is the concrete APERValue[GNBID].
type GNBIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.GNBID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GNBIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GNBIDAPERValue) WithoutReplay() GNBIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// GTPTEIDAPERValue is the concrete APERValue[GTPTEID].
type GTPTEIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.GTPTEID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v GTPTEIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v GTPTEIDAPERValue) WithoutReplay() GTPTEIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HFNAPERValue is the concrete APERValue[HFN].
type HFNAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.HFN

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HFNAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HFNAPERValue) WithoutReplay() HFNAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HFNModifiedAPERValue is the concrete APERValue[HFNModified].
type HFNModifiedAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.HFNModified

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HFNModifiedAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HFNModifiedAPERValue) WithoutReplay() HFNModifiedAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HFNforPDCPSNlength18APERValue is the concrete APERValue[HFNforPDCPSNlength18].
type HFNforPDCPSNlength18APERValue struct {
	context s00.BridgeCodecContext
	Value   s00.HFNforPDCPSNlength18

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HFNforPDCPSNlength18APERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HFNforPDCPSNlength18APERValue) WithoutReplay() HFNforPDCPSNlength18APERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HOReportingCauseAPERValue is the concrete APERValue[HOReportingCause].
type HOReportingCauseAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.HOReportingCause

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HOReportingCauseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HOReportingCauseAPERValue) WithoutReplay() HOReportingCauseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverWindowDurationAPERValue is the concrete APERValue[HandoverWindowDuration].
type HandoverWindowDurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.HandoverWindowDuration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverWindowDurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverWindowDurationAPERValue) WithoutReplay() HandoverWindowDurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverWindowStartAPERValue is the concrete APERValue[HandoverWindowStart].
type HandoverWindowStartAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.HandoverWindowStart

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverWindowStartAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverWindowStartAPERValue) WithoutReplay() HandoverWindowStartAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HoReportTypeAPERValue is the concrete APERValue[HoReportType].
type HoReportTypeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.HoReportType

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HoReportTypeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HoReportTypeAPERValue) WithoutReplay() HoReportTypeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HoTypeAPERValue is the concrete APERValue[HoType].
type HoTypeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.HoType

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HoTypeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HoTypeAPERValue) WithoutReplay() HoTypeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HysteresisAPERValue is the concrete APERValue[Hysteresis].
type HysteresisAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.Hysteresis

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HysteresisAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HysteresisAPERValue) WithoutReplay() HysteresisAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// IMSIAPERValue is the concrete APERValue[IMSI].
type IMSIAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.IMSI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v IMSIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v IMSIAPERValue) WithoutReplay() IMSIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// IntegrityProtectionAlgorithmsAPERValue is the concrete APERValue[IntegrityProtectionAlgorithms].
type IntegrityProtectionAlgorithmsAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.IntegrityProtectionAlgorithms

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v IntegrityProtectionAlgorithmsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v IntegrityProtectionAlgorithmsAPERValue) WithoutReplay() IntegrityProtectionAlgorithmsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// IntegrityProtectionIndicationAPERValue is the concrete APERValue[IntegrityProtectionIndication].
type IntegrityProtectionIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.IntegrityProtectionIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v IntegrityProtectionIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v IntegrityProtectionIndicationAPERValue) WithoutReplay() IntegrityProtectionIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// IntegrityProtectionResultAPERValue is the concrete APERValue[IntegrityProtectionResult].
type IntegrityProtectionResultAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.IntegrityProtectionResult

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v IntegrityProtectionResultAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v IntegrityProtectionResultAPERValue) WithoutReplay() IntegrityProtectionResultAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// IntendedNumberOfPagingAttemptsAPERValue is the concrete APERValue[IntendedNumberOfPagingAttempts].
type IntendedNumberOfPagingAttemptsAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.IntendedNumberOfPagingAttempts

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v IntendedNumberOfPagingAttemptsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v IntendedNumberOfPagingAttemptsAPERValue) WithoutReplay() IntendedNumberOfPagingAttemptsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InterfacesToTraceAPERValue is the concrete APERValue[InterfacesToTrace].
type InterfacesToTraceAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.InterfacesToTrace

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InterfacesToTraceAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InterfacesToTraceAPERValue) WithoutReplay() InterfacesToTraceAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// L3InformationAPERValue is the concrete APERValue[L3Information].
type L3InformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.L3Information

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v L3InformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v L3InformationAPERValue) WithoutReplay() L3InformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LACAPERValue is the concrete APERValue[LAC].
type LACAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.LAC

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LACAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LACAPERValue) WithoutReplay() LACAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LastVisitedNGRANCellInformationAPERValue is the concrete APERValue[LastVisitedNGRANCellInformation].
type LastVisitedNGRANCellInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.LastVisitedNGRANCellInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LastVisitedNGRANCellInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LastVisitedNGRANCellInformationAPERValue) WithoutReplay() LastVisitedNGRANCellInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LastVisitedUTRANCellInformationAPERValue is the concrete APERValue[LastVisitedUTRANCellInformation].
type LastVisitedUTRANCellInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.LastVisitedUTRANCellInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LastVisitedUTRANCellInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LastVisitedUTRANCellInformationAPERValue) WithoutReplay() LastVisitedUTRANCellInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LinksToLogAPERValue is the concrete APERValue[LinksToLog].
type LinksToLogAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.LinksToLog

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LinksToLogAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LinksToLogAPERValue) WithoutReplay() LinksToLogAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LoggingDurationAPERValue is the concrete APERValue[LoggingDuration].
type LoggingDurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.LoggingDuration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LoggingDurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LoggingDurationAPERValue) WithoutReplay() LoggingDurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// LoggingIntervalAPERValue is the concrete APERValue[LoggingInterval].
type LoggingIntervalAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.LoggingInterval

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v LoggingIntervalAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v LoggingIntervalAPERValue) WithoutReplay() LoggingIntervalAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M1ReportingTriggerAPERValue is the concrete APERValue[M1ReportingTrigger].
type M1ReportingTriggerAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.M1ReportingTrigger

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M1ReportingTriggerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M1ReportingTriggerAPERValue) WithoutReplay() M1ReportingTriggerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M3periodAPERValue is the concrete APERValue[M3period].
type M3periodAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.M3period

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M3periodAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M3periodAPERValue) WithoutReplay() M3periodAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M4periodAPERValue is the concrete APERValue[M4period].
type M4periodAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.M4period

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M4periodAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M4periodAPERValue) WithoutReplay() M4periodAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M5periodAPERValue is the concrete APERValue[M5period].
type M5periodAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.M5period

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M5periodAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M5periodAPERValue) WithoutReplay() M5periodAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M6delayThresholdAPERValue is the concrete APERValue[M6delayThreshold].
type M6delayThresholdAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.M6delayThreshold

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M6delayThresholdAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M6delayThresholdAPERValue) WithoutReplay() M6delayThresholdAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M6reportIntervalAPERValue is the concrete APERValue[M6reportInterval].
type M6reportIntervalAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.M6reportInterval

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M6reportIntervalAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M6reportIntervalAPERValue) WithoutReplay() M6reportIntervalAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// M7periodAPERValue is the concrete APERValue[M7period].
type M7periodAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.M7period

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v M7periodAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v M7periodAPERValue) WithoutReplay() M7periodAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MDTActivationAPERValue is the concrete APERValue[MDTActivation].
type MDTActivationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.MDTActivation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MDTActivationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MDTActivationAPERValue) WithoutReplay() MDTActivationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MMECodeAPERValue is the concrete APERValue[MMECode].
type MMECodeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.MMECode

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MMECodeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MMECodeAPERValue) WithoutReplay() MMECodeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MTMSIAPERValue is the concrete APERValue[MTMSI].
type MTMSIAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.MTMSI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MTMSIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MTMSIAPERValue) WithoutReplay() MTMSIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasurementsToActivateAPERValue is the concrete APERValue[MeasurementsToActivate].
type MeasurementsToActivateAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.MeasurementsToActivate

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v MeasurementsToActivateAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v MeasurementsToActivateAPERValue) WithoutReplay() MeasurementsToActivateAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NBIoTPagingEDRXCycleAPERValue is the concrete APERValue[NBIoTPagingEDRXCycle].
type NBIoTPagingEDRXCycleAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NBIoTPagingEDRXCycle

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NBIoTPagingEDRXCycleAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NBIoTPagingEDRXCycleAPERValue) WithoutReplay() NBIoTPagingEDRXCycleAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NBIoTPagingTimeWindowAPERValue is the concrete APERValue[NBIoTPagingTimeWindow].
type NBIoTPagingTimeWindowAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NBIoTPagingTimeWindow

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NBIoTPagingTimeWindowAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NBIoTPagingTimeWindowAPERValue) WithoutReplay() NBIoTPagingTimeWindowAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRCellIdentityAPERValue is the concrete APERValue[NRCellIdentity].
type NRCellIdentityAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NRCellIdentity

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NRCellIdentityAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRCellIdentityAPERValue) WithoutReplay() NRCellIdentityAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRencryptionAlgorithmsAPERValue is the concrete APERValue[NRencryptionAlgorithms].
type NRencryptionAlgorithmsAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NRencryptionAlgorithms

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NRencryptionAlgorithmsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRencryptionAlgorithmsAPERValue) WithoutReplay() NRencryptionAlgorithmsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NRintegrityProtectionAlgorithmsAPERValue is the concrete APERValue[NRintegrityProtectionAlgorithms].
type NRintegrityProtectionAlgorithmsAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NRintegrityProtectionAlgorithms

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NRintegrityProtectionAlgorithmsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NRintegrityProtectionAlgorithmsAPERValue) WithoutReplay() NRintegrityProtectionAlgorithmsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NextPagingAreaScopeAPERValue is the concrete APERValue[NextPagingAreaScope].
type NextPagingAreaScopeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NextPagingAreaScope

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NextPagingAreaScopeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NextPagingAreaScopeAPERValue) WithoutReplay() NextPagingAreaScopeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NotifyFlagAPERValue is the concrete APERValue[NotifyFlag].
type NotifyFlagAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NotifyFlag

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NotifyFlagAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NotifyFlagAPERValue) WithoutReplay() NotifyFlagAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NumberOfBroadcastsAPERValue is the concrete APERValue[NumberOfBroadcasts].
type NumberOfBroadcastsAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NumberOfBroadcasts

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NumberOfBroadcastsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NumberOfBroadcastsAPERValue) WithoutReplay() NumberOfBroadcastsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NumberOfMeasurementReportingLevelsAPERValue is the concrete APERValue[NumberOfMeasurementReportingLevels].
type NumberOfMeasurementReportingLevelsAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NumberOfMeasurementReportingLevels

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v NumberOfMeasurementReportingLevelsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v NumberOfMeasurementReportingLevelsAPERValue) WithoutReplay() NumberOfMeasurementReportingLevelsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OldBSSToNewBSSInformationAPERValue is the concrete APERValue[OldBSSToNewBSSInformation].
type OldBSSToNewBSSInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.OldBSSToNewBSSInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v OldBSSToNewBSSInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v OldBSSToNewBSSInformationAPERValue) WithoutReplay() OldBSSToNewBSSInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OverloadActionAPERValue is the concrete APERValue[OverloadAction].
type OverloadActionAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.OverloadAction

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v OverloadActionAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v OverloadActionAPERValue) WithoutReplay() OverloadActionAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OverloadFlagAPERValue is the concrete APERValue[OverloadFlag].
type OverloadFlagAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.OverloadFlag

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v OverloadFlagAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v OverloadFlagAPERValue) WithoutReplay() OverloadFlagAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PDCPSNAPERValue is the concrete APERValue[PDCPSN].
type PDCPSNAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PDCPSN

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PDCPSNAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PDCPSNAPERValue) WithoutReplay() PDCPSNAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PDCPSNExtendedAPERValue is the concrete APERValue[PDCPSNExtended].
type PDCPSNExtendedAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PDCPSNExtended

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PDCPSNExtendedAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PDCPSNExtendedAPERValue) WithoutReplay() PDCPSNExtendedAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PDCPSNlength18APERValue is the concrete APERValue[PDCPSNlength18].
type PDCPSNlength18APERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PDCPSNlength18

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PDCPSNlength18APERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PDCPSNlength18APERValue) WithoutReplay() PDCPSNlength18APERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PLMNListforQMCAPERValue is the concrete APERValue[PLMNListforQMC].
type PLMNListforQMCAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PLMNListforQMC

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PLMNListforQMCAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PLMNListforQMCAPERValue) WithoutReplay() PLMNListforQMCAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingAttemptCountAPERValue is the concrete APERValue[PagingAttemptCount].
type PagingAttemptCountAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PagingAttemptCount

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingAttemptCountAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingAttemptCountAPERValue) WithoutReplay() PagingAttemptCountAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingEDRXCycleAPERValue is the concrete APERValue[PagingEDRXCycle].
type PagingEDRXCycleAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PagingEDRXCycle

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingEDRXCycleAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingEDRXCycleAPERValue) WithoutReplay() PagingEDRXCycleAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingProbabilityInformationAPERValue is the concrete APERValue[PagingProbabilityInformation].
type PagingProbabilityInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PagingProbabilityInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingProbabilityInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingProbabilityInformationAPERValue) WithoutReplay() PagingProbabilityInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PagingTimeWindowAPERValue is the concrete APERValue[PagingTimeWindow].
type PagingTimeWindowAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PagingTimeWindow

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PagingTimeWindowAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PagingTimeWindowAPERValue) WithoutReplay() PagingTimeWindowAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PedestrianUEAPERValue is the concrete APERValue[PedestrianUE].
type PedestrianUEAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PedestrianUE

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PedestrianUEAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PedestrianUEAPERValue) WithoutReplay() PedestrianUEAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PortNumberAPERValue is the concrete APERValue[PortNumber].
type PortNumberAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PortNumber

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PortNumberAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PortNumberAPERValue) WithoutReplay() PortNumberAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PreEmptionCapabilityAPERValue is the concrete APERValue[PreEmptionCapability].
type PreEmptionCapabilityAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PreEmptionCapability

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PreEmptionCapabilityAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PreEmptionCapabilityAPERValue) WithoutReplay() PreEmptionCapabilityAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PreEmptionVulnerabilityAPERValue is the concrete APERValue[PreEmptionVulnerability].
type PreEmptionVulnerabilityAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PreEmptionVulnerability

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PreEmptionVulnerabilityAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PreEmptionVulnerabilityAPERValue) WithoutReplay() PreEmptionVulnerabilityAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PresenceAPERValue is the concrete APERValue[Presence].
type PresenceAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.Presence

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PresenceAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PresenceAPERValue) WithoutReplay() PresenceAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PriorityLevelAPERValue is the concrete APERValue[PriorityLevel].
type PriorityLevelAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PriorityLevel

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v PriorityLevelAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v PriorityLevelAPERValue) WithoutReplay() PriorityLevelAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ProSeDirectCommunicationAPERValue is the concrete APERValue[ProSeDirectCommunication].
type ProSeDirectCommunicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ProSeDirectCommunication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ProSeDirectCommunicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ProSeDirectCommunicationAPERValue) WithoutReplay() ProSeDirectCommunicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ProSeDirectDiscoveryAPERValue is the concrete APERValue[ProSeDirectDiscovery].
type ProSeDirectDiscoveryAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ProSeDirectDiscovery

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ProSeDirectDiscoveryAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ProSeDirectDiscoveryAPERValue) WithoutReplay() ProSeDirectDiscoveryAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ProcedureCodeAPERValue is the concrete APERValue[ProcedureCode].
type ProcedureCodeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ProcedureCode

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ProcedureCodeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ProcedureCodeAPERValue) WithoutReplay() ProcedureCodeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ProtocolExtensionIDAPERValue is the concrete APERValue[ProtocolExtensionID].
type ProtocolExtensionIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ProtocolExtensionID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ProtocolExtensionIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ProtocolExtensionIDAPERValue) WithoutReplay() ProtocolExtensionIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ProtocolIEIDAPERValue is the concrete APERValue[ProtocolIEID].
type ProtocolIEIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ProtocolIEID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ProtocolIEIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ProtocolIEIDAPERValue) WithoutReplay() ProtocolIEIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// QCIAPERValue is the concrete APERValue[QCI].
type QCIAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.QCI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v QCIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v QCIAPERValue) WithoutReplay() QCIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RACAPERValue is the concrete APERValue[RAC].
type RACAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.RAC

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RACAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RACAPERValue) WithoutReplay() RACAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RANUENGAPIDAPERValue is the concrete APERValue[RANUENGAPID].
type RANUENGAPIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.RANUENGAPID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RANUENGAPIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RANUENGAPIDAPERValue) WithoutReplay() RANUENGAPIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RIMInformationAPERValue is the concrete APERValue[RIMInformation].
type RIMInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.RIMInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RIMInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RIMInformationAPERValue) WithoutReplay() RIMInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RNCIDAPERValue is the concrete APERValue[RNCID].
type RNCIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.RNCID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RNCIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RNCIDAPERValue) WithoutReplay() RNCIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RRCContainerAPERValue is the concrete APERValue[RRCContainer].
type RRCContainerAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.RRCContainer

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RRCContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RRCContainerAPERValue) WithoutReplay() RRCContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RangeAPERValue is the concrete APERValue[Range].
type RangeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.Range

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v RangeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v RangeAPERValue) WithoutReplay() RangeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ReceiveStatusofULPDCPSDUsAPERValue is the concrete APERValue[ReceiveStatusofULPDCPSDUs].
type ReceiveStatusofULPDCPSDUsAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ReceiveStatusofULPDCPSDUs

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v ReceiveStatusofULPDCPSDUsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v ReceiveStatusofULPDCPSDUsAPERValue) WithoutReplay() ReceiveStatusofULPDCPSDUsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeExtendedUEIdentityIndexValueValueCodecFieldCapture(v *ExtendedUEIdentityIndexValueValueCodec) *func(s00.ExtendedUEIdentityIndexValue, aper.DecodeState) (s00.ExtendedUEIdentityIndexValue, aper.Snapshot) {
	return &v.capture
}
func BridgeExtendedUEIdentityIndexValueValueCodecFieldCompare(v *ExtendedUEIdentityIndexValueValueCodec) *func(s00.ExtendedUEIdentityIndexValue, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeExtendedUEIdentityIndexValueValueCodecFieldContext(v *ExtendedUEIdentityIndexValueValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeExtendedUEIdentityIndexValueValueCodecFieldDecode(v *ExtendedUEIdentityIndexValueValueCodec) *func([]byte, aper.DecodeState) (s00.ExtendedUEIdentityIndexValue, error) {
	return &v.decode
}
func BridgeExtendedUEIdentityIndexValueValueCodecFieldEncode(v *ExtendedUEIdentityIndexValueValueCodec) *func(s00.ExtendedUEIdentityIndexValue, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeExtendedUEIdentityIndexValueValueCodecFieldPath(v *ExtendedUEIdentityIndexValueValueCodec) *aper.Path {
	return &v.path
}
func BridgeFailureEventReportingCauseValueCodecFieldCapture(v *FailureEventReportingCauseValueCodec) *func(s00.FailureEventReportingCause, aper.DecodeState) (s00.FailureEventReportingCause, aper.Snapshot) {
	return &v.capture
}
func BridgeFailureEventReportingCauseValueCodecFieldCompare(v *FailureEventReportingCauseValueCodec) *func(s00.FailureEventReportingCause, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeFailureEventReportingCauseValueCodecFieldContext(v *FailureEventReportingCauseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeFailureEventReportingCauseValueCodecFieldDecode(v *FailureEventReportingCauseValueCodec) *func([]byte, aper.DecodeState) (s00.FailureEventReportingCause, error) {
	return &v.decode
}
func BridgeFailureEventReportingCauseValueCodecFieldEncode(v *FailureEventReportingCauseValueCodec) *func(s00.FailureEventReportingCause, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeFailureEventReportingCauseValueCodecFieldPath(v *FailureEventReportingCauseValueCodec) *aper.Path {
	return &v.path
}
func BridgeFiveGSTACValueCodecFieldCapture(v *FiveGSTACValueCodec) *func(s00.FiveGSTAC, aper.DecodeState) (s00.FiveGSTAC, aper.Snapshot) {
	return &v.capture
}
func BridgeFiveGSTACValueCodecFieldCompare(v *FiveGSTACValueCodec) *func(s00.FiveGSTAC, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeFiveGSTACValueCodecFieldContext(v *FiveGSTACValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeFiveGSTACValueCodecFieldDecode(v *FiveGSTACValueCodec) *func([]byte, aper.DecodeState) (s00.FiveGSTAC, error) {
	return &v.decode
}
func BridgeFiveGSTACValueCodecFieldEncode(v *FiveGSTACValueCodec) *func(s00.FiveGSTAC, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeFiveGSTACValueCodecFieldPath(v *FiveGSTACValueCodec) *aper.Path { return &v.path }
func BridgeFiveQIValueCodecFieldCapture(v *FiveQIValueCodec) *func(s00.FiveQI, aper.DecodeState) (s00.FiveQI, aper.Snapshot) {
	return &v.capture
}
func BridgeFiveQIValueCodecFieldCompare(v *FiveQIValueCodec) *func(s00.FiveQI, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeFiveQIValueCodecFieldContext(v *FiveQIValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeFiveQIValueCodecFieldDecode(v *FiveQIValueCodec) *func([]byte, aper.DecodeState) (s00.FiveQI, error) {
	return &v.decode
}
func BridgeFiveQIValueCodecFieldEncode(v *FiveQIValueCodec) *func(s00.FiveQI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeFiveQIValueCodecFieldPath(v *FiveQIValueCodec) *aper.Path { return &v.path }
func BridgeForbiddenInterRATsValueCodecFieldCapture(v *ForbiddenInterRATsValueCodec) *func(s00.ForbiddenInterRATs, aper.DecodeState) (s00.ForbiddenInterRATs, aper.Snapshot) {
	return &v.capture
}
func BridgeForbiddenInterRATsValueCodecFieldCompare(v *ForbiddenInterRATsValueCodec) *func(s00.ForbiddenInterRATs, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeForbiddenInterRATsValueCodecFieldContext(v *ForbiddenInterRATsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeForbiddenInterRATsValueCodecFieldDecode(v *ForbiddenInterRATsValueCodec) *func([]byte, aper.DecodeState) (s00.ForbiddenInterRATs, error) {
	return &v.decode
}
func BridgeForbiddenInterRATsValueCodecFieldEncode(v *ForbiddenInterRATsValueCodec) *func(s00.ForbiddenInterRATs, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeForbiddenInterRATsValueCodecFieldPath(v *ForbiddenInterRATsValueCodec) *aper.Path {
	return &v.path
}
func BridgeForbiddenLACsValueCodecFieldCapture(v *ForbiddenLACsValueCodec) *func(s00.ForbiddenLACs, aper.DecodeState) (s00.ForbiddenLACs, aper.Snapshot) {
	return &v.capture
}
func BridgeForbiddenLACsValueCodecFieldCompare(v *ForbiddenLACsValueCodec) *func(s00.ForbiddenLACs, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeForbiddenLACsValueCodecFieldContext(v *ForbiddenLACsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeForbiddenLACsValueCodecFieldDecode(v *ForbiddenLACsValueCodec) *func([]byte, aper.DecodeState) (s00.ForbiddenLACs, error) {
	return &v.decode
}
func BridgeForbiddenLACsValueCodecFieldEncode(v *ForbiddenLACsValueCodec) *func(s00.ForbiddenLACs, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeForbiddenLACsValueCodecFieldPath(v *ForbiddenLACsValueCodec) *aper.Path { return &v.path }
func BridgeForbiddenTACsValueCodecFieldCapture(v *ForbiddenTACsValueCodec) *func(s00.ForbiddenTACs, aper.DecodeState) (s00.ForbiddenTACs, aper.Snapshot) {
	return &v.capture
}
func BridgeForbiddenTACsValueCodecFieldCompare(v *ForbiddenTACsValueCodec) *func(s00.ForbiddenTACs, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeForbiddenTACsValueCodecFieldContext(v *ForbiddenTACsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeForbiddenTACsValueCodecFieldDecode(v *ForbiddenTACsValueCodec) *func([]byte, aper.DecodeState) (s00.ForbiddenTACs, error) {
	return &v.decode
}
func BridgeForbiddenTACsValueCodecFieldEncode(v *ForbiddenTACsValueCodec) *func(s00.ForbiddenTACs, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeForbiddenTACsValueCodecFieldPath(v *ForbiddenTACsValueCodec) *aper.Path { return &v.path }
func BridgeGNBIDValueCodecFieldCapture(v *GNBIDValueCodec) *func(s00.GNBID, aper.DecodeState) (s00.GNBID, aper.Snapshot) {
	return &v.capture
}
func BridgeGNBIDValueCodecFieldCompare(v *GNBIDValueCodec) *func(s00.GNBID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGNBIDValueCodecFieldContext(v *GNBIDValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeGNBIDValueCodecFieldDecode(v *GNBIDValueCodec) *func([]byte, aper.DecodeState) (s00.GNBID, error) {
	return &v.decode
}
func BridgeGNBIDValueCodecFieldEncode(v *GNBIDValueCodec) *func(s00.GNBID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGNBIDValueCodecFieldPath(v *GNBIDValueCodec) *aper.Path { return &v.path }
func BridgeGTPTEIDValueCodecFieldCapture(v *GTPTEIDValueCodec) *func(s00.GTPTEID, aper.DecodeState) (s00.GTPTEID, aper.Snapshot) {
	return &v.capture
}
func BridgeGTPTEIDValueCodecFieldCompare(v *GTPTEIDValueCodec) *func(s00.GTPTEID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGTPTEIDValueCodecFieldContext(v *GTPTEIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGTPTEIDValueCodecFieldDecode(v *GTPTEIDValueCodec) *func([]byte, aper.DecodeState) (s00.GTPTEID, error) {
	return &v.decode
}
func BridgeGTPTEIDValueCodecFieldEncode(v *GTPTEIDValueCodec) *func(s00.GTPTEID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGTPTEIDValueCodecFieldPath(v *GTPTEIDValueCodec) *aper.Path { return &v.path }
func BridgeGUMMEITypeValueCodecFieldCapture(v *GUMMEITypeValueCodec) *func(s00.GUMMEIType, aper.DecodeState) (s00.GUMMEIType, aper.Snapshot) {
	return &v.capture
}
func BridgeGUMMEITypeValueCodecFieldCompare(v *GUMMEITypeValueCodec) *func(s00.GUMMEIType, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGUMMEITypeValueCodecFieldContext(v *GUMMEITypeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGUMMEITypeValueCodecFieldDecode(v *GUMMEITypeValueCodec) *func([]byte, aper.DecodeState) (s00.GUMMEIType, error) {
	return &v.decode
}
func BridgeGUMMEITypeValueCodecFieldEncode(v *GUMMEITypeValueCodec) *func(s00.GUMMEIType, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGUMMEITypeValueCodecFieldPath(v *GUMMEITypeValueCodec) *aper.Path { return &v.path }
func BridgeGWContextReleaseIndicationValueCodecFieldCapture(v *GWContextReleaseIndicationValueCodec) *func(s00.GWContextReleaseIndication, aper.DecodeState) (s00.GWContextReleaseIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeGWContextReleaseIndicationValueCodecFieldCompare(v *GWContextReleaseIndicationValueCodec) *func(s00.GWContextReleaseIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeGWContextReleaseIndicationValueCodecFieldContext(v *GWContextReleaseIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeGWContextReleaseIndicationValueCodecFieldDecode(v *GWContextReleaseIndicationValueCodec) *func([]byte, aper.DecodeState) (s00.GWContextReleaseIndication, error) {
	return &v.decode
}
func BridgeGWContextReleaseIndicationValueCodecFieldEncode(v *GWContextReleaseIndicationValueCodec) *func(s00.GWContextReleaseIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeGWContextReleaseIndicationValueCodecFieldPath(v *GWContextReleaseIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeHFNModifiedValueCodecFieldCapture(v *HFNModifiedValueCodec) *func(s00.HFNModified, aper.DecodeState) (s00.HFNModified, aper.Snapshot) {
	return &v.capture
}
func BridgeHFNModifiedValueCodecFieldCompare(v *HFNModifiedValueCodec) *func(s00.HFNModified, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHFNModifiedValueCodecFieldContext(v *HFNModifiedValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHFNModifiedValueCodecFieldDecode(v *HFNModifiedValueCodec) *func([]byte, aper.DecodeState) (s00.HFNModified, error) {
	return &v.decode
}
func BridgeHFNModifiedValueCodecFieldEncode(v *HFNModifiedValueCodec) *func(s00.HFNModified, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHFNModifiedValueCodecFieldPath(v *HFNModifiedValueCodec) *aper.Path { return &v.path }
func BridgeHFNValueCodecFieldCapture(v *HFNValueCodec) *func(s00.HFN, aper.DecodeState) (s00.HFN, aper.Snapshot) {
	return &v.capture
}
func BridgeHFNValueCodecFieldCompare(v *HFNValueCodec) *func(s00.HFN, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHFNValueCodecFieldContext(v *HFNValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeHFNValueCodecFieldDecode(v *HFNValueCodec) *func([]byte, aper.DecodeState) (s00.HFN, error) {
	return &v.decode
}
func BridgeHFNValueCodecFieldEncode(v *HFNValueCodec) *func(s00.HFN, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHFNValueCodecFieldPath(v *HFNValueCodec) *aper.Path { return &v.path }
func BridgeHFNforPDCPSNlength18ValueCodecFieldCapture(v *HFNforPDCPSNlength18ValueCodec) *func(s00.HFNforPDCPSNlength18, aper.DecodeState) (s00.HFNforPDCPSNlength18, aper.Snapshot) {
	return &v.capture
}
func BridgeHFNforPDCPSNlength18ValueCodecFieldCompare(v *HFNforPDCPSNlength18ValueCodec) *func(s00.HFNforPDCPSNlength18, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHFNforPDCPSNlength18ValueCodecFieldContext(v *HFNforPDCPSNlength18ValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHFNforPDCPSNlength18ValueCodecFieldDecode(v *HFNforPDCPSNlength18ValueCodec) *func([]byte, aper.DecodeState) (s00.HFNforPDCPSNlength18, error) {
	return &v.decode
}
func BridgeHFNforPDCPSNlength18ValueCodecFieldEncode(v *HFNforPDCPSNlength18ValueCodec) *func(s00.HFNforPDCPSNlength18, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHFNforPDCPSNlength18ValueCodecFieldPath(v *HFNforPDCPSNlength18ValueCodec) *aper.Path {
	return &v.path
}
func BridgeHOReportingCauseValueCodecFieldCapture(v *HOReportingCauseValueCodec) *func(s00.HOReportingCause, aper.DecodeState) (s00.HOReportingCause, aper.Snapshot) {
	return &v.capture
}
func BridgeHOReportingCauseValueCodecFieldCompare(v *HOReportingCauseValueCodec) *func(s00.HOReportingCause, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHOReportingCauseValueCodecFieldContext(v *HOReportingCauseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHOReportingCauseValueCodecFieldDecode(v *HOReportingCauseValueCodec) *func([]byte, aper.DecodeState) (s00.HOReportingCause, error) {
	return &v.decode
}
func BridgeHOReportingCauseValueCodecFieldEncode(v *HOReportingCauseValueCodec) *func(s00.HOReportingCause, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHOReportingCauseValueCodecFieldPath(v *HOReportingCauseValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverFlagValueCodecFieldCapture(v *HandoverFlagValueCodec) *func(s00.HandoverFlag, aper.DecodeState) (s00.HandoverFlag, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverFlagValueCodecFieldCompare(v *HandoverFlagValueCodec) *func(s00.HandoverFlag, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverFlagValueCodecFieldContext(v *HandoverFlagValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverFlagValueCodecFieldDecode(v *HandoverFlagValueCodec) *func([]byte, aper.DecodeState) (s00.HandoverFlag, error) {
	return &v.decode
}
func BridgeHandoverFlagValueCodecFieldEncode(v *HandoverFlagValueCodec) *func(s00.HandoverFlag, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverFlagValueCodecFieldPath(v *HandoverFlagValueCodec) *aper.Path { return &v.path }
func BridgeHandoverTypeValueCodecFieldCapture(v *HandoverTypeValueCodec) *func(s00.HandoverType, aper.DecodeState) (s00.HandoverType, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverTypeValueCodecFieldCompare(v *HandoverTypeValueCodec) *func(s00.HandoverType, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverTypeValueCodecFieldContext(v *HandoverTypeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverTypeValueCodecFieldDecode(v *HandoverTypeValueCodec) *func([]byte, aper.DecodeState) (s00.HandoverType, error) {
	return &v.decode
}
func BridgeHandoverTypeValueCodecFieldEncode(v *HandoverTypeValueCodec) *func(s00.HandoverType, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverTypeValueCodecFieldPath(v *HandoverTypeValueCodec) *aper.Path { return &v.path }
func BridgeHandoverWindowDurationValueCodecFieldCapture(v *HandoverWindowDurationValueCodec) *func(s00.HandoverWindowDuration, aper.DecodeState) (s00.HandoverWindowDuration, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverWindowDurationValueCodecFieldCompare(v *HandoverWindowDurationValueCodec) *func(s00.HandoverWindowDuration, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverWindowDurationValueCodecFieldContext(v *HandoverWindowDurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverWindowDurationValueCodecFieldDecode(v *HandoverWindowDurationValueCodec) *func([]byte, aper.DecodeState) (s00.HandoverWindowDuration, error) {
	return &v.decode
}
func BridgeHandoverWindowDurationValueCodecFieldEncode(v *HandoverWindowDurationValueCodec) *func(s00.HandoverWindowDuration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverWindowDurationValueCodecFieldPath(v *HandoverWindowDurationValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverWindowStartValueCodecFieldCapture(v *HandoverWindowStartValueCodec) *func(s00.HandoverWindowStart, aper.DecodeState) (s00.HandoverWindowStart, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverWindowStartValueCodecFieldCompare(v *HandoverWindowStartValueCodec) *func(s00.HandoverWindowStart, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverWindowStartValueCodecFieldContext(v *HandoverWindowStartValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverWindowStartValueCodecFieldDecode(v *HandoverWindowStartValueCodec) *func([]byte, aper.DecodeState) (s00.HandoverWindowStart, error) {
	return &v.decode
}
func BridgeHandoverWindowStartValueCodecFieldEncode(v *HandoverWindowStartValueCodec) *func(s00.HandoverWindowStart, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverWindowStartValueCodecFieldPath(v *HandoverWindowStartValueCodec) *aper.Path {
	return &v.path
}
func BridgeHoReportTypeValueCodecFieldCapture(v *HoReportTypeValueCodec) *func(s00.HoReportType, aper.DecodeState) (s00.HoReportType, aper.Snapshot) {
	return &v.capture
}
func BridgeHoReportTypeValueCodecFieldCompare(v *HoReportTypeValueCodec) *func(s00.HoReportType, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHoReportTypeValueCodecFieldContext(v *HoReportTypeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHoReportTypeValueCodecFieldDecode(v *HoReportTypeValueCodec) *func([]byte, aper.DecodeState) (s00.HoReportType, error) {
	return &v.decode
}
func BridgeHoReportTypeValueCodecFieldEncode(v *HoReportTypeValueCodec) *func(s00.HoReportType, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHoReportTypeValueCodecFieldPath(v *HoReportTypeValueCodec) *aper.Path { return &v.path }
func BridgeHoTypeValueCodecFieldCapture(v *HoTypeValueCodec) *func(s00.HoType, aper.DecodeState) (s00.HoType, aper.Snapshot) {
	return &v.capture
}
func BridgeHoTypeValueCodecFieldCompare(v *HoTypeValueCodec) *func(s00.HoType, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHoTypeValueCodecFieldContext(v *HoTypeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHoTypeValueCodecFieldDecode(v *HoTypeValueCodec) *func([]byte, aper.DecodeState) (s00.HoType, error) {
	return &v.decode
}
func BridgeHoTypeValueCodecFieldEncode(v *HoTypeValueCodec) *func(s00.HoType, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHoTypeValueCodecFieldPath(v *HoTypeValueCodec) *aper.Path { return &v.path }
func BridgeHysteresisValueCodecFieldCapture(v *HysteresisValueCodec) *func(s00.Hysteresis, aper.DecodeState) (s00.Hysteresis, aper.Snapshot) {
	return &v.capture
}
func BridgeHysteresisValueCodecFieldCompare(v *HysteresisValueCodec) *func(s00.Hysteresis, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHysteresisValueCodecFieldContext(v *HysteresisValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHysteresisValueCodecFieldDecode(v *HysteresisValueCodec) *func([]byte, aper.DecodeState) (s00.Hysteresis, error) {
	return &v.decode
}
func BridgeHysteresisValueCodecFieldEncode(v *HysteresisValueCodec) *func(s00.Hysteresis, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHysteresisValueCodecFieldPath(v *HysteresisValueCodec) *aper.Path { return &v.path }
func BridgeIABAuthorizedValueCodecFieldCapture(v *IABAuthorizedValueCodec) *func(s00.IABAuthorized, aper.DecodeState) (s00.IABAuthorized, aper.Snapshot) {
	return &v.capture
}
func BridgeIABAuthorizedValueCodecFieldCompare(v *IABAuthorizedValueCodec) *func(s00.IABAuthorized, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeIABAuthorizedValueCodecFieldContext(v *IABAuthorizedValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeIABAuthorizedValueCodecFieldDecode(v *IABAuthorizedValueCodec) *func([]byte, aper.DecodeState) (s00.IABAuthorized, error) {
	return &v.decode
}
func BridgeIABAuthorizedValueCodecFieldEncode(v *IABAuthorizedValueCodec) *func(s00.IABAuthorized, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeIABAuthorizedValueCodecFieldPath(v *IABAuthorizedValueCodec) *aper.Path { return &v.path }
func BridgeIABNodeIndicationValueCodecFieldCapture(v *IABNodeIndicationValueCodec) *func(s00.IABNodeIndication, aper.DecodeState) (s00.IABNodeIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeIABNodeIndicationValueCodecFieldCompare(v *IABNodeIndicationValueCodec) *func(s00.IABNodeIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeIABNodeIndicationValueCodecFieldContext(v *IABNodeIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeIABNodeIndicationValueCodecFieldDecode(v *IABNodeIndicationValueCodec) *func([]byte, aper.DecodeState) (s00.IABNodeIndication, error) {
	return &v.decode
}
func BridgeIABNodeIndicationValueCodecFieldEncode(v *IABNodeIndicationValueCodec) *func(s00.IABNodeIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeIABNodeIndicationValueCodecFieldPath(v *IABNodeIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeIABSupportedValueCodecFieldCapture(v *IABSupportedValueCodec) *func(s00.IABSupported, aper.DecodeState) (s00.IABSupported, aper.Snapshot) {
	return &v.capture
}
func BridgeIABSupportedValueCodecFieldCompare(v *IABSupportedValueCodec) *func(s00.IABSupported, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeIABSupportedValueCodecFieldContext(v *IABSupportedValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeIABSupportedValueCodecFieldDecode(v *IABSupportedValueCodec) *func([]byte, aper.DecodeState) (s00.IABSupported, error) {
	return &v.decode
}
func BridgeIABSupportedValueCodecFieldEncode(v *IABSupportedValueCodec) *func(s00.IABSupported, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeIABSupportedValueCodecFieldPath(v *IABSupportedValueCodec) *aper.Path { return &v.path }
func BridgeIMSIValueCodecFieldCapture(v *IMSIValueCodec) *func(s00.IMSI, aper.DecodeState) (s00.IMSI, aper.Snapshot) {
	return &v.capture
}
func BridgeIMSIValueCodecFieldCompare(v *IMSIValueCodec) *func(s00.IMSI, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeIMSIValueCodecFieldContext(v *IMSIValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeIMSIValueCodecFieldDecode(v *IMSIValueCodec) *func([]byte, aper.DecodeState) (s00.IMSI, error) {
	return &v.decode
}
func BridgeIMSIValueCodecFieldEncode(v *IMSIValueCodec) *func(s00.IMSI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeIMSIValueCodecFieldPath(v *IMSIValueCodec) *aper.Path { return &v.path }
func BridgeIMSvoiceEPSfallbackfrom5GValueCodecFieldCapture(v *IMSvoiceEPSfallbackfrom5GValueCodec) *func(s00.IMSvoiceEPSfallbackfrom5G, aper.DecodeState) (s00.IMSvoiceEPSfallbackfrom5G, aper.Snapshot) {
	return &v.capture
}
func BridgeIMSvoiceEPSfallbackfrom5GValueCodecFieldCompare(v *IMSvoiceEPSfallbackfrom5GValueCodec) *func(s00.IMSvoiceEPSfallbackfrom5G, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeIMSvoiceEPSfallbackfrom5GValueCodecFieldContext(v *IMSvoiceEPSfallbackfrom5GValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeIMSvoiceEPSfallbackfrom5GValueCodecFieldDecode(v *IMSvoiceEPSfallbackfrom5GValueCodec) *func([]byte, aper.DecodeState) (s00.IMSvoiceEPSfallbackfrom5G, error) {
	return &v.decode
}
func BridgeIMSvoiceEPSfallbackfrom5GValueCodecFieldEncode(v *IMSvoiceEPSfallbackfrom5GValueCodec) *func(s00.IMSvoiceEPSfallbackfrom5G, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeIMSvoiceEPSfallbackfrom5GValueCodecFieldPath(v *IMSvoiceEPSfallbackfrom5GValueCodec) *aper.Path {
	return &v.path
}
func BridgeIntegrityProtectionAlgorithmsValueCodecFieldCapture(v *IntegrityProtectionAlgorithmsValueCodec) *func(s00.IntegrityProtectionAlgorithms, aper.DecodeState) (s00.IntegrityProtectionAlgorithms, aper.Snapshot) {
	return &v.capture
}
func BridgeIntegrityProtectionAlgorithmsValueCodecFieldCompare(v *IntegrityProtectionAlgorithmsValueCodec) *func(s00.IntegrityProtectionAlgorithms, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeIntegrityProtectionAlgorithmsValueCodecFieldContext(v *IntegrityProtectionAlgorithmsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeIntegrityProtectionAlgorithmsValueCodecFieldDecode(v *IntegrityProtectionAlgorithmsValueCodec) *func([]byte, aper.DecodeState) (s00.IntegrityProtectionAlgorithms, error) {
	return &v.decode
}
func BridgeIntegrityProtectionAlgorithmsValueCodecFieldEncode(v *IntegrityProtectionAlgorithmsValueCodec) *func(s00.IntegrityProtectionAlgorithms, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeIntegrityProtectionAlgorithmsValueCodecFieldPath(v *IntegrityProtectionAlgorithmsValueCodec) *aper.Path {
	return &v.path
}
func BridgeIntegrityProtectionIndicationValueCodecFieldCapture(v *IntegrityProtectionIndicationValueCodec) *func(s00.IntegrityProtectionIndication, aper.DecodeState) (s00.IntegrityProtectionIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeIntegrityProtectionIndicationValueCodecFieldCompare(v *IntegrityProtectionIndicationValueCodec) *func(s00.IntegrityProtectionIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeIntegrityProtectionIndicationValueCodecFieldContext(v *IntegrityProtectionIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeIntegrityProtectionIndicationValueCodecFieldDecode(v *IntegrityProtectionIndicationValueCodec) *func([]byte, aper.DecodeState) (s00.IntegrityProtectionIndication, error) {
	return &v.decode
}
func BridgeIntegrityProtectionIndicationValueCodecFieldEncode(v *IntegrityProtectionIndicationValueCodec) *func(s00.IntegrityProtectionIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeIntegrityProtectionIndicationValueCodecFieldPath(v *IntegrityProtectionIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeIntegrityProtectionResultValueCodecFieldCapture(v *IntegrityProtectionResultValueCodec) *func(s00.IntegrityProtectionResult, aper.DecodeState) (s00.IntegrityProtectionResult, aper.Snapshot) {
	return &v.capture
}
func BridgeIntegrityProtectionResultValueCodecFieldCompare(v *IntegrityProtectionResultValueCodec) *func(s00.IntegrityProtectionResult, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeIntegrityProtectionResultValueCodecFieldContext(v *IntegrityProtectionResultValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeIntegrityProtectionResultValueCodecFieldDecode(v *IntegrityProtectionResultValueCodec) *func([]byte, aper.DecodeState) (s00.IntegrityProtectionResult, error) {
	return &v.decode
}
func BridgeIntegrityProtectionResultValueCodecFieldEncode(v *IntegrityProtectionResultValueCodec) *func(s00.IntegrityProtectionResult, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeIntegrityProtectionResultValueCodecFieldPath(v *IntegrityProtectionResultValueCodec) *aper.Path {
	return &v.path
}
func BridgeIntendedNumberOfPagingAttemptsValueCodecFieldCapture(v *IntendedNumberOfPagingAttemptsValueCodec) *func(s00.IntendedNumberOfPagingAttempts, aper.DecodeState) (s00.IntendedNumberOfPagingAttempts, aper.Snapshot) {
	return &v.capture
}
func BridgeIntendedNumberOfPagingAttemptsValueCodecFieldCompare(v *IntendedNumberOfPagingAttemptsValueCodec) *func(s00.IntendedNumberOfPagingAttempts, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeIntendedNumberOfPagingAttemptsValueCodecFieldContext(v *IntendedNumberOfPagingAttemptsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeIntendedNumberOfPagingAttemptsValueCodecFieldDecode(v *IntendedNumberOfPagingAttemptsValueCodec) *func([]byte, aper.DecodeState) (s00.IntendedNumberOfPagingAttempts, error) {
	return &v.decode
}
func BridgeIntendedNumberOfPagingAttemptsValueCodecFieldEncode(v *IntendedNumberOfPagingAttemptsValueCodec) *func(s00.IntendedNumberOfPagingAttempts, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeIntendedNumberOfPagingAttemptsValueCodecFieldPath(v *IntendedNumberOfPagingAttemptsValueCodec) *aper.Path {
	return &v.path
}
func BridgeInterfacesToTraceValueCodecFieldCapture(v *InterfacesToTraceValueCodec) *func(s00.InterfacesToTrace, aper.DecodeState) (s00.InterfacesToTrace, aper.Snapshot) {
	return &v.capture
}
func BridgeInterfacesToTraceValueCodecFieldCompare(v *InterfacesToTraceValueCodec) *func(s00.InterfacesToTrace, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInterfacesToTraceValueCodecFieldContext(v *InterfacesToTraceValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterfacesToTraceValueCodecFieldDecode(v *InterfacesToTraceValueCodec) *func([]byte, aper.DecodeState) (s00.InterfacesToTrace, error) {
	return &v.decode
}
func BridgeInterfacesToTraceValueCodecFieldEncode(v *InterfacesToTraceValueCodec) *func(s00.InterfacesToTrace, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInterfacesToTraceValueCodecFieldPath(v *InterfacesToTraceValueCodec) *aper.Path {
	return &v.path
}
func BridgeIntersystemSONConfigurationTransferValueCodecFieldCapture(v *IntersystemSONConfigurationTransferValueCodec) *func(s00.IntersystemSONConfigurationTransfer, aper.DecodeState) (s00.IntersystemSONConfigurationTransfer, aper.Snapshot) {
	return &v.capture
}
func BridgeIntersystemSONConfigurationTransferValueCodecFieldCompare(v *IntersystemSONConfigurationTransferValueCodec) *func(s00.IntersystemSONConfigurationTransfer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeIntersystemSONConfigurationTransferValueCodecFieldContext(v *IntersystemSONConfigurationTransferValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeIntersystemSONConfigurationTransferValueCodecFieldDecode(v *IntersystemSONConfigurationTransferValueCodec) *func([]byte, aper.DecodeState) (s00.IntersystemSONConfigurationTransfer, error) {
	return &v.decode
}
func BridgeIntersystemSONConfigurationTransferValueCodecFieldEncode(v *IntersystemSONConfigurationTransferValueCodec) *func(s00.IntersystemSONConfigurationTransfer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeIntersystemSONConfigurationTransferValueCodecFieldPath(v *IntersystemSONConfigurationTransferValueCodec) *aper.Path {
	return &v.path
}
func BridgeKillAllWarningMessagesValueCodecFieldCapture(v *KillAllWarningMessagesValueCodec) *func(s00.KillAllWarningMessages, aper.DecodeState) (s00.KillAllWarningMessages, aper.Snapshot) {
	return &v.capture
}
func BridgeKillAllWarningMessagesValueCodecFieldCompare(v *KillAllWarningMessagesValueCodec) *func(s00.KillAllWarningMessages, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeKillAllWarningMessagesValueCodecFieldContext(v *KillAllWarningMessagesValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeKillAllWarningMessagesValueCodecFieldDecode(v *KillAllWarningMessagesValueCodec) *func([]byte, aper.DecodeState) (s00.KillAllWarningMessages, error) {
	return &v.decode
}
func BridgeKillAllWarningMessagesValueCodecFieldEncode(v *KillAllWarningMessagesValueCodec) *func(s00.KillAllWarningMessages, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeKillAllWarningMessagesValueCodecFieldPath(v *KillAllWarningMessagesValueCodec) *aper.Path {
	return &v.path
}
func BridgeL3InformationValueCodecFieldCapture(v *L3InformationValueCodec) *func(s00.L3Information, aper.DecodeState) (s00.L3Information, aper.Snapshot) {
	return &v.capture
}
func BridgeL3InformationValueCodecFieldCompare(v *L3InformationValueCodec) *func(s00.L3Information, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeL3InformationValueCodecFieldContext(v *L3InformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeL3InformationValueCodecFieldDecode(v *L3InformationValueCodec) *func([]byte, aper.DecodeState) (s00.L3Information, error) {
	return &v.decode
}
func BridgeL3InformationValueCodecFieldEncode(v *L3InformationValueCodec) *func(s00.L3Information, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeL3InformationValueCodecFieldPath(v *L3InformationValueCodec) *aper.Path { return &v.path }
func BridgeLACValueCodecFieldCapture(v *LACValueCodec) *func(s00.LAC, aper.DecodeState) (s00.LAC, aper.Snapshot) {
	return &v.capture
}
func BridgeLACValueCodecFieldCompare(v *LACValueCodec) *func(s00.LAC, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLACValueCodecFieldContext(v *LACValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeLACValueCodecFieldDecode(v *LACValueCodec) *func([]byte, aper.DecodeState) (s00.LAC, error) {
	return &v.decode
}
func BridgeLACValueCodecFieldEncode(v *LACValueCodec) *func(s00.LAC, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLACValueCodecFieldPath(v *LACValueCodec) *aper.Path { return &v.path }
func BridgeLHNIDValueCodecFieldCapture(v *LHNIDValueCodec) *func(s00.LHNID, aper.DecodeState) (s00.LHNID, aper.Snapshot) {
	return &v.capture
}
func BridgeLHNIDValueCodecFieldCompare(v *LHNIDValueCodec) *func(s00.LHNID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLHNIDValueCodecFieldContext(v *LHNIDValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeLHNIDValueCodecFieldDecode(v *LHNIDValueCodec) *func([]byte, aper.DecodeState) (s00.LHNID, error) {
	return &v.decode
}
func BridgeLHNIDValueCodecFieldEncode(v *LHNIDValueCodec) *func(s00.LHNID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLHNIDValueCodecFieldPath(v *LHNIDValueCodec) *aper.Path { return &v.path }
func BridgeLPPaPDUValueCodecFieldCapture(v *LPPaPDUValueCodec) *func(s00.LPPaPDU, aper.DecodeState) (s00.LPPaPDU, aper.Snapshot) {
	return &v.capture
}
func BridgeLPPaPDUValueCodecFieldCompare(v *LPPaPDUValueCodec) *func(s00.LPPaPDU, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLPPaPDUValueCodecFieldContext(v *LPPaPDUValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLPPaPDUValueCodecFieldDecode(v *LPPaPDUValueCodec) *func([]byte, aper.DecodeState) (s00.LPPaPDU, error) {
	return &v.decode
}
func BridgeLPPaPDUValueCodecFieldEncode(v *LPPaPDUValueCodec) *func(s00.LPPaPDU, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLPPaPDUValueCodecFieldPath(v *LPPaPDUValueCodec) *aper.Path { return &v.path }
func BridgeLTEMIndicationValueCodecFieldCapture(v *LTEMIndicationValueCodec) *func(s00.LTEMIndication, aper.DecodeState) (s00.LTEMIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeLTEMIndicationValueCodecFieldCompare(v *LTEMIndicationValueCodec) *func(s00.LTEMIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLTEMIndicationValueCodecFieldContext(v *LTEMIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLTEMIndicationValueCodecFieldDecode(v *LTEMIndicationValueCodec) *func([]byte, aper.DecodeState) (s00.LTEMIndication, error) {
	return &v.decode
}
func BridgeLTEMIndicationValueCodecFieldEncode(v *LTEMIndicationValueCodec) *func(s00.LTEMIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLTEMIndicationValueCodecFieldPath(v *LTEMIndicationValueCodec) *aper.Path { return &v.path }
func BridgeLastVisitedNGRANCellInformationValueCodecFieldCapture(v *LastVisitedNGRANCellInformationValueCodec) *func(s00.LastVisitedNGRANCellInformation, aper.DecodeState) (s00.LastVisitedNGRANCellInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeLastVisitedNGRANCellInformationValueCodecFieldCompare(v *LastVisitedNGRANCellInformationValueCodec) *func(s00.LastVisitedNGRANCellInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLastVisitedNGRANCellInformationValueCodecFieldContext(v *LastVisitedNGRANCellInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLastVisitedNGRANCellInformationValueCodecFieldDecode(v *LastVisitedNGRANCellInformationValueCodec) *func([]byte, aper.DecodeState) (s00.LastVisitedNGRANCellInformation, error) {
	return &v.decode
}
func BridgeLastVisitedNGRANCellInformationValueCodecFieldEncode(v *LastVisitedNGRANCellInformationValueCodec) *func(s00.LastVisitedNGRANCellInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLastVisitedNGRANCellInformationValueCodecFieldPath(v *LastVisitedNGRANCellInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeLastVisitedUTRANCellInformationValueCodecFieldCapture(v *LastVisitedUTRANCellInformationValueCodec) *func(s00.LastVisitedUTRANCellInformation, aper.DecodeState) (s00.LastVisitedUTRANCellInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeLastVisitedUTRANCellInformationValueCodecFieldCompare(v *LastVisitedUTRANCellInformationValueCodec) *func(s00.LastVisitedUTRANCellInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLastVisitedUTRANCellInformationValueCodecFieldContext(v *LastVisitedUTRANCellInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLastVisitedUTRANCellInformationValueCodecFieldDecode(v *LastVisitedUTRANCellInformationValueCodec) *func([]byte, aper.DecodeState) (s00.LastVisitedUTRANCellInformation, error) {
	return &v.decode
}
func BridgeLastVisitedUTRANCellInformationValueCodecFieldEncode(v *LastVisitedUTRANCellInformationValueCodec) *func(s00.LastVisitedUTRANCellInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLastVisitedUTRANCellInformationValueCodecFieldPath(v *LastVisitedUTRANCellInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeLinksToLogValueCodecFieldCapture(v *LinksToLogValueCodec) *func(s00.LinksToLog, aper.DecodeState) (s00.LinksToLog, aper.Snapshot) {
	return &v.capture
}
func BridgeLinksToLogValueCodecFieldCompare(v *LinksToLogValueCodec) *func(s00.LinksToLog, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLinksToLogValueCodecFieldContext(v *LinksToLogValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLinksToLogValueCodecFieldDecode(v *LinksToLogValueCodec) *func([]byte, aper.DecodeState) (s00.LinksToLog, error) {
	return &v.decode
}
func BridgeLinksToLogValueCodecFieldEncode(v *LinksToLogValueCodec) *func(s00.LinksToLog, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLinksToLogValueCodecFieldPath(v *LinksToLogValueCodec) *aper.Path { return &v.path }
func BridgeLoggingDurationValueCodecFieldCapture(v *LoggingDurationValueCodec) *func(s00.LoggingDuration, aper.DecodeState) (s00.LoggingDuration, aper.Snapshot) {
	return &v.capture
}
func BridgeLoggingDurationValueCodecFieldCompare(v *LoggingDurationValueCodec) *func(s00.LoggingDuration, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLoggingDurationValueCodecFieldContext(v *LoggingDurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLoggingDurationValueCodecFieldDecode(v *LoggingDurationValueCodec) *func([]byte, aper.DecodeState) (s00.LoggingDuration, error) {
	return &v.decode
}
func BridgeLoggingDurationValueCodecFieldEncode(v *LoggingDurationValueCodec) *func(s00.LoggingDuration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLoggingDurationValueCodecFieldPath(v *LoggingDurationValueCodec) *aper.Path {
	return &v.path
}
func BridgeLoggingIntervalValueCodecFieldCapture(v *LoggingIntervalValueCodec) *func(s00.LoggingInterval, aper.DecodeState) (s00.LoggingInterval, aper.Snapshot) {
	return &v.capture
}
func BridgeLoggingIntervalValueCodecFieldCompare(v *LoggingIntervalValueCodec) *func(s00.LoggingInterval, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeLoggingIntervalValueCodecFieldContext(v *LoggingIntervalValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeLoggingIntervalValueCodecFieldDecode(v *LoggingIntervalValueCodec) *func([]byte, aper.DecodeState) (s00.LoggingInterval, error) {
	return &v.decode
}
func BridgeLoggingIntervalValueCodecFieldEncode(v *LoggingIntervalValueCodec) *func(s00.LoggingInterval, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeLoggingIntervalValueCodecFieldPath(v *LoggingIntervalValueCodec) *aper.Path {
	return &v.path
}
func BridgeM1ReportingTriggerValueCodecFieldCapture(v *M1ReportingTriggerValueCodec) *func(s00.M1ReportingTrigger, aper.DecodeState) (s00.M1ReportingTrigger, aper.Snapshot) {
	return &v.capture
}
func BridgeM1ReportingTriggerValueCodecFieldCompare(v *M1ReportingTriggerValueCodec) *func(s00.M1ReportingTrigger, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM1ReportingTriggerValueCodecFieldContext(v *M1ReportingTriggerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM1ReportingTriggerValueCodecFieldDecode(v *M1ReportingTriggerValueCodec) *func([]byte, aper.DecodeState) (s00.M1ReportingTrigger, error) {
	return &v.decode
}
func BridgeM1ReportingTriggerValueCodecFieldEncode(v *M1ReportingTriggerValueCodec) *func(s00.M1ReportingTrigger, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM1ReportingTriggerValueCodecFieldPath(v *M1ReportingTriggerValueCodec) *aper.Path {
	return &v.path
}
func BridgeM3periodValueCodecFieldCapture(v *M3periodValueCodec) *func(s00.M3period, aper.DecodeState) (s00.M3period, aper.Snapshot) {
	return &v.capture
}
func BridgeM3periodValueCodecFieldCompare(v *M3periodValueCodec) *func(s00.M3period, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM3periodValueCodecFieldContext(v *M3periodValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM3periodValueCodecFieldDecode(v *M3periodValueCodec) *func([]byte, aper.DecodeState) (s00.M3period, error) {
	return &v.decode
}
func BridgeM3periodValueCodecFieldEncode(v *M3periodValueCodec) *func(s00.M3period, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM3periodValueCodecFieldPath(v *M3periodValueCodec) *aper.Path { return &v.path }
func BridgeM4ReportAmountMDTValueCodecFieldCapture(v *M4ReportAmountMDTValueCodec) *func(s00.M4ReportAmountMDT, aper.DecodeState) (s00.M4ReportAmountMDT, aper.Snapshot) {
	return &v.capture
}
func BridgeM4ReportAmountMDTValueCodecFieldCompare(v *M4ReportAmountMDTValueCodec) *func(s00.M4ReportAmountMDT, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM4ReportAmountMDTValueCodecFieldContext(v *M4ReportAmountMDTValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM4ReportAmountMDTValueCodecFieldDecode(v *M4ReportAmountMDTValueCodec) *func([]byte, aper.DecodeState) (s00.M4ReportAmountMDT, error) {
	return &v.decode
}
func BridgeM4ReportAmountMDTValueCodecFieldEncode(v *M4ReportAmountMDTValueCodec) *func(s00.M4ReportAmountMDT, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM4ReportAmountMDTValueCodecFieldPath(v *M4ReportAmountMDTValueCodec) *aper.Path {
	return &v.path
}
func BridgeM4periodValueCodecFieldCapture(v *M4periodValueCodec) *func(s00.M4period, aper.DecodeState) (s00.M4period, aper.Snapshot) {
	return &v.capture
}
func BridgeM4periodValueCodecFieldCompare(v *M4periodValueCodec) *func(s00.M4period, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM4periodValueCodecFieldContext(v *M4periodValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM4periodValueCodecFieldDecode(v *M4periodValueCodec) *func([]byte, aper.DecodeState) (s00.M4period, error) {
	return &v.decode
}
func BridgeM4periodValueCodecFieldEncode(v *M4periodValueCodec) *func(s00.M4period, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM4periodValueCodecFieldPath(v *M4periodValueCodec) *aper.Path { return &v.path }
func BridgeM5ReportAmountMDTValueCodecFieldCapture(v *M5ReportAmountMDTValueCodec) *func(s00.M5ReportAmountMDT, aper.DecodeState) (s00.M5ReportAmountMDT, aper.Snapshot) {
	return &v.capture
}
func BridgeM5ReportAmountMDTValueCodecFieldCompare(v *M5ReportAmountMDTValueCodec) *func(s00.M5ReportAmountMDT, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM5ReportAmountMDTValueCodecFieldContext(v *M5ReportAmountMDTValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM5ReportAmountMDTValueCodecFieldDecode(v *M5ReportAmountMDTValueCodec) *func([]byte, aper.DecodeState) (s00.M5ReportAmountMDT, error) {
	return &v.decode
}
func BridgeM5ReportAmountMDTValueCodecFieldEncode(v *M5ReportAmountMDTValueCodec) *func(s00.M5ReportAmountMDT, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM5ReportAmountMDTValueCodecFieldPath(v *M5ReportAmountMDTValueCodec) *aper.Path {
	return &v.path
}
func BridgeM5periodValueCodecFieldCapture(v *M5periodValueCodec) *func(s00.M5period, aper.DecodeState) (s00.M5period, aper.Snapshot) {
	return &v.capture
}
func BridgeM5periodValueCodecFieldCompare(v *M5periodValueCodec) *func(s00.M5period, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM5periodValueCodecFieldContext(v *M5periodValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM5periodValueCodecFieldDecode(v *M5periodValueCodec) *func([]byte, aper.DecodeState) (s00.M5period, error) {
	return &v.decode
}
func BridgeM5periodValueCodecFieldEncode(v *M5periodValueCodec) *func(s00.M5period, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM5periodValueCodecFieldPath(v *M5periodValueCodec) *aper.Path { return &v.path }
func BridgeM6ReportAmountMDTValueCodecFieldCapture(v *M6ReportAmountMDTValueCodec) *func(s00.M6ReportAmountMDT, aper.DecodeState) (s00.M6ReportAmountMDT, aper.Snapshot) {
	return &v.capture
}
func BridgeM6ReportAmountMDTValueCodecFieldCompare(v *M6ReportAmountMDTValueCodec) *func(s00.M6ReportAmountMDT, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM6ReportAmountMDTValueCodecFieldContext(v *M6ReportAmountMDTValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM6ReportAmountMDTValueCodecFieldDecode(v *M6ReportAmountMDTValueCodec) *func([]byte, aper.DecodeState) (s00.M6ReportAmountMDT, error) {
	return &v.decode
}
func BridgeM6ReportAmountMDTValueCodecFieldEncode(v *M6ReportAmountMDTValueCodec) *func(s00.M6ReportAmountMDT, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM6ReportAmountMDTValueCodecFieldPath(v *M6ReportAmountMDTValueCodec) *aper.Path {
	return &v.path
}
func BridgeM6delayThresholdValueCodecFieldCapture(v *M6delayThresholdValueCodec) *func(s00.M6delayThreshold, aper.DecodeState) (s00.M6delayThreshold, aper.Snapshot) {
	return &v.capture
}
func BridgeM6delayThresholdValueCodecFieldCompare(v *M6delayThresholdValueCodec) *func(s00.M6delayThreshold, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM6delayThresholdValueCodecFieldContext(v *M6delayThresholdValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM6delayThresholdValueCodecFieldDecode(v *M6delayThresholdValueCodec) *func([]byte, aper.DecodeState) (s00.M6delayThreshold, error) {
	return &v.decode
}
func BridgeM6delayThresholdValueCodecFieldEncode(v *M6delayThresholdValueCodec) *func(s00.M6delayThreshold, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM6delayThresholdValueCodecFieldPath(v *M6delayThresholdValueCodec) *aper.Path {
	return &v.path
}
func BridgeM6reportIntervalValueCodecFieldCapture(v *M6reportIntervalValueCodec) *func(s00.M6reportInterval, aper.DecodeState) (s00.M6reportInterval, aper.Snapshot) {
	return &v.capture
}
func BridgeM6reportIntervalValueCodecFieldCompare(v *M6reportIntervalValueCodec) *func(s00.M6reportInterval, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM6reportIntervalValueCodecFieldContext(v *M6reportIntervalValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM6reportIntervalValueCodecFieldDecode(v *M6reportIntervalValueCodec) *func([]byte, aper.DecodeState) (s00.M6reportInterval, error) {
	return &v.decode
}
func BridgeM6reportIntervalValueCodecFieldEncode(v *M6reportIntervalValueCodec) *func(s00.M6reportInterval, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM6reportIntervalValueCodecFieldPath(v *M6reportIntervalValueCodec) *aper.Path {
	return &v.path
}
func BridgeM7ReportAmountMDTValueCodecFieldCapture(v *M7ReportAmountMDTValueCodec) *func(s00.M7ReportAmountMDT, aper.DecodeState) (s00.M7ReportAmountMDT, aper.Snapshot) {
	return &v.capture
}
func BridgeM7ReportAmountMDTValueCodecFieldCompare(v *M7ReportAmountMDTValueCodec) *func(s00.M7ReportAmountMDT, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM7ReportAmountMDTValueCodecFieldContext(v *M7ReportAmountMDTValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM7ReportAmountMDTValueCodecFieldDecode(v *M7ReportAmountMDTValueCodec) *func([]byte, aper.DecodeState) (s00.M7ReportAmountMDT, error) {
	return &v.decode
}
func BridgeM7ReportAmountMDTValueCodecFieldEncode(v *M7ReportAmountMDTValueCodec) *func(s00.M7ReportAmountMDT, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM7ReportAmountMDTValueCodecFieldPath(v *M7ReportAmountMDTValueCodec) *aper.Path {
	return &v.path
}
func BridgeM7periodValueCodecFieldCapture(v *M7periodValueCodec) *func(s00.M7period, aper.DecodeState) (s00.M7period, aper.Snapshot) {
	return &v.capture
}
func BridgeM7periodValueCodecFieldCompare(v *M7periodValueCodec) *func(s00.M7period, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeM7periodValueCodecFieldContext(v *M7periodValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeM7periodValueCodecFieldDecode(v *M7periodValueCodec) *func([]byte, aper.DecodeState) (s00.M7period, error) {
	return &v.decode
}
func BridgeM7periodValueCodecFieldEncode(v *M7periodValueCodec) *func(s00.M7period, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeM7periodValueCodecFieldPath(v *M7periodValueCodec) *aper.Path { return &v.path }
func BridgeMDTActivationValueCodecFieldCapture(v *MDTActivationValueCodec) *func(s00.MDTActivation, aper.DecodeState) (s00.MDTActivation, aper.Snapshot) {
	return &v.capture
}
func BridgeMDTActivationValueCodecFieldCompare(v *MDTActivationValueCodec) *func(s00.MDTActivation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMDTActivationValueCodecFieldContext(v *MDTActivationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTActivationValueCodecFieldDecode(v *MDTActivationValueCodec) *func([]byte, aper.DecodeState) (s00.MDTActivation, error) {
	return &v.decode
}
func BridgeMDTActivationValueCodecFieldEncode(v *MDTActivationValueCodec) *func(s00.MDTActivation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMDTActivationValueCodecFieldPath(v *MDTActivationValueCodec) *aper.Path { return &v.path }
func BridgeMDTConfigurationNRValueCodecFieldCapture(v *MDTConfigurationNRValueCodec) *func(s00.MDTConfigurationNR, aper.DecodeState) (s00.MDTConfigurationNR, aper.Snapshot) {
	return &v.capture
}
func BridgeMDTConfigurationNRValueCodecFieldCompare(v *MDTConfigurationNRValueCodec) *func(s00.MDTConfigurationNR, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMDTConfigurationNRValueCodecFieldContext(v *MDTConfigurationNRValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTConfigurationNRValueCodecFieldDecode(v *MDTConfigurationNRValueCodec) *func([]byte, aper.DecodeState) (s00.MDTConfigurationNR, error) {
	return &v.decode
}
func BridgeMDTConfigurationNRValueCodecFieldEncode(v *MDTConfigurationNRValueCodec) *func(s00.MDTConfigurationNR, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMDTConfigurationNRValueCodecFieldPath(v *MDTConfigurationNRValueCodec) *aper.Path {
	return &v.path
}
func BridgeMDTLocationInfoValueCodecFieldCapture(v *MDTLocationInfoValueCodec) *func(s00.MDTLocationInfo, aper.DecodeState) (s00.MDTLocationInfo, aper.Snapshot) {
	return &v.capture
}
func BridgeMDTLocationInfoValueCodecFieldCompare(v *MDTLocationInfoValueCodec) *func(s00.MDTLocationInfo, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMDTLocationInfoValueCodecFieldContext(v *MDTLocationInfoValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTLocationInfoValueCodecFieldDecode(v *MDTLocationInfoValueCodec) *func([]byte, aper.DecodeState) (s00.MDTLocationInfo, error) {
	return &v.decode
}
func BridgeMDTLocationInfoValueCodecFieldEncode(v *MDTLocationInfoValueCodec) *func(s00.MDTLocationInfo, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMDTLocationInfoValueCodecFieldPath(v *MDTLocationInfoValueCodec) *aper.Path {
	return &v.path
}
func BridgeMDTPLMNListValueCodecFieldCapture(v *MDTPLMNListValueCodec) *func(s00.MDTPLMNList, aper.DecodeState) (s00.MDTPLMNList, aper.Snapshot) {
	return &v.capture
}
func BridgeMDTPLMNListValueCodecFieldCompare(v *MDTPLMNListValueCodec) *func(s00.MDTPLMNList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMDTPLMNListValueCodecFieldContext(v *MDTPLMNListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMDTPLMNListValueCodecFieldDecode(v *MDTPLMNListValueCodec) *func([]byte, aper.DecodeState) (s00.MDTPLMNList, error) {
	return &v.decode
}
func BridgeMDTPLMNListValueCodecFieldEncode(v *MDTPLMNListValueCodec) *func(s00.MDTPLMNList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMDTPLMNListValueCodecFieldPath(v *MDTPLMNListValueCodec) *aper.Path { return &v.path }
func BridgeMMECodeValueCodecFieldCapture(v *MMECodeValueCodec) *func(s00.MMECode, aper.DecodeState) (s00.MMECode, aper.Snapshot) {
	return &v.capture
}
func BridgeMMECodeValueCodecFieldCompare(v *MMECodeValueCodec) *func(s00.MMECode, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMECodeValueCodecFieldContext(v *MMECodeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMECodeValueCodecFieldDecode(v *MMECodeValueCodec) *func([]byte, aper.DecodeState) (s00.MMECode, error) {
	return &v.decode
}
func BridgeMMECodeValueCodecFieldEncode(v *MMECodeValueCodec) *func(s00.MMECode, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMECodeValueCodecFieldPath(v *MMECodeValueCodec) *aper.Path { return &v.path }
func BridgeMMEGroupIDValueCodecFieldCapture(v *MMEGroupIDValueCodec) *func(s00.MMEGroupID, aper.DecodeState) (s00.MMEGroupID, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEGroupIDValueCodecFieldCompare(v *MMEGroupIDValueCodec) *func(s00.MMEGroupID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEGroupIDValueCodecFieldContext(v *MMEGroupIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEGroupIDValueCodecFieldDecode(v *MMEGroupIDValueCodec) *func([]byte, aper.DecodeState) (s00.MMEGroupID, error) {
	return &v.decode
}
func BridgeMMEGroupIDValueCodecFieldEncode(v *MMEGroupIDValueCodec) *func(s00.MMEGroupID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEGroupIDValueCodecFieldPath(v *MMEGroupIDValueCodec) *aper.Path { return &v.path }
func BridgeMMERelaySupportIndicatorValueCodecFieldCapture(v *MMERelaySupportIndicatorValueCodec) *func(s00.MMERelaySupportIndicator, aper.DecodeState) (s00.MMERelaySupportIndicator, aper.Snapshot) {
	return &v.capture
}
func BridgeMMERelaySupportIndicatorValueCodecFieldCompare(v *MMERelaySupportIndicatorValueCodec) *func(s00.MMERelaySupportIndicator, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMERelaySupportIndicatorValueCodecFieldContext(v *MMERelaySupportIndicatorValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMERelaySupportIndicatorValueCodecFieldDecode(v *MMERelaySupportIndicatorValueCodec) *func([]byte, aper.DecodeState) (s00.MMERelaySupportIndicator, error) {
	return &v.decode
}
func BridgeMMERelaySupportIndicatorValueCodecFieldEncode(v *MMERelaySupportIndicatorValueCodec) *func(s00.MMERelaySupportIndicator, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMERelaySupportIndicatorValueCodecFieldPath(v *MMERelaySupportIndicatorValueCodec) *aper.Path {
	return &v.path
}
func BridgeMMEUES1APIDValueCodecFieldCapture(v *MMEUES1APIDValueCodec) *func(s00.MMEUES1APID, aper.DecodeState) (s00.MMEUES1APID, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEUES1APIDValueCodecFieldCompare(v *MMEUES1APIDValueCodec) *func(s00.MMEUES1APID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEUES1APIDValueCodecFieldContext(v *MMEUES1APIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEUES1APIDValueCodecFieldDecode(v *MMEUES1APIDValueCodec) *func([]byte, aper.DecodeState) (s00.MMEUES1APID, error) {
	return &v.decode
}
func BridgeMMEUES1APIDValueCodecFieldEncode(v *MMEUES1APIDValueCodec) *func(s00.MMEUES1APID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEUES1APIDValueCodecFieldPath(v *MMEUES1APIDValueCodec) *aper.Path { return &v.path }
func BridgeMMEnameValueCodecFieldCapture(v *MMEnameValueCodec) *func(s00.MMEname, aper.DecodeState) (s00.MMEname, aper.Snapshot) {
	return &v.capture
}
func BridgeMMEnameValueCodecFieldCompare(v *MMEnameValueCodec) *func(s00.MMEname, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMMEnameValueCodecFieldContext(v *MMEnameValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMMEnameValueCodecFieldDecode(v *MMEnameValueCodec) *func([]byte, aper.DecodeState) (s00.MMEname, error) {
	return &v.decode
}
func BridgeMMEnameValueCodecFieldEncode(v *MMEnameValueCodec) *func(s00.MMEname, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMMEnameValueCodecFieldPath(v *MMEnameValueCodec) *aper.Path { return &v.path }
func BridgeMSClassmark2ValueCodecFieldCapture(v *MSClassmark2ValueCodec) *func(s00.MSClassmark2, aper.DecodeState) (s00.MSClassmark2, aper.Snapshot) {
	return &v.capture
}
func BridgeMSClassmark2ValueCodecFieldCompare(v *MSClassmark2ValueCodec) *func(s00.MSClassmark2, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMSClassmark2ValueCodecFieldContext(v *MSClassmark2ValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMSClassmark2ValueCodecFieldDecode(v *MSClassmark2ValueCodec) *func([]byte, aper.DecodeState) (s00.MSClassmark2, error) {
	return &v.decode
}
func BridgeMSClassmark2ValueCodecFieldEncode(v *MSClassmark2ValueCodec) *func(s00.MSClassmark2, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMSClassmark2ValueCodecFieldPath(v *MSClassmark2ValueCodec) *aper.Path { return &v.path }
func BridgeMSClassmark3ValueCodecFieldCapture(v *MSClassmark3ValueCodec) *func(s00.MSClassmark3, aper.DecodeState) (s00.MSClassmark3, aper.Snapshot) {
	return &v.capture
}
func BridgeMSClassmark3ValueCodecFieldCompare(v *MSClassmark3ValueCodec) *func(s00.MSClassmark3, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMSClassmark3ValueCodecFieldContext(v *MSClassmark3ValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMSClassmark3ValueCodecFieldDecode(v *MSClassmark3ValueCodec) *func([]byte, aper.DecodeState) (s00.MSClassmark3, error) {
	return &v.decode
}
func BridgeMSClassmark3ValueCodecFieldEncode(v *MSClassmark3ValueCodec) *func(s00.MSClassmark3, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMSClassmark3ValueCodecFieldPath(v *MSClassmark3ValueCodec) *aper.Path { return &v.path }
func BridgeMTMSIValueCodecFieldCapture(v *MTMSIValueCodec) *func(s00.MTMSI, aper.DecodeState) (s00.MTMSI, aper.Snapshot) {
	return &v.capture
}
func BridgeMTMSIValueCodecFieldCompare(v *MTMSIValueCodec) *func(s00.MTMSI, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMTMSIValueCodecFieldContext(v *MTMSIValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeMTMSIValueCodecFieldDecode(v *MTMSIValueCodec) *func([]byte, aper.DecodeState) (s00.MTMSI, error) {
	return &v.decode
}
func BridgeMTMSIValueCodecFieldEncode(v *MTMSIValueCodec) *func(s00.MTMSI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMTMSIValueCodecFieldPath(v *MTMSIValueCodec) *aper.Path { return &v.path }
func BridgeManagementBasedMDTAllowedValueCodecFieldCapture(v *ManagementBasedMDTAllowedValueCodec) *func(s00.ManagementBasedMDTAllowed, aper.DecodeState) (s00.ManagementBasedMDTAllowed, aper.Snapshot) {
	return &v.capture
}
func BridgeManagementBasedMDTAllowedValueCodecFieldCompare(v *ManagementBasedMDTAllowedValueCodec) *func(s00.ManagementBasedMDTAllowed, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeManagementBasedMDTAllowedValueCodecFieldContext(v *ManagementBasedMDTAllowedValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeManagementBasedMDTAllowedValueCodecFieldDecode(v *ManagementBasedMDTAllowedValueCodec) *func([]byte, aper.DecodeState) (s00.ManagementBasedMDTAllowed, error) {
	return &v.decode
}
func BridgeManagementBasedMDTAllowedValueCodecFieldEncode(v *ManagementBasedMDTAllowedValueCodec) *func(s00.ManagementBasedMDTAllowed, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeManagementBasedMDTAllowedValueCodecFieldPath(v *ManagementBasedMDTAllowedValueCodec) *aper.Path {
	return &v.path
}
func BridgeMaskedIMEISVValueCodecFieldCapture(v *MaskedIMEISVValueCodec) *func(s00.MaskedIMEISV, aper.DecodeState) (s00.MaskedIMEISV, aper.Snapshot) {
	return &v.capture
}
func BridgeMaskedIMEISVValueCodecFieldCompare(v *MaskedIMEISVValueCodec) *func(s00.MaskedIMEISV, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMaskedIMEISVValueCodecFieldContext(v *MaskedIMEISVValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMaskedIMEISVValueCodecFieldDecode(v *MaskedIMEISVValueCodec) *func([]byte, aper.DecodeState) (s00.MaskedIMEISV, error) {
	return &v.decode
}
func BridgeMaskedIMEISVValueCodecFieldEncode(v *MaskedIMEISVValueCodec) *func(s00.MaskedIMEISV, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMaskedIMEISVValueCodecFieldPath(v *MaskedIMEISVValueCodec) *aper.Path { return &v.path }
func BridgeMeasurementsToActivateValueCodecFieldCapture(v *MeasurementsToActivateValueCodec) *func(s00.MeasurementsToActivate, aper.DecodeState) (s00.MeasurementsToActivate, aper.Snapshot) {
	return &v.capture
}
func BridgeMeasurementsToActivateValueCodecFieldCompare(v *MeasurementsToActivateValueCodec) *func(s00.MeasurementsToActivate, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMeasurementsToActivateValueCodecFieldContext(v *MeasurementsToActivateValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMeasurementsToActivateValueCodecFieldDecode(v *MeasurementsToActivateValueCodec) *func([]byte, aper.DecodeState) (s00.MeasurementsToActivate, error) {
	return &v.decode
}
func BridgeMeasurementsToActivateValueCodecFieldEncode(v *MeasurementsToActivateValueCodec) *func(s00.MeasurementsToActivate, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMeasurementsToActivateValueCodecFieldPath(v *MeasurementsToActivateValueCodec) *aper.Path {
	return &v.path
}
func BridgeMessageIdentifierValueCodecFieldCapture(v *MessageIdentifierValueCodec) *func(s00.MessageIdentifier, aper.DecodeState) (s00.MessageIdentifier, aper.Snapshot) {
	return &v.capture
}
func BridgeMessageIdentifierValueCodecFieldCompare(v *MessageIdentifierValueCodec) *func(s00.MessageIdentifier, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMessageIdentifierValueCodecFieldContext(v *MessageIdentifierValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMessageIdentifierValueCodecFieldDecode(v *MessageIdentifierValueCodec) *func([]byte, aper.DecodeState) (s00.MessageIdentifier, error) {
	return &v.decode
}
func BridgeMessageIdentifierValueCodecFieldEncode(v *MessageIdentifierValueCodec) *func(s00.MessageIdentifier, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMessageIdentifierValueCodecFieldPath(v *MessageIdentifierValueCodec) *aper.Path {
	return &v.path
}
func BridgeMutingAvailabilityIndicationValueCodecFieldCapture(v *MutingAvailabilityIndicationValueCodec) *func(s00.MutingAvailabilityIndication, aper.DecodeState) (s00.MutingAvailabilityIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeMutingAvailabilityIndicationValueCodecFieldCompare(v *MutingAvailabilityIndicationValueCodec) *func(s00.MutingAvailabilityIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeMutingAvailabilityIndicationValueCodecFieldContext(v *MutingAvailabilityIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMutingAvailabilityIndicationValueCodecFieldDecode(v *MutingAvailabilityIndicationValueCodec) *func([]byte, aper.DecodeState) (s00.MutingAvailabilityIndication, error) {
	return &v.decode
}
func BridgeMutingAvailabilityIndicationValueCodecFieldEncode(v *MutingAvailabilityIndicationValueCodec) *func(s00.MutingAvailabilityIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMutingAvailabilityIndicationValueCodecFieldPath(v *MutingAvailabilityIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeNASPDUAPERValueFieldContext(v *NASPDUAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeNASPDUAPERValueFieldReceived(v *NASPDUAPERValue) *aper.WireSpan         { return &v.received }
func BridgeNASPDUAPERValueFieldReplay(v *NASPDUAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeNASPDUValueCodecFieldCapture(v *NASPDUValueCodec) *func(s00.NASPDU, aper.DecodeState) (s00.NASPDU, aper.Snapshot) {
	return &v.capture
}
func BridgeNASPDUValueCodecFieldCompare(v *NASPDUValueCodec) *func(s00.NASPDU, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNASPDUValueCodecFieldContext(v *NASPDUValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASPDUValueCodecFieldDecode(v *NASPDUValueCodec) *func([]byte, aper.DecodeState) (s00.NASPDU, error) {
	return &v.decode
}
func BridgeNASPDUValueCodecFieldEncode(v *NASPDUValueCodec) *func(s00.NASPDU, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNASPDUValueCodecFieldPath(v *NASPDUValueCodec) *aper.Path { return &v.path }
func BridgeNASSecurityParametersfromEUTRANValueCodecFieldCapture(v *NASSecurityParametersfromEUTRANValueCodec) *func(s00.NASSecurityParametersfromEUTRAN, aper.DecodeState) (s00.NASSecurityParametersfromEUTRAN, aper.Snapshot) {
	return &v.capture
}
func BridgeNASSecurityParametersfromEUTRANValueCodecFieldCompare(v *NASSecurityParametersfromEUTRANValueCodec) *func(s00.NASSecurityParametersfromEUTRAN, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNASSecurityParametersfromEUTRANValueCodecFieldContext(v *NASSecurityParametersfromEUTRANValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASSecurityParametersfromEUTRANValueCodecFieldDecode(v *NASSecurityParametersfromEUTRANValueCodec) *func([]byte, aper.DecodeState) (s00.NASSecurityParametersfromEUTRAN, error) {
	return &v.decode
}
func BridgeNASSecurityParametersfromEUTRANValueCodecFieldEncode(v *NASSecurityParametersfromEUTRANValueCodec) *func(s00.NASSecurityParametersfromEUTRAN, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNASSecurityParametersfromEUTRANValueCodecFieldPath(v *NASSecurityParametersfromEUTRANValueCodec) *aper.Path {
	return &v.path
}
func BridgeNASSecurityParameterstoEUTRANValueCodecFieldCapture(v *NASSecurityParameterstoEUTRANValueCodec) *func(s00.NASSecurityParameterstoEUTRAN, aper.DecodeState) (s00.NASSecurityParameterstoEUTRAN, aper.Snapshot) {
	return &v.capture
}
func BridgeNASSecurityParameterstoEUTRANValueCodecFieldCompare(v *NASSecurityParameterstoEUTRANValueCodec) *func(s00.NASSecurityParameterstoEUTRAN, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNASSecurityParameterstoEUTRANValueCodecFieldContext(v *NASSecurityParameterstoEUTRANValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNASSecurityParameterstoEUTRANValueCodecFieldDecode(v *NASSecurityParameterstoEUTRANValueCodec) *func([]byte, aper.DecodeState) (s00.NASSecurityParameterstoEUTRAN, error) {
	return &v.decode
}
func BridgeNASSecurityParameterstoEUTRANValueCodecFieldEncode(v *NASSecurityParameterstoEUTRANValueCodec) *func(s00.NASSecurityParameterstoEUTRAN, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNASSecurityParameterstoEUTRANValueCodecFieldPath(v *NASSecurityParameterstoEUTRANValueCodec) *aper.Path {
	return &v.path
}
func BridgeNBIoTDefaultPagingDRXValueCodecFieldCapture(v *NBIoTDefaultPagingDRXValueCodec) *func(s00.NBIoTDefaultPagingDRX, aper.DecodeState) (s00.NBIoTDefaultPagingDRX, aper.Snapshot) {
	return &v.capture
}
func BridgeNBIoTDefaultPagingDRXValueCodecFieldCompare(v *NBIoTDefaultPagingDRXValueCodec) *func(s00.NBIoTDefaultPagingDRX, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNBIoTDefaultPagingDRXValueCodecFieldContext(v *NBIoTDefaultPagingDRXValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNBIoTDefaultPagingDRXValueCodecFieldDecode(v *NBIoTDefaultPagingDRXValueCodec) *func([]byte, aper.DecodeState) (s00.NBIoTDefaultPagingDRX, error) {
	return &v.decode
}
func BridgeNBIoTDefaultPagingDRXValueCodecFieldEncode(v *NBIoTDefaultPagingDRXValueCodec) *func(s00.NBIoTDefaultPagingDRX, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNBIoTDefaultPagingDRXValueCodecFieldPath(v *NBIoTDefaultPagingDRXValueCodec) *aper.Path {
	return &v.path
}
func BridgeNBIoTPagingDRXValueCodecFieldCapture(v *NBIoTPagingDRXValueCodec) *func(s00.NBIoTPagingDRX, aper.DecodeState) (s00.NBIoTPagingDRX, aper.Snapshot) {
	return &v.capture
}
func BridgeNBIoTPagingDRXValueCodecFieldCompare(v *NBIoTPagingDRXValueCodec) *func(s00.NBIoTPagingDRX, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNBIoTPagingDRXValueCodecFieldContext(v *NBIoTPagingDRXValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNBIoTPagingDRXValueCodecFieldDecode(v *NBIoTPagingDRXValueCodec) *func([]byte, aper.DecodeState) (s00.NBIoTPagingDRX, error) {
	return &v.decode
}
func BridgeNBIoTPagingDRXValueCodecFieldEncode(v *NBIoTPagingDRXValueCodec) *func(s00.NBIoTPagingDRX, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNBIoTPagingDRXValueCodecFieldPath(v *NBIoTPagingDRXValueCodec) *aper.Path { return &v.path }
func BridgeNBIoTPagingEDRXCycleValueCodecFieldCapture(v *NBIoTPagingEDRXCycleValueCodec) *func(s00.NBIoTPagingEDRXCycle, aper.DecodeState) (s00.NBIoTPagingEDRXCycle, aper.Snapshot) {
	return &v.capture
}
func BridgeNBIoTPagingEDRXCycleValueCodecFieldCompare(v *NBIoTPagingEDRXCycleValueCodec) *func(s00.NBIoTPagingEDRXCycle, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNBIoTPagingEDRXCycleValueCodecFieldContext(v *NBIoTPagingEDRXCycleValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNBIoTPagingEDRXCycleValueCodecFieldDecode(v *NBIoTPagingEDRXCycleValueCodec) *func([]byte, aper.DecodeState) (s00.NBIoTPagingEDRXCycle, error) {
	return &v.decode
}
func BridgeNBIoTPagingEDRXCycleValueCodecFieldEncode(v *NBIoTPagingEDRXCycleValueCodec) *func(s00.NBIoTPagingEDRXCycle, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNBIoTPagingEDRXCycleValueCodecFieldPath(v *NBIoTPagingEDRXCycleValueCodec) *aper.Path {
	return &v.path
}
func BridgeNBIoTPagingTimeWindowValueCodecFieldCapture(v *NBIoTPagingTimeWindowValueCodec) *func(s00.NBIoTPagingTimeWindow, aper.DecodeState) (s00.NBIoTPagingTimeWindow, aper.Snapshot) {
	return &v.capture
}
func BridgeNBIoTPagingTimeWindowValueCodecFieldCompare(v *NBIoTPagingTimeWindowValueCodec) *func(s00.NBIoTPagingTimeWindow, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNBIoTPagingTimeWindowValueCodecFieldContext(v *NBIoTPagingTimeWindowValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNBIoTPagingTimeWindowValueCodecFieldDecode(v *NBIoTPagingTimeWindowValueCodec) *func([]byte, aper.DecodeState) (s00.NBIoTPagingTimeWindow, error) {
	return &v.decode
}
func BridgeNBIoTPagingTimeWindowValueCodecFieldEncode(v *NBIoTPagingTimeWindowValueCodec) *func(s00.NBIoTPagingTimeWindow, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNBIoTPagingTimeWindowValueCodecFieldPath(v *NBIoTPagingTimeWindowValueCodec) *aper.Path {
	return &v.path
}
func BridgeNBIoTRLFReportContainerValueCodecFieldCapture(v *NBIoTRLFReportContainerValueCodec) *func(s00.NBIoTRLFReportContainer, aper.DecodeState) (s00.NBIoTRLFReportContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeNBIoTRLFReportContainerValueCodecFieldCompare(v *NBIoTRLFReportContainerValueCodec) *func(s00.NBIoTRLFReportContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNBIoTRLFReportContainerValueCodecFieldContext(v *NBIoTRLFReportContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNBIoTRLFReportContainerValueCodecFieldDecode(v *NBIoTRLFReportContainerValueCodec) *func([]byte, aper.DecodeState) (s00.NBIoTRLFReportContainer, error) {
	return &v.decode
}
func BridgeNBIoTRLFReportContainerValueCodecFieldEncode(v *NBIoTRLFReportContainerValueCodec) *func(s00.NBIoTRLFReportContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNBIoTRLFReportContainerValueCodecFieldPath(v *NBIoTRLFReportContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeNBIoTUEIdentityIndexValueValueCodecFieldCapture(v *NBIoTUEIdentityIndexValueValueCodec) *func(s00.NBIoTUEIdentityIndexValue, aper.DecodeState) (s00.NBIoTUEIdentityIndexValue, aper.Snapshot) {
	return &v.capture
}
func BridgeNBIoTUEIdentityIndexValueValueCodecFieldCompare(v *NBIoTUEIdentityIndexValueValueCodec) *func(s00.NBIoTUEIdentityIndexValue, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNBIoTUEIdentityIndexValueValueCodecFieldContext(v *NBIoTUEIdentityIndexValueValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNBIoTUEIdentityIndexValueValueCodecFieldDecode(v *NBIoTUEIdentityIndexValueValueCodec) *func([]byte, aper.DecodeState) (s00.NBIoTUEIdentityIndexValue, error) {
	return &v.decode
}
func BridgeNBIoTUEIdentityIndexValueValueCodecFieldEncode(v *NBIoTUEIdentityIndexValueValueCodec) *func(s00.NBIoTUEIdentityIndexValue, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNBIoTUEIdentityIndexValueValueCodecFieldPath(v *NBIoTUEIdentityIndexValueValueCodec) *aper.Path {
	return &v.path
}
func BridgeNRCellIdentityValueCodecFieldCapture(v *NRCellIdentityValueCodec) *func(s00.NRCellIdentity, aper.DecodeState) (s00.NRCellIdentity, aper.Snapshot) {
	return &v.capture
}
func BridgeNRCellIdentityValueCodecFieldCompare(v *NRCellIdentityValueCodec) *func(s00.NRCellIdentity, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNRCellIdentityValueCodecFieldContext(v *NRCellIdentityValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNRCellIdentityValueCodecFieldDecode(v *NRCellIdentityValueCodec) *func([]byte, aper.DecodeState) (s00.NRCellIdentity, error) {
	return &v.decode
}
func BridgeNRCellIdentityValueCodecFieldEncode(v *NRCellIdentityValueCodec) *func(s00.NRCellIdentity, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRCellIdentityValueCodecFieldPath(v *NRCellIdentityValueCodec) *aper.Path { return &v.path }
func BridgeNRencryptionAlgorithmsValueCodecFieldCapture(v *NRencryptionAlgorithmsValueCodec) *func(s00.NRencryptionAlgorithms, aper.DecodeState) (s00.NRencryptionAlgorithms, aper.Snapshot) {
	return &v.capture
}
func BridgeNRencryptionAlgorithmsValueCodecFieldCompare(v *NRencryptionAlgorithmsValueCodec) *func(s00.NRencryptionAlgorithms, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNRencryptionAlgorithmsValueCodecFieldContext(v *NRencryptionAlgorithmsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNRencryptionAlgorithmsValueCodecFieldDecode(v *NRencryptionAlgorithmsValueCodec) *func([]byte, aper.DecodeState) (s00.NRencryptionAlgorithms, error) {
	return &v.decode
}
func BridgeNRencryptionAlgorithmsValueCodecFieldEncode(v *NRencryptionAlgorithmsValueCodec) *func(s00.NRencryptionAlgorithms, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRencryptionAlgorithmsValueCodecFieldPath(v *NRencryptionAlgorithmsValueCodec) *aper.Path {
	return &v.path
}
func BridgeNRintegrityProtectionAlgorithmsValueCodecFieldCapture(v *NRintegrityProtectionAlgorithmsValueCodec) *func(s00.NRintegrityProtectionAlgorithms, aper.DecodeState) (s00.NRintegrityProtectionAlgorithms, aper.Snapshot) {
	return &v.capture
}
func BridgeNRintegrityProtectionAlgorithmsValueCodecFieldCompare(v *NRintegrityProtectionAlgorithmsValueCodec) *func(s00.NRintegrityProtectionAlgorithms, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNRintegrityProtectionAlgorithmsValueCodecFieldContext(v *NRintegrityProtectionAlgorithmsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNRintegrityProtectionAlgorithmsValueCodecFieldDecode(v *NRintegrityProtectionAlgorithmsValueCodec) *func([]byte, aper.DecodeState) (s00.NRintegrityProtectionAlgorithms, error) {
	return &v.decode
}
func BridgeNRintegrityProtectionAlgorithmsValueCodecFieldEncode(v *NRintegrityProtectionAlgorithmsValueCodec) *func(s00.NRintegrityProtectionAlgorithms, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRintegrityProtectionAlgorithmsValueCodecFieldPath(v *NRintegrityProtectionAlgorithmsValueCodec) *aper.Path {
	return &v.path
}
func BridgeNRrestrictionin5GSValueCodecFieldCapture(v *NRrestrictionin5GSValueCodec) *func(s00.NRrestrictionin5GS, aper.DecodeState) (s00.NRrestrictionin5GS, aper.Snapshot) {
	return &v.capture
}
func BridgeNRrestrictionin5GSValueCodecFieldCompare(v *NRrestrictionin5GSValueCodec) *func(s00.NRrestrictionin5GS, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNRrestrictionin5GSValueCodecFieldContext(v *NRrestrictionin5GSValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNRrestrictionin5GSValueCodecFieldDecode(v *NRrestrictionin5GSValueCodec) *func([]byte, aper.DecodeState) (s00.NRrestrictionin5GS, error) {
	return &v.decode
}
func BridgeNRrestrictionin5GSValueCodecFieldEncode(v *NRrestrictionin5GSValueCodec) *func(s00.NRrestrictionin5GS, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRrestrictionin5GSValueCodecFieldPath(v *NRrestrictionin5GSValueCodec) *aper.Path {
	return &v.path
}
func BridgeNRrestrictioninEPSasSecondaryRATValueCodecFieldCapture(v *NRrestrictioninEPSasSecondaryRATValueCodec) *func(s00.NRrestrictioninEPSasSecondaryRAT, aper.DecodeState) (s00.NRrestrictioninEPSasSecondaryRAT, aper.Snapshot) {
	return &v.capture
}
func BridgeNRrestrictioninEPSasSecondaryRATValueCodecFieldCompare(v *NRrestrictioninEPSasSecondaryRATValueCodec) *func(s00.NRrestrictioninEPSasSecondaryRAT, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNRrestrictioninEPSasSecondaryRATValueCodecFieldContext(v *NRrestrictioninEPSasSecondaryRATValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNRrestrictioninEPSasSecondaryRATValueCodecFieldDecode(v *NRrestrictioninEPSasSecondaryRATValueCodec) *func([]byte, aper.DecodeState) (s00.NRrestrictioninEPSasSecondaryRAT, error) {
	return &v.decode
}
func BridgeNRrestrictioninEPSasSecondaryRATValueCodecFieldEncode(v *NRrestrictioninEPSasSecondaryRATValueCodec) *func(s00.NRrestrictioninEPSasSecondaryRAT, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNRrestrictioninEPSasSecondaryRATValueCodecFieldPath(v *NRrestrictioninEPSasSecondaryRATValueCodec) *aper.Path {
	return &v.path
}
func BridgeNextPagingAreaScopeValueCodecFieldCapture(v *NextPagingAreaScopeValueCodec) *func(s00.NextPagingAreaScope, aper.DecodeState) (s00.NextPagingAreaScope, aper.Snapshot) {
	return &v.capture
}
func BridgeNextPagingAreaScopeValueCodecFieldCompare(v *NextPagingAreaScopeValueCodec) *func(s00.NextPagingAreaScope, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNextPagingAreaScopeValueCodecFieldContext(v *NextPagingAreaScopeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNextPagingAreaScopeValueCodecFieldDecode(v *NextPagingAreaScopeValueCodec) *func([]byte, aper.DecodeState) (s00.NextPagingAreaScope, error) {
	return &v.decode
}
func BridgeNextPagingAreaScopeValueCodecFieldEncode(v *NextPagingAreaScopeValueCodec) *func(s00.NextPagingAreaScope, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNextPagingAreaScopeValueCodecFieldPath(v *NextPagingAreaScopeValueCodec) *aper.Path {
	return &v.path
}
func BridgeNotifyFlagValueCodecFieldCapture(v *NotifyFlagValueCodec) *func(s00.NotifyFlag, aper.DecodeState) (s00.NotifyFlag, aper.Snapshot) {
	return &v.capture
}
func BridgeNotifyFlagValueCodecFieldCompare(v *NotifyFlagValueCodec) *func(s00.NotifyFlag, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNotifyFlagValueCodecFieldContext(v *NotifyFlagValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNotifyFlagValueCodecFieldDecode(v *NotifyFlagValueCodec) *func([]byte, aper.DecodeState) (s00.NotifyFlag, error) {
	return &v.decode
}
func BridgeNotifyFlagValueCodecFieldEncode(v *NotifyFlagValueCodec) *func(s00.NotifyFlag, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNotifyFlagValueCodecFieldPath(v *NotifyFlagValueCodec) *aper.Path { return &v.path }
func BridgeNotifySourceeNBValueCodecFieldCapture(v *NotifySourceeNBValueCodec) *func(s00.NotifySourceeNB, aper.DecodeState) (s00.NotifySourceeNB, aper.Snapshot) {
	return &v.capture
}
func BridgeNotifySourceeNBValueCodecFieldCompare(v *NotifySourceeNBValueCodec) *func(s00.NotifySourceeNB, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNotifySourceeNBValueCodecFieldContext(v *NotifySourceeNBValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNotifySourceeNBValueCodecFieldDecode(v *NotifySourceeNBValueCodec) *func([]byte, aper.DecodeState) (s00.NotifySourceeNB, error) {
	return &v.decode
}
func BridgeNotifySourceeNBValueCodecFieldEncode(v *NotifySourceeNBValueCodec) *func(s00.NotifySourceeNB, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNotifySourceeNBValueCodecFieldPath(v *NotifySourceeNBValueCodec) *aper.Path {
	return &v.path
}
func BridgeNumberOfBroadcastsValueCodecFieldCapture(v *NumberOfBroadcastsValueCodec) *func(s00.NumberOfBroadcasts, aper.DecodeState) (s00.NumberOfBroadcasts, aper.Snapshot) {
	return &v.capture
}
func BridgeNumberOfBroadcastsValueCodecFieldCompare(v *NumberOfBroadcastsValueCodec) *func(s00.NumberOfBroadcasts, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNumberOfBroadcastsValueCodecFieldContext(v *NumberOfBroadcastsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNumberOfBroadcastsValueCodecFieldDecode(v *NumberOfBroadcastsValueCodec) *func([]byte, aper.DecodeState) (s00.NumberOfBroadcasts, error) {
	return &v.decode
}
func BridgeNumberOfBroadcastsValueCodecFieldEncode(v *NumberOfBroadcastsValueCodec) *func(s00.NumberOfBroadcasts, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNumberOfBroadcastsValueCodecFieldPath(v *NumberOfBroadcastsValueCodec) *aper.Path {
	return &v.path
}
func BridgeNumberOfMeasurementReportingLevelsValueCodecFieldCapture(v *NumberOfMeasurementReportingLevelsValueCodec) *func(s00.NumberOfMeasurementReportingLevels, aper.DecodeState) (s00.NumberOfMeasurementReportingLevels, aper.Snapshot) {
	return &v.capture
}
func BridgeNumberOfMeasurementReportingLevelsValueCodecFieldCompare(v *NumberOfMeasurementReportingLevelsValueCodec) *func(s00.NumberOfMeasurementReportingLevels, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNumberOfMeasurementReportingLevelsValueCodecFieldContext(v *NumberOfMeasurementReportingLevelsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNumberOfMeasurementReportingLevelsValueCodecFieldDecode(v *NumberOfMeasurementReportingLevelsValueCodec) *func([]byte, aper.DecodeState) (s00.NumberOfMeasurementReportingLevels, error) {
	return &v.decode
}
func BridgeNumberOfMeasurementReportingLevelsValueCodecFieldEncode(v *NumberOfMeasurementReportingLevelsValueCodec) *func(s00.NumberOfMeasurementReportingLevels, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNumberOfMeasurementReportingLevelsValueCodecFieldPath(v *NumberOfMeasurementReportingLevelsValueCodec) *aper.Path {
	return &v.path
}
func BridgeNumberofBroadcastRequestValueCodecFieldCapture(v *NumberofBroadcastRequestValueCodec) *func(s00.NumberofBroadcastRequest, aper.DecodeState) (s00.NumberofBroadcastRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeNumberofBroadcastRequestValueCodecFieldCompare(v *NumberofBroadcastRequestValueCodec) *func(s00.NumberofBroadcastRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeNumberofBroadcastRequestValueCodecFieldContext(v *NumberofBroadcastRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNumberofBroadcastRequestValueCodecFieldDecode(v *NumberofBroadcastRequestValueCodec) *func([]byte, aper.DecodeState) (s00.NumberofBroadcastRequest, error) {
	return &v.decode
}
func BridgeNumberofBroadcastRequestValueCodecFieldEncode(v *NumberofBroadcastRequestValueCodec) *func(s00.NumberofBroadcastRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNumberofBroadcastRequestValueCodecFieldPath(v *NumberofBroadcastRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeOldBSSToNewBSSInformationValueCodecFieldCapture(v *OldBSSToNewBSSInformationValueCodec) *func(s00.OldBSSToNewBSSInformation, aper.DecodeState) (s00.OldBSSToNewBSSInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeOldBSSToNewBSSInformationValueCodecFieldCompare(v *OldBSSToNewBSSInformationValueCodec) *func(s00.OldBSSToNewBSSInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeOldBSSToNewBSSInformationValueCodecFieldContext(v *OldBSSToNewBSSInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOldBSSToNewBSSInformationValueCodecFieldDecode(v *OldBSSToNewBSSInformationValueCodec) *func([]byte, aper.DecodeState) (s00.OldBSSToNewBSSInformation, error) {
	return &v.decode
}
func BridgeOldBSSToNewBSSInformationValueCodecFieldEncode(v *OldBSSToNewBSSInformationValueCodec) *func(s00.OldBSSToNewBSSInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOldBSSToNewBSSInformationValueCodecFieldPath(v *OldBSSToNewBSSInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeOverloadActionValueCodecFieldCapture(v *OverloadActionValueCodec) *func(s00.OverloadAction, aper.DecodeState) (s00.OverloadAction, aper.Snapshot) {
	return &v.capture
}
func BridgeOverloadActionValueCodecFieldCompare(v *OverloadActionValueCodec) *func(s00.OverloadAction, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeOverloadActionValueCodecFieldContext(v *OverloadActionValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadActionValueCodecFieldDecode(v *OverloadActionValueCodec) *func([]byte, aper.DecodeState) (s00.OverloadAction, error) {
	return &v.decode
}
func BridgeOverloadActionValueCodecFieldEncode(v *OverloadActionValueCodec) *func(s00.OverloadAction, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOverloadActionValueCodecFieldPath(v *OverloadActionValueCodec) *aper.Path { return &v.path }
func BridgeOverloadFlagValueCodecFieldCapture(v *OverloadFlagValueCodec) *func(s00.OverloadFlag, aper.DecodeState) (s00.OverloadFlag, aper.Snapshot) {
	return &v.capture
}
func BridgeOverloadFlagValueCodecFieldCompare(v *OverloadFlagValueCodec) *func(s00.OverloadFlag, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeOverloadFlagValueCodecFieldContext(v *OverloadFlagValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOverloadFlagValueCodecFieldDecode(v *OverloadFlagValueCodec) *func([]byte, aper.DecodeState) (s00.OverloadFlag, error) {
	return &v.decode
}
func BridgeOverloadFlagValueCodecFieldEncode(v *OverloadFlagValueCodec) *func(s00.OverloadFlag, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOverloadFlagValueCodecFieldPath(v *OverloadFlagValueCodec) *aper.Path { return &v.path }
func BridgePDCPSNExtendedValueCodecFieldCapture(v *PDCPSNExtendedValueCodec) *func(s00.PDCPSNExtended, aper.DecodeState) (s00.PDCPSNExtended, aper.Snapshot) {
	return &v.capture
}
func BridgePDCPSNExtendedValueCodecFieldCompare(v *PDCPSNExtendedValueCodec) *func(s00.PDCPSNExtended, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePDCPSNExtendedValueCodecFieldContext(v *PDCPSNExtendedValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePDCPSNExtendedValueCodecFieldDecode(v *PDCPSNExtendedValueCodec) *func([]byte, aper.DecodeState) (s00.PDCPSNExtended, error) {
	return &v.decode
}
func BridgePDCPSNExtendedValueCodecFieldEncode(v *PDCPSNExtendedValueCodec) *func(s00.PDCPSNExtended, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePDCPSNExtendedValueCodecFieldPath(v *PDCPSNExtendedValueCodec) *aper.Path { return &v.path }
func BridgePDCPSNValueCodecFieldCapture(v *PDCPSNValueCodec) *func(s00.PDCPSN, aper.DecodeState) (s00.PDCPSN, aper.Snapshot) {
	return &v.capture
}
func BridgePDCPSNValueCodecFieldCompare(v *PDCPSNValueCodec) *func(s00.PDCPSN, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePDCPSNValueCodecFieldContext(v *PDCPSNValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePDCPSNValueCodecFieldDecode(v *PDCPSNValueCodec) *func([]byte, aper.DecodeState) (s00.PDCPSN, error) {
	return &v.decode
}
func BridgePDCPSNValueCodecFieldEncode(v *PDCPSNValueCodec) *func(s00.PDCPSN, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePDCPSNValueCodecFieldPath(v *PDCPSNValueCodec) *aper.Path { return &v.path }
func BridgePDCPSNlength18ValueCodecFieldCapture(v *PDCPSNlength18ValueCodec) *func(s00.PDCPSNlength18, aper.DecodeState) (s00.PDCPSNlength18, aper.Snapshot) {
	return &v.capture
}
func BridgePDCPSNlength18ValueCodecFieldCompare(v *PDCPSNlength18ValueCodec) *func(s00.PDCPSNlength18, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePDCPSNlength18ValueCodecFieldContext(v *PDCPSNlength18ValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePDCPSNlength18ValueCodecFieldDecode(v *PDCPSNlength18ValueCodec) *func([]byte, aper.DecodeState) (s00.PDCPSNlength18, error) {
	return &v.decode
}
func BridgePDCPSNlength18ValueCodecFieldEncode(v *PDCPSNlength18ValueCodec) *func(s00.PDCPSNlength18, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePDCPSNlength18ValueCodecFieldPath(v *PDCPSNlength18ValueCodec) *aper.Path { return &v.path }
func BridgePLMNListforQMCValueCodecFieldCapture(v *PLMNListforQMCValueCodec) *func(s00.PLMNListforQMC, aper.DecodeState) (s00.PLMNListforQMC, aper.Snapshot) {
	return &v.capture
}
func BridgePLMNListforQMCValueCodecFieldCompare(v *PLMNListforQMCValueCodec) *func(s00.PLMNListforQMC, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePLMNListforQMCValueCodecFieldContext(v *PLMNListforQMCValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePLMNListforQMCValueCodecFieldDecode(v *PLMNListforQMCValueCodec) *func([]byte, aper.DecodeState) (s00.PLMNListforQMC, error) {
	return &v.decode
}
func BridgePLMNListforQMCValueCodecFieldEncode(v *PLMNListforQMCValueCodec) *func(s00.PLMNListforQMC, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePLMNListforQMCValueCodecFieldPath(v *PLMNListforQMCValueCodec) *aper.Path { return &v.path }
func BridgePLMNidentityAPERValueFieldContext(v *PLMNidentityAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePLMNidentityAPERValueFieldReceived(v *PLMNidentityAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePLMNidentityAPERValueFieldReplay(v *PLMNidentityAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePLMNidentityValueCodecFieldCapture(v *PLMNidentityValueCodec) *func(s00.PLMNidentity, aper.DecodeState) (s00.PLMNidentity, aper.Snapshot) {
	return &v.capture
}
func BridgePLMNidentityValueCodecFieldCompare(v *PLMNidentityValueCodec) *func(s00.PLMNidentity, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePLMNidentityValueCodecFieldContext(v *PLMNidentityValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePLMNidentityValueCodecFieldDecode(v *PLMNidentityValueCodec) *func([]byte, aper.DecodeState) (s00.PLMNidentity, error) {
	return &v.decode
}
func BridgePLMNidentityValueCodecFieldEncode(v *PLMNidentityValueCodec) *func(s00.PLMNidentity, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePLMNidentityValueCodecFieldPath(v *PLMNidentityValueCodec) *aper.Path { return &v.path }
func BridgePSServiceNotAvailableValueCodecFieldCapture(v *PSServiceNotAvailableValueCodec) *func(s00.PSServiceNotAvailable, aper.DecodeState) (s00.PSServiceNotAvailable, aper.Snapshot) {
	return &v.capture
}
func BridgePSServiceNotAvailableValueCodecFieldCompare(v *PSServiceNotAvailableValueCodec) *func(s00.PSServiceNotAvailable, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePSServiceNotAvailableValueCodecFieldContext(v *PSServiceNotAvailableValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePSServiceNotAvailableValueCodecFieldDecode(v *PSServiceNotAvailableValueCodec) *func([]byte, aper.DecodeState) (s00.PSServiceNotAvailable, error) {
	return &v.decode
}
func BridgePSServiceNotAvailableValueCodecFieldEncode(v *PSServiceNotAvailableValueCodec) *func(s00.PSServiceNotAvailable, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePSServiceNotAvailableValueCodecFieldPath(v *PSServiceNotAvailableValueCodec) *aper.Path {
	return &v.path
}
func BridgePacketLossRateValueCodecFieldCapture(v *PacketLossRateValueCodec) *func(s00.PacketLossRate, aper.DecodeState) (s00.PacketLossRate, aper.Snapshot) {
	return &v.capture
}
func BridgePacketLossRateValueCodecFieldCompare(v *PacketLossRateValueCodec) *func(s00.PacketLossRate, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePacketLossRateValueCodecFieldContext(v *PacketLossRateValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePacketLossRateValueCodecFieldDecode(v *PacketLossRateValueCodec) *func([]byte, aper.DecodeState) (s00.PacketLossRate, error) {
	return &v.decode
}
func BridgePacketLossRateValueCodecFieldEncode(v *PacketLossRateValueCodec) *func(s00.PacketLossRate, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePacketLossRateValueCodecFieldPath(v *PacketLossRateValueCodec) *aper.Path { return &v.path }
func BridgePagingAttemptCountValueCodecFieldCapture(v *PagingAttemptCountValueCodec) *func(s00.PagingAttemptCount, aper.DecodeState) (s00.PagingAttemptCount, aper.Snapshot) {
	return &v.capture
}
func BridgePagingAttemptCountValueCodecFieldCompare(v *PagingAttemptCountValueCodec) *func(s00.PagingAttemptCount, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingAttemptCountValueCodecFieldContext(v *PagingAttemptCountValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingAttemptCountValueCodecFieldDecode(v *PagingAttemptCountValueCodec) *func([]byte, aper.DecodeState) (s00.PagingAttemptCount, error) {
	return &v.decode
}
func BridgePagingAttemptCountValueCodecFieldEncode(v *PagingAttemptCountValueCodec) *func(s00.PagingAttemptCount, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingAttemptCountValueCodecFieldPath(v *PagingAttemptCountValueCodec) *aper.Path {
	return &v.path
}
func BridgePagingCauseValueCodecFieldCapture(v *PagingCauseValueCodec) *func(s00.PagingCause, aper.DecodeState) (s00.PagingCause, aper.Snapshot) {
	return &v.capture
}
func BridgePagingCauseValueCodecFieldCompare(v *PagingCauseValueCodec) *func(s00.PagingCause, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingCauseValueCodecFieldContext(v *PagingCauseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingCauseValueCodecFieldDecode(v *PagingCauseValueCodec) *func([]byte, aper.DecodeState) (s00.PagingCause, error) {
	return &v.decode
}
func BridgePagingCauseValueCodecFieldEncode(v *PagingCauseValueCodec) *func(s00.PagingCause, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingCauseValueCodecFieldPath(v *PagingCauseValueCodec) *aper.Path { return &v.path }
func BridgePagingDRXValueCodecFieldCapture(v *PagingDRXValueCodec) *func(s00.PagingDRX, aper.DecodeState) (s00.PagingDRX, aper.Snapshot) {
	return &v.capture
}
func BridgePagingDRXValueCodecFieldCompare(v *PagingDRXValueCodec) *func(s00.PagingDRX, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingDRXValueCodecFieldContext(v *PagingDRXValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingDRXValueCodecFieldDecode(v *PagingDRXValueCodec) *func([]byte, aper.DecodeState) (s00.PagingDRX, error) {
	return &v.decode
}
func BridgePagingDRXValueCodecFieldEncode(v *PagingDRXValueCodec) *func(s00.PagingDRX, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingDRXValueCodecFieldPath(v *PagingDRXValueCodec) *aper.Path { return &v.path }
func BridgePagingEDRXCycleValueCodecFieldCapture(v *PagingEDRXCycleValueCodec) *func(s00.PagingEDRXCycle, aper.DecodeState) (s00.PagingEDRXCycle, aper.Snapshot) {
	return &v.capture
}
func BridgePagingEDRXCycleValueCodecFieldCompare(v *PagingEDRXCycleValueCodec) *func(s00.PagingEDRXCycle, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingEDRXCycleValueCodecFieldContext(v *PagingEDRXCycleValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingEDRXCycleValueCodecFieldDecode(v *PagingEDRXCycleValueCodec) *func([]byte, aper.DecodeState) (s00.PagingEDRXCycle, error) {
	return &v.decode
}
func BridgePagingEDRXCycleValueCodecFieldEncode(v *PagingEDRXCycleValueCodec) *func(s00.PagingEDRXCycle, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingEDRXCycleValueCodecFieldPath(v *PagingEDRXCycleValueCodec) *aper.Path {
	return &v.path
}
func BridgePagingPriorityValueCodecFieldCapture(v *PagingPriorityValueCodec) *func(s00.PagingPriority, aper.DecodeState) (s00.PagingPriority, aper.Snapshot) {
	return &v.capture
}
func BridgePagingPriorityValueCodecFieldCompare(v *PagingPriorityValueCodec) *func(s00.PagingPriority, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingPriorityValueCodecFieldContext(v *PagingPriorityValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingPriorityValueCodecFieldDecode(v *PagingPriorityValueCodec) *func([]byte, aper.DecodeState) (s00.PagingPriority, error) {
	return &v.decode
}
func BridgePagingPriorityValueCodecFieldEncode(v *PagingPriorityValueCodec) *func(s00.PagingPriority, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingPriorityValueCodecFieldPath(v *PagingPriorityValueCodec) *aper.Path { return &v.path }
func BridgePagingProbabilityInformationValueCodecFieldCapture(v *PagingProbabilityInformationValueCodec) *func(s00.PagingProbabilityInformation, aper.DecodeState) (s00.PagingProbabilityInformation, aper.Snapshot) {
	return &v.capture
}
func BridgePagingProbabilityInformationValueCodecFieldCompare(v *PagingProbabilityInformationValueCodec) *func(s00.PagingProbabilityInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingProbabilityInformationValueCodecFieldContext(v *PagingProbabilityInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingProbabilityInformationValueCodecFieldDecode(v *PagingProbabilityInformationValueCodec) *func([]byte, aper.DecodeState) (s00.PagingProbabilityInformation, error) {
	return &v.decode
}
func BridgePagingProbabilityInformationValueCodecFieldEncode(v *PagingProbabilityInformationValueCodec) *func(s00.PagingProbabilityInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingProbabilityInformationValueCodecFieldPath(v *PagingProbabilityInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgePagingTimeWindowValueCodecFieldCapture(v *PagingTimeWindowValueCodec) *func(s00.PagingTimeWindow, aper.DecodeState) (s00.PagingTimeWindow, aper.Snapshot) {
	return &v.capture
}
func BridgePagingTimeWindowValueCodecFieldCompare(v *PagingTimeWindowValueCodec) *func(s00.PagingTimeWindow, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePagingTimeWindowValueCodecFieldContext(v *PagingTimeWindowValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePagingTimeWindowValueCodecFieldDecode(v *PagingTimeWindowValueCodec) *func([]byte, aper.DecodeState) (s00.PagingTimeWindow, error) {
	return &v.decode
}
func BridgePagingTimeWindowValueCodecFieldEncode(v *PagingTimeWindowValueCodec) *func(s00.PagingTimeWindow, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePagingTimeWindowValueCodecFieldPath(v *PagingTimeWindowValueCodec) *aper.Path {
	return &v.path
}
func BridgePedestrianUEValueCodecFieldCapture(v *PedestrianUEValueCodec) *func(s00.PedestrianUE, aper.DecodeState) (s00.PedestrianUE, aper.Snapshot) {
	return &v.capture
}
func BridgePedestrianUEValueCodecFieldCompare(v *PedestrianUEValueCodec) *func(s00.PedestrianUE, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePedestrianUEValueCodecFieldContext(v *PedestrianUEValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePedestrianUEValueCodecFieldDecode(v *PedestrianUEValueCodec) *func([]byte, aper.DecodeState) (s00.PedestrianUE, error) {
	return &v.decode
}
func BridgePedestrianUEValueCodecFieldEncode(v *PedestrianUEValueCodec) *func(s00.PedestrianUE, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePedestrianUEValueCodecFieldPath(v *PedestrianUEValueCodec) *aper.Path { return &v.path }
func BridgePendingDataIndicationValueCodecFieldCapture(v *PendingDataIndicationValueCodec) *func(s00.PendingDataIndication, aper.DecodeState) (s00.PendingDataIndication, aper.Snapshot) {
	return &v.capture
}
func BridgePendingDataIndicationValueCodecFieldCompare(v *PendingDataIndicationValueCodec) *func(s00.PendingDataIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePendingDataIndicationValueCodecFieldContext(v *PendingDataIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePendingDataIndicationValueCodecFieldDecode(v *PendingDataIndicationValueCodec) *func([]byte, aper.DecodeState) (s00.PendingDataIndication, error) {
	return &v.decode
}
func BridgePendingDataIndicationValueCodecFieldEncode(v *PendingDataIndicationValueCodec) *func(s00.PendingDataIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePendingDataIndicationValueCodecFieldPath(v *PendingDataIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgePortNumberValueCodecFieldCapture(v *PortNumberValueCodec) *func(s00.PortNumber, aper.DecodeState) (s00.PortNumber, aper.Snapshot) {
	return &v.capture
}
func BridgePortNumberValueCodecFieldCompare(v *PortNumberValueCodec) *func(s00.PortNumber, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePortNumberValueCodecFieldContext(v *PortNumberValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePortNumberValueCodecFieldDecode(v *PortNumberValueCodec) *func([]byte, aper.DecodeState) (s00.PortNumber, error) {
	return &v.decode
}
func BridgePortNumberValueCodecFieldEncode(v *PortNumberValueCodec) *func(s00.PortNumber, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePortNumberValueCodecFieldPath(v *PortNumberValueCodec) *aper.Path { return &v.path }
func BridgePreEmptionCapabilityValueCodecFieldCapture(v *PreEmptionCapabilityValueCodec) *func(s00.PreEmptionCapability, aper.DecodeState) (s00.PreEmptionCapability, aper.Snapshot) {
	return &v.capture
}
func BridgePreEmptionCapabilityValueCodecFieldCompare(v *PreEmptionCapabilityValueCodec) *func(s00.PreEmptionCapability, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePreEmptionCapabilityValueCodecFieldContext(v *PreEmptionCapabilityValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePreEmptionCapabilityValueCodecFieldDecode(v *PreEmptionCapabilityValueCodec) *func([]byte, aper.DecodeState) (s00.PreEmptionCapability, error) {
	return &v.decode
}
func BridgePreEmptionCapabilityValueCodecFieldEncode(v *PreEmptionCapabilityValueCodec) *func(s00.PreEmptionCapability, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePreEmptionCapabilityValueCodecFieldPath(v *PreEmptionCapabilityValueCodec) *aper.Path {
	return &v.path
}
func BridgePreEmptionVulnerabilityValueCodecFieldCapture(v *PreEmptionVulnerabilityValueCodec) *func(s00.PreEmptionVulnerability, aper.DecodeState) (s00.PreEmptionVulnerability, aper.Snapshot) {
	return &v.capture
}
func BridgePreEmptionVulnerabilityValueCodecFieldCompare(v *PreEmptionVulnerabilityValueCodec) *func(s00.PreEmptionVulnerability, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePreEmptionVulnerabilityValueCodecFieldContext(v *PreEmptionVulnerabilityValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePreEmptionVulnerabilityValueCodecFieldDecode(v *PreEmptionVulnerabilityValueCodec) *func([]byte, aper.DecodeState) (s00.PreEmptionVulnerability, error) {
	return &v.decode
}
func BridgePreEmptionVulnerabilityValueCodecFieldEncode(v *PreEmptionVulnerabilityValueCodec) *func(s00.PreEmptionVulnerability, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePreEmptionVulnerabilityValueCodecFieldPath(v *PreEmptionVulnerabilityValueCodec) *aper.Path {
	return &v.path
}
func BridgePresenceValueCodecFieldCapture(v *PresenceValueCodec) *func(s00.Presence, aper.DecodeState) (s00.Presence, aper.Snapshot) {
	return &v.capture
}
func BridgePresenceValueCodecFieldCompare(v *PresenceValueCodec) *func(s00.Presence, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePresenceValueCodecFieldContext(v *PresenceValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePresenceValueCodecFieldDecode(v *PresenceValueCodec) *func([]byte, aper.DecodeState) (s00.Presence, error) {
	return &v.decode
}
func BridgePresenceValueCodecFieldEncode(v *PresenceValueCodec) *func(s00.Presence, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePresenceValueCodecFieldPath(v *PresenceValueCodec) *aper.Path { return &v.path }
func BridgePriorityLevelValueCodecFieldCapture(v *PriorityLevelValueCodec) *func(s00.PriorityLevel, aper.DecodeState) (s00.PriorityLevel, aper.Snapshot) {
	return &v.capture
}
func BridgePriorityLevelValueCodecFieldCompare(v *PriorityLevelValueCodec) *func(s00.PriorityLevel, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePriorityLevelValueCodecFieldContext(v *PriorityLevelValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePriorityLevelValueCodecFieldDecode(v *PriorityLevelValueCodec) *func([]byte, aper.DecodeState) (s00.PriorityLevel, error) {
	return &v.decode
}
func BridgePriorityLevelValueCodecFieldEncode(v *PriorityLevelValueCodec) *func(s00.PriorityLevel, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePriorityLevelValueCodecFieldPath(v *PriorityLevelValueCodec) *aper.Path { return &v.path }
func BridgePrivacyIndicatorValueCodecFieldCapture(v *PrivacyIndicatorValueCodec) *func(s00.PrivacyIndicator, aper.DecodeState) (s00.PrivacyIndicator, aper.Snapshot) {
	return &v.capture
}
func BridgePrivacyIndicatorValueCodecFieldCompare(v *PrivacyIndicatorValueCodec) *func(s00.PrivacyIndicator, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgePrivacyIndicatorValueCodecFieldContext(v *PrivacyIndicatorValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePrivacyIndicatorValueCodecFieldDecode(v *PrivacyIndicatorValueCodec) *func([]byte, aper.DecodeState) (s00.PrivacyIndicator, error) {
	return &v.decode
}
func BridgePrivacyIndicatorValueCodecFieldEncode(v *PrivacyIndicatorValueCodec) *func(s00.PrivacyIndicator, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePrivacyIndicatorValueCodecFieldPath(v *PrivacyIndicatorValueCodec) *aper.Path {
	return &v.path
}
func BridgeProSeDirectCommunicationValueCodecFieldCapture(v *ProSeDirectCommunicationValueCodec) *func(s00.ProSeDirectCommunication, aper.DecodeState) (s00.ProSeDirectCommunication, aper.Snapshot) {
	return &v.capture
}
func BridgeProSeDirectCommunicationValueCodecFieldCompare(v *ProSeDirectCommunicationValueCodec) *func(s00.ProSeDirectCommunication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeProSeDirectCommunicationValueCodecFieldContext(v *ProSeDirectCommunicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeProSeDirectCommunicationValueCodecFieldDecode(v *ProSeDirectCommunicationValueCodec) *func([]byte, aper.DecodeState) (s00.ProSeDirectCommunication, error) {
	return &v.decode
}
func BridgeProSeDirectCommunicationValueCodecFieldEncode(v *ProSeDirectCommunicationValueCodec) *func(s00.ProSeDirectCommunication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeProSeDirectCommunicationValueCodecFieldPath(v *ProSeDirectCommunicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeProSeDirectDiscoveryValueCodecFieldCapture(v *ProSeDirectDiscoveryValueCodec) *func(s00.ProSeDirectDiscovery, aper.DecodeState) (s00.ProSeDirectDiscovery, aper.Snapshot) {
	return &v.capture
}
func BridgeProSeDirectDiscoveryValueCodecFieldCompare(v *ProSeDirectDiscoveryValueCodec) *func(s00.ProSeDirectDiscovery, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeProSeDirectDiscoveryValueCodecFieldContext(v *ProSeDirectDiscoveryValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeProSeDirectDiscoveryValueCodecFieldDecode(v *ProSeDirectDiscoveryValueCodec) *func([]byte, aper.DecodeState) (s00.ProSeDirectDiscovery, error) {
	return &v.decode
}
func BridgeProSeDirectDiscoveryValueCodecFieldEncode(v *ProSeDirectDiscoveryValueCodec) *func(s00.ProSeDirectDiscovery, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeProSeDirectDiscoveryValueCodecFieldPath(v *ProSeDirectDiscoveryValueCodec) *aper.Path {
	return &v.path
}
func BridgeProSeUEtoNetworkRelayingValueCodecFieldCapture(v *ProSeUEtoNetworkRelayingValueCodec) *func(s00.ProSeUEtoNetworkRelaying, aper.DecodeState) (s00.ProSeUEtoNetworkRelaying, aper.Snapshot) {
	return &v.capture
}
func BridgeProSeUEtoNetworkRelayingValueCodecFieldCompare(v *ProSeUEtoNetworkRelayingValueCodec) *func(s00.ProSeUEtoNetworkRelaying, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeProSeUEtoNetworkRelayingValueCodecFieldContext(v *ProSeUEtoNetworkRelayingValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeProSeUEtoNetworkRelayingValueCodecFieldDecode(v *ProSeUEtoNetworkRelayingValueCodec) *func([]byte, aper.DecodeState) (s00.ProSeUEtoNetworkRelaying, error) {
	return &v.decode
}
func BridgeProSeUEtoNetworkRelayingValueCodecFieldEncode(v *ProSeUEtoNetworkRelayingValueCodec) *func(s00.ProSeUEtoNetworkRelaying, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeProSeUEtoNetworkRelayingValueCodecFieldPath(v *ProSeUEtoNetworkRelayingValueCodec) *aper.Path {
	return &v.path
}
func BridgeProcedureCodeValueCodecFieldCapture(v *ProcedureCodeValueCodec) *func(s00.ProcedureCode, aper.DecodeState) (s00.ProcedureCode, aper.Snapshot) {
	return &v.capture
}
func BridgeProcedureCodeValueCodecFieldCompare(v *ProcedureCodeValueCodec) *func(s00.ProcedureCode, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeProcedureCodeValueCodecFieldContext(v *ProcedureCodeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeProcedureCodeValueCodecFieldDecode(v *ProcedureCodeValueCodec) *func([]byte, aper.DecodeState) (s00.ProcedureCode, error) {
	return &v.decode
}
func BridgeProcedureCodeValueCodecFieldEncode(v *ProcedureCodeValueCodec) *func(s00.ProcedureCode, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeProcedureCodeValueCodecFieldPath(v *ProcedureCodeValueCodec) *aper.Path { return &v.path }
func BridgeProtocolExtensionIDValueCodecFieldCapture(v *ProtocolExtensionIDValueCodec) *func(s00.ProtocolExtensionID, aper.DecodeState) (s00.ProtocolExtensionID, aper.Snapshot) {
	return &v.capture
}
func BridgeProtocolExtensionIDValueCodecFieldCompare(v *ProtocolExtensionIDValueCodec) *func(s00.ProtocolExtensionID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeProtocolExtensionIDValueCodecFieldContext(v *ProtocolExtensionIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeProtocolExtensionIDValueCodecFieldDecode(v *ProtocolExtensionIDValueCodec) *func([]byte, aper.DecodeState) (s00.ProtocolExtensionID, error) {
	return &v.decode
}
func BridgeProtocolExtensionIDValueCodecFieldEncode(v *ProtocolExtensionIDValueCodec) *func(s00.ProtocolExtensionID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeProtocolExtensionIDValueCodecFieldPath(v *ProtocolExtensionIDValueCodec) *aper.Path {
	return &v.path
}
func BridgeProtocolIEIDValueCodecFieldCapture(v *ProtocolIEIDValueCodec) *func(s00.ProtocolIEID, aper.DecodeState) (s00.ProtocolIEID, aper.Snapshot) {
	return &v.capture
}
func BridgeProtocolIEIDValueCodecFieldCompare(v *ProtocolIEIDValueCodec) *func(s00.ProtocolIEID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeProtocolIEIDValueCodecFieldContext(v *ProtocolIEIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeProtocolIEIDValueCodecFieldDecode(v *ProtocolIEIDValueCodec) *func([]byte, aper.DecodeState) (s00.ProtocolIEID, error) {
	return &v.decode
}
func BridgeProtocolIEIDValueCodecFieldEncode(v *ProtocolIEIDValueCodec) *func(s00.ProtocolIEID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeProtocolIEIDValueCodecFieldPath(v *ProtocolIEIDValueCodec) *aper.Path { return &v.path }
func BridgeQCIValueCodecFieldCapture(v *QCIValueCodec) *func(s00.QCI, aper.DecodeState) (s00.QCI, aper.Snapshot) {
	return &v.capture
}
func BridgeQCIValueCodecFieldCompare(v *QCIValueCodec) *func(s00.QCI, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeQCIValueCodecFieldContext(v *QCIValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeQCIValueCodecFieldDecode(v *QCIValueCodec) *func([]byte, aper.DecodeState) (s00.QCI, error) {
	return &v.decode
}
func BridgeQCIValueCodecFieldEncode(v *QCIValueCodec) *func(s00.QCI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeQCIValueCodecFieldPath(v *QCIValueCodec) *aper.Path { return &v.path }
func BridgeRACSIndicationValueCodecFieldCapture(v *RACSIndicationValueCodec) *func(s00.RACSIndication, aper.DecodeState) (s00.RACSIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeRACSIndicationValueCodecFieldCompare(v *RACSIndicationValueCodec) *func(s00.RACSIndication, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRACSIndicationValueCodecFieldContext(v *RACSIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRACSIndicationValueCodecFieldDecode(v *RACSIndicationValueCodec) *func([]byte, aper.DecodeState) (s00.RACSIndication, error) {
	return &v.decode
}
func BridgeRACSIndicationValueCodecFieldEncode(v *RACSIndicationValueCodec) *func(s00.RACSIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRACSIndicationValueCodecFieldPath(v *RACSIndicationValueCodec) *aper.Path { return &v.path }
func BridgeRACValueCodecFieldCapture(v *RACValueCodec) *func(s00.RAC, aper.DecodeState) (s00.RAC, aper.Snapshot) {
	return &v.capture
}
func BridgeRACValueCodecFieldCompare(v *RACValueCodec) *func(s00.RAC, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRACValueCodecFieldContext(v *RACValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeRACValueCodecFieldDecode(v *RACValueCodec) *func([]byte, aper.DecodeState) (s00.RAC, error) {
	return &v.decode
}
func BridgeRACValueCodecFieldEncode(v *RACValueCodec) *func(s00.RAC, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRACValueCodecFieldPath(v *RACValueCodec) *aper.Path { return &v.path }
func BridgeRANUENGAPIDValueCodecFieldCapture(v *RANUENGAPIDValueCodec) *func(s00.RANUENGAPID, aper.DecodeState) (s00.RANUENGAPID, aper.Snapshot) {
	return &v.capture
}
func BridgeRANUENGAPIDValueCodecFieldCompare(v *RANUENGAPIDValueCodec) *func(s00.RANUENGAPID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRANUENGAPIDValueCodecFieldContext(v *RANUENGAPIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRANUENGAPIDValueCodecFieldDecode(v *RANUENGAPIDValueCodec) *func([]byte, aper.DecodeState) (s00.RANUENGAPID, error) {
	return &v.decode
}
func BridgeRANUENGAPIDValueCodecFieldEncode(v *RANUENGAPIDValueCodec) *func(s00.RANUENGAPID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRANUENGAPIDValueCodecFieldPath(v *RANUENGAPIDValueCodec) *aper.Path { return &v.path }
func BridgeRATTypeValueCodecFieldCapture(v *RATTypeValueCodec) *func(s00.RATType, aper.DecodeState) (s00.RATType, aper.Snapshot) {
	return &v.capture
}
func BridgeRATTypeValueCodecFieldCompare(v *RATTypeValueCodec) *func(s00.RATType, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRATTypeValueCodecFieldContext(v *RATTypeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRATTypeValueCodecFieldDecode(v *RATTypeValueCodec) *func([]byte, aper.DecodeState) (s00.RATType, error) {
	return &v.decode
}
func BridgeRATTypeValueCodecFieldEncode(v *RATTypeValueCodec) *func(s00.RATType, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRATTypeValueCodecFieldPath(v *RATTypeValueCodec) *aper.Path { return &v.path }
func BridgeRIMInformationValueCodecFieldCapture(v *RIMInformationValueCodec) *func(s00.RIMInformation, aper.DecodeState) (s00.RIMInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeRIMInformationValueCodecFieldCompare(v *RIMInformationValueCodec) *func(s00.RIMInformation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRIMInformationValueCodecFieldContext(v *RIMInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRIMInformationValueCodecFieldDecode(v *RIMInformationValueCodec) *func([]byte, aper.DecodeState) (s00.RIMInformation, error) {
	return &v.decode
}
func BridgeRIMInformationValueCodecFieldEncode(v *RIMInformationValueCodec) *func(s00.RIMInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRIMInformationValueCodecFieldPath(v *RIMInformationValueCodec) *aper.Path { return &v.path }
func BridgeRNCIDValueCodecFieldCapture(v *RNCIDValueCodec) *func(s00.RNCID, aper.DecodeState) (s00.RNCID, aper.Snapshot) {
	return &v.capture
}
func BridgeRNCIDValueCodecFieldCompare(v *RNCIDValueCodec) *func(s00.RNCID, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRNCIDValueCodecFieldContext(v *RNCIDValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeRNCIDValueCodecFieldDecode(v *RNCIDValueCodec) *func([]byte, aper.DecodeState) (s00.RNCID, error) {
	return &v.decode
}
func BridgeRNCIDValueCodecFieldEncode(v *RNCIDValueCodec) *func(s00.RNCID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRNCIDValueCodecFieldPath(v *RNCIDValueCodec) *aper.Path { return &v.path }
func BridgeRRCContainerValueCodecFieldCapture(v *RRCContainerValueCodec) *func(s00.RRCContainer, aper.DecodeState) (s00.RRCContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeRRCContainerValueCodecFieldCompare(v *RRCContainerValueCodec) *func(s00.RRCContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRRCContainerValueCodecFieldContext(v *RRCContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRRCContainerValueCodecFieldDecode(v *RRCContainerValueCodec) *func([]byte, aper.DecodeState) (s00.RRCContainer, error) {
	return &v.decode
}
func BridgeRRCContainerValueCodecFieldEncode(v *RRCContainerValueCodec) *func(s00.RRCContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRRCContainerValueCodecFieldPath(v *RRCContainerValueCodec) *aper.Path { return &v.path }
func BridgeRRCEstablishmentCauseValueCodecFieldCapture(v *RRCEstablishmentCauseValueCodec) *func(s00.RRCEstablishmentCause, aper.DecodeState) (s00.RRCEstablishmentCause, aper.Snapshot) {
	return &v.capture
}
func BridgeRRCEstablishmentCauseValueCodecFieldCompare(v *RRCEstablishmentCauseValueCodec) *func(s00.RRCEstablishmentCause, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRRCEstablishmentCauseValueCodecFieldContext(v *RRCEstablishmentCauseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRRCEstablishmentCauseValueCodecFieldDecode(v *RRCEstablishmentCauseValueCodec) *func([]byte, aper.DecodeState) (s00.RRCEstablishmentCause, error) {
	return &v.decode
}
func BridgeRRCEstablishmentCauseValueCodecFieldEncode(v *RRCEstablishmentCauseValueCodec) *func(s00.RRCEstablishmentCause, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRRCEstablishmentCauseValueCodecFieldPath(v *RRCEstablishmentCauseValueCodec) *aper.Path {
	return &v.path
}
func BridgeRangeValueCodecFieldCapture(v *RangeValueCodec) *func(s00.Range, aper.DecodeState) (s00.Range, aper.Snapshot) {
	return &v.capture
}
func BridgeRangeValueCodecFieldCompare(v *RangeValueCodec) *func(s00.Range, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeRangeValueCodecFieldContext(v *RangeValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeRangeValueCodecFieldDecode(v *RangeValueCodec) *func([]byte, aper.DecodeState) (s00.Range, error) {
	return &v.decode
}
func BridgeRangeValueCodecFieldEncode(v *RangeValueCodec) *func(s00.Range, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRangeValueCodecFieldPath(v *RangeValueCodec) *aper.Path { return &v.path }
func BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldCapture(v *ReceiveStatusOfULPDCPSDUsExtendedValueCodec) *func(s00.ReceiveStatusOfULPDCPSDUsExtended, aper.DecodeState) (s00.ReceiveStatusOfULPDCPSDUsExtended, aper.Snapshot) {
	return &v.capture
}
func BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldCompare(v *ReceiveStatusOfULPDCPSDUsExtendedValueCodec) *func(s00.ReceiveStatusOfULPDCPSDUsExtended, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldContext(v *ReceiveStatusOfULPDCPSDUsExtendedValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldDecode(v *ReceiveStatusOfULPDCPSDUsExtendedValueCodec) *func([]byte, aper.DecodeState) (s00.ReceiveStatusOfULPDCPSDUsExtended, error) {
	return &v.decode
}
func BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldEncode(v *ReceiveStatusOfULPDCPSDUsExtendedValueCodec) *func(s00.ReceiveStatusOfULPDCPSDUsExtended, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeReceiveStatusOfULPDCPSDUsExtendedValueCodecFieldPath(v *ReceiveStatusOfULPDCPSDUsExtendedValueCodec) *aper.Path {
	return &v.path
}
func BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldCapture(v *ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec) *func(s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, aper.DecodeState) (s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, aper.Snapshot) {
	return &v.capture
}
func BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldCompare(v *ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec) *func(s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldContext(v *ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldDecode(v *ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec) *func([]byte, aper.DecodeState) (s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, error) {
	return &v.decode
}
func BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldEncode(v *ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec) *func(s00.ReceiveStatusOfULPDCPSDUsPDCPSNlength18, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodecFieldPath(v *ReceiveStatusOfULPDCPSDUsPDCPSNlength18ValueCodec) *aper.Path {
	return &v.path
}
func BridgeReceiveStatusofULPDCPSDUsValueCodecFieldCapture(v *ReceiveStatusofULPDCPSDUsValueCodec) *func(s00.ReceiveStatusofULPDCPSDUs, aper.DecodeState) (s00.ReceiveStatusofULPDCPSDUs, aper.Snapshot) {
	return &v.capture
}
func BridgeReceiveStatusofULPDCPSDUsValueCodecFieldCompare(v *ReceiveStatusofULPDCPSDUsValueCodec) *func(s00.ReceiveStatusofULPDCPSDUs, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeReceiveStatusofULPDCPSDUsValueCodecFieldContext(v *ReceiveStatusofULPDCPSDUsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeReceiveStatusofULPDCPSDUsValueCodecFieldDecode(v *ReceiveStatusofULPDCPSDUsValueCodec) *func([]byte, aper.DecodeState) (s00.ReceiveStatusofULPDCPSDUs, error) {
	return &v.decode
}
func BridgeReceiveStatusofULPDCPSDUsValueCodecFieldEncode(v *ReceiveStatusofULPDCPSDUsValueCodec) *func(s00.ReceiveStatusofULPDCPSDUs, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeReceiveStatusofULPDCPSDUsValueCodecFieldPath(v *ReceiveStatusofULPDCPSDUsValueCodec) *aper.Path {
	return &v.path
}
