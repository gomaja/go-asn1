// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s01 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s01

import (
	q6 "fmt"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// ReportCharacteristicsValueCodec is the concrete ValueCodec[ReportCharacteristics].
type ReportCharacteristicsValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.ReportCharacteristics, q5.DecodeState,

	) (q4.ReportCharacteristics, q5.Snapshot,

	)
	compare func(q4.ReportCharacteristics, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.ReportCharacteristics,

		error)
	encode func(q4.ReportCharacteristics,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c ReportCharacteristicsValueCodec) New(value q4.ReportCharacteristics,

) (ReportCharacteristicsAPERValue, error) {
	if c.encode == nil {
		return ReportCharacteristicsAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return ReportCharacteristicsAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ReportCharacteristicsAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return ReportCharacteristicsAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c ReportCharacteristicsValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (ReportCharacteristicsAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ReportCharacteristicsAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return ReportCharacteristicsAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ReportCharacteristicsAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return ReportCharacteristicsAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return ReportCharacteristicsAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ReportCharacteristicsValueCodec) EncodeAPER(value ReportCharacteristicsAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c ReportCharacteristicsValueCodec) encodeBudget(value q4.ReportCharacteristics,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ReportCharacteristicsValueCodec) encodeChanged(value q4.ReportCharacteristics,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// NumberOfFrequencyHoppingBandsValueCodec is the concrete ValueCodec[NumberOfFrequencyHoppingBands].
type NumberOfFrequencyHoppingBandsValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.NumberOfFrequencyHoppingBands, q5.DecodeState,

	) (q4.NumberOfFrequencyHoppingBands, q5.Snapshot,

	)
	compare func(q4.NumberOfFrequencyHoppingBands, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.NumberOfFrequencyHoppingBands,

		error)
	encode func(q4.NumberOfFrequencyHoppingBands,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c NumberOfFrequencyHoppingBandsValueCodec) New(value q4.NumberOfFrequencyHoppingBands,

) (NumberOfFrequencyHoppingBandsAPERValue, error) {
	if c.encode == nil {
		return NumberOfFrequencyHoppingBandsAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return NumberOfFrequencyHoppingBandsAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NumberOfFrequencyHoppingBandsAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return NumberOfFrequencyHoppingBandsAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c NumberOfFrequencyHoppingBandsValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (NumberOfFrequencyHoppingBandsAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NumberOfFrequencyHoppingBandsAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return NumberOfFrequencyHoppingBandsAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NumberOfFrequencyHoppingBandsAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return NumberOfFrequencyHoppingBandsAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return NumberOfFrequencyHoppingBandsAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c NumberOfFrequencyHoppingBandsValueCodec) EncodeAPER(value NumberOfFrequencyHoppingBandsAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c NumberOfFrequencyHoppingBandsValueCodec) encodeBudget(value q4.NumberOfFrequencyHoppingBands,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NumberOfFrequencyHoppingBandsValueCodec) encodeChanged(value q4.NumberOfFrequencyHoppingBands,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// OTDOAInformationItemValueCodec is the concrete ValueCodec[OTDOAInformationItem].
type OTDOAInformationItemValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.OTDOAInformationItem, q5.DecodeState,

	) (q4.OTDOAInformationItem, q5.Snapshot,

	)
	compare func(q4.OTDOAInformationItem, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.OTDOAInformationItem,

		error)
	encode func(q4.OTDOAInformationItem,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c OTDOAInformationItemValueCodec) New(value q4.OTDOAInformationItem,

) (OTDOAInformationItemAPERValue, error) {
	if c.encode == nil {
		return OTDOAInformationItemAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return OTDOAInformationItemAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOAInformationItemAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return OTDOAInformationItemAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c OTDOAInformationItemValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (OTDOAInformationItemAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOAInformationItemAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return OTDOAInformationItemAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOAInformationItemAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return OTDOAInformationItemAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return OTDOAInformationItemAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c OTDOAInformationItemValueCodec) EncodeAPER(value OTDOAInformationItemAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c OTDOAInformationItemValueCodec) encodeBudget(value q4.OTDOAInformationItem,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOAInformationItemValueCodec) encodeChanged(value q4.OTDOAInformationItem,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// OffsetNBChanneltoEARFCNValueCodec is the concrete ValueCodec[OffsetNBChanneltoEARFCN].
type OffsetNBChanneltoEARFCNValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.OffsetNBChanneltoEARFCN, q5.DecodeState,

	) (q4.OffsetNBChanneltoEARFCN, q5.Snapshot,

	)
	compare func(q4.OffsetNBChanneltoEARFCN, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.OffsetNBChanneltoEARFCN,

		error)
	encode func(q4.OffsetNBChanneltoEARFCN,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c OffsetNBChanneltoEARFCNValueCodec) New(value q4.OffsetNBChanneltoEARFCN,

) (OffsetNBChanneltoEARFCNAPERValue, error) {
	if c.encode == nil {
		return OffsetNBChanneltoEARFCNAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return OffsetNBChanneltoEARFCNAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OffsetNBChanneltoEARFCNAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return OffsetNBChanneltoEARFCNAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c OffsetNBChanneltoEARFCNValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (OffsetNBChanneltoEARFCNAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OffsetNBChanneltoEARFCNAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return OffsetNBChanneltoEARFCNAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OffsetNBChanneltoEARFCNAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return OffsetNBChanneltoEARFCNAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return OffsetNBChanneltoEARFCNAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c OffsetNBChanneltoEARFCNValueCodec) EncodeAPER(value OffsetNBChanneltoEARFCNAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c OffsetNBChanneltoEARFCNValueCodec) encodeBudget(value q4.OffsetNBChanneltoEARFCN,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OffsetNBChanneltoEARFCNValueCodec) encodeChanged(value q4.OffsetNBChanneltoEARFCN,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// OperationModeInfoValueCodec is the concrete ValueCodec[OperationModeInfo].
type OperationModeInfoValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.OperationModeInfo, q5.DecodeState,

	) (q4.OperationModeInfo, q5.Snapshot,

	)
	compare func(q4.OperationModeInfo, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.OperationModeInfo,

		error)
	encode func(q4.OperationModeInfo,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c OperationModeInfoValueCodec) New(value q4.OperationModeInfo,

) (OperationModeInfoAPERValue, error) {
	if c.encode == nil {
		return OperationModeInfoAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return OperationModeInfoAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OperationModeInfoAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return OperationModeInfoAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c OperationModeInfoValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (OperationModeInfoAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OperationModeInfoAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return OperationModeInfoAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OperationModeInfoAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return OperationModeInfoAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return OperationModeInfoAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c OperationModeInfoValueCodec) EncodeAPER(value OperationModeInfoAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c OperationModeInfoValueCodec) encodeBudget(value q4.OperationModeInfo,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OperationModeInfoValueCodec) encodeChanged(value q4.OperationModeInfo,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// OutcomeValueCodec is the concrete ValueCodec[Outcome].
type OutcomeValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.Outcome, q5.DecodeState,

	) (q4.Outcome, q5.Snapshot,

	)
	compare func(q4.Outcome, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.Outcome,

		error)
	encode func(q4.Outcome,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c OutcomeValueCodec) New(value q4.Outcome,

) (OutcomeAPERValue, error) {
	if c.encode == nil {
		return OutcomeAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return OutcomeAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OutcomeAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return OutcomeAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c OutcomeValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (OutcomeAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OutcomeAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return OutcomeAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OutcomeAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return OutcomeAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return OutcomeAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c OutcomeValueCodec) EncodeAPER(value OutcomeAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c OutcomeValueCodec) encodeBudget(value q4.Outcome,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OutcomeValueCodec) encodeChanged(value q4.Outcome,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// PCIValueCodec is the concrete ValueCodec[PCI].
type PCIValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.PCI, q5.DecodeState,

	) (q4.PCI, q5.Snapshot,

	)
	compare func(q4.PCI, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.PCI,

		error)
	encode func(q4.PCI,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c PCIValueCodec) New(value q4.PCI,

) (PCIAPERValue, error) {
	if c.encode == nil {
		return PCIAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return PCIAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PCIAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return PCIAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c PCIValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (PCIAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PCIAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return PCIAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PCIAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return PCIAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return PCIAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PCIValueCodec) EncodeAPER(value PCIAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c PCIValueCodec) encodeBudget(value q4.PCI,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PCIValueCodec) encodeChanged(value q4.PCI,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// PLMNIdentityValueCodec is the concrete ValueCodec[PLMNIdentity].
type PLMNIdentityValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.PLMNIdentity, q5.DecodeState,

	) (q4.PLMNIdentity, q5.Snapshot,

	)
	compare func(q4.PLMNIdentity, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.PLMNIdentity,

		error)
	encode func(q4.PLMNIdentity,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c PLMNIdentityValueCodec) New(value q4.PLMNIdentity,

) (PLMNIdentityAPERValue, error) {
	if c.encode == nil {
		return PLMNIdentityAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return PLMNIdentityAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PLMNIdentityAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return PLMNIdentityAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c PLMNIdentityValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (PLMNIdentityAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PLMNIdentityAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return PLMNIdentityAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PLMNIdentityAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return PLMNIdentityAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return PLMNIdentityAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PLMNIdentityValueCodec) EncodeAPER(value PLMNIdentityAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c PLMNIdentityValueCodec) encodeBudget(value q4.PLMNIdentity,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PLMNIdentityValueCodec) encodeChanged(value q4.PLMNIdentity,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// PRSBandwidthValueCodec is the concrete ValueCodec[PRSBandwidth].
type PRSBandwidthValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.PRSBandwidth, q5.DecodeState,

	) (q4.PRSBandwidth, q5.Snapshot,

	)
	compare func(q4.PRSBandwidth, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.PRSBandwidth,

		error)
	encode func(q4.PRSBandwidth,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c PRSBandwidthValueCodec) New(value q4.PRSBandwidth,

) (PRSBandwidthAPERValue, error) {
	if c.encode == nil {
		return PRSBandwidthAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return PRSBandwidthAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PRSBandwidthAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return PRSBandwidthAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c PRSBandwidthValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (PRSBandwidthAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PRSBandwidthAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return PRSBandwidthAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PRSBandwidthAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return PRSBandwidthAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return PRSBandwidthAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PRSBandwidthValueCodec) EncodeAPER(value PRSBandwidthAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c PRSBandwidthValueCodec) encodeBudget(value q4.PRSBandwidth,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PRSBandwidthValueCodec) encodeChanged(value q4.PRSBandwidth,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// PRSConfigurationIndexValueCodec is the concrete ValueCodec[PRSConfigurationIndex].
type PRSConfigurationIndexValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.PRSConfigurationIndex, q5.DecodeState,

	) (q4.PRSConfigurationIndex, q5.Snapshot,

	)
	compare func(q4.PRSConfigurationIndex, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.PRSConfigurationIndex,

		error)
	encode func(q4.PRSConfigurationIndex,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c PRSConfigurationIndexValueCodec) New(value q4.PRSConfigurationIndex,

) (PRSConfigurationIndexAPERValue, error) {
	if c.encode == nil {
		return PRSConfigurationIndexAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return PRSConfigurationIndexAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PRSConfigurationIndexAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return PRSConfigurationIndexAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c PRSConfigurationIndexValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (PRSConfigurationIndexAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PRSConfigurationIndexAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return PRSConfigurationIndexAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PRSConfigurationIndexAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return PRSConfigurationIndexAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return PRSConfigurationIndexAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PRSConfigurationIndexValueCodec) EncodeAPER(value PRSConfigurationIndexAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c PRSConfigurationIndexValueCodec) encodeBudget(value q4.PRSConfigurationIndex,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PRSConfigurationIndexValueCodec) encodeChanged(value q4.PRSConfigurationIndex,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// PRSFrequencyHoppingConfigurationBandPositionsValueCodec is the concrete ValueCodec[PRSFrequencyHoppingConfigurationBandPositions].
type PRSFrequencyHoppingConfigurationBandPositionsValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.PRSFrequencyHoppingConfigurationBandPositions, q5.DecodeState,

	) (q4.PRSFrequencyHoppingConfigurationBandPositions, q5.Snapshot,

	)
	compare func(q4.PRSFrequencyHoppingConfigurationBandPositions, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.PRSFrequencyHoppingConfigurationBandPositions,

		error)
	encode func(q4.PRSFrequencyHoppingConfigurationBandPositions,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c PRSFrequencyHoppingConfigurationBandPositionsValueCodec) New(value q4.PRSFrequencyHoppingConfigurationBandPositions,

) (PRSFrequencyHoppingConfigurationBandPositionsAPERValue, error) {
	if c.encode == nil {
		return PRSFrequencyHoppingConfigurationBandPositionsAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return PRSFrequencyHoppingConfigurationBandPositionsAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PRSFrequencyHoppingConfigurationBandPositionsAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return PRSFrequencyHoppingConfigurationBandPositionsAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c PRSFrequencyHoppingConfigurationBandPositionsValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (PRSFrequencyHoppingConfigurationBandPositionsAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PRSFrequencyHoppingConfigurationBandPositionsAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return PRSFrequencyHoppingConfigurationBandPositionsAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PRSFrequencyHoppingConfigurationBandPositionsAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return PRSFrequencyHoppingConfigurationBandPositionsAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return PRSFrequencyHoppingConfigurationBandPositionsAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PRSFrequencyHoppingConfigurationBandPositionsValueCodec) EncodeAPER(value PRSFrequencyHoppingConfigurationBandPositionsAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c PRSFrequencyHoppingConfigurationBandPositionsValueCodec) encodeBudget(value q4.PRSFrequencyHoppingConfigurationBandPositions,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PRSFrequencyHoppingConfigurationBandPositionsValueCodec) encodeChanged(value q4.PRSFrequencyHoppingConfigurationBandPositions,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// PRSIDValueCodec is the concrete ValueCodec[PRSID].
type PRSIDValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.PRSID, q5.DecodeState,

	) (q4.PRSID, q5.Snapshot,

	)
	compare func(q4.PRSID, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.PRSID,

		error)
	encode func(q4.PRSID,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c PRSIDValueCodec) New(value q4.PRSID,

) (PRSIDAPERValue, error) {
	if c.encode == nil {
		return PRSIDAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return PRSIDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PRSIDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return PRSIDAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c PRSIDValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (PRSIDAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PRSIDAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return PRSIDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PRSIDAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return PRSIDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return PRSIDAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PRSIDValueCodec) EncodeAPER(value PRSIDAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c PRSIDValueCodec) encodeBudget(value q4.PRSID,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PRSIDValueCodec) encodeChanged(value q4.PRSID,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// PRSOccasionGroupValueCodec is the concrete ValueCodec[PRSOccasionGroup].
type PRSOccasionGroupValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.PRSOccasionGroup, q5.DecodeState,

	) (q4.PRSOccasionGroup, q5.Snapshot,

	)
	compare func(q4.PRSOccasionGroup, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.PRSOccasionGroup,

		error)
	encode func(q4.PRSOccasionGroup,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c PRSOccasionGroupValueCodec) New(value q4.PRSOccasionGroup,

) (PRSOccasionGroupAPERValue, error) {
	if c.encode == nil {
		return PRSOccasionGroupAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return PRSOccasionGroupAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PRSOccasionGroupAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return PRSOccasionGroupAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c PRSOccasionGroupValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (PRSOccasionGroupAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PRSOccasionGroupAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return PRSOccasionGroupAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PRSOccasionGroupAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return PRSOccasionGroupAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return PRSOccasionGroupAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PRSOccasionGroupValueCodec) EncodeAPER(value PRSOccasionGroupAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c PRSOccasionGroupValueCodec) encodeBudget(value q4.PRSOccasionGroup,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PRSOccasionGroupValueCodec) encodeChanged(value q4.PRSOccasionGroup,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// PhysCellIDGERANValueCodec is the concrete ValueCodec[PhysCellIDGERAN].
type PhysCellIDGERANValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.PhysCellIDGERAN, q5.DecodeState,

	) (q4.PhysCellIDGERAN, q5.Snapshot,

	)
	compare func(q4.PhysCellIDGERAN, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.PhysCellIDGERAN,

		error)
	encode func(q4.PhysCellIDGERAN,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c PhysCellIDGERANValueCodec) New(value q4.PhysCellIDGERAN,

) (PhysCellIDGERANAPERValue, error) {
	if c.encode == nil {
		return PhysCellIDGERANAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return PhysCellIDGERANAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PhysCellIDGERANAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return PhysCellIDGERANAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c PhysCellIDGERANValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (PhysCellIDGERANAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PhysCellIDGERANAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return PhysCellIDGERANAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PhysCellIDGERANAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return PhysCellIDGERANAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return PhysCellIDGERANAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PhysCellIDGERANValueCodec) EncodeAPER(value PhysCellIDGERANAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c PhysCellIDGERANValueCodec) encodeBudget(value q4.PhysCellIDGERAN,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PhysCellIDGERANValueCodec) encodeChanged(value q4.PhysCellIDGERAN,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// PhysCellIDUTRAFDDValueCodec is the concrete ValueCodec[PhysCellIDUTRAFDD].
type PhysCellIDUTRAFDDValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.PhysCellIDUTRAFDD, q5.DecodeState,

	) (q4.PhysCellIDUTRAFDD, q5.Snapshot,

	)
	compare func(q4.PhysCellIDUTRAFDD, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.PhysCellIDUTRAFDD,

		error)
	encode func(q4.PhysCellIDUTRAFDD,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c PhysCellIDUTRAFDDValueCodec) New(value q4.PhysCellIDUTRAFDD,

) (PhysCellIDUTRAFDDAPERValue, error) {
	if c.encode == nil {
		return PhysCellIDUTRAFDDAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return PhysCellIDUTRAFDDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PhysCellIDUTRAFDDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return PhysCellIDUTRAFDDAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c PhysCellIDUTRAFDDValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (PhysCellIDUTRAFDDAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PhysCellIDUTRAFDDAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return PhysCellIDUTRAFDDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PhysCellIDUTRAFDDAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return PhysCellIDUTRAFDDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return PhysCellIDUTRAFDDAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PhysCellIDUTRAFDDValueCodec) EncodeAPER(value PhysCellIDUTRAFDDAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c PhysCellIDUTRAFDDValueCodec) encodeBudget(value q4.PhysCellIDUTRAFDD,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PhysCellIDUTRAFDDValueCodec) encodeChanged(value q4.PhysCellIDUTRAFDD,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// PhysCellIDUTRATDDValueCodec is the concrete ValueCodec[PhysCellIDUTRATDD].
type PhysCellIDUTRATDDValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.PhysCellIDUTRATDD, q5.DecodeState,

	) (q4.PhysCellIDUTRATDD, q5.Snapshot,

	)
	compare func(q4.PhysCellIDUTRATDD, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.PhysCellIDUTRATDD,

		error)
	encode func(q4.PhysCellIDUTRATDD,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c PhysCellIDUTRATDDValueCodec) New(value q4.PhysCellIDUTRATDD,

) (PhysCellIDUTRATDDAPERValue, error) {
	if c.encode == nil {
		return PhysCellIDUTRATDDAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return PhysCellIDUTRATDDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PhysCellIDUTRATDDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return PhysCellIDUTRATDDAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c PhysCellIDUTRATDDValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (PhysCellIDUTRATDDAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PhysCellIDUTRATDDAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return PhysCellIDUTRATDDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PhysCellIDUTRATDDAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return PhysCellIDUTRATDDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return PhysCellIDUTRATDDAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PhysCellIDUTRATDDValueCodec) EncodeAPER(value PhysCellIDUTRATDDAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c PhysCellIDUTRATDDValueCodec) encodeBudget(value q4.PhysCellIDUTRATDD,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PhysCellIDUTRATDDValueCodec) encodeChanged(value q4.PhysCellIDUTRATDD,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// PosSIBTypeValueCodec is the concrete ValueCodec[PosSIBType].
type PosSIBTypeValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.PosSIBType, q5.DecodeState,

	) (q4.PosSIBType, q5.Snapshot,

	)
	compare func(q4.PosSIBType, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.PosSIBType,

		error)
	encode func(q4.PosSIBType,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c PosSIBTypeValueCodec) New(value q4.PosSIBType,

) (PosSIBTypeAPERValue, error) {
	if c.encode == nil {
		return PosSIBTypeAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return PosSIBTypeAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PosSIBTypeAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return PosSIBTypeAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c PosSIBTypeValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (PosSIBTypeAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PosSIBTypeAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return PosSIBTypeAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PosSIBTypeAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return PosSIBTypeAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return PosSIBTypeAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PosSIBTypeValueCodec) EncodeAPER(value PosSIBTypeAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c PosSIBTypeValueCodec) encodeBudget(value q4.PosSIBType,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PosSIBTypeValueCodec) encodeChanged(value q4.PosSIBType,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// PresenceValueCodec is the concrete ValueCodec[Presence].
type PresenceValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.Presence, q5.DecodeState,

	) (q4.Presence, q5.Snapshot,

	)
	compare func(q4.Presence, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.Presence,

		error)
	encode func(q4.Presence,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c PresenceValueCodec) New(value q4.Presence,

) (PresenceAPERValue, error) {
	if c.encode == nil {
		return PresenceAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return PresenceAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PresenceAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return PresenceAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c PresenceValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (PresenceAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PresenceAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return PresenceAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PresenceAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return PresenceAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return PresenceAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c PresenceValueCodec) EncodeAPER(value PresenceAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c PresenceValueCodec) encodeBudget(value q4.Presence,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PresenceValueCodec) encodeChanged(value q4.Presence,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// ProcedureCodeValueCodec is the concrete ValueCodec[ProcedureCode].
type ProcedureCodeValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.ProcedureCode, q5.DecodeState,

	) (q4.ProcedureCode, q5.Snapshot,

	)
	compare func(q4.ProcedureCode, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.ProcedureCode,

		error)
	encode func(q4.ProcedureCode,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c ProcedureCodeValueCodec) New(value q4.ProcedureCode,

) (ProcedureCodeAPERValue, error) {
	if c.encode == nil {
		return ProcedureCodeAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return ProcedureCodeAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ProcedureCodeAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return ProcedureCodeAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c ProcedureCodeValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (ProcedureCodeAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ProcedureCodeAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return ProcedureCodeAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ProcedureCodeAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return ProcedureCodeAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return ProcedureCodeAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ProcedureCodeValueCodec) EncodeAPER(value ProcedureCodeAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c ProcedureCodeValueCodec) encodeBudget(value q4.ProcedureCode,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ProcedureCodeValueCodec) encodeChanged(value q4.ProcedureCode,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// ProtocolIEIDValueCodec is the concrete ValueCodec[ProtocolIEID].
type ProtocolIEIDValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.ProtocolIEID, q5.DecodeState,

	) (q4.ProtocolIEID, q5.Snapshot,

	)
	compare func(q4.ProtocolIEID, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.ProtocolIEID,

		error)
	encode func(q4.ProtocolIEID,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c ProtocolIEIDValueCodec) New(value q4.ProtocolIEID,

) (ProtocolIEIDAPERValue, error) {
	if c.encode == nil {
		return ProtocolIEIDAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return ProtocolIEIDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ProtocolIEIDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return ProtocolIEIDAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c ProtocolIEIDValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (ProtocolIEIDAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ProtocolIEIDAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return ProtocolIEIDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ProtocolIEIDAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return ProtocolIEIDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return ProtocolIEIDAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ProtocolIEIDValueCodec) EncodeAPER(value ProtocolIEIDAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c ProtocolIEIDValueCodec) encodeBudget(value q4.ProtocolIEID,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ProtocolIEIDValueCodec) encodeChanged(value q4.ProtocolIEID,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// RSSIValueCodec is the concrete ValueCodec[RSSI].
type RSSIValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.RSSI, q5.DecodeState,

	) (q4.RSSI, q5.Snapshot,

	)
	compare func(q4.RSSI, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.RSSI,

		error)
	encode func(q4.RSSI,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c RSSIValueCodec) New(value q4.RSSI,

) (RSSIAPERValue, error) {
	if c.encode == nil {
		return RSSIAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return RSSIAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RSSIAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return RSSIAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c RSSIValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (RSSIAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return RSSIAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return RSSIAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return RSSIAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return RSSIAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return RSSIAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c RSSIValueCodec) EncodeAPER(value RSSIAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c RSSIValueCodec) encodeBudget(value q4.RSSI,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c RSSIValueCodec) encodeChanged(value q4.RSSI,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// RepetitionNumberofSIB1NBValueCodec is the concrete ValueCodec[RepetitionNumberofSIB1NB].
type RepetitionNumberofSIB1NBValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.RepetitionNumberofSIB1NB, q5.DecodeState,

	) (q4.RepetitionNumberofSIB1NB, q5.Snapshot,

	)
	compare func(q4.RepetitionNumberofSIB1NB, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.RepetitionNumberofSIB1NB,

		error)
	encode func(q4.RepetitionNumberofSIB1NB,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c RepetitionNumberofSIB1NBValueCodec) New(value q4.RepetitionNumberofSIB1NB,

) (RepetitionNumberofSIB1NBAPERValue, error) {
	if c.encode == nil {
		return RepetitionNumberofSIB1NBAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return RepetitionNumberofSIB1NBAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RepetitionNumberofSIB1NBAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return RepetitionNumberofSIB1NBAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c RepetitionNumberofSIB1NBValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (RepetitionNumberofSIB1NBAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return RepetitionNumberofSIB1NBAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return RepetitionNumberofSIB1NBAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return RepetitionNumberofSIB1NBAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return RepetitionNumberofSIB1NBAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return RepetitionNumberofSIB1NBAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c RepetitionNumberofSIB1NBValueCodec) EncodeAPER(value RepetitionNumberofSIB1NBAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c RepetitionNumberofSIB1NBValueCodec) encodeBudget(value q4.RepetitionNumberofSIB1NB,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c RepetitionNumberofSIB1NBValueCodec) encodeChanged(value q4.RepetitionNumberofSIB1NB,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// SFNInitialisationTimeValueCodec is the concrete ValueCodec[SFNInitialisationTime].
type SFNInitialisationTimeValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.SFNInitialisationTime, q5.DecodeState,

	) (q4.SFNInitialisationTime, q5.Snapshot,

	)
	compare func(q4.SFNInitialisationTime, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.SFNInitialisationTime,

		error)
	encode func(q4.SFNInitialisationTime,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c SFNInitialisationTimeValueCodec) New(value q4.SFNInitialisationTime,

) (SFNInitialisationTimeAPERValue, error) {
	if c.encode == nil {
		return SFNInitialisationTimeAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return SFNInitialisationTimeAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SFNInitialisationTimeAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return SFNInitialisationTimeAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c SFNInitialisationTimeValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (SFNInitialisationTimeAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SFNInitialisationTimeAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return SFNInitialisationTimeAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SFNInitialisationTimeAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return SFNInitialisationTimeAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return SFNInitialisationTimeAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c SFNInitialisationTimeValueCodec) EncodeAPER(value SFNInitialisationTimeAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c SFNInitialisationTimeValueCodec) encodeBudget(value q4.SFNInitialisationTime,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SFNInitialisationTimeValueCodec) encodeChanged(value q4.SFNInitialisationTime,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// SSBIndexValueCodec is the concrete ValueCodec[SSBIndex].
type SSBIndexValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.SSBIndex, q5.DecodeState,

	) (q4.SSBIndex, q5.Snapshot,

	)
	compare func(q4.SSBIndex, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.SSBIndex,

		error)
	encode func(q4.SSBIndex,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c SSBIndexValueCodec) New(value q4.SSBIndex,

) (SSBIndexAPERValue, error) {
	if c.encode == nil {
		return SSBIndexAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return SSBIndexAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SSBIndexAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return SSBIndexAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c SSBIndexValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (SSBIndexAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SSBIndexAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return SSBIndexAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SSBIndexAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return SSBIndexAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return SSBIndexAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c SSBIndexValueCodec) EncodeAPER(value SSBIndexAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c SSBIndexValueCodec) encodeBudget(value q4.SSBIndex,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SSBIndexValueCodec) encodeChanged(value q4.SSBIndex,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// SSIDValueCodec is the concrete ValueCodec[SSID].
type SSIDValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.SSID, q5.DecodeState,

	) (q4.SSID, q5.Snapshot,

	)
	compare func(q4.SSID, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.SSID,

		error)
	encode func(q4.SSID,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c SSIDValueCodec) New(value q4.SSID,

) (SSIDAPERValue, error) {
	if c.encode == nil {
		return SSIDAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return SSIDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SSIDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return SSIDAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c SSIDValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (SSIDAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SSIDAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return SSIDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SSIDAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return SSIDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return SSIDAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c SSIDValueCodec) EncodeAPER(value SSIDAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c SSIDValueCodec) encodeBudget(value q4.SSID,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SSIDValueCodec) encodeChanged(value q4.SSID,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// SSNRRSRPValueCodec is the concrete ValueCodec[SSNRRSRP].
type SSNRRSRPValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.SSNRRSRP, q5.DecodeState,

	) (q4.SSNRRSRP, q5.Snapshot,

	)
	compare func(q4.SSNRRSRP, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.SSNRRSRP,

		error)
	encode func(q4.SSNRRSRP,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c SSNRRSRPValueCodec) New(value q4.SSNRRSRP,

) (SSNRRSRPAPERValue, error) {
	if c.encode == nil {
		return SSNRRSRPAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return SSNRRSRPAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SSNRRSRPAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return SSNRRSRPAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c SSNRRSRPValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (SSNRRSRPAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SSNRRSRPAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return SSNRRSRPAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SSNRRSRPAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return SSNRRSRPAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return SSNRRSRPAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c SSNRRSRPValueCodec) EncodeAPER(value SSNRRSRPAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c SSNRRSRPValueCodec) encodeBudget(value q4.SSNRRSRP,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SSNRRSRPValueCodec) encodeChanged(value q4.SSNRRSRP,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// SSNRRSRQValueCodec is the concrete ValueCodec[SSNRRSRQ].
type SSNRRSRQValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.SSNRRSRQ, q5.DecodeState,

	) (q4.SSNRRSRQ, q5.Snapshot,

	)
	compare func(q4.SSNRRSRQ, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.SSNRRSRQ,

		error)
	encode func(q4.SSNRRSRQ,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c SSNRRSRQValueCodec) New(value q4.SSNRRSRQ,

) (SSNRRSRQAPERValue, error) {
	if c.encode == nil {
		return SSNRRSRQAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return SSNRRSRQAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SSNRRSRQAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return SSNRRSRQAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c SSNRRSRQValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (SSNRRSRQAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SSNRRSRQAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return SSNRRSRQAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SSNRRSRQAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return SSNRRSRQAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return SSNRRSRQAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c SSNRRSRQValueCodec) EncodeAPER(value SSNRRSRQAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c SSNRRSRQValueCodec) encodeBudget(value q4.SSNRRSRQ,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SSNRRSRQValueCodec) encodeChanged(value q4.SSNRRSRQ,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// TACValueCodec is the concrete ValueCodec[TAC].
type TACValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.TAC, q5.DecodeState,

	) (q4.TAC, q5.Snapshot,

	)
	compare func(q4.TAC, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.TAC,

		error)
	encode func(q4.TAC,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c TACValueCodec) New(value q4.TAC,

) (TACAPERValue, error) {
	if c.encode == nil {
		return TACAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return TACAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TACAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return TACAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c TACValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (TACAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return TACAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return TACAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return TACAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return TACAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return TACAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c TACValueCodec) EncodeAPER(value TACAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c TACValueCodec) encodeBudget(value q4.TAC,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c TACValueCodec) encodeChanged(value q4.TAC,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// TPIDValueCodec is the concrete ValueCodec[TPID].
type TPIDValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.TPID, q5.DecodeState,

	) (q4.TPID, q5.Snapshot,

	)
	compare func(q4.TPID, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.TPID,

		error)
	encode func(q4.TPID,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c TPIDValueCodec) New(value q4.TPID,

) (TPIDAPERValue, error) {
	if c.encode == nil {
		return TPIDAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return TPIDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TPIDAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return TPIDAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c TPIDValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (TPIDAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return TPIDAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return TPIDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return TPIDAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return TPIDAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return TPIDAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c TPIDValueCodec) EncodeAPER(value TPIDAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c TPIDValueCodec) encodeBudget(value q4.TPID,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c TPIDValueCodec) encodeChanged(value q4.TPID,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// TPTypeValueCodec is the concrete ValueCodec[TPType].
type TPTypeValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.TPType, q5.DecodeState,

	) (q4.TPType, q5.Snapshot,

	)
	compare func(q4.TPType, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.TPType,

		error)
	encode func(q4.TPType,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c TPTypeValueCodec) New(value q4.TPType,

) (TPTypeAPERValue, error) {
	if c.encode == nil {
		return TPTypeAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return TPTypeAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TPTypeAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return TPTypeAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c TPTypeValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (TPTypeAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return TPTypeAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return TPTypeAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return TPTypeAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return TPTypeAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return TPTypeAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c TPTypeValueCodec) EncodeAPER(value TPTypeAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c TPTypeValueCodec) encodeBudget(value q4.TPType,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c TPTypeValueCodec) encodeChanged(value q4.TPType,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// TriggeringMessageValueCodec is the concrete ValueCodec[TriggeringMessage].
type TriggeringMessageValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.TriggeringMessage, q5.DecodeState,

	) (q4.TriggeringMessage, q5.Snapshot,

	)
	compare func(q4.TriggeringMessage, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.TriggeringMessage,

		error)
	encode func(q4.TriggeringMessage,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c TriggeringMessageValueCodec) New(value q4.TriggeringMessage,

) (TriggeringMessageAPERValue, error) {
	if c.encode == nil {
		return TriggeringMessageAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return TriggeringMessageAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TriggeringMessageAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return TriggeringMessageAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c TriggeringMessageValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (TriggeringMessageAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return TriggeringMessageAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return TriggeringMessageAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return TriggeringMessageAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return TriggeringMessageAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return TriggeringMessageAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c TriggeringMessageValueCodec) EncodeAPER(value TriggeringMessageAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c TriggeringMessageValueCodec) encodeBudget(value q4.TriggeringMessage,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c TriggeringMessageValueCodec) encodeChanged(value q4.TriggeringMessage,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// TypeOfErrorValueCodec is the concrete ValueCodec[TypeOfError].
type TypeOfErrorValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.TypeOfError, q5.DecodeState,

	) (q4.TypeOfError, q5.Snapshot,

	)
	compare func(q4.TypeOfError, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.TypeOfError,

		error)
	encode func(q4.TypeOfError,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c TypeOfErrorValueCodec) New(value q4.TypeOfError,

) (TypeOfErrorAPERValue, error) {
	if c.encode == nil {
		return TypeOfErrorAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return TypeOfErrorAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TypeOfErrorAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return TypeOfErrorAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c TypeOfErrorValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (TypeOfErrorAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return TypeOfErrorAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return TypeOfErrorAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return TypeOfErrorAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return TypeOfErrorAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return TypeOfErrorAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c TypeOfErrorValueCodec) EncodeAPER(value TypeOfErrorAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c TypeOfErrorValueCodec) encodeBudget(value q4.TypeOfError,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c TypeOfErrorValueCodec) encodeChanged(value q4.TypeOfError,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// UARFCNValueCodec is the concrete ValueCodec[UARFCN].
type UARFCNValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.UARFCN, q5.DecodeState,

	) (q4.UARFCN, q5.Snapshot,

	)
	compare func(q4.UARFCN, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.UARFCN,

		error)
	encode func(q4.UARFCN,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c UARFCNValueCodec) New(value q4.UARFCN,

) (UARFCNAPERValue, error) {
	if c.encode == nil {
		return UARFCNAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return UARFCNAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UARFCNAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return UARFCNAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c UARFCNValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (UARFCNAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return UARFCNAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return UARFCNAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return UARFCNAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return UARFCNAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return UARFCNAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c UARFCNValueCodec) EncodeAPER(value UARFCNAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c UARFCNValueCodec) encodeBudget(value q4.UARFCN,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c UARFCNValueCodec) encodeChanged(value q4.UARFCN,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// UTRAEcN0ValueCodec is the concrete ValueCodec[UTRAEcN0].
type UTRAEcN0ValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.UTRAEcN0, q5.DecodeState,

	) (q4.UTRAEcN0, q5.Snapshot,

	)
	compare func(q4.UTRAEcN0, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.UTRAEcN0,

		error)
	encode func(q4.UTRAEcN0,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c UTRAEcN0ValueCodec) New(value q4.UTRAEcN0,

) (UTRAEcN0APERValue, error) {
	if c.encode == nil {
		return UTRAEcN0APERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return UTRAEcN0APERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UTRAEcN0APERValue{}, q5.OperationError(err, "Value.New")
	}
	return UTRAEcN0APERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c UTRAEcN0ValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (UTRAEcN0APERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return UTRAEcN0APERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return UTRAEcN0APERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return UTRAEcN0APERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return UTRAEcN0APERValue{}, report, q5.OperationError(err, c.path)
	}
	return UTRAEcN0APERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c UTRAEcN0ValueCodec) EncodeAPER(value UTRAEcN0APERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c UTRAEcN0ValueCodec) encodeBudget(value q4.UTRAEcN0,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c UTRAEcN0ValueCodec) encodeChanged(value q4.UTRAEcN0,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// UTRARSCPValueCodec is the concrete ValueCodec[UTRARSCP].
type UTRARSCPValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.UTRARSCP, q5.DecodeState,

	) (q4.UTRARSCP, q5.Snapshot,

	)
	compare func(q4.UTRARSCP, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.UTRARSCP,

		error)
	encode func(q4.UTRARSCP,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c UTRARSCPValueCodec) New(value q4.UTRARSCP,

) (UTRARSCPAPERValue, error) {
	if c.encode == nil {
		return UTRARSCPAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return UTRARSCPAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UTRARSCPAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return UTRARSCPAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c UTRARSCPValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (UTRARSCPAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return UTRARSCPAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return UTRARSCPAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return UTRARSCPAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return UTRARSCPAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return UTRARSCPAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c UTRARSCPValueCodec) EncodeAPER(value UTRARSCPAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c UTRARSCPValueCodec) encodeBudget(value q4.UTRARSCP,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c UTRARSCPValueCodec) encodeChanged(value q4.UTRARSCP,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// ValueRSRPValueCodec is the concrete ValueCodec[ValueRSRP].
type ValueRSRPValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.ValueRSRP, q5.DecodeState,

	) (q4.ValueRSRP, q5.Snapshot,

	)
	compare func(q4.ValueRSRP, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.ValueRSRP,

		error)
	encode func(q4.ValueRSRP,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c ValueRSRPValueCodec) New(value q4.ValueRSRP,

) (ValueRSRPAPERValue, error) {
	if c.encode == nil {
		return ValueRSRPAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return ValueRSRPAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ValueRSRPAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return ValueRSRPAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c ValueRSRPValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (ValueRSRPAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ValueRSRPAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return ValueRSRPAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ValueRSRPAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return ValueRSRPAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return ValueRSRPAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ValueRSRPValueCodec) EncodeAPER(value ValueRSRPAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c ValueRSRPValueCodec) encodeBudget(value q4.ValueRSRP,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ValueRSRPValueCodec) encodeChanged(value q4.ValueRSRP,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// ValueRSRQValueCodec is the concrete ValueCodec[ValueRSRQ].
type ValueRSRQValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.ValueRSRQ, q5.DecodeState,

	) (q4.ValueRSRQ, q5.Snapshot,

	)
	compare func(q4.ValueRSRQ, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.ValueRSRQ,

		error)
	encode func(q4.ValueRSRQ,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c ValueRSRQValueCodec) New(value q4.ValueRSRQ,

) (ValueRSRQAPERValue, error) {
	if c.encode == nil {
		return ValueRSRQAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return ValueRSRQAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ValueRSRQAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return ValueRSRQAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c ValueRSRQValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (ValueRSRQAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ValueRSRQAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return ValueRSRQAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ValueRSRQAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return ValueRSRQAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return ValueRSRQAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ValueRSRQValueCodec) EncodeAPER(value ValueRSRQAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c ValueRSRQValueCodec) encodeBudget(value q4.ValueRSRQ,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ValueRSRQValueCodec) encodeChanged(value q4.ValueRSRQ,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// WLANBandValueCodec is the concrete ValueCodec[WLANBand].
type WLANBandValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.WLANBand, q5.DecodeState,

	) (q4.WLANBand, q5.Snapshot,

	)
	compare func(q4.WLANBand, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.WLANBand,

		error)
	encode func(q4.WLANBand,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c WLANBandValueCodec) New(value q4.WLANBand,

) (WLANBandAPERValue, error) {
	if c.encode == nil {
		return WLANBandAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return WLANBandAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANBandAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return WLANBandAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c WLANBandValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (WLANBandAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANBandAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return WLANBandAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANBandAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return WLANBandAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return WLANBandAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c WLANBandValueCodec) EncodeAPER(value WLANBandAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c WLANBandValueCodec) encodeBudget(value q4.WLANBand,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANBandValueCodec) encodeChanged(value q4.WLANBand,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// WLANChannelValueCodec is the concrete ValueCodec[WLANChannel].
type WLANChannelValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.WLANChannel, q5.DecodeState,

	) (q4.WLANChannel, q5.Snapshot,

	)
	compare func(q4.WLANChannel, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.WLANChannel,

		error)
	encode func(q4.WLANChannel,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c WLANChannelValueCodec) New(value q4.WLANChannel,

) (WLANChannelAPERValue, error) {
	if c.encode == nil {
		return WLANChannelAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return WLANChannelAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANChannelAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return WLANChannelAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c WLANChannelValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (WLANChannelAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANChannelAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return WLANChannelAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANChannelAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return WLANChannelAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return WLANChannelAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c WLANChannelValueCodec) EncodeAPER(value WLANChannelAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c WLANChannelValueCodec) encodeBudget(value q4.WLANChannel,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANChannelValueCodec) encodeChanged(value q4.WLANChannel,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// WLANChannelListValueCodec is the concrete ValueCodec[WLANChannelList].
type WLANChannelListValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.WLANChannelList, q5.DecodeState,

	) (q4.WLANChannelList, q5.Snapshot,

	)
	compare func(q4.WLANChannelList, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.WLANChannelList,

		error)
	encode func(q4.WLANChannelList,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c WLANChannelListValueCodec) New(value q4.WLANChannelList,

) (WLANChannelListAPERValue, error) {
	if c.encode == nil {
		return WLANChannelListAPERValue{}, q5.OperationError(q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return WLANChannelListAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANChannelListAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return WLANChannelListAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c WLANChannelListValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (WLANChannelListAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANChannelListAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return WLANChannelListAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANChannelListAPERValue{}, q5.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return WLANChannelListAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return WLANChannelListAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c WLANChannelListValueCodec) EncodeAPER(value WLANChannelListAPERValue, options ...q5.EncodeOption) ([]byte, error) {
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
func (c WLANChannelListValueCodec) encodeBudget(value q4.WLANChannelList,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANChannelListValueCodec) encodeChanged(value q4.WLANChannelList,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// ReportCharacteristicsAPERValue is the concrete APERValue[ReportCharacteristics].
type ReportCharacteristicsAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.ReportCharacteristics

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v ReportCharacteristicsAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v ReportCharacteristicsAPERValue) WithoutReplay() ReportCharacteristicsAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// NumberOfFrequencyHoppingBandsAPERValue is the concrete APERValue[NumberOfFrequencyHoppingBands].
type NumberOfFrequencyHoppingBandsAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.NumberOfFrequencyHoppingBands

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v NumberOfFrequencyHoppingBandsAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v NumberOfFrequencyHoppingBandsAPERValue) WithoutReplay() NumberOfFrequencyHoppingBandsAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// OTDOAInformationItemAPERValue is the concrete APERValue[OTDOAInformationItem].
type OTDOAInformationItemAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.OTDOAInformationItem

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v OTDOAInformationItemAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v OTDOAInformationItemAPERValue) WithoutReplay() OTDOAInformationItemAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// OffsetNBChanneltoEARFCNAPERValue is the concrete APERValue[OffsetNBChanneltoEARFCN].
type OffsetNBChanneltoEARFCNAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.OffsetNBChanneltoEARFCN

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v OffsetNBChanneltoEARFCNAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v OffsetNBChanneltoEARFCNAPERValue) WithoutReplay() OffsetNBChanneltoEARFCNAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// OperationModeInfoAPERValue is the concrete APERValue[OperationModeInfo].
type OperationModeInfoAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.OperationModeInfo

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v OperationModeInfoAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v OperationModeInfoAPERValue) WithoutReplay() OperationModeInfoAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// OutcomeAPERValue is the concrete APERValue[Outcome].
type OutcomeAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.Outcome

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v OutcomeAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v OutcomeAPERValue) WithoutReplay() OutcomeAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// PCIAPERValue is the concrete APERValue[PCI].
type PCIAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.PCI

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v PCIAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v PCIAPERValue) WithoutReplay() PCIAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// PLMNIdentityAPERValue is the concrete APERValue[PLMNIdentity].
type PLMNIdentityAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.PLMNIdentity

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v PLMNIdentityAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v PLMNIdentityAPERValue) WithoutReplay() PLMNIdentityAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// PRSBandwidthAPERValue is the concrete APERValue[PRSBandwidth].
type PRSBandwidthAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.PRSBandwidth

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v PRSBandwidthAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v PRSBandwidthAPERValue) WithoutReplay() PRSBandwidthAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// PRSConfigurationIndexAPERValue is the concrete APERValue[PRSConfigurationIndex].
type PRSConfigurationIndexAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.PRSConfigurationIndex

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v PRSConfigurationIndexAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v PRSConfigurationIndexAPERValue) WithoutReplay() PRSConfigurationIndexAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// PRSFrequencyHoppingConfigurationBandPositionsAPERValue is the concrete APERValue[PRSFrequencyHoppingConfigurationBandPositions].
type PRSFrequencyHoppingConfigurationBandPositionsAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.PRSFrequencyHoppingConfigurationBandPositions

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v PRSFrequencyHoppingConfigurationBandPositionsAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v PRSFrequencyHoppingConfigurationBandPositionsAPERValue) WithoutReplay() PRSFrequencyHoppingConfigurationBandPositionsAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// PRSIDAPERValue is the concrete APERValue[PRSID].
type PRSIDAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.PRSID

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v PRSIDAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v PRSIDAPERValue) WithoutReplay() PRSIDAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// PRSOccasionGroupAPERValue is the concrete APERValue[PRSOccasionGroup].
type PRSOccasionGroupAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.PRSOccasionGroup

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v PRSOccasionGroupAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v PRSOccasionGroupAPERValue) WithoutReplay() PRSOccasionGroupAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// PhysCellIDGERANAPERValue is the concrete APERValue[PhysCellIDGERAN].
type PhysCellIDGERANAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.PhysCellIDGERAN

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v PhysCellIDGERANAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v PhysCellIDGERANAPERValue) WithoutReplay() PhysCellIDGERANAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// PhysCellIDUTRAFDDAPERValue is the concrete APERValue[PhysCellIDUTRAFDD].
type PhysCellIDUTRAFDDAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.PhysCellIDUTRAFDD

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v PhysCellIDUTRAFDDAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v PhysCellIDUTRAFDDAPERValue) WithoutReplay() PhysCellIDUTRAFDDAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// PhysCellIDUTRATDDAPERValue is the concrete APERValue[PhysCellIDUTRATDD].
type PhysCellIDUTRATDDAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.PhysCellIDUTRATDD

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v PhysCellIDUTRATDDAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v PhysCellIDUTRATDDAPERValue) WithoutReplay() PhysCellIDUTRATDDAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// PosSIBTypeAPERValue is the concrete APERValue[PosSIBType].
type PosSIBTypeAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.PosSIBType

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v PosSIBTypeAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v PosSIBTypeAPERValue) WithoutReplay() PosSIBTypeAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// PresenceAPERValue is the concrete APERValue[Presence].
type PresenceAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.Presence

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v PresenceAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v PresenceAPERValue) WithoutReplay() PresenceAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// ProcedureCodeAPERValue is the concrete APERValue[ProcedureCode].
type ProcedureCodeAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.ProcedureCode

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v ProcedureCodeAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v ProcedureCodeAPERValue) WithoutReplay() ProcedureCodeAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// ProtocolIEIDAPERValue is the concrete APERValue[ProtocolIEID].
type ProtocolIEIDAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.ProtocolIEID

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v ProtocolIEIDAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v ProtocolIEIDAPERValue) WithoutReplay() ProtocolIEIDAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// RSSIAPERValue is the concrete APERValue[RSSI].
type RSSIAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.RSSI

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v RSSIAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v RSSIAPERValue) WithoutReplay() RSSIAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// RepetitionNumberofSIB1NBAPERValue is the concrete APERValue[RepetitionNumberofSIB1NB].
type RepetitionNumberofSIB1NBAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.RepetitionNumberofSIB1NB

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v RepetitionNumberofSIB1NBAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v RepetitionNumberofSIB1NBAPERValue) WithoutReplay() RepetitionNumberofSIB1NBAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// SFNInitialisationTimeAPERValue is the concrete APERValue[SFNInitialisationTime].
type SFNInitialisationTimeAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.SFNInitialisationTime

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v SFNInitialisationTimeAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v SFNInitialisationTimeAPERValue) WithoutReplay() SFNInitialisationTimeAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// SSBIndexAPERValue is the concrete APERValue[SSBIndex].
type SSBIndexAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.SSBIndex

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v SSBIndexAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v SSBIndexAPERValue) WithoutReplay() SSBIndexAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// SSIDAPERValue is the concrete APERValue[SSID].
type SSIDAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.SSID

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v SSIDAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v SSIDAPERValue) WithoutReplay() SSIDAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// SSNRRSRPAPERValue is the concrete APERValue[SSNRRSRP].
type SSNRRSRPAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.SSNRRSRP

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v SSNRRSRPAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v SSNRRSRPAPERValue) WithoutReplay() SSNRRSRPAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// SSNRRSRQAPERValue is the concrete APERValue[SSNRRSRQ].
type SSNRRSRQAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.SSNRRSRQ

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v SSNRRSRQAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v SSNRRSRQAPERValue) WithoutReplay() SSNRRSRQAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// TACAPERValue is the concrete APERValue[TAC].
type TACAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.TAC

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v TACAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v TACAPERValue) WithoutReplay() TACAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// TPIDAPERValue is the concrete APERValue[TPID].
type TPIDAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.TPID

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v TPIDAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v TPIDAPERValue) WithoutReplay() TPIDAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// TPTypeAPERValue is the concrete APERValue[TPType].
type TPTypeAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.TPType

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v TPTypeAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v TPTypeAPERValue) WithoutReplay() TPTypeAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// TriggeringMessageAPERValue is the concrete APERValue[TriggeringMessage].
type TriggeringMessageAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.TriggeringMessage

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v TriggeringMessageAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v TriggeringMessageAPERValue) WithoutReplay() TriggeringMessageAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// TypeOfErrorAPERValue is the concrete APERValue[TypeOfError].
type TypeOfErrorAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.TypeOfError

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v TypeOfErrorAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v TypeOfErrorAPERValue) WithoutReplay() TypeOfErrorAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// UARFCNAPERValue is the concrete APERValue[UARFCN].
type UARFCNAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.UARFCN

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v UARFCNAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v UARFCNAPERValue) WithoutReplay() UARFCNAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// UTRAEcN0APERValue is the concrete APERValue[UTRAEcN0].
type UTRAEcN0APERValue struct {
	context q4.BridgeCodecContext
	Value   q4.UTRAEcN0

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v UTRAEcN0APERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v UTRAEcN0APERValue) WithoutReplay() UTRAEcN0APERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// UTRARSCPAPERValue is the concrete APERValue[UTRARSCP].
type UTRARSCPAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.UTRARSCP

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v UTRARSCPAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v UTRARSCPAPERValue) WithoutReplay() UTRARSCPAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// ValueRSRPAPERValue is the concrete APERValue[ValueRSRP].
type ValueRSRPAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.ValueRSRP

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v ValueRSRPAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v ValueRSRPAPERValue) WithoutReplay() ValueRSRPAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// ValueRSRQAPERValue is the concrete APERValue[ValueRSRQ].
type ValueRSRQAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.ValueRSRQ

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v ValueRSRQAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v ValueRSRQAPERValue) WithoutReplay() ValueRSRQAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// WLANBandAPERValue is the concrete APERValue[WLANBand].
type WLANBandAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.WLANBand

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v WLANBandAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v WLANBandAPERValue) WithoutReplay() WLANBandAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// WLANChannelAPERValue is the concrete APERValue[WLANChannel].
type WLANChannelAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.WLANChannel

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v WLANChannelAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v WLANChannelAPERValue) WithoutReplay() WLANChannelAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// WLANChannelListAPERValue is the concrete APERValue[WLANChannelList].
type WLANChannelListAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.WLANChannelList

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v WLANChannelListAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v WLANChannelListAPERValue) WithoutReplay() WLANChannelListAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// WLANCountryCodeAPERValue is the concrete APERValue[WLANCountryCode].
type WLANCountryCodeAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.WLANCountryCode

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v WLANCountryCodeAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v WLANCountryCodeAPERValue) WithoutReplay() WLANCountryCodeAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeNumberOfFrequencyHoppingBandsAPERValueFieldContext(v *NumberOfFrequencyHoppingBandsAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeNumberOfFrequencyHoppingBandsAPERValueFieldReceived(v *NumberOfFrequencyHoppingBandsAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeNumberOfFrequencyHoppingBandsAPERValueFieldReplay(v *NumberOfFrequencyHoppingBandsAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeNumberOfFrequencyHoppingBandsAPERValueFieldWithoutReplay(v *NumberOfFrequencyHoppingBandsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNumberOfFrequencyHoppingBandsValueCodecFieldCapture(v *NumberOfFrequencyHoppingBandsValueCodec) *func(q4.NumberOfFrequencyHoppingBands, q5.DecodeState) (q4.NumberOfFrequencyHoppingBands, q5.Snapshot) {
	return &v.capture
}
func BridgeNumberOfFrequencyHoppingBandsValueCodecFieldCompare(v *NumberOfFrequencyHoppingBandsValueCodec) *func(q4.NumberOfFrequencyHoppingBands, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeNumberOfFrequencyHoppingBandsValueCodecFieldContext(v *NumberOfFrequencyHoppingBandsValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeNumberOfFrequencyHoppingBandsValueCodecFieldDecode(v *NumberOfFrequencyHoppingBandsValueCodec) *func([]byte, q5.DecodeState) (q4.NumberOfFrequencyHoppingBands, error) {
	return &v.decode
}
func BridgeNumberOfFrequencyHoppingBandsValueCodecFieldEncode(v *NumberOfFrequencyHoppingBandsValueCodec) *func(q4.NumberOfFrequencyHoppingBands, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNumberOfFrequencyHoppingBandsValueCodecFieldPath(v *NumberOfFrequencyHoppingBandsValueCodec) *q5.Path {
	return &v.path
}
func BridgeNumberOfFrequencyHoppingBandsValueCodecMethodEncodeBudget(v NumberOfFrequencyHoppingBandsValueCodec, a0 q4.NumberOfFrequencyHoppingBands, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNumberOfFrequencyHoppingBandsValueCodecMethodEncodeChanged(v NumberOfFrequencyHoppingBandsValueCodec, a0 q4.NumberOfFrequencyHoppingBands, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOAInformationItemAPERValueFieldContext(v *OTDOAInformationItemAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationItemAPERValueFieldReceived(v *OTDOAInformationItemAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationItemAPERValueFieldReplay(v *OTDOAInformationItemAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationItemAPERValueFieldWithoutReplay(v *OTDOAInformationItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationItemValueCodecFieldCapture(v *OTDOAInformationItemValueCodec) *func(q4.OTDOAInformationItem, q5.DecodeState) (q4.OTDOAInformationItem, q5.Snapshot) {
	return &v.capture
}
func BridgeOTDOAInformationItemValueCodecFieldCompare(v *OTDOAInformationItemValueCodec) *func(q4.OTDOAInformationItem, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeOTDOAInformationItemValueCodecFieldContext(v *OTDOAInformationItemValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationItemValueCodecFieldDecode(v *OTDOAInformationItemValueCodec) *func([]byte, q5.DecodeState) (q4.OTDOAInformationItem, error) {
	return &v.decode
}
func BridgeOTDOAInformationItemValueCodecFieldEncode(v *OTDOAInformationItemValueCodec) *func(q4.OTDOAInformationItem, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOAInformationItemValueCodecFieldPath(v *OTDOAInformationItemValueCodec) *q5.Path {
	return &v.path
}
func BridgeOTDOAInformationItemValueCodecMethodEncodeBudget(v OTDOAInformationItemValueCodec, a0 q4.OTDOAInformationItem, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOAInformationItemValueCodecMethodEncodeChanged(v OTDOAInformationItemValueCodec, a0 q4.OTDOAInformationItem, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOffsetNBChanneltoEARFCNAPERValueFieldContext(v *OffsetNBChanneltoEARFCNAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeOffsetNBChanneltoEARFCNAPERValueFieldReceived(v *OffsetNBChanneltoEARFCNAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeOffsetNBChanneltoEARFCNAPERValueFieldReplay(v *OffsetNBChanneltoEARFCNAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeOffsetNBChanneltoEARFCNAPERValueFieldWithoutReplay(v *OffsetNBChanneltoEARFCNAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOffsetNBChanneltoEARFCNValueCodecFieldCapture(v *OffsetNBChanneltoEARFCNValueCodec) *func(q4.OffsetNBChanneltoEARFCN, q5.DecodeState) (q4.OffsetNBChanneltoEARFCN, q5.Snapshot) {
	return &v.capture
}
func BridgeOffsetNBChanneltoEARFCNValueCodecFieldCompare(v *OffsetNBChanneltoEARFCNValueCodec) *func(q4.OffsetNBChanneltoEARFCN, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeOffsetNBChanneltoEARFCNValueCodecFieldContext(v *OffsetNBChanneltoEARFCNValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeOffsetNBChanneltoEARFCNValueCodecFieldDecode(v *OffsetNBChanneltoEARFCNValueCodec) *func([]byte, q5.DecodeState) (q4.OffsetNBChanneltoEARFCN, error) {
	return &v.decode
}
func BridgeOffsetNBChanneltoEARFCNValueCodecFieldEncode(v *OffsetNBChanneltoEARFCNValueCodec) *func(q4.OffsetNBChanneltoEARFCN, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOffsetNBChanneltoEARFCNValueCodecFieldPath(v *OffsetNBChanneltoEARFCNValueCodec) *q5.Path {
	return &v.path
}
func BridgeOffsetNBChanneltoEARFCNValueCodecMethodEncodeBudget(v OffsetNBChanneltoEARFCNValueCodec, a0 q4.OffsetNBChanneltoEARFCN, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOffsetNBChanneltoEARFCNValueCodecMethodEncodeChanged(v OffsetNBChanneltoEARFCNValueCodec, a0 q4.OffsetNBChanneltoEARFCN, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOperationModeInfoAPERValueFieldContext(v *OperationModeInfoAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeOperationModeInfoAPERValueFieldReceived(v *OperationModeInfoAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeOperationModeInfoAPERValueFieldReplay(v *OperationModeInfoAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeOperationModeInfoAPERValueFieldWithoutReplay(v *OperationModeInfoAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOperationModeInfoValueCodecFieldCapture(v *OperationModeInfoValueCodec) *func(q4.OperationModeInfo, q5.DecodeState) (q4.OperationModeInfo, q5.Snapshot) {
	return &v.capture
}
func BridgeOperationModeInfoValueCodecFieldCompare(v *OperationModeInfoValueCodec) *func(q4.OperationModeInfo, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeOperationModeInfoValueCodecFieldContext(v *OperationModeInfoValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeOperationModeInfoValueCodecFieldDecode(v *OperationModeInfoValueCodec) *func([]byte, q5.DecodeState) (q4.OperationModeInfo, error) {
	return &v.decode
}
func BridgeOperationModeInfoValueCodecFieldEncode(v *OperationModeInfoValueCodec) *func(q4.OperationModeInfo, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOperationModeInfoValueCodecFieldPath(v *OperationModeInfoValueCodec) *q5.Path {
	return &v.path
}
func BridgeOperationModeInfoValueCodecMethodEncodeBudget(v OperationModeInfoValueCodec, a0 q4.OperationModeInfo, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOperationModeInfoValueCodecMethodEncodeChanged(v OperationModeInfoValueCodec, a0 q4.OperationModeInfo, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOutcomeAPERValueFieldContext(v *OutcomeAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeOutcomeAPERValueFieldReceived(v *OutcomeAPERValue) *q5.WireSpan { return &v.received }
func BridgeOutcomeAPERValueFieldReplay(v *OutcomeAPERValue) *q5.Snapshot   { return &v.replay }
func BridgeOutcomeAPERValueFieldWithoutReplay(v *OutcomeAPERValue) *bool   { return &v.withoutReplay }
func BridgeOutcomeValueCodecFieldCapture(v *OutcomeValueCodec) *func(q4.Outcome, q5.DecodeState) (q4.Outcome, q5.Snapshot) {
	return &v.capture
}
func BridgeOutcomeValueCodecFieldCompare(v *OutcomeValueCodec) *func(q4.Outcome, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeOutcomeValueCodecFieldContext(v *OutcomeValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeOutcomeValueCodecFieldDecode(v *OutcomeValueCodec) *func([]byte, q5.DecodeState) (q4.Outcome, error) {
	return &v.decode
}
func BridgeOutcomeValueCodecFieldEncode(v *OutcomeValueCodec) *func(q4.Outcome, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOutcomeValueCodecFieldPath(v *OutcomeValueCodec) *q5.Path { return &v.path }
func BridgeOutcomeValueCodecMethodEncodeBudget(v OutcomeValueCodec, a0 q4.Outcome, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOutcomeValueCodecMethodEncodeChanged(v OutcomeValueCodec, a0 q4.Outcome, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePCIAPERValueFieldContext(v *PCIAPERValue) *q4.BridgeCodecContext { return &v.context }
func BridgePCIAPERValueFieldReceived(v *PCIAPERValue) *q5.WireSpan          { return &v.received }
func BridgePCIAPERValueFieldReplay(v *PCIAPERValue) *q5.Snapshot            { return &v.replay }
func BridgePCIAPERValueFieldWithoutReplay(v *PCIAPERValue) *bool            { return &v.withoutReplay }
func BridgePCIValueCodecFieldCapture(v *PCIValueCodec) *func(q4.PCI, q5.DecodeState) (q4.PCI, q5.Snapshot) {
	return &v.capture
}
func BridgePCIValueCodecFieldCompare(v *PCIValueCodec) *func(q4.PCI, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgePCIValueCodecFieldContext(v *PCIValueCodec) *q4.BridgeCodecContext { return &v.context }
func BridgePCIValueCodecFieldDecode(v *PCIValueCodec) *func([]byte, q5.DecodeState) (q4.PCI, error) {
	return &v.decode
}
func BridgePCIValueCodecFieldEncode(v *PCIValueCodec) *func(q4.PCI, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePCIValueCodecFieldPath(v *PCIValueCodec) *q5.Path { return &v.path }
func BridgePCIValueCodecMethodEncodeBudget(v PCIValueCodec, a0 q4.PCI, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePCIValueCodecMethodEncodeChanged(v PCIValueCodec, a0 q4.PCI, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePLMNIdentityAPERValueFieldContext(v *PLMNIdentityAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePLMNIdentityAPERValueFieldReceived(v *PLMNIdentityAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgePLMNIdentityAPERValueFieldReplay(v *PLMNIdentityAPERValue) *q5.Snapshot { return &v.replay }
func BridgePLMNIdentityAPERValueFieldWithoutReplay(v *PLMNIdentityAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePLMNIdentityValueCodecFieldCapture(v *PLMNIdentityValueCodec) *func(q4.PLMNIdentity, q5.DecodeState) (q4.PLMNIdentity, q5.Snapshot) {
	return &v.capture
}
func BridgePLMNIdentityValueCodecFieldCompare(v *PLMNIdentityValueCodec) *func(q4.PLMNIdentity, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgePLMNIdentityValueCodecFieldContext(v *PLMNIdentityValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePLMNIdentityValueCodecFieldDecode(v *PLMNIdentityValueCodec) *func([]byte, q5.DecodeState) (q4.PLMNIdentity, error) {
	return &v.decode
}
func BridgePLMNIdentityValueCodecFieldEncode(v *PLMNIdentityValueCodec) *func(q4.PLMNIdentity, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePLMNIdentityValueCodecFieldPath(v *PLMNIdentityValueCodec) *q5.Path { return &v.path }
func BridgePLMNIdentityValueCodecMethodEncodeBudget(v PLMNIdentityValueCodec, a0 q4.PLMNIdentity, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePLMNIdentityValueCodecMethodEncodeChanged(v PLMNIdentityValueCodec, a0 q4.PLMNIdentity, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePRSBandwidthAPERValueFieldContext(v *PRSBandwidthAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePRSBandwidthAPERValueFieldReceived(v *PRSBandwidthAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgePRSBandwidthAPERValueFieldReplay(v *PRSBandwidthAPERValue) *q5.Snapshot { return &v.replay }
func BridgePRSBandwidthAPERValueFieldWithoutReplay(v *PRSBandwidthAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePRSBandwidthValueCodecFieldCapture(v *PRSBandwidthValueCodec) *func(q4.PRSBandwidth, q5.DecodeState) (q4.PRSBandwidth, q5.Snapshot) {
	return &v.capture
}
func BridgePRSBandwidthValueCodecFieldCompare(v *PRSBandwidthValueCodec) *func(q4.PRSBandwidth, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgePRSBandwidthValueCodecFieldContext(v *PRSBandwidthValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePRSBandwidthValueCodecFieldDecode(v *PRSBandwidthValueCodec) *func([]byte, q5.DecodeState) (q4.PRSBandwidth, error) {
	return &v.decode
}
func BridgePRSBandwidthValueCodecFieldEncode(v *PRSBandwidthValueCodec) *func(q4.PRSBandwidth, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePRSBandwidthValueCodecFieldPath(v *PRSBandwidthValueCodec) *q5.Path { return &v.path }
func BridgePRSBandwidthValueCodecMethodEncodeBudget(v PRSBandwidthValueCodec, a0 q4.PRSBandwidth, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePRSBandwidthValueCodecMethodEncodeChanged(v PRSBandwidthValueCodec, a0 q4.PRSBandwidth, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePRSConfigurationIndexAPERValueFieldContext(v *PRSConfigurationIndexAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePRSConfigurationIndexAPERValueFieldReceived(v *PRSConfigurationIndexAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgePRSConfigurationIndexAPERValueFieldReplay(v *PRSConfigurationIndexAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgePRSConfigurationIndexAPERValueFieldWithoutReplay(v *PRSConfigurationIndexAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePRSConfigurationIndexValueCodecFieldCapture(v *PRSConfigurationIndexValueCodec) *func(q4.PRSConfigurationIndex, q5.DecodeState) (q4.PRSConfigurationIndex, q5.Snapshot) {
	return &v.capture
}
func BridgePRSConfigurationIndexValueCodecFieldCompare(v *PRSConfigurationIndexValueCodec) *func(q4.PRSConfigurationIndex, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgePRSConfigurationIndexValueCodecFieldContext(v *PRSConfigurationIndexValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePRSConfigurationIndexValueCodecFieldDecode(v *PRSConfigurationIndexValueCodec) *func([]byte, q5.DecodeState) (q4.PRSConfigurationIndex, error) {
	return &v.decode
}
func BridgePRSConfigurationIndexValueCodecFieldEncode(v *PRSConfigurationIndexValueCodec) *func(q4.PRSConfigurationIndex, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePRSConfigurationIndexValueCodecFieldPath(v *PRSConfigurationIndexValueCodec) *q5.Path {
	return &v.path
}
func BridgePRSConfigurationIndexValueCodecMethodEncodeBudget(v PRSConfigurationIndexValueCodec, a0 q4.PRSConfigurationIndex, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePRSConfigurationIndexValueCodecMethodEncodeChanged(v PRSConfigurationIndexValueCodec, a0 q4.PRSConfigurationIndex, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsAPERValueFieldContext(v *PRSFrequencyHoppingConfigurationBandPositionsAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsAPERValueFieldReceived(v *PRSFrequencyHoppingConfigurationBandPositionsAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsAPERValueFieldReplay(v *PRSFrequencyHoppingConfigurationBandPositionsAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsAPERValueFieldWithoutReplay(v *PRSFrequencyHoppingConfigurationBandPositionsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldCapture(v *PRSFrequencyHoppingConfigurationBandPositionsValueCodec) *func(q4.PRSFrequencyHoppingConfigurationBandPositions, q5.DecodeState) (q4.PRSFrequencyHoppingConfigurationBandPositions, q5.Snapshot) {
	return &v.capture
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldCompare(v *PRSFrequencyHoppingConfigurationBandPositionsValueCodec) *func(q4.PRSFrequencyHoppingConfigurationBandPositions, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldContext(v *PRSFrequencyHoppingConfigurationBandPositionsValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldDecode(v *PRSFrequencyHoppingConfigurationBandPositionsValueCodec) *func([]byte, q5.DecodeState) (q4.PRSFrequencyHoppingConfigurationBandPositions, error) {
	return &v.decode
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldEncode(v *PRSFrequencyHoppingConfigurationBandPositionsValueCodec) *func(q4.PRSFrequencyHoppingConfigurationBandPositions, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldPath(v *PRSFrequencyHoppingConfigurationBandPositionsValueCodec) *q5.Path {
	return &v.path
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecMethodEncodeBudget(v PRSFrequencyHoppingConfigurationBandPositionsValueCodec, a0 q4.PRSFrequencyHoppingConfigurationBandPositions, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecMethodEncodeChanged(v PRSFrequencyHoppingConfigurationBandPositionsValueCodec, a0 q4.PRSFrequencyHoppingConfigurationBandPositions, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePRSIDAPERValueFieldContext(v *PRSIDAPERValue) *q4.BridgeCodecContext { return &v.context }
func BridgePRSIDAPERValueFieldReceived(v *PRSIDAPERValue) *q5.WireSpan          { return &v.received }
func BridgePRSIDAPERValueFieldReplay(v *PRSIDAPERValue) *q5.Snapshot            { return &v.replay }
func BridgePRSIDAPERValueFieldWithoutReplay(v *PRSIDAPERValue) *bool            { return &v.withoutReplay }
func BridgePRSIDValueCodecFieldCapture(v *PRSIDValueCodec) *func(q4.PRSID, q5.DecodeState) (q4.PRSID, q5.Snapshot) {
	return &v.capture
}
func BridgePRSIDValueCodecFieldCompare(v *PRSIDValueCodec) *func(q4.PRSID, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgePRSIDValueCodecFieldContext(v *PRSIDValueCodec) *q4.BridgeCodecContext { return &v.context }
func BridgePRSIDValueCodecFieldDecode(v *PRSIDValueCodec) *func([]byte, q5.DecodeState) (q4.PRSID, error) {
	return &v.decode
}
func BridgePRSIDValueCodecFieldEncode(v *PRSIDValueCodec) *func(q4.PRSID, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePRSIDValueCodecFieldPath(v *PRSIDValueCodec) *q5.Path { return &v.path }
func BridgePRSIDValueCodecMethodEncodeBudget(v PRSIDValueCodec, a0 q4.PRSID, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePRSIDValueCodecMethodEncodeChanged(v PRSIDValueCodec, a0 q4.PRSID, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePRSOccasionGroupAPERValueFieldContext(v *PRSOccasionGroupAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePRSOccasionGroupAPERValueFieldReceived(v *PRSOccasionGroupAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgePRSOccasionGroupAPERValueFieldReplay(v *PRSOccasionGroupAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgePRSOccasionGroupAPERValueFieldWithoutReplay(v *PRSOccasionGroupAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePRSOccasionGroupValueCodecFieldCapture(v *PRSOccasionGroupValueCodec) *func(q4.PRSOccasionGroup, q5.DecodeState) (q4.PRSOccasionGroup, q5.Snapshot) {
	return &v.capture
}
func BridgePRSOccasionGroupValueCodecFieldCompare(v *PRSOccasionGroupValueCodec) *func(q4.PRSOccasionGroup, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgePRSOccasionGroupValueCodecFieldContext(v *PRSOccasionGroupValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePRSOccasionGroupValueCodecFieldDecode(v *PRSOccasionGroupValueCodec) *func([]byte, q5.DecodeState) (q4.PRSOccasionGroup, error) {
	return &v.decode
}
func BridgePRSOccasionGroupValueCodecFieldEncode(v *PRSOccasionGroupValueCodec) *func(q4.PRSOccasionGroup, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePRSOccasionGroupValueCodecFieldPath(v *PRSOccasionGroupValueCodec) *q5.Path {
	return &v.path
}
func BridgePRSOccasionGroupValueCodecMethodEncodeBudget(v PRSOccasionGroupValueCodec, a0 q4.PRSOccasionGroup, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePRSOccasionGroupValueCodecMethodEncodeChanged(v PRSOccasionGroupValueCodec, a0 q4.PRSOccasionGroup, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePhysCellIDGERANAPERValueFieldContext(v *PhysCellIDGERANAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePhysCellIDGERANAPERValueFieldReceived(v *PhysCellIDGERANAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgePhysCellIDGERANAPERValueFieldReplay(v *PhysCellIDGERANAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgePhysCellIDGERANAPERValueFieldWithoutReplay(v *PhysCellIDGERANAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePhysCellIDGERANValueCodecFieldCapture(v *PhysCellIDGERANValueCodec) *func(q4.PhysCellIDGERAN, q5.DecodeState) (q4.PhysCellIDGERAN, q5.Snapshot) {
	return &v.capture
}
func BridgePhysCellIDGERANValueCodecFieldCompare(v *PhysCellIDGERANValueCodec) *func(q4.PhysCellIDGERAN, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgePhysCellIDGERANValueCodecFieldContext(v *PhysCellIDGERANValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePhysCellIDGERANValueCodecFieldDecode(v *PhysCellIDGERANValueCodec) *func([]byte, q5.DecodeState) (q4.PhysCellIDGERAN, error) {
	return &v.decode
}
func BridgePhysCellIDGERANValueCodecFieldEncode(v *PhysCellIDGERANValueCodec) *func(q4.PhysCellIDGERAN, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePhysCellIDGERANValueCodecFieldPath(v *PhysCellIDGERANValueCodec) *q5.Path { return &v.path }
func BridgePhysCellIDGERANValueCodecMethodEncodeBudget(v PhysCellIDGERANValueCodec, a0 q4.PhysCellIDGERAN, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePhysCellIDGERANValueCodecMethodEncodeChanged(v PhysCellIDGERANValueCodec, a0 q4.PhysCellIDGERAN, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePhysCellIDUTRAFDDAPERValueFieldContext(v *PhysCellIDUTRAFDDAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePhysCellIDUTRAFDDAPERValueFieldReceived(v *PhysCellIDUTRAFDDAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgePhysCellIDUTRAFDDAPERValueFieldReplay(v *PhysCellIDUTRAFDDAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgePhysCellIDUTRAFDDAPERValueFieldWithoutReplay(v *PhysCellIDUTRAFDDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePhysCellIDUTRAFDDValueCodecFieldCapture(v *PhysCellIDUTRAFDDValueCodec) *func(q4.PhysCellIDUTRAFDD, q5.DecodeState) (q4.PhysCellIDUTRAFDD, q5.Snapshot) {
	return &v.capture
}
func BridgePhysCellIDUTRAFDDValueCodecFieldCompare(v *PhysCellIDUTRAFDDValueCodec) *func(q4.PhysCellIDUTRAFDD, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgePhysCellIDUTRAFDDValueCodecFieldContext(v *PhysCellIDUTRAFDDValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePhysCellIDUTRAFDDValueCodecFieldDecode(v *PhysCellIDUTRAFDDValueCodec) *func([]byte, q5.DecodeState) (q4.PhysCellIDUTRAFDD, error) {
	return &v.decode
}
func BridgePhysCellIDUTRAFDDValueCodecFieldEncode(v *PhysCellIDUTRAFDDValueCodec) *func(q4.PhysCellIDUTRAFDD, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePhysCellIDUTRAFDDValueCodecFieldPath(v *PhysCellIDUTRAFDDValueCodec) *q5.Path {
	return &v.path
}
func BridgePhysCellIDUTRAFDDValueCodecMethodEncodeBudget(v PhysCellIDUTRAFDDValueCodec, a0 q4.PhysCellIDUTRAFDD, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePhysCellIDUTRAFDDValueCodecMethodEncodeChanged(v PhysCellIDUTRAFDDValueCodec, a0 q4.PhysCellIDUTRAFDD, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePhysCellIDUTRATDDAPERValueFieldContext(v *PhysCellIDUTRATDDAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePhysCellIDUTRATDDAPERValueFieldReceived(v *PhysCellIDUTRATDDAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgePhysCellIDUTRATDDAPERValueFieldReplay(v *PhysCellIDUTRATDDAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgePhysCellIDUTRATDDAPERValueFieldWithoutReplay(v *PhysCellIDUTRATDDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePhysCellIDUTRATDDValueCodecFieldCapture(v *PhysCellIDUTRATDDValueCodec) *func(q4.PhysCellIDUTRATDD, q5.DecodeState) (q4.PhysCellIDUTRATDD, q5.Snapshot) {
	return &v.capture
}
func BridgePhysCellIDUTRATDDValueCodecFieldCompare(v *PhysCellIDUTRATDDValueCodec) *func(q4.PhysCellIDUTRATDD, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgePhysCellIDUTRATDDValueCodecFieldContext(v *PhysCellIDUTRATDDValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePhysCellIDUTRATDDValueCodecFieldDecode(v *PhysCellIDUTRATDDValueCodec) *func([]byte, q5.DecodeState) (q4.PhysCellIDUTRATDD, error) {
	return &v.decode
}
func BridgePhysCellIDUTRATDDValueCodecFieldEncode(v *PhysCellIDUTRATDDValueCodec) *func(q4.PhysCellIDUTRATDD, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePhysCellIDUTRATDDValueCodecFieldPath(v *PhysCellIDUTRATDDValueCodec) *q5.Path {
	return &v.path
}
func BridgePhysCellIDUTRATDDValueCodecMethodEncodeBudget(v PhysCellIDUTRATDDValueCodec, a0 q4.PhysCellIDUTRATDD, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePhysCellIDUTRATDDValueCodecMethodEncodeChanged(v PhysCellIDUTRATDDValueCodec, a0 q4.PhysCellIDUTRATDD, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePosSIBTypeAPERValueFieldContext(v *PosSIBTypeAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBTypeAPERValueFieldReceived(v *PosSIBTypeAPERValue) *q5.WireSpan { return &v.received }
func BridgePosSIBTypeAPERValueFieldReplay(v *PosSIBTypeAPERValue) *q5.Snapshot   { return &v.replay }
func BridgePosSIBTypeAPERValueFieldWithoutReplay(v *PosSIBTypeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePosSIBTypeValueCodecFieldCapture(v *PosSIBTypeValueCodec) *func(q4.PosSIBType, q5.DecodeState) (q4.PosSIBType, q5.Snapshot) {
	return &v.capture
}
func BridgePosSIBTypeValueCodecFieldCompare(v *PosSIBTypeValueCodec) *func(q4.PosSIBType, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgePosSIBTypeValueCodecFieldContext(v *PosSIBTypeValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBTypeValueCodecFieldDecode(v *PosSIBTypeValueCodec) *func([]byte, q5.DecodeState) (q4.PosSIBType, error) {
	return &v.decode
}
func BridgePosSIBTypeValueCodecFieldEncode(v *PosSIBTypeValueCodec) *func(q4.PosSIBType, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePosSIBTypeValueCodecFieldPath(v *PosSIBTypeValueCodec) *q5.Path { return &v.path }
func BridgePosSIBTypeValueCodecMethodEncodeBudget(v PosSIBTypeValueCodec, a0 q4.PosSIBType, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePosSIBTypeValueCodecMethodEncodeChanged(v PosSIBTypeValueCodec, a0 q4.PosSIBType, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePresenceAPERValueFieldContext(v *PresenceAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePresenceAPERValueFieldReceived(v *PresenceAPERValue) *q5.WireSpan { return &v.received }
func BridgePresenceAPERValueFieldReplay(v *PresenceAPERValue) *q5.Snapshot   { return &v.replay }
func BridgePresenceAPERValueFieldWithoutReplay(v *PresenceAPERValue) *bool   { return &v.withoutReplay }
func BridgePresenceValueCodecFieldCapture(v *PresenceValueCodec) *func(q4.Presence, q5.DecodeState) (q4.Presence, q5.Snapshot) {
	return &v.capture
}
func BridgePresenceValueCodecFieldCompare(v *PresenceValueCodec) *func(q4.Presence, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgePresenceValueCodecFieldContext(v *PresenceValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgePresenceValueCodecFieldDecode(v *PresenceValueCodec) *func([]byte, q5.DecodeState) (q4.Presence, error) {
	return &v.decode
}
func BridgePresenceValueCodecFieldEncode(v *PresenceValueCodec) *func(q4.Presence, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePresenceValueCodecFieldPath(v *PresenceValueCodec) *q5.Path { return &v.path }
func BridgePresenceValueCodecMethodEncodeBudget(v PresenceValueCodec, a0 q4.Presence, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePresenceValueCodecMethodEncodeChanged(v PresenceValueCodec, a0 q4.Presence, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeProcedureCodeAPERValueFieldContext(v *ProcedureCodeAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeProcedureCodeAPERValueFieldReceived(v *ProcedureCodeAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeProcedureCodeAPERValueFieldReplay(v *ProcedureCodeAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeProcedureCodeAPERValueFieldWithoutReplay(v *ProcedureCodeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeProcedureCodeValueCodecFieldCapture(v *ProcedureCodeValueCodec) *func(q4.ProcedureCode, q5.DecodeState) (q4.ProcedureCode, q5.Snapshot) {
	return &v.capture
}
func BridgeProcedureCodeValueCodecFieldCompare(v *ProcedureCodeValueCodec) *func(q4.ProcedureCode, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeProcedureCodeValueCodecFieldContext(v *ProcedureCodeValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeProcedureCodeValueCodecFieldDecode(v *ProcedureCodeValueCodec) *func([]byte, q5.DecodeState) (q4.ProcedureCode, error) {
	return &v.decode
}
func BridgeProcedureCodeValueCodecFieldEncode(v *ProcedureCodeValueCodec) *func(q4.ProcedureCode, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeProcedureCodeValueCodecFieldPath(v *ProcedureCodeValueCodec) *q5.Path { return &v.path }
func BridgeProcedureCodeValueCodecMethodEncodeBudget(v ProcedureCodeValueCodec, a0 q4.ProcedureCode, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeProcedureCodeValueCodecMethodEncodeChanged(v ProcedureCodeValueCodec, a0 q4.ProcedureCode, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeProtocolIEIDAPERValueFieldContext(v *ProtocolIEIDAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeProtocolIEIDAPERValueFieldReceived(v *ProtocolIEIDAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeProtocolIEIDAPERValueFieldReplay(v *ProtocolIEIDAPERValue) *q5.Snapshot { return &v.replay }
func BridgeProtocolIEIDAPERValueFieldWithoutReplay(v *ProtocolIEIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeProtocolIEIDValueCodecFieldCapture(v *ProtocolIEIDValueCodec) *func(q4.ProtocolIEID, q5.DecodeState) (q4.ProtocolIEID, q5.Snapshot) {
	return &v.capture
}
func BridgeProtocolIEIDValueCodecFieldCompare(v *ProtocolIEIDValueCodec) *func(q4.ProtocolIEID, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeProtocolIEIDValueCodecFieldContext(v *ProtocolIEIDValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeProtocolIEIDValueCodecFieldDecode(v *ProtocolIEIDValueCodec) *func([]byte, q5.DecodeState) (q4.ProtocolIEID, error) {
	return &v.decode
}
func BridgeProtocolIEIDValueCodecFieldEncode(v *ProtocolIEIDValueCodec) *func(q4.ProtocolIEID, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeProtocolIEIDValueCodecFieldPath(v *ProtocolIEIDValueCodec) *q5.Path { return &v.path }
func BridgeProtocolIEIDValueCodecMethodEncodeBudget(v ProtocolIEIDValueCodec, a0 q4.ProtocolIEID, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeProtocolIEIDValueCodecMethodEncodeChanged(v ProtocolIEIDValueCodec, a0 q4.ProtocolIEID, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRSSIAPERValueFieldContext(v *RSSIAPERValue) *q4.BridgeCodecContext { return &v.context }
func BridgeRSSIAPERValueFieldReceived(v *RSSIAPERValue) *q5.WireSpan          { return &v.received }
func BridgeRSSIAPERValueFieldReplay(v *RSSIAPERValue) *q5.Snapshot            { return &v.replay }
func BridgeRSSIAPERValueFieldWithoutReplay(v *RSSIAPERValue) *bool            { return &v.withoutReplay }
func BridgeRSSIValueCodecFieldCapture(v *RSSIValueCodec) *func(q4.RSSI, q5.DecodeState) (q4.RSSI, q5.Snapshot) {
	return &v.capture
}
func BridgeRSSIValueCodecFieldCompare(v *RSSIValueCodec) *func(q4.RSSI, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeRSSIValueCodecFieldContext(v *RSSIValueCodec) *q4.BridgeCodecContext { return &v.context }
func BridgeRSSIValueCodecFieldDecode(v *RSSIValueCodec) *func([]byte, q5.DecodeState) (q4.RSSI, error) {
	return &v.decode
}
func BridgeRSSIValueCodecFieldEncode(v *RSSIValueCodec) *func(q4.RSSI, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRSSIValueCodecFieldPath(v *RSSIValueCodec) *q5.Path { return &v.path }
func BridgeRSSIValueCodecMethodEncodeBudget(v RSSIValueCodec, a0 q4.RSSI, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeRSSIValueCodecMethodEncodeChanged(v RSSIValueCodec, a0 q4.RSSI, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRepetitionNumberofSIB1NBAPERValueFieldContext(v *RepetitionNumberofSIB1NBAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeRepetitionNumberofSIB1NBAPERValueFieldReceived(v *RepetitionNumberofSIB1NBAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeRepetitionNumberofSIB1NBAPERValueFieldReplay(v *RepetitionNumberofSIB1NBAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeRepetitionNumberofSIB1NBAPERValueFieldWithoutReplay(v *RepetitionNumberofSIB1NBAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRepetitionNumberofSIB1NBValueCodecFieldCapture(v *RepetitionNumberofSIB1NBValueCodec) *func(q4.RepetitionNumberofSIB1NB, q5.DecodeState) (q4.RepetitionNumberofSIB1NB, q5.Snapshot) {
	return &v.capture
}
func BridgeRepetitionNumberofSIB1NBValueCodecFieldCompare(v *RepetitionNumberofSIB1NBValueCodec) *func(q4.RepetitionNumberofSIB1NB, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeRepetitionNumberofSIB1NBValueCodecFieldContext(v *RepetitionNumberofSIB1NBValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeRepetitionNumberofSIB1NBValueCodecFieldDecode(v *RepetitionNumberofSIB1NBValueCodec) *func([]byte, q5.DecodeState) (q4.RepetitionNumberofSIB1NB, error) {
	return &v.decode
}
func BridgeRepetitionNumberofSIB1NBValueCodecFieldEncode(v *RepetitionNumberofSIB1NBValueCodec) *func(q4.RepetitionNumberofSIB1NB, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRepetitionNumberofSIB1NBValueCodecFieldPath(v *RepetitionNumberofSIB1NBValueCodec) *q5.Path {
	return &v.path
}
func BridgeRepetitionNumberofSIB1NBValueCodecMethodEncodeBudget(v RepetitionNumberofSIB1NBValueCodec, a0 q4.RepetitionNumberofSIB1NB, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeRepetitionNumberofSIB1NBValueCodecMethodEncodeChanged(v RepetitionNumberofSIB1NBValueCodec, a0 q4.RepetitionNumberofSIB1NB, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeReportCharacteristicsAPERValueFieldContext(v *ReportCharacteristicsAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeReportCharacteristicsAPERValueFieldReceived(v *ReportCharacteristicsAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeReportCharacteristicsAPERValueFieldReplay(v *ReportCharacteristicsAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeReportCharacteristicsAPERValueFieldWithoutReplay(v *ReportCharacteristicsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeReportCharacteristicsValueCodecFieldCapture(v *ReportCharacteristicsValueCodec) *func(q4.ReportCharacteristics, q5.DecodeState) (q4.ReportCharacteristics, q5.Snapshot) {
	return &v.capture
}
func BridgeReportCharacteristicsValueCodecFieldCompare(v *ReportCharacteristicsValueCodec) *func(q4.ReportCharacteristics, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeReportCharacteristicsValueCodecFieldContext(v *ReportCharacteristicsValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeReportCharacteristicsValueCodecFieldDecode(v *ReportCharacteristicsValueCodec) *func([]byte, q5.DecodeState) (q4.ReportCharacteristics, error) {
	return &v.decode
}
func BridgeReportCharacteristicsValueCodecFieldEncode(v *ReportCharacteristicsValueCodec) *func(q4.ReportCharacteristics, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeReportCharacteristicsValueCodecFieldPath(v *ReportCharacteristicsValueCodec) *q5.Path {
	return &v.path
}
func BridgeReportCharacteristicsValueCodecMethodEncodeBudget(v ReportCharacteristicsValueCodec, a0 q4.ReportCharacteristics, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeReportCharacteristicsValueCodecMethodEncodeChanged(v ReportCharacteristicsValueCodec, a0 q4.ReportCharacteristics, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSFNInitialisationTimeAPERValueFieldContext(v *SFNInitialisationTimeAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeSFNInitialisationTimeAPERValueFieldReceived(v *SFNInitialisationTimeAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeSFNInitialisationTimeAPERValueFieldReplay(v *SFNInitialisationTimeAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeSFNInitialisationTimeAPERValueFieldWithoutReplay(v *SFNInitialisationTimeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSFNInitialisationTimeValueCodecFieldCapture(v *SFNInitialisationTimeValueCodec) *func(q4.SFNInitialisationTime, q5.DecodeState) (q4.SFNInitialisationTime, q5.Snapshot) {
	return &v.capture
}
func BridgeSFNInitialisationTimeValueCodecFieldCompare(v *SFNInitialisationTimeValueCodec) *func(q4.SFNInitialisationTime, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeSFNInitialisationTimeValueCodecFieldContext(v *SFNInitialisationTimeValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeSFNInitialisationTimeValueCodecFieldDecode(v *SFNInitialisationTimeValueCodec) *func([]byte, q5.DecodeState) (q4.SFNInitialisationTime, error) {
	return &v.decode
}
func BridgeSFNInitialisationTimeValueCodecFieldEncode(v *SFNInitialisationTimeValueCodec) *func(q4.SFNInitialisationTime, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSFNInitialisationTimeValueCodecFieldPath(v *SFNInitialisationTimeValueCodec) *q5.Path {
	return &v.path
}
func BridgeSFNInitialisationTimeValueCodecMethodEncodeBudget(v SFNInitialisationTimeValueCodec, a0 q4.SFNInitialisationTime, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSFNInitialisationTimeValueCodecMethodEncodeChanged(v SFNInitialisationTimeValueCodec, a0 q4.SFNInitialisationTime, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSSBIndexAPERValueFieldContext(v *SSBIndexAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeSSBIndexAPERValueFieldReceived(v *SSBIndexAPERValue) *q5.WireSpan { return &v.received }
func BridgeSSBIndexAPERValueFieldReplay(v *SSBIndexAPERValue) *q5.Snapshot   { return &v.replay }
func BridgeSSBIndexAPERValueFieldWithoutReplay(v *SSBIndexAPERValue) *bool   { return &v.withoutReplay }
func BridgeSSBIndexValueCodecFieldCapture(v *SSBIndexValueCodec) *func(q4.SSBIndex, q5.DecodeState) (q4.SSBIndex, q5.Snapshot) {
	return &v.capture
}
func BridgeSSBIndexValueCodecFieldCompare(v *SSBIndexValueCodec) *func(q4.SSBIndex, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeSSBIndexValueCodecFieldContext(v *SSBIndexValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeSSBIndexValueCodecFieldDecode(v *SSBIndexValueCodec) *func([]byte, q5.DecodeState) (q4.SSBIndex, error) {
	return &v.decode
}
func BridgeSSBIndexValueCodecFieldEncode(v *SSBIndexValueCodec) *func(q4.SSBIndex, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSSBIndexValueCodecFieldPath(v *SSBIndexValueCodec) *q5.Path { return &v.path }
func BridgeSSBIndexValueCodecMethodEncodeBudget(v SSBIndexValueCodec, a0 q4.SSBIndex, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSSBIndexValueCodecMethodEncodeChanged(v SSBIndexValueCodec, a0 q4.SSBIndex, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSSIDAPERValueFieldContext(v *SSIDAPERValue) *q4.BridgeCodecContext { return &v.context }
func BridgeSSIDAPERValueFieldReceived(v *SSIDAPERValue) *q5.WireSpan          { return &v.received }
func BridgeSSIDAPERValueFieldReplay(v *SSIDAPERValue) *q5.Snapshot            { return &v.replay }
func BridgeSSIDAPERValueFieldWithoutReplay(v *SSIDAPERValue) *bool            { return &v.withoutReplay }
func BridgeSSIDValueCodecFieldCapture(v *SSIDValueCodec) *func(q4.SSID, q5.DecodeState) (q4.SSID, q5.Snapshot) {
	return &v.capture
}
func BridgeSSIDValueCodecFieldCompare(v *SSIDValueCodec) *func(q4.SSID, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeSSIDValueCodecFieldContext(v *SSIDValueCodec) *q4.BridgeCodecContext { return &v.context }
func BridgeSSIDValueCodecFieldDecode(v *SSIDValueCodec) *func([]byte, q5.DecodeState) (q4.SSID, error) {
	return &v.decode
}
func BridgeSSIDValueCodecFieldEncode(v *SSIDValueCodec) *func(q4.SSID, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSSIDValueCodecFieldPath(v *SSIDValueCodec) *q5.Path { return &v.path }
func BridgeSSIDValueCodecMethodEncodeBudget(v SSIDValueCodec, a0 q4.SSID, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSSIDValueCodecMethodEncodeChanged(v SSIDValueCodec, a0 q4.SSID, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSSNRRSRPAPERValueFieldContext(v *SSNRRSRPAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeSSNRRSRPAPERValueFieldReceived(v *SSNRRSRPAPERValue) *q5.WireSpan { return &v.received }
func BridgeSSNRRSRPAPERValueFieldReplay(v *SSNRRSRPAPERValue) *q5.Snapshot   { return &v.replay }
func BridgeSSNRRSRPAPERValueFieldWithoutReplay(v *SSNRRSRPAPERValue) *bool   { return &v.withoutReplay }
func BridgeSSNRRSRPValueCodecFieldCapture(v *SSNRRSRPValueCodec) *func(q4.SSNRRSRP, q5.DecodeState) (q4.SSNRRSRP, q5.Snapshot) {
	return &v.capture
}
func BridgeSSNRRSRPValueCodecFieldCompare(v *SSNRRSRPValueCodec) *func(q4.SSNRRSRP, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeSSNRRSRPValueCodecFieldContext(v *SSNRRSRPValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeSSNRRSRPValueCodecFieldDecode(v *SSNRRSRPValueCodec) *func([]byte, q5.DecodeState) (q4.SSNRRSRP, error) {
	return &v.decode
}
func BridgeSSNRRSRPValueCodecFieldEncode(v *SSNRRSRPValueCodec) *func(q4.SSNRRSRP, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSSNRRSRPValueCodecFieldPath(v *SSNRRSRPValueCodec) *q5.Path { return &v.path }
func BridgeSSNRRSRPValueCodecMethodEncodeBudget(v SSNRRSRPValueCodec, a0 q4.SSNRRSRP, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSSNRRSRPValueCodecMethodEncodeChanged(v SSNRRSRPValueCodec, a0 q4.SSNRRSRP, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSSNRRSRQAPERValueFieldContext(v *SSNRRSRQAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeSSNRRSRQAPERValueFieldReceived(v *SSNRRSRQAPERValue) *q5.WireSpan { return &v.received }
func BridgeSSNRRSRQAPERValueFieldReplay(v *SSNRRSRQAPERValue) *q5.Snapshot   { return &v.replay }
func BridgeSSNRRSRQAPERValueFieldWithoutReplay(v *SSNRRSRQAPERValue) *bool   { return &v.withoutReplay }
func BridgeSSNRRSRQValueCodecFieldCapture(v *SSNRRSRQValueCodec) *func(q4.SSNRRSRQ, q5.DecodeState) (q4.SSNRRSRQ, q5.Snapshot) {
	return &v.capture
}
func BridgeSSNRRSRQValueCodecFieldCompare(v *SSNRRSRQValueCodec) *func(q4.SSNRRSRQ, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeSSNRRSRQValueCodecFieldContext(v *SSNRRSRQValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeSSNRRSRQValueCodecFieldDecode(v *SSNRRSRQValueCodec) *func([]byte, q5.DecodeState) (q4.SSNRRSRQ, error) {
	return &v.decode
}
func BridgeSSNRRSRQValueCodecFieldEncode(v *SSNRRSRQValueCodec) *func(q4.SSNRRSRQ, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSSNRRSRQValueCodecFieldPath(v *SSNRRSRQValueCodec) *q5.Path { return &v.path }
func BridgeSSNRRSRQValueCodecMethodEncodeBudget(v SSNRRSRQValueCodec, a0 q4.SSNRRSRQ, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSSNRRSRQValueCodecMethodEncodeChanged(v SSNRRSRQValueCodec, a0 q4.SSNRRSRQ, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTACAPERValueFieldContext(v *TACAPERValue) *q4.BridgeCodecContext { return &v.context }
func BridgeTACAPERValueFieldReceived(v *TACAPERValue) *q5.WireSpan          { return &v.received }
func BridgeTACAPERValueFieldReplay(v *TACAPERValue) *q5.Snapshot            { return &v.replay }
func BridgeTACAPERValueFieldWithoutReplay(v *TACAPERValue) *bool            { return &v.withoutReplay }
func BridgeTACValueCodecFieldCapture(v *TACValueCodec) *func(q4.TAC, q5.DecodeState) (q4.TAC, q5.Snapshot) {
	return &v.capture
}
func BridgeTACValueCodecFieldCompare(v *TACValueCodec) *func(q4.TAC, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeTACValueCodecFieldContext(v *TACValueCodec) *q4.BridgeCodecContext { return &v.context }
func BridgeTACValueCodecFieldDecode(v *TACValueCodec) *func([]byte, q5.DecodeState) (q4.TAC, error) {
	return &v.decode
}
func BridgeTACValueCodecFieldEncode(v *TACValueCodec) *func(q4.TAC, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTACValueCodecFieldPath(v *TACValueCodec) *q5.Path { return &v.path }
func BridgeTACValueCodecMethodEncodeBudget(v TACValueCodec, a0 q4.TAC, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeTACValueCodecMethodEncodeChanged(v TACValueCodec, a0 q4.TAC, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTPIDAPERValueFieldContext(v *TPIDAPERValue) *q4.BridgeCodecContext { return &v.context }
func BridgeTPIDAPERValueFieldReceived(v *TPIDAPERValue) *q5.WireSpan          { return &v.received }
func BridgeTPIDAPERValueFieldReplay(v *TPIDAPERValue) *q5.Snapshot            { return &v.replay }
func BridgeTPIDAPERValueFieldWithoutReplay(v *TPIDAPERValue) *bool            { return &v.withoutReplay }
func BridgeTPIDValueCodecFieldCapture(v *TPIDValueCodec) *func(q4.TPID, q5.DecodeState) (q4.TPID, q5.Snapshot) {
	return &v.capture
}
func BridgeTPIDValueCodecFieldCompare(v *TPIDValueCodec) *func(q4.TPID, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeTPIDValueCodecFieldContext(v *TPIDValueCodec) *q4.BridgeCodecContext { return &v.context }
func BridgeTPIDValueCodecFieldDecode(v *TPIDValueCodec) *func([]byte, q5.DecodeState) (q4.TPID, error) {
	return &v.decode
}
func BridgeTPIDValueCodecFieldEncode(v *TPIDValueCodec) *func(q4.TPID, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTPIDValueCodecFieldPath(v *TPIDValueCodec) *q5.Path { return &v.path }
func BridgeTPIDValueCodecMethodEncodeBudget(v TPIDValueCodec, a0 q4.TPID, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeTPIDValueCodecMethodEncodeChanged(v TPIDValueCodec, a0 q4.TPID, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTPTypeAPERValueFieldContext(v *TPTypeAPERValue) *q4.BridgeCodecContext { return &v.context }
func BridgeTPTypeAPERValueFieldReceived(v *TPTypeAPERValue) *q5.WireSpan          { return &v.received }
func BridgeTPTypeAPERValueFieldReplay(v *TPTypeAPERValue) *q5.Snapshot            { return &v.replay }
func BridgeTPTypeAPERValueFieldWithoutReplay(v *TPTypeAPERValue) *bool            { return &v.withoutReplay }
func BridgeTPTypeValueCodecFieldCapture(v *TPTypeValueCodec) *func(q4.TPType, q5.DecodeState) (q4.TPType, q5.Snapshot) {
	return &v.capture
}
func BridgeTPTypeValueCodecFieldCompare(v *TPTypeValueCodec) *func(q4.TPType, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeTPTypeValueCodecFieldContext(v *TPTypeValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeTPTypeValueCodecFieldDecode(v *TPTypeValueCodec) *func([]byte, q5.DecodeState) (q4.TPType, error) {
	return &v.decode
}
func BridgeTPTypeValueCodecFieldEncode(v *TPTypeValueCodec) *func(q4.TPType, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTPTypeValueCodecFieldPath(v *TPTypeValueCodec) *q5.Path { return &v.path }
func BridgeTPTypeValueCodecMethodEncodeBudget(v TPTypeValueCodec, a0 q4.TPType, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeTPTypeValueCodecMethodEncodeChanged(v TPTypeValueCodec, a0 q4.TPType, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTriggeringMessageAPERValueFieldContext(v *TriggeringMessageAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeTriggeringMessageAPERValueFieldReceived(v *TriggeringMessageAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeTriggeringMessageAPERValueFieldReplay(v *TriggeringMessageAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeTriggeringMessageAPERValueFieldWithoutReplay(v *TriggeringMessageAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTriggeringMessageValueCodecFieldCapture(v *TriggeringMessageValueCodec) *func(q4.TriggeringMessage, q5.DecodeState) (q4.TriggeringMessage, q5.Snapshot) {
	return &v.capture
}
func BridgeTriggeringMessageValueCodecFieldCompare(v *TriggeringMessageValueCodec) *func(q4.TriggeringMessage, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeTriggeringMessageValueCodecFieldContext(v *TriggeringMessageValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeTriggeringMessageValueCodecFieldDecode(v *TriggeringMessageValueCodec) *func([]byte, q5.DecodeState) (q4.TriggeringMessage, error) {
	return &v.decode
}
func BridgeTriggeringMessageValueCodecFieldEncode(v *TriggeringMessageValueCodec) *func(q4.TriggeringMessage, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTriggeringMessageValueCodecFieldPath(v *TriggeringMessageValueCodec) *q5.Path {
	return &v.path
}
func BridgeTriggeringMessageValueCodecMethodEncodeBudget(v TriggeringMessageValueCodec, a0 q4.TriggeringMessage, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeTriggeringMessageValueCodecMethodEncodeChanged(v TriggeringMessageValueCodec, a0 q4.TriggeringMessage, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTypeOfErrorAPERValueFieldContext(v *TypeOfErrorAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeTypeOfErrorAPERValueFieldReceived(v *TypeOfErrorAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeTypeOfErrorAPERValueFieldReplay(v *TypeOfErrorAPERValue) *q5.Snapshot { return &v.replay }
func BridgeTypeOfErrorAPERValueFieldWithoutReplay(v *TypeOfErrorAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTypeOfErrorValueCodecFieldCapture(v *TypeOfErrorValueCodec) *func(q4.TypeOfError, q5.DecodeState) (q4.TypeOfError, q5.Snapshot) {
	return &v.capture
}
func BridgeTypeOfErrorValueCodecFieldCompare(v *TypeOfErrorValueCodec) *func(q4.TypeOfError, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeTypeOfErrorValueCodecFieldContext(v *TypeOfErrorValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeTypeOfErrorValueCodecFieldDecode(v *TypeOfErrorValueCodec) *func([]byte, q5.DecodeState) (q4.TypeOfError, error) {
	return &v.decode
}
func BridgeTypeOfErrorValueCodecFieldEncode(v *TypeOfErrorValueCodec) *func(q4.TypeOfError, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTypeOfErrorValueCodecFieldPath(v *TypeOfErrorValueCodec) *q5.Path { return &v.path }
func BridgeTypeOfErrorValueCodecMethodEncodeBudget(v TypeOfErrorValueCodec, a0 q4.TypeOfError, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeTypeOfErrorValueCodecMethodEncodeChanged(v TypeOfErrorValueCodec, a0 q4.TypeOfError, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUARFCNAPERValueFieldContext(v *UARFCNAPERValue) *q4.BridgeCodecContext { return &v.context }
func BridgeUARFCNAPERValueFieldReceived(v *UARFCNAPERValue) *q5.WireSpan          { return &v.received }
func BridgeUARFCNAPERValueFieldReplay(v *UARFCNAPERValue) *q5.Snapshot            { return &v.replay }
func BridgeUARFCNAPERValueFieldWithoutReplay(v *UARFCNAPERValue) *bool            { return &v.withoutReplay }
func BridgeUARFCNValueCodecFieldCapture(v *UARFCNValueCodec) *func(q4.UARFCN, q5.DecodeState) (q4.UARFCN, q5.Snapshot) {
	return &v.capture
}
func BridgeUARFCNValueCodecFieldCompare(v *UARFCNValueCodec) *func(q4.UARFCN, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeUARFCNValueCodecFieldContext(v *UARFCNValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeUARFCNValueCodecFieldDecode(v *UARFCNValueCodec) *func([]byte, q5.DecodeState) (q4.UARFCN, error) {
	return &v.decode
}
func BridgeUARFCNValueCodecFieldEncode(v *UARFCNValueCodec) *func(q4.UARFCN, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUARFCNValueCodecFieldPath(v *UARFCNValueCodec) *q5.Path { return &v.path }
func BridgeUARFCNValueCodecMethodEncodeBudget(v UARFCNValueCodec, a0 q4.UARFCN, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeUARFCNValueCodecMethodEncodeChanged(v UARFCNValueCodec, a0 q4.UARFCN, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUTRAEcN0APERValueFieldContext(v *UTRAEcN0APERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeUTRAEcN0APERValueFieldReceived(v *UTRAEcN0APERValue) *q5.WireSpan { return &v.received }
func BridgeUTRAEcN0APERValueFieldReplay(v *UTRAEcN0APERValue) *q5.Snapshot   { return &v.replay }
func BridgeUTRAEcN0APERValueFieldWithoutReplay(v *UTRAEcN0APERValue) *bool   { return &v.withoutReplay }
func BridgeUTRAEcN0ValueCodecFieldCapture(v *UTRAEcN0ValueCodec) *func(q4.UTRAEcN0, q5.DecodeState) (q4.UTRAEcN0, q5.Snapshot) {
	return &v.capture
}
func BridgeUTRAEcN0ValueCodecFieldCompare(v *UTRAEcN0ValueCodec) *func(q4.UTRAEcN0, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeUTRAEcN0ValueCodecFieldContext(v *UTRAEcN0ValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeUTRAEcN0ValueCodecFieldDecode(v *UTRAEcN0ValueCodec) *func([]byte, q5.DecodeState) (q4.UTRAEcN0, error) {
	return &v.decode
}
func BridgeUTRAEcN0ValueCodecFieldEncode(v *UTRAEcN0ValueCodec) *func(q4.UTRAEcN0, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTRAEcN0ValueCodecFieldPath(v *UTRAEcN0ValueCodec) *q5.Path { return &v.path }
func BridgeUTRAEcN0ValueCodecMethodEncodeBudget(v UTRAEcN0ValueCodec, a0 q4.UTRAEcN0, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeUTRAEcN0ValueCodecMethodEncodeChanged(v UTRAEcN0ValueCodec, a0 q4.UTRAEcN0, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUTRARSCPAPERValueFieldContext(v *UTRARSCPAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeUTRARSCPAPERValueFieldReceived(v *UTRARSCPAPERValue) *q5.WireSpan { return &v.received }
func BridgeUTRARSCPAPERValueFieldReplay(v *UTRARSCPAPERValue) *q5.Snapshot   { return &v.replay }
func BridgeUTRARSCPAPERValueFieldWithoutReplay(v *UTRARSCPAPERValue) *bool   { return &v.withoutReplay }
func BridgeUTRARSCPValueCodecFieldCapture(v *UTRARSCPValueCodec) *func(q4.UTRARSCP, q5.DecodeState) (q4.UTRARSCP, q5.Snapshot) {
	return &v.capture
}
func BridgeUTRARSCPValueCodecFieldCompare(v *UTRARSCPValueCodec) *func(q4.UTRARSCP, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeUTRARSCPValueCodecFieldContext(v *UTRARSCPValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeUTRARSCPValueCodecFieldDecode(v *UTRARSCPValueCodec) *func([]byte, q5.DecodeState) (q4.UTRARSCP, error) {
	return &v.decode
}
func BridgeUTRARSCPValueCodecFieldEncode(v *UTRARSCPValueCodec) *func(q4.UTRARSCP, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTRARSCPValueCodecFieldPath(v *UTRARSCPValueCodec) *q5.Path { return &v.path }
func BridgeUTRARSCPValueCodecMethodEncodeBudget(v UTRARSCPValueCodec, a0 q4.UTRARSCP, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeUTRARSCPValueCodecMethodEncodeChanged(v UTRARSCPValueCodec, a0 q4.UTRARSCP, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeValueRSRPAPERValueFieldContext(v *ValueRSRPAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeValueRSRPAPERValueFieldReceived(v *ValueRSRPAPERValue) *q5.WireSpan { return &v.received }
func BridgeValueRSRPAPERValueFieldReplay(v *ValueRSRPAPERValue) *q5.Snapshot   { return &v.replay }
func BridgeValueRSRPAPERValueFieldWithoutReplay(v *ValueRSRPAPERValue) *bool   { return &v.withoutReplay }
func BridgeValueRSRPValueCodecFieldCapture(v *ValueRSRPValueCodec) *func(q4.ValueRSRP, q5.DecodeState) (q4.ValueRSRP, q5.Snapshot) {
	return &v.capture
}
func BridgeValueRSRPValueCodecFieldCompare(v *ValueRSRPValueCodec) *func(q4.ValueRSRP, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeValueRSRPValueCodecFieldContext(v *ValueRSRPValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeValueRSRPValueCodecFieldDecode(v *ValueRSRPValueCodec) *func([]byte, q5.DecodeState) (q4.ValueRSRP, error) {
	return &v.decode
}
func BridgeValueRSRPValueCodecFieldEncode(v *ValueRSRPValueCodec) *func(q4.ValueRSRP, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeValueRSRPValueCodecFieldPath(v *ValueRSRPValueCodec) *q5.Path { return &v.path }
func BridgeValueRSRPValueCodecMethodEncodeBudget(v ValueRSRPValueCodec, a0 q4.ValueRSRP, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeValueRSRPValueCodecMethodEncodeChanged(v ValueRSRPValueCodec, a0 q4.ValueRSRP, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeValueRSRQAPERValueFieldContext(v *ValueRSRQAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeValueRSRQAPERValueFieldReceived(v *ValueRSRQAPERValue) *q5.WireSpan { return &v.received }
func BridgeValueRSRQAPERValueFieldReplay(v *ValueRSRQAPERValue) *q5.Snapshot   { return &v.replay }
func BridgeValueRSRQAPERValueFieldWithoutReplay(v *ValueRSRQAPERValue) *bool   { return &v.withoutReplay }
func BridgeValueRSRQValueCodecFieldCapture(v *ValueRSRQValueCodec) *func(q4.ValueRSRQ, q5.DecodeState) (q4.ValueRSRQ, q5.Snapshot) {
	return &v.capture
}
func BridgeValueRSRQValueCodecFieldCompare(v *ValueRSRQValueCodec) *func(q4.ValueRSRQ, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeValueRSRQValueCodecFieldContext(v *ValueRSRQValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeValueRSRQValueCodecFieldDecode(v *ValueRSRQValueCodec) *func([]byte, q5.DecodeState) (q4.ValueRSRQ, error) {
	return &v.decode
}
func BridgeValueRSRQValueCodecFieldEncode(v *ValueRSRQValueCodec) *func(q4.ValueRSRQ, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeValueRSRQValueCodecFieldPath(v *ValueRSRQValueCodec) *q5.Path { return &v.path }
func BridgeValueRSRQValueCodecMethodEncodeBudget(v ValueRSRQValueCodec, a0 q4.ValueRSRQ, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeValueRSRQValueCodecMethodEncodeChanged(v ValueRSRQValueCodec, a0 q4.ValueRSRQ, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANBandAPERValueFieldContext(v *WLANBandAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeWLANBandAPERValueFieldReceived(v *WLANBandAPERValue) *q5.WireSpan { return &v.received }
func BridgeWLANBandAPERValueFieldReplay(v *WLANBandAPERValue) *q5.Snapshot   { return &v.replay }
func BridgeWLANBandAPERValueFieldWithoutReplay(v *WLANBandAPERValue) *bool   { return &v.withoutReplay }
func BridgeWLANBandValueCodecFieldCapture(v *WLANBandValueCodec) *func(q4.WLANBand, q5.DecodeState) (q4.WLANBand, q5.Snapshot) {
	return &v.capture
}
func BridgeWLANBandValueCodecFieldCompare(v *WLANBandValueCodec) *func(q4.WLANBand, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeWLANBandValueCodecFieldContext(v *WLANBandValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeWLANBandValueCodecFieldDecode(v *WLANBandValueCodec) *func([]byte, q5.DecodeState) (q4.WLANBand, error) {
	return &v.decode
}
func BridgeWLANBandValueCodecFieldEncode(v *WLANBandValueCodec) *func(q4.WLANBand, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANBandValueCodecFieldPath(v *WLANBandValueCodec) *q5.Path { return &v.path }
func BridgeWLANBandValueCodecMethodEncodeBudget(v WLANBandValueCodec, a0 q4.WLANBand, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANBandValueCodecMethodEncodeChanged(v WLANBandValueCodec, a0 q4.WLANBand, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANChannelAPERValueFieldContext(v *WLANChannelAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeWLANChannelAPERValueFieldReceived(v *WLANChannelAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeWLANChannelAPERValueFieldReplay(v *WLANChannelAPERValue) *q5.Snapshot { return &v.replay }
func BridgeWLANChannelAPERValueFieldWithoutReplay(v *WLANChannelAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANChannelListAPERValueFieldContext(v *WLANChannelListAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeWLANChannelListAPERValueFieldReceived(v *WLANChannelListAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeWLANChannelListAPERValueFieldReplay(v *WLANChannelListAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeWLANChannelListAPERValueFieldWithoutReplay(v *WLANChannelListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANChannelListValueCodecFieldCapture(v *WLANChannelListValueCodec) *func(q4.WLANChannelList, q5.DecodeState) (q4.WLANChannelList, q5.Snapshot) {
	return &v.capture
}
func BridgeWLANChannelListValueCodecFieldCompare(v *WLANChannelListValueCodec) *func(q4.WLANChannelList, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeWLANChannelListValueCodecFieldContext(v *WLANChannelListValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeWLANChannelListValueCodecFieldDecode(v *WLANChannelListValueCodec) *func([]byte, q5.DecodeState) (q4.WLANChannelList, error) {
	return &v.decode
}
func BridgeWLANChannelListValueCodecFieldEncode(v *WLANChannelListValueCodec) *func(q4.WLANChannelList, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANChannelListValueCodecFieldPath(v *WLANChannelListValueCodec) *q5.Path { return &v.path }
func BridgeWLANChannelListValueCodecMethodEncodeBudget(v WLANChannelListValueCodec, a0 q4.WLANChannelList, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANChannelListValueCodecMethodEncodeChanged(v WLANChannelListValueCodec, a0 q4.WLANChannelList, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANChannelValueCodecFieldCapture(v *WLANChannelValueCodec) *func(q4.WLANChannel, q5.DecodeState) (q4.WLANChannel, q5.Snapshot) {
	return &v.capture
}
func BridgeWLANChannelValueCodecFieldCompare(v *WLANChannelValueCodec) *func(q4.WLANChannel, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeWLANChannelValueCodecFieldContext(v *WLANChannelValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeWLANChannelValueCodecFieldDecode(v *WLANChannelValueCodec) *func([]byte, q5.DecodeState) (q4.WLANChannel, error) {
	return &v.decode
}
func BridgeWLANChannelValueCodecFieldEncode(v *WLANChannelValueCodec) *func(q4.WLANChannel, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANChannelValueCodecFieldPath(v *WLANChannelValueCodec) *q5.Path { return &v.path }
func BridgeWLANChannelValueCodecMethodEncodeBudget(v WLANChannelValueCodec, a0 q4.WLANChannel, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANChannelValueCodecMethodEncodeChanged(v WLANChannelValueCodec, a0 q4.WLANChannel, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANCountryCodeAPERValueFieldContext(v *WLANCountryCodeAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeWLANCountryCodeAPERValueFieldReceived(v *WLANCountryCodeAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeWLANCountryCodeAPERValueFieldReplay(v *WLANCountryCodeAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeWLANCountryCodeAPERValueFieldWithoutReplay(v *WLANCountryCodeAPERValue) *bool {
	return &v.withoutReplay
}
