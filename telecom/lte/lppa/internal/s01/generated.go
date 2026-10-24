// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s01 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s01

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// ReportCharacteristicsValueCodec is the concrete ValueCodec[ReportCharacteristics].
type ReportCharacteristicsValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.ReportCharacteristics, aper.DecodeState,

	) (s00.ReportCharacteristics, aper.Snapshot,

	)
	compare func(s00.ReportCharacteristics, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.ReportCharacteristics,

		error)
	encode func(s00.ReportCharacteristics,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ReportCharacteristicsValueCodec) New(value s00.ReportCharacteristics,

) (ReportCharacteristicsAPERValue, error) {
	if c.encode == nil {
		return ReportCharacteristicsAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ReportCharacteristicsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ReportCharacteristicsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ReportCharacteristicsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ReportCharacteristicsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ReportCharacteristicsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ReportCharacteristicsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ReportCharacteristicsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ReportCharacteristicsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ReportCharacteristicsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ReportCharacteristicsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ReportCharacteristicsValueCodec) EncodeAPER(value ReportCharacteristicsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ReportCharacteristicsValueCodec) encodeBudget(value s00.ReportCharacteristics,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ReportCharacteristicsValueCodec) encodeChanged(value s00.ReportCharacteristics,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// NumberOfFrequencyHoppingBandsValueCodec is the concrete ValueCodec[NumberOfFrequencyHoppingBands].
type NumberOfFrequencyHoppingBandsValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.NumberOfFrequencyHoppingBands, aper.DecodeState,

	) (s00.NumberOfFrequencyHoppingBands, aper.Snapshot,

	)
	compare func(s00.NumberOfFrequencyHoppingBands, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.NumberOfFrequencyHoppingBands,

		error)
	encode func(s00.NumberOfFrequencyHoppingBands,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c NumberOfFrequencyHoppingBandsValueCodec) New(value s00.NumberOfFrequencyHoppingBands,

) (NumberOfFrequencyHoppingBandsAPERValue, error) {
	if c.encode == nil {
		return NumberOfFrequencyHoppingBandsAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return NumberOfFrequencyHoppingBandsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return NumberOfFrequencyHoppingBandsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return NumberOfFrequencyHoppingBandsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c NumberOfFrequencyHoppingBandsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (NumberOfFrequencyHoppingBandsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return NumberOfFrequencyHoppingBandsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return NumberOfFrequencyHoppingBandsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return NumberOfFrequencyHoppingBandsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return NumberOfFrequencyHoppingBandsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return NumberOfFrequencyHoppingBandsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c NumberOfFrequencyHoppingBandsValueCodec) EncodeAPER(value NumberOfFrequencyHoppingBandsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c NumberOfFrequencyHoppingBandsValueCodec) encodeBudget(value s00.NumberOfFrequencyHoppingBands,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c NumberOfFrequencyHoppingBandsValueCodec) encodeChanged(value s00.NumberOfFrequencyHoppingBands,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// OTDOAInformationItemValueCodec is the concrete ValueCodec[OTDOAInformationItem].
type OTDOAInformationItemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.OTDOAInformationItem, aper.DecodeState,

	) (s00.OTDOAInformationItem, aper.Snapshot,

	)
	compare func(s00.OTDOAInformationItem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.OTDOAInformationItem,

		error)
	encode func(s00.OTDOAInformationItem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c OTDOAInformationItemValueCodec) New(value s00.OTDOAInformationItem,

) (OTDOAInformationItemAPERValue, error) {
	if c.encode == nil {
		return OTDOAInformationItemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OTDOAInformationItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OTDOAInformationItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return OTDOAInformationItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c OTDOAInformationItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OTDOAInformationItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OTDOAInformationItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return OTDOAInformationItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OTDOAInformationItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return OTDOAInformationItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return OTDOAInformationItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c OTDOAInformationItemValueCodec) EncodeAPER(value OTDOAInformationItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OTDOAInformationItemValueCodec) encodeBudget(value s00.OTDOAInformationItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOAInformationItemValueCodec) encodeChanged(value s00.OTDOAInformationItem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// OffsetNBChanneltoEARFCNValueCodec is the concrete ValueCodec[OffsetNBChanneltoEARFCN].
type OffsetNBChanneltoEARFCNValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.OffsetNBChanneltoEARFCN, aper.DecodeState,

	) (s00.OffsetNBChanneltoEARFCN, aper.Snapshot,

	)
	compare func(s00.OffsetNBChanneltoEARFCN, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.OffsetNBChanneltoEARFCN,

		error)
	encode func(s00.OffsetNBChanneltoEARFCN,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c OffsetNBChanneltoEARFCNValueCodec) New(value s00.OffsetNBChanneltoEARFCN,

) (OffsetNBChanneltoEARFCNAPERValue, error) {
	if c.encode == nil {
		return OffsetNBChanneltoEARFCNAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OffsetNBChanneltoEARFCNAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OffsetNBChanneltoEARFCNAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return OffsetNBChanneltoEARFCNAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c OffsetNBChanneltoEARFCNValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OffsetNBChanneltoEARFCNAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OffsetNBChanneltoEARFCNAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return OffsetNBChanneltoEARFCNAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OffsetNBChanneltoEARFCNAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return OffsetNBChanneltoEARFCNAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return OffsetNBChanneltoEARFCNAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c OffsetNBChanneltoEARFCNValueCodec) EncodeAPER(value OffsetNBChanneltoEARFCNAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OffsetNBChanneltoEARFCNValueCodec) encodeBudget(value s00.OffsetNBChanneltoEARFCN,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OffsetNBChanneltoEARFCNValueCodec) encodeChanged(value s00.OffsetNBChanneltoEARFCN,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// OperationModeInfoValueCodec is the concrete ValueCodec[OperationModeInfo].
type OperationModeInfoValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.OperationModeInfo, aper.DecodeState,

	) (s00.OperationModeInfo, aper.Snapshot,

	)
	compare func(s00.OperationModeInfo, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.OperationModeInfo,

		error)
	encode func(s00.OperationModeInfo,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c OperationModeInfoValueCodec) New(value s00.OperationModeInfo,

) (OperationModeInfoAPERValue, error) {
	if c.encode == nil {
		return OperationModeInfoAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OperationModeInfoAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OperationModeInfoAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return OperationModeInfoAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c OperationModeInfoValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OperationModeInfoAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OperationModeInfoAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return OperationModeInfoAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OperationModeInfoAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return OperationModeInfoAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return OperationModeInfoAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c OperationModeInfoValueCodec) EncodeAPER(value OperationModeInfoAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OperationModeInfoValueCodec) encodeBudget(value s00.OperationModeInfo,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OperationModeInfoValueCodec) encodeChanged(value s00.OperationModeInfo,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// OutcomeValueCodec is the concrete ValueCodec[Outcome].
type OutcomeValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.Outcome, aper.DecodeState,

	) (s00.Outcome, aper.Snapshot,

	)
	compare func(s00.Outcome, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.Outcome,

		error)
	encode func(s00.Outcome,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c OutcomeValueCodec) New(value s00.Outcome,

) (OutcomeAPERValue, error) {
	if c.encode == nil {
		return OutcomeAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return OutcomeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return OutcomeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return OutcomeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c OutcomeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (OutcomeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return OutcomeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return OutcomeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return OutcomeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return OutcomeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return OutcomeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c OutcomeValueCodec) EncodeAPER(value OutcomeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c OutcomeValueCodec) encodeBudget(value s00.Outcome,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OutcomeValueCodec) encodeChanged(value s00.Outcome,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// PCIValueCodec is the concrete ValueCodec[PCI].
type PCIValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.PCI, aper.DecodeState,

	) (s00.PCI, aper.Snapshot,

	)
	compare func(s00.PCI, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.PCI,

		error)
	encode func(s00.PCI,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PCIValueCodec) New(value s00.PCI,

) (PCIAPERValue, error) {
	if c.encode == nil {
		return PCIAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PCIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PCIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PCIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PCIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PCIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PCIAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PCIAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PCIAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PCIAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PCIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PCIValueCodec) EncodeAPER(value PCIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PCIValueCodec) encodeBudget(value s00.PCI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PCIValueCodec) encodeChanged(value s00.PCI,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// PLMNIdentityValueCodec is the concrete ValueCodec[PLMNIdentity].
type PLMNIdentityValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.PLMNIdentity, aper.DecodeState,

	) (s00.PLMNIdentity, aper.Snapshot,

	)
	compare func(s00.PLMNIdentity, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.PLMNIdentity,

		error)
	encode func(s00.PLMNIdentity,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PLMNIdentityValueCodec) New(value s00.PLMNIdentity,

) (PLMNIdentityAPERValue, error) {
	if c.encode == nil {
		return PLMNIdentityAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PLMNIdentityAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PLMNIdentityAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PLMNIdentityAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PLMNIdentityValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PLMNIdentityAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PLMNIdentityAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PLMNIdentityAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PLMNIdentityAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PLMNIdentityAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PLMNIdentityAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PLMNIdentityValueCodec) EncodeAPER(value PLMNIdentityAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PLMNIdentityValueCodec) encodeBudget(value s00.PLMNIdentity,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PLMNIdentityValueCodec) encodeChanged(value s00.PLMNIdentity,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// PRSBandwidthValueCodec is the concrete ValueCodec[PRSBandwidth].
type PRSBandwidthValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.PRSBandwidth, aper.DecodeState,

	) (s00.PRSBandwidth, aper.Snapshot,

	)
	compare func(s00.PRSBandwidth, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.PRSBandwidth,

		error)
	encode func(s00.PRSBandwidth,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PRSBandwidthValueCodec) New(value s00.PRSBandwidth,

) (PRSBandwidthAPERValue, error) {
	if c.encode == nil {
		return PRSBandwidthAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PRSBandwidthAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PRSBandwidthAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PRSBandwidthAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PRSBandwidthValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PRSBandwidthAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PRSBandwidthAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PRSBandwidthAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PRSBandwidthAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PRSBandwidthAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PRSBandwidthAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PRSBandwidthValueCodec) EncodeAPER(value PRSBandwidthAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PRSBandwidthValueCodec) encodeBudget(value s00.PRSBandwidth,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PRSBandwidthValueCodec) encodeChanged(value s00.PRSBandwidth,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// PRSConfigurationIndexValueCodec is the concrete ValueCodec[PRSConfigurationIndex].
type PRSConfigurationIndexValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.PRSConfigurationIndex, aper.DecodeState,

	) (s00.PRSConfigurationIndex, aper.Snapshot,

	)
	compare func(s00.PRSConfigurationIndex, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.PRSConfigurationIndex,

		error)
	encode func(s00.PRSConfigurationIndex,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PRSConfigurationIndexValueCodec) New(value s00.PRSConfigurationIndex,

) (PRSConfigurationIndexAPERValue, error) {
	if c.encode == nil {
		return PRSConfigurationIndexAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PRSConfigurationIndexAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PRSConfigurationIndexAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PRSConfigurationIndexAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PRSConfigurationIndexValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PRSConfigurationIndexAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PRSConfigurationIndexAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PRSConfigurationIndexAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PRSConfigurationIndexAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PRSConfigurationIndexAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PRSConfigurationIndexAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PRSConfigurationIndexValueCodec) EncodeAPER(value PRSConfigurationIndexAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PRSConfigurationIndexValueCodec) encodeBudget(value s00.PRSConfigurationIndex,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PRSConfigurationIndexValueCodec) encodeChanged(value s00.PRSConfigurationIndex,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// PRSFrequencyHoppingConfigurationBandPositionsValueCodec is the concrete ValueCodec[PRSFrequencyHoppingConfigurationBandPositions].
type PRSFrequencyHoppingConfigurationBandPositionsValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.PRSFrequencyHoppingConfigurationBandPositions, aper.DecodeState,

	) (s00.PRSFrequencyHoppingConfigurationBandPositions, aper.Snapshot,

	)
	compare func(s00.PRSFrequencyHoppingConfigurationBandPositions, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.PRSFrequencyHoppingConfigurationBandPositions,

		error)
	encode func(s00.PRSFrequencyHoppingConfigurationBandPositions,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PRSFrequencyHoppingConfigurationBandPositionsValueCodec) New(value s00.PRSFrequencyHoppingConfigurationBandPositions,

) (PRSFrequencyHoppingConfigurationBandPositionsAPERValue, error) {
	if c.encode == nil {
		return PRSFrequencyHoppingConfigurationBandPositionsAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PRSFrequencyHoppingConfigurationBandPositionsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PRSFrequencyHoppingConfigurationBandPositionsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PRSFrequencyHoppingConfigurationBandPositionsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PRSFrequencyHoppingConfigurationBandPositionsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PRSFrequencyHoppingConfigurationBandPositionsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PRSFrequencyHoppingConfigurationBandPositionsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PRSFrequencyHoppingConfigurationBandPositionsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PRSFrequencyHoppingConfigurationBandPositionsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PRSFrequencyHoppingConfigurationBandPositionsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PRSFrequencyHoppingConfigurationBandPositionsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PRSFrequencyHoppingConfigurationBandPositionsValueCodec) EncodeAPER(value PRSFrequencyHoppingConfigurationBandPositionsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PRSFrequencyHoppingConfigurationBandPositionsValueCodec) encodeBudget(value s00.PRSFrequencyHoppingConfigurationBandPositions,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PRSFrequencyHoppingConfigurationBandPositionsValueCodec) encodeChanged(value s00.PRSFrequencyHoppingConfigurationBandPositions,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// PRSIDValueCodec is the concrete ValueCodec[PRSID].
type PRSIDValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.PRSID, aper.DecodeState,

	) (s00.PRSID, aper.Snapshot,

	)
	compare func(s00.PRSID, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.PRSID,

		error)
	encode func(s00.PRSID,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PRSIDValueCodec) New(value s00.PRSID,

) (PRSIDAPERValue, error) {
	if c.encode == nil {
		return PRSIDAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PRSIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PRSIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PRSIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PRSIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PRSIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PRSIDAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PRSIDAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PRSIDAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PRSIDAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PRSIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PRSIDValueCodec) EncodeAPER(value PRSIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PRSIDValueCodec) encodeBudget(value s00.PRSID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PRSIDValueCodec) encodeChanged(value s00.PRSID,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// PRSOccasionGroupValueCodec is the concrete ValueCodec[PRSOccasionGroup].
type PRSOccasionGroupValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.PRSOccasionGroup, aper.DecodeState,

	) (s00.PRSOccasionGroup, aper.Snapshot,

	)
	compare func(s00.PRSOccasionGroup, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.PRSOccasionGroup,

		error)
	encode func(s00.PRSOccasionGroup,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PRSOccasionGroupValueCodec) New(value s00.PRSOccasionGroup,

) (PRSOccasionGroupAPERValue, error) {
	if c.encode == nil {
		return PRSOccasionGroupAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PRSOccasionGroupAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PRSOccasionGroupAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PRSOccasionGroupAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PRSOccasionGroupValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PRSOccasionGroupAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PRSOccasionGroupAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PRSOccasionGroupAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PRSOccasionGroupAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PRSOccasionGroupAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PRSOccasionGroupAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PRSOccasionGroupValueCodec) EncodeAPER(value PRSOccasionGroupAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PRSOccasionGroupValueCodec) encodeBudget(value s00.PRSOccasionGroup,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PRSOccasionGroupValueCodec) encodeChanged(value s00.PRSOccasionGroup,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// PhysCellIDGERANValueCodec is the concrete ValueCodec[PhysCellIDGERAN].
type PhysCellIDGERANValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.PhysCellIDGERAN, aper.DecodeState,

	) (s00.PhysCellIDGERAN, aper.Snapshot,

	)
	compare func(s00.PhysCellIDGERAN, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.PhysCellIDGERAN,

		error)
	encode func(s00.PhysCellIDGERAN,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PhysCellIDGERANValueCodec) New(value s00.PhysCellIDGERAN,

) (PhysCellIDGERANAPERValue, error) {
	if c.encode == nil {
		return PhysCellIDGERANAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PhysCellIDGERANAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PhysCellIDGERANAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PhysCellIDGERANAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PhysCellIDGERANValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PhysCellIDGERANAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PhysCellIDGERANAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PhysCellIDGERANAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PhysCellIDGERANAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PhysCellIDGERANAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PhysCellIDGERANAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PhysCellIDGERANValueCodec) EncodeAPER(value PhysCellIDGERANAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PhysCellIDGERANValueCodec) encodeBudget(value s00.PhysCellIDGERAN,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PhysCellIDGERANValueCodec) encodeChanged(value s00.PhysCellIDGERAN,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// PhysCellIDUTRAFDDValueCodec is the concrete ValueCodec[PhysCellIDUTRAFDD].
type PhysCellIDUTRAFDDValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.PhysCellIDUTRAFDD, aper.DecodeState,

	) (s00.PhysCellIDUTRAFDD, aper.Snapshot,

	)
	compare func(s00.PhysCellIDUTRAFDD, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.PhysCellIDUTRAFDD,

		error)
	encode func(s00.PhysCellIDUTRAFDD,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PhysCellIDUTRAFDDValueCodec) New(value s00.PhysCellIDUTRAFDD,

) (PhysCellIDUTRAFDDAPERValue, error) {
	if c.encode == nil {
		return PhysCellIDUTRAFDDAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PhysCellIDUTRAFDDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PhysCellIDUTRAFDDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PhysCellIDUTRAFDDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PhysCellIDUTRAFDDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PhysCellIDUTRAFDDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PhysCellIDUTRAFDDAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PhysCellIDUTRAFDDAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PhysCellIDUTRAFDDAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PhysCellIDUTRAFDDAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PhysCellIDUTRAFDDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PhysCellIDUTRAFDDValueCodec) EncodeAPER(value PhysCellIDUTRAFDDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PhysCellIDUTRAFDDValueCodec) encodeBudget(value s00.PhysCellIDUTRAFDD,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PhysCellIDUTRAFDDValueCodec) encodeChanged(value s00.PhysCellIDUTRAFDD,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// PhysCellIDUTRATDDValueCodec is the concrete ValueCodec[PhysCellIDUTRATDD].
type PhysCellIDUTRATDDValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.PhysCellIDUTRATDD, aper.DecodeState,

	) (s00.PhysCellIDUTRATDD, aper.Snapshot,

	)
	compare func(s00.PhysCellIDUTRATDD, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.PhysCellIDUTRATDD,

		error)
	encode func(s00.PhysCellIDUTRATDD,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PhysCellIDUTRATDDValueCodec) New(value s00.PhysCellIDUTRATDD,

) (PhysCellIDUTRATDDAPERValue, error) {
	if c.encode == nil {
		return PhysCellIDUTRATDDAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PhysCellIDUTRATDDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PhysCellIDUTRATDDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PhysCellIDUTRATDDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PhysCellIDUTRATDDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PhysCellIDUTRATDDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PhysCellIDUTRATDDAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PhysCellIDUTRATDDAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PhysCellIDUTRATDDAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PhysCellIDUTRATDDAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PhysCellIDUTRATDDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PhysCellIDUTRATDDValueCodec) EncodeAPER(value PhysCellIDUTRATDDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PhysCellIDUTRATDDValueCodec) encodeBudget(value s00.PhysCellIDUTRATDD,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PhysCellIDUTRATDDValueCodec) encodeChanged(value s00.PhysCellIDUTRATDD,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// PosSIBTypeValueCodec is the concrete ValueCodec[PosSIBType].
type PosSIBTypeValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.PosSIBType, aper.DecodeState,

	) (s00.PosSIBType, aper.Snapshot,

	)
	compare func(s00.PosSIBType, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.PosSIBType,

		error)
	encode func(s00.PosSIBType,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PosSIBTypeValueCodec) New(value s00.PosSIBType,

) (PosSIBTypeAPERValue, error) {
	if c.encode == nil {
		return PosSIBTypeAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PosSIBTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PosSIBTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PosSIBTypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PosSIBTypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PosSIBTypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PosSIBTypeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PosSIBTypeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PosSIBTypeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PosSIBTypeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PosSIBTypeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PosSIBTypeValueCodec) EncodeAPER(value PosSIBTypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PosSIBTypeValueCodec) encodeBudget(value s00.PosSIBType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PosSIBTypeValueCodec) encodeChanged(value s00.PosSIBType,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// PresenceValueCodec is the concrete ValueCodec[Presence].
type PresenceValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.Presence, aper.DecodeState,

	) (s00.Presence, aper.Snapshot,

	)
	compare func(s00.Presence, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.Presence,

		error)
	encode func(s00.Presence,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PresenceValueCodec) New(value s00.Presence,

) (PresenceAPERValue, error) {
	if c.encode == nil {
		return PresenceAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PresenceAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PresenceAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PresenceAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PresenceValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PresenceAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PresenceAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PresenceAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PresenceAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PresenceAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PresenceAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PresenceValueCodec) EncodeAPER(value PresenceAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PresenceValueCodec) encodeBudget(value s00.Presence,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PresenceValueCodec) encodeChanged(value s00.Presence,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ProcedureCodeValueCodec is the concrete ValueCodec[ProcedureCode].
type ProcedureCodeValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.ProcedureCode, aper.DecodeState,

	) (s00.ProcedureCode, aper.Snapshot,

	)
	compare func(s00.ProcedureCode, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.ProcedureCode,

		error)
	encode func(s00.ProcedureCode,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ProcedureCodeValueCodec) New(value s00.ProcedureCode,

) (ProcedureCodeAPERValue, error) {
	if c.encode == nil {
		return ProcedureCodeAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ProcedureCodeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ProcedureCodeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ProcedureCodeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ProcedureCodeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ProcedureCodeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ProcedureCodeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ProcedureCodeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ProcedureCodeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ProcedureCodeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ProcedureCodeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ProcedureCodeValueCodec) EncodeAPER(value ProcedureCodeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ProcedureCodeValueCodec) encodeBudget(value s00.ProcedureCode,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ProcedureCodeValueCodec) encodeChanged(value s00.ProcedureCode,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ProtocolIEIDValueCodec is the concrete ValueCodec[ProtocolIEID].
type ProtocolIEIDValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.ProtocolIEID, aper.DecodeState,

	) (s00.ProtocolIEID, aper.Snapshot,

	)
	compare func(s00.ProtocolIEID, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.ProtocolIEID,

		error)
	encode func(s00.ProtocolIEID,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ProtocolIEIDValueCodec) New(value s00.ProtocolIEID,

) (ProtocolIEIDAPERValue, error) {
	if c.encode == nil {
		return ProtocolIEIDAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ProtocolIEIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ProtocolIEIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ProtocolIEIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ProtocolIEIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ProtocolIEIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ProtocolIEIDAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ProtocolIEIDAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ProtocolIEIDAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ProtocolIEIDAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ProtocolIEIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ProtocolIEIDValueCodec) EncodeAPER(value ProtocolIEIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ProtocolIEIDValueCodec) encodeBudget(value s00.ProtocolIEID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ProtocolIEIDValueCodec) encodeChanged(value s00.ProtocolIEID,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// RSSIValueCodec is the concrete ValueCodec[RSSI].
type RSSIValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.RSSI, aper.DecodeState,

	) (s00.RSSI, aper.Snapshot,

	)
	compare func(s00.RSSI, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.RSSI,

		error)
	encode func(s00.RSSI,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c RSSIValueCodec) New(value s00.RSSI,

) (RSSIAPERValue, error) {
	if c.encode == nil {
		return RSSIAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RSSIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RSSIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return RSSIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c RSSIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RSSIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return RSSIAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return RSSIAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return RSSIAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return RSSIAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return RSSIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c RSSIValueCodec) EncodeAPER(value RSSIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RSSIValueCodec) encodeBudget(value s00.RSSI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c RSSIValueCodec) encodeChanged(value s00.RSSI,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// RepetitionNumberofSIB1NBValueCodec is the concrete ValueCodec[RepetitionNumberofSIB1NB].
type RepetitionNumberofSIB1NBValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.RepetitionNumberofSIB1NB, aper.DecodeState,

	) (s00.RepetitionNumberofSIB1NB, aper.Snapshot,

	)
	compare func(s00.RepetitionNumberofSIB1NB, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.RepetitionNumberofSIB1NB,

		error)
	encode func(s00.RepetitionNumberofSIB1NB,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c RepetitionNumberofSIB1NBValueCodec) New(value s00.RepetitionNumberofSIB1NB,

) (RepetitionNumberofSIB1NBAPERValue, error) {
	if c.encode == nil {
		return RepetitionNumberofSIB1NBAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RepetitionNumberofSIB1NBAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RepetitionNumberofSIB1NBAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return RepetitionNumberofSIB1NBAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c RepetitionNumberofSIB1NBValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RepetitionNumberofSIB1NBAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return RepetitionNumberofSIB1NBAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return RepetitionNumberofSIB1NBAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return RepetitionNumberofSIB1NBAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return RepetitionNumberofSIB1NBAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return RepetitionNumberofSIB1NBAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c RepetitionNumberofSIB1NBValueCodec) EncodeAPER(value RepetitionNumberofSIB1NBAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RepetitionNumberofSIB1NBValueCodec) encodeBudget(value s00.RepetitionNumberofSIB1NB,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c RepetitionNumberofSIB1NBValueCodec) encodeChanged(value s00.RepetitionNumberofSIB1NB,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// SFNInitialisationTimeValueCodec is the concrete ValueCodec[SFNInitialisationTime].
type SFNInitialisationTimeValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.SFNInitialisationTime, aper.DecodeState,

	) (s00.SFNInitialisationTime, aper.Snapshot,

	)
	compare func(s00.SFNInitialisationTime, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.SFNInitialisationTime,

		error)
	encode func(s00.SFNInitialisationTime,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c SFNInitialisationTimeValueCodec) New(value s00.SFNInitialisationTime,

) (SFNInitialisationTimeAPERValue, error) {
	if c.encode == nil {
		return SFNInitialisationTimeAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SFNInitialisationTimeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SFNInitialisationTimeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SFNInitialisationTimeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c SFNInitialisationTimeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SFNInitialisationTimeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SFNInitialisationTimeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return SFNInitialisationTimeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SFNInitialisationTimeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return SFNInitialisationTimeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return SFNInitialisationTimeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c SFNInitialisationTimeValueCodec) EncodeAPER(value SFNInitialisationTimeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SFNInitialisationTimeValueCodec) encodeBudget(value s00.SFNInitialisationTime,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SFNInitialisationTimeValueCodec) encodeChanged(value s00.SFNInitialisationTime,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// SSBIndexValueCodec is the concrete ValueCodec[SSBIndex].
type SSBIndexValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.SSBIndex, aper.DecodeState,

	) (s00.SSBIndex, aper.Snapshot,

	)
	compare func(s00.SSBIndex, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.SSBIndex,

		error)
	encode func(s00.SSBIndex,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c SSBIndexValueCodec) New(value s00.SSBIndex,

) (SSBIndexAPERValue, error) {
	if c.encode == nil {
		return SSBIndexAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SSBIndexAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SSBIndexAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SSBIndexAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c SSBIndexValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SSBIndexAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SSBIndexAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return SSBIndexAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SSBIndexAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return SSBIndexAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return SSBIndexAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c SSBIndexValueCodec) EncodeAPER(value SSBIndexAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SSBIndexValueCodec) encodeBudget(value s00.SSBIndex,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SSBIndexValueCodec) encodeChanged(value s00.SSBIndex,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// SSIDValueCodec is the concrete ValueCodec[SSID].
type SSIDValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.SSID, aper.DecodeState,

	) (s00.SSID, aper.Snapshot,

	)
	compare func(s00.SSID, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.SSID,

		error)
	encode func(s00.SSID,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c SSIDValueCodec) New(value s00.SSID,

) (SSIDAPERValue, error) {
	if c.encode == nil {
		return SSIDAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SSIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SSIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SSIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c SSIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SSIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SSIDAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return SSIDAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SSIDAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return SSIDAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return SSIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c SSIDValueCodec) EncodeAPER(value SSIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SSIDValueCodec) encodeBudget(value s00.SSID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SSIDValueCodec) encodeChanged(value s00.SSID,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// SSNRRSRPValueCodec is the concrete ValueCodec[SSNRRSRP].
type SSNRRSRPValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.SSNRRSRP, aper.DecodeState,

	) (s00.SSNRRSRP, aper.Snapshot,

	)
	compare func(s00.SSNRRSRP, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.SSNRRSRP,

		error)
	encode func(s00.SSNRRSRP,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c SSNRRSRPValueCodec) New(value s00.SSNRRSRP,

) (SSNRRSRPAPERValue, error) {
	if c.encode == nil {
		return SSNRRSRPAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SSNRRSRPAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SSNRRSRPAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SSNRRSRPAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c SSNRRSRPValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SSNRRSRPAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SSNRRSRPAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return SSNRRSRPAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SSNRRSRPAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return SSNRRSRPAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return SSNRRSRPAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c SSNRRSRPValueCodec) EncodeAPER(value SSNRRSRPAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SSNRRSRPValueCodec) encodeBudget(value s00.SSNRRSRP,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SSNRRSRPValueCodec) encodeChanged(value s00.SSNRRSRP,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// SSNRRSRQValueCodec is the concrete ValueCodec[SSNRRSRQ].
type SSNRRSRQValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.SSNRRSRQ, aper.DecodeState,

	) (s00.SSNRRSRQ, aper.Snapshot,

	)
	compare func(s00.SSNRRSRQ, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.SSNRRSRQ,

		error)
	encode func(s00.SSNRRSRQ,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c SSNRRSRQValueCodec) New(value s00.SSNRRSRQ,

) (SSNRRSRQAPERValue, error) {
	if c.encode == nil {
		return SSNRRSRQAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SSNRRSRQAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SSNRRSRQAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SSNRRSRQAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c SSNRRSRQValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SSNRRSRQAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SSNRRSRQAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return SSNRRSRQAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SSNRRSRQAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return SSNRRSRQAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return SSNRRSRQAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c SSNRRSRQValueCodec) EncodeAPER(value SSNRRSRQAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SSNRRSRQValueCodec) encodeBudget(value s00.SSNRRSRQ,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SSNRRSRQValueCodec) encodeChanged(value s00.SSNRRSRQ,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// TACValueCodec is the concrete ValueCodec[TAC].
type TACValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.TAC, aper.DecodeState,

	) (s00.TAC, aper.Snapshot,

	)
	compare func(s00.TAC, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.TAC,

		error)
	encode func(s00.TAC,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c TACValueCodec) New(value s00.TAC,

) (TACAPERValue, error) {
	if c.encode == nil {
		return TACAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TACAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TACAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return TACAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c TACValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TACAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return TACAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return TACAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return TACAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return TACAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return TACAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c TACValueCodec) EncodeAPER(value TACAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TACValueCodec) encodeBudget(value s00.TAC,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c TACValueCodec) encodeChanged(value s00.TAC,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// TPIDValueCodec is the concrete ValueCodec[TPID].
type TPIDValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.TPID, aper.DecodeState,

	) (s00.TPID, aper.Snapshot,

	)
	compare func(s00.TPID, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.TPID,

		error)
	encode func(s00.TPID,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c TPIDValueCodec) New(value s00.TPID,

) (TPIDAPERValue, error) {
	if c.encode == nil {
		return TPIDAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TPIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TPIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return TPIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c TPIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TPIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return TPIDAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return TPIDAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return TPIDAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return TPIDAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return TPIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c TPIDValueCodec) EncodeAPER(value TPIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TPIDValueCodec) encodeBudget(value s00.TPID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c TPIDValueCodec) encodeChanged(value s00.TPID,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// TPTypeValueCodec is the concrete ValueCodec[TPType].
type TPTypeValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.TPType, aper.DecodeState,

	) (s00.TPType, aper.Snapshot,

	)
	compare func(s00.TPType, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.TPType,

		error)
	encode func(s00.TPType,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c TPTypeValueCodec) New(value s00.TPType,

) (TPTypeAPERValue, error) {
	if c.encode == nil {
		return TPTypeAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TPTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TPTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return TPTypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c TPTypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TPTypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return TPTypeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return TPTypeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return TPTypeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return TPTypeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return TPTypeAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c TPTypeValueCodec) EncodeAPER(value TPTypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TPTypeValueCodec) encodeBudget(value s00.TPType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c TPTypeValueCodec) encodeChanged(value s00.TPType,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// TriggeringMessageValueCodec is the concrete ValueCodec[TriggeringMessage].
type TriggeringMessageValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.TriggeringMessage, aper.DecodeState,

	) (s00.TriggeringMessage, aper.Snapshot,

	)
	compare func(s00.TriggeringMessage, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.TriggeringMessage,

		error)
	encode func(s00.TriggeringMessage,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c TriggeringMessageValueCodec) New(value s00.TriggeringMessage,

) (TriggeringMessageAPERValue, error) {
	if c.encode == nil {
		return TriggeringMessageAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TriggeringMessageAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TriggeringMessageAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return TriggeringMessageAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c TriggeringMessageValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TriggeringMessageAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return TriggeringMessageAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return TriggeringMessageAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return TriggeringMessageAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return TriggeringMessageAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return TriggeringMessageAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c TriggeringMessageValueCodec) EncodeAPER(value TriggeringMessageAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TriggeringMessageValueCodec) encodeBudget(value s00.TriggeringMessage,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c TriggeringMessageValueCodec) encodeChanged(value s00.TriggeringMessage,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// TypeOfErrorValueCodec is the concrete ValueCodec[TypeOfError].
type TypeOfErrorValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.TypeOfError, aper.DecodeState,

	) (s00.TypeOfError, aper.Snapshot,

	)
	compare func(s00.TypeOfError, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.TypeOfError,

		error)
	encode func(s00.TypeOfError,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c TypeOfErrorValueCodec) New(value s00.TypeOfError,

) (TypeOfErrorAPERValue, error) {
	if c.encode == nil {
		return TypeOfErrorAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TypeOfErrorAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TypeOfErrorAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return TypeOfErrorAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c TypeOfErrorValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TypeOfErrorAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return TypeOfErrorAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return TypeOfErrorAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return TypeOfErrorAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return TypeOfErrorAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return TypeOfErrorAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c TypeOfErrorValueCodec) EncodeAPER(value TypeOfErrorAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c TypeOfErrorValueCodec) encodeBudget(value s00.TypeOfError,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c TypeOfErrorValueCodec) encodeChanged(value s00.TypeOfError,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// UARFCNValueCodec is the concrete ValueCodec[UARFCN].
type UARFCNValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.UARFCN, aper.DecodeState,

	) (s00.UARFCN, aper.Snapshot,

	)
	compare func(s00.UARFCN, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.UARFCN,

		error)
	encode func(s00.UARFCN,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c UARFCNValueCodec) New(value s00.UARFCN,

) (UARFCNAPERValue, error) {
	if c.encode == nil {
		return UARFCNAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UARFCNAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UARFCNAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return UARFCNAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c UARFCNValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UARFCNAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return UARFCNAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return UARFCNAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return UARFCNAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return UARFCNAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return UARFCNAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c UARFCNValueCodec) EncodeAPER(value UARFCNAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UARFCNValueCodec) encodeBudget(value s00.UARFCN,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c UARFCNValueCodec) encodeChanged(value s00.UARFCN,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// UTRAEcN0ValueCodec is the concrete ValueCodec[UTRAEcN0].
type UTRAEcN0ValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.UTRAEcN0, aper.DecodeState,

	) (s00.UTRAEcN0, aper.Snapshot,

	)
	compare func(s00.UTRAEcN0, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.UTRAEcN0,

		error)
	encode func(s00.UTRAEcN0,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c UTRAEcN0ValueCodec) New(value s00.UTRAEcN0,

) (UTRAEcN0APERValue, error) {
	if c.encode == nil {
		return UTRAEcN0APERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UTRAEcN0APERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UTRAEcN0APERValue{}, aper.OperationError(err, "Value.New")
	}
	return UTRAEcN0APERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c UTRAEcN0ValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UTRAEcN0APERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return UTRAEcN0APERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return UTRAEcN0APERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return UTRAEcN0APERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return UTRAEcN0APERValue{}, report, aper.OperationError(err, c.path)
	}
	return UTRAEcN0APERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c UTRAEcN0ValueCodec) EncodeAPER(value UTRAEcN0APERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UTRAEcN0ValueCodec) encodeBudget(value s00.UTRAEcN0,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c UTRAEcN0ValueCodec) encodeChanged(value s00.UTRAEcN0,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// UTRARSCPValueCodec is the concrete ValueCodec[UTRARSCP].
type UTRARSCPValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.UTRARSCP, aper.DecodeState,

	) (s00.UTRARSCP, aper.Snapshot,

	)
	compare func(s00.UTRARSCP, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.UTRARSCP,

		error)
	encode func(s00.UTRARSCP,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c UTRARSCPValueCodec) New(value s00.UTRARSCP,

) (UTRARSCPAPERValue, error) {
	if c.encode == nil {
		return UTRARSCPAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UTRARSCPAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return UTRARSCPAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return UTRARSCPAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c UTRARSCPValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (UTRARSCPAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return UTRARSCPAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return UTRARSCPAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return UTRARSCPAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return UTRARSCPAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return UTRARSCPAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c UTRARSCPValueCodec) EncodeAPER(value UTRARSCPAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c UTRARSCPValueCodec) encodeBudget(value s00.UTRARSCP,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c UTRARSCPValueCodec) encodeChanged(value s00.UTRARSCP,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ValueRSRPValueCodec is the concrete ValueCodec[ValueRSRP].
type ValueRSRPValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.ValueRSRP, aper.DecodeState,

	) (s00.ValueRSRP, aper.Snapshot,

	)
	compare func(s00.ValueRSRP, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.ValueRSRP,

		error)
	encode func(s00.ValueRSRP,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ValueRSRPValueCodec) New(value s00.ValueRSRP,

) (ValueRSRPAPERValue, error) {
	if c.encode == nil {
		return ValueRSRPAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ValueRSRPAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ValueRSRPAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ValueRSRPAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ValueRSRPValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ValueRSRPAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ValueRSRPAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ValueRSRPAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ValueRSRPAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ValueRSRPAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ValueRSRPAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ValueRSRPValueCodec) EncodeAPER(value ValueRSRPAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ValueRSRPValueCodec) encodeBudget(value s00.ValueRSRP,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ValueRSRPValueCodec) encodeChanged(value s00.ValueRSRP,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ValueRSRQValueCodec is the concrete ValueCodec[ValueRSRQ].
type ValueRSRQValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.ValueRSRQ, aper.DecodeState,

	) (s00.ValueRSRQ, aper.Snapshot,

	)
	compare func(s00.ValueRSRQ, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.ValueRSRQ,

		error)
	encode func(s00.ValueRSRQ,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ValueRSRQValueCodec) New(value s00.ValueRSRQ,

) (ValueRSRQAPERValue, error) {
	if c.encode == nil {
		return ValueRSRQAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ValueRSRQAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ValueRSRQAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ValueRSRQAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ValueRSRQValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ValueRSRQAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ValueRSRQAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ValueRSRQAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ValueRSRQAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ValueRSRQAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ValueRSRQAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ValueRSRQValueCodec) EncodeAPER(value ValueRSRQAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ValueRSRQValueCodec) encodeBudget(value s00.ValueRSRQ,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ValueRSRQValueCodec) encodeChanged(value s00.ValueRSRQ,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// WLANBandValueCodec is the concrete ValueCodec[WLANBand].
type WLANBandValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.WLANBand, aper.DecodeState,

	) (s00.WLANBand, aper.Snapshot,

	)
	compare func(s00.WLANBand, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.WLANBand,

		error)
	encode func(s00.WLANBand,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c WLANBandValueCodec) New(value s00.WLANBand,

) (WLANBandAPERValue, error) {
	if c.encode == nil {
		return WLANBandAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WLANBandAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANBandAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return WLANBandAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c WLANBandValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WLANBandAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANBandAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return WLANBandAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANBandAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return WLANBandAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return WLANBandAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c WLANBandValueCodec) EncodeAPER(value WLANBandAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c WLANBandValueCodec) encodeBudget(value s00.WLANBand,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANBandValueCodec) encodeChanged(value s00.WLANBand,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// WLANChannelValueCodec is the concrete ValueCodec[WLANChannel].
type WLANChannelValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.WLANChannel, aper.DecodeState,

	) (s00.WLANChannel, aper.Snapshot,

	)
	compare func(s00.WLANChannel, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.WLANChannel,

		error)
	encode func(s00.WLANChannel,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c WLANChannelValueCodec) New(value s00.WLANChannel,

) (WLANChannelAPERValue, error) {
	if c.encode == nil {
		return WLANChannelAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WLANChannelAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANChannelAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return WLANChannelAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c WLANChannelValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WLANChannelAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANChannelAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return WLANChannelAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANChannelAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return WLANChannelAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return WLANChannelAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c WLANChannelValueCodec) EncodeAPER(value WLANChannelAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c WLANChannelValueCodec) encodeBudget(value s00.WLANChannel,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANChannelValueCodec) encodeChanged(value s00.WLANChannel,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// WLANChannelListValueCodec is the concrete ValueCodec[WLANChannelList].
type WLANChannelListValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.WLANChannelList, aper.DecodeState,

	) (s00.WLANChannelList, aper.Snapshot,

	)
	compare func(s00.WLANChannelList, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.WLANChannelList,

		error)
	encode func(s00.WLANChannelList,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c WLANChannelListValueCodec) New(value s00.WLANChannelList,

) (WLANChannelListAPERValue, error) {
	if c.encode == nil {
		return WLANChannelListAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WLANChannelListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANChannelListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return WLANChannelListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c WLANChannelListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WLANChannelListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANChannelListAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return WLANChannelListAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANChannelListAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return WLANChannelListAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return WLANChannelListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c WLANChannelListValueCodec) EncodeAPER(value WLANChannelListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c WLANChannelListValueCodec) encodeBudget(value s00.WLANChannelList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANChannelListValueCodec) encodeChanged(value s00.WLANChannelList,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ReportCharacteristicsAPERValue is the concrete APERValue[ReportCharacteristics].
type ReportCharacteristicsAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ReportCharacteristics

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ReportCharacteristicsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ReportCharacteristicsAPERValue) WithoutReplay() ReportCharacteristicsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// NumberOfFrequencyHoppingBandsAPERValue is the concrete APERValue[NumberOfFrequencyHoppingBands].
type NumberOfFrequencyHoppingBandsAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.NumberOfFrequencyHoppingBands

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v NumberOfFrequencyHoppingBandsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v NumberOfFrequencyHoppingBandsAPERValue) WithoutReplay() NumberOfFrequencyHoppingBandsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OTDOAInformationItemAPERValue is the concrete APERValue[OTDOAInformationItem].
type OTDOAInformationItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.OTDOAInformationItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v OTDOAInformationItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOAInformationItemAPERValue) WithoutReplay() OTDOAInformationItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OffsetNBChanneltoEARFCNAPERValue is the concrete APERValue[OffsetNBChanneltoEARFCN].
type OffsetNBChanneltoEARFCNAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.OffsetNBChanneltoEARFCN

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v OffsetNBChanneltoEARFCNAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OffsetNBChanneltoEARFCNAPERValue) WithoutReplay() OffsetNBChanneltoEARFCNAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OperationModeInfoAPERValue is the concrete APERValue[OperationModeInfo].
type OperationModeInfoAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.OperationModeInfo

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v OperationModeInfoAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OperationModeInfoAPERValue) WithoutReplay() OperationModeInfoAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// OutcomeAPERValue is the concrete APERValue[Outcome].
type OutcomeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.Outcome

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v OutcomeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OutcomeAPERValue) WithoutReplay() OutcomeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PCIAPERValue is the concrete APERValue[PCI].
type PCIAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PCI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PCIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PCIAPERValue) WithoutReplay() PCIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PLMNIdentityAPERValue is the concrete APERValue[PLMNIdentity].
type PLMNIdentityAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PLMNIdentity

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PLMNIdentityAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PLMNIdentityAPERValue) WithoutReplay() PLMNIdentityAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PRSBandwidthAPERValue is the concrete APERValue[PRSBandwidth].
type PRSBandwidthAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PRSBandwidth

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PRSBandwidthAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PRSBandwidthAPERValue) WithoutReplay() PRSBandwidthAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PRSConfigurationIndexAPERValue is the concrete APERValue[PRSConfigurationIndex].
type PRSConfigurationIndexAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PRSConfigurationIndex

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PRSConfigurationIndexAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PRSConfigurationIndexAPERValue) WithoutReplay() PRSConfigurationIndexAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PRSFrequencyHoppingConfigurationBandPositionsAPERValue is the concrete APERValue[PRSFrequencyHoppingConfigurationBandPositions].
type PRSFrequencyHoppingConfigurationBandPositionsAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PRSFrequencyHoppingConfigurationBandPositions

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PRSFrequencyHoppingConfigurationBandPositionsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PRSFrequencyHoppingConfigurationBandPositionsAPERValue) WithoutReplay() PRSFrequencyHoppingConfigurationBandPositionsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PRSIDAPERValue is the concrete APERValue[PRSID].
type PRSIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PRSID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PRSIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PRSIDAPERValue) WithoutReplay() PRSIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PRSOccasionGroupAPERValue is the concrete APERValue[PRSOccasionGroup].
type PRSOccasionGroupAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PRSOccasionGroup

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PRSOccasionGroupAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PRSOccasionGroupAPERValue) WithoutReplay() PRSOccasionGroupAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PhysCellIDGERANAPERValue is the concrete APERValue[PhysCellIDGERAN].
type PhysCellIDGERANAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PhysCellIDGERAN

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PhysCellIDGERANAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PhysCellIDGERANAPERValue) WithoutReplay() PhysCellIDGERANAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PhysCellIDUTRAFDDAPERValue is the concrete APERValue[PhysCellIDUTRAFDD].
type PhysCellIDUTRAFDDAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PhysCellIDUTRAFDD

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PhysCellIDUTRAFDDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PhysCellIDUTRAFDDAPERValue) WithoutReplay() PhysCellIDUTRAFDDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PhysCellIDUTRATDDAPERValue is the concrete APERValue[PhysCellIDUTRATDD].
type PhysCellIDUTRATDDAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PhysCellIDUTRATDD

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PhysCellIDUTRATDDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PhysCellIDUTRATDDAPERValue) WithoutReplay() PhysCellIDUTRATDDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PosSIBTypeAPERValue is the concrete APERValue[PosSIBType].
type PosSIBTypeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.PosSIBType

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PosSIBTypeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PosSIBTypeAPERValue) WithoutReplay() PosSIBTypeAPERValue {
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

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PresenceAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PresenceAPERValue) WithoutReplay() PresenceAPERValue {
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

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ProcedureCodeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ProcedureCodeAPERValue) WithoutReplay() ProcedureCodeAPERValue {
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

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ProtocolIEIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ProtocolIEIDAPERValue) WithoutReplay() ProtocolIEIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RSSIAPERValue is the concrete APERValue[RSSI].
type RSSIAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.RSSI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v RSSIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v RSSIAPERValue) WithoutReplay() RSSIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// RepetitionNumberofSIB1NBAPERValue is the concrete APERValue[RepetitionNumberofSIB1NB].
type RepetitionNumberofSIB1NBAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.RepetitionNumberofSIB1NB

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v RepetitionNumberofSIB1NBAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v RepetitionNumberofSIB1NBAPERValue) WithoutReplay() RepetitionNumberofSIB1NBAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SFNInitialisationTimeAPERValue is the concrete APERValue[SFNInitialisationTime].
type SFNInitialisationTimeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SFNInitialisationTime

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v SFNInitialisationTimeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v SFNInitialisationTimeAPERValue) WithoutReplay() SFNInitialisationTimeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SSBIndexAPERValue is the concrete APERValue[SSBIndex].
type SSBIndexAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SSBIndex

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v SSBIndexAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v SSBIndexAPERValue) WithoutReplay() SSBIndexAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SSIDAPERValue is the concrete APERValue[SSID].
type SSIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SSID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v SSIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v SSIDAPERValue) WithoutReplay() SSIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SSNRRSRPAPERValue is the concrete APERValue[SSNRRSRP].
type SSNRRSRPAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SSNRRSRP

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v SSNRRSRPAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v SSNRRSRPAPERValue) WithoutReplay() SSNRRSRPAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SSNRRSRQAPERValue is the concrete APERValue[SSNRRSRQ].
type SSNRRSRQAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.SSNRRSRQ

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v SSNRRSRQAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v SSNRRSRQAPERValue) WithoutReplay() SSNRRSRQAPERValue {
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

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v TACAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v TACAPERValue) WithoutReplay() TACAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TPIDAPERValue is the concrete APERValue[TPID].
type TPIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TPID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v TPIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v TPIDAPERValue) WithoutReplay() TPIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TPTypeAPERValue is the concrete APERValue[TPType].
type TPTypeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.TPType

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v TPTypeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v TPTypeAPERValue) WithoutReplay() TPTypeAPERValue {
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

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v TriggeringMessageAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
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

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v TypeOfErrorAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v TypeOfErrorAPERValue) WithoutReplay() TypeOfErrorAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UARFCNAPERValue is the concrete APERValue[UARFCN].
type UARFCNAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.UARFCN

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v UARFCNAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v UARFCNAPERValue) WithoutReplay() UARFCNAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UTRAEcN0APERValue is the concrete APERValue[UTRAEcN0].
type UTRAEcN0APERValue struct {
	context s00.BridgeCodecContext
	Value   s00.UTRAEcN0

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v UTRAEcN0APERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v UTRAEcN0APERValue) WithoutReplay() UTRAEcN0APERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// UTRARSCPAPERValue is the concrete APERValue[UTRARSCP].
type UTRARSCPAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.UTRARSCP

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v UTRARSCPAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v UTRARSCPAPERValue) WithoutReplay() UTRARSCPAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ValueRSRPAPERValue is the concrete APERValue[ValueRSRP].
type ValueRSRPAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ValueRSRP

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ValueRSRPAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ValueRSRPAPERValue) WithoutReplay() ValueRSRPAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ValueRSRQAPERValue is the concrete APERValue[ValueRSRQ].
type ValueRSRQAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.ValueRSRQ

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ValueRSRQAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ValueRSRQAPERValue) WithoutReplay() ValueRSRQAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WLANBandAPERValue is the concrete APERValue[WLANBand].
type WLANBandAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.WLANBand

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v WLANBandAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v WLANBandAPERValue) WithoutReplay() WLANBandAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WLANChannelAPERValue is the concrete APERValue[WLANChannel].
type WLANChannelAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.WLANChannel

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v WLANChannelAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v WLANChannelAPERValue) WithoutReplay() WLANChannelAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WLANChannelListAPERValue is the concrete APERValue[WLANChannelList].
type WLANChannelListAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.WLANChannelList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v WLANChannelListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v WLANChannelListAPERValue) WithoutReplay() WLANChannelListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WLANCountryCodeAPERValue is the concrete APERValue[WLANCountryCode].
type WLANCountryCodeAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.WLANCountryCode

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v WLANCountryCodeAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v WLANCountryCodeAPERValue) WithoutReplay() WLANCountryCodeAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeNumberOfFrequencyHoppingBandsAPERValueFieldContext(v *NumberOfFrequencyHoppingBandsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNumberOfFrequencyHoppingBandsAPERValueFieldReceived(v *NumberOfFrequencyHoppingBandsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeNumberOfFrequencyHoppingBandsAPERValueFieldReplay(v *NumberOfFrequencyHoppingBandsAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeNumberOfFrequencyHoppingBandsAPERValueFieldWithoutReplay(v *NumberOfFrequencyHoppingBandsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeNumberOfFrequencyHoppingBandsValueCodecFieldCapture(v *NumberOfFrequencyHoppingBandsValueCodec) *func(s00.NumberOfFrequencyHoppingBands, aper.DecodeState) (s00.NumberOfFrequencyHoppingBands, aper.Snapshot) {
	return &v.capture
}
func BridgeNumberOfFrequencyHoppingBandsValueCodecFieldCompare(v *NumberOfFrequencyHoppingBandsValueCodec) *func(s00.NumberOfFrequencyHoppingBands, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeNumberOfFrequencyHoppingBandsValueCodecFieldContext(v *NumberOfFrequencyHoppingBandsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeNumberOfFrequencyHoppingBandsValueCodecFieldDecode(v *NumberOfFrequencyHoppingBandsValueCodec) *func([]byte, aper.DecodeState) (s00.NumberOfFrequencyHoppingBands, error) {
	return &v.decode
}
func BridgeNumberOfFrequencyHoppingBandsValueCodecFieldEncode(v *NumberOfFrequencyHoppingBandsValueCodec) *func(s00.NumberOfFrequencyHoppingBands, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeNumberOfFrequencyHoppingBandsValueCodecFieldPath(v *NumberOfFrequencyHoppingBandsValueCodec) *aper.Path {
	return &v.path
}
func BridgeNumberOfFrequencyHoppingBandsValueCodecMethodEncodeBudget(v NumberOfFrequencyHoppingBandsValueCodec, a0 s00.NumberOfFrequencyHoppingBands, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeNumberOfFrequencyHoppingBandsValueCodecMethodEncodeChanged(v NumberOfFrequencyHoppingBandsValueCodec, a0 s00.NumberOfFrequencyHoppingBands, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOTDOAInformationItemAPERValueFieldContext(v *OTDOAInformationItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationItemAPERValueFieldReceived(v *OTDOAInformationItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationItemAPERValueFieldReplay(v *OTDOAInformationItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationItemAPERValueFieldWithoutReplay(v *OTDOAInformationItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationItemValueCodecFieldCapture(v *OTDOAInformationItemValueCodec) *func(s00.OTDOAInformationItem, aper.DecodeState) (s00.OTDOAInformationItem, aper.Snapshot) {
	return &v.capture
}
func BridgeOTDOAInformationItemValueCodecFieldCompare(v *OTDOAInformationItemValueCodec) *func(s00.OTDOAInformationItem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeOTDOAInformationItemValueCodecFieldContext(v *OTDOAInformationItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationItemValueCodecFieldDecode(v *OTDOAInformationItemValueCodec) *func([]byte, aper.DecodeState) (s00.OTDOAInformationItem, error) {
	return &v.decode
}
func BridgeOTDOAInformationItemValueCodecFieldEncode(v *OTDOAInformationItemValueCodec) *func(s00.OTDOAInformationItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOAInformationItemValueCodecFieldPath(v *OTDOAInformationItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeOTDOAInformationItemValueCodecMethodEncodeBudget(v OTDOAInformationItemValueCodec, a0 s00.OTDOAInformationItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOAInformationItemValueCodecMethodEncodeChanged(v OTDOAInformationItemValueCodec, a0 s00.OTDOAInformationItem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOffsetNBChanneltoEARFCNAPERValueFieldContext(v *OffsetNBChanneltoEARFCNAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOffsetNBChanneltoEARFCNAPERValueFieldReceived(v *OffsetNBChanneltoEARFCNAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOffsetNBChanneltoEARFCNAPERValueFieldReplay(v *OffsetNBChanneltoEARFCNAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOffsetNBChanneltoEARFCNAPERValueFieldWithoutReplay(v *OffsetNBChanneltoEARFCNAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOffsetNBChanneltoEARFCNValueCodecFieldCapture(v *OffsetNBChanneltoEARFCNValueCodec) *func(s00.OffsetNBChanneltoEARFCN, aper.DecodeState) (s00.OffsetNBChanneltoEARFCN, aper.Snapshot) {
	return &v.capture
}
func BridgeOffsetNBChanneltoEARFCNValueCodecFieldCompare(v *OffsetNBChanneltoEARFCNValueCodec) *func(s00.OffsetNBChanneltoEARFCN, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeOffsetNBChanneltoEARFCNValueCodecFieldContext(v *OffsetNBChanneltoEARFCNValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOffsetNBChanneltoEARFCNValueCodecFieldDecode(v *OffsetNBChanneltoEARFCNValueCodec) *func([]byte, aper.DecodeState) (s00.OffsetNBChanneltoEARFCN, error) {
	return &v.decode
}
func BridgeOffsetNBChanneltoEARFCNValueCodecFieldEncode(v *OffsetNBChanneltoEARFCNValueCodec) *func(s00.OffsetNBChanneltoEARFCN, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOffsetNBChanneltoEARFCNValueCodecFieldPath(v *OffsetNBChanneltoEARFCNValueCodec) *aper.Path {
	return &v.path
}
func BridgeOffsetNBChanneltoEARFCNValueCodecMethodEncodeBudget(v OffsetNBChanneltoEARFCNValueCodec, a0 s00.OffsetNBChanneltoEARFCN, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOffsetNBChanneltoEARFCNValueCodecMethodEncodeChanged(v OffsetNBChanneltoEARFCNValueCodec, a0 s00.OffsetNBChanneltoEARFCN, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOperationModeInfoAPERValueFieldContext(v *OperationModeInfoAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOperationModeInfoAPERValueFieldReceived(v *OperationModeInfoAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeOperationModeInfoAPERValueFieldReplay(v *OperationModeInfoAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOperationModeInfoAPERValueFieldWithoutReplay(v *OperationModeInfoAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeOperationModeInfoValueCodecFieldCapture(v *OperationModeInfoValueCodec) *func(s00.OperationModeInfo, aper.DecodeState) (s00.OperationModeInfo, aper.Snapshot) {
	return &v.capture
}
func BridgeOperationModeInfoValueCodecFieldCompare(v *OperationModeInfoValueCodec) *func(s00.OperationModeInfo, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeOperationModeInfoValueCodecFieldContext(v *OperationModeInfoValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOperationModeInfoValueCodecFieldDecode(v *OperationModeInfoValueCodec) *func([]byte, aper.DecodeState) (s00.OperationModeInfo, error) {
	return &v.decode
}
func BridgeOperationModeInfoValueCodecFieldEncode(v *OperationModeInfoValueCodec) *func(s00.OperationModeInfo, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOperationModeInfoValueCodecFieldPath(v *OperationModeInfoValueCodec) *aper.Path {
	return &v.path
}
func BridgeOperationModeInfoValueCodecMethodEncodeBudget(v OperationModeInfoValueCodec, a0 s00.OperationModeInfo, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOperationModeInfoValueCodecMethodEncodeChanged(v OperationModeInfoValueCodec, a0 s00.OperationModeInfo, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeOutcomeAPERValueFieldContext(v *OutcomeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOutcomeAPERValueFieldReceived(v *OutcomeAPERValue) *aper.WireSpan { return &v.received }
func BridgeOutcomeAPERValueFieldReplay(v *OutcomeAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeOutcomeAPERValueFieldWithoutReplay(v *OutcomeAPERValue) *bool     { return &v.withoutReplay }
func BridgeOutcomeValueCodecFieldCapture(v *OutcomeValueCodec) *func(s00.Outcome, aper.DecodeState) (s00.Outcome, aper.Snapshot) {
	return &v.capture
}
func BridgeOutcomeValueCodecFieldCompare(v *OutcomeValueCodec) *func(s00.Outcome, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeOutcomeValueCodecFieldContext(v *OutcomeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOutcomeValueCodecFieldDecode(v *OutcomeValueCodec) *func([]byte, aper.DecodeState) (s00.Outcome, error) {
	return &v.decode
}
func BridgeOutcomeValueCodecFieldEncode(v *OutcomeValueCodec) *func(s00.Outcome, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOutcomeValueCodecFieldPath(v *OutcomeValueCodec) *aper.Path { return &v.path }
func BridgeOutcomeValueCodecMethodEncodeBudget(v OutcomeValueCodec, a0 s00.Outcome, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOutcomeValueCodecMethodEncodeChanged(v OutcomeValueCodec, a0 s00.Outcome, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePCIAPERValueFieldContext(v *PCIAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgePCIAPERValueFieldReceived(v *PCIAPERValue) *aper.WireSpan         { return &v.received }
func BridgePCIAPERValueFieldReplay(v *PCIAPERValue) *aper.Snapshot           { return &v.replay }
func BridgePCIAPERValueFieldWithoutReplay(v *PCIAPERValue) *bool             { return &v.withoutReplay }
func BridgePCIValueCodecFieldCapture(v *PCIValueCodec) *func(s00.PCI, aper.DecodeState) (s00.PCI, aper.Snapshot) {
	return &v.capture
}
func BridgePCIValueCodecFieldCompare(v *PCIValueCodec) *func(s00.PCI, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePCIValueCodecFieldContext(v *PCIValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgePCIValueCodecFieldDecode(v *PCIValueCodec) *func([]byte, aper.DecodeState) (s00.PCI, error) {
	return &v.decode
}
func BridgePCIValueCodecFieldEncode(v *PCIValueCodec) *func(s00.PCI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePCIValueCodecFieldPath(v *PCIValueCodec) *aper.Path { return &v.path }
func BridgePCIValueCodecMethodEncodeBudget(v PCIValueCodec, a0 s00.PCI, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePCIValueCodecMethodEncodeChanged(v PCIValueCodec, a0 s00.PCI, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePLMNIdentityAPERValueFieldContext(v *PLMNIdentityAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePLMNIdentityAPERValueFieldReceived(v *PLMNIdentityAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePLMNIdentityAPERValueFieldReplay(v *PLMNIdentityAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePLMNIdentityAPERValueFieldWithoutReplay(v *PLMNIdentityAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePLMNIdentityValueCodecFieldCapture(v *PLMNIdentityValueCodec) *func(s00.PLMNIdentity, aper.DecodeState) (s00.PLMNIdentity, aper.Snapshot) {
	return &v.capture
}
func BridgePLMNIdentityValueCodecFieldCompare(v *PLMNIdentityValueCodec) *func(s00.PLMNIdentity, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePLMNIdentityValueCodecFieldContext(v *PLMNIdentityValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePLMNIdentityValueCodecFieldDecode(v *PLMNIdentityValueCodec) *func([]byte, aper.DecodeState) (s00.PLMNIdentity, error) {
	return &v.decode
}
func BridgePLMNIdentityValueCodecFieldEncode(v *PLMNIdentityValueCodec) *func(s00.PLMNIdentity, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePLMNIdentityValueCodecFieldPath(v *PLMNIdentityValueCodec) *aper.Path { return &v.path }
func BridgePLMNIdentityValueCodecMethodEncodeBudget(v PLMNIdentityValueCodec, a0 s00.PLMNIdentity, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePLMNIdentityValueCodecMethodEncodeChanged(v PLMNIdentityValueCodec, a0 s00.PLMNIdentity, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePRSBandwidthAPERValueFieldContext(v *PRSBandwidthAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePRSBandwidthAPERValueFieldReceived(v *PRSBandwidthAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePRSBandwidthAPERValueFieldReplay(v *PRSBandwidthAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePRSBandwidthAPERValueFieldWithoutReplay(v *PRSBandwidthAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePRSBandwidthValueCodecFieldCapture(v *PRSBandwidthValueCodec) *func(s00.PRSBandwidth, aper.DecodeState) (s00.PRSBandwidth, aper.Snapshot) {
	return &v.capture
}
func BridgePRSBandwidthValueCodecFieldCompare(v *PRSBandwidthValueCodec) *func(s00.PRSBandwidth, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePRSBandwidthValueCodecFieldContext(v *PRSBandwidthValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePRSBandwidthValueCodecFieldDecode(v *PRSBandwidthValueCodec) *func([]byte, aper.DecodeState) (s00.PRSBandwidth, error) {
	return &v.decode
}
func BridgePRSBandwidthValueCodecFieldEncode(v *PRSBandwidthValueCodec) *func(s00.PRSBandwidth, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePRSBandwidthValueCodecFieldPath(v *PRSBandwidthValueCodec) *aper.Path { return &v.path }
func BridgePRSBandwidthValueCodecMethodEncodeBudget(v PRSBandwidthValueCodec, a0 s00.PRSBandwidth, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePRSBandwidthValueCodecMethodEncodeChanged(v PRSBandwidthValueCodec, a0 s00.PRSBandwidth, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePRSConfigurationIndexAPERValueFieldContext(v *PRSConfigurationIndexAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePRSConfigurationIndexAPERValueFieldReceived(v *PRSConfigurationIndexAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePRSConfigurationIndexAPERValueFieldReplay(v *PRSConfigurationIndexAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePRSConfigurationIndexAPERValueFieldWithoutReplay(v *PRSConfigurationIndexAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePRSConfigurationIndexValueCodecFieldCapture(v *PRSConfigurationIndexValueCodec) *func(s00.PRSConfigurationIndex, aper.DecodeState) (s00.PRSConfigurationIndex, aper.Snapshot) {
	return &v.capture
}
func BridgePRSConfigurationIndexValueCodecFieldCompare(v *PRSConfigurationIndexValueCodec) *func(s00.PRSConfigurationIndex, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePRSConfigurationIndexValueCodecFieldContext(v *PRSConfigurationIndexValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePRSConfigurationIndexValueCodecFieldDecode(v *PRSConfigurationIndexValueCodec) *func([]byte, aper.DecodeState) (s00.PRSConfigurationIndex, error) {
	return &v.decode
}
func BridgePRSConfigurationIndexValueCodecFieldEncode(v *PRSConfigurationIndexValueCodec) *func(s00.PRSConfigurationIndex, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePRSConfigurationIndexValueCodecFieldPath(v *PRSConfigurationIndexValueCodec) *aper.Path {
	return &v.path
}
func BridgePRSConfigurationIndexValueCodecMethodEncodeBudget(v PRSConfigurationIndexValueCodec, a0 s00.PRSConfigurationIndex, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePRSConfigurationIndexValueCodecMethodEncodeChanged(v PRSConfigurationIndexValueCodec, a0 s00.PRSConfigurationIndex, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsAPERValueFieldContext(v *PRSFrequencyHoppingConfigurationBandPositionsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsAPERValueFieldReceived(v *PRSFrequencyHoppingConfigurationBandPositionsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsAPERValueFieldReplay(v *PRSFrequencyHoppingConfigurationBandPositionsAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsAPERValueFieldWithoutReplay(v *PRSFrequencyHoppingConfigurationBandPositionsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldCapture(v *PRSFrequencyHoppingConfigurationBandPositionsValueCodec) *func(s00.PRSFrequencyHoppingConfigurationBandPositions, aper.DecodeState) (s00.PRSFrequencyHoppingConfigurationBandPositions, aper.Snapshot) {
	return &v.capture
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldCompare(v *PRSFrequencyHoppingConfigurationBandPositionsValueCodec) *func(s00.PRSFrequencyHoppingConfigurationBandPositions, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldContext(v *PRSFrequencyHoppingConfigurationBandPositionsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldDecode(v *PRSFrequencyHoppingConfigurationBandPositionsValueCodec) *func([]byte, aper.DecodeState) (s00.PRSFrequencyHoppingConfigurationBandPositions, error) {
	return &v.decode
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldEncode(v *PRSFrequencyHoppingConfigurationBandPositionsValueCodec) *func(s00.PRSFrequencyHoppingConfigurationBandPositions, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldPath(v *PRSFrequencyHoppingConfigurationBandPositionsValueCodec) *aper.Path {
	return &v.path
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecMethodEncodeBudget(v PRSFrequencyHoppingConfigurationBandPositionsValueCodec, a0 s00.PRSFrequencyHoppingConfigurationBandPositions, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecMethodEncodeChanged(v PRSFrequencyHoppingConfigurationBandPositionsValueCodec, a0 s00.PRSFrequencyHoppingConfigurationBandPositions, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePRSIDAPERValueFieldContext(v *PRSIDAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgePRSIDAPERValueFieldReceived(v *PRSIDAPERValue) *aper.WireSpan         { return &v.received }
func BridgePRSIDAPERValueFieldReplay(v *PRSIDAPERValue) *aper.Snapshot           { return &v.replay }
func BridgePRSIDAPERValueFieldWithoutReplay(v *PRSIDAPERValue) *bool             { return &v.withoutReplay }
func BridgePRSIDValueCodecFieldCapture(v *PRSIDValueCodec) *func(s00.PRSID, aper.DecodeState) (s00.PRSID, aper.Snapshot) {
	return &v.capture
}
func BridgePRSIDValueCodecFieldCompare(v *PRSIDValueCodec) *func(s00.PRSID, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePRSIDValueCodecFieldContext(v *PRSIDValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgePRSIDValueCodecFieldDecode(v *PRSIDValueCodec) *func([]byte, aper.DecodeState) (s00.PRSID, error) {
	return &v.decode
}
func BridgePRSIDValueCodecFieldEncode(v *PRSIDValueCodec) *func(s00.PRSID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePRSIDValueCodecFieldPath(v *PRSIDValueCodec) *aper.Path { return &v.path }
func BridgePRSIDValueCodecMethodEncodeBudget(v PRSIDValueCodec, a0 s00.PRSID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePRSIDValueCodecMethodEncodeChanged(v PRSIDValueCodec, a0 s00.PRSID, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePRSOccasionGroupAPERValueFieldContext(v *PRSOccasionGroupAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePRSOccasionGroupAPERValueFieldReceived(v *PRSOccasionGroupAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePRSOccasionGroupAPERValueFieldReplay(v *PRSOccasionGroupAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePRSOccasionGroupAPERValueFieldWithoutReplay(v *PRSOccasionGroupAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePRSOccasionGroupValueCodecFieldCapture(v *PRSOccasionGroupValueCodec) *func(s00.PRSOccasionGroup, aper.DecodeState) (s00.PRSOccasionGroup, aper.Snapshot) {
	return &v.capture
}
func BridgePRSOccasionGroupValueCodecFieldCompare(v *PRSOccasionGroupValueCodec) *func(s00.PRSOccasionGroup, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePRSOccasionGroupValueCodecFieldContext(v *PRSOccasionGroupValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePRSOccasionGroupValueCodecFieldDecode(v *PRSOccasionGroupValueCodec) *func([]byte, aper.DecodeState) (s00.PRSOccasionGroup, error) {
	return &v.decode
}
func BridgePRSOccasionGroupValueCodecFieldEncode(v *PRSOccasionGroupValueCodec) *func(s00.PRSOccasionGroup, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePRSOccasionGroupValueCodecFieldPath(v *PRSOccasionGroupValueCodec) *aper.Path {
	return &v.path
}
func BridgePRSOccasionGroupValueCodecMethodEncodeBudget(v PRSOccasionGroupValueCodec, a0 s00.PRSOccasionGroup, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePRSOccasionGroupValueCodecMethodEncodeChanged(v PRSOccasionGroupValueCodec, a0 s00.PRSOccasionGroup, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePhysCellIDGERANAPERValueFieldContext(v *PhysCellIDGERANAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePhysCellIDGERANAPERValueFieldReceived(v *PhysCellIDGERANAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePhysCellIDGERANAPERValueFieldReplay(v *PhysCellIDGERANAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePhysCellIDGERANAPERValueFieldWithoutReplay(v *PhysCellIDGERANAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePhysCellIDGERANValueCodecFieldCapture(v *PhysCellIDGERANValueCodec) *func(s00.PhysCellIDGERAN, aper.DecodeState) (s00.PhysCellIDGERAN, aper.Snapshot) {
	return &v.capture
}
func BridgePhysCellIDGERANValueCodecFieldCompare(v *PhysCellIDGERANValueCodec) *func(s00.PhysCellIDGERAN, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePhysCellIDGERANValueCodecFieldContext(v *PhysCellIDGERANValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePhysCellIDGERANValueCodecFieldDecode(v *PhysCellIDGERANValueCodec) *func([]byte, aper.DecodeState) (s00.PhysCellIDGERAN, error) {
	return &v.decode
}
func BridgePhysCellIDGERANValueCodecFieldEncode(v *PhysCellIDGERANValueCodec) *func(s00.PhysCellIDGERAN, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePhysCellIDGERANValueCodecFieldPath(v *PhysCellIDGERANValueCodec) *aper.Path {
	return &v.path
}
func BridgePhysCellIDGERANValueCodecMethodEncodeBudget(v PhysCellIDGERANValueCodec, a0 s00.PhysCellIDGERAN, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePhysCellIDGERANValueCodecMethodEncodeChanged(v PhysCellIDGERANValueCodec, a0 s00.PhysCellIDGERAN, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePhysCellIDUTRAFDDAPERValueFieldContext(v *PhysCellIDUTRAFDDAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePhysCellIDUTRAFDDAPERValueFieldReceived(v *PhysCellIDUTRAFDDAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePhysCellIDUTRAFDDAPERValueFieldReplay(v *PhysCellIDUTRAFDDAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePhysCellIDUTRAFDDAPERValueFieldWithoutReplay(v *PhysCellIDUTRAFDDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePhysCellIDUTRAFDDValueCodecFieldCapture(v *PhysCellIDUTRAFDDValueCodec) *func(s00.PhysCellIDUTRAFDD, aper.DecodeState) (s00.PhysCellIDUTRAFDD, aper.Snapshot) {
	return &v.capture
}
func BridgePhysCellIDUTRAFDDValueCodecFieldCompare(v *PhysCellIDUTRAFDDValueCodec) *func(s00.PhysCellIDUTRAFDD, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePhysCellIDUTRAFDDValueCodecFieldContext(v *PhysCellIDUTRAFDDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePhysCellIDUTRAFDDValueCodecFieldDecode(v *PhysCellIDUTRAFDDValueCodec) *func([]byte, aper.DecodeState) (s00.PhysCellIDUTRAFDD, error) {
	return &v.decode
}
func BridgePhysCellIDUTRAFDDValueCodecFieldEncode(v *PhysCellIDUTRAFDDValueCodec) *func(s00.PhysCellIDUTRAFDD, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePhysCellIDUTRAFDDValueCodecFieldPath(v *PhysCellIDUTRAFDDValueCodec) *aper.Path {
	return &v.path
}
func BridgePhysCellIDUTRAFDDValueCodecMethodEncodeBudget(v PhysCellIDUTRAFDDValueCodec, a0 s00.PhysCellIDUTRAFDD, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePhysCellIDUTRAFDDValueCodecMethodEncodeChanged(v PhysCellIDUTRAFDDValueCodec, a0 s00.PhysCellIDUTRAFDD, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePhysCellIDUTRATDDAPERValueFieldContext(v *PhysCellIDUTRATDDAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePhysCellIDUTRATDDAPERValueFieldReceived(v *PhysCellIDUTRATDDAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePhysCellIDUTRATDDAPERValueFieldReplay(v *PhysCellIDUTRATDDAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePhysCellIDUTRATDDAPERValueFieldWithoutReplay(v *PhysCellIDUTRATDDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePhysCellIDUTRATDDValueCodecFieldCapture(v *PhysCellIDUTRATDDValueCodec) *func(s00.PhysCellIDUTRATDD, aper.DecodeState) (s00.PhysCellIDUTRATDD, aper.Snapshot) {
	return &v.capture
}
func BridgePhysCellIDUTRATDDValueCodecFieldCompare(v *PhysCellIDUTRATDDValueCodec) *func(s00.PhysCellIDUTRATDD, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePhysCellIDUTRATDDValueCodecFieldContext(v *PhysCellIDUTRATDDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePhysCellIDUTRATDDValueCodecFieldDecode(v *PhysCellIDUTRATDDValueCodec) *func([]byte, aper.DecodeState) (s00.PhysCellIDUTRATDD, error) {
	return &v.decode
}
func BridgePhysCellIDUTRATDDValueCodecFieldEncode(v *PhysCellIDUTRATDDValueCodec) *func(s00.PhysCellIDUTRATDD, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePhysCellIDUTRATDDValueCodecFieldPath(v *PhysCellIDUTRATDDValueCodec) *aper.Path {
	return &v.path
}
func BridgePhysCellIDUTRATDDValueCodecMethodEncodeBudget(v PhysCellIDUTRATDDValueCodec, a0 s00.PhysCellIDUTRATDD, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePhysCellIDUTRATDDValueCodecMethodEncodeChanged(v PhysCellIDUTRATDDValueCodec, a0 s00.PhysCellIDUTRATDD, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePosSIBTypeAPERValueFieldContext(v *PosSIBTypeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBTypeAPERValueFieldReceived(v *PosSIBTypeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePosSIBTypeAPERValueFieldReplay(v *PosSIBTypeAPERValue) *aper.Snapshot { return &v.replay }
func BridgePosSIBTypeAPERValueFieldWithoutReplay(v *PosSIBTypeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePosSIBTypeValueCodecFieldCapture(v *PosSIBTypeValueCodec) *func(s00.PosSIBType, aper.DecodeState) (s00.PosSIBType, aper.Snapshot) {
	return &v.capture
}
func BridgePosSIBTypeValueCodecFieldCompare(v *PosSIBTypeValueCodec) *func(s00.PosSIBType, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePosSIBTypeValueCodecFieldContext(v *PosSIBTypeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBTypeValueCodecFieldDecode(v *PosSIBTypeValueCodec) *func([]byte, aper.DecodeState) (s00.PosSIBType, error) {
	return &v.decode
}
func BridgePosSIBTypeValueCodecFieldEncode(v *PosSIBTypeValueCodec) *func(s00.PosSIBType, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePosSIBTypeValueCodecFieldPath(v *PosSIBTypeValueCodec) *aper.Path { return &v.path }
func BridgePosSIBTypeValueCodecMethodEncodeBudget(v PosSIBTypeValueCodec, a0 s00.PosSIBType, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePosSIBTypeValueCodecMethodEncodeChanged(v PosSIBTypeValueCodec, a0 s00.PosSIBType, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePresenceAPERValueFieldContext(v *PresenceAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePresenceAPERValueFieldReceived(v *PresenceAPERValue) *aper.WireSpan { return &v.received }
func BridgePresenceAPERValueFieldReplay(v *PresenceAPERValue) *aper.Snapshot   { return &v.replay }
func BridgePresenceAPERValueFieldWithoutReplay(v *PresenceAPERValue) *bool     { return &v.withoutReplay }
func BridgePresenceValueCodecFieldCapture(v *PresenceValueCodec) *func(s00.Presence, aper.DecodeState) (s00.Presence, aper.Snapshot) {
	return &v.capture
}
func BridgePresenceValueCodecFieldCompare(v *PresenceValueCodec) *func(s00.Presence, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
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
func BridgePresenceValueCodecMethodEncodeBudget(v PresenceValueCodec, a0 s00.Presence, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePresenceValueCodecMethodEncodeChanged(v PresenceValueCodec, a0 s00.Presence, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeProcedureCodeAPERValueFieldContext(v *ProcedureCodeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeProcedureCodeAPERValueFieldReceived(v *ProcedureCodeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeProcedureCodeAPERValueFieldReplay(v *ProcedureCodeAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeProcedureCodeAPERValueFieldWithoutReplay(v *ProcedureCodeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeProcedureCodeValueCodecFieldCapture(v *ProcedureCodeValueCodec) *func(s00.ProcedureCode, aper.DecodeState) (s00.ProcedureCode, aper.Snapshot) {
	return &v.capture
}
func BridgeProcedureCodeValueCodecFieldCompare(v *ProcedureCodeValueCodec) *func(s00.ProcedureCode, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
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
func BridgeProcedureCodeValueCodecMethodEncodeBudget(v ProcedureCodeValueCodec, a0 s00.ProcedureCode, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeProcedureCodeValueCodecMethodEncodeChanged(v ProcedureCodeValueCodec, a0 s00.ProcedureCode, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeProtocolIEIDAPERValueFieldContext(v *ProtocolIEIDAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeProtocolIEIDAPERValueFieldReceived(v *ProtocolIEIDAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeProtocolIEIDAPERValueFieldReplay(v *ProtocolIEIDAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeProtocolIEIDAPERValueFieldWithoutReplay(v *ProtocolIEIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeProtocolIEIDValueCodecFieldCapture(v *ProtocolIEIDValueCodec) *func(s00.ProtocolIEID, aper.DecodeState) (s00.ProtocolIEID, aper.Snapshot) {
	return &v.capture
}
func BridgeProtocolIEIDValueCodecFieldCompare(v *ProtocolIEIDValueCodec) *func(s00.ProtocolIEID, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
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
func BridgeProtocolIEIDValueCodecMethodEncodeBudget(v ProtocolIEIDValueCodec, a0 s00.ProtocolIEID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeProtocolIEIDValueCodecMethodEncodeChanged(v ProtocolIEIDValueCodec, a0 s00.ProtocolIEID, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRSSIAPERValueFieldContext(v *RSSIAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeRSSIAPERValueFieldReceived(v *RSSIAPERValue) *aper.WireSpan         { return &v.received }
func BridgeRSSIAPERValueFieldReplay(v *RSSIAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeRSSIAPERValueFieldWithoutReplay(v *RSSIAPERValue) *bool             { return &v.withoutReplay }
func BridgeRSSIValueCodecFieldCapture(v *RSSIValueCodec) *func(s00.RSSI, aper.DecodeState) (s00.RSSI, aper.Snapshot) {
	return &v.capture
}
func BridgeRSSIValueCodecFieldCompare(v *RSSIValueCodec) *func(s00.RSSI, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeRSSIValueCodecFieldContext(v *RSSIValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeRSSIValueCodecFieldDecode(v *RSSIValueCodec) *func([]byte, aper.DecodeState) (s00.RSSI, error) {
	return &v.decode
}
func BridgeRSSIValueCodecFieldEncode(v *RSSIValueCodec) *func(s00.RSSI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRSSIValueCodecFieldPath(v *RSSIValueCodec) *aper.Path { return &v.path }
func BridgeRSSIValueCodecMethodEncodeBudget(v RSSIValueCodec, a0 s00.RSSI, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeRSSIValueCodecMethodEncodeChanged(v RSSIValueCodec, a0 s00.RSSI, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeRepetitionNumberofSIB1NBAPERValueFieldContext(v *RepetitionNumberofSIB1NBAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRepetitionNumberofSIB1NBAPERValueFieldReceived(v *RepetitionNumberofSIB1NBAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRepetitionNumberofSIB1NBAPERValueFieldReplay(v *RepetitionNumberofSIB1NBAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeRepetitionNumberofSIB1NBAPERValueFieldWithoutReplay(v *RepetitionNumberofSIB1NBAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeRepetitionNumberofSIB1NBValueCodecFieldCapture(v *RepetitionNumberofSIB1NBValueCodec) *func(s00.RepetitionNumberofSIB1NB, aper.DecodeState) (s00.RepetitionNumberofSIB1NB, aper.Snapshot) {
	return &v.capture
}
func BridgeRepetitionNumberofSIB1NBValueCodecFieldCompare(v *RepetitionNumberofSIB1NBValueCodec) *func(s00.RepetitionNumberofSIB1NB, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeRepetitionNumberofSIB1NBValueCodecFieldContext(v *RepetitionNumberofSIB1NBValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRepetitionNumberofSIB1NBValueCodecFieldDecode(v *RepetitionNumberofSIB1NBValueCodec) *func([]byte, aper.DecodeState) (s00.RepetitionNumberofSIB1NB, error) {
	return &v.decode
}
func BridgeRepetitionNumberofSIB1NBValueCodecFieldEncode(v *RepetitionNumberofSIB1NBValueCodec) *func(s00.RepetitionNumberofSIB1NB, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRepetitionNumberofSIB1NBValueCodecFieldPath(v *RepetitionNumberofSIB1NBValueCodec) *aper.Path {
	return &v.path
}
func BridgeRepetitionNumberofSIB1NBValueCodecMethodEncodeBudget(v RepetitionNumberofSIB1NBValueCodec, a0 s00.RepetitionNumberofSIB1NB, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeRepetitionNumberofSIB1NBValueCodecMethodEncodeChanged(v RepetitionNumberofSIB1NBValueCodec, a0 s00.RepetitionNumberofSIB1NB, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeReportCharacteristicsAPERValueFieldContext(v *ReportCharacteristicsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeReportCharacteristicsAPERValueFieldReceived(v *ReportCharacteristicsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeReportCharacteristicsAPERValueFieldReplay(v *ReportCharacteristicsAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeReportCharacteristicsAPERValueFieldWithoutReplay(v *ReportCharacteristicsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeReportCharacteristicsValueCodecFieldCapture(v *ReportCharacteristicsValueCodec) *func(s00.ReportCharacteristics, aper.DecodeState) (s00.ReportCharacteristics, aper.Snapshot) {
	return &v.capture
}
func BridgeReportCharacteristicsValueCodecFieldCompare(v *ReportCharacteristicsValueCodec) *func(s00.ReportCharacteristics, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeReportCharacteristicsValueCodecFieldContext(v *ReportCharacteristicsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeReportCharacteristicsValueCodecFieldDecode(v *ReportCharacteristicsValueCodec) *func([]byte, aper.DecodeState) (s00.ReportCharacteristics, error) {
	return &v.decode
}
func BridgeReportCharacteristicsValueCodecFieldEncode(v *ReportCharacteristicsValueCodec) *func(s00.ReportCharacteristics, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeReportCharacteristicsValueCodecFieldPath(v *ReportCharacteristicsValueCodec) *aper.Path {
	return &v.path
}
func BridgeReportCharacteristicsValueCodecMethodEncodeBudget(v ReportCharacteristicsValueCodec, a0 s00.ReportCharacteristics, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeReportCharacteristicsValueCodecMethodEncodeChanged(v ReportCharacteristicsValueCodec, a0 s00.ReportCharacteristics, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSFNInitialisationTimeAPERValueFieldContext(v *SFNInitialisationTimeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSFNInitialisationTimeAPERValueFieldReceived(v *SFNInitialisationTimeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSFNInitialisationTimeAPERValueFieldReplay(v *SFNInitialisationTimeAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSFNInitialisationTimeAPERValueFieldWithoutReplay(v *SFNInitialisationTimeAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSFNInitialisationTimeValueCodecFieldCapture(v *SFNInitialisationTimeValueCodec) *func(s00.SFNInitialisationTime, aper.DecodeState) (s00.SFNInitialisationTime, aper.Snapshot) {
	return &v.capture
}
func BridgeSFNInitialisationTimeValueCodecFieldCompare(v *SFNInitialisationTimeValueCodec) *func(s00.SFNInitialisationTime, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeSFNInitialisationTimeValueCodecFieldContext(v *SFNInitialisationTimeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSFNInitialisationTimeValueCodecFieldDecode(v *SFNInitialisationTimeValueCodec) *func([]byte, aper.DecodeState) (s00.SFNInitialisationTime, error) {
	return &v.decode
}
func BridgeSFNInitialisationTimeValueCodecFieldEncode(v *SFNInitialisationTimeValueCodec) *func(s00.SFNInitialisationTime, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSFNInitialisationTimeValueCodecFieldPath(v *SFNInitialisationTimeValueCodec) *aper.Path {
	return &v.path
}
func BridgeSFNInitialisationTimeValueCodecMethodEncodeBudget(v SFNInitialisationTimeValueCodec, a0 s00.SFNInitialisationTime, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSFNInitialisationTimeValueCodecMethodEncodeChanged(v SFNInitialisationTimeValueCodec, a0 s00.SFNInitialisationTime, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSSBIndexAPERValueFieldContext(v *SSBIndexAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSSBIndexAPERValueFieldReceived(v *SSBIndexAPERValue) *aper.WireSpan { return &v.received }
func BridgeSSBIndexAPERValueFieldReplay(v *SSBIndexAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeSSBIndexAPERValueFieldWithoutReplay(v *SSBIndexAPERValue) *bool     { return &v.withoutReplay }
func BridgeSSBIndexValueCodecFieldCapture(v *SSBIndexValueCodec) *func(s00.SSBIndex, aper.DecodeState) (s00.SSBIndex, aper.Snapshot) {
	return &v.capture
}
func BridgeSSBIndexValueCodecFieldCompare(v *SSBIndexValueCodec) *func(s00.SSBIndex, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeSSBIndexValueCodecFieldContext(v *SSBIndexValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSSBIndexValueCodecFieldDecode(v *SSBIndexValueCodec) *func([]byte, aper.DecodeState) (s00.SSBIndex, error) {
	return &v.decode
}
func BridgeSSBIndexValueCodecFieldEncode(v *SSBIndexValueCodec) *func(s00.SSBIndex, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSSBIndexValueCodecFieldPath(v *SSBIndexValueCodec) *aper.Path { return &v.path }
func BridgeSSBIndexValueCodecMethodEncodeBudget(v SSBIndexValueCodec, a0 s00.SSBIndex, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSSBIndexValueCodecMethodEncodeChanged(v SSBIndexValueCodec, a0 s00.SSBIndex, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSSIDAPERValueFieldContext(v *SSIDAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeSSIDAPERValueFieldReceived(v *SSIDAPERValue) *aper.WireSpan         { return &v.received }
func BridgeSSIDAPERValueFieldReplay(v *SSIDAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeSSIDAPERValueFieldWithoutReplay(v *SSIDAPERValue) *bool             { return &v.withoutReplay }
func BridgeSSIDValueCodecFieldCapture(v *SSIDValueCodec) *func(s00.SSID, aper.DecodeState) (s00.SSID, aper.Snapshot) {
	return &v.capture
}
func BridgeSSIDValueCodecFieldCompare(v *SSIDValueCodec) *func(s00.SSID, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeSSIDValueCodecFieldContext(v *SSIDValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeSSIDValueCodecFieldDecode(v *SSIDValueCodec) *func([]byte, aper.DecodeState) (s00.SSID, error) {
	return &v.decode
}
func BridgeSSIDValueCodecFieldEncode(v *SSIDValueCodec) *func(s00.SSID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSSIDValueCodecFieldPath(v *SSIDValueCodec) *aper.Path { return &v.path }
func BridgeSSIDValueCodecMethodEncodeBudget(v SSIDValueCodec, a0 s00.SSID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSSIDValueCodecMethodEncodeChanged(v SSIDValueCodec, a0 s00.SSID, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSSNRRSRPAPERValueFieldContext(v *SSNRRSRPAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSSNRRSRPAPERValueFieldReceived(v *SSNRRSRPAPERValue) *aper.WireSpan { return &v.received }
func BridgeSSNRRSRPAPERValueFieldReplay(v *SSNRRSRPAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeSSNRRSRPAPERValueFieldWithoutReplay(v *SSNRRSRPAPERValue) *bool     { return &v.withoutReplay }
func BridgeSSNRRSRPValueCodecFieldCapture(v *SSNRRSRPValueCodec) *func(s00.SSNRRSRP, aper.DecodeState) (s00.SSNRRSRP, aper.Snapshot) {
	return &v.capture
}
func BridgeSSNRRSRPValueCodecFieldCompare(v *SSNRRSRPValueCodec) *func(s00.SSNRRSRP, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeSSNRRSRPValueCodecFieldContext(v *SSNRRSRPValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSSNRRSRPValueCodecFieldDecode(v *SSNRRSRPValueCodec) *func([]byte, aper.DecodeState) (s00.SSNRRSRP, error) {
	return &v.decode
}
func BridgeSSNRRSRPValueCodecFieldEncode(v *SSNRRSRPValueCodec) *func(s00.SSNRRSRP, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSSNRRSRPValueCodecFieldPath(v *SSNRRSRPValueCodec) *aper.Path { return &v.path }
func BridgeSSNRRSRPValueCodecMethodEncodeBudget(v SSNRRSRPValueCodec, a0 s00.SSNRRSRP, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSSNRRSRPValueCodecMethodEncodeChanged(v SSNRRSRPValueCodec, a0 s00.SSNRRSRP, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSSNRRSRQAPERValueFieldContext(v *SSNRRSRQAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSSNRRSRQAPERValueFieldReceived(v *SSNRRSRQAPERValue) *aper.WireSpan { return &v.received }
func BridgeSSNRRSRQAPERValueFieldReplay(v *SSNRRSRQAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeSSNRRSRQAPERValueFieldWithoutReplay(v *SSNRRSRQAPERValue) *bool     { return &v.withoutReplay }
func BridgeSSNRRSRQValueCodecFieldCapture(v *SSNRRSRQValueCodec) *func(s00.SSNRRSRQ, aper.DecodeState) (s00.SSNRRSRQ, aper.Snapshot) {
	return &v.capture
}
func BridgeSSNRRSRQValueCodecFieldCompare(v *SSNRRSRQValueCodec) *func(s00.SSNRRSRQ, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeSSNRRSRQValueCodecFieldContext(v *SSNRRSRQValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSSNRRSRQValueCodecFieldDecode(v *SSNRRSRQValueCodec) *func([]byte, aper.DecodeState) (s00.SSNRRSRQ, error) {
	return &v.decode
}
func BridgeSSNRRSRQValueCodecFieldEncode(v *SSNRRSRQValueCodec) *func(s00.SSNRRSRQ, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSSNRRSRQValueCodecFieldPath(v *SSNRRSRQValueCodec) *aper.Path { return &v.path }
func BridgeSSNRRSRQValueCodecMethodEncodeBudget(v SSNRRSRQValueCodec, a0 s00.SSNRRSRQ, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSSNRRSRQValueCodecMethodEncodeChanged(v SSNRRSRQValueCodec, a0 s00.SSNRRSRQ, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTACAPERValueFieldContext(v *TACAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeTACAPERValueFieldReceived(v *TACAPERValue) *aper.WireSpan         { return &v.received }
func BridgeTACAPERValueFieldReplay(v *TACAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeTACAPERValueFieldWithoutReplay(v *TACAPERValue) *bool             { return &v.withoutReplay }
func BridgeTACValueCodecFieldCapture(v *TACValueCodec) *func(s00.TAC, aper.DecodeState) (s00.TAC, aper.Snapshot) {
	return &v.capture
}
func BridgeTACValueCodecFieldCompare(v *TACValueCodec) *func(s00.TAC, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
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
func BridgeTACValueCodecMethodEncodeBudget(v TACValueCodec, a0 s00.TAC, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeTACValueCodecMethodEncodeChanged(v TACValueCodec, a0 s00.TAC, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTPIDAPERValueFieldContext(v *TPIDAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeTPIDAPERValueFieldReceived(v *TPIDAPERValue) *aper.WireSpan         { return &v.received }
func BridgeTPIDAPERValueFieldReplay(v *TPIDAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeTPIDAPERValueFieldWithoutReplay(v *TPIDAPERValue) *bool             { return &v.withoutReplay }
func BridgeTPIDValueCodecFieldCapture(v *TPIDValueCodec) *func(s00.TPID, aper.DecodeState) (s00.TPID, aper.Snapshot) {
	return &v.capture
}
func BridgeTPIDValueCodecFieldCompare(v *TPIDValueCodec) *func(s00.TPID, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeTPIDValueCodecFieldContext(v *TPIDValueCodec) *s00.BridgeCodecContext { return &v.context }
func BridgeTPIDValueCodecFieldDecode(v *TPIDValueCodec) *func([]byte, aper.DecodeState) (s00.TPID, error) {
	return &v.decode
}
func BridgeTPIDValueCodecFieldEncode(v *TPIDValueCodec) *func(s00.TPID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTPIDValueCodecFieldPath(v *TPIDValueCodec) *aper.Path { return &v.path }
func BridgeTPIDValueCodecMethodEncodeBudget(v TPIDValueCodec, a0 s00.TPID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeTPIDValueCodecMethodEncodeChanged(v TPIDValueCodec, a0 s00.TPID, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTPTypeAPERValueFieldContext(v *TPTypeAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeTPTypeAPERValueFieldReceived(v *TPTypeAPERValue) *aper.WireSpan         { return &v.received }
func BridgeTPTypeAPERValueFieldReplay(v *TPTypeAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeTPTypeAPERValueFieldWithoutReplay(v *TPTypeAPERValue) *bool             { return &v.withoutReplay }
func BridgeTPTypeValueCodecFieldCapture(v *TPTypeValueCodec) *func(s00.TPType, aper.DecodeState) (s00.TPType, aper.Snapshot) {
	return &v.capture
}
func BridgeTPTypeValueCodecFieldCompare(v *TPTypeValueCodec) *func(s00.TPType, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeTPTypeValueCodecFieldContext(v *TPTypeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTPTypeValueCodecFieldDecode(v *TPTypeValueCodec) *func([]byte, aper.DecodeState) (s00.TPType, error) {
	return &v.decode
}
func BridgeTPTypeValueCodecFieldEncode(v *TPTypeValueCodec) *func(s00.TPType, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTPTypeValueCodecFieldPath(v *TPTypeValueCodec) *aper.Path { return &v.path }
func BridgeTPTypeValueCodecMethodEncodeBudget(v TPTypeValueCodec, a0 s00.TPType, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeTPTypeValueCodecMethodEncodeChanged(v TPTypeValueCodec, a0 s00.TPType, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
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
func BridgeTriggeringMessageValueCodecFieldCompare(v *TriggeringMessageValueCodec) *func(s00.TriggeringMessage, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
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
func BridgeTriggeringMessageValueCodecMethodEncodeBudget(v TriggeringMessageValueCodec, a0 s00.TriggeringMessage, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeTriggeringMessageValueCodecMethodEncodeChanged(v TriggeringMessageValueCodec, a0 s00.TriggeringMessage, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
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
func BridgeTypeOfErrorValueCodecFieldCompare(v *TypeOfErrorValueCodec) *func(s00.TypeOfError, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
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
func BridgeTypeOfErrorValueCodecMethodEncodeBudget(v TypeOfErrorValueCodec, a0 s00.TypeOfError, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeTypeOfErrorValueCodecMethodEncodeChanged(v TypeOfErrorValueCodec, a0 s00.TypeOfError, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUARFCNAPERValueFieldContext(v *UARFCNAPERValue) *s00.BridgeCodecContext { return &v.context }
func BridgeUARFCNAPERValueFieldReceived(v *UARFCNAPERValue) *aper.WireSpan         { return &v.received }
func BridgeUARFCNAPERValueFieldReplay(v *UARFCNAPERValue) *aper.Snapshot           { return &v.replay }
func BridgeUARFCNAPERValueFieldWithoutReplay(v *UARFCNAPERValue) *bool             { return &v.withoutReplay }
func BridgeUARFCNValueCodecFieldCapture(v *UARFCNValueCodec) *func(s00.UARFCN, aper.DecodeState) (s00.UARFCN, aper.Snapshot) {
	return &v.capture
}
func BridgeUARFCNValueCodecFieldCompare(v *UARFCNValueCodec) *func(s00.UARFCN, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeUARFCNValueCodecFieldContext(v *UARFCNValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUARFCNValueCodecFieldDecode(v *UARFCNValueCodec) *func([]byte, aper.DecodeState) (s00.UARFCN, error) {
	return &v.decode
}
func BridgeUARFCNValueCodecFieldEncode(v *UARFCNValueCodec) *func(s00.UARFCN, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUARFCNValueCodecFieldPath(v *UARFCNValueCodec) *aper.Path { return &v.path }
func BridgeUARFCNValueCodecMethodEncodeBudget(v UARFCNValueCodec, a0 s00.UARFCN, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeUARFCNValueCodecMethodEncodeChanged(v UARFCNValueCodec, a0 s00.UARFCN, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUTRAEcN0APERValueFieldContext(v *UTRAEcN0APERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUTRAEcN0APERValueFieldReceived(v *UTRAEcN0APERValue) *aper.WireSpan { return &v.received }
func BridgeUTRAEcN0APERValueFieldReplay(v *UTRAEcN0APERValue) *aper.Snapshot   { return &v.replay }
func BridgeUTRAEcN0APERValueFieldWithoutReplay(v *UTRAEcN0APERValue) *bool     { return &v.withoutReplay }
func BridgeUTRAEcN0ValueCodecFieldCapture(v *UTRAEcN0ValueCodec) *func(s00.UTRAEcN0, aper.DecodeState) (s00.UTRAEcN0, aper.Snapshot) {
	return &v.capture
}
func BridgeUTRAEcN0ValueCodecFieldCompare(v *UTRAEcN0ValueCodec) *func(s00.UTRAEcN0, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeUTRAEcN0ValueCodecFieldContext(v *UTRAEcN0ValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUTRAEcN0ValueCodecFieldDecode(v *UTRAEcN0ValueCodec) *func([]byte, aper.DecodeState) (s00.UTRAEcN0, error) {
	return &v.decode
}
func BridgeUTRAEcN0ValueCodecFieldEncode(v *UTRAEcN0ValueCodec) *func(s00.UTRAEcN0, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTRAEcN0ValueCodecFieldPath(v *UTRAEcN0ValueCodec) *aper.Path { return &v.path }
func BridgeUTRAEcN0ValueCodecMethodEncodeBudget(v UTRAEcN0ValueCodec, a0 s00.UTRAEcN0, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeUTRAEcN0ValueCodecMethodEncodeChanged(v UTRAEcN0ValueCodec, a0 s00.UTRAEcN0, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUTRARSCPAPERValueFieldContext(v *UTRARSCPAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUTRARSCPAPERValueFieldReceived(v *UTRARSCPAPERValue) *aper.WireSpan { return &v.received }
func BridgeUTRARSCPAPERValueFieldReplay(v *UTRARSCPAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeUTRARSCPAPERValueFieldWithoutReplay(v *UTRARSCPAPERValue) *bool     { return &v.withoutReplay }
func BridgeUTRARSCPValueCodecFieldCapture(v *UTRARSCPValueCodec) *func(s00.UTRARSCP, aper.DecodeState) (s00.UTRARSCP, aper.Snapshot) {
	return &v.capture
}
func BridgeUTRARSCPValueCodecFieldCompare(v *UTRARSCPValueCodec) *func(s00.UTRARSCP, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeUTRARSCPValueCodecFieldContext(v *UTRARSCPValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeUTRARSCPValueCodecFieldDecode(v *UTRARSCPValueCodec) *func([]byte, aper.DecodeState) (s00.UTRARSCP, error) {
	return &v.decode
}
func BridgeUTRARSCPValueCodecFieldEncode(v *UTRARSCPValueCodec) *func(s00.UTRARSCP, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeUTRARSCPValueCodecFieldPath(v *UTRARSCPValueCodec) *aper.Path { return &v.path }
func BridgeUTRARSCPValueCodecMethodEncodeBudget(v UTRARSCPValueCodec, a0 s00.UTRARSCP, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeUTRARSCPValueCodecMethodEncodeChanged(v UTRARSCPValueCodec, a0 s00.UTRARSCP, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeValueRSRPAPERValueFieldContext(v *ValueRSRPAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeValueRSRPAPERValueFieldReceived(v *ValueRSRPAPERValue) *aper.WireSpan { return &v.received }
func BridgeValueRSRPAPERValueFieldReplay(v *ValueRSRPAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeValueRSRPAPERValueFieldWithoutReplay(v *ValueRSRPAPERValue) *bool     { return &v.withoutReplay }
func BridgeValueRSRPValueCodecFieldCapture(v *ValueRSRPValueCodec) *func(s00.ValueRSRP, aper.DecodeState) (s00.ValueRSRP, aper.Snapshot) {
	return &v.capture
}
func BridgeValueRSRPValueCodecFieldCompare(v *ValueRSRPValueCodec) *func(s00.ValueRSRP, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeValueRSRPValueCodecFieldContext(v *ValueRSRPValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeValueRSRPValueCodecFieldDecode(v *ValueRSRPValueCodec) *func([]byte, aper.DecodeState) (s00.ValueRSRP, error) {
	return &v.decode
}
func BridgeValueRSRPValueCodecFieldEncode(v *ValueRSRPValueCodec) *func(s00.ValueRSRP, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeValueRSRPValueCodecFieldPath(v *ValueRSRPValueCodec) *aper.Path { return &v.path }
func BridgeValueRSRPValueCodecMethodEncodeBudget(v ValueRSRPValueCodec, a0 s00.ValueRSRP, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeValueRSRPValueCodecMethodEncodeChanged(v ValueRSRPValueCodec, a0 s00.ValueRSRP, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeValueRSRQAPERValueFieldContext(v *ValueRSRQAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeValueRSRQAPERValueFieldReceived(v *ValueRSRQAPERValue) *aper.WireSpan { return &v.received }
func BridgeValueRSRQAPERValueFieldReplay(v *ValueRSRQAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeValueRSRQAPERValueFieldWithoutReplay(v *ValueRSRQAPERValue) *bool     { return &v.withoutReplay }
func BridgeValueRSRQValueCodecFieldCapture(v *ValueRSRQValueCodec) *func(s00.ValueRSRQ, aper.DecodeState) (s00.ValueRSRQ, aper.Snapshot) {
	return &v.capture
}
func BridgeValueRSRQValueCodecFieldCompare(v *ValueRSRQValueCodec) *func(s00.ValueRSRQ, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeValueRSRQValueCodecFieldContext(v *ValueRSRQValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeValueRSRQValueCodecFieldDecode(v *ValueRSRQValueCodec) *func([]byte, aper.DecodeState) (s00.ValueRSRQ, error) {
	return &v.decode
}
func BridgeValueRSRQValueCodecFieldEncode(v *ValueRSRQValueCodec) *func(s00.ValueRSRQ, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeValueRSRQValueCodecFieldPath(v *ValueRSRQValueCodec) *aper.Path { return &v.path }
func BridgeValueRSRQValueCodecMethodEncodeBudget(v ValueRSRQValueCodec, a0 s00.ValueRSRQ, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeValueRSRQValueCodecMethodEncodeChanged(v ValueRSRQValueCodec, a0 s00.ValueRSRQ, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANBandAPERValueFieldContext(v *WLANBandAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANBandAPERValueFieldReceived(v *WLANBandAPERValue) *aper.WireSpan { return &v.received }
func BridgeWLANBandAPERValueFieldReplay(v *WLANBandAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeWLANBandAPERValueFieldWithoutReplay(v *WLANBandAPERValue) *bool     { return &v.withoutReplay }
func BridgeWLANBandValueCodecFieldCapture(v *WLANBandValueCodec) *func(s00.WLANBand, aper.DecodeState) (s00.WLANBand, aper.Snapshot) {
	return &v.capture
}
func BridgeWLANBandValueCodecFieldCompare(v *WLANBandValueCodec) *func(s00.WLANBand, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeWLANBandValueCodecFieldContext(v *WLANBandValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANBandValueCodecFieldDecode(v *WLANBandValueCodec) *func([]byte, aper.DecodeState) (s00.WLANBand, error) {
	return &v.decode
}
func BridgeWLANBandValueCodecFieldEncode(v *WLANBandValueCodec) *func(s00.WLANBand, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANBandValueCodecFieldPath(v *WLANBandValueCodec) *aper.Path { return &v.path }
func BridgeWLANBandValueCodecMethodEncodeBudget(v WLANBandValueCodec, a0 s00.WLANBand, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANBandValueCodecMethodEncodeChanged(v WLANBandValueCodec, a0 s00.WLANBand, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANChannelAPERValueFieldContext(v *WLANChannelAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANChannelAPERValueFieldReceived(v *WLANChannelAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWLANChannelAPERValueFieldReplay(v *WLANChannelAPERValue) *aper.Snapshot { return &v.replay }
func BridgeWLANChannelAPERValueFieldWithoutReplay(v *WLANChannelAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANChannelListAPERValueFieldContext(v *WLANChannelListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANChannelListAPERValueFieldReceived(v *WLANChannelListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWLANChannelListAPERValueFieldReplay(v *WLANChannelListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANChannelListAPERValueFieldWithoutReplay(v *WLANChannelListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANChannelListValueCodecFieldCapture(v *WLANChannelListValueCodec) *func(s00.WLANChannelList, aper.DecodeState) (s00.WLANChannelList, aper.Snapshot) {
	return &v.capture
}
func BridgeWLANChannelListValueCodecFieldCompare(v *WLANChannelListValueCodec) *func(s00.WLANChannelList, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeWLANChannelListValueCodecFieldContext(v *WLANChannelListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANChannelListValueCodecFieldDecode(v *WLANChannelListValueCodec) *func([]byte, aper.DecodeState) (s00.WLANChannelList, error) {
	return &v.decode
}
func BridgeWLANChannelListValueCodecFieldEncode(v *WLANChannelListValueCodec) *func(s00.WLANChannelList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANChannelListValueCodecFieldPath(v *WLANChannelListValueCodec) *aper.Path {
	return &v.path
}
func BridgeWLANChannelListValueCodecMethodEncodeBudget(v WLANChannelListValueCodec, a0 s00.WLANChannelList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANChannelListValueCodecMethodEncodeChanged(v WLANChannelListValueCodec, a0 s00.WLANChannelList, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANChannelValueCodecFieldCapture(v *WLANChannelValueCodec) *func(s00.WLANChannel, aper.DecodeState) (s00.WLANChannel, aper.Snapshot) {
	return &v.capture
}
func BridgeWLANChannelValueCodecFieldCompare(v *WLANChannelValueCodec) *func(s00.WLANChannel, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeWLANChannelValueCodecFieldContext(v *WLANChannelValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANChannelValueCodecFieldDecode(v *WLANChannelValueCodec) *func([]byte, aper.DecodeState) (s00.WLANChannel, error) {
	return &v.decode
}
func BridgeWLANChannelValueCodecFieldEncode(v *WLANChannelValueCodec) *func(s00.WLANChannel, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANChannelValueCodecFieldPath(v *WLANChannelValueCodec) *aper.Path { return &v.path }
func BridgeWLANChannelValueCodecMethodEncodeBudget(v WLANChannelValueCodec, a0 s00.WLANChannel, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANChannelValueCodecMethodEncodeChanged(v WLANChannelValueCodec, a0 s00.WLANChannel, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANCountryCodeAPERValueFieldContext(v *WLANCountryCodeAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANCountryCodeAPERValueFieldReceived(v *WLANCountryCodeAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWLANCountryCodeAPERValueFieldReplay(v *WLANCountryCodeAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANCountryCodeAPERValueFieldWithoutReplay(v *WLANCountryCodeAPERValue) *bool {
	return &v.withoutReplay
}
