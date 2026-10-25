// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s08 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s08

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
	"math/big"
)

// PrivateMessageIEsValuePrivateIEContainer is the concrete PrivateIEContainer[PrivateMessageIEsValue].
type PrivateMessageIEsValuePrivateIEContainer []PrivateMessageIEsValuePrivateIEField

// PrivateMessageIEsValuePrivateIEField is the concrete PrivateIEField[PrivateMessageIEsValue].
type PrivateMessageIEsValuePrivateIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            PrivateIEID
	Criticality   s00.Criticality
	Value         PrivateMessageIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PrivateMessageIEsValuePrivateIEField) WithoutReplay() PrivateMessageIEsValuePrivateIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *PrivateMessageIEsValuePrivateIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *PrivateMessageIEsValuePrivateIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		return fmt.Errorf("nil PrivateIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the private value to @id, too.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: private field id does not match its value selector", aper.ErrInvalidValue), "PrivateIEField.Id")
	}
	if err := v.Id.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
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
	return aper.EncodeOpenTypeAligned(bb, data)
}
func (v *PrivateMessageIEsValuePrivateIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil PrivateIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PrivateMessageIEsValuePrivateIEField{}
	if err := v.Id.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero PrivateMessageIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("PrivateIEField.Value")
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
	capture func(s07.OTDOAInformationType, aper.DecodeState,

	) (s07.OTDOAInformationType, aper.Snapshot,

	)
	compare func(s07.OTDOAInformationType, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s07.OTDOAInformationType,

		error)
	encode func(s07.OTDOAInformationType,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c OTDOAInformationTypeValueCodec) New(value s07.OTDOAInformationType,

) (s07.OTDOAInformationTypeAPERValue, error) {
	if c.encode == nil {
		return s07.OTDOAInformationTypeAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s07.OTDOAInformationTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return s07.OTDOAInformationTypeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return s07.OTDOAInformationTypeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c OTDOAInformationTypeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (s07.OTDOAInformationTypeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return s07.OTDOAInformationTypeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return s07.OTDOAInformationTypeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return s07.OTDOAInformationTypeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return s07.OTDOAInformationTypeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return func() s07.OTDOAInformationTypeAPERValue {
		sealed := s07.OTDOAInformationTypeAPERValue{Value: value}
		*s07.BridgeOTDOAInformationTypeAPERValueFieldReceived(&sealed) = aper.OriginalWire(data)
		*s07.BridgeOTDOAInformationTypeAPERValueFieldReplay(&sealed) = replay
		*s07.BridgeOTDOAInformationTypeAPERValueFieldContext(&sealed) = c.context
		return sealed
	}(), report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c OTDOAInformationTypeValueCodec) EncodeAPER(value s07.OTDOAInformationTypeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	fresh := *s07.BridgeOTDOAInformationTypeAPERValueFieldWithoutReplay(&value) || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && *s07.BridgeOTDOAInformationTypeAPERValueFieldContext(&value) == c.context && (*s07.BridgeOTDOAInformationTypeAPERValueFieldReplay(&value)).Present() {

		plan := c.compare(value.Value, *s07.BridgeOTDOAInformationTypeAPERValueFieldReplay(&value), aper.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(*s07.BridgeOTDOAInformationTypeAPERValueFieldReplay(&value)) {
			if err := (*s07.BridgeOTDOAInformationTypeAPERValueFieldReplay(&value)).ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, c.path)
			}
			out, err := (*s07.BridgeOTDOAInformationTypeAPERValueFieldReceived(&value)).ReplayBytes(&budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, aper.OperationError(err, c.path)
}
func (c OTDOAInformationTypeValueCodec) encodeBudget(value s07.OTDOAInformationType,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c OTDOAInformationTypeValueCodec) encodeChanged(value s07.OTDOAInformationType,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// RequestedSRSTransmissionCharacteristicsValueCodec is the concrete ValueCodec[RequestedSRSTransmissionCharacteristics].
type RequestedSRSTransmissionCharacteristicsValueCodec struct {
	context s00.BridgeCodecContext
	capture func(RequestedSRSTransmissionCharacteristics, aper.DecodeState,

	) (RequestedSRSTransmissionCharacteristics, aper.Snapshot,

	)
	compare func(RequestedSRSTransmissionCharacteristics, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (RequestedSRSTransmissionCharacteristics,

		error)
	encode func(RequestedSRSTransmissionCharacteristics,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c RequestedSRSTransmissionCharacteristicsValueCodec) New(value RequestedSRSTransmissionCharacteristics,

) (RequestedSRSTransmissionCharacteristicsAPERValue, error) {
	if c.encode == nil {
		return RequestedSRSTransmissionCharacteristicsAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return RequestedSRSTransmissionCharacteristicsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return RequestedSRSTransmissionCharacteristicsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return RequestedSRSTransmissionCharacteristicsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c RequestedSRSTransmissionCharacteristicsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (RequestedSRSTransmissionCharacteristicsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return RequestedSRSTransmissionCharacteristicsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return RequestedSRSTransmissionCharacteristicsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return RequestedSRSTransmissionCharacteristicsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return RequestedSRSTransmissionCharacteristicsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return RequestedSRSTransmissionCharacteristicsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c RequestedSRSTransmissionCharacteristicsValueCodec) EncodeAPER(value RequestedSRSTransmissionCharacteristicsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c RequestedSRSTransmissionCharacteristicsValueCodec) encodeBudget(value RequestedSRSTransmissionCharacteristics,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c RequestedSRSTransmissionCharacteristicsValueCodec) encodeChanged(value RequestedSRSTransmissionCharacteristics,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// PRSFrequencyHoppingConfigurationValueCodec is the concrete ValueCodec[PRSFrequencyHoppingConfiguration].
type PRSFrequencyHoppingConfigurationValueCodec struct {
	context s00.BridgeCodecContext
	capture func(PRSFrequencyHoppingConfiguration, aper.DecodeState,

	) (PRSFrequencyHoppingConfiguration, aper.Snapshot,

	)
	compare func(PRSFrequencyHoppingConfiguration, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (PRSFrequencyHoppingConfiguration,

		error)
	encode func(PRSFrequencyHoppingConfiguration,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PRSFrequencyHoppingConfigurationValueCodec) New(value PRSFrequencyHoppingConfiguration,

) (PRSFrequencyHoppingConfigurationAPERValue, error) {
	if c.encode == nil {
		return PRSFrequencyHoppingConfigurationAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PRSFrequencyHoppingConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PRSFrequencyHoppingConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PRSFrequencyHoppingConfigurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PRSFrequencyHoppingConfigurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PRSFrequencyHoppingConfigurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PRSFrequencyHoppingConfigurationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PRSFrequencyHoppingConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PRSFrequencyHoppingConfigurationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PRSFrequencyHoppingConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PRSFrequencyHoppingConfigurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PRSFrequencyHoppingConfigurationValueCodec) EncodeAPER(value PRSFrequencyHoppingConfigurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PRSFrequencyHoppingConfigurationValueCodec) encodeBudget(value PRSFrequencyHoppingConfiguration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PRSFrequencyHoppingConfigurationValueCodec) encodeChanged(value PRSFrequencyHoppingConfiguration,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// PRSMutingConfigurationValueCodec is the concrete ValueCodec[PRSMutingConfiguration].
type PRSMutingConfigurationValueCodec struct {
	context s00.BridgeCodecContext
	capture func(PRSMutingConfiguration, aper.DecodeState,

	) (PRSMutingConfiguration, aper.Snapshot,

	)
	compare func(PRSMutingConfiguration, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (PRSMutingConfiguration,

		error)
	encode func(PRSMutingConfiguration,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PRSMutingConfigurationValueCodec) New(value PRSMutingConfiguration,

) (PRSMutingConfigurationAPERValue, error) {
	if c.encode == nil {
		return PRSMutingConfigurationAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PRSMutingConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PRSMutingConfigurationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PRSMutingConfigurationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PRSMutingConfigurationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PRSMutingConfigurationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PRSMutingConfigurationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PRSMutingConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PRSMutingConfigurationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PRSMutingConfigurationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PRSMutingConfigurationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PRSMutingConfigurationValueCodec) EncodeAPER(value PRSMutingConfigurationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PRSMutingConfigurationValueCodec) encodeBudget(value PRSMutingConfiguration,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PRSMutingConfigurationValueCodec) encodeChanged(value PRSMutingConfiguration,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// PosSIBSegmentsValueCodec is the concrete ValueCodec[PosSIBSegments].
type PosSIBSegmentsValueCodec struct {
	context s00.BridgeCodecContext
	capture func(PosSIBSegments, aper.DecodeState,

	) (PosSIBSegments, aper.Snapshot,

	)
	compare func(PosSIBSegments, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (PosSIBSegments,

		error)
	encode func(PosSIBSegments,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PosSIBSegmentsValueCodec) New(value PosSIBSegments,

) (PosSIBSegmentsAPERValue, error) {
	if c.encode == nil {
		return PosSIBSegmentsAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PosSIBSegmentsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PosSIBSegmentsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PosSIBSegmentsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PosSIBSegmentsValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PosSIBSegmentsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PosSIBSegmentsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PosSIBSegmentsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PosSIBSegmentsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PosSIBSegmentsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PosSIBSegmentsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PosSIBSegmentsValueCodec) EncodeAPER(value PosSIBSegmentsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PosSIBSegmentsValueCodec) encodeBudget(value PosSIBSegments,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PosSIBSegmentsValueCodec) encodeChanged(value PosSIBSegments,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// PosSIBSegmentsElemValueCodec is the concrete ValueCodec[PosSIBSegmentsElem].
type PosSIBSegmentsElemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(PosSIBSegmentsElem, aper.DecodeState,

	) (PosSIBSegmentsElem, aper.Snapshot,

	)
	compare func(PosSIBSegmentsElem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (PosSIBSegmentsElem,

		error)
	encode func(PosSIBSegmentsElem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PosSIBSegmentsElemValueCodec) New(value PosSIBSegmentsElem,

) (PosSIBSegmentsElemAPERValue, error) {
	if c.encode == nil {
		return PosSIBSegmentsElemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PosSIBSegmentsElemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PosSIBSegmentsElemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PosSIBSegmentsElemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PosSIBSegmentsElemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PosSIBSegmentsElemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PosSIBSegmentsElemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PosSIBSegmentsElemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PosSIBSegmentsElemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PosSIBSegmentsElemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PosSIBSegmentsElemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PosSIBSegmentsElemValueCodec) EncodeAPER(value PosSIBSegmentsElemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PosSIBSegmentsElemValueCodec) encodeBudget(value PosSIBSegmentsElem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PosSIBSegmentsElemValueCodec) encodeChanged(value PosSIBSegmentsElem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// PrivateIEIDValueCodec is the concrete ValueCodec[PrivateIEID].
type PrivateIEIDValueCodec struct {
	context s00.BridgeCodecContext
	capture func(PrivateIEID, aper.DecodeState,

	) (PrivateIEID, aper.Snapshot,

	)
	compare func(PrivateIEID, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (PrivateIEID,

		error)
	encode func(PrivateIEID,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c PrivateIEIDValueCodec) New(value PrivateIEID,

) (PrivateIEIDAPERValue, error) {
	if c.encode == nil {
		return PrivateIEIDAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return PrivateIEIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return PrivateIEIDAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return PrivateIEIDAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c PrivateIEIDValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (PrivateIEIDAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return PrivateIEIDAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return PrivateIEIDAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return PrivateIEIDAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return PrivateIEIDAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return PrivateIEIDAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c PrivateIEIDValueCodec) EncodeAPER(value PrivateIEIDAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c PrivateIEIDValueCodec) encodeBudget(value PrivateIEID,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c PrivateIEIDValueCodec) encodeChanged(value PrivateIEID,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ResultUTRANItemPhysCellIDUTRANValueCodec is the concrete ValueCodec[ResultUTRANItemPhysCellIDUTRAN].
type ResultUTRANItemPhysCellIDUTRANValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ResultUTRANItemPhysCellIDUTRAN, aper.DecodeState,

	) (ResultUTRANItemPhysCellIDUTRAN, aper.Snapshot,

	)
	compare func(ResultUTRANItemPhysCellIDUTRAN, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ResultUTRANItemPhysCellIDUTRAN,

		error)
	encode func(ResultUTRANItemPhysCellIDUTRAN,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ResultUTRANItemPhysCellIDUTRANValueCodec) New(value ResultUTRANItemPhysCellIDUTRAN,

) (ResultUTRANItemPhysCellIDUTRANAPERValue, error) {
	if c.encode == nil {
		return ResultUTRANItemPhysCellIDUTRANAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResultUTRANItemPhysCellIDUTRANAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultUTRANItemPhysCellIDUTRANAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ResultUTRANItemPhysCellIDUTRANAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ResultUTRANItemPhysCellIDUTRANValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResultUTRANItemPhysCellIDUTRANAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultUTRANItemPhysCellIDUTRANAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ResultUTRANItemPhysCellIDUTRANAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultUTRANItemPhysCellIDUTRANAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ResultUTRANItemPhysCellIDUTRANAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ResultUTRANItemPhysCellIDUTRANAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ResultUTRANItemPhysCellIDUTRANValueCodec) EncodeAPER(value ResultUTRANItemPhysCellIDUTRANAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResultUTRANItemPhysCellIDUTRANValueCodec) encodeBudget(value ResultUTRANItemPhysCellIDUTRAN,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultUTRANItemPhysCellIDUTRANValueCodec) encodeChanged(value ResultUTRANItemPhysCellIDUTRAN,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// RequestedSRSTransmissionCharacteristicsAPERValue is the concrete APERValue[RequestedSRSTransmissionCharacteristics].
type RequestedSRSTransmissionCharacteristicsAPERValue struct {
	context s00.BridgeCodecContext
	Value   RequestedSRSTransmissionCharacteristics

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v RequestedSRSTransmissionCharacteristicsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v RequestedSRSTransmissionCharacteristicsAPERValue) WithoutReplay() RequestedSRSTransmissionCharacteristicsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PRSFrequencyHoppingConfigurationAPERValue is the concrete APERValue[PRSFrequencyHoppingConfiguration].
type PRSFrequencyHoppingConfigurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   PRSFrequencyHoppingConfiguration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PRSFrequencyHoppingConfigurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PRSFrequencyHoppingConfigurationAPERValue) WithoutReplay() PRSFrequencyHoppingConfigurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PRSMutingConfigurationAPERValue is the concrete APERValue[PRSMutingConfiguration].
type PRSMutingConfigurationAPERValue struct {
	context s00.BridgeCodecContext
	Value   PRSMutingConfiguration

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PRSMutingConfigurationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PRSMutingConfigurationAPERValue) WithoutReplay() PRSMutingConfigurationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PosSIBSegmentsAPERValue is the concrete APERValue[PosSIBSegments].
type PosSIBSegmentsAPERValue struct {
	context s00.BridgeCodecContext
	Value   PosSIBSegments

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PosSIBSegmentsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PosSIBSegmentsAPERValue) WithoutReplay() PosSIBSegmentsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PosSIBSegmentsElemAPERValue is the concrete APERValue[PosSIBSegmentsElem].
type PosSIBSegmentsElemAPERValue struct {
	context s00.BridgeCodecContext
	Value   PosSIBSegmentsElem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PosSIBSegmentsElemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PosSIBSegmentsElemAPERValue) WithoutReplay() PosSIBSegmentsElemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PrivateIEIDAPERValue is the concrete APERValue[PrivateIEID].
type PrivateIEIDAPERValue struct {
	context s00.BridgeCodecContext
	Value   PrivateIEID

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v PrivateIEIDAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PrivateIEIDAPERValue) WithoutReplay() PrivateIEIDAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultUTRANItemPhysCellIDUTRANAPERValue is the concrete APERValue[ResultUTRANItemPhysCellIDUTRAN].
type ResultUTRANItemPhysCellIDUTRANAPERValue struct {
	context s00.BridgeCodecContext
	Value   ResultUTRANItemPhysCellIDUTRAN

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ResultUTRANItemPhysCellIDUTRANAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultUTRANItemPhysCellIDUTRANAPERValue) WithoutReplay() ResultUTRANItemPhysCellIDUTRANAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// PrivateIEID represents the ASN.1 CHOICE type PrivateIE-ID.
type PrivateIEID struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	withoutReplay      bool
	received           bool
	receivedBytes      aper.WireSpan
	Choice             int
	perPadding         aper.CompletePadding      `json:"-"`
	perOpenTypePadding aper.CompletePadding      `json:"-"`
	Local              *int64                    `json:"Local,omitempty"`
	Global             *runtime.ObjectIdentifier `json:"Global,omitempty"`
}

// MarshalAPER encodes PrivateIEID to APER format.
func (v *PrivateIEID) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *PrivateIEID) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		return fmt.Errorf("%s choice %d must be positive", "PrivateIEID:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.PrivateIEIDChoiceLocal:
		if v.Local == nil {
			return fmt.Errorf("choice alternative local is nil")
		}
		if err := aper.EncodeIntegerAligned(bb, int64(*v.Local), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
			return fmt.Errorf("encoding local: %w", err)
		}
	case s00.PrivateIEIDChoiceGlobal:
		if v.Global == nil {
			return fmt.Errorf("choice alternative global is nil")
		}
		if err := aper.EncodeObjectIdentifierAligned(bb, *v.Global); err != nil {
			return fmt.Errorf("encoding global: %w", err)
		}
	default:
		return fmt.Errorf("unknown PrivateIEID choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes PrivateIEID from APER format.
func (v *PrivateIEID) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PrivateIEID with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PrivateIEID) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PrivateIEID")
	}
	bb.EnterComponent("PrivateIEID")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PrivateIEID")
	}
	padding, err := aper.CaptureFinalBits(bb, "PrivateIEID")
	if err != nil {
		return runtime.WrapDecodePath(err, "PrivateIEID")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *PrivateIEID) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PrivateIEID{}
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 1)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.PrivateIEIDChoiceLocal:
		val_local, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "Local")
		}
		if err := aper.ChargeValue(bb, val_local); err != nil {
			return err
		}
		v.Local = (*int64)(bb.OwnInt64(int64(val_local)))
	case s00.PrivateIEIDChoiceGlobal:
		val_global, err := aper.DecodeObjectIdentifierAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "Global")
		}
		tmp_global := val_global
		if err := aper.ChargeValue(bb, tmp_global); err != nil {
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
func (v *PrivateIEID) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "PrivateIEID", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PrivateIEID) WithoutReplay() PrivateIEID {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero PrivateIEID
	v.perPadding = zero.perPadding
	return v
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *PrivateIEID) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PrivateIEID")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "PrivateIEID")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaPrivateIEID(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "PrivateIEID")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "PrivateIEID")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "PrivateIEID")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "PrivateIEID")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "PrivateIEID")
}
func (v *PrivateIEID) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *PrivateIEID) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *PrivateIEID) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *PrivateIEID) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *PrivateIEID) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *PrivateIEID) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PrivateIEID")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded PrivateIEID
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaPrivateIEID(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = PrivateIEID{}
		return report, aper.OperationError(err, "PrivateIEID")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PrivateIEID")
}

type PosSIBSegments = []PosSIBSegmentsElem

// PRSMutingConfiguration represents the ASN.1 CHOICE type PRSMutingConfiguration.
type PRSMutingConfiguration struct {
	knownOpenBytes           uint64
	replay                   aper.Snapshot
	stream                   aper.WireSpan
	withoutReplay            bool
	received                 bool
	receivedBytes            aper.WireSpan
	Choice                   int
	perPadding               aper.CompletePadding  `json:"-"`
	perOpenTypePadding       aper.CompletePadding  `json:"-"`
	UnknownExtension         *aper.ChoiceExtension `json:"UnknownExtension,omitempty"`
	Two                      *runtime.BitString    `json:"Two,omitempty"`
	Four                     *runtime.BitString    `json:"Four,omitempty"`
	Eight                    *runtime.BitString    `json:"Eight,omitempty"`
	Sixteen                  *runtime.BitString    `json:"Sixteen,omitempty"`
	ThirtyTwo                *runtime.BitString    `json:"ThirtyTwo,omitempty"`
	SixtyFour                *runtime.BitString    `json:"SixtyFour,omitempty"`
	OneHundredAndTwentyEight *runtime.BitString    `json:"OneHundredAndTwentyEight,omitempty"`
	TwoHundredAndFiftySix    *runtime.BitString    `json:"TwoHundredAndFiftySix,omitempty"`
	FiveHundredAndTwelve     *runtime.BitString    `json:"FiveHundredAndTwelve,omitempty"`
	OneThousandAndTwentyFour *runtime.BitString    `json:"OneThousandAndTwentyFour,omitempty"`
}

// PRSFrequencyHoppingConfiguration represents the ASN.1 type PRSFrequencyHoppingConfiguration (SEQUENCE).
type PRSFrequencyHoppingConfiguration struct {
	replay               aper.Snapshot
	stream               aper.WireSpan
	withoutReplay        bool
	received             bool
	receivedBytes        aper.WireSpan
	NoOfFreqHoppingBands s00.NumberOfFrequencyHoppingBands                       `asn1:"tag:0,context,implicit"`
	BandPositions        s00.PRSFrequencyHoppingConfigurationBandPositions       `asn1:"tag:1,context,implicit"`
	bandPositionsIndef   bool                                                    `asn1:"-" json:"-"`
	IEExtensions         s04.PRSFrequencyHoppingConfigurationItemIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef    bool                                                    `asn1:"-" json:"-"`
	extCount             int64                                                   `asn1:"-" json:"-"`
	extPresent           []bool                                                  `asn1:"-" json:"-"`
	extData              [][]byte                                                `asn1:"-" json:"-"`
	perPadding           aper.FinalPadding                                       `asn1:"-" json:"-"`
	perExtPadding        []aper.CompletePadding                                  `asn1:"-" json:"-"`
	extOrigin            []aper.OpaqueOrigin
	extWire              []aper.WireSpan
}

// RequestedSRSTransmissionCharacteristics represents the ASN.1 type RequestedSRSTransmissionCharacteristics (SEQUENCE).
type RequestedSRSTransmissionCharacteristics struct {
	replay                aper.Snapshot
	stream                aper.WireSpan
	withoutReplay         bool
	received              bool
	receivedBytes         aper.WireSpan
	NumberOfTransmissions *big.Int               `asn1:"tag:0,context,implicit"`
	Bandwidth             *big.Int               `asn1:"tag:1,context,implicit"`
	extCount              int64                  `asn1:"-" json:"-"`
	extPresent            []bool                 `asn1:"-" json:"-"`
	extData               [][]byte               `asn1:"-" json:"-"`
	perPadding            aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding         []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin             []aper.OpaqueOrigin
	extWire               []aper.WireSpan
}

// PosSIBSegmentsElem represents the ASN.1 type PosSIB-Segments-Elem (SEQUENCE).
type PosSIBSegmentsElem struct {
	replay                   aper.Snapshot
	stream                   aper.WireSpan
	withoutReplay            bool
	received                 bool
	receivedBytes            aper.WireSpan
	AssistanceDataSIBelement []byte                               `asn1:"tag:0,context,implicit"`
	IEExtensions             s04.PosSIBSegmentsExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef        bool                                 `asn1:"-" json:"-"`
	extCount                 int64                                `asn1:"-" json:"-"`
	extPresent               []bool                               `asn1:"-" json:"-"`
	extData                  [][]byte                             `asn1:"-" json:"-"`
	perPadding               aper.FinalPadding                    `asn1:"-" json:"-"`
	perExtPadding            []aper.CompletePadding               `asn1:"-" json:"-"`
	extOrigin                []aper.OpaqueOrigin
	extWire                  []aper.WireSpan
}

// ResultUTRANItemPhysCellIDUTRAN represents the ASN.1 CHOICE type ResultUTRAN-Item-physCellIDUTRAN.
type ResultUTRANItemPhysCellIDUTRAN struct {
	replay             aper.Snapshot
	stream             aper.WireSpan
	withoutReplay      bool
	received           bool
	receivedBytes      aper.WireSpan
	Choice             int
	perPadding         aper.CompletePadding  `json:"-"`
	perOpenTypePadding aper.CompletePadding  `json:"-"`
	PhysCellIDUTRAFDD  s00.PhysCellIDUTRAFDD `json:"PhysCellIDUTRAFDD,omitzero"`
	PhysCellIDUTRATDD  s00.PhysCellIDUTRATDD `json:"PhysCellIDUTRATDD,omitzero"`
}

// MarshalAPER encodes PRSMutingConfiguration to APER format.
func (v *PRSMutingConfiguration) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *PRSMutingConfiguration) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "PRSMutingConfiguration:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "PRSMutingConfiguration:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 6 {
			return fmt.Errorf("%s extension index %d is known to this schema", "PRSMutingConfiguration:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "PRSMutingConfiguration:", v.Choice)
	}
	isExtension := v.Choice > 4
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 4 {
			return fmt.Errorf("extension choice index outside root")
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-4-1)); err != nil {
			return err
		}
		inner := aper.NewBudgetBuffer(bb.Budget())
		switch v.Choice {
		case s00.PRSMutingConfigurationChoiceThirtyTwo:
			if v.ThirtyTwo == nil {
				return fmt.Errorf("choice alternative thirty-two is nil")
			}
			if err := aper.EncodeBitStringAligned(inner, v.ThirtyTwo.Bytes, v.ThirtyTwo.BitLength, 32, 32, true); err != nil {
				return fmt.Errorf("encoding thirty-two: %w", err)
			}
		case s00.PRSMutingConfigurationChoiceSixtyFour:
			if v.SixtyFour == nil {
				return fmt.Errorf("choice alternative sixty-four is nil")
			}
			if err := aper.EncodeBitStringAligned(inner, v.SixtyFour.Bytes, v.SixtyFour.BitLength, 64, 64, true); err != nil {
				return fmt.Errorf("encoding sixty-four: %w", err)
			}
		case s00.PRSMutingConfigurationChoiceOneHundredAndTwentyEight:
			if v.OneHundredAndTwentyEight == nil {
				return fmt.Errorf("choice alternative one-hundred-and-twenty-eight is nil")
			}
			if err := aper.EncodeBitStringAligned(inner, v.OneHundredAndTwentyEight.Bytes, v.OneHundredAndTwentyEight.BitLength, 128, 128, true); err != nil {
				return fmt.Errorf("encoding one-hundred-and-twenty-eight: %w", err)
			}
		case s00.PRSMutingConfigurationChoiceTwoHundredAndFiftySix:
			if v.TwoHundredAndFiftySix == nil {
				return fmt.Errorf("choice alternative two-hundred-and-fifty-six is nil")
			}
			if err := aper.EncodeBitStringAligned(inner, v.TwoHundredAndFiftySix.Bytes, v.TwoHundredAndFiftySix.BitLength, 256, 256, true); err != nil {
				return fmt.Errorf("encoding two-hundred-and-fifty-six: %w", err)
			}
		case s00.PRSMutingConfigurationChoiceFiveHundredAndTwelve:
			if v.FiveHundredAndTwelve == nil {
				return fmt.Errorf("choice alternative five-hundred-and-twelve is nil")
			}
			if err := aper.EncodeBitStringAligned(inner, v.FiveHundredAndTwelve.Bytes, v.FiveHundredAndTwelve.BitLength, 512, 512, true); err != nil {
				return fmt.Errorf("encoding five-hundred-and-twelve: %w", err)
			}
		case s00.PRSMutingConfigurationChoiceOneThousandAndTwentyFour:
			if v.OneThousandAndTwentyFour == nil {
				return fmt.Errorf("choice alternative one-thousand-and-twenty-four is nil")
			}
			if err := aper.EncodeBitStringAligned(inner, v.OneThousandAndTwentyFour.Bytes, v.OneThousandAndTwentyFour.BitLength, 1024, 1024, true); err != nil {
				return fmt.Errorf("encoding one-thousand-and-twenty-four: %w", err)
			}
		default:
			return fmt.Errorf("unknown PRSMutingConfiguration extension choice %d", v.Choice)
		}
		openBytes, err := inner.CompleteBytesWithPadding(v.perOpenTypePadding)
		if err != nil {
			return err
		}
		if err := aper.EncodeOpenTypeAligned(bb, openBytes); err != nil {
			return err
		}
		return nil
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 3); err != nil {
		return err
	}
	switch v.Choice {
	case s00.PRSMutingConfigurationChoiceTwo:
		if v.Two == nil {
			return fmt.Errorf("choice alternative two is nil")
		}
		if err := aper.EncodeBitStringAligned(bb, v.Two.Bytes, v.Two.BitLength, 2, 2, true); err != nil {
			return fmt.Errorf("encoding two: %w", err)
		}
	case s00.PRSMutingConfigurationChoiceFour:
		if v.Four == nil {
			return fmt.Errorf("choice alternative four is nil")
		}
		if err := aper.EncodeBitStringAligned(bb, v.Four.Bytes, v.Four.BitLength, 4, 4, true); err != nil {
			return fmt.Errorf("encoding four: %w", err)
		}
	case s00.PRSMutingConfigurationChoiceEight:
		if v.Eight == nil {
			return fmt.Errorf("choice alternative eight is nil")
		}
		if err := aper.EncodeBitStringAligned(bb, v.Eight.Bytes, v.Eight.BitLength, 8, 8, true); err != nil {
			return fmt.Errorf("encoding eight: %w", err)
		}
	case s00.PRSMutingConfigurationChoiceSixteen:
		if v.Sixteen == nil {
			return fmt.Errorf("choice alternative sixteen is nil")
		}
		if err := aper.EncodeBitStringAligned(bb, v.Sixteen.Bytes, v.Sixteen.BitLength, 16, 16, true); err != nil {
			return fmt.Errorf("encoding sixteen: %w", err)
		}
	default:
		return fmt.Errorf("unknown PRSMutingConfiguration choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes PRSMutingConfiguration from APER format.
func (v *PRSMutingConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PRSMutingConfiguration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PRSMutingConfiguration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PRSMutingConfiguration")
	}
	bb.EnterComponent("PRSMutingConfiguration")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PRSMutingConfiguration")
	}
	padding, err := aper.CaptureFinalBits(bb, "PRSMutingConfiguration")
	if err != nil {
		return runtime.WrapDecodePath(err, "PRSMutingConfiguration")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *PRSMutingConfiguration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PRSMutingConfiguration{}
	isExtension, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := aper.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := aper.DecodeChoiceExtensionAligned(bb, extIdx, 6)
		if extIdx < 6 {
			v.knownOpenBytes = max(v.knownOpenBytes, openExtension.ContentLength())
		}
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
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
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 4 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case s00.PRSMutingConfigurationChoiceThirtyTwo:
			extensionPath = "ThirtyTwo"
			bsBytes_thirtytwo, bsBitLen_thirtytwo, err := aper.DecodeBitStringAligned(inner, 32, 32, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "ThirtyTwo")
			}
			tmp_thirtytwo := runtime.BitString{Bytes: bsBytes_thirtytwo, BitLength: bsBitLen_thirtytwo}
			if err := aper.ChargeValue(inner, tmp_thirtytwo); err != nil {
				return err
			}
			v.ThirtyTwo = &tmp_thirtytwo
		case s00.PRSMutingConfigurationChoiceSixtyFour:
			extensionPath = "SixtyFour"
			bsBytes_sixtyfour, bsBitLen_sixtyfour, err := aper.DecodeBitStringAligned(inner, 64, 64, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "SixtyFour")
			}
			tmp_sixtyfour := runtime.BitString{Bytes: bsBytes_sixtyfour, BitLength: bsBitLen_sixtyfour}
			if err := aper.ChargeValue(inner, tmp_sixtyfour); err != nil {
				return err
			}
			v.SixtyFour = &tmp_sixtyfour
		case s00.PRSMutingConfigurationChoiceOneHundredAndTwentyEight:
			extensionPath = "OneHundredAndTwentyEight"
			bsBytes_onehundredandtwentyeight, bsBitLen_onehundredandtwentyeight, err := aper.DecodeBitStringAligned(inner, 128, 128, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "OneHundredAndTwentyEight")
			}
			tmp_onehundredandtwentyeight := runtime.BitString{Bytes: bsBytes_onehundredandtwentyeight, BitLength: bsBitLen_onehundredandtwentyeight}
			if err := aper.ChargeValue(inner, tmp_onehundredandtwentyeight); err != nil {
				return err
			}
			v.OneHundredAndTwentyEight = &tmp_onehundredandtwentyeight
		case s00.PRSMutingConfigurationChoiceTwoHundredAndFiftySix:
			extensionPath = "TwoHundredAndFiftySix"
			bsBytes_twohundredandfiftysix, bsBitLen_twohundredandfiftysix, err := aper.DecodeBitStringAligned(inner, 256, 256, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "TwoHundredAndFiftySix")
			}
			tmp_twohundredandfiftysix := runtime.BitString{Bytes: bsBytes_twohundredandfiftysix, BitLength: bsBitLen_twohundredandfiftysix}
			if err := aper.ChargeValue(inner, tmp_twohundredandfiftysix); err != nil {
				return err
			}
			v.TwoHundredAndFiftySix = &tmp_twohundredandfiftysix
		case s00.PRSMutingConfigurationChoiceFiveHundredAndTwelve:
			extensionPath = "FiveHundredAndTwelve"
			bsBytes_fivehundredandtwelve, bsBitLen_fivehundredandtwelve, err := aper.DecodeBitStringAligned(inner, 512, 512, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "FiveHundredAndTwelve")
			}
			tmp_fivehundredandtwelve := runtime.BitString{Bytes: bsBytes_fivehundredandtwelve, BitLength: bsBitLen_fivehundredandtwelve}
			if err := aper.ChargeValue(inner, tmp_fivehundredandtwelve); err != nil {
				return err
			}
			v.FiveHundredAndTwelve = &tmp_fivehundredandtwelve
		case s00.PRSMutingConfigurationChoiceOneThousandAndTwentyFour:
			extensionPath = "OneThousandAndTwentyFour"
			bsBytes_onethousandandtwentyfour, bsBitLen_onethousandandtwentyfour, err := aper.DecodeBitStringAligned(inner, 1024, 1024, true)
			if err != nil {
				return runtime.WrapDecodePath(err, "OneThousandAndTwentyFour")
			}
			tmp_onethousandandtwentyfour := runtime.BitString{Bytes: bsBytes_onethousandandtwentyfour, BitLength: bsBitLen_onethousandandtwentyfour}
			if err := aper.ChargeValue(inner, tmp_onethousandandtwentyfour); err != nil {
				return err
			}
			v.OneThousandAndTwentyFour = &tmp_onethousandandtwentyfour
		}
		paddingMark := inner.EnterComponent(extensionPath)
		padding, err := aper.CaptureOpenTypePadding(inner)
		inner.LeaveComponent(paddingMark)
		if err != nil {
			return runtime.WrapDecodePath(err, extensionPath)
		}
		v.perOpenTypePadding = padding
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
	case s00.PRSMutingConfigurationChoiceTwo:
		bsBytes_two, bsBitLen_two, err := aper.DecodeBitStringAligned(bb, 2, 2, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Two")
		}
		tmp_two := runtime.BitString{Bytes: bsBytes_two, BitLength: bsBitLen_two}
		if err := aper.ChargeValue(bb, tmp_two); err != nil {
			return err
		}
		v.Two = &tmp_two
	case s00.PRSMutingConfigurationChoiceFour:
		bsBytes_four, bsBitLen_four, err := aper.DecodeBitStringAligned(bb, 4, 4, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Four")
		}
		tmp_four := runtime.BitString{Bytes: bsBytes_four, BitLength: bsBitLen_four}
		if err := aper.ChargeValue(bb, tmp_four); err != nil {
			return err
		}
		v.Four = &tmp_four
	case s00.PRSMutingConfigurationChoiceEight:
		bsBytes_eight, bsBitLen_eight, err := aper.DecodeBitStringAligned(bb, 8, 8, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "Eight")
		}
		tmp_eight := runtime.BitString{Bytes: bsBytes_eight, BitLength: bsBitLen_eight}
		if err := aper.ChargeValue(bb, tmp_eight); err != nil {
			return err
		}
		v.Eight = &tmp_eight
	case s00.PRSMutingConfigurationChoiceSixteen:
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

// MarshalAPER encodes PRSFrequencyHoppingConfiguration to APER format.
func (v *PRSFrequencyHoppingConfiguration) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PRSFrequencyHoppingConfiguration) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

	recoveryStart := bb.BitsWritten()
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.NoOfFreqHoppingBands), 2, true); err != nil {
		return fmt.Errorf("encoding noOfFreqHoppingBands: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.BandPositions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 7, HasUpper: true}, true, func(fragmentOffset_bandpositions, fragmentLength_bandpositions int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_bandpositions < 0 || fragmentOffset_bandpositions > int64(len(v.BandPositions)) || fragmentLength_bandpositions < 0 || fragmentLength_bandpositions > int64(len(v.BandPositions[fragmentOffset_bandpositions:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.BandPositions[fragmentOffset_bandpositions : fragmentOffset_bandpositions+fragmentLength_bandpositions] {
			if err := aper.EncodeIntegerBigBoundsAligned(bb, elem, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound7, true); err != nil {
				return fmt.Errorf("encoding bandPositions element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding bandPositions: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s04.BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
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
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes PRSFrequencyHoppingConfiguration from APER format.
func (v *PRSFrequencyHoppingConfiguration) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PRSFrequencyHoppingConfiguration with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PRSFrequencyHoppingConfiguration) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PRSFrequencyHoppingConfiguration")
	}
	bb.EnterComponent("PRSFrequencyHoppingConfiguration")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PRSFrequencyHoppingConfiguration")
	}
	padding, err := aper.CaptureFinalBits(bb, "PRSFrequencyHoppingConfiguration")
	if err != nil {
		return runtime.WrapDecodePath(err, "PRSFrequencyHoppingConfiguration")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PRSFrequencyHoppingConfiguration) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PRSFrequencyHoppingConfiguration{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_nooffreqhoppingbands, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "NoOfFreqHoppingBands"})
	if err != nil {
		return runtime.WrapDecodePath(err, "NoOfFreqHoppingBands")
	}
	v.NoOfFreqHoppingBands = s00.NumberOfFrequencyHoppingBands(val_nooffreqhoppingbands)
	toleranceMark_bandpositions := bb.EnterComponent("BandPositions")
	v.BandPositions = make(s00.PRSFrequencyHoppingConfigurationBandPositions, 0)
	_, errCollection_bandpositions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 7, HasUpper: true}, true, func(fragmentOffset_bandpositions, fragmentLength_bandpositions int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_2: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1136
		if fragmentOffset_bandpositions < 0 || fragmentLength_bandpositions < 0 || fragmentLength_bandpositions > int64(^uint(0)>>1) || fragmentOffset_bandpositions > int64(^uint(0)>>1)-fragmentLength_bandpositions {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_bandpositions; i++ {
			val, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound7, true)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("BandPositions[%d]", fragmentOffset_bandpositions+i))
			}
			if next, err := aper.AppendValues(bb, v.BandPositions, val); err != nil {
				return err
			} else {
				v.BandPositions = next
			}
		}
		return nil
	})
	if errCollection_bandpositions != nil {
		return runtime.WrapDecodePath(errCollection_bandpositions, "BandPositions")
	}
	bb.LeaveComponent(toleranceMark_bandpositions)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s04.PRSFrequencyHoppingConfigurationItemIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s04.PRSFrequencyHoppingConfigurationItemIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s04.BridgePRSFrequencyHoppingConfigurationItemIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
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
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *RequestedSRSTransmissionCharacteristics) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

	recoveryStart := bb.BitsWritten()
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
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.NumberOfTransmissions, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound16, true); err != nil {
		return fmt.Errorf("encoding numberOfTransmissions: %w", err)
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.Bandwidth, s00.BridgeAsn1IntegerBound2, s00.BridgeAsn1IntegerBound3, true); err != nil {
		return fmt.Errorf("encoding bandwidth: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
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
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes RequestedSRSTransmissionCharacteristics from APER format.
func (v *RequestedSRSTransmissionCharacteristics) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes RequestedSRSTransmissionCharacteristics with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *RequestedSRSTransmissionCharacteristics) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "RequestedSRSTransmissionCharacteristics")
	}
	bb.EnterComponent("RequestedSRSTransmissionCharacteristics")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "RequestedSRSTransmissionCharacteristics")
	}
	padding, err := aper.CaptureFinalBits(bb, "RequestedSRSTransmissionCharacteristics")
	if err != nil {
		return runtime.WrapDecodePath(err, "RequestedSRSTransmissionCharacteristics")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *RequestedSRSTransmissionCharacteristics) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = RequestedSRSTransmissionCharacteristics{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_numberoftransmissions, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound16, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "NumberOfTransmissions")
	}
	v.NumberOfTransmissions = val_numberoftransmissions
	val_bandwidth, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound2, s00.BridgeAsn1IntegerBound3, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "Bandwidth")
	}
	v.Bandwidth = val_bandwidth
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
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
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *PosSIBSegmentsElem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

	recoveryStart := bb.BitsWritten()
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
	if err := aper.EncodeOctetStringAligned(bb, v.AssistanceDataSIBelement, 0, 0, false); err != nil {
		return fmt.Errorf("encoding assistanceDataSIBelement: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s04.BridgePosSIBSegmentsExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
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
	aper.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	aper.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes PosSIBSegmentsElem from APER format.
func (v *PosSIBSegmentsElem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PosSIBSegmentsElem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PosSIBSegmentsElem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PosSIBSegmentsElem")
	}
	bb.EnterComponent("PosSIBSegmentsElem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "PosSIBSegmentsElem")
	}
	padding, err := aper.CaptureFinalBits(bb, "PosSIBSegmentsElem")
	if err != nil {
		return runtime.WrapDecodePath(err, "PosSIBSegmentsElem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *PosSIBSegmentsElem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = PosSIBSegmentsElem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_assistancedatasibelement, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceDataSIBelement")
	}
	v.AssistanceDataSIBelement = val_assistancedatasibelement
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s04.PosSIBSegmentsExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s04.PosSIBSegmentsExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s04.BridgePosSIBSegmentsExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
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
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *ResultUTRANItemPhysCellIDUTRAN) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		return fmt.Errorf("%s choice %d must be positive", "ResultUTRANItemPhysCellIDUTRAN:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRAFDD:
		if err := aper.EncodeIntegerBigBoundsAligned(bb, v.PhysCellIDUTRAFDD, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound18, true); err != nil {
			return fmt.Errorf("encoding physCellIDUTRA-FDD: %w", err)
		}
	case s00.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRATDD:
		if err := aper.EncodeIntegerBigBoundsAligned(bb, v.PhysCellIDUTRATDD, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound5, true); err != nil {
			return fmt.Errorf("encoding physCellIDUTRA-TDD: %w", err)
		}
	default:
		return fmt.Errorf("unknown ResultUTRANItemPhysCellIDUTRAN choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes ResultUTRANItemPhysCellIDUTRAN from APER format.
func (v *ResultUTRANItemPhysCellIDUTRAN) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResultUTRANItemPhysCellIDUTRAN with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResultUTRANItemPhysCellIDUTRAN) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ResultUTRANItemPhysCellIDUTRAN")
	}
	bb.EnterComponent("ResultUTRANItemPhysCellIDUTRAN")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResultUTRANItemPhysCellIDUTRAN")
	}
	padding, err := aper.CaptureFinalBits(bb, "ResultUTRANItemPhysCellIDUTRAN")
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultUTRANItemPhysCellIDUTRAN")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *ResultUTRANItemPhysCellIDUTRAN) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultUTRANItemPhysCellIDUTRAN{}
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 1)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRAFDD:
		val_physcellidutrafdd, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound18, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "PhysCellIDUTRAFDD")
		}
		v.PhysCellIDUTRAFDD = val_physcellidutrafdd
	case s00.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRATDD:
		val_physcellidutratdd, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound5, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "PhysCellIDUTRATDD")
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
func (v *PRSFrequencyHoppingConfiguration) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "PRSFrequencyHoppingConfiguration", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PRSFrequencyHoppingConfiguration) WithoutReplay() PRSFrequencyHoppingConfiguration {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero PRSFrequencyHoppingConfiguration
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PRSMutingConfiguration) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "PRSMutingConfiguration", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PRSMutingConfiguration) WithoutReplay() PRSMutingConfiguration {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero PRSMutingConfiguration
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PosSIBSegmentsElem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "PosSIBSegmentsElem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PosSIBSegmentsElem) WithoutReplay() PosSIBSegmentsElem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero PosSIBSegmentsElem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *RequestedSRSTransmissionCharacteristics) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "RequestedSRSTransmissionCharacteristics", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v RequestedSRSTransmissionCharacteristics) WithoutReplay() RequestedSRSTransmissionCharacteristics {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero RequestedSRSTransmissionCharacteristics
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultUTRANItemPhysCellIDUTRAN) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultUTRANItemPhysCellIDUTRAN", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultUTRANItemPhysCellIDUTRAN) WithoutReplay() ResultUTRANItemPhysCellIDUTRAN {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ResultUTRANItemPhysCellIDUTRAN
	v.perPadding = zero.perPadding
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *PRSFrequencyHoppingConfiguration) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PRSFrequencyHoppingConfiguration) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PRSFrequencyHoppingConfiguration.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PRSFrequencyHoppingConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PRSFrequencyHoppingConfiguration) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PRSFrequencyHoppingConfiguration.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PRSFrequencyHoppingConfiguration.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *PosSIBSegmentsElem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *PosSIBSegmentsElem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PosSIBSegmentsElem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PosSIBSegmentsElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *PosSIBSegmentsElem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("PosSIBSegmentsElem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("PosSIBSegmentsElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *RequestedSRSTransmissionCharacteristics) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *RequestedSRSTransmissionCharacteristics) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RequestedSRSTransmissionCharacteristics.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RequestedSRSTransmissionCharacteristics.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *RequestedSRSTransmissionCharacteristics) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("RequestedSRSTransmissionCharacteristics.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("RequestedSRSTransmissionCharacteristics.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *PRSFrequencyHoppingConfiguration) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PRSFrequencyHoppingConfiguration")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "PRSFrequencyHoppingConfiguration")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaPRSFrequencyHoppingConfiguration(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "PRSFrequencyHoppingConfiguration")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "PRSFrequencyHoppingConfiguration")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "PRSFrequencyHoppingConfiguration")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "PRSFrequencyHoppingConfiguration")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "PRSFrequencyHoppingConfiguration")
}
func (v *PRSFrequencyHoppingConfiguration) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *PRSFrequencyHoppingConfiguration) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *PRSFrequencyHoppingConfiguration) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *PRSFrequencyHoppingConfiguration) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *PRSFrequencyHoppingConfiguration) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *PRSMutingConfiguration) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PRSMutingConfiguration")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "PRSMutingConfiguration")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaPRSMutingConfiguration(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "PRSMutingConfiguration")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "PRSMutingConfiguration")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "PRSMutingConfiguration")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "PRSMutingConfiguration")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "PRSMutingConfiguration")
}
func (v *PRSMutingConfiguration) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *PRSMutingConfiguration) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *PRSMutingConfiguration) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *PRSMutingConfiguration) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *PRSMutingConfiguration) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *PosSIBSegmentsElem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PosSIBSegmentsElem")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "PosSIBSegmentsElem")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaPosSIBSegmentsElem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "PosSIBSegmentsElem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "PosSIBSegmentsElem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "PosSIBSegmentsElem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "PosSIBSegmentsElem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "PosSIBSegmentsElem")
}
func (v *PosSIBSegmentsElem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *PosSIBSegmentsElem) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *PosSIBSegmentsElem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *PosSIBSegmentsElem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *PosSIBSegmentsElem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *RequestedSRSTransmissionCharacteristics) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "RequestedSRSTransmissionCharacteristics")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "RequestedSRSTransmissionCharacteristics")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaRequestedSRSTransmissionCharacteristics(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "RequestedSRSTransmissionCharacteristics")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "RequestedSRSTransmissionCharacteristics")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "RequestedSRSTransmissionCharacteristics")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "RequestedSRSTransmissionCharacteristics")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "RequestedSRSTransmissionCharacteristics")
}
func (v *RequestedSRSTransmissionCharacteristics) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *RequestedSRSTransmissionCharacteristics) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *RequestedSRSTransmissionCharacteristics) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *RequestedSRSTransmissionCharacteristics) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *RequestedSRSTransmissionCharacteristics) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ResultUTRANItemPhysCellIDUTRAN) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ResultUTRANItemPhysCellIDUTRAN")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ResultUTRANItemPhysCellIDUTRAN")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaResultUTRANItemPhysCellIDUTRAN(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ResultUTRANItemPhysCellIDUTRAN")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ResultUTRANItemPhysCellIDUTRAN")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ResultUTRANItemPhysCellIDUTRAN")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ResultUTRANItemPhysCellIDUTRAN")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ResultUTRANItemPhysCellIDUTRAN")
}
func (v *ResultUTRANItemPhysCellIDUTRAN) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultUTRANItemPhysCellIDUTRAN) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultUTRANItemPhysCellIDUTRAN) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *ResultUTRANItemPhysCellIDUTRAN) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultUTRANItemPhysCellIDUTRAN) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *PRSFrequencyHoppingConfiguration) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PRSFrequencyHoppingConfiguration")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded PRSFrequencyHoppingConfiguration
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaPRSFrequencyHoppingConfiguration(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = PRSFrequencyHoppingConfiguration{}
		return report, aper.OperationError(err, "PRSFrequencyHoppingConfiguration")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PRSFrequencyHoppingConfiguration")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *PRSMutingConfiguration) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PRSMutingConfiguration")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded PRSMutingConfiguration
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaPRSMutingConfiguration(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = PRSMutingConfiguration{}
		return report, aper.OperationError(err, "PRSMutingConfiguration")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PRSMutingConfiguration")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *PosSIBSegmentsElem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PosSIBSegmentsElem")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded PosSIBSegmentsElem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaPosSIBSegmentsElem(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = PosSIBSegmentsElem{}
		return report, aper.OperationError(err, "PosSIBSegmentsElem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PosSIBSegmentsElem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *RequestedSRSTransmissionCharacteristics) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "RequestedSRSTransmissionCharacteristics")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded RequestedSRSTransmissionCharacteristics
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaRequestedSRSTransmissionCharacteristics(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = RequestedSRSTransmissionCharacteristics{}
		return report, aper.OperationError(err, "RequestedSRSTransmissionCharacteristics")
	}
	*v = decoded
	return report, aper.OperationError(nil, "RequestedSRSTransmissionCharacteristics")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultUTRANItemPhysCellIDUTRAN) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ResultUTRANItemPhysCellIDUTRAN")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ResultUTRANItemPhysCellIDUTRAN
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultUTRANItemPhysCellIDUTRAN(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ResultUTRANItemPhysCellIDUTRAN{}
		return report, aper.OperationError(err, "ResultUTRANItemPhysCellIDUTRAN")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ResultUTRANItemPhysCellIDUTRAN")
}

// NewPRSMutingConfigurationUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewPRSMutingConfigurationUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (PRSMutingConfiguration, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationUnknownExtension")
	}
	value := PRSMutingConfiguration{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationUnknownExtension")
	}
	return value, aper.OperationError(nil, "PRSMutingConfigurationUnknownExtension")
}
func BridgeCaptureLPPaPRSFrequencyHoppingConfiguration(v *PRSFrequencyHoppingConfiguration, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaNumberOfFrequencyHoppingBands(&v.NoOfFreqHoppingBands, s)
	s00.BridgeCaptureLPPaPRSFrequencyHoppingConfigurationBandPositions(&v.BandPositions, s)
	s.Bool(v.IEExtensions == nil)
	s05.BridgePRSFrequencyHoppingConfigurationItemIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaPRSFrequencyHoppingConfiguration(v *PRSFrequencyHoppingConfiguration, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaNumberOfFrequencyHoppingBands(&v.NoOfFreqHoppingBands, s)
	s02.BridgeCompareLPPaPRSFrequencyHoppingConfigurationBandPositions(&v.BandPositions, s)
	s.Bool(v.IEExtensions == nil)
	s05.BridgePRSFrequencyHoppingConfigurationItemIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaPRSMutingConfiguration(v *PRSMutingConfiguration, s *aper.SemanticCapture) {
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
	case s00.PRSMutingConfigurationChoiceTwo:
		{
			f := s.Begin()
			s.Bool(v.Two == nil)
			if v.Two != nil {
				s.BitString((*v.Two).Bytes, (*v.Two).BitLength)
			}
			s.End(f, nil, false)
		}
	case s00.PRSMutingConfigurationChoiceFour:
		{
			f := s.Begin()
			s.Bool(v.Four == nil)
			if v.Four != nil {
				s.BitString((*v.Four).Bytes, (*v.Four).BitLength)
			}
			s.End(f, nil, false)
		}
	case s00.PRSMutingConfigurationChoiceEight:
		{
			f := s.Begin()
			s.Bool(v.Eight == nil)
			if v.Eight != nil {
				s.BitString((*v.Eight).Bytes, (*v.Eight).BitLength)
			}
			s.End(f, nil, false)
		}
	case s00.PRSMutingConfigurationChoiceSixteen:
		{
			f := s.Begin()
			s.Bool(v.Sixteen == nil)
			if v.Sixteen != nil {
				s.BitString((*v.Sixteen).Bytes, (*v.Sixteen).BitLength)
			}
			s.End(f, nil, false)
		}
	case s00.PRSMutingConfigurationChoiceThirtyTwo:
		{
			f := s.Begin()
			s.Bool(v.ThirtyTwo == nil)
			if v.ThirtyTwo != nil {
				s.BitString((*v.ThirtyTwo).Bytes, (*v.ThirtyTwo).BitLength)
			}
			s.End(f, nil, false)
		}
	case s00.PRSMutingConfigurationChoiceSixtyFour:
		{
			f := s.Begin()
			s.Bool(v.SixtyFour == nil)
			if v.SixtyFour != nil {
				s.BitString((*v.SixtyFour).Bytes, (*v.SixtyFour).BitLength)
			}
			s.End(f, nil, false)
		}
	case s00.PRSMutingConfigurationChoiceOneHundredAndTwentyEight:
		{
			f := s.Begin()
			s.Bool(v.OneHundredAndTwentyEight == nil)
			if v.OneHundredAndTwentyEight != nil {
				s.BitString((*v.OneHundredAndTwentyEight).Bytes, (*v.OneHundredAndTwentyEight).BitLength)
			}
			s.End(f, nil, false)
		}
	case s00.PRSMutingConfigurationChoiceTwoHundredAndFiftySix:
		{
			f := s.Begin()
			s.Bool(v.TwoHundredAndFiftySix == nil)
			if v.TwoHundredAndFiftySix != nil {
				s.BitString((*v.TwoHundredAndFiftySix).Bytes, (*v.TwoHundredAndFiftySix).BitLength)
			}
			s.End(f, nil, false)
		}
	case s00.PRSMutingConfigurationChoiceFiveHundredAndTwelve:
		{
			f := s.Begin()
			s.Bool(v.FiveHundredAndTwelve == nil)
			if v.FiveHundredAndTwelve != nil {
				s.BitString((*v.FiveHundredAndTwelve).Bytes, (*v.FiveHundredAndTwelve).BitLength)
			}
			s.End(f, nil, false)
		}
	case s00.PRSMutingConfigurationChoiceOneThousandAndTwentyFour:
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
func BridgeCompareLPPaPRSMutingConfiguration(v *PRSMutingConfiguration, s *aper.SemanticComparison) {
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
	case s00.PRSMutingConfigurationChoiceTwo:
		{
			f := s.Begin()
			s.Bool(v.Two == nil)
			if v.Two != nil {
				s.BitString((*v.Two).Bytes, (*v.Two).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.PRSMutingConfigurationChoiceFour:
		{
			f := s.Begin()
			s.Bool(v.Four == nil)
			if v.Four != nil {
				s.BitString((*v.Four).Bytes, (*v.Four).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.PRSMutingConfigurationChoiceEight:
		{
			f := s.Begin()
			s.Bool(v.Eight == nil)
			if v.Eight != nil {
				s.BitString((*v.Eight).Bytes, (*v.Eight).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.PRSMutingConfigurationChoiceSixteen:
		{
			f := s.Begin()
			s.Bool(v.Sixteen == nil)
			if v.Sixteen != nil {
				s.BitString((*v.Sixteen).Bytes, (*v.Sixteen).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.PRSMutingConfigurationChoiceThirtyTwo:
		{
			f := s.Begin()
			s.Bool(v.ThirtyTwo == nil)
			if v.ThirtyTwo != nil {
				s.BitString((*v.ThirtyTwo).Bytes, (*v.ThirtyTwo).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.PRSMutingConfigurationChoiceSixtyFour:
		{
			f := s.Begin()
			s.Bool(v.SixtyFour == nil)
			if v.SixtyFour != nil {
				s.BitString((*v.SixtyFour).Bytes, (*v.SixtyFour).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.PRSMutingConfigurationChoiceOneHundredAndTwentyEight:
		{
			f := s.Begin()
			s.Bool(v.OneHundredAndTwentyEight == nil)
			if v.OneHundredAndTwentyEight != nil {
				s.BitString((*v.OneHundredAndTwentyEight).Bytes, (*v.OneHundredAndTwentyEight).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.PRSMutingConfigurationChoiceTwoHundredAndFiftySix:
		{
			f := s.Begin()
			s.Bool(v.TwoHundredAndFiftySix == nil)
			if v.TwoHundredAndFiftySix != nil {
				s.BitString((*v.TwoHundredAndFiftySix).Bytes, (*v.TwoHundredAndFiftySix).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.PRSMutingConfigurationChoiceFiveHundredAndTwelve:
		{
			f := s.Begin()
			s.Bool(v.FiveHundredAndTwelve == nil)
			if v.FiveHundredAndTwelve != nil {
				s.BitString((*v.FiveHundredAndTwelve).Bytes, (*v.FiveHundredAndTwelve).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.PRSMutingConfigurationChoiceOneThousandAndTwentyFour:
		{
			f := s.Begin()
			s.Bool(v.OneThousandAndTwentyFour == nil)
			if v.OneThousandAndTwentyFour != nil {
				s.BitString((*v.OneThousandAndTwentyFour).Bytes, (*v.OneThousandAndTwentyFour).BitLength)
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaPosSIBSegmentsElem(v *PosSIBSegmentsElem, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s.Bytes(v.AssistanceDataSIBelement)
	s.Bool(v.IEExtensions == nil)
	s05.BridgePosSIBSegmentsExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaPosSIBSegmentsElem(v *PosSIBSegmentsElem, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

	s.Bytes(v.AssistanceDataSIBelement)
	s.Bool(v.IEExtensions == nil)
	s05.BridgePosSIBSegmentsExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaPrivateIEID(v *PrivateIEID, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s.Int(int64(v.Choice))
	switch v.Choice {
	case s00.PrivateIEIDChoiceLocal:
		{
			f := s.Begin()
			s.Bool(v.Local == nil)
			if v.Local != nil {
				s.Int(int64((*v.Local)))
			}
			s.End(f, nil, false)
		}
	case s00.PrivateIEIDChoiceGlobal:
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
func BridgeCompareLPPaPrivateIEID(v *PrivateIEID, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

	s.Int(int64(v.Choice))
	switch v.Choice {
	case s00.PrivateIEIDChoiceLocal:
		{
			f := s.Begin()
			s.Bool(v.Local == nil)
			if v.Local != nil {
				s.Int(int64((*v.Local)))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.PrivateIEIDChoiceGlobal:
		{
			f := s.Begin()
			s.Bool(v.Global == nil)
			if v.Global != nil {
				s.String((*v.Global).Encoded())
			}
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaPrivateMessageIEsValue(v *PrivateMessageIEsValue, s *aper.SemanticCapture) {
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
func (v PrivateMessageIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v PrivateMessageIEsValue) captureFraming() uint64 {
	if v.opaque == nil {
		return 0
	}
	return v.opaque.ContentLength()
}
func (v PrivateMessageIEsValue) captureSemantics(s aper.SemanticCapture) PrivateMessageIEsValue {
	BridgeCaptureLPPaPrivateMessageIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaPrivateMessageIEsValue(v *PrivateMessageIEsValue, s *aper.SemanticComparison) {
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
			s.End(f, aper.Snapshot{}, false)
		}
	}
	s.Bool(v.valid)
	s.End(f, v.replay, v.withoutReplay)
}
func (v PrivateMessageIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaPrivateMessageIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PrivateMessageIEsValue) WithoutReplay() PrivateMessageIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaRequestedSRSTransmissionCharacteristics(v *RequestedSRSTransmissionCharacteristics, s *aper.SemanticCapture) {
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
func BridgeCompareLPPaRequestedSRSTransmissionCharacteristics(v *RequestedSRSTransmissionCharacteristics, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

	{
		f := s.Begin()
		s.BigInt(v.NumberOfTransmissions)
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.BigInt(v.Bandwidth)
		s.End(f, aper.Snapshot{}, false)
	}
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultUTRANItemPhysCellIDUTRAN(v *ResultUTRANItemPhysCellIDUTRAN, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s.Int(int64(v.Choice))
	switch v.Choice {
	case s00.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRAFDD:
		s00.BridgeCaptureLPPaPhysCellIDUTRAFDD(&v.PhysCellIDUTRAFDD, s)
	case s00.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRATDD:
		s00.BridgeCaptureLPPaPhysCellIDUTRATDD(&v.PhysCellIDUTRATDD, s)
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultUTRANItemPhysCellIDUTRAN(v *ResultUTRANItemPhysCellIDUTRAN, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()

	s.Int(int64(v.Choice))
	switch v.Choice {
	case s00.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRAFDD:
		s02.BridgeCompareLPPaPhysCellIDUTRAFDD(&v.PhysCellIDUTRAFDD, s)
	case s00.ResultUTRANItemPhysCellIDUTRANChoicePhysCellIDUTRATDD:
		s02.BridgeCompareLPPaPhysCellIDUTRATDD(&v.PhysCellIDUTRATDD, s)
	}
	s.End(f, v.replay, v.withoutReplay)
}

type PrivateMessageIEsValue struct {
	withoutReplay bool
	replay        aper.Snapshot
	idChoice      int
	idLocal       int64
	idGlobal      string
	opaque        *aper.OpaqueOpenType
	valid         bool
}

// TS 36.455 V19.0.0 §9.3.8 binds the scalar or OID private identity.
func BridgePrivateValue(id PrivateIEID, raw *aper.OpaqueOpenType) PrivateMessageIEsValue {
	v := PrivateMessageIEsValue{idChoice: id.Choice, opaque: raw}
	switch id.Choice {
	case s00.PrivateIEIDChoiceLocal:
		if id.Local != nil {
			v.idLocal = *id.Local
			v.valid = true
		}
	case s00.PrivateIEIDChoiceGlobal:
		if id.Global != nil {
			v.idGlobal = id.Global.Encoded()
			v.valid = true
		}
	}
	return v
}
func (v PrivateMessageIEsValue) matchesID(id PrivateIEID, _ *aper.DecodeBudget) bool {
	if !v.valid || v.opaque == nil || v.idChoice != id.Choice {
		return false
	}
	switch id.Choice {
	case s00.PrivateIEIDChoiceLocal:
		return id.Local != nil && v.idLocal == *id.Local
	case s00.PrivateIEIDChoiceGlobal:
		return id.Global != nil && v.idGlobal == id.Global.Encoded()
	default:
		return false
	}
}
func (PrivateMessageIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "PrivateMessage-IEs"}}
}
func (PrivateMessageIEsValue) decode(id PrivateIEID, raw aper.OpaqueOpenType) (PrivateMessageIEsValue, error) {
	if err := raw.Observe(aper.UnknownIE); err != nil {
		return PrivateMessageIEsValue{}, err
	}
	retained, err := raw.Retained()
	if err != nil {
		return PrivateMessageIEsValue{}, err
	}
	return BridgePrivateValue(id, retained), nil
}
func (v PrivateMessageIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v PrivateMessageIEsValue) encodeFresh(_ bool, budget *aper.DecodeBudget) ([]byte, error) {
	if !v.valid || v.opaque == nil {
		return nil, fmt.Errorf("%s missing opaque value", "PrivateMessage-IEs:")
	}
	return v.opaque.EncodeBytes(budget)
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *PrivateMessageIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.valid || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}

type PrivateMessageIETable struct{}

func PrivateMessageIEs() PrivateMessageIETable { return PrivateMessageIETable{} }

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (PrivateMessageIETable) NewOpaque(id PrivateIEID, criticality s00.Criticality, data []byte) (PrivateMessageIEsValuePrivateIEField, error) {
	budget, err := aper.BuildBudget()
	if err != nil {
		return PrivateMessageIEsValuePrivateIEField{}, aper.OperationError(err, "Opaque")
	}
	if _, err := id.marshalAPERBudget(budget, true); err != nil {
		return PrivateMessageIEsValuePrivateIEField{}, aper.OperationError(err, "Opaque")
	}
	if criticality < 0 || criticality > 2 {
		return PrivateMessageIEsValuePrivateIEField{}, aper.OperationError(fmt.Errorf("invalid private IE criticality %d", criticality), "Opaque")
	}
	opaque, err := aper.BuildOpaqueOpenType(data, budget)
	if err != nil {
		return PrivateMessageIEsValuePrivateIEField{}, aper.OperationError(err, "Opaque")
	}
	retained, err := opaque.Retained(budget)
	if err != nil {
		return PrivateMessageIEsValuePrivateIEField{}, aper.OperationError(err, "Opaque")
	}
	return PrivateMessageIEsValuePrivateIEField{Id: id, Criticality: criticality, Value: BridgePrivateValue(id, retained)}, aper.OperationError(nil, "Opaque")
}

// PRSFrequencyHoppingConfigurationCodec binds the complete source value type.
func PRSFrequencyHoppingConfigurationCodec() PRSFrequencyHoppingConfigurationValueCodec {
	return PRSFrequencyHoppingConfigurationValueCodec{path: "PRSFrequencyHoppingConfiguration", decode: func(data []byte, options aper.DecodeState) (PRSFrequencyHoppingConfiguration, error) {
		var value PRSFrequencyHoppingConfiguration
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return PRSFrequencyHoppingConfiguration{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value PRSFrequencyHoppingConfiguration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v PRSFrequencyHoppingConfiguration, options aper.DecodeState) (PRSFrequencyHoppingConfiguration, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaPRSFrequencyHoppingConfiguration(&v, &s)
		var root aper.Snapshot

		s.OperationCounts()
		s.End(f, &root, false)

		return v, root
	}, compare: func(v PRSFrequencyHoppingConfiguration, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaPRSFrequencyHoppingConfiguration(&v, &s)
		s.End(f, root,

			false,
		)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PRSFrequencyHoppingConfiguration"
		return sealed
	}(),
	}
}

// PRSMutingConfigurationCodec binds the complete source value type.
func PRSMutingConfigurationCodec() PRSMutingConfigurationValueCodec {
	return PRSMutingConfigurationValueCodec{path: "PRSMutingConfiguration", decode: func(data []byte, options aper.DecodeState) (PRSMutingConfiguration, error) {
		var value PRSMutingConfiguration
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return PRSMutingConfiguration{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value PRSMutingConfiguration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v PRSMutingConfiguration, options aper.DecodeState) (PRSMutingConfiguration, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaPRSMutingConfiguration(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v PRSMutingConfiguration, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaPRSMutingConfiguration(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PRSMutingConfiguration"
		return sealed
	}(),
	}
}

// PosSIBSegmentsElemCodec binds the complete source value type.
func PosSIBSegmentsElemCodec() PosSIBSegmentsElemValueCodec {
	return PosSIBSegmentsElemValueCodec{path: "PosSIBSegmentsElem", decode: func(data []byte, options aper.DecodeState) (PosSIBSegmentsElem, error) {
		var value PosSIBSegmentsElem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return PosSIBSegmentsElem{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value PosSIBSegmentsElem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v PosSIBSegmentsElem, options aper.DecodeState) (PosSIBSegmentsElem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaPosSIBSegmentsElem(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f,
			&root,
			false)
		return v, root
	}, compare: func(v PosSIBSegmentsElem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaPosSIBSegmentsElem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PosSIBSegmentsElem"
		return sealed
	}(),
	}
}

// PrivateIEIDCodec binds the complete source value type.
func PrivateIEIDCodec() PrivateIEIDValueCodec {
	return PrivateIEIDValueCodec{path: "PrivateIEID", decode: func(data []byte, options aper.DecodeState) (PrivateIEID, error) {
		var value PrivateIEID
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return PrivateIEID{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value PrivateIEID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v PrivateIEID, options aper.DecodeState) (PrivateIEID, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaPrivateIEID(&v, &s)
		var root aper.Snapshot

		s.OperationCounts()
		s.End(f, &root, false)
		return v,
			root
	}, compare: func(v PrivateIEID, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaPrivateIEID(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PrivateIEID"
		return sealed
	}(),
	}
}

// ResultUTRANItemPhysCellIDUTRANCodec binds the complete source value type.
func ResultUTRANItemPhysCellIDUTRANCodec() ResultUTRANItemPhysCellIDUTRANValueCodec {
	return ResultUTRANItemPhysCellIDUTRANValueCodec{path: "ResultUTRANItemPhysCellIDUTRAN", decode: func(data []byte, options aper.DecodeState) (ResultUTRANItemPhysCellIDUTRAN, error) {
		var value ResultUTRANItemPhysCellIDUTRAN
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ResultUTRANItemPhysCellIDUTRAN{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ResultUTRANItemPhysCellIDUTRAN, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ResultUTRANItemPhysCellIDUTRAN, options aper.DecodeState) (ResultUTRANItemPhysCellIDUTRAN, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaResultUTRANItemPhysCellIDUTRAN(&v, &s)
		var root aper.Snapshot

		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResultUTRANItemPhysCellIDUTRAN, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaResultUTRANItemPhysCellIDUTRAN(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ResultUTRANItemPhysCellIDUTRAN"
		return sealed
	}(),
	}
}
func BridgeOTDOAInformationTypeValueCodecFieldCapture(v *OTDOAInformationTypeValueCodec) *func(s07.OTDOAInformationType, aper.DecodeState) (s07.OTDOAInformationType, aper.Snapshot) {
	return &v.capture
}
func BridgeOTDOAInformationTypeValueCodecFieldCompare(v *OTDOAInformationTypeValueCodec) *func(s07.OTDOAInformationType, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeOTDOAInformationTypeValueCodecFieldContext(v *OTDOAInformationTypeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeOTDOAInformationTypeValueCodecFieldDecode(v *OTDOAInformationTypeValueCodec) *func([]byte, aper.DecodeState) (s07.OTDOAInformationType, error) {
	return &v.decode
}
func BridgeOTDOAInformationTypeValueCodecFieldEncode(v *OTDOAInformationTypeValueCodec) *func(s07.OTDOAInformationType, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeOTDOAInformationTypeValueCodecFieldPath(v *OTDOAInformationTypeValueCodec) *aper.Path {
	return &v.path
}
func BridgeOTDOAInformationTypeValueCodecMethodEncodeBudget(v OTDOAInformationTypeValueCodec, a0 s07.OTDOAInformationType, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeOTDOAInformationTypeValueCodecMethodEncodeChanged(v OTDOAInformationTypeValueCodec, a0 s07.OTDOAInformationType, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePRSFrequencyHoppingConfigurationAPERValueFieldContext(v *PRSFrequencyHoppingConfigurationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePRSFrequencyHoppingConfigurationAPERValueFieldReceived(v *PRSFrequencyHoppingConfigurationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePRSFrequencyHoppingConfigurationAPERValueFieldReplay(v *PRSFrequencyHoppingConfigurationAPERValue) *aper.Snapshot {
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
func BridgePRSFrequencyHoppingConfigurationFieldExtOrigin(v *PRSFrequencyHoppingConfiguration) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgePRSFrequencyHoppingConfigurationFieldExtPresent(v *PRSFrequencyHoppingConfiguration) *[]bool {
	return &v.extPresent
}
func BridgePRSFrequencyHoppingConfigurationFieldExtWire(v *PRSFrequencyHoppingConfiguration) *[]aper.WireSpan {
	return &v.extWire
}
func BridgePRSFrequencyHoppingConfigurationFieldIEExtensionsIndef(v *PRSFrequencyHoppingConfiguration) *bool {
	return &v.iEExtensionsIndef
}
func BridgePRSFrequencyHoppingConfigurationFieldPerExtPadding(v *PRSFrequencyHoppingConfiguration) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgePRSFrequencyHoppingConfigurationFieldPerPadding(v *PRSFrequencyHoppingConfiguration) *aper.FinalPadding {
	return &v.perPadding
}
func BridgePRSFrequencyHoppingConfigurationFieldReceived(v *PRSFrequencyHoppingConfiguration) *bool {
	return &v.received
}
func BridgePRSFrequencyHoppingConfigurationFieldReceivedBytes(v *PRSFrequencyHoppingConfiguration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePRSFrequencyHoppingConfigurationFieldReplay(v *PRSFrequencyHoppingConfiguration) *aper.Snapshot {
	return &v.replay
}
func BridgePRSFrequencyHoppingConfigurationFieldStream(v *PRSFrequencyHoppingConfiguration) *aper.WireSpan {
	return &v.stream
}
func BridgePRSFrequencyHoppingConfigurationFieldWithoutReplay(v *PRSFrequencyHoppingConfiguration) *bool {
	return &v.withoutReplay
}
func BridgePRSFrequencyHoppingConfigurationMethodMarshalAPERBudget(v *PRSFrequencyHoppingConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationMethodMarshalAPERChanged(v *PRSFrequencyHoppingConfiguration, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePRSFrequencyHoppingConfigurationMethodMarshalAPERChangedValue(v *PRSFrequencyHoppingConfiguration, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePRSFrequencyHoppingConfigurationMethodMarshalAPERFreshValue(v *PRSFrequencyHoppingConfiguration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationMethodMarshalAPERLegacy(v *PRSFrequencyHoppingConfiguration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePRSFrequencyHoppingConfigurationMethodMarshalAPERPlanned(v *PRSFrequencyHoppingConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationMethodMarshalAPERTo(v *PRSFrequencyHoppingConfiguration, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePRSFrequencyHoppingConfigurationMethodUnmarshalAPERFrom(v *PRSFrequencyHoppingConfiguration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePRSFrequencyHoppingConfigurationMethodUnmarshalAPERLegacy(v *PRSFrequencyHoppingConfiguration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePRSFrequencyHoppingConfigurationMethodUnmarshalAPERWithOptions(v *PRSFrequencyHoppingConfiguration, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationValueCodecFieldCapture(v *PRSFrequencyHoppingConfigurationValueCodec) *func(PRSFrequencyHoppingConfiguration, aper.DecodeState) (PRSFrequencyHoppingConfiguration, aper.Snapshot) {
	return &v.capture
}
func BridgePRSFrequencyHoppingConfigurationValueCodecFieldCompare(v *PRSFrequencyHoppingConfigurationValueCodec) *func(PRSFrequencyHoppingConfiguration, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePRSFrequencyHoppingConfigurationValueCodecFieldContext(v *PRSFrequencyHoppingConfigurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePRSFrequencyHoppingConfigurationValueCodecFieldDecode(v *PRSFrequencyHoppingConfigurationValueCodec) *func([]byte, aper.DecodeState) (PRSFrequencyHoppingConfiguration, error) {
	return &v.decode
}
func BridgePRSFrequencyHoppingConfigurationValueCodecFieldEncode(v *PRSFrequencyHoppingConfigurationValueCodec) *func(PRSFrequencyHoppingConfiguration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePRSFrequencyHoppingConfigurationValueCodecFieldPath(v *PRSFrequencyHoppingConfigurationValueCodec) *aper.Path {
	return &v.path
}
func BridgePRSFrequencyHoppingConfigurationValueCodecMethodEncodeBudget(v PRSFrequencyHoppingConfigurationValueCodec, a0 PRSFrequencyHoppingConfiguration, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePRSFrequencyHoppingConfigurationValueCodecMethodEncodeChanged(v PRSFrequencyHoppingConfigurationValueCodec, a0 PRSFrequencyHoppingConfiguration, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePRSMutingConfigurationAPERValueFieldContext(v *PRSMutingConfigurationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePRSMutingConfigurationAPERValueFieldReceived(v *PRSMutingConfigurationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePRSMutingConfigurationAPERValueFieldReplay(v *PRSMutingConfigurationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePRSMutingConfigurationAPERValueFieldWithoutReplay(v *PRSMutingConfigurationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePRSMutingConfigurationFieldKnownOpenBytes(v *PRSMutingConfiguration) *uint64 {
	return &v.knownOpenBytes
}
func BridgePRSMutingConfigurationFieldPerOpenTypePadding(v *PRSMutingConfiguration) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgePRSMutingConfigurationFieldPerPadding(v *PRSMutingConfiguration) *aper.CompletePadding {
	return &v.perPadding
}
func BridgePRSMutingConfigurationFieldReceived(v *PRSMutingConfiguration) *bool { return &v.received }
func BridgePRSMutingConfigurationFieldReceivedBytes(v *PRSMutingConfiguration) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePRSMutingConfigurationFieldReplay(v *PRSMutingConfiguration) *aper.Snapshot {
	return &v.replay
}
func BridgePRSMutingConfigurationFieldStream(v *PRSMutingConfiguration) *aper.WireSpan {
	return &v.stream
}
func BridgePRSMutingConfigurationFieldWithoutReplay(v *PRSMutingConfiguration) *bool {
	return &v.withoutReplay
}
func BridgePRSMutingConfigurationMethodMarshalAPERBudget(v *PRSMutingConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePRSMutingConfigurationMethodMarshalAPERChanged(v *PRSMutingConfiguration, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePRSMutingConfigurationMethodMarshalAPERChangedValue(v *PRSMutingConfiguration, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePRSMutingConfigurationMethodMarshalAPERFreshValue(v *PRSMutingConfiguration, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgePRSMutingConfigurationMethodMarshalAPERLegacy(v *PRSMutingConfiguration) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePRSMutingConfigurationMethodMarshalAPERPlanned(v *PRSMutingConfiguration, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgePRSMutingConfigurationMethodMarshalAPERTo(v *PRSMutingConfiguration, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePRSMutingConfigurationMethodUnmarshalAPERFrom(v *PRSMutingConfiguration, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePRSMutingConfigurationMethodUnmarshalAPERLegacy(v *PRSMutingConfiguration, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePRSMutingConfigurationMethodUnmarshalAPERWithOptions(v *PRSMutingConfiguration, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePRSMutingConfigurationValueCodecFieldCapture(v *PRSMutingConfigurationValueCodec) *func(PRSMutingConfiguration, aper.DecodeState) (PRSMutingConfiguration, aper.Snapshot) {
	return &v.capture
}
func BridgePRSMutingConfigurationValueCodecFieldCompare(v *PRSMutingConfigurationValueCodec) *func(PRSMutingConfiguration, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePRSMutingConfigurationValueCodecFieldContext(v *PRSMutingConfigurationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePRSMutingConfigurationValueCodecFieldDecode(v *PRSMutingConfigurationValueCodec) *func([]byte, aper.DecodeState) (PRSMutingConfiguration, error) {
	return &v.decode
}
func BridgePRSMutingConfigurationValueCodecFieldEncode(v *PRSMutingConfigurationValueCodec) *func(PRSMutingConfiguration, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePRSMutingConfigurationValueCodecFieldPath(v *PRSMutingConfigurationValueCodec) *aper.Path {
	return &v.path
}
func BridgePRSMutingConfigurationValueCodecMethodEncodeBudget(v PRSMutingConfigurationValueCodec, a0 PRSMutingConfiguration, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePRSMutingConfigurationValueCodecMethodEncodeChanged(v PRSMutingConfigurationValueCodec, a0 PRSMutingConfiguration, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePosSIBSegmentsAPERValueFieldContext(v *PosSIBSegmentsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBSegmentsAPERValueFieldReceived(v *PosSIBSegmentsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePosSIBSegmentsAPERValueFieldReplay(v *PosSIBSegmentsAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePosSIBSegmentsAPERValueFieldWithoutReplay(v *PosSIBSegmentsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePosSIBSegmentsElemAPERValueFieldContext(v *PosSIBSegmentsElemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBSegmentsElemAPERValueFieldReceived(v *PosSIBSegmentsElemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePosSIBSegmentsElemAPERValueFieldReplay(v *PosSIBSegmentsElemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgePosSIBSegmentsElemAPERValueFieldWithoutReplay(v *PosSIBSegmentsElemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePosSIBSegmentsElemFieldExtCount(v *PosSIBSegmentsElem) *int64   { return &v.extCount }
func BridgePosSIBSegmentsElemFieldExtData(v *PosSIBSegmentsElem) *[][]byte { return &v.extData }
func BridgePosSIBSegmentsElemFieldExtOrigin(v *PosSIBSegmentsElem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgePosSIBSegmentsElemFieldExtPresent(v *PosSIBSegmentsElem) *[]bool       { return &v.extPresent }
func BridgePosSIBSegmentsElemFieldExtWire(v *PosSIBSegmentsElem) *[]aper.WireSpan { return &v.extWire }
func BridgePosSIBSegmentsElemFieldIEExtensionsIndef(v *PosSIBSegmentsElem) *bool {
	return &v.iEExtensionsIndef
}
func BridgePosSIBSegmentsElemFieldPerExtPadding(v *PosSIBSegmentsElem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgePosSIBSegmentsElemFieldPerPadding(v *PosSIBSegmentsElem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgePosSIBSegmentsElemFieldReceived(v *PosSIBSegmentsElem) *bool { return &v.received }
func BridgePosSIBSegmentsElemFieldReceivedBytes(v *PosSIBSegmentsElem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePosSIBSegmentsElemFieldReplay(v *PosSIBSegmentsElem) *aper.Snapshot { return &v.replay }
func BridgePosSIBSegmentsElemFieldStream(v *PosSIBSegmentsElem) *aper.WireSpan { return &v.stream }
func BridgePosSIBSegmentsElemFieldWithoutReplay(v *PosSIBSegmentsElem) *bool   { return &v.withoutReplay }
func BridgePosSIBSegmentsElemMethodMarshalAPERBudget(v *PosSIBSegmentsElem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePosSIBSegmentsElemMethodMarshalAPERChanged(v *PosSIBSegmentsElem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePosSIBSegmentsElemMethodMarshalAPERChangedValue(v *PosSIBSegmentsElem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePosSIBSegmentsElemMethodMarshalAPERFreshValue(v *PosSIBSegmentsElem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgePosSIBSegmentsElemMethodMarshalAPERLegacy(v *PosSIBSegmentsElem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePosSIBSegmentsElemMethodMarshalAPERPlanned(v *PosSIBSegmentsElem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgePosSIBSegmentsElemMethodMarshalAPERTo(v *PosSIBSegmentsElem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePosSIBSegmentsElemMethodUnmarshalAPERFrom(v *PosSIBSegmentsElem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePosSIBSegmentsElemMethodUnmarshalAPERLegacy(v *PosSIBSegmentsElem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePosSIBSegmentsElemMethodUnmarshalAPERWithOptions(v *PosSIBSegmentsElem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePosSIBSegmentsElemValueCodecFieldCapture(v *PosSIBSegmentsElemValueCodec) *func(PosSIBSegmentsElem, aper.DecodeState) (PosSIBSegmentsElem, aper.Snapshot) {
	return &v.capture
}
func BridgePosSIBSegmentsElemValueCodecFieldCompare(v *PosSIBSegmentsElemValueCodec) *func(PosSIBSegmentsElem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePosSIBSegmentsElemValueCodecFieldContext(v *PosSIBSegmentsElemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBSegmentsElemValueCodecFieldDecode(v *PosSIBSegmentsElemValueCodec) *func([]byte, aper.DecodeState) (PosSIBSegmentsElem, error) {
	return &v.decode
}
func BridgePosSIBSegmentsElemValueCodecFieldEncode(v *PosSIBSegmentsElemValueCodec) *func(PosSIBSegmentsElem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePosSIBSegmentsElemValueCodecFieldPath(v *PosSIBSegmentsElemValueCodec) *aper.Path {
	return &v.path
}
func BridgePosSIBSegmentsElemValueCodecMethodEncodeBudget(v PosSIBSegmentsElemValueCodec, a0 PosSIBSegmentsElem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePosSIBSegmentsElemValueCodecMethodEncodeChanged(v PosSIBSegmentsElemValueCodec, a0 PosSIBSegmentsElem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePosSIBSegmentsValueCodecFieldCapture(v *PosSIBSegmentsValueCodec) *func(PosSIBSegments, aper.DecodeState) (PosSIBSegments, aper.Snapshot) {
	return &v.capture
}
func BridgePosSIBSegmentsValueCodecFieldCompare(v *PosSIBSegmentsValueCodec) *func(PosSIBSegments, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePosSIBSegmentsValueCodecFieldContext(v *PosSIBSegmentsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePosSIBSegmentsValueCodecFieldDecode(v *PosSIBSegmentsValueCodec) *func([]byte, aper.DecodeState) (PosSIBSegments, error) {
	return &v.decode
}
func BridgePosSIBSegmentsValueCodecFieldEncode(v *PosSIBSegmentsValueCodec) *func(PosSIBSegments, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePosSIBSegmentsValueCodecFieldPath(v *PosSIBSegmentsValueCodec) *aper.Path { return &v.path }
func BridgePosSIBSegmentsValueCodecMethodEncodeBudget(v PosSIBSegmentsValueCodec, a0 PosSIBSegments, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePosSIBSegmentsValueCodecMethodEncodeChanged(v PosSIBSegmentsValueCodec, a0 PosSIBSegments, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePrivateIEIDAPERValueFieldContext(v *PrivateIEIDAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePrivateIEIDAPERValueFieldReceived(v *PrivateIEIDAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgePrivateIEIDAPERValueFieldReplay(v *PrivateIEIDAPERValue) *aper.Snapshot { return &v.replay }
func BridgePrivateIEIDAPERValueFieldWithoutReplay(v *PrivateIEIDAPERValue) *bool {
	return &v.withoutReplay
}
func BridgePrivateIEIDFieldPerOpenTypePadding(v *PrivateIEID) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgePrivateIEIDFieldPerPadding(v *PrivateIEID) *aper.CompletePadding { return &v.perPadding }
func BridgePrivateIEIDFieldReceived(v *PrivateIEID) *bool                   { return &v.received }
func BridgePrivateIEIDFieldReceivedBytes(v *PrivateIEID) *aper.WireSpan     { return &v.receivedBytes }
func BridgePrivateIEIDFieldReplay(v *PrivateIEID) *aper.Snapshot            { return &v.replay }
func BridgePrivateIEIDFieldStream(v *PrivateIEID) *aper.WireSpan            { return &v.stream }
func BridgePrivateIEIDFieldWithoutReplay(v *PrivateIEID) *bool              { return &v.withoutReplay }
func BridgePrivateIEIDMethodMarshalAPERBudget(v *PrivateIEID, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePrivateIEIDMethodMarshalAPERChanged(v *PrivateIEID, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePrivateIEIDMethodMarshalAPERChangedValue(v *PrivateIEID, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePrivateIEIDMethodMarshalAPERFreshValue(v *PrivateIEID, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgePrivateIEIDMethodMarshalAPERLegacy(v *PrivateIEID) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePrivateIEIDMethodMarshalAPERPlanned(v *PrivateIEID, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgePrivateIEIDMethodMarshalAPERTo(v *PrivateIEID, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePrivateIEIDMethodUnmarshalAPERFrom(v *PrivateIEID, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgePrivateIEIDMethodUnmarshalAPERLegacy(v *PrivateIEID, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePrivateIEIDMethodUnmarshalAPERWithOptions(v *PrivateIEID, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePrivateIEIDValueCodecFieldCapture(v *PrivateIEIDValueCodec) *func(PrivateIEID, aper.DecodeState) (PrivateIEID, aper.Snapshot) {
	return &v.capture
}
func BridgePrivateIEIDValueCodecFieldCompare(v *PrivateIEIDValueCodec) *func(PrivateIEID, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgePrivateIEIDValueCodecFieldContext(v *PrivateIEIDValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgePrivateIEIDValueCodecFieldDecode(v *PrivateIEIDValueCodec) *func([]byte, aper.DecodeState) (PrivateIEID, error) {
	return &v.decode
}
func BridgePrivateIEIDValueCodecFieldEncode(v *PrivateIEIDValueCodec) *func(PrivateIEID, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgePrivateIEIDValueCodecFieldPath(v *PrivateIEIDValueCodec) *aper.Path { return &v.path }
func BridgePrivateIEIDValueCodecMethodEncodeBudget(v PrivateIEIDValueCodec, a0 PrivateIEID, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgePrivateIEIDValueCodecMethodEncodeChanged(v PrivateIEIDValueCodec, a0 PrivateIEID, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgePrivateMessageIEsValueFieldIdChoice(v *PrivateMessageIEsValue) *int    { return &v.idChoice }
func BridgePrivateMessageIEsValueFieldIdGlobal(v *PrivateMessageIEsValue) *string { return &v.idGlobal }
func BridgePrivateMessageIEsValueFieldIdLocal(v *PrivateMessageIEsValue) *int64   { return &v.idLocal }
func BridgePrivateMessageIEsValueFieldOpaque(v *PrivateMessageIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgePrivateMessageIEsValueFieldReplay(v *PrivateMessageIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgePrivateMessageIEsValueFieldValid(v *PrivateMessageIEsValue) *bool { return &v.valid }
func BridgePrivateMessageIEsValueFieldWithoutReplay(v *PrivateMessageIEsValue) *bool {
	return &v.withoutReplay
}
func BridgePrivateMessageIEsValueMethodCaptureFraming(v PrivateMessageIEsValue) uint64 {
	return v.captureFraming()
}
func BridgePrivateMessageIEsValueMethodCaptureSemantics(v PrivateMessageIEsValue, a0 aper.SemanticCapture) PrivateMessageIEsValue {
	return v.captureSemantics(a0)
}
func BridgePrivateMessageIEsValueMethodCaptureSnapshot(v PrivateMessageIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgePrivateMessageIEsValueMethodCompareSemantics(v PrivateMessageIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgePrivateMessageIEsValueMethodDecode(v PrivateMessageIEsValue, a0 PrivateIEID, a1 aper.OpaqueOpenType) (PrivateMessageIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgePrivateMessageIEsValueMethodEncode(v PrivateMessageIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgePrivateMessageIEsValueMethodEncodeFresh(v PrivateMessageIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgePrivateMessageIEsValueMethodMatchesID(v PrivateMessageIEsValue, a0 PrivateIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgePrivateMessageIEsValueMethodRule(v PrivateMessageIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgePrivateMessageIEsValuePrivateIEFieldFieldReceived(v *PrivateMessageIEsValuePrivateIEField) *aper.CompletePadding {
	return &v.received
}
func BridgePrivateMessageIEsValuePrivateIEFieldFieldReplay(v *PrivateMessageIEsValuePrivateIEField) *aper.Snapshot {
	return &v.replay
}
func BridgePrivateMessageIEsValuePrivateIEFieldFieldStream(v *PrivateMessageIEsValuePrivateIEField) *aper.WireSpan {
	return &v.stream
}
func BridgePrivateMessageIEsValuePrivateIEFieldFieldWithoutReplay(v *PrivateMessageIEsValuePrivateIEField) *bool {
	return &v.withoutReplay
}
func BridgePrivateMessageIEsValuePrivateIEFieldMethodMarshalAPERTo(v *PrivateMessageIEsValuePrivateIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgePrivateMessageIEsValuePrivateIEFieldMethodUnmarshalAPERFrom(v *PrivateMessageIEsValuePrivateIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRequestedSRSTransmissionCharacteristicsAPERValueFieldContext(v *RequestedSRSTransmissionCharacteristicsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRequestedSRSTransmissionCharacteristicsAPERValueFieldReceived(v *RequestedSRSTransmissionCharacteristicsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeRequestedSRSTransmissionCharacteristicsAPERValueFieldReplay(v *RequestedSRSTransmissionCharacteristicsAPERValue) *aper.Snapshot {
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
func BridgeRequestedSRSTransmissionCharacteristicsFieldExtOrigin(v *RequestedSRSTransmissionCharacteristics) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldExtPresent(v *RequestedSRSTransmissionCharacteristics) *[]bool {
	return &v.extPresent
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldExtWire(v *RequestedSRSTransmissionCharacteristics) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldPerExtPadding(v *RequestedSRSTransmissionCharacteristics) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldPerPadding(v *RequestedSRSTransmissionCharacteristics) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldReceived(v *RequestedSRSTransmissionCharacteristics) *bool {
	return &v.received
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldReceivedBytes(v *RequestedSRSTransmissionCharacteristics) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldReplay(v *RequestedSRSTransmissionCharacteristics) *aper.Snapshot {
	return &v.replay
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldStream(v *RequestedSRSTransmissionCharacteristics) *aper.WireSpan {
	return &v.stream
}
func BridgeRequestedSRSTransmissionCharacteristicsFieldWithoutReplay(v *RequestedSRSTransmissionCharacteristics) *bool {
	return &v.withoutReplay
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodMarshalAPERBudget(v *RequestedSRSTransmissionCharacteristics, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodMarshalAPERChanged(v *RequestedSRSTransmissionCharacteristics, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodMarshalAPERChangedValue(v *RequestedSRSTransmissionCharacteristics, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodMarshalAPERFreshValue(v *RequestedSRSTransmissionCharacteristics, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodMarshalAPERLegacy(v *RequestedSRSTransmissionCharacteristics) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodMarshalAPERPlanned(v *RequestedSRSTransmissionCharacteristics, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodMarshalAPERTo(v *RequestedSRSTransmissionCharacteristics, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodUnmarshalAPERFrom(v *RequestedSRSTransmissionCharacteristics, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodUnmarshalAPERLegacy(v *RequestedSRSTransmissionCharacteristics, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeRequestedSRSTransmissionCharacteristicsMethodUnmarshalAPERWithOptions(v *RequestedSRSTransmissionCharacteristics, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldCapture(v *RequestedSRSTransmissionCharacteristicsValueCodec) *func(RequestedSRSTransmissionCharacteristics, aper.DecodeState) (RequestedSRSTransmissionCharacteristics, aper.Snapshot) {
	return &v.capture
}
func BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldCompare(v *RequestedSRSTransmissionCharacteristicsValueCodec) *func(RequestedSRSTransmissionCharacteristics, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldContext(v *RequestedSRSTransmissionCharacteristicsValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldDecode(v *RequestedSRSTransmissionCharacteristicsValueCodec) *func([]byte, aper.DecodeState) (RequestedSRSTransmissionCharacteristics, error) {
	return &v.decode
}
func BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldEncode(v *RequestedSRSTransmissionCharacteristicsValueCodec) *func(RequestedSRSTransmissionCharacteristics, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeRequestedSRSTransmissionCharacteristicsValueCodecFieldPath(v *RequestedSRSTransmissionCharacteristicsValueCodec) *aper.Path {
	return &v.path
}
func BridgeRequestedSRSTransmissionCharacteristicsValueCodecMethodEncodeBudget(v RequestedSRSTransmissionCharacteristicsValueCodec, a0 RequestedSRSTransmissionCharacteristics, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeRequestedSRSTransmissionCharacteristicsValueCodecMethodEncodeChanged(v RequestedSRSTransmissionCharacteristicsValueCodec, a0 RequestedSRSTransmissionCharacteristics, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultUTRANItemPhysCellIDUTRANAPERValueFieldContext(v *ResultUTRANItemPhysCellIDUTRANAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultUTRANItemPhysCellIDUTRANAPERValueFieldReceived(v *ResultUTRANItemPhysCellIDUTRANAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResultUTRANItemPhysCellIDUTRANAPERValueFieldReplay(v *ResultUTRANItemPhysCellIDUTRANAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResultUTRANItemPhysCellIDUTRANAPERValueFieldWithoutReplay(v *ResultUTRANItemPhysCellIDUTRANAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultUTRANItemPhysCellIDUTRANFieldPerOpenTypePadding(v *ResultUTRANItemPhysCellIDUTRAN) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeResultUTRANItemPhysCellIDUTRANFieldPerPadding(v *ResultUTRANItemPhysCellIDUTRAN) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeResultUTRANItemPhysCellIDUTRANFieldReceived(v *ResultUTRANItemPhysCellIDUTRAN) *bool {
	return &v.received
}
func BridgeResultUTRANItemPhysCellIDUTRANFieldReceivedBytes(v *ResultUTRANItemPhysCellIDUTRAN) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeResultUTRANItemPhysCellIDUTRANFieldReplay(v *ResultUTRANItemPhysCellIDUTRAN) *aper.Snapshot {
	return &v.replay
}
func BridgeResultUTRANItemPhysCellIDUTRANFieldStream(v *ResultUTRANItemPhysCellIDUTRAN) *aper.WireSpan {
	return &v.stream
}
func BridgeResultUTRANItemPhysCellIDUTRANFieldWithoutReplay(v *ResultUTRANItemPhysCellIDUTRAN) *bool {
	return &v.withoutReplay
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERBudget(v *ResultUTRANItemPhysCellIDUTRAN, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERChanged(v *ResultUTRANItemPhysCellIDUTRAN, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERChangedValue(v *ResultUTRANItemPhysCellIDUTRAN, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERFreshValue(v *ResultUTRANItemPhysCellIDUTRAN, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERLegacy(v *ResultUTRANItemPhysCellIDUTRAN) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERPlanned(v *ResultUTRANItemPhysCellIDUTRAN, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERTo(v *ResultUTRANItemPhysCellIDUTRAN, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodUnmarshalAPERFrom(v *ResultUTRANItemPhysCellIDUTRAN, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodUnmarshalAPERLegacy(v *ResultUTRANItemPhysCellIDUTRAN, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultUTRANItemPhysCellIDUTRANMethodUnmarshalAPERWithOptions(v *ResultUTRANItemPhysCellIDUTRAN, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultUTRANItemPhysCellIDUTRANValueCodecFieldCapture(v *ResultUTRANItemPhysCellIDUTRANValueCodec) *func(ResultUTRANItemPhysCellIDUTRAN, aper.DecodeState) (ResultUTRANItemPhysCellIDUTRAN, aper.Snapshot) {
	return &v.capture
}
func BridgeResultUTRANItemPhysCellIDUTRANValueCodecFieldCompare(v *ResultUTRANItemPhysCellIDUTRANValueCodec) *func(ResultUTRANItemPhysCellIDUTRAN, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeResultUTRANItemPhysCellIDUTRANValueCodecFieldContext(v *ResultUTRANItemPhysCellIDUTRANValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultUTRANItemPhysCellIDUTRANValueCodecFieldDecode(v *ResultUTRANItemPhysCellIDUTRANValueCodec) *func([]byte, aper.DecodeState) (ResultUTRANItemPhysCellIDUTRAN, error) {
	return &v.decode
}
func BridgeResultUTRANItemPhysCellIDUTRANValueCodecFieldEncode(v *ResultUTRANItemPhysCellIDUTRANValueCodec) *func(ResultUTRANItemPhysCellIDUTRAN, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultUTRANItemPhysCellIDUTRANValueCodecFieldPath(v *ResultUTRANItemPhysCellIDUTRANValueCodec) *aper.Path {
	return &v.path
}
func BridgeResultUTRANItemPhysCellIDUTRANValueCodecMethodEncodeBudget(v ResultUTRANItemPhysCellIDUTRANValueCodec, a0 ResultUTRANItemPhysCellIDUTRAN, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultUTRANItemPhysCellIDUTRANValueCodecMethodEncodeChanged(v ResultUTRANItemPhysCellIDUTRANValueCodec, a0 ResultUTRANItemPhysCellIDUTRAN, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
