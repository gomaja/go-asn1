// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s02 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s02

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// WLANCountryCodeValueCodec is the concrete ValueCodec[WLANCountryCode].
type WLANCountryCodeValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.WLANCountryCode, aper.DecodeState,

	) (s00.WLANCountryCode, aper.Snapshot,

	)
	compare func(s00.WLANCountryCode, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.WLANCountryCode,

		error)
	encode func(s00.WLANCountryCode,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c WLANCountryCodeValueCodec) New(value s00.WLANCountryCode,

) (s01.WLANCountryCodeAPERValue, error) {
	if c.encode == nil {
		return s01.WLANCountryCodeAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s01.WLANCountryCodeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return s01.WLANCountryCodeAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return s01.WLANCountryCodeAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c WLANCountryCodeValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (s01.WLANCountryCodeAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return s01.WLANCountryCodeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return s01.WLANCountryCodeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return s01.WLANCountryCodeAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return s01.WLANCountryCodeAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return func() s01.WLANCountryCodeAPERValue {
		sealed := s01.WLANCountryCodeAPERValue{Value: value}
		*s01.BridgeWLANCountryCodeAPERValueFieldReceived(&sealed) = aper.OriginalWire(data)
		*s01.BridgeWLANCountryCodeAPERValueFieldReplay(&sealed) = replay
		*s01.BridgeWLANCountryCodeAPERValueFieldContext(&sealed) = c.context
		return sealed
	}(), report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c WLANCountryCodeValueCodec) EncodeAPER(value s01.WLANCountryCodeAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	fresh := *s01.BridgeWLANCountryCodeAPERValueFieldWithoutReplay(&value) || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	if !fresh && *s01.BridgeWLANCountryCodeAPERValueFieldContext(&value) == c.context && (*s01.BridgeWLANCountryCodeAPERValueFieldReplay(&value)).Present() {

		plan := c.compare(value.Value, *s01.BridgeWLANCountryCodeAPERValueFieldReplay(&value), aper.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(*s01.BridgeWLANCountryCodeAPERValueFieldReplay(&value)) {
			if err := (*s01.BridgeWLANCountryCodeAPERValueFieldReplay(&value)).ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, c.path)
			}
			out, err := (*s01.BridgeWLANCountryCodeAPERValueFieldReceived(&value)).ReplayBytes(&budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, aper.OperationError(err, c.path)
}
func (c WLANCountryCodeValueCodec) encodeBudget(value s00.WLANCountryCode,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANCountryCodeValueCodec) encodeChanged(value s00.WLANCountryCode,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// WLANMeasurementQuantitiesValueValueCodec is the concrete ValueCodec[WLANMeasurementQuantitiesValue].
type WLANMeasurementQuantitiesValueValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.WLANMeasurementQuantitiesValue, aper.DecodeState,

	) (s00.WLANMeasurementQuantitiesValue, aper.Snapshot,

	)
	compare func(s00.WLANMeasurementQuantitiesValue, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.WLANMeasurementQuantitiesValue,

		error)
	encode func(s00.WLANMeasurementQuantitiesValue,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c WLANMeasurementQuantitiesValueValueCodec) New(value s00.WLANMeasurementQuantitiesValue,

) (WLANMeasurementQuantitiesValueAPERValue, error) {
	if c.encode == nil {
		return WLANMeasurementQuantitiesValueAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WLANMeasurementQuantitiesValueAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANMeasurementQuantitiesValueAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return WLANMeasurementQuantitiesValueAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c WLANMeasurementQuantitiesValueValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WLANMeasurementQuantitiesValueAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANMeasurementQuantitiesValueAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return WLANMeasurementQuantitiesValueAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANMeasurementQuantitiesValueAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return WLANMeasurementQuantitiesValueAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return WLANMeasurementQuantitiesValueAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c WLANMeasurementQuantitiesValueValueCodec) EncodeAPER(value WLANMeasurementQuantitiesValueAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c WLANMeasurementQuantitiesValueValueCodec) encodeBudget(value s00.WLANMeasurementQuantitiesValue,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANMeasurementQuantitiesValueValueCodec) encodeChanged(value s00.WLANMeasurementQuantitiesValue,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// WLANOperatingClassValueCodec is the concrete ValueCodec[WLANOperatingClass].
type WLANOperatingClassValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.WLANOperatingClass, aper.DecodeState,

	) (s00.WLANOperatingClass, aper.Snapshot,

	)
	compare func(s00.WLANOperatingClass, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.WLANOperatingClass,

		error)
	encode func(s00.WLANOperatingClass,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c WLANOperatingClassValueCodec) New(value s00.WLANOperatingClass,

) (WLANOperatingClassAPERValue, error) {
	if c.encode == nil {
		return WLANOperatingClassAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WLANOperatingClassAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANOperatingClassAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return WLANOperatingClassAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c WLANOperatingClassValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WLANOperatingClassAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANOperatingClassAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return WLANOperatingClassAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANOperatingClassAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return WLANOperatingClassAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return WLANOperatingClassAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c WLANOperatingClassValueCodec) EncodeAPER(value WLANOperatingClassAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c WLANOperatingClassValueCodec) encodeBudget(value s00.WLANOperatingClass,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANOperatingClassValueCodec) encodeChanged(value s00.WLANOperatingClass,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// WLANRSSIValueCodec is the concrete ValueCodec[WLANRSSI].
type WLANRSSIValueCodec struct {
	context s00.BridgeCodecContext
	capture func(s00.WLANRSSI, aper.DecodeState,

	) (s00.WLANRSSI, aper.Snapshot,

	)
	compare func(s00.WLANRSSI, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (s00.WLANRSSI,

		error)
	encode func(s00.WLANRSSI,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c WLANRSSIValueCodec) New(value s00.WLANRSSI,

) (WLANRSSIAPERValue, error) {
	if c.encode == nil {
		return WLANRSSIAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WLANRSSIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANRSSIAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return WLANRSSIAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c WLANRSSIValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WLANRSSIAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANRSSIAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return WLANRSSIAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANRSSIAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return WLANRSSIAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return WLANRSSIAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c WLANRSSIValueCodec) EncodeAPER(value WLANRSSIAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c WLANRSSIValueCodec) encodeBudget(value s00.WLANRSSI,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANRSSIValueCodec) encodeChanged(value s00.WLANRSSI,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// WLANMeasurementQuantitiesValueAPERValue is the concrete APERValue[WLANMeasurementQuantitiesValue].
type WLANMeasurementQuantitiesValueAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.WLANMeasurementQuantitiesValue

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v WLANMeasurementQuantitiesValueAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v WLANMeasurementQuantitiesValueAPERValue) WithoutReplay() WLANMeasurementQuantitiesValueAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WLANOperatingClassAPERValue is the concrete APERValue[WLANOperatingClass].
type WLANOperatingClassAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.WLANOperatingClass

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v WLANOperatingClassAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v WLANOperatingClassAPERValue) WithoutReplay() WLANOperatingClassAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WLANRSSIAPERValue is the concrete APERValue[WLANRSSI].
type WLANRSSIAPERValue struct {
	context s00.BridgeCodecContext
	Value   s00.WLANRSSI

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v WLANRSSIAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v WLANRSSIAPERValue) WithoutReplay() WLANRSSIAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureLPPaAddOTDOACellsExtIEsValue(v *AddOTDOACellsExtIEsValue, s *aper.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v AddOTDOACellsExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v AddOTDOACellsExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v AddOTDOACellsExtIEsValue) captureSemantics(s aper.SemanticCapture) AddOTDOACellsExtIEsValue {
	BridgeCaptureLPPaAddOTDOACellsExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaAddOTDOACellsExtIEsValue(v *AddOTDOACellsExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaProtocolIEID(&v.id, s)
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
	s.End(f, v.replay, v.withoutReplay)
}
func (v AddOTDOACellsExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaAddOTDOACellsExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AddOTDOACellsExtIEsValue) WithoutReplay() AddOTDOACellsExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaAssistanceInformationExtIEsValue(v *AssistanceInformationExtIEsValue, s *aper.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v AssistanceInformationExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v AssistanceInformationExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v AssistanceInformationExtIEsValue) captureSemantics(s aper.SemanticCapture) AssistanceInformationExtIEsValue {
	BridgeCaptureLPPaAssistanceInformationExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaAssistanceInformationExtIEsValue(v *AssistanceInformationExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaProtocolIEID(&v.id, s)
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
	s.End(f, v.replay, v.withoutReplay)
}
func (v AssistanceInformationExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaAssistanceInformationExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AssistanceInformationExtIEsValue) WithoutReplay() AssistanceInformationExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaAssistanceInformationFailureListExtIEsValue(v *AssistanceInformationFailureListExtIEsValue, s *aper.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v AssistanceInformationFailureListExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v AssistanceInformationFailureListExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v AssistanceInformationFailureListExtIEsValue) captureSemantics(s aper.SemanticCapture) AssistanceInformationFailureListExtIEsValue {
	BridgeCaptureLPPaAssistanceInformationFailureListExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaAssistanceInformationFailureListExtIEsValue(v *AssistanceInformationFailureListExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaProtocolIEID(&v.id, s)
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
	s.End(f, v.replay, v.withoutReplay)
}
func (v AssistanceInformationFailureListExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaAssistanceInformationFailureListExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AssistanceInformationFailureListExtIEsValue) WithoutReplay() AssistanceInformationFailureListExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaAssistanceInformationMetaDataExtIEsValue(v *AssistanceInformationMetaDataExtIEsValue, s *aper.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v AssistanceInformationMetaDataExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v AssistanceInformationMetaDataExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v AssistanceInformationMetaDataExtIEsValue) captureSemantics(s aper.SemanticCapture) AssistanceInformationMetaDataExtIEsValue {
	BridgeCaptureLPPaAssistanceInformationMetaDataExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaAssistanceInformationMetaDataExtIEsValue(v *AssistanceInformationMetaDataExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaProtocolIEID(&v.id, s)
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
	s.End(f, v.replay, v.withoutReplay)
}
func (v AssistanceInformationMetaDataExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaAssistanceInformationMetaDataExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AssistanceInformationMetaDataExtIEsValue) WithoutReplay() AssistanceInformationMetaDataExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCompareLPPaBCCH(v *s00.BCCH, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCompareLPPaBSSID(v *s00.BSSID, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Bytes((*v))
}
func BridgeCompareLPPaBroadcast(v *s00.Broadcast, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaBroadcastPeriodicity(v *s00.BroadcastPeriodicity, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaCPLength(v *s00.CPLength, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaCauseMisc(v *s00.CauseMisc, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaCauseProtocol(v *s00.CauseProtocol, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaCauseRadioNetwork(v *s00.CauseRadioNetwork, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaCellPortionID(v *s00.CellPortionID, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCompareLPPaCriticality(v *s00.Criticality, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaCriticalityDiagnosticsExtIEsValue(v *CriticalityDiagnosticsExtIEsValue, s *aper.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v CriticalityDiagnosticsExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v CriticalityDiagnosticsExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v CriticalityDiagnosticsExtIEsValue) captureSemantics(s aper.SemanticCapture) CriticalityDiagnosticsExtIEsValue {
	BridgeCaptureLPPaCriticalityDiagnosticsExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaCriticalityDiagnosticsExtIEsValue(v *CriticalityDiagnosticsExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaProtocolIEID(&v.id, s)
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
	s.End(f, v.replay, v.withoutReplay)
}
func (v CriticalityDiagnosticsExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaCriticalityDiagnosticsExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v CriticalityDiagnosticsExtIEsValue) WithoutReplay() CriticalityDiagnosticsExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaCriticalityDiagnosticsIEListExtIEsValue(v *CriticalityDiagnosticsIEListExtIEsValue, s *aper.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v CriticalityDiagnosticsIEListExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v CriticalityDiagnosticsIEListExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v CriticalityDiagnosticsIEListExtIEsValue) captureSemantics(s aper.SemanticCapture) CriticalityDiagnosticsIEListExtIEsValue {
	BridgeCaptureLPPaCriticalityDiagnosticsIEListExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaCriticalityDiagnosticsIEListExtIEsValue(v *CriticalityDiagnosticsIEListExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaProtocolIEID(&v.id, s)
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
	s.End(f, v.replay, v.withoutReplay)
}
func (v CriticalityDiagnosticsIEListExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaCriticalityDiagnosticsIEListExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v CriticalityDiagnosticsIEListExtIEsValue) WithoutReplay() CriticalityDiagnosticsIEListExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCompareLPPaDLBandwidth(v *s00.DLBandwidth, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaEARFCN(v *s00.EARFCN, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCaptureLPPaECGIExtIEsValue(v *ECGIExtIEsValue, s *aper.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ECGIExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v ECGIExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ECGIExtIEsValue) captureSemantics(s aper.SemanticCapture) ECGIExtIEsValue {
	BridgeCaptureLPPaECGIExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaECGIExtIEsValue(v *ECGIExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaProtocolIEID(&v.id, s)
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
	s.End(f, v.replay, v.withoutReplay)
}
func (v ECGIExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaECGIExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECGIExtIEsValue) WithoutReplay() ECGIExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaECIDMeasurementTerminationCommandIEValue(v *ECIDMeasurementTerminationCommandIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowESMLCUEMeasurementID == nil)
				if v.rowESMLCUEMeasurementID != nil {
					s00.BridgeCaptureLPPaMeasurementID(v.rowESMLCUEMeasurementID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(6):
			{
				f := s.Begin()
				s.Bool(v.rowENBUEMeasurementID == nil)
				if v.rowENBUEMeasurementID != nil {
					s00.BridgeCaptureLPPaMeasurementID(v.rowENBUEMeasurementID, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ECIDMeasurementTerminationCommandIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v ECIDMeasurementTerminationCommandIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ECIDMeasurementTerminationCommandIEValue) captureSemantics(s aper.SemanticCapture) ECIDMeasurementTerminationCommandIEValue {
	BridgeCaptureLPPaECIDMeasurementTerminationCommandIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaECIDMeasurementTerminationCommandIEValue(v *ECIDMeasurementTerminationCommandIEValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaProtocolIEID(&v.id, s)
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowESMLCUEMeasurementID == nil)
				if v.rowESMLCUEMeasurementID != nil {
					BridgeCompareLPPaMeasurementID(v.rowESMLCUEMeasurementID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(6):
			{
				f := s.Begin()
				s.Bool(v.rowENBUEMeasurementID == nil)
				if v.rowENBUEMeasurementID != nil {
					BridgeCompareLPPaMeasurementID(v.rowENBUEMeasurementID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v ECIDMeasurementTerminationCommandIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaECIDMeasurementTerminationCommandIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECIDMeasurementTerminationCommandIEValue) WithoutReplay() ECIDMeasurementTerminationCommandIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCompareLPPaEUTRANCellIdentifier(v *s00.EUTRANCellIdentifier, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.BitString((*v).Bytes, (*v).BitLength)
}
func BridgeCompareLPPaHESSID(v *s00.HESSID, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Bytes((*v))
}
func BridgeCompareLPPaInterRATMeasurementQuantitiesValue(v *s00.InterRATMeasurementQuantitiesValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaInterRATMeasurementQuantitiesValueExtIEsValue(v *InterRATMeasurementQuantitiesValueExtIEsValue, s *aper.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v InterRATMeasurementQuantitiesValueExtIEsValue) captureSnapshot() aper.Snapshot {
	return v.replay
}
func (v InterRATMeasurementQuantitiesValueExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v InterRATMeasurementQuantitiesValueExtIEsValue) captureSemantics(s aper.SemanticCapture) InterRATMeasurementQuantitiesValueExtIEsValue {
	BridgeCaptureLPPaInterRATMeasurementQuantitiesValueExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaInterRATMeasurementQuantitiesValueExtIEsValue(v *InterRATMeasurementQuantitiesValueExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaProtocolIEID(&v.id, s)
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
	s.End(f, v.replay, v.withoutReplay)
}
func (v InterRATMeasurementQuantitiesValueExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaInterRATMeasurementQuantitiesValueExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v InterRATMeasurementQuantitiesValueExtIEsValue) WithoutReplay() InterRATMeasurementQuantitiesValueExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCompareLPPaLPPATransactionID(v *s00.LPPATransactionID, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaMeasurementID(v *s00.MeasurementID, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCompareLPPaMeasurementPeriodicity(v *s00.MeasurementPeriodicity, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaMeasurementQuantitiesValue(v *s00.MeasurementQuantitiesValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaMeasurementQuantitiesValueExtIEsValue(v *MeasurementQuantitiesValueExtIEsValue, s *aper.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v MeasurementQuantitiesValueExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v MeasurementQuantitiesValueExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v MeasurementQuantitiesValueExtIEsValue) captureSemantics(s aper.SemanticCapture) MeasurementQuantitiesValueExtIEsValue {
	BridgeCaptureLPPaMeasurementQuantitiesValueExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaMeasurementQuantitiesValueExtIEsValue(v *MeasurementQuantitiesValueExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaProtocolIEID(&v.id, s)
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
	s.End(f, v.replay, v.withoutReplay)
}
func (v MeasurementQuantitiesValueExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaMeasurementQuantitiesValueExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v MeasurementQuantitiesValueExtIEsValue) WithoutReplay() MeasurementQuantitiesValueExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCompareLPPaNPRSSequenceInfo(v *s00.NPRSSequenceInfo, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCompareLPPaNRARFCN(v *s00.NRARFCN, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaNRCGIExtIEsValue(v *NRCGIExtIEsValue, s *aper.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v NRCGIExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v NRCGIExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v NRCGIExtIEsValue) captureSemantics(s aper.SemanticCapture) NRCGIExtIEsValue {
	BridgeCaptureLPPaNRCGIExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaNRCGIExtIEsValue(v *NRCGIExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaProtocolIEID(&v.id, s)
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
	s.End(f, v.replay, v.withoutReplay)
}
func (v NRCGIExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaNRCGIExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v NRCGIExtIEsValue) WithoutReplay() NRCGIExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCompareLPPaNRCellIdentity(v *s00.NRCellIdentity, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.BitString((*v).Bytes, (*v).BitLength)
}
func BridgeCompareLPPaNRPCI(v *s00.NRPCI, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaNarrowBandIndex(v *s00.NarrowBandIndex, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCompareLPPaNumberOfAntennaPorts(v *s00.NumberOfAntennaPorts, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaNumberOfDlFrames(v *s00.NumberOfDlFrames, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaNumberOfDlFramesExtended(v *s00.NumberOfDlFramesExtended, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCompareLPPaNumberOfFrequencyHoppingBands(v *s00.NumberOfFrequencyHoppingBands, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaOTDOACellsExtIEsValue(v *OTDOACellsExtIEsValue, s *aper.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v OTDOACellsExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v OTDOACellsExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v OTDOACellsExtIEsValue) captureSemantics(s aper.SemanticCapture) OTDOACellsExtIEsValue {
	BridgeCaptureLPPaOTDOACellsExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaOTDOACellsExtIEsValue(v *OTDOACellsExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaProtocolIEID(&v.id, s)
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
	s.End(f, v.replay, v.withoutReplay)
}
func (v OTDOACellsExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaOTDOACellsExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOACellsExtIEsValue) WithoutReplay() OTDOACellsExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCompareLPPaOTDOAInformationItem(v *s00.OTDOAInformationItem, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaOTDOAInformationTypeItemExtIEsValue(v *OTDOAInformationTypeItemExtIEsValue, s *aper.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v OTDOAInformationTypeItemExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v OTDOAInformationTypeItemExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v OTDOAInformationTypeItemExtIEsValue) captureSemantics(s aper.SemanticCapture) OTDOAInformationTypeItemExtIEsValue {
	BridgeCaptureLPPaOTDOAInformationTypeItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaOTDOAInformationTypeItemExtIEsValue(v *OTDOAInformationTypeItemExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaProtocolIEID(&v.id, s)
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
	s.End(f, v.replay, v.withoutReplay)
}
func (v OTDOAInformationTypeItemExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaOTDOAInformationTypeItemExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v OTDOAInformationTypeItemExtIEsValue) WithoutReplay() OTDOAInformationTypeItemExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCompareLPPaOffsetNBChanneltoEARFCN(v *s00.OffsetNBChanneltoEARFCN, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaOperationModeInfo(v *s00.OperationModeInfo, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaOutcome(v *s00.Outcome, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaPCI(v *s00.PCI, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCompareLPPaPLMNIdentity(v *s00.PLMNIdentity, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Bytes((*v))
}
func BridgeCompareLPPaPRSBandwidth(v *s00.PRSBandwidth, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaPRSConfigurationIndex(v *s00.PRSConfigurationIndex, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCompareLPPaPRSFrequencyHoppingConfigurationBandPositions(v *s00.PRSFrequencyHoppingConfigurationBandPositions, s *aper.SemanticComparison) {
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
			BridgeCompareLPPaNarrowBandIndex(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaPRSFrequencyHoppingConfigurationItemIEsValue(v *PRSFrequencyHoppingConfigurationItemIEsValue, s *aper.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v PRSFrequencyHoppingConfigurationItemIEsValue) captureSnapshot() aper.Snapshot {
	return v.replay
}
func (v PRSFrequencyHoppingConfigurationItemIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v PRSFrequencyHoppingConfigurationItemIEsValue) captureSemantics(s aper.SemanticCapture) PRSFrequencyHoppingConfigurationItemIEsValue {
	BridgeCaptureLPPaPRSFrequencyHoppingConfigurationItemIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaPRSFrequencyHoppingConfigurationItemIEsValue(v *PRSFrequencyHoppingConfigurationItemIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaProtocolIEID(&v.id, s)
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
	s.End(f, v.replay, v.withoutReplay)
}
func (v PRSFrequencyHoppingConfigurationItemIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaPRSFrequencyHoppingConfigurationItemIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PRSFrequencyHoppingConfigurationItemIEsValue) WithoutReplay() PRSFrequencyHoppingConfigurationItemIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCompareLPPaPRSID(v *s00.PRSID, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCompareLPPaPRSOccasionGroup(v *s00.PRSOccasionGroup, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaPhysCellIDGERAN(v *s00.PhysCellIDGERAN, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCompareLPPaPhysCellIDUTRAFDD(v *s00.PhysCellIDUTRAFDD, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCompareLPPaPhysCellIDUTRATDD(v *s00.PhysCellIDUTRATDD, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeCaptureLPPaPosSIBSegmentsExtIEsValue(v *PosSIBSegmentsExtIEsValue, s *aper.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v PosSIBSegmentsExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v PosSIBSegmentsExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v PosSIBSegmentsExtIEsValue) captureSemantics(s aper.SemanticCapture) PosSIBSegmentsExtIEsValue {
	BridgeCaptureLPPaPosSIBSegmentsExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaPosSIBSegmentsExtIEsValue(v *PosSIBSegmentsExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaProtocolIEID(&v.id, s)
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
	s.End(f, v.replay, v.withoutReplay)
}
func (v PosSIBSegmentsExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaPosSIBSegmentsExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v PosSIBSegmentsExtIEsValue) WithoutReplay() PosSIBSegmentsExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCompareLPPaPosSIBType(v *s00.PosSIBType, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaPresence(v *s00.Presence, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaProcedureCode(v *s00.ProcedureCode, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaProtocolIEID(v *s00.ProtocolIEID, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}

type AddOTDOACellsExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v AddOTDOACellsExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *AddOTDOACellsExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (AddOTDOACellsExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "Add-OTDOACells-ExtIEs"}}
}
func (AddOTDOACellsExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
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
	case s00.ProtocolIEID(10):
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
func (v AddOTDOACellsExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (AddOTDOACellsExtIEsValue, error) {
	out := AddOTDOACellsExtIEsValue{id: id}
	switch id {
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
func (v AddOTDOACellsExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v AddOTDOACellsExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "AddOTDOACellsExtIEsValue:", v.id)
	}
}

type AssistanceInformationExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v AssistanceInformationExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *AssistanceInformationExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (AssistanceInformationExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "Assistance-Information-ExtIEs"}}
}
func (AssistanceInformationExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
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
	case s00.ProtocolIEID(10):
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
func (v AssistanceInformationExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (AssistanceInformationExtIEsValue, error) {
	out := AssistanceInformationExtIEsValue{id: id}
	switch id {
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
func (v AssistanceInformationExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v AssistanceInformationExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "AssistanceInformationExtIEsValue:", v.id)
	}
}

type AssistanceInformationFailureListExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v AssistanceInformationFailureListExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *AssistanceInformationFailureListExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (AssistanceInformationFailureListExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "AssistanceInformationFailureList-ExtIEs"}}
}
func (AssistanceInformationFailureListExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
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
	case s00.ProtocolIEID(10):
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
func (v AssistanceInformationFailureListExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (AssistanceInformationFailureListExtIEsValue, error) {
	out := AssistanceInformationFailureListExtIEsValue{id: id}
	switch id {
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
func (v AssistanceInformationFailureListExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v AssistanceInformationFailureListExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "AssistanceInformationFailureListExtIEsValue:", v.id)
	}
}

type AssistanceInformationMetaDataExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v AssistanceInformationMetaDataExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *AssistanceInformationMetaDataExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (AssistanceInformationMetaDataExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "AssistanceInformationMetaData-ExtIEs"}}
}
func (AssistanceInformationMetaDataExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
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
	case s00.ProtocolIEID(10):
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
func (v AssistanceInformationMetaDataExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (AssistanceInformationMetaDataExtIEsValue, error) {
	out := AssistanceInformationMetaDataExtIEsValue{id: id}
	switch id {
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
func (v AssistanceInformationMetaDataExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v AssistanceInformationMetaDataExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "AssistanceInformationMetaDataExtIEsValue:", v.id)
	}
}

type CriticalityDiagnosticsExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v CriticalityDiagnosticsExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *CriticalityDiagnosticsExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (CriticalityDiagnosticsExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics-ExtIEs"}}
}
func (CriticalityDiagnosticsExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
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
	case s00.ProtocolIEID(10):
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
func (v CriticalityDiagnosticsExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (CriticalityDiagnosticsExtIEsValue, error) {
	out := CriticalityDiagnosticsExtIEsValue{id: id}
	switch id {
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
func (v CriticalityDiagnosticsExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v CriticalityDiagnosticsExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "CriticalityDiagnosticsExtIEsValue:", v.id)
	}
}

type CriticalityDiagnosticsIEListExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v CriticalityDiagnosticsIEListExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *CriticalityDiagnosticsIEListExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (CriticalityDiagnosticsIEListExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics-IE-List-ExtIEs"}}
}
func (CriticalityDiagnosticsIEListExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
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
	case s00.ProtocolIEID(10):
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
func (v CriticalityDiagnosticsIEListExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (CriticalityDiagnosticsIEListExtIEsValue, error) {
	out := CriticalityDiagnosticsIEListExtIEsValue{id: id}
	switch id {
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
func (v CriticalityDiagnosticsIEListExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v CriticalityDiagnosticsIEListExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "CriticalityDiagnosticsIEListExtIEsValue:", v.id)
	}
}

type ECGIExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v ECGIExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *ECGIExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ECGIExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ECGI-ExtIEs"}}
}
func (ECGIExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
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
	case s00.ProtocolIEID(10):
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
func (v ECGIExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ECGIExtIEsValue, error) {
	out := ECGIExtIEsValue{id: id}
	switch id {
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
func (v ECGIExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ECGIExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ECGIExtIEsValue:", v.id)
	}
}

type InterRATMeasurementQuantitiesValueExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v InterRATMeasurementQuantitiesValueExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *InterRATMeasurementQuantitiesValueExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (InterRATMeasurementQuantitiesValueExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "InterRATMeasurementQuantitiesValue-ExtIEs"}}
}
func (InterRATMeasurementQuantitiesValueExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
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
	case s00.ProtocolIEID(10):
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
func (v InterRATMeasurementQuantitiesValueExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (InterRATMeasurementQuantitiesValueExtIEsValue, error) {
	out := InterRATMeasurementQuantitiesValueExtIEsValue{id: id}
	switch id {
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
func (v InterRATMeasurementQuantitiesValueExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v InterRATMeasurementQuantitiesValueExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "InterRATMeasurementQuantitiesValueExtIEsValue:", v.id)
	}
}

type MeasurementQuantitiesValueExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v MeasurementQuantitiesValueExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *MeasurementQuantitiesValueExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (MeasurementQuantitiesValueExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementQuantitiesValue-ExtIEs"}}
}
func (MeasurementQuantitiesValueExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
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
	case s00.ProtocolIEID(10):
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
func (v MeasurementQuantitiesValueExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (MeasurementQuantitiesValueExtIEsValue, error) {
	out := MeasurementQuantitiesValueExtIEsValue{id: id}
	switch id {
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
func (v MeasurementQuantitiesValueExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v MeasurementQuantitiesValueExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "MeasurementQuantitiesValueExtIEsValue:", v.id)
	}
}

type NRCGIExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v NRCGIExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *NRCGIExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (NRCGIExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "NR-CGI-ExtIEs"}}
}
func (NRCGIExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
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
	case s00.ProtocolIEID(10):
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
func (v NRCGIExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (NRCGIExtIEsValue, error) {
	out := NRCGIExtIEsValue{id: id}
	switch id {
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
func (v NRCGIExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v NRCGIExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "NRCGIExtIEsValue:", v.id)
	}
}

type OTDOACellsExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v OTDOACellsExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *OTDOACellsExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (OTDOACellsExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "OTDOACells-ExtIEs"}}
}
func (OTDOACellsExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
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
	case s00.ProtocolIEID(10):
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
func (v OTDOACellsExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (OTDOACellsExtIEsValue, error) {
	out := OTDOACellsExtIEsValue{id: id}
	switch id {
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
func (v OTDOACellsExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v OTDOACellsExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "OTDOACellsExtIEsValue:", v.id)
	}
}

type PRSFrequencyHoppingConfigurationItemIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v PRSFrequencyHoppingConfigurationItemIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *PRSFrequencyHoppingConfigurationItemIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (PRSFrequencyHoppingConfigurationItemIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "PRSFrequencyHoppingConfiguration-Item-IEs"}}
}
func (PRSFrequencyHoppingConfigurationItemIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
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
	case s00.ProtocolIEID(10):
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
func (v PRSFrequencyHoppingConfigurationItemIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (PRSFrequencyHoppingConfigurationItemIEsValue, error) {
	out := PRSFrequencyHoppingConfigurationItemIEsValue{id: id}
	switch id {
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
func (v PRSFrequencyHoppingConfigurationItemIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v PRSFrequencyHoppingConfigurationItemIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "PRSFrequencyHoppingConfigurationItemIEsValue:", v.id)
	}
}

type PosSIBSegmentsExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v PosSIBSegmentsExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *PosSIBSegmentsExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (PosSIBSegmentsExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "PosSIB-Segments-ExtIEs"}}
}
func (PosSIBSegmentsExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
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
	case s00.ProtocolIEID(10):
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
func (v PosSIBSegmentsExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (PosSIBSegmentsExtIEsValue, error) {
	out := PosSIBSegmentsExtIEsValue{id: id}
	switch id {
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
func (v PosSIBSegmentsExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v PosSIBSegmentsExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "PosSIBSegmentsExtIEsValue:", v.id)
	}
}

type ECIDMeasurementTerminationCommandIEValue struct {
	id                      s00.ProtocolIEID
	withoutReplay           bool
	received                aper.WireSpan
	replay                  aper.Snapshot
	opaque                  *aper.OpaqueOpenType
	isOpaque                bool
	rowESMLCUEMeasurementID *s00.MeasurementID
	rowENBUEMeasurementID   *s00.MeasurementID
}

func (v ECIDMeasurementTerminationCommandIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case s00.ProtocolIEID(2):
		return v.rowESMLCUEMeasurementID != nil
	case s00.ProtocolIEID(6):
		return v.rowENBUEMeasurementID != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *ECIDMeasurementTerminationCommandIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ECIDMeasurementTerminationCommandIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementTerminationCommand-IEs"}}
}
func (ECIDMeasurementTerminationCommandIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(6):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
		return aper.NotInTable
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(3):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
		return aper.NotInTable
	case s00.ProtocolIEID(5):
		return aper.NotInTable
	case s00.ProtocolIEID(7):
		return aper.NotInTable
	case s00.ProtocolIEID(8):
		return aper.NotInTable
	case s00.ProtocolIEID(9):
		return aper.NotInTable
	case s00.ProtocolIEID(10):
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

// AsESMLCUEMeasurementID returns the selected ESMLCUEMeasurementID value and reports whether that alternative is active.
func (v *ECIDMeasurementTerminationCommandIEValue) AsESMLCUEMeasurementID() (*s00.MeasurementID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowESMLCUEMeasurementID == nil {
		return nil, false
	}
	return v.rowESMLCUEMeasurementID, true
}

// AsENBUEMeasurementID returns the selected ENBUEMeasurementID value and reports whether that alternative is active.
func (v *ECIDMeasurementTerminationCommandIEValue) AsENBUEMeasurementID() (*s00.MeasurementID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(6) || v.rowENBUEMeasurementID == nil {
		return nil, false
	}
	return v.rowENBUEMeasurementID, true
}
func (v ECIDMeasurementTerminationCommandIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ECIDMeasurementTerminationCommandIEValue, error) {
	out := ECIDMeasurementTerminationCommandIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 2, 6:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case s00.ProtocolIEID(2):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound2, s00.BridgeAsn1IntegerBound7, true)
		value := s00.MeasurementID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ESMLCUEMeasurementID:", err)
		}
		if _, err := aper.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowESMLCUEMeasurementID = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case s00.ProtocolIEID(6):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound2, s00.BridgeAsn1IntegerBound7, true)
		value := s00.MeasurementID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ENBUEMeasurementID:", err)
		}
		if _, err := aper.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowENBUEMeasurementID = &value
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
func (v ECIDMeasurementTerminationCommandIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ECIDMeasurementTerminationCommandIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(2):
		if v.rowESMLCUEMeasurementID == nil {
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementTerminationCommand-IEs.id-E-SMLC-UE-Measurement-ID:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerBigBoundsAligned(encodeBB, *v.rowESMLCUEMeasurementID, s00.BridgeAsn1IntegerBound2, s00.BridgeAsn1IntegerBound7, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(6):
		if v.rowENBUEMeasurementID == nil {
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementTerminationCommand-IEs.id-eNB-UE-Measurement-ID:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerBigBoundsAligned(encodeBB, *v.rowENBUEMeasurementID, s00.BridgeAsn1IntegerBound2, s00.BridgeAsn1IntegerBound7, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ECIDMeasurementTerminationCommandIEValue:", v.id)
	}
}

type OTDOAInformationTypeItemExtIEsValue struct {
	id            s00.ProtocolIEID
	withoutReplay bool
	received      aper.WireSpan
	replay        aper.Snapshot
	opaque        *aper.OpaqueOpenType
	isOpaque      bool
}

func (v OTDOAInformationTypeItemExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *OTDOAInformationTypeItemExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (OTDOAInformationTypeItemExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOA-Information-Type-ItemExtIEs"}}
}
func (OTDOAInformationTypeItemExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
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
	case s00.ProtocolIEID(10):
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
func (v OTDOAInformationTypeItemExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (OTDOAInformationTypeItemExtIEsValue, error) {
	out := OTDOAInformationTypeItemExtIEsValue{id: id}
	switch id {
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
func (v OTDOAInformationTypeItemExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v OTDOAInformationTypeItemExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, fmt.Errorf("%s id %d has no value", "OTDOAInformationTypeItemExtIEsValue:", v.id)
	}
}

// BCCHCodec binds the complete source value type.
func BCCHCodec() s00.BCCHValueCodec {
	return func() s00.BCCHValueCodec {
		sealed := s00.BCCHValueCodec{}
		*s00.BridgeBCCHValueCodecFieldPath(&sealed) = "BCCH"
		*s00.BridgeBCCHValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.BCCH, error) {
			var zero s00.BCCH
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound4, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "BCCH"); err != nil {
				return zero, err
			}
			return s00.BCCH(decoded), nil
		}
		*s00.BridgeBCCHValueCodecFieldEncode(&sealed) = func(value s00.BCCH, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerBigBoundsAligned(bb, value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound4, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeBCCHValueCodecFieldCapture(&sealed) = func(v s00.BCCH, options aper.DecodeState) (s00.BCCH, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaBCCH(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeBCCHValueCodecFieldCompare(&sealed) = func(v s00.BCCH, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaBCCH(&v, &s)
			s.End(f,
				root, false)
			return s.Plan()
		}
		*s00.BridgeBCCHValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BCCH"
			return sealed
		}()
		return sealed
	}()

}

// BSSIDCodec binds the complete source value type.
func BSSIDCodec() s00.BSSIDValueCodec {
	return func() s00.BSSIDValueCodec {
		sealed := s00.BSSIDValueCodec{}
		*s00.BridgeBSSIDValueCodecFieldPath(&sealed) = "BSSID"
		*s00.BridgeBSSIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.BSSID, error) {
			var zero s00.BSSID
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			octets, err := aper.DecodeOctetStringAligned(bb, 6, 6, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "BSSID"); err != nil {
				return zero, err
			}
			return s00.BSSID(octets), nil
		}
		*s00.BridgeBSSIDValueCodecFieldEncode(&sealed) = func(value s00.BSSID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeOctetStringAligned(bb, []byte(value), 6, 6, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeBSSIDValueCodecFieldCapture(&sealed) = func(v s00.BSSID, options aper.DecodeState) (s00.BSSID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaBSSID(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeBSSIDValueCodecFieldCompare(&sealed) = func(v s00.BSSID, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaBSSID(&v, &s)
			s.End(
				f, root, false)
			return s.Plan()
		}
		*s00.BridgeBSSIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BSSID"
			return sealed
		}()
		return sealed
	}()

}

// BroadcastPeriodicityCodec binds the complete source value type.
func BroadcastPeriodicityCodec() s00.BroadcastPeriodicityValueCodec {
	return func() s00.BroadcastPeriodicityValueCodec {
		sealed := s00.BroadcastPeriodicityValueCodec{}
		*s00.BridgeBroadcastPeriodicityValueCodecFieldPath(&sealed) = "BroadcastPeriodicity"
		*s00.BridgeBroadcastPeriodicityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.BroadcastPeriodicity, error) {
			var zero s00.BroadcastPeriodicity
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 7, true, aper.EnumerationSource{KnownExtensions: 0, Path: "BroadcastPeriodicity"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "BroadcastPeriodicity"); err != nil {
				return zero, err
			}
			return s00.BroadcastPeriodicity(decoded), nil
		}
		*s00.BridgeBroadcastPeriodicityValueCodecFieldEncode(&sealed) = func(value s00.BroadcastPeriodicity, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 7, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeBroadcastPeriodicityValueCodecFieldCapture(&sealed) = func(v s00.BroadcastPeriodicity, options aper.DecodeState) (s00.BroadcastPeriodicity, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaBroadcastPeriodicity(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*s00.BridgeBroadcastPeriodicityValueCodecFieldCompare(&sealed) = func(v s00.BroadcastPeriodicity, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaBroadcastPeriodicity(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeBroadcastPeriodicityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:BroadcastPeriodicity"
			return sealed
		}()
		return sealed
	}()

}

// CPLengthCodec binds the complete source value type.
func CPLengthCodec() s00.CPLengthValueCodec {
	return func() s00.CPLengthValueCodec {
		sealed := s00.CPLengthValueCodec{}
		*s00.BridgeCPLengthValueCodecFieldPath(&sealed) = "CPLength"
		*s00.BridgeCPLengthValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CPLength, error) {
			var zero s00.CPLength
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CPLength"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "CPLength"); err != nil {
				return zero, err
			}
			return s00.CPLength(decoded), nil
		}
		*s00.BridgeCPLengthValueCodecFieldEncode(&sealed) = func(value s00.CPLength, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 2, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeCPLengthValueCodecFieldCapture(&sealed) = func(v s00.CPLength, options aper.DecodeState) (s00.CPLength, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureLPPaCPLength(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCPLengthValueCodecFieldCompare(&sealed) = func(v s00.CPLength, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaCPLength(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeCPLengthValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CPLength"
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
			decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CauseMisc"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "CauseMisc"); err != nil {
				return zero, err
			}
			return s00.CauseMisc(decoded), nil
		}
		*s00.BridgeCauseMiscValueCodecFieldEncode(&sealed) = func(value s00.CauseMisc, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 1, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeCauseMiscValueCodecFieldCapture(&sealed) = func(v s00.CauseMisc, options aper.DecodeState) (s00.CauseMisc, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureLPPaCauseMisc(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCauseMiscValueCodecFieldCompare(&sealed) = func(v s00.CauseMisc, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaCauseMisc(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeCauseMiscValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CauseMisc"
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
			decoded, err := aper.DecodeEnumeratedAligned(bb, 7, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CauseProtocol"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "CauseProtocol"); err != nil {
				return zero, err
			}
			return s00.CauseProtocol(decoded), nil
		}
		*s00.BridgeCauseProtocolValueCodecFieldEncode(&sealed) = func(value s00.CauseProtocol, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 7, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeCauseProtocolValueCodecFieldCapture(&sealed) = func(v s00.CauseProtocol, options aper.DecodeState) (s00.CauseProtocol, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaCauseProtocol(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCauseProtocolValueCodecFieldCompare(&sealed) = func(v s00.CauseProtocol, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaCauseProtocol(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeCauseProtocolValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CauseProtocol"
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
			decoded, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CauseRadioNetwork"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "CauseRadioNetwork"); err != nil {
				return zero, err
			}
			return s00.CauseRadioNetwork(decoded), nil
		}
		*s00.BridgeCauseRadioNetworkValueCodecFieldEncode(&sealed) = func(value s00.CauseRadioNetwork, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 3, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeCauseRadioNetworkValueCodecFieldCapture(&sealed) = func(v s00.CauseRadioNetwork, options aper.DecodeState) (s00.CauseRadioNetwork, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaCauseRadioNetwork(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root,

				false)
			return v, root
		}
		*s00.BridgeCauseRadioNetworkValueCodecFieldCompare(&sealed) = func(v s00.CauseRadioNetwork, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaCauseRadioNetwork(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeCauseRadioNetworkValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CauseRadioNetwork"
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
			decoded, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Criticality"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "Criticality"); err != nil {
				return zero, err
			}
			return s00.Criticality(decoded), nil
		}
		*s00.BridgeCriticalityValueCodecFieldEncode(&sealed) = func(value s00.Criticality, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 3, false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeCriticalityValueCodecFieldCapture(&sealed) = func(v s00.Criticality, options aper.DecodeState) (s00.Criticality, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaCriticality(&v, &s)
			var root aper.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v,
				root
		}
		*s00.BridgeCriticalityValueCodecFieldCompare(&sealed) = func(v s00.Criticality, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaCriticality(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeCriticalityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Criticality"
			return sealed
		}()
		return sealed
	}()

}

// DLBandwidthCodec binds the complete source value type.
func DLBandwidthCodec() s00.DLBandwidthValueCodec {
	return func() s00.DLBandwidthValueCodec {
		sealed := s00.DLBandwidthValueCodec{}
		*s00.BridgeDLBandwidthValueCodecFieldPath(&sealed) = "DLBandwidth"
		*s00.BridgeDLBandwidthValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.DLBandwidth, error) {
			var zero s00.DLBandwidth
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 6, true, aper.EnumerationSource{KnownExtensions: 0, Path: "DLBandwidth"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "DLBandwidth"); err != nil {
				return zero, err
			}
			return s00.DLBandwidth(decoded), nil
		}
		*s00.BridgeDLBandwidthValueCodecFieldEncode(&sealed) = func(value s00.DLBandwidth, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 6, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeDLBandwidthValueCodecFieldCapture(&sealed) = func(v s00.DLBandwidth, options aper.DecodeState) (s00.DLBandwidth, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaDLBandwidth(&v, &s)
			var root aper.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v,
				root
		}
		*s00.BridgeDLBandwidthValueCodecFieldCompare(&sealed) = func(v s00.DLBandwidth, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaDLBandwidth(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeDLBandwidthValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:DLBandwidth"
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
			decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound20, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "EARFCN"); err != nil {
				return zero, err
			}
			return s00.EARFCN(decoded), nil
		}
		*s00.BridgeEARFCNValueCodecFieldEncode(&sealed) = func(value s00.EARFCN, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerBigBoundsAligned(bb, value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound20, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeEARFCNValueCodecFieldCapture(&sealed) = func(v s00.EARFCN, options aper.DecodeState) (s00.EARFCN, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureLPPaEARFCN(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeEARFCNValueCodecFieldCompare(&sealed) = func(v s00.EARFCN, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaEARFCN(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeEARFCNValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EARFCN"
			return sealed
		}()
		return sealed
	}()

}

// EUTRANCellIdentifierCodec binds the complete source value type.
func EUTRANCellIdentifierCodec() s00.EUTRANCellIdentifierValueCodec {
	return func() s00.EUTRANCellIdentifierValueCodec {
		sealed := s00.EUTRANCellIdentifierValueCodec{}
		*s00.BridgeEUTRANCellIdentifierValueCodecFieldPath(&sealed) = "EUTRANCellIdentifier"
		*s00.BridgeEUTRANCellIdentifierValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EUTRANCellIdentifier, error) {
			var zero s00.EUTRANCellIdentifier
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			bits, length, err := aper.DecodeBitStringAligned(bb, 28, 28, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "EUTRANCellIdentifier"); err != nil {
				return zero, err
			}
			return s00.EUTRANCellIdentifier(runtime.BitString{Bytes: bits, BitLength: length}), nil
		}
		*s00.BridgeEUTRANCellIdentifierValueCodecFieldEncode(&sealed) = func(value s00.EUTRANCellIdentifier, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeBitStringAligned(bb, value.Bytes, value.BitLength, 28, 28, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeEUTRANCellIdentifierValueCodecFieldCapture(&sealed) = func(v s00.EUTRANCellIdentifier, options aper.DecodeState) (s00.EUTRANCellIdentifier, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaEUTRANCellIdentifier(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*s00.BridgeEUTRANCellIdentifierValueCodecFieldCompare(&sealed) = func(v s00.EUTRANCellIdentifier, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaEUTRANCellIdentifier(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeEUTRANCellIdentifierValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EUTRANCellIdentifier"
			return sealed
		}()
		return sealed
	}()

}

// HESSIDCodec binds the complete source value type.
func HESSIDCodec() s00.HESSIDValueCodec {
	return func() s00.HESSIDValueCodec {
		sealed := s00.HESSIDValueCodec{}
		*s00.BridgeHESSIDValueCodecFieldPath(&sealed) = "HESSID"
		*s00.BridgeHESSIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.HESSID, error) {
			var zero s00.HESSID
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			octets, err := aper.DecodeOctetStringAligned(bb, 6, 6, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "HESSID"); err != nil {
				return zero, err
			}
			return s00.HESSID(octets), nil
		}
		*s00.BridgeHESSIDValueCodecFieldEncode(&sealed) = func(value s00.HESSID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeOctetStringAligned(bb, []byte(value), 6, 6, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeHESSIDValueCodecFieldCapture(&sealed) = func(v s00.HESSID, options aper.DecodeState) (s00.HESSID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureLPPaHESSID(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeHESSIDValueCodecFieldCompare(&sealed) = func(v s00.HESSID, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaHESSID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeHESSIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HESSID"
			return sealed
		}()
		return sealed
	}()

}

// InterRATMeasurementQuantitiesValueCodec binds the complete source value type.
func InterRATMeasurementQuantitiesValueCodec() s00.InterRATMeasurementQuantitiesValueValueCodec {
	return func() s00.InterRATMeasurementQuantitiesValueValueCodec {
		sealed := s00.InterRATMeasurementQuantitiesValueValueCodec{}
		*s00.BridgeInterRATMeasurementQuantitiesValueValueCodecFieldPath(&sealed) = "InterRATMeasurementQuantitiesValue"
		*s00.BridgeInterRATMeasurementQuantitiesValueValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.InterRATMeasurementQuantitiesValue, error) {
			var zero s00.InterRATMeasurementQuantitiesValue
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 1, Path: "InterRATMeasurementQuantitiesValue"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "InterRATMeasurementQuantitiesValue"); err != nil {
				return zero, err
			}
			return s00.InterRATMeasurementQuantitiesValue(decoded), nil
		}
		*s00.BridgeInterRATMeasurementQuantitiesValueValueCodecFieldEncode(&sealed) = func(value s00.InterRATMeasurementQuantitiesValue, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 2, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeInterRATMeasurementQuantitiesValueValueCodecFieldCapture(&sealed) = func(v s00.InterRATMeasurementQuantitiesValue, options aper.DecodeState) (s00.InterRATMeasurementQuantitiesValue, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaInterRATMeasurementQuantitiesValue(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root,
				false,
			)
			return v, root
		}
		*s00.BridgeInterRATMeasurementQuantitiesValueValueCodecFieldCompare(&sealed) = func(v s00.InterRATMeasurementQuantitiesValue, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaInterRATMeasurementQuantitiesValue(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan()
		}
		*s00.BridgeInterRATMeasurementQuantitiesValueValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InterRATMeasurementQuantitiesValue"
			return sealed
		}()
		return sealed
	}()

}

// MeasurementQuantitiesValueCodec binds the complete source value type.
func MeasurementQuantitiesValueCodec() s00.MeasurementQuantitiesValueValueCodec {
	return func() s00.MeasurementQuantitiesValueValueCodec {
		sealed := s00.MeasurementQuantitiesValueValueCodec{}
		*s00.BridgeMeasurementQuantitiesValueValueCodecFieldPath(&sealed) = "MeasurementQuantitiesValue"
		*s00.BridgeMeasurementQuantitiesValueValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MeasurementQuantitiesValue, error) {
			var zero s00.MeasurementQuantitiesValue
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 6, true, aper.EnumerationSource{KnownExtensions: 0, Path: "MeasurementQuantitiesValue"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "MeasurementQuantitiesValue"); err != nil {
				return zero, err
			}
			return s00.MeasurementQuantitiesValue(decoded), nil
		}
		*s00.BridgeMeasurementQuantitiesValueValueCodecFieldEncode(&sealed) = func(value s00.MeasurementQuantitiesValue, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 6, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeMeasurementQuantitiesValueValueCodecFieldCapture(&sealed) = func(v s00.MeasurementQuantitiesValue, options aper.DecodeState) (s00.MeasurementQuantitiesValue, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaMeasurementQuantitiesValue(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeMeasurementQuantitiesValueValueCodecFieldCompare(&sealed) = func(v s00.MeasurementQuantitiesValue, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaMeasurementQuantitiesValue(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeMeasurementQuantitiesValueValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementQuantitiesValue"
			return sealed
		}()
		return sealed
	}()

}

// NPRSSequenceInfoCodec binds the complete source value type.
func NPRSSequenceInfoCodec() s00.NPRSSequenceInfoValueCodec {
	return func() s00.NPRSSequenceInfoValueCodec {
		sealed := s00.NPRSSequenceInfoValueCodec{}
		*s00.BridgeNPRSSequenceInfoValueCodecFieldPath(&sealed) = "NPRSSequenceInfo"
		*s00.BridgeNPRSSequenceInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NPRSSequenceInfo, error) {
			var zero s00.NPRSSequenceInfo
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound11, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "NPRSSequenceInfo"); err != nil {
				return zero, err
			}
			return s00.NPRSSequenceInfo(decoded), nil
		}
		*s00.BridgeNPRSSequenceInfoValueCodecFieldEncode(&sealed) = func(value s00.NPRSSequenceInfo, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerBigBoundsAligned(bb, value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound11, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeNPRSSequenceInfoValueCodecFieldCapture(&sealed) = func(v s00.NPRSSequenceInfo, options aper.DecodeState) (s00.NPRSSequenceInfo, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureLPPaNPRSSequenceInfo(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root,
				false,
			)
			return v, root
		}
		*s00.BridgeNPRSSequenceInfoValueCodecFieldCompare(&sealed) = func(v s00.NPRSSequenceInfo, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaNPRSSequenceInfo(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeNPRSSequenceInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NPRSSequenceInfo"
			return sealed
		}()
		return sealed
	}()

}

// NRCellIdentityCodec binds the complete source value type.
func NRCellIdentityCodec() s00.NRCellIdentityValueCodec {
	return func() s00.NRCellIdentityValueCodec {
		sealed := s00.NRCellIdentityValueCodec{}
		*s00.BridgeNRCellIdentityValueCodecFieldPath(&sealed) = "NRCellIdentity"
		*s00.BridgeNRCellIdentityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NRCellIdentity, error) {
			var zero s00.NRCellIdentity
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			bits, length, err := aper.DecodeBitStringAligned(bb, 36, 36, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "NRCellIdentity"); err != nil {
				return zero, err
			}
			return s00.NRCellIdentity(runtime.BitString{Bytes: bits, BitLength: length}), nil
		}
		*s00.BridgeNRCellIdentityValueCodecFieldEncode(&sealed) = func(value s00.NRCellIdentity, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeBitStringAligned(bb, value.Bytes, value.BitLength, 36, 36, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeNRCellIdentityValueCodecFieldCapture(&sealed) = func(v s00.NRCellIdentity, options aper.DecodeState) (s00.NRCellIdentity, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaNRCellIdentity(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeNRCellIdentityValueCodecFieldCompare(&sealed) = func(v s00.NRCellIdentity, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaNRCellIdentity(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeNRCellIdentityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRCellIdentity"
			return sealed
		}()
		return sealed
	}()

}

// NarrowBandIndexCodec binds the complete source value type.
func NarrowBandIndexCodec() s00.NarrowBandIndexValueCodec {
	return func() s00.NarrowBandIndexValueCodec {
		sealed := s00.NarrowBandIndexValueCodec{}
		*s00.BridgeNarrowBandIndexValueCodecFieldPath(&sealed) = "NarrowBandIndex"
		*s00.BridgeNarrowBandIndexValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NarrowBandIndex, error) {
			var zero s00.NarrowBandIndex
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound7, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "NarrowBandIndex"); err != nil {
				return zero, err
			}
			return s00.NarrowBandIndex(decoded), nil
		}
		*s00.BridgeNarrowBandIndexValueCodecFieldEncode(&sealed) = func(value s00.NarrowBandIndex, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerBigBoundsAligned(bb, value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound7, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeNarrowBandIndexValueCodecFieldCapture(&sealed) = func(v s00.NarrowBandIndex, options aper.DecodeState) (s00.NarrowBandIndex, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaNarrowBandIndex(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeNarrowBandIndexValueCodecFieldCompare(&sealed) = func(v s00.NarrowBandIndex, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaNarrowBandIndex(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeNarrowBandIndexValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NarrowBandIndex"
			return sealed
		}()
		return sealed
	}()

}

// NumberOfAntennaPortsCodec binds the complete source value type.
func NumberOfAntennaPortsCodec() s00.NumberOfAntennaPortsValueCodec {
	return func() s00.NumberOfAntennaPortsValueCodec {
		sealed := s00.NumberOfAntennaPortsValueCodec{}
		*s00.BridgeNumberOfAntennaPortsValueCodecFieldPath(&sealed) = "NumberOfAntennaPorts"
		*s00.BridgeNumberOfAntennaPortsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NumberOfAntennaPorts, error) {
			var zero s00.NumberOfAntennaPorts
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "NumberOfAntennaPorts"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "NumberOfAntennaPorts"); err != nil {
				return zero, err
			}
			return s00.NumberOfAntennaPorts(decoded), nil
		}
		*s00.BridgeNumberOfAntennaPortsValueCodecFieldEncode(&sealed) = func(value s00.NumberOfAntennaPorts, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 2, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeNumberOfAntennaPortsValueCodecFieldCapture(&sealed) = func(v s00.NumberOfAntennaPorts, options aper.DecodeState) (s00.NumberOfAntennaPorts, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaNumberOfAntennaPorts(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*s00.BridgeNumberOfAntennaPortsValueCodecFieldCompare(&sealed) = func(v s00.NumberOfAntennaPorts, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaNumberOfAntennaPorts(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeNumberOfAntennaPortsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NumberOfAntennaPorts"
			return sealed
		}()
		return sealed
	}()

}

// NumberOfDlFramesCodec binds the complete source value type.
func NumberOfDlFramesCodec() s00.NumberOfDlFramesValueCodec {
	return func() s00.NumberOfDlFramesValueCodec {
		sealed := s00.NumberOfDlFramesValueCodec{}
		*s00.BridgeNumberOfDlFramesValueCodecFieldPath(&sealed) = "NumberOfDlFrames"
		*s00.BridgeNumberOfDlFramesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NumberOfDlFrames, error) {
			var zero s00.NumberOfDlFrames
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 0, Path: "NumberOfDlFrames"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "NumberOfDlFrames"); err != nil {
				return zero, err
			}
			return s00.NumberOfDlFrames(decoded), nil
		}
		*s00.BridgeNumberOfDlFramesValueCodecFieldEncode(&sealed) = func(value s00.NumberOfDlFrames, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 4, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeNumberOfDlFramesValueCodecFieldCapture(&sealed) = func(v s00.NumberOfDlFrames, options aper.DecodeState) (s00.NumberOfDlFrames, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureLPPaNumberOfDlFrames(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root,
				false,
			)
			return v, root
		}
		*s00.BridgeNumberOfDlFramesValueCodecFieldCompare(&sealed) = func(v s00.NumberOfDlFrames, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaNumberOfDlFrames(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeNumberOfDlFramesValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NumberOfDlFrames"
			return sealed
		}()
		return sealed
	}()

}

// NumberOfDlFramesExtendedCodec binds the complete source value type.
func NumberOfDlFramesExtendedCodec() s00.NumberOfDlFramesExtendedValueCodec {
	return func() s00.NumberOfDlFramesExtendedValueCodec {
		sealed := s00.NumberOfDlFramesExtendedValueCodec{}
		*s00.BridgeNumberOfDlFramesExtendedValueCodecFieldPath(&sealed) = "NumberOfDlFramesExtended"
		*s00.BridgeNumberOfDlFramesExtendedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NumberOfDlFramesExtended, error) {
			var zero s00.NumberOfDlFramesExtended
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound2, s00.BridgeAsn1IntegerBound9, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "NumberOfDlFramesExtended"); err != nil {
				return zero, err
			}
			return s00.NumberOfDlFramesExtended(decoded), nil
		}
		*s00.BridgeNumberOfDlFramesExtendedValueCodecFieldEncode(&sealed) = func(value s00.NumberOfDlFramesExtended, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerBigBoundsAligned(bb, value, s00.BridgeAsn1IntegerBound2, s00.BridgeAsn1IntegerBound9, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s00.BridgeNumberOfDlFramesExtendedValueCodecFieldCapture(&sealed) = func(v s00.NumberOfDlFramesExtended, options aper.DecodeState) (s00.NumberOfDlFramesExtended, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaNumberOfDlFramesExtended(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeNumberOfDlFramesExtendedValueCodecFieldCompare(&sealed) = func(v s00.NumberOfDlFramesExtended, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaNumberOfDlFramesExtended(&v, &s)
			s.End(f, root, false)
			return s.
				Plan()
		}
		*s00.BridgeNumberOfDlFramesExtendedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NumberOfDlFramesExtended"
			return sealed
		}()
		return sealed
	}()

}

// NumberOfFrequencyHoppingBandsCodec binds the complete source value type.
func NumberOfFrequencyHoppingBandsCodec() s01.NumberOfFrequencyHoppingBandsValueCodec {
	return func() s01.NumberOfFrequencyHoppingBandsValueCodec {
		sealed := s01.NumberOfFrequencyHoppingBandsValueCodec{}
		*s01.BridgeNumberOfFrequencyHoppingBandsValueCodecFieldPath(&sealed) = "NumberOfFrequencyHoppingBands"
		*s01.BridgeNumberOfFrequencyHoppingBandsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NumberOfFrequencyHoppingBands, error) {
			var zero s00.NumberOfFrequencyHoppingBands
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "NumberOfFrequencyHoppingBands"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "NumberOfFrequencyHoppingBands"); err != nil {
				return zero, err
			}
			return s00.NumberOfFrequencyHoppingBands(decoded), nil
		}
		*s01.BridgeNumberOfFrequencyHoppingBandsValueCodecFieldEncode(&sealed) = func(value s00.NumberOfFrequencyHoppingBands, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 2, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeNumberOfFrequencyHoppingBandsValueCodecFieldCapture(&sealed) = func(v s00.NumberOfFrequencyHoppingBands, options aper.DecodeState) (s00.NumberOfFrequencyHoppingBands, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaNumberOfFrequencyHoppingBands(&v, &s)
			var root aper.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v,

				root
		}
		*s01.BridgeNumberOfFrequencyHoppingBandsValueCodecFieldCompare(&sealed) = func(v s00.NumberOfFrequencyHoppingBands, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaNumberOfFrequencyHoppingBands(&v, &s)
			s.End(f, root, false)

			return s.Plan()
		}
		*s01.BridgeNumberOfFrequencyHoppingBandsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NumberOfFrequencyHoppingBands"
			return sealed
		}()
		return sealed
	}()

}

// OTDOAInformationItemCodec binds the complete source value type.
func OTDOAInformationItemCodec() s01.OTDOAInformationItemValueCodec {
	return func() s01.OTDOAInformationItemValueCodec {
		sealed := s01.OTDOAInformationItemValueCodec{}
		*s01.BridgeOTDOAInformationItemValueCodecFieldPath(&sealed) = "OTDOAInformationItem"
		*s01.BridgeOTDOAInformationItemValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.OTDOAInformationItem, error) {
			var zero s00.OTDOAInformationItem
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 10, true, aper.EnumerationSource{KnownExtensions: 19, Path: "OTDOAInformationItem"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "OTDOAInformationItem"); err != nil {
				return zero, err
			}
			return s00.OTDOAInformationItem(decoded), nil
		}
		*s01.BridgeOTDOAInformationItemValueCodecFieldEncode(&sealed) = func(value s00.OTDOAInformationItem, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 10, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeOTDOAInformationItemValueCodecFieldCapture(&sealed) = func(v s00.OTDOAInformationItem, options aper.DecodeState) (s00.OTDOAInformationItem, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaOTDOAInformationItem(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*s01.BridgeOTDOAInformationItemValueCodecFieldCompare(&sealed) = func(v s00.OTDOAInformationItem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaOTDOAInformationItem(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeOTDOAInformationItemValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOAInformationItem"
			return sealed
		}()
		return sealed
	}()

}

// OffsetNBChanneltoEARFCNCodec binds the complete source value type.
func OffsetNBChanneltoEARFCNCodec() s01.OffsetNBChanneltoEARFCNValueCodec {
	return func() s01.OffsetNBChanneltoEARFCNValueCodec {
		sealed := s01.OffsetNBChanneltoEARFCNValueCodec{}
		*s01.BridgeOffsetNBChanneltoEARFCNValueCodecFieldPath(&sealed) = "OffsetNBChanneltoEARFCN"
		*s01.BridgeOffsetNBChanneltoEARFCNValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.OffsetNBChanneltoEARFCN, error) {
			var zero s00.OffsetNBChanneltoEARFCN
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 21, true, aper.EnumerationSource{KnownExtensions: 0, Path: "OffsetNBChanneltoEARFCN"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "OffsetNBChanneltoEARFCN"); err != nil {
				return zero, err
			}
			return s00.OffsetNBChanneltoEARFCN(decoded), nil
		}
		*s01.BridgeOffsetNBChanneltoEARFCNValueCodecFieldEncode(&sealed) = func(value s00.OffsetNBChanneltoEARFCN, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 21, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeOffsetNBChanneltoEARFCNValueCodecFieldCapture(&sealed) = func(v s00.OffsetNBChanneltoEARFCN, options aper.DecodeState) (s00.OffsetNBChanneltoEARFCN, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaOffsetNBChanneltoEARFCN(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeOffsetNBChanneltoEARFCNValueCodecFieldCompare(&sealed) = func(v s00.OffsetNBChanneltoEARFCN, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaOffsetNBChanneltoEARFCN(&v, &s)
			s.End(f, root, false)
			return s.
				Plan()
		}
		*s01.BridgeOffsetNBChanneltoEARFCNValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:OffsetNBChanneltoEARFCN"
			return sealed
		}()
		return sealed
	}()

}

// OperationModeInfoCodec binds the complete source value type.
func OperationModeInfoCodec() s01.OperationModeInfoValueCodec {
	return func() s01.OperationModeInfoValueCodec {
		sealed := s01.OperationModeInfoValueCodec{}
		*s01.BridgeOperationModeInfoValueCodecFieldPath(&sealed) = "OperationModeInfo"
		*s01.BridgeOperationModeInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.OperationModeInfo, error) {
			var zero s00.OperationModeInfo
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 3, true, aper.EnumerationSource{KnownExtensions: 0, Path: "OperationModeInfo"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "OperationModeInfo"); err != nil {
				return zero, err
			}
			return s00.OperationModeInfo(decoded), nil
		}
		*s01.BridgeOperationModeInfoValueCodecFieldEncode(&sealed) = func(value s00.OperationModeInfo, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 3, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeOperationModeInfoValueCodecFieldCapture(&sealed) = func(v s00.OperationModeInfo, options aper.DecodeState) (s00.OperationModeInfo, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaOperationModeInfo(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root,

				false)
			return v, root
		}
		*s01.BridgeOperationModeInfoValueCodecFieldCompare(&sealed) = func(v s00.OperationModeInfo, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaOperationModeInfo(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeOperationModeInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:OperationModeInfo"
			return sealed
		}()
		return sealed
	}()

}

// OutcomeCodec binds the complete source value type.
func OutcomeCodec() s01.OutcomeValueCodec {
	return func() s01.OutcomeValueCodec {
		sealed := s01.OutcomeValueCodec{}
		*s01.BridgeOutcomeValueCodecFieldPath(&sealed) = "Outcome"
		*s01.BridgeOutcomeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Outcome, error) {
			var zero s00.Outcome
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Outcome"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "Outcome"); err != nil {
				return zero, err
			}
			return s00.Outcome(decoded), nil
		}
		*s01.BridgeOutcomeValueCodecFieldEncode(&sealed) = func(value s00.Outcome, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 1, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgeOutcomeValueCodecFieldCapture(&sealed) = func(v s00.Outcome, options aper.DecodeState) (s00.Outcome, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureLPPaOutcome(&v, &s)
			var root aper.Snapshot
			s.
				OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeOutcomeValueCodecFieldCompare(&sealed) = func(v s00.Outcome, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(
				root, limits)
			f := s.Begin()
			BridgeCompareLPPaOutcome(&v, &s)
			s.
				End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeOutcomeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Outcome"
			return sealed
		}()
		return sealed
	}()

}

// PCICodec binds the complete source value type.
func PCICodec() s01.PCIValueCodec {
	return func() s01.PCIValueCodec {
		sealed := s01.PCIValueCodec{}
		*s01.BridgePCIValueCodecFieldPath(&sealed) = "PCI"
		*s01.BridgePCIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PCI, error) {
			var zero s00.PCI
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound17, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PCI"); err != nil {
				return zero, err
			}
			return s00.PCI(decoded), nil
		}
		*s01.BridgePCIValueCodecFieldEncode(&sealed) = func(value s00.PCI, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerBigBoundsAligned(bb, value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound17, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgePCIValueCodecFieldCapture(&sealed) = func(v s00.PCI, options aper.DecodeState) (s00.PCI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaPCI(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePCIValueCodecFieldCompare(&sealed) = func(v s00.PCI, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaPCI(&v, &s)
			s.End(f, root,
				false)
			return s.Plan()
		}
		*s01.BridgePCIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PCI"
			return sealed
		}()
		return sealed
	}()

}

// PLMNIdentityCodec binds the complete source value type.
func PLMNIdentityCodec() s01.PLMNIdentityValueCodec {
	return func() s01.PLMNIdentityValueCodec {
		sealed := s01.PLMNIdentityValueCodec{}
		*s01.BridgePLMNIdentityValueCodecFieldPath(&sealed) = "PLMNIdentity"
		*s01.BridgePLMNIdentityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PLMNIdentity, error) {
			var zero s00.PLMNIdentity
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			octets, err := aper.DecodeOctetStringAligned(bb, 3, 3, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PLMNIdentity"); err != nil {
				return zero, err
			}
			return s00.PLMNIdentity(octets), nil
		}
		*s01.BridgePLMNIdentityValueCodecFieldEncode(&sealed) = func(value s00.PLMNIdentity, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeOctetStringAligned(bb, []byte(value), 3, 3, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgePLMNIdentityValueCodecFieldCapture(&sealed) = func(v s00.PLMNIdentity, options aper.DecodeState) (s00.PLMNIdentity, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaPLMNIdentity(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePLMNIdentityValueCodecFieldCompare(&sealed) = func(v s00.PLMNIdentity, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaPLMNIdentity(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgePLMNIdentityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PLMNIdentity"
			return sealed
		}()
		return sealed
	}()

}

// PRSBandwidthCodec binds the complete source value type.
func PRSBandwidthCodec() s01.PRSBandwidthValueCodec {
	return func() s01.PRSBandwidthValueCodec {
		sealed := s01.PRSBandwidthValueCodec{}
		*s01.BridgePRSBandwidthValueCodecFieldPath(&sealed) = "PRSBandwidth"
		*s01.BridgePRSBandwidthValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PRSBandwidth, error) {
			var zero s00.PRSBandwidth
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 6, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PRSBandwidth"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PRSBandwidth"); err != nil {
				return zero, err
			}
			return s00.PRSBandwidth(decoded), nil
		}
		*s01.BridgePRSBandwidthValueCodecFieldEncode(&sealed) = func(value s00.PRSBandwidth, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 6, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgePRSBandwidthValueCodecFieldCapture(&sealed) = func(v s00.PRSBandwidth, options aper.DecodeState) (s00.PRSBandwidth, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaPRSBandwidth(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePRSBandwidthValueCodecFieldCompare(&sealed) = func(v s00.PRSBandwidth, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaPRSBandwidth(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgePRSBandwidthValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PRSBandwidth"
			return sealed
		}()
		return sealed
	}()

}

// PRSConfigurationIndexCodec binds the complete source value type.
func PRSConfigurationIndexCodec() s01.PRSConfigurationIndexValueCodec {
	return func() s01.PRSConfigurationIndexValueCodec {
		sealed := s01.PRSConfigurationIndexValueCodec{}
		*s01.BridgePRSConfigurationIndexValueCodecFieldPath(&sealed) = "PRSConfigurationIndex"
		*s01.BridgePRSConfigurationIndexValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PRSConfigurationIndex, error) {
			var zero s00.PRSConfigurationIndex
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound14, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PRSConfigurationIndex"); err != nil {
				return zero, err
			}
			return s00.PRSConfigurationIndex(decoded), nil
		}
		*s01.BridgePRSConfigurationIndexValueCodecFieldEncode(&sealed) = func(value s00.PRSConfigurationIndex, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerBigBoundsAligned(bb, value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound14, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgePRSConfigurationIndexValueCodecFieldCapture(&sealed) = func(v s00.PRSConfigurationIndex, options aper.DecodeState) (s00.PRSConfigurationIndex, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaPRSConfigurationIndex(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*s01.BridgePRSConfigurationIndexValueCodecFieldCompare(&sealed) = func(v s00.PRSConfigurationIndex, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaPRSConfigurationIndex(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgePRSConfigurationIndexValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PRSConfigurationIndex"
			return sealed
		}()
		return sealed
	}()

}

// PRSIDCodec binds the complete source value type.
func PRSIDCodec() s01.PRSIDValueCodec {
	return func() s01.PRSIDValueCodec {
		sealed := s01.PRSIDValueCodec{}
		*s01.BridgePRSIDValueCodecFieldPath(&sealed) = "PRSID"
		*s01.BridgePRSIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PRSID, error) {
			var zero s00.PRSID
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound14, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PRSID"); err != nil {
				return zero, err
			}
			return s00.PRSID(decoded), nil
		}
		*s01.BridgePRSIDValueCodecFieldEncode(&sealed) = func(value s00.PRSID, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerBigBoundsAligned(bb, value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound14, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgePRSIDValueCodecFieldCapture(&sealed) = func(v s00.PRSID, options aper.DecodeState) (s00.PRSID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaPRSID(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePRSIDValueCodecFieldCompare(&sealed) = func(v s00.PRSID, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaPRSID(&v, &s)
			s.End(
				f, root, false)
			return s.Plan()
		}
		*s01.BridgePRSIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PRSID"
			return sealed
		}()
		return sealed
	}()

}

// PRSOccasionGroupCodec binds the complete source value type.
func PRSOccasionGroupCodec() s01.PRSOccasionGroupValueCodec {
	return func() s01.PRSOccasionGroupValueCodec {
		sealed := s01.PRSOccasionGroupValueCodec{}
		*s01.BridgePRSOccasionGroupValueCodecFieldPath(&sealed) = "PRSOccasionGroup"
		*s01.BridgePRSOccasionGroupValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PRSOccasionGroup, error) {
			var zero s00.PRSOccasionGroup
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 7, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PRSOccasionGroup"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PRSOccasionGroup"); err != nil {
				return zero, err
			}
			return s00.PRSOccasionGroup(decoded), nil
		}
		*s01.BridgePRSOccasionGroupValueCodecFieldEncode(&sealed) = func(value s00.PRSOccasionGroup, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 7, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgePRSOccasionGroupValueCodecFieldCapture(&sealed) = func(v s00.PRSOccasionGroup, options aper.DecodeState) (s00.PRSOccasionGroup, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureLPPaPRSOccasionGroup(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root,
				false,
			)
			return v, root
		}
		*s01.BridgePRSOccasionGroupValueCodecFieldCompare(&sealed) = func(v s00.PRSOccasionGroup, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaPRSOccasionGroup(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgePRSOccasionGroupValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PRSOccasionGroup"
			return sealed
		}()
		return sealed
	}()

}

// PhysCellIDGERANCodec binds the complete source value type.
func PhysCellIDGERANCodec() s01.PhysCellIDGERANValueCodec {
	return func() s01.PhysCellIDGERANValueCodec {
		sealed := s01.PhysCellIDGERANValueCodec{}
		*s01.BridgePhysCellIDGERANValueCodecFieldPath(&sealed) = "PhysCellIDGERAN"
		*s01.BridgePhysCellIDGERANValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PhysCellIDGERAN, error) {
			var zero s00.PhysCellIDGERAN
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound19, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PhysCellIDGERAN"); err != nil {
				return zero, err
			}
			return s00.PhysCellIDGERAN(decoded), nil
		}
		*s01.BridgePhysCellIDGERANValueCodecFieldEncode(&sealed) = func(value s00.PhysCellIDGERAN, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerBigBoundsAligned(bb, value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound19, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgePhysCellIDGERANValueCodecFieldCapture(&sealed) = func(v s00.PhysCellIDGERAN, options aper.DecodeState) (s00.PhysCellIDGERAN, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaPhysCellIDGERAN(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePhysCellIDGERANValueCodecFieldCompare(&sealed) = func(v s00.PhysCellIDGERAN, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaPhysCellIDGERAN(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgePhysCellIDGERANValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PhysCellIDGERAN"
			return sealed
		}()
		return sealed
	}()

}

// PhysCellIDUTRAFDDCodec binds the complete source value type.
func PhysCellIDUTRAFDDCodec() s01.PhysCellIDUTRAFDDValueCodec {
	return func() s01.PhysCellIDUTRAFDDValueCodec {
		sealed := s01.PhysCellIDUTRAFDDValueCodec{}
		*s01.BridgePhysCellIDUTRAFDDValueCodecFieldPath(&sealed) = "PhysCellIDUTRAFDD"
		*s01.BridgePhysCellIDUTRAFDDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PhysCellIDUTRAFDD, error) {
			var zero s00.PhysCellIDUTRAFDD
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound18, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PhysCellIDUTRAFDD"); err != nil {
				return zero, err
			}
			return s00.PhysCellIDUTRAFDD(decoded), nil
		}
		*s01.BridgePhysCellIDUTRAFDDValueCodecFieldEncode(&sealed) = func(value s00.PhysCellIDUTRAFDD, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerBigBoundsAligned(bb, value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound18, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgePhysCellIDUTRAFDDValueCodecFieldCapture(&sealed) = func(v s00.PhysCellIDUTRAFDD, options aper.DecodeState) (s00.PhysCellIDUTRAFDD, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaPhysCellIDUTRAFDD(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root,

				false)
			return v, root
		}
		*s01.BridgePhysCellIDUTRAFDDValueCodecFieldCompare(&sealed) = func(v s00.PhysCellIDUTRAFDD, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaPhysCellIDUTRAFDD(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgePhysCellIDUTRAFDDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PhysCellIDUTRAFDD"
			return sealed
		}()
		return sealed
	}()

}

// PhysCellIDUTRATDDCodec binds the complete source value type.
func PhysCellIDUTRATDDCodec() s01.PhysCellIDUTRATDDValueCodec {
	return func() s01.PhysCellIDUTRATDDValueCodec {
		sealed := s01.PhysCellIDUTRATDDValueCodec{}
		*s01.BridgePhysCellIDUTRATDDValueCodecFieldPath(&sealed) = "PhysCellIDUTRATDD"
		*s01.BridgePhysCellIDUTRATDDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PhysCellIDUTRATDD, error) {
			var zero s00.PhysCellIDUTRATDD
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound5, true)
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PhysCellIDUTRATDD"); err != nil {
				return zero, err
			}
			return s00.PhysCellIDUTRATDD(decoded), nil
		}
		*s01.BridgePhysCellIDUTRATDDValueCodecFieldEncode(&sealed) = func(value s00.PhysCellIDUTRATDD, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeIntegerBigBoundsAligned(bb, value, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound5, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgePhysCellIDUTRATDDValueCodecFieldCapture(&sealed) = func(v s00.PhysCellIDUTRATDD, options aper.DecodeState) (s00.PhysCellIDUTRATDD, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaPhysCellIDUTRATDD(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root,

				false)
			return v, root
		}
		*s01.BridgePhysCellIDUTRATDDValueCodecFieldCompare(&sealed) = func(v s00.PhysCellIDUTRATDD, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaPhysCellIDUTRATDD(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgePhysCellIDUTRATDDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PhysCellIDUTRATDD"
			return sealed
		}()
		return sealed
	}()

}

// PosSIBTypeCodec binds the complete source value type.
func PosSIBTypeCodec() s01.PosSIBTypeValueCodec {
	return func() s01.PosSIBTypeValueCodec {
		sealed := s01.PosSIBTypeValueCodec{}
		*s01.BridgePosSIBTypeValueCodecFieldPath(&sealed) = "PosSIBType"
		*s01.BridgePosSIBTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PosSIBType, error) {
			var zero s00.PosSIBType
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := aper.DecodeEnumeratedAligned(bb, 27, true, aper.EnumerationSource{KnownExtensions: 4, Path: "PosSIBType"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "PosSIBType"); err != nil {
				return zero, err
			}
			return s00.PosSIBType(decoded), nil
		}
		*s01.BridgePosSIBTypeValueCodecFieldEncode(&sealed) = func(value s00.PosSIBType, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 27, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgePosSIBTypeValueCodecFieldCapture(&sealed) = func(v s00.PosSIBType, options aper.DecodeState) (s00.PosSIBType, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s00.BridgeCaptureLPPaPosSIBType(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root

		}
		*s01.BridgePosSIBTypeValueCodecFieldCompare(&sealed) = func(v s00.PosSIBType, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaPosSIBType(&v,
				&s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgePosSIBTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PosSIBType"
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
			decoded, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Presence"})
			if err != nil {
				return zero, err
			}
			if _, err := aper.CaptureFinalBits(bb, "Presence"); err != nil {
				return zero, err
			}
			return s00.Presence(decoded), nil
		}
		*s01.BridgePresenceValueCodecFieldEncode(&sealed) = func(value s00.Presence, _ bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := aper.EncodeEnumeratedAligned(bb, int64(value), 3, false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s01.BridgePresenceValueCodecFieldCapture(&sealed) = func(v s00.Presence, options aper.DecodeState) (s00.Presence, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureLPPaPresence(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePresenceValueCodecFieldCompare(&sealed) = func(v s00.Presence, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaPresence(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgePresenceValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Presence"
			return sealed
		}()
		return sealed
	}()

}
func BridgeAddOTDOACellsExtIEsValueFieldId(v *AddOTDOACellsExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeAddOTDOACellsExtIEsValueFieldIsOpaque(v *AddOTDOACellsExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeAddOTDOACellsExtIEsValueFieldOpaque(v *AddOTDOACellsExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeAddOTDOACellsExtIEsValueFieldReceived(v *AddOTDOACellsExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeAddOTDOACellsExtIEsValueFieldReplay(v *AddOTDOACellsExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAddOTDOACellsExtIEsValueFieldWithoutReplay(v *AddOTDOACellsExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeAddOTDOACellsExtIEsValueMethodCaptureFraming(v AddOTDOACellsExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeAddOTDOACellsExtIEsValueMethodCaptureSemantics(v AddOTDOACellsExtIEsValue, a0 aper.SemanticCapture) AddOTDOACellsExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeAddOTDOACellsExtIEsValueMethodCaptureSnapshot(v AddOTDOACellsExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeAddOTDOACellsExtIEsValueMethodCompareSemantics(v AddOTDOACellsExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeAddOTDOACellsExtIEsValueMethodDecode(v AddOTDOACellsExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (AddOTDOACellsExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeAddOTDOACellsExtIEsValueMethodEncode(v AddOTDOACellsExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeAddOTDOACellsExtIEsValueMethodEncodeFresh(v AddOTDOACellsExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeAddOTDOACellsExtIEsValueMethodMatchesID(v AddOTDOACellsExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeAddOTDOACellsExtIEsValueMethodReason(v AddOTDOACellsExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeAddOTDOACellsExtIEsValueMethodRule(v AddOTDOACellsExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeAssistanceInformationExtIEsValueFieldId(v *AssistanceInformationExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeAssistanceInformationExtIEsValueFieldIsOpaque(v *AssistanceInformationExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeAssistanceInformationExtIEsValueFieldOpaque(v *AssistanceInformationExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeAssistanceInformationExtIEsValueFieldReceived(v *AssistanceInformationExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationExtIEsValueFieldReplay(v *AssistanceInformationExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationExtIEsValueFieldWithoutReplay(v *AssistanceInformationExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationExtIEsValueMethodCaptureFraming(v AssistanceInformationExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeAssistanceInformationExtIEsValueMethodCaptureSemantics(v AssistanceInformationExtIEsValue, a0 aper.SemanticCapture) AssistanceInformationExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeAssistanceInformationExtIEsValueMethodCaptureSnapshot(v AssistanceInformationExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeAssistanceInformationExtIEsValueMethodCompareSemantics(v AssistanceInformationExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeAssistanceInformationExtIEsValueMethodDecode(v AssistanceInformationExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (AssistanceInformationExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeAssistanceInformationExtIEsValueMethodEncode(v AssistanceInformationExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeAssistanceInformationExtIEsValueMethodEncodeFresh(v AssistanceInformationExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeAssistanceInformationExtIEsValueMethodMatchesID(v AssistanceInformationExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeAssistanceInformationExtIEsValueMethodReason(v AssistanceInformationExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeAssistanceInformationExtIEsValueMethodRule(v AssistanceInformationExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeAssistanceInformationFailureListExtIEsValueFieldId(v *AssistanceInformationFailureListExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeAssistanceInformationFailureListExtIEsValueFieldIsOpaque(v *AssistanceInformationFailureListExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeAssistanceInformationFailureListExtIEsValueFieldOpaque(v *AssistanceInformationFailureListExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeAssistanceInformationFailureListExtIEsValueFieldReceived(v *AssistanceInformationFailureListExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationFailureListExtIEsValueFieldReplay(v *AssistanceInformationFailureListExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFailureListExtIEsValueFieldWithoutReplay(v *AssistanceInformationFailureListExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodCaptureFraming(v AssistanceInformationFailureListExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodCaptureSemantics(v AssistanceInformationFailureListExtIEsValue, a0 aper.SemanticCapture) AssistanceInformationFailureListExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodCaptureSnapshot(v AssistanceInformationFailureListExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodCompareSemantics(v AssistanceInformationFailureListExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodDecode(v AssistanceInformationFailureListExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (AssistanceInformationFailureListExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodEncode(v AssistanceInformationFailureListExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodEncodeFresh(v AssistanceInformationFailureListExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodMatchesID(v AssistanceInformationFailureListExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodReason(v AssistanceInformationFailureListExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodRule(v AssistanceInformationFailureListExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeAssistanceInformationMetaDataExtIEsValueFieldId(v *AssistanceInformationMetaDataExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeAssistanceInformationMetaDataExtIEsValueFieldIsOpaque(v *AssistanceInformationMetaDataExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeAssistanceInformationMetaDataExtIEsValueFieldOpaque(v *AssistanceInformationMetaDataExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeAssistanceInformationMetaDataExtIEsValueFieldReceived(v *AssistanceInformationMetaDataExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationMetaDataExtIEsValueFieldReplay(v *AssistanceInformationMetaDataExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationMetaDataExtIEsValueFieldWithoutReplay(v *AssistanceInformationMetaDataExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodCaptureFraming(v AssistanceInformationMetaDataExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodCaptureSemantics(v AssistanceInformationMetaDataExtIEsValue, a0 aper.SemanticCapture) AssistanceInformationMetaDataExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodCaptureSnapshot(v AssistanceInformationMetaDataExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodCompareSemantics(v AssistanceInformationMetaDataExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodDecode(v AssistanceInformationMetaDataExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (AssistanceInformationMetaDataExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodEncode(v AssistanceInformationMetaDataExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodEncodeFresh(v AssistanceInformationMetaDataExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodMatchesID(v AssistanceInformationMetaDataExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodReason(v AssistanceInformationMetaDataExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodRule(v AssistanceInformationMetaDataExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeCriticalityDiagnosticsExtIEsValueFieldId(v *CriticalityDiagnosticsExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeCriticalityDiagnosticsExtIEsValueFieldIsOpaque(v *CriticalityDiagnosticsExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeCriticalityDiagnosticsExtIEsValueFieldOpaque(v *CriticalityDiagnosticsExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeCriticalityDiagnosticsExtIEsValueFieldReceived(v *CriticalityDiagnosticsExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeCriticalityDiagnosticsExtIEsValueFieldReplay(v *CriticalityDiagnosticsExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsExtIEsValueFieldWithoutReplay(v *CriticalityDiagnosticsExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodCaptureFraming(v CriticalityDiagnosticsExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodCaptureSemantics(v CriticalityDiagnosticsExtIEsValue, a0 aper.SemanticCapture) CriticalityDiagnosticsExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodCaptureSnapshot(v CriticalityDiagnosticsExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodCompareSemantics(v CriticalityDiagnosticsExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodDecode(v CriticalityDiagnosticsExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (CriticalityDiagnosticsExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodEncode(v CriticalityDiagnosticsExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodEncodeFresh(v CriticalityDiagnosticsExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodMatchesID(v CriticalityDiagnosticsExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodReason(v CriticalityDiagnosticsExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodRule(v CriticalityDiagnosticsExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueFieldId(v *CriticalityDiagnosticsIEListExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueFieldIsOpaque(v *CriticalityDiagnosticsIEListExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueFieldOpaque(v *CriticalityDiagnosticsIEListExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueFieldReceived(v *CriticalityDiagnosticsIEListExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueFieldReplay(v *CriticalityDiagnosticsIEListExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueFieldWithoutReplay(v *CriticalityDiagnosticsIEListExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodCaptureFraming(v CriticalityDiagnosticsIEListExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodCaptureSemantics(v CriticalityDiagnosticsIEListExtIEsValue, a0 aper.SemanticCapture) CriticalityDiagnosticsIEListExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodCaptureSnapshot(v CriticalityDiagnosticsIEListExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodCompareSemantics(v CriticalityDiagnosticsIEListExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodDecode(v CriticalityDiagnosticsIEListExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (CriticalityDiagnosticsIEListExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodEncode(v CriticalityDiagnosticsIEListExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodEncodeFresh(v CriticalityDiagnosticsIEListExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodMatchesID(v CriticalityDiagnosticsIEListExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodReason(v CriticalityDiagnosticsIEListExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodRule(v CriticalityDiagnosticsIEListExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeECGIExtIEsValueFieldId(v *ECGIExtIEsValue) *s00.ProtocolIEID         { return &v.id }
func BridgeECGIExtIEsValueFieldIsOpaque(v *ECGIExtIEsValue) *bool               { return &v.isOpaque }
func BridgeECGIExtIEsValueFieldOpaque(v *ECGIExtIEsValue) **aper.OpaqueOpenType { return &v.opaque }
func BridgeECGIExtIEsValueFieldReceived(v *ECGIExtIEsValue) *aper.WireSpan      { return &v.received }
func BridgeECGIExtIEsValueFieldReplay(v *ECGIExtIEsValue) *aper.Snapshot        { return &v.replay }
func BridgeECGIExtIEsValueFieldWithoutReplay(v *ECGIExtIEsValue) *bool          { return &v.withoutReplay }
func BridgeECGIExtIEsValueMethodCaptureFraming(v ECGIExtIEsValue) uint64        { return v.captureFraming() }
func BridgeECGIExtIEsValueMethodCaptureSemantics(v ECGIExtIEsValue, a0 aper.SemanticCapture) ECGIExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeECGIExtIEsValueMethodCaptureSnapshot(v ECGIExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeECGIExtIEsValueMethodCompareSemantics(v ECGIExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeECGIExtIEsValueMethodDecode(v ECGIExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ECGIExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeECGIExtIEsValueMethodEncode(v ECGIExtIEsValue) ([]byte, error) { return v.encode() }
func BridgeECGIExtIEsValueMethodEncodeFresh(v ECGIExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeECGIExtIEsValueMethodMatchesID(v ECGIExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeECGIExtIEsValueMethodReason(v ECGIExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeECGIExtIEsValueMethodRule(v ECGIExtIEsValue) aper.SourceRule { return v.rule() }
func BridgeECIDMeasurementTerminationCommandIEValueFieldId(v *ECIDMeasurementTerminationCommandIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeECIDMeasurementTerminationCommandIEValueFieldIsOpaque(v *ECIDMeasurementTerminationCommandIEValue) *bool {
	return &v.isOpaque
}
func BridgeECIDMeasurementTerminationCommandIEValueFieldOpaque(v *ECIDMeasurementTerminationCommandIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeECIDMeasurementTerminationCommandIEValueFieldReceived(v *ECIDMeasurementTerminationCommandIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementTerminationCommandIEValueFieldReplay(v *ECIDMeasurementTerminationCommandIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementTerminationCommandIEValueFieldRowENBUEMeasurementID(v *ECIDMeasurementTerminationCommandIEValue) **s00.MeasurementID {
	return &v.rowENBUEMeasurementID
}
func BridgeECIDMeasurementTerminationCommandIEValueFieldRowESMLCUEMeasurementID(v *ECIDMeasurementTerminationCommandIEValue) **s00.MeasurementID {
	return &v.rowESMLCUEMeasurementID
}
func BridgeECIDMeasurementTerminationCommandIEValueFieldWithoutReplay(v *ECIDMeasurementTerminationCommandIEValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodCaptureFraming(v ECIDMeasurementTerminationCommandIEValue) uint64 {
	return v.captureFraming()
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodCaptureSemantics(v ECIDMeasurementTerminationCommandIEValue, a0 aper.SemanticCapture) ECIDMeasurementTerminationCommandIEValue {
	return v.captureSemantics(a0)
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodCaptureSnapshot(v ECIDMeasurementTerminationCommandIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodCompareSemantics(v ECIDMeasurementTerminationCommandIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodDecode(v ECIDMeasurementTerminationCommandIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ECIDMeasurementTerminationCommandIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodEncode(v ECIDMeasurementTerminationCommandIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodEncodeFresh(v ECIDMeasurementTerminationCommandIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodMatchesID(v ECIDMeasurementTerminationCommandIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodReason(v ECIDMeasurementTerminationCommandIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodRule(v ECIDMeasurementTerminationCommandIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueFieldId(v *InterRATMeasurementQuantitiesValueExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueFieldIsOpaque(v *InterRATMeasurementQuantitiesValueExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueFieldOpaque(v *InterRATMeasurementQuantitiesValueExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueFieldReceived(v *InterRATMeasurementQuantitiesValueExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueFieldReplay(v *InterRATMeasurementQuantitiesValueExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueFieldWithoutReplay(v *InterRATMeasurementQuantitiesValueExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodCaptureFraming(v InterRATMeasurementQuantitiesValueExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodCaptureSemantics(v InterRATMeasurementQuantitiesValueExtIEsValue, a0 aper.SemanticCapture) InterRATMeasurementQuantitiesValueExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodCaptureSnapshot(v InterRATMeasurementQuantitiesValueExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodCompareSemantics(v InterRATMeasurementQuantitiesValueExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodDecode(v InterRATMeasurementQuantitiesValueExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (InterRATMeasurementQuantitiesValueExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodEncode(v InterRATMeasurementQuantitiesValueExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodEncodeFresh(v InterRATMeasurementQuantitiesValueExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodMatchesID(v InterRATMeasurementQuantitiesValueExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodReason(v InterRATMeasurementQuantitiesValueExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodRule(v InterRATMeasurementQuantitiesValueExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeMeasurementQuantitiesValueExtIEsValueFieldId(v *MeasurementQuantitiesValueExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeMeasurementQuantitiesValueExtIEsValueFieldIsOpaque(v *MeasurementQuantitiesValueExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeMeasurementQuantitiesValueExtIEsValueFieldOpaque(v *MeasurementQuantitiesValueExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeMeasurementQuantitiesValueExtIEsValueFieldReceived(v *MeasurementQuantitiesValueExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeMeasurementQuantitiesValueExtIEsValueFieldReplay(v *MeasurementQuantitiesValueExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMeasurementQuantitiesValueExtIEsValueFieldWithoutReplay(v *MeasurementQuantitiesValueExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodCaptureFraming(v MeasurementQuantitiesValueExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodCaptureSemantics(v MeasurementQuantitiesValueExtIEsValue, a0 aper.SemanticCapture) MeasurementQuantitiesValueExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodCaptureSnapshot(v MeasurementQuantitiesValueExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodCompareSemantics(v MeasurementQuantitiesValueExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodDecode(v MeasurementQuantitiesValueExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (MeasurementQuantitiesValueExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodEncode(v MeasurementQuantitiesValueExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodEncodeFresh(v MeasurementQuantitiesValueExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodMatchesID(v MeasurementQuantitiesValueExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodReason(v MeasurementQuantitiesValueExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodRule(v MeasurementQuantitiesValueExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeNRCGIExtIEsValueFieldId(v *NRCGIExtIEsValue) *s00.ProtocolIEID         { return &v.id }
func BridgeNRCGIExtIEsValueFieldIsOpaque(v *NRCGIExtIEsValue) *bool               { return &v.isOpaque }
func BridgeNRCGIExtIEsValueFieldOpaque(v *NRCGIExtIEsValue) **aper.OpaqueOpenType { return &v.opaque }
func BridgeNRCGIExtIEsValueFieldReceived(v *NRCGIExtIEsValue) *aper.WireSpan      { return &v.received }
func BridgeNRCGIExtIEsValueFieldReplay(v *NRCGIExtIEsValue) *aper.Snapshot        { return &v.replay }
func BridgeNRCGIExtIEsValueFieldWithoutReplay(v *NRCGIExtIEsValue) *bool          { return &v.withoutReplay }
func BridgeNRCGIExtIEsValueMethodCaptureFraming(v NRCGIExtIEsValue) uint64        { return v.captureFraming() }
func BridgeNRCGIExtIEsValueMethodCaptureSemantics(v NRCGIExtIEsValue, a0 aper.SemanticCapture) NRCGIExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeNRCGIExtIEsValueMethodCaptureSnapshot(v NRCGIExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeNRCGIExtIEsValueMethodCompareSemantics(v NRCGIExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeNRCGIExtIEsValueMethodDecode(v NRCGIExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (NRCGIExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeNRCGIExtIEsValueMethodEncode(v NRCGIExtIEsValue) ([]byte, error) { return v.encode() }
func BridgeNRCGIExtIEsValueMethodEncodeFresh(v NRCGIExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeNRCGIExtIEsValueMethodMatchesID(v NRCGIExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeNRCGIExtIEsValueMethodReason(v NRCGIExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeNRCGIExtIEsValueMethodRule(v NRCGIExtIEsValue) aper.SourceRule           { return v.rule() }
func BridgeOTDOACellsExtIEsValueFieldId(v *OTDOACellsExtIEsValue) *s00.ProtocolIEID { return &v.id }
func BridgeOTDOACellsExtIEsValueFieldIsOpaque(v *OTDOACellsExtIEsValue) *bool       { return &v.isOpaque }
func BridgeOTDOACellsExtIEsValueFieldOpaque(v *OTDOACellsExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeOTDOACellsExtIEsValueFieldReceived(v *OTDOACellsExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeOTDOACellsExtIEsValueFieldReplay(v *OTDOACellsExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOACellsExtIEsValueFieldWithoutReplay(v *OTDOACellsExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOACellsExtIEsValueMethodCaptureFraming(v OTDOACellsExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeOTDOACellsExtIEsValueMethodCaptureSemantics(v OTDOACellsExtIEsValue, a0 aper.SemanticCapture) OTDOACellsExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeOTDOACellsExtIEsValueMethodCaptureSnapshot(v OTDOACellsExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeOTDOACellsExtIEsValueMethodCompareSemantics(v OTDOACellsExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeOTDOACellsExtIEsValueMethodDecode(v OTDOACellsExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (OTDOACellsExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeOTDOACellsExtIEsValueMethodEncode(v OTDOACellsExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeOTDOACellsExtIEsValueMethodEncodeFresh(v OTDOACellsExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeOTDOACellsExtIEsValueMethodMatchesID(v OTDOACellsExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeOTDOACellsExtIEsValueMethodReason(v OTDOACellsExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeOTDOACellsExtIEsValueMethodRule(v OTDOACellsExtIEsValue) aper.SourceRule { return v.rule() }
func BridgeOTDOAInformationTypeItemExtIEsValueFieldId(v *OTDOAInformationTypeItemExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeOTDOAInformationTypeItemExtIEsValueFieldIsOpaque(v *OTDOAInformationTypeItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeOTDOAInformationTypeItemExtIEsValueFieldOpaque(v *OTDOAInformationTypeItemExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeOTDOAInformationTypeItemExtIEsValueFieldReceived(v *OTDOAInformationTypeItemExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationTypeItemExtIEsValueFieldReplay(v *OTDOAInformationTypeItemExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationTypeItemExtIEsValueFieldWithoutReplay(v *OTDOAInformationTypeItemExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodCaptureFraming(v OTDOAInformationTypeItemExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodCaptureSemantics(v OTDOAInformationTypeItemExtIEsValue, a0 aper.SemanticCapture) OTDOAInformationTypeItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodCaptureSnapshot(v OTDOAInformationTypeItemExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodCompareSemantics(v OTDOAInformationTypeItemExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodDecode(v OTDOAInformationTypeItemExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (OTDOAInformationTypeItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodEncode(v OTDOAInformationTypeItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodEncodeFresh(v OTDOAInformationTypeItemExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodMatchesID(v OTDOAInformationTypeItemExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodReason(v OTDOAInformationTypeItemExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodRule(v OTDOAInformationTypeItemExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueFieldId(v *PRSFrequencyHoppingConfigurationItemIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueFieldIsOpaque(v *PRSFrequencyHoppingConfigurationItemIEsValue) *bool {
	return &v.isOpaque
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueFieldOpaque(v *PRSFrequencyHoppingConfigurationItemIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueFieldReceived(v *PRSFrequencyHoppingConfigurationItemIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueFieldReplay(v *PRSFrequencyHoppingConfigurationItemIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueFieldWithoutReplay(v *PRSFrequencyHoppingConfigurationItemIEsValue) *bool {
	return &v.withoutReplay
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodCaptureFraming(v PRSFrequencyHoppingConfigurationItemIEsValue) uint64 {
	return v.captureFraming()
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodCaptureSemantics(v PRSFrequencyHoppingConfigurationItemIEsValue, a0 aper.SemanticCapture) PRSFrequencyHoppingConfigurationItemIEsValue {
	return v.captureSemantics(a0)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodCaptureSnapshot(v PRSFrequencyHoppingConfigurationItemIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodCompareSemantics(v PRSFrequencyHoppingConfigurationItemIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodDecode(v PRSFrequencyHoppingConfigurationItemIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (PRSFrequencyHoppingConfigurationItemIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodEncode(v PRSFrequencyHoppingConfigurationItemIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodEncodeFresh(v PRSFrequencyHoppingConfigurationItemIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodMatchesID(v PRSFrequencyHoppingConfigurationItemIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodReason(v PRSFrequencyHoppingConfigurationItemIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodRule(v PRSFrequencyHoppingConfigurationItemIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgePosSIBSegmentsExtIEsValueFieldId(v *PosSIBSegmentsExtIEsValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgePosSIBSegmentsExtIEsValueFieldIsOpaque(v *PosSIBSegmentsExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgePosSIBSegmentsExtIEsValueFieldOpaque(v *PosSIBSegmentsExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgePosSIBSegmentsExtIEsValueFieldReceived(v *PosSIBSegmentsExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgePosSIBSegmentsExtIEsValueFieldReplay(v *PosSIBSegmentsExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgePosSIBSegmentsExtIEsValueFieldWithoutReplay(v *PosSIBSegmentsExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgePosSIBSegmentsExtIEsValueMethodCaptureFraming(v PosSIBSegmentsExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgePosSIBSegmentsExtIEsValueMethodCaptureSemantics(v PosSIBSegmentsExtIEsValue, a0 aper.SemanticCapture) PosSIBSegmentsExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgePosSIBSegmentsExtIEsValueMethodCaptureSnapshot(v PosSIBSegmentsExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgePosSIBSegmentsExtIEsValueMethodCompareSemantics(v PosSIBSegmentsExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgePosSIBSegmentsExtIEsValueMethodDecode(v PosSIBSegmentsExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (PosSIBSegmentsExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgePosSIBSegmentsExtIEsValueMethodEncode(v PosSIBSegmentsExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgePosSIBSegmentsExtIEsValueMethodEncodeFresh(v PosSIBSegmentsExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgePosSIBSegmentsExtIEsValueMethodMatchesID(v PosSIBSegmentsExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgePosSIBSegmentsExtIEsValueMethodReason(v PosSIBSegmentsExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgePosSIBSegmentsExtIEsValueMethodRule(v PosSIBSegmentsExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeWLANCountryCodeValueCodecFieldCapture(v *WLANCountryCodeValueCodec) *func(s00.WLANCountryCode, aper.DecodeState) (s00.WLANCountryCode, aper.Snapshot) {
	return &v.capture
}
func BridgeWLANCountryCodeValueCodecFieldCompare(v *WLANCountryCodeValueCodec) *func(s00.WLANCountryCode, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeWLANCountryCodeValueCodecFieldContext(v *WLANCountryCodeValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANCountryCodeValueCodecFieldDecode(v *WLANCountryCodeValueCodec) *func([]byte, aper.DecodeState) (s00.WLANCountryCode, error) {
	return &v.decode
}
func BridgeWLANCountryCodeValueCodecFieldEncode(v *WLANCountryCodeValueCodec) *func(s00.WLANCountryCode, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANCountryCodeValueCodecFieldPath(v *WLANCountryCodeValueCodec) *aper.Path {
	return &v.path
}
func BridgeWLANCountryCodeValueCodecMethodEncodeBudget(v WLANCountryCodeValueCodec, a0 s00.WLANCountryCode, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANCountryCodeValueCodecMethodEncodeChanged(v WLANCountryCodeValueCodec, a0 s00.WLANCountryCode, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANMeasurementQuantitiesValueAPERValueFieldContext(v *WLANMeasurementQuantitiesValueAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementQuantitiesValueAPERValueFieldReceived(v *WLANMeasurementQuantitiesValueAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesValueAPERValueFieldReplay(v *WLANMeasurementQuantitiesValueAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesValueAPERValueFieldWithoutReplay(v *WLANMeasurementQuantitiesValueAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesValueValueCodecFieldCapture(v *WLANMeasurementQuantitiesValueValueCodec) *func(s00.WLANMeasurementQuantitiesValue, aper.DecodeState) (s00.WLANMeasurementQuantitiesValue, aper.Snapshot) {
	return &v.capture
}
func BridgeWLANMeasurementQuantitiesValueValueCodecFieldCompare(v *WLANMeasurementQuantitiesValueValueCodec) *func(s00.WLANMeasurementQuantitiesValue, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeWLANMeasurementQuantitiesValueValueCodecFieldContext(v *WLANMeasurementQuantitiesValueValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementQuantitiesValueValueCodecFieldDecode(v *WLANMeasurementQuantitiesValueValueCodec) *func([]byte, aper.DecodeState) (s00.WLANMeasurementQuantitiesValue, error) {
	return &v.decode
}
func BridgeWLANMeasurementQuantitiesValueValueCodecFieldEncode(v *WLANMeasurementQuantitiesValueValueCodec) *func(s00.WLANMeasurementQuantitiesValue, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANMeasurementQuantitiesValueValueCodecFieldPath(v *WLANMeasurementQuantitiesValueValueCodec) *aper.Path {
	return &v.path
}
func BridgeWLANMeasurementQuantitiesValueValueCodecMethodEncodeBudget(v WLANMeasurementQuantitiesValueValueCodec, a0 s00.WLANMeasurementQuantitiesValue, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANMeasurementQuantitiesValueValueCodecMethodEncodeChanged(v WLANMeasurementQuantitiesValueValueCodec, a0 s00.WLANMeasurementQuantitiesValue, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANOperatingClassAPERValueFieldContext(v *WLANOperatingClassAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANOperatingClassAPERValueFieldReceived(v *WLANOperatingClassAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWLANOperatingClassAPERValueFieldReplay(v *WLANOperatingClassAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANOperatingClassAPERValueFieldWithoutReplay(v *WLANOperatingClassAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANOperatingClassValueCodecFieldCapture(v *WLANOperatingClassValueCodec) *func(s00.WLANOperatingClass, aper.DecodeState) (s00.WLANOperatingClass, aper.Snapshot) {
	return &v.capture
}
func BridgeWLANOperatingClassValueCodecFieldCompare(v *WLANOperatingClassValueCodec) *func(s00.WLANOperatingClass, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeWLANOperatingClassValueCodecFieldContext(v *WLANOperatingClassValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANOperatingClassValueCodecFieldDecode(v *WLANOperatingClassValueCodec) *func([]byte, aper.DecodeState) (s00.WLANOperatingClass, error) {
	return &v.decode
}
func BridgeWLANOperatingClassValueCodecFieldEncode(v *WLANOperatingClassValueCodec) *func(s00.WLANOperatingClass, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANOperatingClassValueCodecFieldPath(v *WLANOperatingClassValueCodec) *aper.Path {
	return &v.path
}
func BridgeWLANOperatingClassValueCodecMethodEncodeBudget(v WLANOperatingClassValueCodec, a0 s00.WLANOperatingClass, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANOperatingClassValueCodecMethodEncodeChanged(v WLANOperatingClassValueCodec, a0 s00.WLANOperatingClass, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANRSSIAPERValueFieldContext(v *WLANRSSIAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANRSSIAPERValueFieldReceived(v *WLANRSSIAPERValue) *aper.WireSpan { return &v.received }
func BridgeWLANRSSIAPERValueFieldReplay(v *WLANRSSIAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeWLANRSSIAPERValueFieldWithoutReplay(v *WLANRSSIAPERValue) *bool     { return &v.withoutReplay }
func BridgeWLANRSSIValueCodecFieldCapture(v *WLANRSSIValueCodec) *func(s00.WLANRSSI, aper.DecodeState) (s00.WLANRSSI, aper.Snapshot) {
	return &v.capture
}
func BridgeWLANRSSIValueCodecFieldCompare(v *WLANRSSIValueCodec) *func(s00.WLANRSSI, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeWLANRSSIValueCodecFieldContext(v *WLANRSSIValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANRSSIValueCodecFieldDecode(v *WLANRSSIValueCodec) *func([]byte, aper.DecodeState) (s00.WLANRSSI, error) {
	return &v.decode
}
func BridgeWLANRSSIValueCodecFieldEncode(v *WLANRSSIValueCodec) *func(s00.WLANRSSI, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANRSSIValueCodecFieldPath(v *WLANRSSIValueCodec) *aper.Path { return &v.path }
func BridgeWLANRSSIValueCodecMethodEncodeBudget(v WLANRSSIValueCodec, a0 s00.WLANRSSI, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANRSSIValueCodecMethodEncodeChanged(v WLANRSSIValueCodec, a0 s00.WLANRSSI, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
