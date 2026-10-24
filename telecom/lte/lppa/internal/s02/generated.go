// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s02 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s02

import (
	q7 "fmt"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q6 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// WLANCountryCodeValueCodec is the concrete ValueCodec[WLANCountryCode].
type WLANCountryCodeValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.WLANCountryCode, q5.DecodeState,

	) (q4.WLANCountryCode, q5.Snapshot,

	)
	compare func(q4.WLANCountryCode, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.WLANCountryCode,

		error)
	encode func(q4.WLANCountryCode,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c WLANCountryCodeValueCodec) New(value q4.WLANCountryCode,

) (q6.WLANCountryCodeAPERValue, error) {
	if c.encode == nil {
		return q6.WLANCountryCodeAPERValue{}, q5.OperationError(q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return q6.WLANCountryCodeAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return q6.WLANCountryCodeAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return q6.WLANCountryCodeAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c WLANCountryCodeValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (q6.WLANCountryCodeAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return q6.WLANCountryCodeAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return q6.WLANCountryCodeAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return q6.WLANCountryCodeAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return q6.WLANCountryCodeAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return func() q6.WLANCountryCodeAPERValue {
		sealed := q6.WLANCountryCodeAPERValue{Value: value}
		*q6.BridgeWLANCountryCodeAPERValueFieldReceived(&sealed) = q5.OriginalWire(data)
		*q6.BridgeWLANCountryCodeAPERValueFieldReplay(&sealed) = replay
		*q6.BridgeWLANCountryCodeAPERValueFieldContext(&sealed) = c.context
		return sealed
	}(), report, nil
}
func (c WLANCountryCodeValueCodec) EncodeAPER(value q6.WLANCountryCodeAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	fresh := *q6.BridgeWLANCountryCodeAPERValueFieldWithoutReplay(&value) || q5.EncodeWithoutReplay(options...)
	var budget q5.DecodeBudget
	if err := q5.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q5.OperationError(err, c.path)
	}
	if !fresh && *q6.BridgeWLANCountryCodeAPERValueFieldContext(&value) == c.context && (*q6.BridgeWLANCountryCodeAPERValueFieldReplay(&value)).Present() {

		plan := c.compare(value.Value, *q6.BridgeWLANCountryCodeAPERValueFieldReplay(&value), q5.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q5.OperationError(err, c.path)
		}
		if plan.Unchanged(*q6.BridgeWLANCountryCodeAPERValueFieldReplay(&value)) {
			if err := (*q6.BridgeWLANCountryCodeAPERValueFieldReplay(&value)).ApplyReplay(&budget); err != nil {
				return nil, q5.OperationError(err, c.path)
			}
			out, err := (*q6.BridgeWLANCountryCodeAPERValueFieldReceived(&value)).ReplayBytes(&budget)
			return out, q5.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q5.OperationError(err, c.path)
}
func (c WLANCountryCodeValueCodec) encodeBudget(value q4.WLANCountryCode,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANCountryCodeValueCodec) encodeChanged(value q4.WLANCountryCode,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// WLANMeasurementQuantitiesValueValueCodec is the concrete ValueCodec[WLANMeasurementQuantitiesValue].
type WLANMeasurementQuantitiesValueValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.WLANMeasurementQuantitiesValue, q5.DecodeState,

	) (q4.WLANMeasurementQuantitiesValue, q5.Snapshot,

	)
	compare func(q4.WLANMeasurementQuantitiesValue, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.WLANMeasurementQuantitiesValue,

		error)
	encode func(q4.WLANMeasurementQuantitiesValue,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c WLANMeasurementQuantitiesValueValueCodec) New(value q4.WLANMeasurementQuantitiesValue,

) (WLANMeasurementQuantitiesValueAPERValue, error) {
	if c.encode == nil {
		return WLANMeasurementQuantitiesValueAPERValue{}, q5.OperationError(q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return WLANMeasurementQuantitiesValueAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANMeasurementQuantitiesValueAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return WLANMeasurementQuantitiesValueAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c WLANMeasurementQuantitiesValueValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (WLANMeasurementQuantitiesValueAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANMeasurementQuantitiesValueAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return WLANMeasurementQuantitiesValueAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANMeasurementQuantitiesValueAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return WLANMeasurementQuantitiesValueAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return WLANMeasurementQuantitiesValueAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c WLANMeasurementQuantitiesValueValueCodec) EncodeAPER(value WLANMeasurementQuantitiesValueAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c WLANMeasurementQuantitiesValueValueCodec) encodeBudget(value q4.WLANMeasurementQuantitiesValue,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANMeasurementQuantitiesValueValueCodec) encodeChanged(value q4.WLANMeasurementQuantitiesValue,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// WLANOperatingClassValueCodec is the concrete ValueCodec[WLANOperatingClass].
type WLANOperatingClassValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.WLANOperatingClass, q5.DecodeState,

	) (q4.WLANOperatingClass, q5.Snapshot,

	)
	compare func(q4.WLANOperatingClass, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.WLANOperatingClass,

		error)
	encode func(q4.WLANOperatingClass,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c WLANOperatingClassValueCodec) New(value q4.WLANOperatingClass,

) (WLANOperatingClassAPERValue, error) {
	if c.encode == nil {
		return WLANOperatingClassAPERValue{}, q5.OperationError(q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return WLANOperatingClassAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANOperatingClassAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return WLANOperatingClassAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c WLANOperatingClassValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (WLANOperatingClassAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANOperatingClassAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return WLANOperatingClassAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANOperatingClassAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return WLANOperatingClassAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return WLANOperatingClassAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c WLANOperatingClassValueCodec) EncodeAPER(value WLANOperatingClassAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c WLANOperatingClassValueCodec) encodeBudget(value q4.WLANOperatingClass,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANOperatingClassValueCodec) encodeChanged(value q4.WLANOperatingClass,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// WLANRSSIValueCodec is the concrete ValueCodec[WLANRSSI].
type WLANRSSIValueCodec struct {
	context q4.BridgeCodecContext
	capture func(q4.WLANRSSI, q5.DecodeState,

	) (q4.WLANRSSI, q5.Snapshot,

	)
	compare func(q4.WLANRSSI, q5.Snapshot, q5.ComparisonLimits,

	) q5.ReplayPlan
	path   q5.Path
	decode func([]byte, q5.DecodeState) (q4.WLANRSSI,

		error)
	encode func(q4.WLANRSSI,

		bool, *q5.DecodeBudget) ([]byte, error)
}

func (c WLANRSSIValueCodec) New(value q4.WLANRSSI,

) (WLANRSSIAPERValue, error) {
	if c.encode == nil {
		return WLANRSSIAPERValue{}, q5.OperationError(q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue), "Value.New")
	}
	budget, err := q5.BuildBudget()
	if err != nil {
		return WLANRSSIAPERValue{}, q5.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANRSSIAPERValue{}, q5.OperationError(err, "Value.New")
	}
	return WLANRSSIAPERValue{Value: value}, q5.OperationError(nil, "Value.New")
}
func (c WLANRSSIValueCodec) DecodeAPER(data []byte, options ...q5.DecodeOption) (WLANRSSIAPERValue, q5.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANRSSIAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
	}
	data, settings := q5.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q5.FinishDecode(settings, err)
		return WLANRSSIAPERValue{}, report, q5.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANRSSIAPERValue{}, q5.DecodeReport{}, q7.Errorf("%w: missing semantic capture", q5.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q5.FinishDecode(settings, nil)
	if err != nil {
		return WLANRSSIAPERValue{}, report, q5.OperationError(err, c.path)
	}
	return WLANRSSIAPERValue{Value: value, received: q5.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c WLANRSSIValueCodec) EncodeAPER(value WLANRSSIAPERValue, options ...q5.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q7.Errorf("%w: unbound value codec", q5.ErrInvalidValue)
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
func (c WLANRSSIValueCodec) encodeBudget(value q4.WLANRSSI,

	fresh bool, budget q5.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANRSSIValueCodec) encodeChanged(value q4.WLANRSSI,

	fresh bool, plan q5.ReplayPlan, budget q5.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q5.OperationError(err, c.path)
}

// WLANMeasurementQuantitiesValueAPERValue is the concrete APERValue[WLANMeasurementQuantitiesValue].
type WLANMeasurementQuantitiesValueAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.WLANMeasurementQuantitiesValue

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v WLANMeasurementQuantitiesValueAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v WLANMeasurementQuantitiesValueAPERValue) WithoutReplay() WLANMeasurementQuantitiesValueAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// WLANOperatingClassAPERValue is the concrete APERValue[WLANOperatingClass].
type WLANOperatingClassAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.WLANOperatingClass

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v WLANOperatingClassAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v WLANOperatingClassAPERValue) WithoutReplay() WLANOperatingClassAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}

// WLANRSSIAPERValue is the concrete APERValue[WLANRSSI].
type WLANRSSIAPERValue struct {
	context q4.BridgeCodecContext
	Value   q4.WLANRSSI

	received      q5.WireSpan
	replay        q5.Snapshot
	withoutReplay bool
}

func (v WLANRSSIAPERValue) ReceivedForm() q5.ReceivedForm {
	return q5.NewReceivedSpanForm(v.received.Present(), v.received, q5.Location{}, nil)
}
func (v WLANRSSIAPERValue) WithoutReplay() WLANRSSIAPERValue {
	v.received = q5.WireSpan{}
	v.replay = q5.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureLPPaAddOTDOACellsExtIEsValue(v *AddOTDOACellsExtIEsValue, s *q5.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v AddOTDOACellsExtIEsValue) captureSnapshot() q5.Snapshot { return v.replay }
func (v AddOTDOACellsExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v AddOTDOACellsExtIEsValue) captureSemantics(s q5.SemanticCapture) AddOTDOACellsExtIEsValue {
	BridgeCaptureLPPaAddOTDOACellsExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaAddOTDOACellsExtIEsValue(v *AddOTDOACellsExtIEsValue, s *q5.SemanticComparison) {
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
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v AddOTDOACellsExtIEsValue) compareSemantics(s q5.SemanticComparison) q5.SemanticComparison {
	BridgeCompareLPPaAddOTDOACellsExtIEsValue(&v, &s)
	return s
}
func (v AddOTDOACellsExtIEsValue) WithoutReplay() AddOTDOACellsExtIEsValue {
	v.withoutReplay = true
	v.replay = q5.Snapshot{}
	return v
}
func BridgeCaptureLPPaAssistanceInformationExtIEsValue(v *AssistanceInformationExtIEsValue, s *q5.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v AssistanceInformationExtIEsValue) captureSnapshot() q5.Snapshot { return v.replay }
func (v AssistanceInformationExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v AssistanceInformationExtIEsValue) captureSemantics(s q5.SemanticCapture) AssistanceInformationExtIEsValue {
	BridgeCaptureLPPaAssistanceInformationExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaAssistanceInformationExtIEsValue(v *AssistanceInformationExtIEsValue, s *q5.SemanticComparison) {
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
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v AssistanceInformationExtIEsValue) compareSemantics(s q5.SemanticComparison) q5.SemanticComparison {
	BridgeCompareLPPaAssistanceInformationExtIEsValue(&v, &s)
	return s
}
func (v AssistanceInformationExtIEsValue) WithoutReplay() AssistanceInformationExtIEsValue {
	v.withoutReplay = true
	v.replay = q5.Snapshot{}
	return v
}
func BridgeCaptureLPPaAssistanceInformationFailureListExtIEsValue(v *AssistanceInformationFailureListExtIEsValue, s *q5.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v AssistanceInformationFailureListExtIEsValue) captureSnapshot() q5.Snapshot { return v.replay }
func (v AssistanceInformationFailureListExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v AssistanceInformationFailureListExtIEsValue) captureSemantics(s q5.SemanticCapture) AssistanceInformationFailureListExtIEsValue {
	BridgeCaptureLPPaAssistanceInformationFailureListExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaAssistanceInformationFailureListExtIEsValue(v *AssistanceInformationFailureListExtIEsValue, s *q5.SemanticComparison) {
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
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v AssistanceInformationFailureListExtIEsValue) compareSemantics(s q5.SemanticComparison) q5.SemanticComparison {
	BridgeCompareLPPaAssistanceInformationFailureListExtIEsValue(&v, &s)
	return s
}
func (v AssistanceInformationFailureListExtIEsValue) WithoutReplay() AssistanceInformationFailureListExtIEsValue {
	v.withoutReplay = true
	v.replay = q5.Snapshot{}
	return v
}
func BridgeCaptureLPPaAssistanceInformationMetaDataExtIEsValue(v *AssistanceInformationMetaDataExtIEsValue, s *q5.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v AssistanceInformationMetaDataExtIEsValue) captureSnapshot() q5.Snapshot { return v.replay }
func (v AssistanceInformationMetaDataExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v AssistanceInformationMetaDataExtIEsValue) captureSemantics(s q5.SemanticCapture) AssistanceInformationMetaDataExtIEsValue {
	BridgeCaptureLPPaAssistanceInformationMetaDataExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaAssistanceInformationMetaDataExtIEsValue(v *AssistanceInformationMetaDataExtIEsValue, s *q5.SemanticComparison) {
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
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v AssistanceInformationMetaDataExtIEsValue) compareSemantics(s q5.SemanticComparison) q5.SemanticComparison {
	BridgeCompareLPPaAssistanceInformationMetaDataExtIEsValue(&v, &s)
	return s
}
func (v AssistanceInformationMetaDataExtIEsValue) WithoutReplay() AssistanceInformationMetaDataExtIEsValue {
	v.withoutReplay = true
	v.replay = q5.Snapshot{}
	return v
}
func BridgeCompareLPPaBCCH(v *q4.BCCH, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeCompareLPPaBSSID(v *q4.BSSID, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Bytes((*v))
}
func BridgeCompareLPPaBroadcast(v *q4.Broadcast, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaBroadcastPeriodicity(v *q4.BroadcastPeriodicity, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaCPLength(v *q4.CPLength, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaCauseMisc(v *q4.CauseMisc, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaCauseProtocol(v *q4.CauseProtocol, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaCauseRadioNetwork(v *q4.CauseRadioNetwork, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaCellPortionID(v *q4.CellPortionID, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeCompareLPPaCriticality(v *q4.Criticality, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaCriticalityDiagnosticsExtIEsValue(v *CriticalityDiagnosticsExtIEsValue, s *q5.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v CriticalityDiagnosticsExtIEsValue) captureSnapshot() q5.Snapshot { return v.replay }
func (v CriticalityDiagnosticsExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v CriticalityDiagnosticsExtIEsValue) captureSemantics(s q5.SemanticCapture) CriticalityDiagnosticsExtIEsValue {
	BridgeCaptureLPPaCriticalityDiagnosticsExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaCriticalityDiagnosticsExtIEsValue(v *CriticalityDiagnosticsExtIEsValue, s *q5.SemanticComparison) {
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
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v CriticalityDiagnosticsExtIEsValue) compareSemantics(s q5.SemanticComparison) q5.SemanticComparison {
	BridgeCompareLPPaCriticalityDiagnosticsExtIEsValue(&v, &s)
	return s
}
func (v CriticalityDiagnosticsExtIEsValue) WithoutReplay() CriticalityDiagnosticsExtIEsValue {
	v.withoutReplay = true
	v.replay = q5.Snapshot{}
	return v
}
func BridgeCaptureLPPaCriticalityDiagnosticsIEListExtIEsValue(v *CriticalityDiagnosticsIEListExtIEsValue, s *q5.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v CriticalityDiagnosticsIEListExtIEsValue) captureSnapshot() q5.Snapshot { return v.replay }
func (v CriticalityDiagnosticsIEListExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v CriticalityDiagnosticsIEListExtIEsValue) captureSemantics(s q5.SemanticCapture) CriticalityDiagnosticsIEListExtIEsValue {
	BridgeCaptureLPPaCriticalityDiagnosticsIEListExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaCriticalityDiagnosticsIEListExtIEsValue(v *CriticalityDiagnosticsIEListExtIEsValue, s *q5.SemanticComparison) {
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
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v CriticalityDiagnosticsIEListExtIEsValue) compareSemantics(s q5.SemanticComparison) q5.SemanticComparison {
	BridgeCompareLPPaCriticalityDiagnosticsIEListExtIEsValue(&v, &s)
	return s
}
func (v CriticalityDiagnosticsIEListExtIEsValue) WithoutReplay() CriticalityDiagnosticsIEListExtIEsValue {
	v.withoutReplay = true
	v.replay = q5.Snapshot{}
	return v
}
func BridgeCompareLPPaDLBandwidth(v *q4.DLBandwidth, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaEARFCN(v *q4.EARFCN, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeCaptureLPPaECGIExtIEsValue(v *ECGIExtIEsValue, s *q5.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ECGIExtIEsValue) captureSnapshot() q5.Snapshot { return v.replay }
func (v ECGIExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ECGIExtIEsValue) captureSemantics(s q5.SemanticCapture) ECGIExtIEsValue {
	BridgeCaptureLPPaECGIExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaECGIExtIEsValue(v *ECGIExtIEsValue, s *q5.SemanticComparison) {
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
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v ECGIExtIEsValue) compareSemantics(s q5.SemanticComparison) q5.SemanticComparison {
	BridgeCompareLPPaECGIExtIEsValue(&v, &s)
	return s
}
func (v ECGIExtIEsValue) WithoutReplay() ECGIExtIEsValue {
	v.withoutReplay = true
	v.replay = q5.Snapshot{}
	return v
}
func BridgeCaptureLPPaECIDMeasurementTerminationCommandIEValue(v *ECIDMeasurementTerminationCommandIEValue, s *q5.SemanticCapture) {
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
		case q4.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowESMLCUEMeasurementID == nil)
				if v.rowESMLCUEMeasurementID != nil {
					q4.BridgeCaptureLPPaMeasurementID(v.rowESMLCUEMeasurementID, s)
				}
				s.End(f, nil, false)
			}
		case q4.ProtocolIEID(6):
			{
				f := s.Begin()
				s.Bool(v.rowENBUEMeasurementID == nil)
				if v.rowENBUEMeasurementID != nil {
					q4.BridgeCaptureLPPaMeasurementID(v.rowENBUEMeasurementID, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ECIDMeasurementTerminationCommandIEValue) captureSnapshot() q5.Snapshot { return v.replay }
func (v ECIDMeasurementTerminationCommandIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ECIDMeasurementTerminationCommandIEValue) captureSemantics(s q5.SemanticCapture) ECIDMeasurementTerminationCommandIEValue {
	BridgeCaptureLPPaECIDMeasurementTerminationCommandIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaECIDMeasurementTerminationCommandIEValue(v *ECIDMeasurementTerminationCommandIEValue, s *q5.SemanticComparison) {
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
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case q4.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowESMLCUEMeasurementID == nil)
				if v.rowESMLCUEMeasurementID != nil {
					BridgeCompareLPPaMeasurementID(v.rowESMLCUEMeasurementID, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		case q4.ProtocolIEID(6):
			{
				f := s.Begin()
				s.Bool(v.rowENBUEMeasurementID == nil)
				if v.rowENBUEMeasurementID != nil {
					BridgeCompareLPPaMeasurementID(v.rowENBUEMeasurementID, s)
				}
				s.End(f, q5.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v ECIDMeasurementTerminationCommandIEValue) compareSemantics(s q5.SemanticComparison) q5.SemanticComparison {
	BridgeCompareLPPaECIDMeasurementTerminationCommandIEValue(&v, &s)
	return s
}
func (v ECIDMeasurementTerminationCommandIEValue) WithoutReplay() ECIDMeasurementTerminationCommandIEValue {
	v.withoutReplay = true
	v.replay = q5.Snapshot{}
	return v
}
func BridgeCompareLPPaEUTRANCellIdentifier(v *q4.EUTRANCellIdentifier, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.BitString((*v).Bytes, (*v).BitLength)
}
func BridgeCompareLPPaHESSID(v *q4.HESSID, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Bytes((*v))
}
func BridgeCompareLPPaInterRATMeasurementQuantitiesValue(v *q4.InterRATMeasurementQuantitiesValue, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaInterRATMeasurementQuantitiesValueExtIEsValue(v *InterRATMeasurementQuantitiesValueExtIEsValue, s *q5.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v InterRATMeasurementQuantitiesValueExtIEsValue) captureSnapshot() q5.Snapshot {
	return v.replay
}
func (v InterRATMeasurementQuantitiesValueExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v InterRATMeasurementQuantitiesValueExtIEsValue) captureSemantics(s q5.SemanticCapture) InterRATMeasurementQuantitiesValueExtIEsValue {
	BridgeCaptureLPPaInterRATMeasurementQuantitiesValueExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaInterRATMeasurementQuantitiesValueExtIEsValue(v *InterRATMeasurementQuantitiesValueExtIEsValue, s *q5.SemanticComparison) {
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
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v InterRATMeasurementQuantitiesValueExtIEsValue) compareSemantics(s q5.SemanticComparison) q5.SemanticComparison {
	BridgeCompareLPPaInterRATMeasurementQuantitiesValueExtIEsValue(&v, &s)
	return s
}
func (v InterRATMeasurementQuantitiesValueExtIEsValue) WithoutReplay() InterRATMeasurementQuantitiesValueExtIEsValue {
	v.withoutReplay = true
	v.replay = q5.Snapshot{}
	return v
}
func BridgeCompareLPPaLPPATransactionID(v *q4.LPPATransactionID, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaMeasurementID(v *q4.MeasurementID, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeCompareLPPaMeasurementPeriodicity(v *q4.MeasurementPeriodicity, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaMeasurementQuantitiesValue(v *q4.MeasurementQuantitiesValue, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaMeasurementQuantitiesValueExtIEsValue(v *MeasurementQuantitiesValueExtIEsValue, s *q5.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v MeasurementQuantitiesValueExtIEsValue) captureSnapshot() q5.Snapshot { return v.replay }
func (v MeasurementQuantitiesValueExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v MeasurementQuantitiesValueExtIEsValue) captureSemantics(s q5.SemanticCapture) MeasurementQuantitiesValueExtIEsValue {
	BridgeCaptureLPPaMeasurementQuantitiesValueExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaMeasurementQuantitiesValueExtIEsValue(v *MeasurementQuantitiesValueExtIEsValue, s *q5.SemanticComparison) {
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
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v MeasurementQuantitiesValueExtIEsValue) compareSemantics(s q5.SemanticComparison) q5.SemanticComparison {
	BridgeCompareLPPaMeasurementQuantitiesValueExtIEsValue(&v, &s)
	return s
}
func (v MeasurementQuantitiesValueExtIEsValue) WithoutReplay() MeasurementQuantitiesValueExtIEsValue {
	v.withoutReplay = true
	v.replay = q5.Snapshot{}
	return v
}
func BridgeCompareLPPaNPRSSequenceInfo(v *q4.NPRSSequenceInfo, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeCompareLPPaNRARFCN(v *q4.NRARFCN, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaNRCGIExtIEsValue(v *NRCGIExtIEsValue, s *q5.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v NRCGIExtIEsValue) captureSnapshot() q5.Snapshot { return v.replay }
func (v NRCGIExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v NRCGIExtIEsValue) captureSemantics(s q5.SemanticCapture) NRCGIExtIEsValue {
	BridgeCaptureLPPaNRCGIExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaNRCGIExtIEsValue(v *NRCGIExtIEsValue, s *q5.SemanticComparison) {
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
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v NRCGIExtIEsValue) compareSemantics(s q5.SemanticComparison) q5.SemanticComparison {
	BridgeCompareLPPaNRCGIExtIEsValue(&v, &s)
	return s
}
func (v NRCGIExtIEsValue) WithoutReplay() NRCGIExtIEsValue {
	v.withoutReplay = true
	v.replay = q5.Snapshot{}
	return v
}
func BridgeCompareLPPaNRCellIdentity(v *q4.NRCellIdentity, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.BitString((*v).Bytes, (*v).BitLength)
}
func BridgeCompareLPPaNRPCI(v *q4.NRPCI, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaNarrowBandIndex(v *q4.NarrowBandIndex, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeCompareLPPaNumberOfAntennaPorts(v *q4.NumberOfAntennaPorts, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaNumberOfDlFrames(v *q4.NumberOfDlFrames, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaNumberOfDlFramesExtended(v *q4.NumberOfDlFramesExtended, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeCompareLPPaNumberOfFrequencyHoppingBands(v *q4.NumberOfFrequencyHoppingBands, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaOTDOACellsExtIEsValue(v *OTDOACellsExtIEsValue, s *q5.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v OTDOACellsExtIEsValue) captureSnapshot() q5.Snapshot { return v.replay }
func (v OTDOACellsExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v OTDOACellsExtIEsValue) captureSemantics(s q5.SemanticCapture) OTDOACellsExtIEsValue {
	BridgeCaptureLPPaOTDOACellsExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaOTDOACellsExtIEsValue(v *OTDOACellsExtIEsValue, s *q5.SemanticComparison) {
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
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v OTDOACellsExtIEsValue) compareSemantics(s q5.SemanticComparison) q5.SemanticComparison {
	BridgeCompareLPPaOTDOACellsExtIEsValue(&v, &s)
	return s
}
func (v OTDOACellsExtIEsValue) WithoutReplay() OTDOACellsExtIEsValue {
	v.withoutReplay = true
	v.replay = q5.Snapshot{}
	return v
}
func BridgeCompareLPPaOTDOAInformationItem(v *q4.OTDOAInformationItem, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCaptureLPPaOTDOAInformationTypeItemExtIEsValue(v *OTDOAInformationTypeItemExtIEsValue, s *q5.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v OTDOAInformationTypeItemExtIEsValue) captureSnapshot() q5.Snapshot { return v.replay }
func (v OTDOAInformationTypeItemExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v OTDOAInformationTypeItemExtIEsValue) captureSemantics(s q5.SemanticCapture) OTDOAInformationTypeItemExtIEsValue {
	BridgeCaptureLPPaOTDOAInformationTypeItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaOTDOAInformationTypeItemExtIEsValue(v *OTDOAInformationTypeItemExtIEsValue, s *q5.SemanticComparison) {
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
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v OTDOAInformationTypeItemExtIEsValue) compareSemantics(s q5.SemanticComparison) q5.SemanticComparison {
	BridgeCompareLPPaOTDOAInformationTypeItemExtIEsValue(&v, &s)
	return s
}
func (v OTDOAInformationTypeItemExtIEsValue) WithoutReplay() OTDOAInformationTypeItemExtIEsValue {
	v.withoutReplay = true
	v.replay = q5.Snapshot{}
	return v
}
func BridgeCompareLPPaOffsetNBChanneltoEARFCN(v *q4.OffsetNBChanneltoEARFCN, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaOperationModeInfo(v *q4.OperationModeInfo, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaOutcome(v *q4.Outcome, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaPCI(v *q4.PCI, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeCompareLPPaPLMNIdentity(v *q4.PLMNIdentity, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Bytes((*v))
}
func BridgeCompareLPPaPRSBandwidth(v *q4.PRSBandwidth, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaPRSConfigurationIndex(v *q4.PRSConfigurationIndex, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeCompareLPPaPRSFrequencyHoppingConfigurationBandPositions(v *q4.PRSFrequencyHoppingConfigurationBandPositions, s *q5.SemanticComparison) {
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
		s.End(f, q5.Snapshot{}, false)
	}
	s.End(f, q5.Snapshot{}, false)
}
func BridgeCaptureLPPaPRSFrequencyHoppingConfigurationItemIEsValue(v *PRSFrequencyHoppingConfigurationItemIEsValue, s *q5.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v PRSFrequencyHoppingConfigurationItemIEsValue) captureSnapshot() q5.Snapshot {
	return v.replay
}
func (v PRSFrequencyHoppingConfigurationItemIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v PRSFrequencyHoppingConfigurationItemIEsValue) captureSemantics(s q5.SemanticCapture) PRSFrequencyHoppingConfigurationItemIEsValue {
	BridgeCaptureLPPaPRSFrequencyHoppingConfigurationItemIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaPRSFrequencyHoppingConfigurationItemIEsValue(v *PRSFrequencyHoppingConfigurationItemIEsValue, s *q5.SemanticComparison) {
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
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v PRSFrequencyHoppingConfigurationItemIEsValue) compareSemantics(s q5.SemanticComparison) q5.SemanticComparison {
	BridgeCompareLPPaPRSFrequencyHoppingConfigurationItemIEsValue(&v, &s)
	return s
}
func (v PRSFrequencyHoppingConfigurationItemIEsValue) WithoutReplay() PRSFrequencyHoppingConfigurationItemIEsValue {
	v.withoutReplay = true
	v.replay = q5.Snapshot{}
	return v
}
func BridgeCompareLPPaPRSID(v *q4.PRSID, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeCompareLPPaPRSOccasionGroup(v *q4.PRSOccasionGroup, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaPhysCellIDGERAN(v *q4.PhysCellIDGERAN, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeCompareLPPaPhysCellIDUTRAFDD(v *q4.PhysCellIDUTRAFDD, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeCompareLPPaPhysCellIDUTRATDD(v *q4.PhysCellIDUTRATDD, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.BigInt((*v))
		s.End(f, q5.Snapshot{}, false)
	}
}
func BridgeCaptureLPPaPosSIBSegmentsExtIEsValue(v *PosSIBSegmentsExtIEsValue, s *q5.SemanticCapture) {
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
	s.End(f, &v.replay, v.withoutReplay)
}
func (v PosSIBSegmentsExtIEsValue) captureSnapshot() q5.Snapshot { return v.replay }
func (v PosSIBSegmentsExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v PosSIBSegmentsExtIEsValue) captureSemantics(s q5.SemanticCapture) PosSIBSegmentsExtIEsValue {
	BridgeCaptureLPPaPosSIBSegmentsExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaPosSIBSegmentsExtIEsValue(v *PosSIBSegmentsExtIEsValue, s *q5.SemanticComparison) {
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
			s.End(f, q5.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	s.End(f, v.replay, v.withoutReplay)
}
func (v PosSIBSegmentsExtIEsValue) compareSemantics(s q5.SemanticComparison) q5.SemanticComparison {
	BridgeCompareLPPaPosSIBSegmentsExtIEsValue(&v, &s)
	return s
}
func (v PosSIBSegmentsExtIEsValue) WithoutReplay() PosSIBSegmentsExtIEsValue {
	v.withoutReplay = true
	v.replay = q5.Snapshot{}
	return v
}
func BridgeCompareLPPaPosSIBType(v *q4.PosSIBType, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaPresence(v *q4.Presence, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaProcedureCode(v *q4.ProcedureCode, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}
func BridgeCompareLPPaProtocolIEID(v *q4.ProtocolIEID, s *q5.SemanticComparison) {
	if s.Failed() {
		return
	}
	s.Int(int64((*v)))
}

type AddOTDOACellsExtIEsValue struct {
	id            q4.ProtocolIEID
	withoutReplay bool
	received      q5.WireSpan
	replay        q5.Snapshot
	opaque        *q5.OpaqueOpenType
	isOpaque      bool
}

func (v AddOTDOACellsExtIEsValue) matchesID(id q4.ProtocolIEID, _ *q5.DecodeBudget) bool {
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
func (v *AddOTDOACellsExtIEsValue) Opaque() (q5.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q5.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (AddOTDOACellsExtIEsValue) rule() q5.SourceRule {
	return q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "Add-OTDOACells-ExtIEs"}}
}
func (AddOTDOACellsExtIEsValue) reason(id q4.ProtocolIEID) q5.OpaqueReason {
	switch id {
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
	case q4.ProtocolIEID(10):
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
func (v AddOTDOACellsExtIEsValue) decode(id q4.ProtocolIEID, raw q5.OpaqueOpenType) (AddOTDOACellsExtIEsValue, error) {
	out := AddOTDOACellsExtIEsValue{id: id}
	switch id {
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
func (v AddOTDOACellsExtIEsValue) encode() ([]byte, error) {
	budget, err := q5.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v AddOTDOACellsExtIEsValue) encodeFresh(fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, q7.Errorf("%s id %d has no value", "AddOTDOACellsExtIEsValue:", v.id)
	}
}

type AssistanceInformationExtIEsValue struct {
	id            q4.ProtocolIEID
	withoutReplay bool
	received      q5.WireSpan
	replay        q5.Snapshot
	opaque        *q5.OpaqueOpenType
	isOpaque      bool
}

func (v AssistanceInformationExtIEsValue) matchesID(id q4.ProtocolIEID, _ *q5.DecodeBudget) bool {
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
func (v *AssistanceInformationExtIEsValue) Opaque() (q5.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q5.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (AssistanceInformationExtIEsValue) rule() q5.SourceRule {
	return q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "Assistance-Information-ExtIEs"}}
}
func (AssistanceInformationExtIEsValue) reason(id q4.ProtocolIEID) q5.OpaqueReason {
	switch id {
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
	case q4.ProtocolIEID(10):
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
func (v AssistanceInformationExtIEsValue) decode(id q4.ProtocolIEID, raw q5.OpaqueOpenType) (AssistanceInformationExtIEsValue, error) {
	out := AssistanceInformationExtIEsValue{id: id}
	switch id {
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
func (v AssistanceInformationExtIEsValue) encode() ([]byte, error) {
	budget, err := q5.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v AssistanceInformationExtIEsValue) encodeFresh(fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, q7.Errorf("%s id %d has no value", "AssistanceInformationExtIEsValue:", v.id)
	}
}

type AssistanceInformationFailureListExtIEsValue struct {
	id            q4.ProtocolIEID
	withoutReplay bool
	received      q5.WireSpan
	replay        q5.Snapshot
	opaque        *q5.OpaqueOpenType
	isOpaque      bool
}

func (v AssistanceInformationFailureListExtIEsValue) matchesID(id q4.ProtocolIEID, _ *q5.DecodeBudget) bool {
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
func (v *AssistanceInformationFailureListExtIEsValue) Opaque() (q5.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q5.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (AssistanceInformationFailureListExtIEsValue) rule() q5.SourceRule {
	return q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "AssistanceInformationFailureList-ExtIEs"}}
}
func (AssistanceInformationFailureListExtIEsValue) reason(id q4.ProtocolIEID) q5.OpaqueReason {
	switch id {
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
	case q4.ProtocolIEID(10):
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
func (v AssistanceInformationFailureListExtIEsValue) decode(id q4.ProtocolIEID, raw q5.OpaqueOpenType) (AssistanceInformationFailureListExtIEsValue, error) {
	out := AssistanceInformationFailureListExtIEsValue{id: id}
	switch id {
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
func (v AssistanceInformationFailureListExtIEsValue) encode() ([]byte, error) {
	budget, err := q5.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v AssistanceInformationFailureListExtIEsValue) encodeFresh(fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, q7.Errorf("%s id %d has no value", "AssistanceInformationFailureListExtIEsValue:", v.id)
	}
}

type AssistanceInformationMetaDataExtIEsValue struct {
	id            q4.ProtocolIEID
	withoutReplay bool
	received      q5.WireSpan
	replay        q5.Snapshot
	opaque        *q5.OpaqueOpenType
	isOpaque      bool
}

func (v AssistanceInformationMetaDataExtIEsValue) matchesID(id q4.ProtocolIEID, _ *q5.DecodeBudget) bool {
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
func (v *AssistanceInformationMetaDataExtIEsValue) Opaque() (q5.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q5.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (AssistanceInformationMetaDataExtIEsValue) rule() q5.SourceRule {
	return q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "AssistanceInformationMetaData-ExtIEs"}}
}
func (AssistanceInformationMetaDataExtIEsValue) reason(id q4.ProtocolIEID) q5.OpaqueReason {
	switch id {
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
	case q4.ProtocolIEID(10):
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
func (v AssistanceInformationMetaDataExtIEsValue) decode(id q4.ProtocolIEID, raw q5.OpaqueOpenType) (AssistanceInformationMetaDataExtIEsValue, error) {
	out := AssistanceInformationMetaDataExtIEsValue{id: id}
	switch id {
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
func (v AssistanceInformationMetaDataExtIEsValue) encode() ([]byte, error) {
	budget, err := q5.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v AssistanceInformationMetaDataExtIEsValue) encodeFresh(fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, q7.Errorf("%s id %d has no value", "AssistanceInformationMetaDataExtIEsValue:", v.id)
	}
}

type CriticalityDiagnosticsExtIEsValue struct {
	id            q4.ProtocolIEID
	withoutReplay bool
	received      q5.WireSpan
	replay        q5.Snapshot
	opaque        *q5.OpaqueOpenType
	isOpaque      bool
}

func (v CriticalityDiagnosticsExtIEsValue) matchesID(id q4.ProtocolIEID, _ *q5.DecodeBudget) bool {
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
func (v *CriticalityDiagnosticsExtIEsValue) Opaque() (q5.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q5.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (CriticalityDiagnosticsExtIEsValue) rule() q5.SourceRule {
	return q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics-ExtIEs"}}
}
func (CriticalityDiagnosticsExtIEsValue) reason(id q4.ProtocolIEID) q5.OpaqueReason {
	switch id {
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
	case q4.ProtocolIEID(10):
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
func (v CriticalityDiagnosticsExtIEsValue) decode(id q4.ProtocolIEID, raw q5.OpaqueOpenType) (CriticalityDiagnosticsExtIEsValue, error) {
	out := CriticalityDiagnosticsExtIEsValue{id: id}
	switch id {
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
func (v CriticalityDiagnosticsExtIEsValue) encode() ([]byte, error) {
	budget, err := q5.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v CriticalityDiagnosticsExtIEsValue) encodeFresh(fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, q7.Errorf("%s id %d has no value", "CriticalityDiagnosticsExtIEsValue:", v.id)
	}
}

type CriticalityDiagnosticsIEListExtIEsValue struct {
	id            q4.ProtocolIEID
	withoutReplay bool
	received      q5.WireSpan
	replay        q5.Snapshot
	opaque        *q5.OpaqueOpenType
	isOpaque      bool
}

func (v CriticalityDiagnosticsIEListExtIEsValue) matchesID(id q4.ProtocolIEID, _ *q5.DecodeBudget) bool {
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
func (v *CriticalityDiagnosticsIEListExtIEsValue) Opaque() (q5.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q5.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (CriticalityDiagnosticsIEListExtIEsValue) rule() q5.SourceRule {
	return q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics-IE-List-ExtIEs"}}
}
func (CriticalityDiagnosticsIEListExtIEsValue) reason(id q4.ProtocolIEID) q5.OpaqueReason {
	switch id {
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
	case q4.ProtocolIEID(10):
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
func (v CriticalityDiagnosticsIEListExtIEsValue) decode(id q4.ProtocolIEID, raw q5.OpaqueOpenType) (CriticalityDiagnosticsIEListExtIEsValue, error) {
	out := CriticalityDiagnosticsIEListExtIEsValue{id: id}
	switch id {
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
func (v CriticalityDiagnosticsIEListExtIEsValue) encode() ([]byte, error) {
	budget, err := q5.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v CriticalityDiagnosticsIEListExtIEsValue) encodeFresh(fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, q7.Errorf("%s id %d has no value", "CriticalityDiagnosticsIEListExtIEsValue:", v.id)
	}
}

type ECGIExtIEsValue struct {
	id            q4.ProtocolIEID
	withoutReplay bool
	received      q5.WireSpan
	replay        q5.Snapshot
	opaque        *q5.OpaqueOpenType
	isOpaque      bool
}

func (v ECGIExtIEsValue) matchesID(id q4.ProtocolIEID, _ *q5.DecodeBudget) bool {
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
func (v *ECGIExtIEsValue) Opaque() (q5.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q5.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ECGIExtIEsValue) rule() q5.SourceRule {
	return q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "ECGI-ExtIEs"}}
}
func (ECGIExtIEsValue) reason(id q4.ProtocolIEID) q5.OpaqueReason {
	switch id {
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
	case q4.ProtocolIEID(10):
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
func (v ECGIExtIEsValue) decode(id q4.ProtocolIEID, raw q5.OpaqueOpenType) (ECGIExtIEsValue, error) {
	out := ECGIExtIEsValue{id: id}
	switch id {
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
func (v ECGIExtIEsValue) encode() ([]byte, error) {
	budget, err := q5.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ECGIExtIEsValue) encodeFresh(fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, q7.Errorf("%s id %d has no value", "ECGIExtIEsValue:", v.id)
	}
}

type InterRATMeasurementQuantitiesValueExtIEsValue struct {
	id            q4.ProtocolIEID
	withoutReplay bool
	received      q5.WireSpan
	replay        q5.Snapshot
	opaque        *q5.OpaqueOpenType
	isOpaque      bool
}

func (v InterRATMeasurementQuantitiesValueExtIEsValue) matchesID(id q4.ProtocolIEID, _ *q5.DecodeBudget) bool {
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
func (v *InterRATMeasurementQuantitiesValueExtIEsValue) Opaque() (q5.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q5.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (InterRATMeasurementQuantitiesValueExtIEsValue) rule() q5.SourceRule {
	return q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "InterRATMeasurementQuantitiesValue-ExtIEs"}}
}
func (InterRATMeasurementQuantitiesValueExtIEsValue) reason(id q4.ProtocolIEID) q5.OpaqueReason {
	switch id {
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
	case q4.ProtocolIEID(10):
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
func (v InterRATMeasurementQuantitiesValueExtIEsValue) decode(id q4.ProtocolIEID, raw q5.OpaqueOpenType) (InterRATMeasurementQuantitiesValueExtIEsValue, error) {
	out := InterRATMeasurementQuantitiesValueExtIEsValue{id: id}
	switch id {
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
func (v InterRATMeasurementQuantitiesValueExtIEsValue) encode() ([]byte, error) {
	budget, err := q5.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v InterRATMeasurementQuantitiesValueExtIEsValue) encodeFresh(fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, q7.Errorf("%s id %d has no value", "InterRATMeasurementQuantitiesValueExtIEsValue:", v.id)
	}
}

type MeasurementQuantitiesValueExtIEsValue struct {
	id            q4.ProtocolIEID
	withoutReplay bool
	received      q5.WireSpan
	replay        q5.Snapshot
	opaque        *q5.OpaqueOpenType
	isOpaque      bool
}

func (v MeasurementQuantitiesValueExtIEsValue) matchesID(id q4.ProtocolIEID, _ *q5.DecodeBudget) bool {
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
func (v *MeasurementQuantitiesValueExtIEsValue) Opaque() (q5.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q5.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (MeasurementQuantitiesValueExtIEsValue) rule() q5.SourceRule {
	return q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementQuantitiesValue-ExtIEs"}}
}
func (MeasurementQuantitiesValueExtIEsValue) reason(id q4.ProtocolIEID) q5.OpaqueReason {
	switch id {
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
	case q4.ProtocolIEID(10):
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
func (v MeasurementQuantitiesValueExtIEsValue) decode(id q4.ProtocolIEID, raw q5.OpaqueOpenType) (MeasurementQuantitiesValueExtIEsValue, error) {
	out := MeasurementQuantitiesValueExtIEsValue{id: id}
	switch id {
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
func (v MeasurementQuantitiesValueExtIEsValue) encode() ([]byte, error) {
	budget, err := q5.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v MeasurementQuantitiesValueExtIEsValue) encodeFresh(fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, q7.Errorf("%s id %d has no value", "MeasurementQuantitiesValueExtIEsValue:", v.id)
	}
}

type NRCGIExtIEsValue struct {
	id            q4.ProtocolIEID
	withoutReplay bool
	received      q5.WireSpan
	replay        q5.Snapshot
	opaque        *q5.OpaqueOpenType
	isOpaque      bool
}

func (v NRCGIExtIEsValue) matchesID(id q4.ProtocolIEID, _ *q5.DecodeBudget) bool {
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
func (v *NRCGIExtIEsValue) Opaque() (q5.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q5.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (NRCGIExtIEsValue) rule() q5.SourceRule {
	return q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "NR-CGI-ExtIEs"}}
}
func (NRCGIExtIEsValue) reason(id q4.ProtocolIEID) q5.OpaqueReason {
	switch id {
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
	case q4.ProtocolIEID(10):
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
func (v NRCGIExtIEsValue) decode(id q4.ProtocolIEID, raw q5.OpaqueOpenType) (NRCGIExtIEsValue, error) {
	out := NRCGIExtIEsValue{id: id}
	switch id {
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
func (v NRCGIExtIEsValue) encode() ([]byte, error) {
	budget, err := q5.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v NRCGIExtIEsValue) encodeFresh(fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, q7.Errorf("%s id %d has no value", "NRCGIExtIEsValue:", v.id)
	}
}

type OTDOACellsExtIEsValue struct {
	id            q4.ProtocolIEID
	withoutReplay bool
	received      q5.WireSpan
	replay        q5.Snapshot
	opaque        *q5.OpaqueOpenType
	isOpaque      bool
}

func (v OTDOACellsExtIEsValue) matchesID(id q4.ProtocolIEID, _ *q5.DecodeBudget) bool {
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
func (v *OTDOACellsExtIEsValue) Opaque() (q5.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q5.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (OTDOACellsExtIEsValue) rule() q5.SourceRule {
	return q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "OTDOACells-ExtIEs"}}
}
func (OTDOACellsExtIEsValue) reason(id q4.ProtocolIEID) q5.OpaqueReason {
	switch id {
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
	case q4.ProtocolIEID(10):
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
func (v OTDOACellsExtIEsValue) decode(id q4.ProtocolIEID, raw q5.OpaqueOpenType) (OTDOACellsExtIEsValue, error) {
	out := OTDOACellsExtIEsValue{id: id}
	switch id {
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
func (v OTDOACellsExtIEsValue) encode() ([]byte, error) {
	budget, err := q5.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v OTDOACellsExtIEsValue) encodeFresh(fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, q7.Errorf("%s id %d has no value", "OTDOACellsExtIEsValue:", v.id)
	}
}

type PRSFrequencyHoppingConfigurationItemIEsValue struct {
	id            q4.ProtocolIEID
	withoutReplay bool
	received      q5.WireSpan
	replay        q5.Snapshot
	opaque        *q5.OpaqueOpenType
	isOpaque      bool
}

func (v PRSFrequencyHoppingConfigurationItemIEsValue) matchesID(id q4.ProtocolIEID, _ *q5.DecodeBudget) bool {
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
func (v *PRSFrequencyHoppingConfigurationItemIEsValue) Opaque() (q5.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q5.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (PRSFrequencyHoppingConfigurationItemIEsValue) rule() q5.SourceRule {
	return q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "PRSFrequencyHoppingConfiguration-Item-IEs"}}
}
func (PRSFrequencyHoppingConfigurationItemIEsValue) reason(id q4.ProtocolIEID) q5.OpaqueReason {
	switch id {
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
	case q4.ProtocolIEID(10):
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
func (v PRSFrequencyHoppingConfigurationItemIEsValue) decode(id q4.ProtocolIEID, raw q5.OpaqueOpenType) (PRSFrequencyHoppingConfigurationItemIEsValue, error) {
	out := PRSFrequencyHoppingConfigurationItemIEsValue{id: id}
	switch id {
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
func (v PRSFrequencyHoppingConfigurationItemIEsValue) encode() ([]byte, error) {
	budget, err := q5.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v PRSFrequencyHoppingConfigurationItemIEsValue) encodeFresh(fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, q7.Errorf("%s id %d has no value", "PRSFrequencyHoppingConfigurationItemIEsValue:", v.id)
	}
}

type PosSIBSegmentsExtIEsValue struct {
	id            q4.ProtocolIEID
	withoutReplay bool
	received      q5.WireSpan
	replay        q5.Snapshot
	opaque        *q5.OpaqueOpenType
	isOpaque      bool
}

func (v PosSIBSegmentsExtIEsValue) matchesID(id q4.ProtocolIEID, _ *q5.DecodeBudget) bool {
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
func (v *PosSIBSegmentsExtIEsValue) Opaque() (q5.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q5.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (PosSIBSegmentsExtIEsValue) rule() q5.SourceRule {
	return q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q5.SourceAssignment{Module: "LPPA-IEs", Assignment: "PosSIB-Segments-ExtIEs"}}
}
func (PosSIBSegmentsExtIEsValue) reason(id q4.ProtocolIEID) q5.OpaqueReason {
	switch id {
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
	case q4.ProtocolIEID(10):
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
func (v PosSIBSegmentsExtIEsValue) decode(id q4.ProtocolIEID, raw q5.OpaqueOpenType) (PosSIBSegmentsExtIEsValue, error) {
	out := PosSIBSegmentsExtIEsValue{id: id}
	switch id {
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
func (v PosSIBSegmentsExtIEsValue) encode() ([]byte, error) {
	budget, err := q5.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v PosSIBSegmentsExtIEsValue) encodeFresh(fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, q7.Errorf("%s id %d has no value", "PosSIBSegmentsExtIEsValue:", v.id)
	}
}

type ECIDMeasurementTerminationCommandIEValue struct {
	id                      q4.ProtocolIEID
	withoutReplay           bool
	received                q5.WireSpan
	replay                  q5.Snapshot
	opaque                  *q5.OpaqueOpenType
	isOpaque                bool
	rowESMLCUEMeasurementID *q4.MeasurementID
	rowENBUEMeasurementID   *q4.MeasurementID
}

func (v ECIDMeasurementTerminationCommandIEValue) matchesID(id q4.ProtocolIEID, _ *q5.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q4.ProtocolIEID(2):
		return v.rowESMLCUEMeasurementID != nil
	case q4.ProtocolIEID(6):
		return v.rowENBUEMeasurementID != nil
	default:
		return false
	}
}
func (v *ECIDMeasurementTerminationCommandIEValue) Opaque() (q5.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q5.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ECIDMeasurementTerminationCommandIEValue) rule() q5.SourceRule {
	return q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementTerminationCommand-IEs"}}
}
func (ECIDMeasurementTerminationCommandIEValue) reason(id q4.ProtocolIEID) q5.OpaqueReason {
	switch id {
	case q4.ProtocolIEID(2):
		return q5.UnknownSelector
	case q4.ProtocolIEID(6):
		return q5.UnknownSelector
	case q4.ProtocolIEID(0):
		return q5.NotInTable
	case q4.ProtocolIEID(1):
		return q5.NotInTable
	case q4.ProtocolIEID(3):
		return q5.NotInTable
	case q4.ProtocolIEID(4):
		return q5.NotInTable
	case q4.ProtocolIEID(5):
		return q5.NotInTable
	case q4.ProtocolIEID(7):
		return q5.NotInTable
	case q4.ProtocolIEID(8):
		return q5.NotInTable
	case q4.ProtocolIEID(9):
		return q5.NotInTable
	case q4.ProtocolIEID(10):
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
func (v *ECIDMeasurementTerminationCommandIEValue) AsESMLCUEMeasurementID() (*q4.MeasurementID, bool) {
	if v == nil || v.id != q4.ProtocolIEID(2) || v.rowESMLCUEMeasurementID == nil {
		return nil, false
	}
	return v.rowESMLCUEMeasurementID, true
}
func (v *ECIDMeasurementTerminationCommandIEValue) AsENBUEMeasurementID() (*q4.MeasurementID, bool) {
	if v == nil || v.id != q4.ProtocolIEID(6) || v.rowENBUEMeasurementID == nil {
		return nil, false
	}
	return v.rowENBUEMeasurementID, true
}
func (v ECIDMeasurementTerminationCommandIEValue) decode(id q4.ProtocolIEID, raw q5.OpaqueOpenType) (ECIDMeasurementTerminationCommandIEValue, error) {
	out := ECIDMeasurementTerminationCommandIEValue{id: id}
	var scope *q5.BitBuffer
	switch id {
	case 2, 6:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q4.ProtocolIEID(2):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := q5.DecodeIntegerBigBoundsAligned(bb, q4.BridgeAsn1IntegerBound2, q4.BridgeAsn1IntegerBound7, true)
		value := q4.MeasurementID(decoded)
		if err != nil {
			return out, q7.Errorf("%s %w", "ESMLCUEMeasurementID:", err)
		}
		if _, err := q5.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		if err := q5.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowESMLCUEMeasurementID = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q4.ProtocolIEID(6):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := q5.DecodeIntegerBigBoundsAligned(bb, q4.BridgeAsn1IntegerBound2, q4.BridgeAsn1IntegerBound7, true)
		value := q4.MeasurementID(decoded)
		if err != nil {
			return out, q7.Errorf("%s %w", "ENBUEMeasurementID:", err)
		}
		if _, err := q5.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		if err := q5.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowENBUEMeasurementID = &value
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
func (v ECIDMeasurementTerminationCommandIEValue) encode() ([]byte, error) {
	budget, err := q5.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ECIDMeasurementTerminationCommandIEValue) encodeFresh(fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
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
	case q4.ProtocolIEID(2):
		if v.rowESMLCUEMeasurementID == nil {
			return nil, q7.Errorf("%s missing value", "E-CIDMeasurementTerminationCommand-IEs.id-E-SMLC-UE-Measurement-ID:")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := q5.NewBudgetBuffer(budget)
		if err := q5.EncodeIntegerBigBoundsAligned(encodeBB, *v.rowESMLCUEMeasurementID, q4.BridgeAsn1IntegerBound2, q4.BridgeAsn1IntegerBound7, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case q4.ProtocolIEID(6):
		if v.rowENBUEMeasurementID == nil {
			return nil, q7.Errorf("%s missing value", "E-CIDMeasurementTerminationCommand-IEs.id-eNB-UE-Measurement-ID:")
		}
		if !fresh && q5.NewBudgetBuffer(budget).ReplayPlan() != nil && q5.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := q5.NewBudgetBuffer(budget)
		if err := q5.EncodeIntegerBigBoundsAligned(encodeBB, *v.rowENBUEMeasurementID, q4.BridgeAsn1IntegerBound2, q4.BridgeAsn1IntegerBound7, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, q7.Errorf("%s id %d has no value", "ECIDMeasurementTerminationCommandIEValue:", v.id)
	}
}

type OTDOAInformationTypeItemExtIEsValue struct {
	id            q4.ProtocolIEID
	withoutReplay bool
	received      q5.WireSpan
	replay        q5.Snapshot
	opaque        *q5.OpaqueOpenType
	isOpaque      bool
}

func (v OTDOAInformationTypeItemExtIEsValue) matchesID(id q4.ProtocolIEID, _ *q5.DecodeBudget) bool {
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
func (v *OTDOAInformationTypeItemExtIEsValue) Opaque() (q5.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q5.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (OTDOAInformationTypeItemExtIEsValue) rule() q5.SourceRule {
	return q5.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q5.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "OTDOA-Information-Type-ItemExtIEs"}}
}
func (OTDOAInformationTypeItemExtIEsValue) reason(id q4.ProtocolIEID) q5.OpaqueReason {
	switch id {
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
	case q4.ProtocolIEID(10):
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
func (v OTDOAInformationTypeItemExtIEsValue) decode(id q4.ProtocolIEID, raw q5.OpaqueOpenType) (OTDOAInformationTypeItemExtIEsValue, error) {
	out := OTDOAInformationTypeItemExtIEsValue{id: id}
	switch id {
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
func (v OTDOAInformationTypeItemExtIEsValue) encode() ([]byte, error) {
	budget, err := q5.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v OTDOAInformationTypeItemExtIEsValue) encodeFresh(fresh bool, budget *q5.DecodeBudget) ([]byte, error) {
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
	default:
		return nil, q7.Errorf("%s id %d has no value", "OTDOAInformationTypeItemExtIEsValue:", v.id)
	}
}

// BCCHCodec binds the complete source value type.
func BCCHCodec() q4.BCCHValueCodec {
	return func() q4.BCCHValueCodec {
		sealed := q4.BCCHValueCodec{}
		*q4.BridgeBCCHValueCodecFieldPath(&sealed) = "BCCH"
		*q4.BridgeBCCHValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.BCCH, error) {
			var zero q4.BCCH
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeIntegerBigBoundsAligned(bb, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound4, true)
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "BCCH"); err != nil {
				return zero, err
			}
			return q4.BCCH(decoded), nil
		}
		*q4.BridgeBCCHValueCodecFieldEncode(&sealed) = func(value q4.BCCH, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeIntegerBigBoundsAligned(bb, value, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound4, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeBCCHValueCodecFieldCapture(&sealed) = func(v q4.BCCH, options q5.DecodeState) (q4.BCCH, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaBCCH(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q4.BridgeBCCHValueCodecFieldCompare(&sealed) = func(v q4.BCCH, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaBCCH(&v, &s)
			s.End(f,
				root, false)
			return s.Plan()
		}
		*q4.BridgeBCCHValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:BCCH"
			return sealed
		}()
		return sealed
	}()

}

// BSSIDCodec binds the complete source value type.
func BSSIDCodec() q4.BSSIDValueCodec {
	return func() q4.BSSIDValueCodec {
		sealed := q4.BSSIDValueCodec{}
		*q4.BridgeBSSIDValueCodecFieldPath(&sealed) = "BSSID"
		*q4.BridgeBSSIDValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.BSSID, error) {
			var zero q4.BSSID
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			octets, err := q5.DecodeOctetStringAligned(bb, 6, 6, true)
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "BSSID"); err != nil {
				return zero, err
			}
			return q4.BSSID(octets), nil
		}
		*q4.BridgeBSSIDValueCodecFieldEncode(&sealed) = func(value q4.BSSID, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeOctetStringAligned(bb, []byte(value), 6, 6, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeBSSIDValueCodecFieldCapture(&sealed) = func(v q4.BSSID, options q5.DecodeState) (q4.BSSID, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaBSSID(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q4.BridgeBSSIDValueCodecFieldCompare(&sealed) = func(v q4.BSSID, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaBSSID(&v, &s)
			s.End(
				f, root, false)
			return s.Plan()
		}
		*q4.BridgeBSSIDValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:BSSID"
			return sealed
		}()
		return sealed
	}()

}

// BroadcastPeriodicityCodec binds the complete source value type.
func BroadcastPeriodicityCodec() q4.BroadcastPeriodicityValueCodec {
	return func() q4.BroadcastPeriodicityValueCodec {
		sealed := q4.BroadcastPeriodicityValueCodec{}
		*q4.BridgeBroadcastPeriodicityValueCodecFieldPath(&sealed) = "BroadcastPeriodicity"
		*q4.BridgeBroadcastPeriodicityValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.BroadcastPeriodicity, error) {
			var zero q4.BroadcastPeriodicity
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 7, true, q5.EnumerationSource{KnownExtensions: 0, Path: "BroadcastPeriodicity"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "BroadcastPeriodicity"); err != nil {
				return zero, err
			}
			return q4.BroadcastPeriodicity(decoded), nil
		}
		*q4.BridgeBroadcastPeriodicityValueCodecFieldEncode(&sealed) = func(value q4.BroadcastPeriodicity, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 7, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeBroadcastPeriodicityValueCodecFieldCapture(&sealed) = func(v q4.BroadcastPeriodicity, options q5.DecodeState) (q4.BroadcastPeriodicity, q5.Snapshot,
		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaBroadcastPeriodicity(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*q4.BridgeBroadcastPeriodicityValueCodecFieldCompare(&sealed) = func(v q4.BroadcastPeriodicity, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaBroadcastPeriodicity(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeBroadcastPeriodicityValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:BroadcastPeriodicity"
			return sealed
		}()
		return sealed
	}()

}

// CPLengthCodec binds the complete source value type.
func CPLengthCodec() q4.CPLengthValueCodec {
	return func() q4.CPLengthValueCodec {
		sealed := q4.CPLengthValueCodec{}
		*q4.BridgeCPLengthValueCodecFieldPath(&sealed) = "CPLength"
		*q4.BridgeCPLengthValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.CPLength, error) {
			var zero q4.CPLength
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 2, true, q5.EnumerationSource{KnownExtensions: 0, Path: "CPLength"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "CPLength"); err != nil {
				return zero, err
			}
			return q4.CPLength(decoded), nil
		}
		*q4.BridgeCPLengthValueCodecFieldEncode(&sealed) = func(value q4.CPLength, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 2, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeCPLengthValueCodecFieldCapture(&sealed) = func(v q4.CPLength, options q5.DecodeState) (q4.CPLength, q5.Snapshot) {
			s := q5.SemanticCaptureFor(
				options)
			f := s.Begin()
			q4.BridgeCaptureLPPaCPLength(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q4.BridgeCPLengthValueCodecFieldCompare(&sealed) = func(v q4.CPLength, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaCPLength(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeCPLengthValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:CPLength"
			return sealed
		}()
		return sealed
	}()

}

// CauseMiscCodec binds the complete source value type.
func CauseMiscCodec() q4.CauseMiscValueCodec {
	return func() q4.CauseMiscValueCodec {
		sealed := q4.CauseMiscValueCodec{}
		*q4.BridgeCauseMiscValueCodecFieldPath(&sealed) = "CauseMisc"
		*q4.BridgeCauseMiscValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.CauseMisc, error) {
			var zero q4.CauseMisc
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 1, true, q5.EnumerationSource{KnownExtensions: 0, Path: "CauseMisc"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "CauseMisc"); err != nil {
				return zero, err
			}
			return q4.CauseMisc(decoded), nil
		}
		*q4.BridgeCauseMiscValueCodecFieldEncode(&sealed) = func(value q4.CauseMisc, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 1, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeCauseMiscValueCodecFieldCapture(&sealed) = func(v q4.CauseMisc, options q5.DecodeState) (q4.CauseMisc, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.
				Begin()
			q4.BridgeCaptureLPPaCauseMisc(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q4.BridgeCauseMiscValueCodecFieldCompare(&sealed) = func(v q4.CauseMisc, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaCauseMisc(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeCauseMiscValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:CauseMisc"
			return sealed
		}()
		return sealed
	}()

}

// CauseProtocolCodec binds the complete source value type.
func CauseProtocolCodec() q4.CauseProtocolValueCodec {
	return func() q4.CauseProtocolValueCodec {
		sealed := q4.CauseProtocolValueCodec{}
		*q4.BridgeCauseProtocolValueCodecFieldPath(&sealed) = "CauseProtocol"
		*q4.BridgeCauseProtocolValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.CauseProtocol, error) {
			var zero q4.CauseProtocol
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 7, true, q5.EnumerationSource{KnownExtensions: 0, Path: "CauseProtocol"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "CauseProtocol"); err != nil {
				return zero, err
			}
			return q4.CauseProtocol(decoded), nil
		}
		*q4.BridgeCauseProtocolValueCodecFieldEncode(&sealed) = func(value q4.CauseProtocol, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 7, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeCauseProtocolValueCodecFieldCapture(&sealed) = func(v q4.CauseProtocol, options q5.DecodeState) (q4.CauseProtocol, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaCauseProtocol(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q4.BridgeCauseProtocolValueCodecFieldCompare(&sealed) = func(v q4.CauseProtocol, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaCauseProtocol(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeCauseProtocolValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:CauseProtocol"
			return sealed
		}()
		return sealed
	}()

}

// CauseRadioNetworkCodec binds the complete source value type.
func CauseRadioNetworkCodec() q4.CauseRadioNetworkValueCodec {
	return func() q4.CauseRadioNetworkValueCodec {
		sealed := q4.CauseRadioNetworkValueCodec{}
		*q4.BridgeCauseRadioNetworkValueCodecFieldPath(&sealed) = "CauseRadioNetwork"
		*q4.BridgeCauseRadioNetworkValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.CauseRadioNetwork, error) {
			var zero q4.CauseRadioNetwork
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 3, true, q5.EnumerationSource{KnownExtensions: 0, Path: "CauseRadioNetwork"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "CauseRadioNetwork"); err != nil {
				return zero, err
			}
			return q4.CauseRadioNetwork(decoded), nil
		}
		*q4.BridgeCauseRadioNetworkValueCodecFieldEncode(&sealed) = func(value q4.CauseRadioNetwork, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 3, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeCauseRadioNetworkValueCodecFieldCapture(&sealed) = func(v q4.CauseRadioNetwork, options q5.DecodeState) (q4.CauseRadioNetwork, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaCauseRadioNetwork(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root,

				false)
			return v, root
		}
		*q4.BridgeCauseRadioNetworkValueCodecFieldCompare(&sealed) = func(v q4.CauseRadioNetwork, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaCauseRadioNetwork(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeCauseRadioNetworkValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:CauseRadioNetwork"
			return sealed
		}()
		return sealed
	}()

}

// CriticalityCodec binds the complete source value type.
func CriticalityCodec() q4.CriticalityValueCodec {
	return func() q4.CriticalityValueCodec {
		sealed := q4.CriticalityValueCodec{}
		*q4.BridgeCriticalityValueCodecFieldPath(&sealed) = "Criticality"
		*q4.BridgeCriticalityValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.Criticality, error) {
			var zero q4.Criticality
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 3, false, q5.EnumerationSource{KnownExtensions: 0, Path: "Criticality"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "Criticality"); err != nil {
				return zero, err
			}
			return q4.Criticality(decoded), nil
		}
		*q4.BridgeCriticalityValueCodecFieldEncode(&sealed) = func(value q4.Criticality, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 3, false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeCriticalityValueCodecFieldCapture(&sealed) = func(v q4.Criticality, options q5.DecodeState) (q4.Criticality, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaCriticality(&v, &s)
			var root q5.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v,
				root
		}
		*q4.BridgeCriticalityValueCodecFieldCompare(&sealed) = func(v q4.Criticality, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaCriticality(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeCriticalityValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:Criticality"
			return sealed
		}()
		return sealed
	}()

}

// DLBandwidthCodec binds the complete source value type.
func DLBandwidthCodec() q4.DLBandwidthValueCodec {
	return func() q4.DLBandwidthValueCodec {
		sealed := q4.DLBandwidthValueCodec{}
		*q4.BridgeDLBandwidthValueCodecFieldPath(&sealed) = "DLBandwidth"
		*q4.BridgeDLBandwidthValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.DLBandwidth, error) {
			var zero q4.DLBandwidth
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 6, true, q5.EnumerationSource{KnownExtensions: 0, Path: "DLBandwidth"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "DLBandwidth"); err != nil {
				return zero, err
			}
			return q4.DLBandwidth(decoded), nil
		}
		*q4.BridgeDLBandwidthValueCodecFieldEncode(&sealed) = func(value q4.DLBandwidth, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 6, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeDLBandwidthValueCodecFieldCapture(&sealed) = func(v q4.DLBandwidth, options q5.DecodeState) (q4.DLBandwidth, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaDLBandwidth(&v, &s)
			var root q5.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v,
				root
		}
		*q4.BridgeDLBandwidthValueCodecFieldCompare(&sealed) = func(v q4.DLBandwidth, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaDLBandwidth(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeDLBandwidthValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:DLBandwidth"
			return sealed
		}()
		return sealed
	}()

}

// EARFCNCodec binds the complete source value type.
func EARFCNCodec() q4.EARFCNValueCodec {
	return func() q4.EARFCNValueCodec {
		sealed := q4.EARFCNValueCodec{}
		*q4.BridgeEARFCNValueCodecFieldPath(&sealed) = "EARFCN"
		*q4.BridgeEARFCNValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.EARFCN, error) {
			var zero q4.EARFCN
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeIntegerBigBoundsAligned(bb, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound20, true)
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "EARFCN"); err != nil {
				return zero, err
			}
			return q4.EARFCN(decoded), nil
		}
		*q4.BridgeEARFCNValueCodecFieldEncode(&sealed) = func(value q4.EARFCN, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeIntegerBigBoundsAligned(bb, value, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound20, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeEARFCNValueCodecFieldCapture(&sealed) = func(v q4.EARFCN, options q5.DecodeState) (q4.EARFCN, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.
				Begin()
			q4.BridgeCaptureLPPaEARFCN(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q4.BridgeEARFCNValueCodecFieldCompare(&sealed) = func(v q4.EARFCN, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaEARFCN(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeEARFCNValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:EARFCN"
			return sealed
		}()
		return sealed
	}()

}

// EUTRANCellIdentifierCodec binds the complete source value type.
func EUTRANCellIdentifierCodec() q4.EUTRANCellIdentifierValueCodec {
	return func() q4.EUTRANCellIdentifierValueCodec {
		sealed := q4.EUTRANCellIdentifierValueCodec{}
		*q4.BridgeEUTRANCellIdentifierValueCodecFieldPath(&sealed) = "EUTRANCellIdentifier"
		*q4.BridgeEUTRANCellIdentifierValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.EUTRANCellIdentifier, error) {
			var zero q4.EUTRANCellIdentifier
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			bits, length, err := q5.DecodeBitStringAligned(bb, 28, 28, true)
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "EUTRANCellIdentifier"); err != nil {
				return zero, err
			}
			return q4.EUTRANCellIdentifier(q8.BitString{Bytes: bits, BitLength: length}), nil
		}
		*q4.BridgeEUTRANCellIdentifierValueCodecFieldEncode(&sealed) = func(value q4.EUTRANCellIdentifier, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeBitStringAligned(bb, value.Bytes, value.BitLength, 28, 28, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeEUTRANCellIdentifierValueCodecFieldCapture(&sealed) = func(v q4.EUTRANCellIdentifier, options q5.DecodeState) (q4.EUTRANCellIdentifier, q5.Snapshot,
		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaEUTRANCellIdentifier(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*q4.BridgeEUTRANCellIdentifierValueCodecFieldCompare(&sealed) = func(v q4.EUTRANCellIdentifier, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaEUTRANCellIdentifier(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeEUTRANCellIdentifierValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:EUTRANCellIdentifier"
			return sealed
		}()
		return sealed
	}()

}

// HESSIDCodec binds the complete source value type.
func HESSIDCodec() q4.HESSIDValueCodec {
	return func() q4.HESSIDValueCodec {
		sealed := q4.HESSIDValueCodec{}
		*q4.BridgeHESSIDValueCodecFieldPath(&sealed) = "HESSID"
		*q4.BridgeHESSIDValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.HESSID, error) {
			var zero q4.HESSID
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			octets, err := q5.DecodeOctetStringAligned(bb, 6, 6, true)
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "HESSID"); err != nil {
				return zero, err
			}
			return q4.HESSID(octets), nil
		}
		*q4.BridgeHESSIDValueCodecFieldEncode(&sealed) = func(value q4.HESSID, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeOctetStringAligned(bb, []byte(value), 6, 6, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeHESSIDValueCodecFieldCapture(&sealed) = func(v q4.HESSID, options q5.DecodeState) (q4.HESSID, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.
				Begin()
			q4.BridgeCaptureLPPaHESSID(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q4.BridgeHESSIDValueCodecFieldCompare(&sealed) = func(v q4.HESSID, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaHESSID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeHESSIDValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:HESSID"
			return sealed
		}()
		return sealed
	}()

}

// InterRATMeasurementQuantitiesValueCodec binds the complete source value type.
func InterRATMeasurementQuantitiesValueCodec() q4.InterRATMeasurementQuantitiesValueValueCodec {
	return func() q4.InterRATMeasurementQuantitiesValueValueCodec {
		sealed := q4.InterRATMeasurementQuantitiesValueValueCodec{}
		*q4.BridgeInterRATMeasurementQuantitiesValueValueCodecFieldPath(&sealed) = "InterRATMeasurementQuantitiesValue"
		*q4.BridgeInterRATMeasurementQuantitiesValueValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.InterRATMeasurementQuantitiesValue, error) {
			var zero q4.InterRATMeasurementQuantitiesValue
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 2, true, q5.EnumerationSource{KnownExtensions: 1, Path: "InterRATMeasurementQuantitiesValue"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "InterRATMeasurementQuantitiesValue"); err != nil {
				return zero, err
			}
			return q4.InterRATMeasurementQuantitiesValue(decoded), nil
		}
		*q4.BridgeInterRATMeasurementQuantitiesValueValueCodecFieldEncode(&sealed) = func(value q4.InterRATMeasurementQuantitiesValue, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 2, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeInterRATMeasurementQuantitiesValueValueCodecFieldCapture(&sealed) = func(v q4.InterRATMeasurementQuantitiesValue, options q5.DecodeState) (q4.InterRATMeasurementQuantitiesValue, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaInterRATMeasurementQuantitiesValue(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root,
				false,
			)
			return v, root
		}
		*q4.BridgeInterRATMeasurementQuantitiesValueValueCodecFieldCompare(&sealed) = func(v q4.InterRATMeasurementQuantitiesValue, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaInterRATMeasurementQuantitiesValue(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan()
		}
		*q4.BridgeInterRATMeasurementQuantitiesValueValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:InterRATMeasurementQuantitiesValue"
			return sealed
		}()
		return sealed
	}()

}

// MeasurementQuantitiesValueCodec binds the complete source value type.
func MeasurementQuantitiesValueCodec() q4.MeasurementQuantitiesValueValueCodec {
	return func() q4.MeasurementQuantitiesValueValueCodec {
		sealed := q4.MeasurementQuantitiesValueValueCodec{}
		*q4.BridgeMeasurementQuantitiesValueValueCodecFieldPath(&sealed) = "MeasurementQuantitiesValue"
		*q4.BridgeMeasurementQuantitiesValueValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.MeasurementQuantitiesValue, error) {
			var zero q4.MeasurementQuantitiesValue
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 6, true, q5.EnumerationSource{KnownExtensions: 0, Path: "MeasurementQuantitiesValue"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "MeasurementQuantitiesValue"); err != nil {
				return zero, err
			}
			return q4.MeasurementQuantitiesValue(decoded), nil
		}
		*q4.BridgeMeasurementQuantitiesValueValueCodecFieldEncode(&sealed) = func(value q4.MeasurementQuantitiesValue, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 6, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeMeasurementQuantitiesValueValueCodecFieldCapture(&sealed) = func(v q4.MeasurementQuantitiesValue, options q5.DecodeState) (q4.MeasurementQuantitiesValue, q5.Snapshot,
		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaMeasurementQuantitiesValue(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q4.BridgeMeasurementQuantitiesValueValueCodecFieldCompare(&sealed) = func(v q4.MeasurementQuantitiesValue, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaMeasurementQuantitiesValue(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeMeasurementQuantitiesValueValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementQuantitiesValue"
			return sealed
		}()
		return sealed
	}()

}

// NPRSSequenceInfoCodec binds the complete source value type.
func NPRSSequenceInfoCodec() q4.NPRSSequenceInfoValueCodec {
	return func() q4.NPRSSequenceInfoValueCodec {
		sealed := q4.NPRSSequenceInfoValueCodec{}
		*q4.BridgeNPRSSequenceInfoValueCodecFieldPath(&sealed) = "NPRSSequenceInfo"
		*q4.BridgeNPRSSequenceInfoValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.NPRSSequenceInfo, error) {
			var zero q4.NPRSSequenceInfo
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeIntegerBigBoundsAligned(bb, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound11, true)
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "NPRSSequenceInfo"); err != nil {
				return zero, err
			}
			return q4.NPRSSequenceInfo(decoded), nil
		}
		*q4.BridgeNPRSSequenceInfoValueCodecFieldEncode(&sealed) = func(value q4.NPRSSequenceInfo, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeIntegerBigBoundsAligned(bb, value, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound11, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeNPRSSequenceInfoValueCodecFieldCapture(&sealed) = func(v q4.NPRSSequenceInfo, options q5.DecodeState) (q4.NPRSSequenceInfo, q5.Snapshot) {
			s := q5.SemanticCaptureFor(
				options)
			f := s.Begin()
			q4.BridgeCaptureLPPaNPRSSequenceInfo(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root,
				false,
			)
			return v, root
		}
		*q4.BridgeNPRSSequenceInfoValueCodecFieldCompare(&sealed) = func(v q4.NPRSSequenceInfo, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaNPRSSequenceInfo(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeNPRSSequenceInfoValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:NPRSSequenceInfo"
			return sealed
		}()
		return sealed
	}()

}

// NRCellIdentityCodec binds the complete source value type.
func NRCellIdentityCodec() q4.NRCellIdentityValueCodec {
	return func() q4.NRCellIdentityValueCodec {
		sealed := q4.NRCellIdentityValueCodec{}
		*q4.BridgeNRCellIdentityValueCodecFieldPath(&sealed) = "NRCellIdentity"
		*q4.BridgeNRCellIdentityValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.NRCellIdentity, error) {
			var zero q4.NRCellIdentity
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			bits, length, err := q5.DecodeBitStringAligned(bb, 36, 36, true)
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "NRCellIdentity"); err != nil {
				return zero, err
			}
			return q4.NRCellIdentity(q8.BitString{Bytes: bits, BitLength: length}), nil
		}
		*q4.BridgeNRCellIdentityValueCodecFieldEncode(&sealed) = func(value q4.NRCellIdentity, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeBitStringAligned(bb, value.Bytes, value.BitLength, 36, 36, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeNRCellIdentityValueCodecFieldCapture(&sealed) = func(v q4.NRCellIdentity, options q5.DecodeState) (q4.NRCellIdentity, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaNRCellIdentity(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q4.BridgeNRCellIdentityValueCodecFieldCompare(&sealed) = func(v q4.NRCellIdentity, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaNRCellIdentity(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeNRCellIdentityValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:NRCellIdentity"
			return sealed
		}()
		return sealed
	}()

}

// NarrowBandIndexCodec binds the complete source value type.
func NarrowBandIndexCodec() q4.NarrowBandIndexValueCodec {
	return func() q4.NarrowBandIndexValueCodec {
		sealed := q4.NarrowBandIndexValueCodec{}
		*q4.BridgeNarrowBandIndexValueCodecFieldPath(&sealed) = "NarrowBandIndex"
		*q4.BridgeNarrowBandIndexValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.NarrowBandIndex, error) {
			var zero q4.NarrowBandIndex
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeIntegerBigBoundsAligned(bb, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound7, true)
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "NarrowBandIndex"); err != nil {
				return zero, err
			}
			return q4.NarrowBandIndex(decoded), nil
		}
		*q4.BridgeNarrowBandIndexValueCodecFieldEncode(&sealed) = func(value q4.NarrowBandIndex, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeIntegerBigBoundsAligned(bb, value, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound7, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeNarrowBandIndexValueCodecFieldCapture(&sealed) = func(v q4.NarrowBandIndex, options q5.DecodeState) (q4.NarrowBandIndex, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaNarrowBandIndex(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q4.BridgeNarrowBandIndexValueCodecFieldCompare(&sealed) = func(v q4.NarrowBandIndex, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaNarrowBandIndex(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeNarrowBandIndexValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:NarrowBandIndex"
			return sealed
		}()
		return sealed
	}()

}

// NumberOfAntennaPortsCodec binds the complete source value type.
func NumberOfAntennaPortsCodec() q4.NumberOfAntennaPortsValueCodec {
	return func() q4.NumberOfAntennaPortsValueCodec {
		sealed := q4.NumberOfAntennaPortsValueCodec{}
		*q4.BridgeNumberOfAntennaPortsValueCodecFieldPath(&sealed) = "NumberOfAntennaPorts"
		*q4.BridgeNumberOfAntennaPortsValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.NumberOfAntennaPorts, error) {
			var zero q4.NumberOfAntennaPorts
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 2, true, q5.EnumerationSource{KnownExtensions: 0, Path: "NumberOfAntennaPorts"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "NumberOfAntennaPorts"); err != nil {
				return zero, err
			}
			return q4.NumberOfAntennaPorts(decoded), nil
		}
		*q4.BridgeNumberOfAntennaPortsValueCodecFieldEncode(&sealed) = func(value q4.NumberOfAntennaPorts, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 2, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeNumberOfAntennaPortsValueCodecFieldCapture(&sealed) = func(v q4.NumberOfAntennaPorts, options q5.DecodeState) (q4.NumberOfAntennaPorts, q5.Snapshot,
		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaNumberOfAntennaPorts(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*q4.BridgeNumberOfAntennaPortsValueCodecFieldCompare(&sealed) = func(v q4.NumberOfAntennaPorts, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaNumberOfAntennaPorts(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeNumberOfAntennaPortsValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:NumberOfAntennaPorts"
			return sealed
		}()
		return sealed
	}()

}

// NumberOfDlFramesCodec binds the complete source value type.
func NumberOfDlFramesCodec() q4.NumberOfDlFramesValueCodec {
	return func() q4.NumberOfDlFramesValueCodec {
		sealed := q4.NumberOfDlFramesValueCodec{}
		*q4.BridgeNumberOfDlFramesValueCodecFieldPath(&sealed) = "NumberOfDlFrames"
		*q4.BridgeNumberOfDlFramesValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.NumberOfDlFrames, error) {
			var zero q4.NumberOfDlFrames
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 4, true, q5.EnumerationSource{KnownExtensions: 0, Path: "NumberOfDlFrames"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "NumberOfDlFrames"); err != nil {
				return zero, err
			}
			return q4.NumberOfDlFrames(decoded), nil
		}
		*q4.BridgeNumberOfDlFramesValueCodecFieldEncode(&sealed) = func(value q4.NumberOfDlFrames, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 4, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeNumberOfDlFramesValueCodecFieldCapture(&sealed) = func(v q4.NumberOfDlFrames, options q5.DecodeState) (q4.NumberOfDlFrames, q5.Snapshot) {
			s := q5.SemanticCaptureFor(
				options)
			f := s.Begin()
			q4.BridgeCaptureLPPaNumberOfDlFrames(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root,
				false,
			)
			return v, root
		}
		*q4.BridgeNumberOfDlFramesValueCodecFieldCompare(&sealed) = func(v q4.NumberOfDlFrames, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaNumberOfDlFrames(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q4.BridgeNumberOfDlFramesValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:NumberOfDlFrames"
			return sealed
		}()
		return sealed
	}()

}

// NumberOfDlFramesExtendedCodec binds the complete source value type.
func NumberOfDlFramesExtendedCodec() q4.NumberOfDlFramesExtendedValueCodec {
	return func() q4.NumberOfDlFramesExtendedValueCodec {
		sealed := q4.NumberOfDlFramesExtendedValueCodec{}
		*q4.BridgeNumberOfDlFramesExtendedValueCodecFieldPath(&sealed) = "NumberOfDlFramesExtended"
		*q4.BridgeNumberOfDlFramesExtendedValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.NumberOfDlFramesExtended, error) {
			var zero q4.NumberOfDlFramesExtended
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeIntegerBigBoundsAligned(bb, q4.BridgeAsn1IntegerBound2, q4.BridgeAsn1IntegerBound9, true)
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "NumberOfDlFramesExtended"); err != nil {
				return zero, err
			}
			return q4.NumberOfDlFramesExtended(decoded), nil
		}
		*q4.BridgeNumberOfDlFramesExtendedValueCodecFieldEncode(&sealed) = func(value q4.NumberOfDlFramesExtended, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeIntegerBigBoundsAligned(bb, value, q4.BridgeAsn1IntegerBound2, q4.BridgeAsn1IntegerBound9, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q4.BridgeNumberOfDlFramesExtendedValueCodecFieldCapture(&sealed) = func(v q4.NumberOfDlFramesExtended, options q5.DecodeState) (q4.NumberOfDlFramesExtended, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaNumberOfDlFramesExtended(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q4.BridgeNumberOfDlFramesExtendedValueCodecFieldCompare(&sealed) = func(v q4.NumberOfDlFramesExtended, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaNumberOfDlFramesExtended(&v, &s)
			s.End(f, root, false)
			return s.
				Plan()
		}
		*q4.BridgeNumberOfDlFramesExtendedValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:NumberOfDlFramesExtended"
			return sealed
		}()
		return sealed
	}()

}

// NumberOfFrequencyHoppingBandsCodec binds the complete source value type.
func NumberOfFrequencyHoppingBandsCodec() q6.NumberOfFrequencyHoppingBandsValueCodec {
	return func() q6.NumberOfFrequencyHoppingBandsValueCodec {
		sealed := q6.NumberOfFrequencyHoppingBandsValueCodec{}
		*q6.BridgeNumberOfFrequencyHoppingBandsValueCodecFieldPath(&sealed) = "NumberOfFrequencyHoppingBands"
		*q6.BridgeNumberOfFrequencyHoppingBandsValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.NumberOfFrequencyHoppingBands, error) {
			var zero q4.NumberOfFrequencyHoppingBands
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 2, true, q5.EnumerationSource{KnownExtensions: 0, Path: "NumberOfFrequencyHoppingBands"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "NumberOfFrequencyHoppingBands"); err != nil {
				return zero, err
			}
			return q4.NumberOfFrequencyHoppingBands(decoded), nil
		}
		*q6.BridgeNumberOfFrequencyHoppingBandsValueCodecFieldEncode(&sealed) = func(value q4.NumberOfFrequencyHoppingBands, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 2, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgeNumberOfFrequencyHoppingBandsValueCodecFieldCapture(&sealed) = func(v q4.NumberOfFrequencyHoppingBands, options q5.DecodeState) (q4.NumberOfFrequencyHoppingBands, q5.Snapshot,

		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaNumberOfFrequencyHoppingBands(&v, &s)
			var root q5.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v,

				root
		}
		*q6.BridgeNumberOfFrequencyHoppingBandsValueCodecFieldCompare(&sealed) = func(v q4.NumberOfFrequencyHoppingBands, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaNumberOfFrequencyHoppingBands(&v, &s)
			s.End(f, root, false)

			return s.Plan()
		}
		*q6.BridgeNumberOfFrequencyHoppingBandsValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:NumberOfFrequencyHoppingBands"
			return sealed
		}()
		return sealed
	}()

}

// OTDOAInformationItemCodec binds the complete source value type.
func OTDOAInformationItemCodec() q6.OTDOAInformationItemValueCodec {
	return func() q6.OTDOAInformationItemValueCodec {
		sealed := q6.OTDOAInformationItemValueCodec{}
		*q6.BridgeOTDOAInformationItemValueCodecFieldPath(&sealed) = "OTDOAInformationItem"
		*q6.BridgeOTDOAInformationItemValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.OTDOAInformationItem, error) {
			var zero q4.OTDOAInformationItem
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 10, true, q5.EnumerationSource{KnownExtensions: 19, Path: "OTDOAInformationItem"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "OTDOAInformationItem"); err != nil {
				return zero, err
			}
			return q4.OTDOAInformationItem(decoded), nil
		}
		*q6.BridgeOTDOAInformationItemValueCodecFieldEncode(&sealed) = func(value q4.OTDOAInformationItem, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 10, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgeOTDOAInformationItemValueCodecFieldCapture(&sealed) = func(v q4.OTDOAInformationItem, options q5.DecodeState) (q4.OTDOAInformationItem, q5.Snapshot,
		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaOTDOAInformationItem(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*q6.BridgeOTDOAInformationItemValueCodecFieldCompare(&sealed) = func(v q4.OTDOAInformationItem, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaOTDOAInformationItem(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q6.BridgeOTDOAInformationItemValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:OTDOAInformationItem"
			return sealed
		}()
		return sealed
	}()

}

// OffsetNBChanneltoEARFCNCodec binds the complete source value type.
func OffsetNBChanneltoEARFCNCodec() q6.OffsetNBChanneltoEARFCNValueCodec {
	return func() q6.OffsetNBChanneltoEARFCNValueCodec {
		sealed := q6.OffsetNBChanneltoEARFCNValueCodec{}
		*q6.BridgeOffsetNBChanneltoEARFCNValueCodecFieldPath(&sealed) = "OffsetNBChanneltoEARFCN"
		*q6.BridgeOffsetNBChanneltoEARFCNValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.OffsetNBChanneltoEARFCN, error) {
			var zero q4.OffsetNBChanneltoEARFCN
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 21, true, q5.EnumerationSource{KnownExtensions: 0, Path: "OffsetNBChanneltoEARFCN"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "OffsetNBChanneltoEARFCN"); err != nil {
				return zero, err
			}
			return q4.OffsetNBChanneltoEARFCN(decoded), nil
		}
		*q6.BridgeOffsetNBChanneltoEARFCNValueCodecFieldEncode(&sealed) = func(value q4.OffsetNBChanneltoEARFCN, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 21, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgeOffsetNBChanneltoEARFCNValueCodecFieldCapture(&sealed) = func(v q4.OffsetNBChanneltoEARFCN, options q5.DecodeState) (q4.OffsetNBChanneltoEARFCN, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaOffsetNBChanneltoEARFCN(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q6.BridgeOffsetNBChanneltoEARFCNValueCodecFieldCompare(&sealed) = func(v q4.OffsetNBChanneltoEARFCN, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaOffsetNBChanneltoEARFCN(&v, &s)
			s.End(f, root, false)
			return s.
				Plan()
		}
		*q6.BridgeOffsetNBChanneltoEARFCNValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:OffsetNBChanneltoEARFCN"
			return sealed
		}()
		return sealed
	}()

}

// OperationModeInfoCodec binds the complete source value type.
func OperationModeInfoCodec() q6.OperationModeInfoValueCodec {
	return func() q6.OperationModeInfoValueCodec {
		sealed := q6.OperationModeInfoValueCodec{}
		*q6.BridgeOperationModeInfoValueCodecFieldPath(&sealed) = "OperationModeInfo"
		*q6.BridgeOperationModeInfoValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.OperationModeInfo, error) {
			var zero q4.OperationModeInfo
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 3, true, q5.EnumerationSource{KnownExtensions: 0, Path: "OperationModeInfo"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "OperationModeInfo"); err != nil {
				return zero, err
			}
			return q4.OperationModeInfo(decoded), nil
		}
		*q6.BridgeOperationModeInfoValueCodecFieldEncode(&sealed) = func(value q4.OperationModeInfo, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 3, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgeOperationModeInfoValueCodecFieldCapture(&sealed) = func(v q4.OperationModeInfo, options q5.DecodeState) (q4.OperationModeInfo, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaOperationModeInfo(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root,

				false)
			return v, root
		}
		*q6.BridgeOperationModeInfoValueCodecFieldCompare(&sealed) = func(v q4.OperationModeInfo, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaOperationModeInfo(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q6.BridgeOperationModeInfoValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:OperationModeInfo"
			return sealed
		}()
		return sealed
	}()

}

// OutcomeCodec binds the complete source value type.
func OutcomeCodec() q6.OutcomeValueCodec {
	return func() q6.OutcomeValueCodec {
		sealed := q6.OutcomeValueCodec{}
		*q6.BridgeOutcomeValueCodecFieldPath(&sealed) = "Outcome"
		*q6.BridgeOutcomeValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.Outcome, error) {
			var zero q4.Outcome
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 1, true, q5.EnumerationSource{KnownExtensions: 0, Path: "Outcome"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "Outcome"); err != nil {
				return zero, err
			}
			return q4.Outcome(decoded), nil
		}
		*q6.BridgeOutcomeValueCodecFieldEncode(&sealed) = func(value q4.Outcome, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 1, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgeOutcomeValueCodecFieldCapture(&sealed) = func(v q4.Outcome, options q5.DecodeState) (q4.Outcome, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f :=
				s.Begin()
			q4.BridgeCaptureLPPaOutcome(&v, &s)
			var root q5.Snapshot
			s.
				OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q6.BridgeOutcomeValueCodecFieldCompare(&sealed) = func(v q4.Outcome, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(
				root, limits)
			f := s.Begin()
			BridgeCompareLPPaOutcome(&v, &s)
			s.
				End(f, root, false)
			return s.Plan()
		}
		*q6.BridgeOutcomeValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:Outcome"
			return sealed
		}()
		return sealed
	}()

}

// PCICodec binds the complete source value type.
func PCICodec() q6.PCIValueCodec {
	return func() q6.PCIValueCodec {
		sealed := q6.PCIValueCodec{}
		*q6.BridgePCIValueCodecFieldPath(&sealed) = "PCI"
		*q6.BridgePCIValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.PCI, error) {
			var zero q4.PCI
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeIntegerBigBoundsAligned(bb, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound17, true)
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "PCI"); err != nil {
				return zero, err
			}
			return q4.PCI(decoded), nil
		}
		*q6.BridgePCIValueCodecFieldEncode(&sealed) = func(value q4.PCI, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeIntegerBigBoundsAligned(bb, value, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound17, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgePCIValueCodecFieldCapture(&sealed) = func(v q4.PCI, options q5.DecodeState) (q4.PCI, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaPCI(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q6.BridgePCIValueCodecFieldCompare(&sealed) = func(v q4.PCI, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaPCI(&v, &s)
			s.End(f, root,
				false)
			return s.Plan()
		}
		*q6.BridgePCIValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:PCI"
			return sealed
		}()
		return sealed
	}()

}

// PLMNIdentityCodec binds the complete source value type.
func PLMNIdentityCodec() q6.PLMNIdentityValueCodec {
	return func() q6.PLMNIdentityValueCodec {
		sealed := q6.PLMNIdentityValueCodec{}
		*q6.BridgePLMNIdentityValueCodecFieldPath(&sealed) = "PLMNIdentity"
		*q6.BridgePLMNIdentityValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.PLMNIdentity, error) {
			var zero q4.PLMNIdentity
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			octets, err := q5.DecodeOctetStringAligned(bb, 3, 3, true)
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "PLMNIdentity"); err != nil {
				return zero, err
			}
			return q4.PLMNIdentity(octets), nil
		}
		*q6.BridgePLMNIdentityValueCodecFieldEncode(&sealed) = func(value q4.PLMNIdentity, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeOctetStringAligned(bb, []byte(value), 3, 3, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgePLMNIdentityValueCodecFieldCapture(&sealed) = func(v q4.PLMNIdentity, options q5.DecodeState) (q4.PLMNIdentity, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaPLMNIdentity(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q6.BridgePLMNIdentityValueCodecFieldCompare(&sealed) = func(v q4.PLMNIdentity, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaPLMNIdentity(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q6.BridgePLMNIdentityValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:PLMNIdentity"
			return sealed
		}()
		return sealed
	}()

}

// PRSBandwidthCodec binds the complete source value type.
func PRSBandwidthCodec() q6.PRSBandwidthValueCodec {
	return func() q6.PRSBandwidthValueCodec {
		sealed := q6.PRSBandwidthValueCodec{}
		*q6.BridgePRSBandwidthValueCodecFieldPath(&sealed) = "PRSBandwidth"
		*q6.BridgePRSBandwidthValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.PRSBandwidth, error) {
			var zero q4.PRSBandwidth
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 6, true, q5.EnumerationSource{KnownExtensions: 0, Path: "PRSBandwidth"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "PRSBandwidth"); err != nil {
				return zero, err
			}
			return q4.PRSBandwidth(decoded), nil
		}
		*q6.BridgePRSBandwidthValueCodecFieldEncode(&sealed) = func(value q4.PRSBandwidth, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 6, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgePRSBandwidthValueCodecFieldCapture(&sealed) = func(v q4.PRSBandwidth, options q5.DecodeState) (q4.PRSBandwidth, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaPRSBandwidth(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q6.BridgePRSBandwidthValueCodecFieldCompare(&sealed) = func(v q4.PRSBandwidth, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaPRSBandwidth(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q6.BridgePRSBandwidthValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:PRSBandwidth"
			return sealed
		}()
		return sealed
	}()

}

// PRSConfigurationIndexCodec binds the complete source value type.
func PRSConfigurationIndexCodec() q6.PRSConfigurationIndexValueCodec {
	return func() q6.PRSConfigurationIndexValueCodec {
		sealed := q6.PRSConfigurationIndexValueCodec{}
		*q6.BridgePRSConfigurationIndexValueCodecFieldPath(&sealed) = "PRSConfigurationIndex"
		*q6.BridgePRSConfigurationIndexValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.PRSConfigurationIndex, error) {
			var zero q4.PRSConfigurationIndex
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeIntegerBigBoundsAligned(bb, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound14, true)
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "PRSConfigurationIndex"); err != nil {
				return zero, err
			}
			return q4.PRSConfigurationIndex(decoded), nil
		}
		*q6.BridgePRSConfigurationIndexValueCodecFieldEncode(&sealed) = func(value q4.PRSConfigurationIndex, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeIntegerBigBoundsAligned(bb, value, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound14, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgePRSConfigurationIndexValueCodecFieldCapture(&sealed) = func(v q4.PRSConfigurationIndex, options q5.DecodeState) (q4.PRSConfigurationIndex, q5.Snapshot,
		) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaPRSConfigurationIndex(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*q6.BridgePRSConfigurationIndexValueCodecFieldCompare(&sealed) = func(v q4.PRSConfigurationIndex, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaPRSConfigurationIndex(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q6.BridgePRSConfigurationIndexValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:PRSConfigurationIndex"
			return sealed
		}()
		return sealed
	}()

}

// PRSIDCodec binds the complete source value type.
func PRSIDCodec() q6.PRSIDValueCodec {
	return func() q6.PRSIDValueCodec {
		sealed := q6.PRSIDValueCodec{}
		*q6.BridgePRSIDValueCodecFieldPath(&sealed) = "PRSID"
		*q6.BridgePRSIDValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.PRSID, error) {
			var zero q4.PRSID
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeIntegerBigBoundsAligned(bb, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound14, true)
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "PRSID"); err != nil {
				return zero, err
			}
			return q4.PRSID(decoded), nil
		}
		*q6.BridgePRSIDValueCodecFieldEncode(&sealed) = func(value q4.PRSID, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeIntegerBigBoundsAligned(bb, value, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound14, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgePRSIDValueCodecFieldCapture(&sealed) = func(v q4.PRSID, options q5.DecodeState) (q4.PRSID, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaPRSID(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q6.BridgePRSIDValueCodecFieldCompare(&sealed) = func(v q4.PRSID, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			BridgeCompareLPPaPRSID(&v, &s)
			s.End(
				f, root, false)
			return s.Plan()
		}
		*q6.BridgePRSIDValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:PRSID"
			return sealed
		}()
		return sealed
	}()

}

// PRSOccasionGroupCodec binds the complete source value type.
func PRSOccasionGroupCodec() q6.PRSOccasionGroupValueCodec {
	return func() q6.PRSOccasionGroupValueCodec {
		sealed := q6.PRSOccasionGroupValueCodec{}
		*q6.BridgePRSOccasionGroupValueCodecFieldPath(&sealed) = "PRSOccasionGroup"
		*q6.BridgePRSOccasionGroupValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.PRSOccasionGroup, error) {
			var zero q4.PRSOccasionGroup
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 7, true, q5.EnumerationSource{KnownExtensions: 0, Path: "PRSOccasionGroup"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "PRSOccasionGroup"); err != nil {
				return zero, err
			}
			return q4.PRSOccasionGroup(decoded), nil
		}
		*q6.BridgePRSOccasionGroupValueCodecFieldEncode(&sealed) = func(value q4.PRSOccasionGroup, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 7, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgePRSOccasionGroupValueCodecFieldCapture(&sealed) = func(v q4.PRSOccasionGroup, options q5.DecodeState) (q4.PRSOccasionGroup, q5.Snapshot) {
			s := q5.SemanticCaptureFor(
				options)
			f := s.Begin()
			q4.BridgeCaptureLPPaPRSOccasionGroup(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root,
				false,
			)
			return v, root
		}
		*q6.BridgePRSOccasionGroupValueCodecFieldCompare(&sealed) = func(v q4.PRSOccasionGroup, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaPRSOccasionGroup(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q6.BridgePRSOccasionGroupValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:PRSOccasionGroup"
			return sealed
		}()
		return sealed
	}()

}

// PhysCellIDGERANCodec binds the complete source value type.
func PhysCellIDGERANCodec() q6.PhysCellIDGERANValueCodec {
	return func() q6.PhysCellIDGERANValueCodec {
		sealed := q6.PhysCellIDGERANValueCodec{}
		*q6.BridgePhysCellIDGERANValueCodecFieldPath(&sealed) = "PhysCellIDGERAN"
		*q6.BridgePhysCellIDGERANValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.PhysCellIDGERAN, error) {
			var zero q4.PhysCellIDGERAN
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeIntegerBigBoundsAligned(bb, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound19, true)
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "PhysCellIDGERAN"); err != nil {
				return zero, err
			}
			return q4.PhysCellIDGERAN(decoded), nil
		}
		*q6.BridgePhysCellIDGERANValueCodecFieldEncode(&sealed) = func(value q4.PhysCellIDGERAN, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeIntegerBigBoundsAligned(bb, value, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound19, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgePhysCellIDGERANValueCodecFieldCapture(&sealed) = func(v q4.PhysCellIDGERAN, options q5.DecodeState) (q4.PhysCellIDGERAN, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaPhysCellIDGERAN(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q6.BridgePhysCellIDGERANValueCodecFieldCompare(&sealed) = func(v q4.PhysCellIDGERAN, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaPhysCellIDGERAN(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q6.BridgePhysCellIDGERANValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:PhysCellIDGERAN"
			return sealed
		}()
		return sealed
	}()

}

// PhysCellIDUTRAFDDCodec binds the complete source value type.
func PhysCellIDUTRAFDDCodec() q6.PhysCellIDUTRAFDDValueCodec {
	return func() q6.PhysCellIDUTRAFDDValueCodec {
		sealed := q6.PhysCellIDUTRAFDDValueCodec{}
		*q6.BridgePhysCellIDUTRAFDDValueCodecFieldPath(&sealed) = "PhysCellIDUTRAFDD"
		*q6.BridgePhysCellIDUTRAFDDValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.PhysCellIDUTRAFDD, error) {
			var zero q4.PhysCellIDUTRAFDD
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeIntegerBigBoundsAligned(bb, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound18, true)
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "PhysCellIDUTRAFDD"); err != nil {
				return zero, err
			}
			return q4.PhysCellIDUTRAFDD(decoded), nil
		}
		*q6.BridgePhysCellIDUTRAFDDValueCodecFieldEncode(&sealed) = func(value q4.PhysCellIDUTRAFDD, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeIntegerBigBoundsAligned(bb, value, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound18, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgePhysCellIDUTRAFDDValueCodecFieldCapture(&sealed) = func(v q4.PhysCellIDUTRAFDD, options q5.DecodeState) (q4.PhysCellIDUTRAFDD, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaPhysCellIDUTRAFDD(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root,

				false)
			return v, root
		}
		*q6.BridgePhysCellIDUTRAFDDValueCodecFieldCompare(&sealed) = func(v q4.PhysCellIDUTRAFDD, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaPhysCellIDUTRAFDD(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q6.BridgePhysCellIDUTRAFDDValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:PhysCellIDUTRAFDD"
			return sealed
		}()
		return sealed
	}()

}

// PhysCellIDUTRATDDCodec binds the complete source value type.
func PhysCellIDUTRATDDCodec() q6.PhysCellIDUTRATDDValueCodec {
	return func() q6.PhysCellIDUTRATDDValueCodec {
		sealed := q6.PhysCellIDUTRATDDValueCodec{}
		*q6.BridgePhysCellIDUTRATDDValueCodecFieldPath(&sealed) = "PhysCellIDUTRATDD"
		*q6.BridgePhysCellIDUTRATDDValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.PhysCellIDUTRATDD, error) {
			var zero q4.PhysCellIDUTRATDD
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeIntegerBigBoundsAligned(bb, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound5, true)
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "PhysCellIDUTRATDD"); err != nil {
				return zero, err
			}
			return q4.PhysCellIDUTRATDD(decoded), nil
		}
		*q6.BridgePhysCellIDUTRATDDValueCodecFieldEncode(&sealed) = func(value q4.PhysCellIDUTRATDD, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeIntegerBigBoundsAligned(bb, value, q4.BridgeAsn1IntegerBound1, q4.BridgeAsn1IntegerBound5, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgePhysCellIDUTRATDDValueCodecFieldCapture(&sealed) = func(v q4.PhysCellIDUTRATDD, options q5.DecodeState) (q4.PhysCellIDUTRATDD, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f := s.Begin()
			q4.BridgeCaptureLPPaPhysCellIDUTRATDD(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root,

				false)
			return v, root
		}
		*q6.BridgePhysCellIDUTRATDDValueCodecFieldCompare(&sealed) = func(v q4.PhysCellIDUTRATDD, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaPhysCellIDUTRATDD(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q6.BridgePhysCellIDUTRATDDValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:PhysCellIDUTRATDD"
			return sealed
		}()
		return sealed
	}()

}

// PosSIBTypeCodec binds the complete source value type.
func PosSIBTypeCodec() q6.PosSIBTypeValueCodec {
	return func() q6.PosSIBTypeValueCodec {
		sealed := q6.PosSIBTypeValueCodec{}
		*q6.BridgePosSIBTypeValueCodecFieldPath(&sealed) = "PosSIBType"
		*q6.BridgePosSIBTypeValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.PosSIBType, error) {
			var zero q4.PosSIBType
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 27, true, q5.EnumerationSource{KnownExtensions: 4, Path: "PosSIBType"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "PosSIBType"); err != nil {
				return zero, err
			}
			return q4.PosSIBType(decoded), nil
		}
		*q6.BridgePosSIBTypeValueCodecFieldEncode(&sealed) = func(value q4.PosSIBType, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 27, true); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgePosSIBTypeValueCodecFieldCapture(&sealed) = func(v q4.PosSIBType, options q5.DecodeState) (q4.PosSIBType, q5.Snapshot) {
			s := q5.SemanticCaptureFor(options)
			f :=
				s.Begin()
			q4.BridgeCaptureLPPaPosSIBType(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root

		}
		*q6.BridgePosSIBTypeValueCodecFieldCompare(&sealed) = func(v q4.PosSIBType, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaPosSIBType(&v,
				&s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q6.BridgePosSIBTypeValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:PosSIBType"
			return sealed
		}()
		return sealed
	}()

}

// PresenceCodec binds the complete source value type.
func PresenceCodec() q6.PresenceValueCodec {
	return func() q6.PresenceValueCodec {
		sealed := q6.PresenceValueCodec{}
		*q6.BridgePresenceValueCodecFieldPath(&sealed) = "Presence"
		*q6.BridgePresenceValueCodecFieldDecode(&sealed) = func(data []byte, options q5.DecodeState) (q4.Presence, error) {
			var zero q4.Presence
			bb := q5.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return zero, err
			}
			decoded, err := q5.DecodeEnumeratedAligned(bb, 3, false, q5.EnumerationSource{KnownExtensions: 0, Path: "Presence"})
			if err != nil {
				return zero, err
			}
			if _, err := q5.CaptureFinalBits(bb, "Presence"); err != nil {
				return zero, err
			}
			return q4.Presence(decoded), nil
		}
		*q6.BridgePresenceValueCodecFieldEncode(&sealed) = func(value q4.Presence, _ bool, budget *q5.DecodeBudget) ([]byte, error) {
			bb := q5.NewBudgetBuffer(budget)
			if err := q5.EncodeEnumeratedAligned(bb, int64(value), 3, false); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*q6.BridgePresenceValueCodecFieldCapture(&sealed) = func(v q4.Presence, options q5.DecodeState) (q4.Presence, q5.Snapshot) {
			s := q5.SemanticCaptureFor(
				options)
			f := s.Begin()
			q4.BridgeCaptureLPPaPresence(&v, &s)
			var root q5.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q6.BridgePresenceValueCodecFieldCompare(&sealed) = func(v q4.Presence, root q5.Snapshot, limits q5.ComparisonLimits) q5.ReplayPlan {
			s := q5.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaPresence(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q6.BridgePresenceValueCodecFieldContext(&sealed) = func() q4.BridgeCodecContext {
			sealed := q4.BridgeCodecContext{}
			*q4.BridgecodecContextFieldSource(&sealed) = "source-value:Presence"
			return sealed
		}()
		return sealed
	}()

}
func BridgeAddOTDOACellsExtIEsValueFieldId(v *AddOTDOACellsExtIEsValue) *q4.ProtocolIEID {
	return &v.id
}
func BridgeAddOTDOACellsExtIEsValueFieldIsOpaque(v *AddOTDOACellsExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeAddOTDOACellsExtIEsValueFieldOpaque(v *AddOTDOACellsExtIEsValue) **q5.OpaqueOpenType {
	return &v.opaque
}
func BridgeAddOTDOACellsExtIEsValueFieldReceived(v *AddOTDOACellsExtIEsValue) *q5.WireSpan {
	return &v.received
}
func BridgeAddOTDOACellsExtIEsValueFieldReplay(v *AddOTDOACellsExtIEsValue) *q5.Snapshot {
	return &v.replay
}
func BridgeAddOTDOACellsExtIEsValueFieldWithoutReplay(v *AddOTDOACellsExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeAddOTDOACellsExtIEsValueMethodCaptureFraming(v AddOTDOACellsExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeAddOTDOACellsExtIEsValueMethodCaptureSemantics(v AddOTDOACellsExtIEsValue, a0 q5.SemanticCapture) AddOTDOACellsExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeAddOTDOACellsExtIEsValueMethodCaptureSnapshot(v AddOTDOACellsExtIEsValue) q5.Snapshot {
	return v.captureSnapshot()
}
func BridgeAddOTDOACellsExtIEsValueMethodCompareSemantics(v AddOTDOACellsExtIEsValue, a0 q5.SemanticComparison) q5.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeAddOTDOACellsExtIEsValueMethodDecode(v AddOTDOACellsExtIEsValue, a0 q4.ProtocolIEID, a1 q5.OpaqueOpenType) (AddOTDOACellsExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeAddOTDOACellsExtIEsValueMethodEncode(v AddOTDOACellsExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeAddOTDOACellsExtIEsValueMethodEncodeFresh(v AddOTDOACellsExtIEsValue, a0 bool, a1 *q5.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeAddOTDOACellsExtIEsValueMethodMatchesID(v AddOTDOACellsExtIEsValue, a0 q4.ProtocolIEID, a1 *q5.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeAddOTDOACellsExtIEsValueMethodReason(v AddOTDOACellsExtIEsValue, a0 q4.ProtocolIEID) q5.OpaqueReason {
	return v.reason(a0)
}
func BridgeAddOTDOACellsExtIEsValueMethodRule(v AddOTDOACellsExtIEsValue) q5.SourceRule {
	return v.rule()
}
func BridgeAssistanceInformationExtIEsValueFieldId(v *AssistanceInformationExtIEsValue) *q4.ProtocolIEID {
	return &v.id
}
func BridgeAssistanceInformationExtIEsValueFieldIsOpaque(v *AssistanceInformationExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeAssistanceInformationExtIEsValueFieldOpaque(v *AssistanceInformationExtIEsValue) **q5.OpaqueOpenType {
	return &v.opaque
}
func BridgeAssistanceInformationExtIEsValueFieldReceived(v *AssistanceInformationExtIEsValue) *q5.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationExtIEsValueFieldReplay(v *AssistanceInformationExtIEsValue) *q5.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationExtIEsValueFieldWithoutReplay(v *AssistanceInformationExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationExtIEsValueMethodCaptureFraming(v AssistanceInformationExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeAssistanceInformationExtIEsValueMethodCaptureSemantics(v AssistanceInformationExtIEsValue, a0 q5.SemanticCapture) AssistanceInformationExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeAssistanceInformationExtIEsValueMethodCaptureSnapshot(v AssistanceInformationExtIEsValue) q5.Snapshot {
	return v.captureSnapshot()
}
func BridgeAssistanceInformationExtIEsValueMethodCompareSemantics(v AssistanceInformationExtIEsValue, a0 q5.SemanticComparison) q5.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeAssistanceInformationExtIEsValueMethodDecode(v AssistanceInformationExtIEsValue, a0 q4.ProtocolIEID, a1 q5.OpaqueOpenType) (AssistanceInformationExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeAssistanceInformationExtIEsValueMethodEncode(v AssistanceInformationExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeAssistanceInformationExtIEsValueMethodEncodeFresh(v AssistanceInformationExtIEsValue, a0 bool, a1 *q5.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeAssistanceInformationExtIEsValueMethodMatchesID(v AssistanceInformationExtIEsValue, a0 q4.ProtocolIEID, a1 *q5.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeAssistanceInformationExtIEsValueMethodReason(v AssistanceInformationExtIEsValue, a0 q4.ProtocolIEID) q5.OpaqueReason {
	return v.reason(a0)
}
func BridgeAssistanceInformationExtIEsValueMethodRule(v AssistanceInformationExtIEsValue) q5.SourceRule {
	return v.rule()
}
func BridgeAssistanceInformationFailureListExtIEsValueFieldId(v *AssistanceInformationFailureListExtIEsValue) *q4.ProtocolIEID {
	return &v.id
}
func BridgeAssistanceInformationFailureListExtIEsValueFieldIsOpaque(v *AssistanceInformationFailureListExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeAssistanceInformationFailureListExtIEsValueFieldOpaque(v *AssistanceInformationFailureListExtIEsValue) **q5.OpaqueOpenType {
	return &v.opaque
}
func BridgeAssistanceInformationFailureListExtIEsValueFieldReceived(v *AssistanceInformationFailureListExtIEsValue) *q5.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationFailureListExtIEsValueFieldReplay(v *AssistanceInformationFailureListExtIEsValue) *q5.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFailureListExtIEsValueFieldWithoutReplay(v *AssistanceInformationFailureListExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodCaptureFraming(v AssistanceInformationFailureListExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodCaptureSemantics(v AssistanceInformationFailureListExtIEsValue, a0 q5.SemanticCapture) AssistanceInformationFailureListExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodCaptureSnapshot(v AssistanceInformationFailureListExtIEsValue) q5.Snapshot {
	return v.captureSnapshot()
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodCompareSemantics(v AssistanceInformationFailureListExtIEsValue, a0 q5.SemanticComparison) q5.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodDecode(v AssistanceInformationFailureListExtIEsValue, a0 q4.ProtocolIEID, a1 q5.OpaqueOpenType) (AssistanceInformationFailureListExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodEncode(v AssistanceInformationFailureListExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodEncodeFresh(v AssistanceInformationFailureListExtIEsValue, a0 bool, a1 *q5.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodMatchesID(v AssistanceInformationFailureListExtIEsValue, a0 q4.ProtocolIEID, a1 *q5.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodReason(v AssistanceInformationFailureListExtIEsValue, a0 q4.ProtocolIEID) q5.OpaqueReason {
	return v.reason(a0)
}
func BridgeAssistanceInformationFailureListExtIEsValueMethodRule(v AssistanceInformationFailureListExtIEsValue) q5.SourceRule {
	return v.rule()
}
func BridgeAssistanceInformationMetaDataExtIEsValueFieldId(v *AssistanceInformationMetaDataExtIEsValue) *q4.ProtocolIEID {
	return &v.id
}
func BridgeAssistanceInformationMetaDataExtIEsValueFieldIsOpaque(v *AssistanceInformationMetaDataExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeAssistanceInformationMetaDataExtIEsValueFieldOpaque(v *AssistanceInformationMetaDataExtIEsValue) **q5.OpaqueOpenType {
	return &v.opaque
}
func BridgeAssistanceInformationMetaDataExtIEsValueFieldReceived(v *AssistanceInformationMetaDataExtIEsValue) *q5.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationMetaDataExtIEsValueFieldReplay(v *AssistanceInformationMetaDataExtIEsValue) *q5.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationMetaDataExtIEsValueFieldWithoutReplay(v *AssistanceInformationMetaDataExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodCaptureFraming(v AssistanceInformationMetaDataExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodCaptureSemantics(v AssistanceInformationMetaDataExtIEsValue, a0 q5.SemanticCapture) AssistanceInformationMetaDataExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodCaptureSnapshot(v AssistanceInformationMetaDataExtIEsValue) q5.Snapshot {
	return v.captureSnapshot()
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodCompareSemantics(v AssistanceInformationMetaDataExtIEsValue, a0 q5.SemanticComparison) q5.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodDecode(v AssistanceInformationMetaDataExtIEsValue, a0 q4.ProtocolIEID, a1 q5.OpaqueOpenType) (AssistanceInformationMetaDataExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodEncode(v AssistanceInformationMetaDataExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodEncodeFresh(v AssistanceInformationMetaDataExtIEsValue, a0 bool, a1 *q5.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodMatchesID(v AssistanceInformationMetaDataExtIEsValue, a0 q4.ProtocolIEID, a1 *q5.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodReason(v AssistanceInformationMetaDataExtIEsValue, a0 q4.ProtocolIEID) q5.OpaqueReason {
	return v.reason(a0)
}
func BridgeAssistanceInformationMetaDataExtIEsValueMethodRule(v AssistanceInformationMetaDataExtIEsValue) q5.SourceRule {
	return v.rule()
}
func BridgeCriticalityDiagnosticsExtIEsValueFieldId(v *CriticalityDiagnosticsExtIEsValue) *q4.ProtocolIEID {
	return &v.id
}
func BridgeCriticalityDiagnosticsExtIEsValueFieldIsOpaque(v *CriticalityDiagnosticsExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeCriticalityDiagnosticsExtIEsValueFieldOpaque(v *CriticalityDiagnosticsExtIEsValue) **q5.OpaqueOpenType {
	return &v.opaque
}
func BridgeCriticalityDiagnosticsExtIEsValueFieldReceived(v *CriticalityDiagnosticsExtIEsValue) *q5.WireSpan {
	return &v.received
}
func BridgeCriticalityDiagnosticsExtIEsValueFieldReplay(v *CriticalityDiagnosticsExtIEsValue) *q5.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsExtIEsValueFieldWithoutReplay(v *CriticalityDiagnosticsExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodCaptureFraming(v CriticalityDiagnosticsExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodCaptureSemantics(v CriticalityDiagnosticsExtIEsValue, a0 q5.SemanticCapture) CriticalityDiagnosticsExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodCaptureSnapshot(v CriticalityDiagnosticsExtIEsValue) q5.Snapshot {
	return v.captureSnapshot()
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodCompareSemantics(v CriticalityDiagnosticsExtIEsValue, a0 q5.SemanticComparison) q5.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodDecode(v CriticalityDiagnosticsExtIEsValue, a0 q4.ProtocolIEID, a1 q5.OpaqueOpenType) (CriticalityDiagnosticsExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodEncode(v CriticalityDiagnosticsExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodEncodeFresh(v CriticalityDiagnosticsExtIEsValue, a0 bool, a1 *q5.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodMatchesID(v CriticalityDiagnosticsExtIEsValue, a0 q4.ProtocolIEID, a1 *q5.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodReason(v CriticalityDiagnosticsExtIEsValue, a0 q4.ProtocolIEID) q5.OpaqueReason {
	return v.reason(a0)
}
func BridgeCriticalityDiagnosticsExtIEsValueMethodRule(v CriticalityDiagnosticsExtIEsValue) q5.SourceRule {
	return v.rule()
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueFieldId(v *CriticalityDiagnosticsIEListExtIEsValue) *q4.ProtocolIEID {
	return &v.id
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueFieldIsOpaque(v *CriticalityDiagnosticsIEListExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueFieldOpaque(v *CriticalityDiagnosticsIEListExtIEsValue) **q5.OpaqueOpenType {
	return &v.opaque
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueFieldReceived(v *CriticalityDiagnosticsIEListExtIEsValue) *q5.WireSpan {
	return &v.received
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueFieldReplay(v *CriticalityDiagnosticsIEListExtIEsValue) *q5.Snapshot {
	return &v.replay
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueFieldWithoutReplay(v *CriticalityDiagnosticsIEListExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodCaptureFraming(v CriticalityDiagnosticsIEListExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodCaptureSemantics(v CriticalityDiagnosticsIEListExtIEsValue, a0 q5.SemanticCapture) CriticalityDiagnosticsIEListExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodCaptureSnapshot(v CriticalityDiagnosticsIEListExtIEsValue) q5.Snapshot {
	return v.captureSnapshot()
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodCompareSemantics(v CriticalityDiagnosticsIEListExtIEsValue, a0 q5.SemanticComparison) q5.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodDecode(v CriticalityDiagnosticsIEListExtIEsValue, a0 q4.ProtocolIEID, a1 q5.OpaqueOpenType) (CriticalityDiagnosticsIEListExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodEncode(v CriticalityDiagnosticsIEListExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodEncodeFresh(v CriticalityDiagnosticsIEListExtIEsValue, a0 bool, a1 *q5.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodMatchesID(v CriticalityDiagnosticsIEListExtIEsValue, a0 q4.ProtocolIEID, a1 *q5.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodReason(v CriticalityDiagnosticsIEListExtIEsValue, a0 q4.ProtocolIEID) q5.OpaqueReason {
	return v.reason(a0)
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueMethodRule(v CriticalityDiagnosticsIEListExtIEsValue) q5.SourceRule {
	return v.rule()
}
func BridgeECGIExtIEsValueFieldId(v *ECGIExtIEsValue) *q4.ProtocolIEID        { return &v.id }
func BridgeECGIExtIEsValueFieldIsOpaque(v *ECGIExtIEsValue) *bool             { return &v.isOpaque }
func BridgeECGIExtIEsValueFieldOpaque(v *ECGIExtIEsValue) **q5.OpaqueOpenType { return &v.opaque }
func BridgeECGIExtIEsValueFieldReceived(v *ECGIExtIEsValue) *q5.WireSpan      { return &v.received }
func BridgeECGIExtIEsValueFieldReplay(v *ECGIExtIEsValue) *q5.Snapshot        { return &v.replay }
func BridgeECGIExtIEsValueFieldWithoutReplay(v *ECGIExtIEsValue) *bool        { return &v.withoutReplay }
func BridgeECGIExtIEsValueMethodCaptureFraming(v ECGIExtIEsValue) uint64      { return v.captureFraming() }
func BridgeECGIExtIEsValueMethodCaptureSemantics(v ECGIExtIEsValue, a0 q5.SemanticCapture) ECGIExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeECGIExtIEsValueMethodCaptureSnapshot(v ECGIExtIEsValue) q5.Snapshot {
	return v.captureSnapshot()
}
func BridgeECGIExtIEsValueMethodCompareSemantics(v ECGIExtIEsValue, a0 q5.SemanticComparison) q5.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeECGIExtIEsValueMethodDecode(v ECGIExtIEsValue, a0 q4.ProtocolIEID, a1 q5.OpaqueOpenType) (ECGIExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeECGIExtIEsValueMethodEncode(v ECGIExtIEsValue) ([]byte, error) { return v.encode() }
func BridgeECGIExtIEsValueMethodEncodeFresh(v ECGIExtIEsValue, a0 bool, a1 *q5.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeECGIExtIEsValueMethodMatchesID(v ECGIExtIEsValue, a0 q4.ProtocolIEID, a1 *q5.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeECGIExtIEsValueMethodReason(v ECGIExtIEsValue, a0 q4.ProtocolIEID) q5.OpaqueReason {
	return v.reason(a0)
}
func BridgeECGIExtIEsValueMethodRule(v ECGIExtIEsValue) q5.SourceRule { return v.rule() }
func BridgeECIDMeasurementTerminationCommandIEValueFieldId(v *ECIDMeasurementTerminationCommandIEValue) *q4.ProtocolIEID {
	return &v.id
}
func BridgeECIDMeasurementTerminationCommandIEValueFieldIsOpaque(v *ECIDMeasurementTerminationCommandIEValue) *bool {
	return &v.isOpaque
}
func BridgeECIDMeasurementTerminationCommandIEValueFieldOpaque(v *ECIDMeasurementTerminationCommandIEValue) **q5.OpaqueOpenType {
	return &v.opaque
}
func BridgeECIDMeasurementTerminationCommandIEValueFieldReceived(v *ECIDMeasurementTerminationCommandIEValue) *q5.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementTerminationCommandIEValueFieldReplay(v *ECIDMeasurementTerminationCommandIEValue) *q5.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementTerminationCommandIEValueFieldRowENBUEMeasurementID(v *ECIDMeasurementTerminationCommandIEValue) **q4.MeasurementID {
	return &v.rowENBUEMeasurementID
}
func BridgeECIDMeasurementTerminationCommandIEValueFieldRowESMLCUEMeasurementID(v *ECIDMeasurementTerminationCommandIEValue) **q4.MeasurementID {
	return &v.rowESMLCUEMeasurementID
}
func BridgeECIDMeasurementTerminationCommandIEValueFieldWithoutReplay(v *ECIDMeasurementTerminationCommandIEValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodCaptureFraming(v ECIDMeasurementTerminationCommandIEValue) uint64 {
	return v.captureFraming()
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodCaptureSemantics(v ECIDMeasurementTerminationCommandIEValue, a0 q5.SemanticCapture) ECIDMeasurementTerminationCommandIEValue {
	return v.captureSemantics(a0)
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodCaptureSnapshot(v ECIDMeasurementTerminationCommandIEValue) q5.Snapshot {
	return v.captureSnapshot()
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodCompareSemantics(v ECIDMeasurementTerminationCommandIEValue, a0 q5.SemanticComparison) q5.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodDecode(v ECIDMeasurementTerminationCommandIEValue, a0 q4.ProtocolIEID, a1 q5.OpaqueOpenType) (ECIDMeasurementTerminationCommandIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodEncode(v ECIDMeasurementTerminationCommandIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodEncodeFresh(v ECIDMeasurementTerminationCommandIEValue, a0 bool, a1 *q5.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodMatchesID(v ECIDMeasurementTerminationCommandIEValue, a0 q4.ProtocolIEID, a1 *q5.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodReason(v ECIDMeasurementTerminationCommandIEValue, a0 q4.ProtocolIEID) q5.OpaqueReason {
	return v.reason(a0)
}
func BridgeECIDMeasurementTerminationCommandIEValueMethodRule(v ECIDMeasurementTerminationCommandIEValue) q5.SourceRule {
	return v.rule()
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueFieldId(v *InterRATMeasurementQuantitiesValueExtIEsValue) *q4.ProtocolIEID {
	return &v.id
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueFieldIsOpaque(v *InterRATMeasurementQuantitiesValueExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueFieldOpaque(v *InterRATMeasurementQuantitiesValueExtIEsValue) **q5.OpaqueOpenType {
	return &v.opaque
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueFieldReceived(v *InterRATMeasurementQuantitiesValueExtIEsValue) *q5.WireSpan {
	return &v.received
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueFieldReplay(v *InterRATMeasurementQuantitiesValueExtIEsValue) *q5.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueFieldWithoutReplay(v *InterRATMeasurementQuantitiesValueExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodCaptureFraming(v InterRATMeasurementQuantitiesValueExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodCaptureSemantics(v InterRATMeasurementQuantitiesValueExtIEsValue, a0 q5.SemanticCapture) InterRATMeasurementQuantitiesValueExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodCaptureSnapshot(v InterRATMeasurementQuantitiesValueExtIEsValue) q5.Snapshot {
	return v.captureSnapshot()
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodCompareSemantics(v InterRATMeasurementQuantitiesValueExtIEsValue, a0 q5.SemanticComparison) q5.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodDecode(v InterRATMeasurementQuantitiesValueExtIEsValue, a0 q4.ProtocolIEID, a1 q5.OpaqueOpenType) (InterRATMeasurementQuantitiesValueExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodEncode(v InterRATMeasurementQuantitiesValueExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodEncodeFresh(v InterRATMeasurementQuantitiesValueExtIEsValue, a0 bool, a1 *q5.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodMatchesID(v InterRATMeasurementQuantitiesValueExtIEsValue, a0 q4.ProtocolIEID, a1 *q5.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodReason(v InterRATMeasurementQuantitiesValueExtIEsValue, a0 q4.ProtocolIEID) q5.OpaqueReason {
	return v.reason(a0)
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodRule(v InterRATMeasurementQuantitiesValueExtIEsValue) q5.SourceRule {
	return v.rule()
}
func BridgeMeasurementQuantitiesValueExtIEsValueFieldId(v *MeasurementQuantitiesValueExtIEsValue) *q4.ProtocolIEID {
	return &v.id
}
func BridgeMeasurementQuantitiesValueExtIEsValueFieldIsOpaque(v *MeasurementQuantitiesValueExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeMeasurementQuantitiesValueExtIEsValueFieldOpaque(v *MeasurementQuantitiesValueExtIEsValue) **q5.OpaqueOpenType {
	return &v.opaque
}
func BridgeMeasurementQuantitiesValueExtIEsValueFieldReceived(v *MeasurementQuantitiesValueExtIEsValue) *q5.WireSpan {
	return &v.received
}
func BridgeMeasurementQuantitiesValueExtIEsValueFieldReplay(v *MeasurementQuantitiesValueExtIEsValue) *q5.Snapshot {
	return &v.replay
}
func BridgeMeasurementQuantitiesValueExtIEsValueFieldWithoutReplay(v *MeasurementQuantitiesValueExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodCaptureFraming(v MeasurementQuantitiesValueExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodCaptureSemantics(v MeasurementQuantitiesValueExtIEsValue, a0 q5.SemanticCapture) MeasurementQuantitiesValueExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodCaptureSnapshot(v MeasurementQuantitiesValueExtIEsValue) q5.Snapshot {
	return v.captureSnapshot()
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodCompareSemantics(v MeasurementQuantitiesValueExtIEsValue, a0 q5.SemanticComparison) q5.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodDecode(v MeasurementQuantitiesValueExtIEsValue, a0 q4.ProtocolIEID, a1 q5.OpaqueOpenType) (MeasurementQuantitiesValueExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodEncode(v MeasurementQuantitiesValueExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodEncodeFresh(v MeasurementQuantitiesValueExtIEsValue, a0 bool, a1 *q5.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodMatchesID(v MeasurementQuantitiesValueExtIEsValue, a0 q4.ProtocolIEID, a1 *q5.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodReason(v MeasurementQuantitiesValueExtIEsValue, a0 q4.ProtocolIEID) q5.OpaqueReason {
	return v.reason(a0)
}
func BridgeMeasurementQuantitiesValueExtIEsValueMethodRule(v MeasurementQuantitiesValueExtIEsValue) q5.SourceRule {
	return v.rule()
}
func BridgeNRCGIExtIEsValueFieldId(v *NRCGIExtIEsValue) *q4.ProtocolIEID        { return &v.id }
func BridgeNRCGIExtIEsValueFieldIsOpaque(v *NRCGIExtIEsValue) *bool             { return &v.isOpaque }
func BridgeNRCGIExtIEsValueFieldOpaque(v *NRCGIExtIEsValue) **q5.OpaqueOpenType { return &v.opaque }
func BridgeNRCGIExtIEsValueFieldReceived(v *NRCGIExtIEsValue) *q5.WireSpan      { return &v.received }
func BridgeNRCGIExtIEsValueFieldReplay(v *NRCGIExtIEsValue) *q5.Snapshot        { return &v.replay }
func BridgeNRCGIExtIEsValueFieldWithoutReplay(v *NRCGIExtIEsValue) *bool        { return &v.withoutReplay }
func BridgeNRCGIExtIEsValueMethodCaptureFraming(v NRCGIExtIEsValue) uint64      { return v.captureFraming() }
func BridgeNRCGIExtIEsValueMethodCaptureSemantics(v NRCGIExtIEsValue, a0 q5.SemanticCapture) NRCGIExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeNRCGIExtIEsValueMethodCaptureSnapshot(v NRCGIExtIEsValue) q5.Snapshot {
	return v.captureSnapshot()
}
func BridgeNRCGIExtIEsValueMethodCompareSemantics(v NRCGIExtIEsValue, a0 q5.SemanticComparison) q5.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeNRCGIExtIEsValueMethodDecode(v NRCGIExtIEsValue, a0 q4.ProtocolIEID, a1 q5.OpaqueOpenType) (NRCGIExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeNRCGIExtIEsValueMethodEncode(v NRCGIExtIEsValue) ([]byte, error) { return v.encode() }
func BridgeNRCGIExtIEsValueMethodEncodeFresh(v NRCGIExtIEsValue, a0 bool, a1 *q5.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeNRCGIExtIEsValueMethodMatchesID(v NRCGIExtIEsValue, a0 q4.ProtocolIEID, a1 *q5.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeNRCGIExtIEsValueMethodReason(v NRCGIExtIEsValue, a0 q4.ProtocolIEID) q5.OpaqueReason {
	return v.reason(a0)
}
func BridgeNRCGIExtIEsValueMethodRule(v NRCGIExtIEsValue) q5.SourceRule            { return v.rule() }
func BridgeOTDOACellsExtIEsValueFieldId(v *OTDOACellsExtIEsValue) *q4.ProtocolIEID { return &v.id }
func BridgeOTDOACellsExtIEsValueFieldIsOpaque(v *OTDOACellsExtIEsValue) *bool      { return &v.isOpaque }
func BridgeOTDOACellsExtIEsValueFieldOpaque(v *OTDOACellsExtIEsValue) **q5.OpaqueOpenType {
	return &v.opaque
}
func BridgeOTDOACellsExtIEsValueFieldReceived(v *OTDOACellsExtIEsValue) *q5.WireSpan {
	return &v.received
}
func BridgeOTDOACellsExtIEsValueFieldReplay(v *OTDOACellsExtIEsValue) *q5.Snapshot { return &v.replay }
func BridgeOTDOACellsExtIEsValueFieldWithoutReplay(v *OTDOACellsExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOACellsExtIEsValueMethodCaptureFraming(v OTDOACellsExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeOTDOACellsExtIEsValueMethodCaptureSemantics(v OTDOACellsExtIEsValue, a0 q5.SemanticCapture) OTDOACellsExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeOTDOACellsExtIEsValueMethodCaptureSnapshot(v OTDOACellsExtIEsValue) q5.Snapshot {
	return v.captureSnapshot()
}
func BridgeOTDOACellsExtIEsValueMethodCompareSemantics(v OTDOACellsExtIEsValue, a0 q5.SemanticComparison) q5.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeOTDOACellsExtIEsValueMethodDecode(v OTDOACellsExtIEsValue, a0 q4.ProtocolIEID, a1 q5.OpaqueOpenType) (OTDOACellsExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeOTDOACellsExtIEsValueMethodEncode(v OTDOACellsExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeOTDOACellsExtIEsValueMethodEncodeFresh(v OTDOACellsExtIEsValue, a0 bool, a1 *q5.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeOTDOACellsExtIEsValueMethodMatchesID(v OTDOACellsExtIEsValue, a0 q4.ProtocolIEID, a1 *q5.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeOTDOACellsExtIEsValueMethodReason(v OTDOACellsExtIEsValue, a0 q4.ProtocolIEID) q5.OpaqueReason {
	return v.reason(a0)
}
func BridgeOTDOACellsExtIEsValueMethodRule(v OTDOACellsExtIEsValue) q5.SourceRule { return v.rule() }
func BridgeOTDOAInformationTypeItemExtIEsValueFieldId(v *OTDOAInformationTypeItemExtIEsValue) *q4.ProtocolIEID {
	return &v.id
}
func BridgeOTDOAInformationTypeItemExtIEsValueFieldIsOpaque(v *OTDOAInformationTypeItemExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgeOTDOAInformationTypeItemExtIEsValueFieldOpaque(v *OTDOAInformationTypeItemExtIEsValue) **q5.OpaqueOpenType {
	return &v.opaque
}
func BridgeOTDOAInformationTypeItemExtIEsValueFieldReceived(v *OTDOAInformationTypeItemExtIEsValue) *q5.WireSpan {
	return &v.received
}
func BridgeOTDOAInformationTypeItemExtIEsValueFieldReplay(v *OTDOAInformationTypeItemExtIEsValue) *q5.Snapshot {
	return &v.replay
}
func BridgeOTDOAInformationTypeItemExtIEsValueFieldWithoutReplay(v *OTDOAInformationTypeItemExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodCaptureFraming(v OTDOAInformationTypeItemExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodCaptureSemantics(v OTDOAInformationTypeItemExtIEsValue, a0 q5.SemanticCapture) OTDOAInformationTypeItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodCaptureSnapshot(v OTDOAInformationTypeItemExtIEsValue) q5.Snapshot {
	return v.captureSnapshot()
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodCompareSemantics(v OTDOAInformationTypeItemExtIEsValue, a0 q5.SemanticComparison) q5.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodDecode(v OTDOAInformationTypeItemExtIEsValue, a0 q4.ProtocolIEID, a1 q5.OpaqueOpenType) (OTDOAInformationTypeItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodEncode(v OTDOAInformationTypeItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodEncodeFresh(v OTDOAInformationTypeItemExtIEsValue, a0 bool, a1 *q5.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodMatchesID(v OTDOAInformationTypeItemExtIEsValue, a0 q4.ProtocolIEID, a1 *q5.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodReason(v OTDOAInformationTypeItemExtIEsValue, a0 q4.ProtocolIEID) q5.OpaqueReason {
	return v.reason(a0)
}
func BridgeOTDOAInformationTypeItemExtIEsValueMethodRule(v OTDOAInformationTypeItemExtIEsValue) q5.SourceRule {
	return v.rule()
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueFieldId(v *PRSFrequencyHoppingConfigurationItemIEsValue) *q4.ProtocolIEID {
	return &v.id
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueFieldIsOpaque(v *PRSFrequencyHoppingConfigurationItemIEsValue) *bool {
	return &v.isOpaque
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueFieldOpaque(v *PRSFrequencyHoppingConfigurationItemIEsValue) **q5.OpaqueOpenType {
	return &v.opaque
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueFieldReceived(v *PRSFrequencyHoppingConfigurationItemIEsValue) *q5.WireSpan {
	return &v.received
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueFieldReplay(v *PRSFrequencyHoppingConfigurationItemIEsValue) *q5.Snapshot {
	return &v.replay
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueFieldWithoutReplay(v *PRSFrequencyHoppingConfigurationItemIEsValue) *bool {
	return &v.withoutReplay
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodCaptureFraming(v PRSFrequencyHoppingConfigurationItemIEsValue) uint64 {
	return v.captureFraming()
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodCaptureSemantics(v PRSFrequencyHoppingConfigurationItemIEsValue, a0 q5.SemanticCapture) PRSFrequencyHoppingConfigurationItemIEsValue {
	return v.captureSemantics(a0)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodCaptureSnapshot(v PRSFrequencyHoppingConfigurationItemIEsValue) q5.Snapshot {
	return v.captureSnapshot()
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodCompareSemantics(v PRSFrequencyHoppingConfigurationItemIEsValue, a0 q5.SemanticComparison) q5.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodDecode(v PRSFrequencyHoppingConfigurationItemIEsValue, a0 q4.ProtocolIEID, a1 q5.OpaqueOpenType) (PRSFrequencyHoppingConfigurationItemIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodEncode(v PRSFrequencyHoppingConfigurationItemIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodEncodeFresh(v PRSFrequencyHoppingConfigurationItemIEsValue, a0 bool, a1 *q5.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodMatchesID(v PRSFrequencyHoppingConfigurationItemIEsValue, a0 q4.ProtocolIEID, a1 *q5.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodReason(v PRSFrequencyHoppingConfigurationItemIEsValue, a0 q4.ProtocolIEID) q5.OpaqueReason {
	return v.reason(a0)
}
func BridgePRSFrequencyHoppingConfigurationItemIEsValueMethodRule(v PRSFrequencyHoppingConfigurationItemIEsValue) q5.SourceRule {
	return v.rule()
}
func BridgePosSIBSegmentsExtIEsValueFieldId(v *PosSIBSegmentsExtIEsValue) *q4.ProtocolIEID {
	return &v.id
}
func BridgePosSIBSegmentsExtIEsValueFieldIsOpaque(v *PosSIBSegmentsExtIEsValue) *bool {
	return &v.isOpaque
}
func BridgePosSIBSegmentsExtIEsValueFieldOpaque(v *PosSIBSegmentsExtIEsValue) **q5.OpaqueOpenType {
	return &v.opaque
}
func BridgePosSIBSegmentsExtIEsValueFieldReceived(v *PosSIBSegmentsExtIEsValue) *q5.WireSpan {
	return &v.received
}
func BridgePosSIBSegmentsExtIEsValueFieldReplay(v *PosSIBSegmentsExtIEsValue) *q5.Snapshot {
	return &v.replay
}
func BridgePosSIBSegmentsExtIEsValueFieldWithoutReplay(v *PosSIBSegmentsExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgePosSIBSegmentsExtIEsValueMethodCaptureFraming(v PosSIBSegmentsExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgePosSIBSegmentsExtIEsValueMethodCaptureSemantics(v PosSIBSegmentsExtIEsValue, a0 q5.SemanticCapture) PosSIBSegmentsExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgePosSIBSegmentsExtIEsValueMethodCaptureSnapshot(v PosSIBSegmentsExtIEsValue) q5.Snapshot {
	return v.captureSnapshot()
}
func BridgePosSIBSegmentsExtIEsValueMethodCompareSemantics(v PosSIBSegmentsExtIEsValue, a0 q5.SemanticComparison) q5.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgePosSIBSegmentsExtIEsValueMethodDecode(v PosSIBSegmentsExtIEsValue, a0 q4.ProtocolIEID, a1 q5.OpaqueOpenType) (PosSIBSegmentsExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgePosSIBSegmentsExtIEsValueMethodEncode(v PosSIBSegmentsExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgePosSIBSegmentsExtIEsValueMethodEncodeFresh(v PosSIBSegmentsExtIEsValue, a0 bool, a1 *q5.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgePosSIBSegmentsExtIEsValueMethodMatchesID(v PosSIBSegmentsExtIEsValue, a0 q4.ProtocolIEID, a1 *q5.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgePosSIBSegmentsExtIEsValueMethodReason(v PosSIBSegmentsExtIEsValue, a0 q4.ProtocolIEID) q5.OpaqueReason {
	return v.reason(a0)
}
func BridgePosSIBSegmentsExtIEsValueMethodRule(v PosSIBSegmentsExtIEsValue) q5.SourceRule {
	return v.rule()
}
func BridgeWLANCountryCodeValueCodecFieldCapture(v *WLANCountryCodeValueCodec) *func(q4.WLANCountryCode, q5.DecodeState) (q4.WLANCountryCode, q5.Snapshot) {
	return &v.capture
}
func BridgeWLANCountryCodeValueCodecFieldCompare(v *WLANCountryCodeValueCodec) *func(q4.WLANCountryCode, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeWLANCountryCodeValueCodecFieldContext(v *WLANCountryCodeValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeWLANCountryCodeValueCodecFieldDecode(v *WLANCountryCodeValueCodec) *func([]byte, q5.DecodeState) (q4.WLANCountryCode, error) {
	return &v.decode
}
func BridgeWLANCountryCodeValueCodecFieldEncode(v *WLANCountryCodeValueCodec) *func(q4.WLANCountryCode, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANCountryCodeValueCodecFieldPath(v *WLANCountryCodeValueCodec) *q5.Path { return &v.path }
func BridgeWLANCountryCodeValueCodecMethodEncodeBudget(v WLANCountryCodeValueCodec, a0 q4.WLANCountryCode, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANCountryCodeValueCodecMethodEncodeChanged(v WLANCountryCodeValueCodec, a0 q4.WLANCountryCode, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANMeasurementQuantitiesValueAPERValueFieldContext(v *WLANMeasurementQuantitiesValueAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementQuantitiesValueAPERValueFieldReceived(v *WLANMeasurementQuantitiesValueAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesValueAPERValueFieldReplay(v *WLANMeasurementQuantitiesValueAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesValueAPERValueFieldWithoutReplay(v *WLANMeasurementQuantitiesValueAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesValueValueCodecFieldCapture(v *WLANMeasurementQuantitiesValueValueCodec) *func(q4.WLANMeasurementQuantitiesValue, q5.DecodeState) (q4.WLANMeasurementQuantitiesValue, q5.Snapshot) {
	return &v.capture
}
func BridgeWLANMeasurementQuantitiesValueValueCodecFieldCompare(v *WLANMeasurementQuantitiesValueValueCodec) *func(q4.WLANMeasurementQuantitiesValue, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeWLANMeasurementQuantitiesValueValueCodecFieldContext(v *WLANMeasurementQuantitiesValueValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementQuantitiesValueValueCodecFieldDecode(v *WLANMeasurementQuantitiesValueValueCodec) *func([]byte, q5.DecodeState) (q4.WLANMeasurementQuantitiesValue, error) {
	return &v.decode
}
func BridgeWLANMeasurementQuantitiesValueValueCodecFieldEncode(v *WLANMeasurementQuantitiesValueValueCodec) *func(q4.WLANMeasurementQuantitiesValue, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANMeasurementQuantitiesValueValueCodecFieldPath(v *WLANMeasurementQuantitiesValueValueCodec) *q5.Path {
	return &v.path
}
func BridgeWLANMeasurementQuantitiesValueValueCodecMethodEncodeBudget(v WLANMeasurementQuantitiesValueValueCodec, a0 q4.WLANMeasurementQuantitiesValue, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANMeasurementQuantitiesValueValueCodecMethodEncodeChanged(v WLANMeasurementQuantitiesValueValueCodec, a0 q4.WLANMeasurementQuantitiesValue, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANOperatingClassAPERValueFieldContext(v *WLANOperatingClassAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeWLANOperatingClassAPERValueFieldReceived(v *WLANOperatingClassAPERValue) *q5.WireSpan {
	return &v.received
}
func BridgeWLANOperatingClassAPERValueFieldReplay(v *WLANOperatingClassAPERValue) *q5.Snapshot {
	return &v.replay
}
func BridgeWLANOperatingClassAPERValueFieldWithoutReplay(v *WLANOperatingClassAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANOperatingClassValueCodecFieldCapture(v *WLANOperatingClassValueCodec) *func(q4.WLANOperatingClass, q5.DecodeState) (q4.WLANOperatingClass, q5.Snapshot) {
	return &v.capture
}
func BridgeWLANOperatingClassValueCodecFieldCompare(v *WLANOperatingClassValueCodec) *func(q4.WLANOperatingClass, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeWLANOperatingClassValueCodecFieldContext(v *WLANOperatingClassValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeWLANOperatingClassValueCodecFieldDecode(v *WLANOperatingClassValueCodec) *func([]byte, q5.DecodeState) (q4.WLANOperatingClass, error) {
	return &v.decode
}
func BridgeWLANOperatingClassValueCodecFieldEncode(v *WLANOperatingClassValueCodec) *func(q4.WLANOperatingClass, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANOperatingClassValueCodecFieldPath(v *WLANOperatingClassValueCodec) *q5.Path {
	return &v.path
}
func BridgeWLANOperatingClassValueCodecMethodEncodeBudget(v WLANOperatingClassValueCodec, a0 q4.WLANOperatingClass, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANOperatingClassValueCodecMethodEncodeChanged(v WLANOperatingClassValueCodec, a0 q4.WLANOperatingClass, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANRSSIAPERValueFieldContext(v *WLANRSSIAPERValue) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeWLANRSSIAPERValueFieldReceived(v *WLANRSSIAPERValue) *q5.WireSpan { return &v.received }
func BridgeWLANRSSIAPERValueFieldReplay(v *WLANRSSIAPERValue) *q5.Snapshot   { return &v.replay }
func BridgeWLANRSSIAPERValueFieldWithoutReplay(v *WLANRSSIAPERValue) *bool   { return &v.withoutReplay }
func BridgeWLANRSSIValueCodecFieldCapture(v *WLANRSSIValueCodec) *func(q4.WLANRSSI, q5.DecodeState) (q4.WLANRSSI, q5.Snapshot) {
	return &v.capture
}
func BridgeWLANRSSIValueCodecFieldCompare(v *WLANRSSIValueCodec) *func(q4.WLANRSSI, q5.Snapshot, q5.ComparisonLimits) q5.ReplayPlan {
	return &v.compare
}
func BridgeWLANRSSIValueCodecFieldContext(v *WLANRSSIValueCodec) *q4.BridgeCodecContext {
	return &v.context
}
func BridgeWLANRSSIValueCodecFieldDecode(v *WLANRSSIValueCodec) *func([]byte, q5.DecodeState) (q4.WLANRSSI, error) {
	return &v.decode
}
func BridgeWLANRSSIValueCodecFieldEncode(v *WLANRSSIValueCodec) *func(q4.WLANRSSI, bool, *q5.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANRSSIValueCodecFieldPath(v *WLANRSSIValueCodec) *q5.Path { return &v.path }
func BridgeWLANRSSIValueCodecMethodEncodeBudget(v WLANRSSIValueCodec, a0 q4.WLANRSSI, a1 bool, a2 q5.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANRSSIValueCodecMethodEncodeChanged(v WLANRSSIValueCodec, a0 q4.WLANRSSI, a1 bool, a2 q5.ReplayPlan, a3 q5.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
