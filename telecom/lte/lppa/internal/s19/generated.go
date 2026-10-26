// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s19 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s19

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s12"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s13"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s14"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s18"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// ResultNRItemExtIEsExtContainer is ProtocolExtensionContainer {{ResultNR-Item-ExtIEs}} of TS 36.455: a list of ResultNRItemExtIEsExtField values.
type ResultNRItemExtIEsExtContainer []ResultNRItemExtIEsExtField

// ResultNRItemExtIEsExtField is ProtocolExtensionField {{ResultNR-Item-ExtIEs}} of TS 36.455: a field carrying a value of ResultNRItemExtIEsValue.
type ResultNRItemExtIEsExtField struct {
	withoutReplay  bool
	replay         aper.Snapshot
	stream         aper.WireSpan
	Id             s00.ProtocolIEID
	Criticality    s00.Criticality
	ExtensionValue ResultNRItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultNRItemExtIEsExtField) WithoutReplay() ResultNRItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ResultNRItemExtIEsExtField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultNRItemExtIEsExtField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.ExtensionValue.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.ExtensionValue.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *ResultNRItemExtIEsExtField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultNRItemExtIEsExtField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero ResultNRItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	paddingMark := bb.EnterComponent("ExtensionValue")
	value, err := zero.decode(v.Id, raw)
	bb.LeaveComponent(paddingMark)
	if err != nil {
		return runtime.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}
func BridgeResultNRItemExtIEsValueCaptureLPPaProtocolExtensionContainer(v *ResultNRItemExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeResultNRItemExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeResultNRItemExtIEsValueCompareLPPaProtocolExtensionContainer(v *ResultNRItemExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	{
		f := s.Begin()
		s.Uint(uint64(len((*v))))
		s.Elements(uint64(len((*v))))
		for i := range *v {
			if s.Failed() {
				break
			}
			BridgeResultNRItemExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}

// ResultNRItemExtIEsResultsPerSSBIndexListExtBinding binds ResultsPerSSBIndexList to ProtocolExtensionField {{ResultNR-Item-ExtIEs}} of TS 36.455.
type ResultNRItemExtIEsResultsPerSSBIndexListExtBinding struct {
	info   s00.FieldInfo
	codec  s14.ResultsPerSSBIndexListValueCodec
	inject func(s14.ResultsPerSSBIndexList,

	) ResultNRItemExtIEsValue

	get func(*ResultNRItemExtIEsValue,

	) (*s14.ResultsPerSSBIndexList,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ResultNRItemExtIEsResultsPerSSBIndexListExtBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ResultNRItemExtIEsResultsPerSSBIndexListExtBinding) Codec() s14.ResultsPerSSBIndexListValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ResultNRItemExtIEsResultsPerSSBIndexListExtBinding) New(value s14.ResultsPerSSBIndexList,

) (ResultNRItemExtIEsExtField, error) {
	if b.inject == nil {
		return ResultNRItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResultNRItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s14.BridgeResultsPerSSBIndexListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ResultNRItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ResultNRItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ResultNRItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ResultNRItemExtIEsResultsPerSSBIndexListExtBinding) Get(field *ResultNRItemExtIEsExtField) (*s14.ResultsPerSSBIndexList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ResultNRItemExtIEsNRCGIExtBinding binds NRCGI to ProtocolExtensionField {{ResultNR-Item-ExtIEs}} of TS 36.455.
type ResultNRItemExtIEsNRCGIExtBinding struct {
	info   s00.FieldInfo
	codec  s07.NRCGIValueCodec
	inject func(s07.NRCGI,

	) ResultNRItemExtIEsValue

	get func(*ResultNRItemExtIEsValue,

	) (*s07.NRCGI,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ResultNRItemExtIEsNRCGIExtBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ResultNRItemExtIEsNRCGIExtBinding) Codec() s07.NRCGIValueCodec { return b.codec }

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ResultNRItemExtIEsNRCGIExtBinding) New(value s07.NRCGI,

) (ResultNRItemExtIEsExtField, error) {
	if b.inject == nil {
		return ResultNRItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResultNRItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s07.BridgeNRCGIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ResultNRItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ResultNRItemExtIEsExtField{}, aper.OperationError(err, "Value.New")
	}
	return ResultNRItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ResultNRItemExtIEsNRCGIExtBinding) Get(field *ResultNRItemExtIEsExtField) (*s07.NRCGI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ResultNRValueCodec is the concrete ValueCodec[ResultNR].
type ResultNRValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ResultNR, aper.DecodeState,

	) (ResultNR, aper.Snapshot,

	)
	compare func(ResultNR, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ResultNR,

		error)
	encode func(ResultNR,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ResultNRValueCodec) New(value ResultNR,

) (ResultNRAPERValue, error) {
	if c.encode == nil {
		return ResultNRAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResultNRAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultNRAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ResultNRAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ResultNRValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResultNRAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultNRAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ResultNRAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultNRAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ResultNRAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ResultNRAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ResultNRValueCodec) EncodeAPER(value ResultNRAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResultNRValueCodec) encodeBudget(value ResultNR,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultNRValueCodec) encodeChanged(value ResultNR,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ResultNRItemValueCodec is the concrete ValueCodec[ResultNRItem].
type ResultNRItemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ResultNRItem, aper.DecodeState,

	) (ResultNRItem, aper.Snapshot,

	)
	compare func(ResultNRItem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ResultNRItem,

		error)
	encode func(ResultNRItem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ResultNRItemValueCodec) New(value ResultNRItem,

) (ResultNRItemAPERValue, error) {
	if c.encode == nil {
		return ResultNRItemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResultNRItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultNRItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ResultNRItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ResultNRItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResultNRItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultNRItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ResultNRItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultNRItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ResultNRItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ResultNRItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ResultNRItemValueCodec) EncodeAPER(value ResultNRItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResultNRItemValueCodec) encodeBudget(value ResultNRItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultNRItemValueCodec) encodeChanged(value ResultNRItem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}
func BridgeResultNRItemExtIEsValueCaptureLPPaProtocolExtensionField(v *ResultNRItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(v.ExtensionValue.captureFraming())
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.Child(v.ExtensionValue.captureSnapshot())
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeResultNRItemExtIEsValueCompareLPPaProtocolExtensionField(v *ResultNRItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// InterRATMeasuredResultsValueAPERValue is the concrete APERValue[InterRATMeasuredResultsValue].
type InterRATMeasuredResultsValueAPERValue struct {
	context s00.BridgeCodecContext
	Value   InterRATMeasuredResultsValue

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v InterRATMeasuredResultsValueAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v InterRATMeasuredResultsValueAPERValue) WithoutReplay() InterRATMeasuredResultsValueAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultNRAPERValue is the concrete APERValue[ResultNR].
type ResultNRAPERValue struct {
	context s00.BridgeCodecContext
	Value   ResultNR

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ResultNRAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultNRAPERValue) WithoutReplay() ResultNRAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultNRItemAPERValue is the concrete APERValue[ResultNRItem].
type ResultNRItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ResultNRItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ResultNRItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultNRItemAPERValue) WithoutReplay() ResultNRItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultNRItemExtIEsIEField uses the ProtocolIE-Field shape for object set ResultNR-Item-ExtIEs of TS 36.455.
type ResultNRItemExtIEsIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ResultNRItemExtIEsValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultNRItemExtIEsIEField) WithoutReplay() ResultNRItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ResultNRItemExtIEsIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultNRItemExtIEsIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		return fmt.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false); err != nil {
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
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *ResultNRItemExtIEsIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultNRItemExtIEsIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero ResultNRItemExtIEsValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
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

// ResultNRItemExtIEsIEContainer uses the ProtocolIE-Container shape for object set ResultNR-Item-ExtIEs of TS 36.455: a list of ResultNRItemExtIEsIEField values.
type ResultNRItemExtIEsIEContainer []ResultNRItemExtIEsIEField

// InterRATMeasuredResultsValue represents the ASN.1 CHOICE type InterRATMeasuredResultsValue.
type InterRATMeasuredResultsValue struct {
	knownOpenBytes     uint64
	replay             aper.Snapshot
	stream             aper.WireSpan
	withoutReplay      bool
	received           bool
	receivedBytes      aper.WireSpan
	Choice             int
	perPadding         aper.CompletePadding  `json:"-"`
	perOpenTypePadding aper.CompletePadding  `json:"-"`
	UnknownExtension   *aper.ChoiceExtension `json:"UnknownExtension,omitempty"`
	ResultGERAN        s12.ResultGERAN       `json:"ResultGERAN,omitzero"`
	ResultUTRAN        s14.ResultUTRAN       `json:"ResultUTRAN,omitzero"`
	ResultNR           ResultNR              `json:"ResultNR,omitzero"`
}
type ResultNR = []ResultNRItem

// ResultNRItem represents the ASN.1 type ResultNR-Item (SEQUENCE).
type ResultNRItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     aper.WireSpan
	NRARFCN           s00.NRARFCN                    `asn1:"tag:0,context,implicit"`
	NRPCI             s00.NRPCI                      `asn1:"tag:1,context,implicit"`
	SSNRRSRP          *s00.SSNRRSRP                  `asn1:"tag:2,context,implicit,optional" json:"SSNRRSRP,omitempty"`
	SSNRRSRQ          *s00.SSNRRSRQ                  `asn1:"tag:3,context,implicit,optional" json:"SSNRRSRQ,omitempty"`
	IEExtensions      ResultNRItemExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                           `asn1:"-" json:"-"`
	extCount          int64                          `asn1:"-" json:"-"`
	extPresent        []bool                         `asn1:"-" json:"-"`
	extData           [][]byte                       `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding              `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding         `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// MarshalAPER encodes InterRATMeasuredResultsValue to APER format.
func (v *InterRATMeasuredResultsValue) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *InterRATMeasuredResultsValue) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.UnknownExtension != nil {
		if v.Choice != 0 {
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "InterRATMeasuredResultsValue:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "InterRATMeasuredResultsValue:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 1 {
			return fmt.Errorf("%s extension index %d is known to this schema", "InterRATMeasuredResultsValue:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "InterRATMeasuredResultsValue:", v.Choice)
	}
	isExtension := v.Choice > 2
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 2 {
			return fmt.Errorf("extension choice index outside root")
		}
		if err := aper.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-2-1)); err != nil {
			return err
		}
		inner := aper.NewBudgetBuffer(bb.Budget())
		switch v.Choice {
		case s00.InterRATMeasuredResultsValueChoiceResultNR:
			if err := aper.EncodeCollection(inner, int64(len(v.ResultNR)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_resultnr, fragmentLength_resultnr int64) error {
				// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
				if fragmentOffset_resultnr < 0 || fragmentOffset_resultnr > int64(len(v.ResultNR)) || fragmentLength_resultnr < 0 || fragmentLength_resultnr > int64(len(v.ResultNR[fragmentOffset_resultnr:])) {
					return fmt.Errorf("collection fragment outside value")
				}
				for _, elem := range v.ResultNR[fragmentOffset_resultnr : fragmentOffset_resultnr+fragmentLength_resultnr] {
					if err := elem.marshalAPERTo(inner, len(fresh) != 0 && fresh[0]); err != nil {
						return fmt.Errorf("encoding resultNR element: %w", err)
					}
				}
				return nil
			}); err != nil {
				return fmt.Errorf("encoding resultNR: %w", err)
			}
		default:
			return fmt.Errorf("unknown InterRATMeasuredResultsValue extension choice %d", v.Choice)
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
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case s00.InterRATMeasuredResultsValueChoiceResultGERAN:
		if err := aper.EncodeCollection(bb, int64(len(v.ResultGERAN)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_resultgeran, fragmentLength_resultgeran int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_resultgeran < 0 || fragmentOffset_resultgeran > int64(len(v.ResultGERAN)) || fragmentLength_resultgeran < 0 || fragmentLength_resultgeran > int64(len(v.ResultGERAN[fragmentOffset_resultgeran:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.ResultGERAN[fragmentOffset_resultgeran : fragmentOffset_resultgeran+fragmentLength_resultgeran] {
				if err := s12.BridgeResultGERANItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding resultGERAN element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding resultGERAN: %w", err)
		}
	case s00.InterRATMeasuredResultsValueChoiceResultUTRAN:
		if err := aper.EncodeCollection(bb, int64(len(v.ResultUTRAN)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_resultutran, fragmentLength_resultutran int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_resultutran < 0 || fragmentOffset_resultutran > int64(len(v.ResultUTRAN)) || fragmentLength_resultutran < 0 || fragmentLength_resultutran > int64(len(v.ResultUTRAN[fragmentOffset_resultutran:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.ResultUTRAN[fragmentOffset_resultutran : fragmentOffset_resultutran+fragmentLength_resultutran] {
				if err := s14.BridgeResultUTRANItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding resultUTRAN element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding resultUTRAN: %w", err)
		}
	default:
		return fmt.Errorf("unknown InterRATMeasuredResultsValue choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes InterRATMeasuredResultsValue from APER format.
func (v *InterRATMeasuredResultsValue) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *InterRATMeasuredResultsValue) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasuredResultsValue")
	}
	bb.EnterComponent("InterRATMeasuredResultsValue")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasuredResultsValue")
	}
	padding, err := aper.CaptureFinalBits(bb, "InterRATMeasuredResultsValue")
	if err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasuredResultsValue")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *InterRATMeasuredResultsValue) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InterRATMeasuredResultsValue{}
	isExtension, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := aper.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := aper.DecodeChoiceExtensionAligned(bb, extIdx, 1)
		if extIdx < 1 {
			v.knownOpenBytes = max(v.knownOpenBytes, openExtension.ContentLength())
		}
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		if extIdx >= 1 {
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
		if extIdx < 0 || extIdx >= int64(^uint(0)>>1)-int64(2) {
			return fmt.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 2 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case s00.InterRATMeasuredResultsValueChoiceResultNR:
			extensionPath = "ResultNR"
			toleranceMark_resultnr := inner.EnterComponent("ResultNR")
			tmp_resultnr := make(ResultNR, 0)
			_, errCollection_resultnr := aper.DecodeCollection(inner, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_resultnr, fragmentLength_resultnr int64) error {
				// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
				if fragmentOffset_resultnr < 0 || fragmentLength_resultnr < 0 || fragmentLength_resultnr > int64(^uint(0)>>1) || fragmentOffset_resultnr > int64(^uint(0)>>1)-fragmentLength_resultnr {
					return fmt.Errorf("collection fragment count out of range")
				}
				for i := int64(0); i < fragmentLength_resultnr; i++ {
					var elem ResultNRItem
					elementMark := inner.EnterIndex(fragmentOffset_resultnr + i)
					if err := elem.unmarshalAPERFrom(inner); err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("ResultNR[%d]", fragmentOffset_resultnr+i))
					}
					inner.LeaveComponent(elementMark)
					if next, err := aper.AppendValues(inner, tmp_resultnr, elem); err != nil {
						return err
					} else {
						tmp_resultnr = next
					}
				}
				return nil
			})
			if errCollection_resultnr != nil {
				return runtime.WrapDecodePath(errCollection_resultnr, "ResultNR")
			}
			v.ResultNR = tmp_resultnr
			inner.LeaveComponent(toleranceMark_resultnr)
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
	case s00.InterRATMeasuredResultsValueChoiceResultGERAN:
		toleranceMark_resultgeran := bb.EnterComponent("ResultGERAN")
		tmp_resultgeran := make(s12.ResultGERAN, 0)
		_, errCollection_resultgeran := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_resultgeran, fragmentLength_resultgeran int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
			if fragmentOffset_resultgeran < 0 || fragmentLength_resultgeran < 0 || fragmentLength_resultgeran > int64(^uint(0)>>1) || fragmentOffset_resultgeran > int64(^uint(0)>>1)-fragmentLength_resultgeran {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_resultgeran; i++ {
				var elem s12.ResultGERANItem
				elementMark := bb.EnterIndex(fragmentOffset_resultgeran + i)
				if err := s12.BridgeResultGERANItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ResultGERAN[%d]", fragmentOffset_resultgeran+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_resultgeran, elem); err != nil {
					return err
				} else {
					tmp_resultgeran = next
				}
			}
			return nil
		})
		if errCollection_resultgeran != nil {
			return runtime.WrapDecodePath(errCollection_resultgeran, "ResultGERAN")
		}
		v.ResultGERAN = tmp_resultgeran
		bb.LeaveComponent(toleranceMark_resultgeran)
	case s00.InterRATMeasuredResultsValueChoiceResultUTRAN:
		toleranceMark_resultutran := bb.EnterComponent("ResultUTRAN")
		tmp_resultutran := make(s14.ResultUTRAN, 0)
		_, errCollection_resultutran := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_resultutran, fragmentLength_resultutran int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
			if fragmentOffset_resultutran < 0 || fragmentLength_resultutran < 0 || fragmentLength_resultutran > int64(^uint(0)>>1) || fragmentOffset_resultutran > int64(^uint(0)>>1)-fragmentLength_resultutran {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_resultutran; i++ {
				var elem s14.ResultUTRANItem
				elementMark := bb.EnterIndex(fragmentOffset_resultutran + i)
				if err := s14.BridgeResultUTRANItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ResultUTRAN[%d]", fragmentOffset_resultutran+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_resultutran, elem); err != nil {
					return err
				} else {
					tmp_resultutran = next
				}
			}
			return nil
		})
		if errCollection_resultutran != nil {
			return runtime.WrapDecodePath(errCollection_resultutran, "ResultUTRAN")
		}
		v.ResultUTRAN = tmp_resultutran
		bb.LeaveComponent(toleranceMark_resultutran)
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// PosSIBsComplete carries a complete PosSIBs encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type PosSIBsComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s10.PosSIBs
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *PosSIBsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s11.BridgeMarshalAPERPosSIBsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes PosSIBs from APER format.
func (v *PosSIBsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *PosSIBsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PosSIBs")
	}
	bb.EnterComponent("PosSIBs")
	value, err := BridgeUnmarshalAPERPosSIBsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PosSIBs")
	}
	padding, err := aper.CaptureFinalBits(bb, "PosSIBs")
	if err != nil {
		return runtime.WrapDecodePath(err, "PosSIBs")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERPosSIBs encodes a PosSIBs list to APER.
func BridgeMarshalAPERPosSIBs(list PosSIBsComplete) ([]byte, error) { return list.marshalAPERLegacy() }

// UnmarshalAPERPosSIBs decodes a PosSIBs list from APER.
func BridgeUnmarshalAPERPosSIBs(data []byte) (PosSIBsComplete, error) {
	var value PosSIBsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERPosSIBsFrom decodes a PosSIBs list from bb.
func BridgeUnmarshalAPERPosSIBsFrom(bb *aper.BitBuffer) (s10.PosSIBs, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s10.BridgeAsn1cAPERPosSIBsListValue
	if err := BridgeUnmarshalAPERPosSIBsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERPosSIBsInto(v *s10.BridgeAsn1cAPERPosSIBsListValue, bb *aper.BitBuffer) error {
	v.Value = make(s10.PosSIBs, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s10.PosSIBsElem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s10.BridgePosSIBsElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return errCollection_value
	}
	return nil
}

// PosSIBSegmentsComplete carries a complete PosSIBSegments encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type PosSIBSegmentsComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s08.PosSIBSegments
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *PosSIBSegmentsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s11.BridgeMarshalAPERPosSIBSegmentsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes PosSIBSegments from APER format.
func (v *PosSIBSegmentsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *PosSIBSegmentsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PosSIBSegments")
	}
	bb.EnterComponent("PosSIBSegments")
	value, err := BridgeUnmarshalAPERPosSIBSegmentsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PosSIBSegments")
	}
	padding, err := aper.CaptureFinalBits(bb, "PosSIBSegments")
	if err != nil {
		return runtime.WrapDecodePath(err, "PosSIBSegments")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERPosSIBSegments encodes a PosSIBSegments list to APER.
func BridgeMarshalAPERPosSIBSegments(list PosSIBSegmentsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERPosSIBSegments decodes a PosSIBSegments list from APER.
func BridgeUnmarshalAPERPosSIBSegments(data []byte) (PosSIBSegmentsComplete, error) {
	var value PosSIBSegmentsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERPosSIBSegmentsFrom decodes a PosSIBSegments list from bb.
func BridgeUnmarshalAPERPosSIBSegmentsFrom(bb *aper.BitBuffer) (s08.PosSIBSegments, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s09.BridgeAsn1cAPERPosSIBSegmentsListValue
	if err := BridgeUnmarshalAPERPosSIBSegmentsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERPosSIBSegmentsInto(v *s09.BridgeAsn1cAPERPosSIBSegmentsListValue, bb *aper.BitBuffer) error {
	v.Value = make(s08.PosSIBSegments, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s08.PosSIBSegmentsElem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s08.BridgePosSIBSegmentsElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return errCollection_value
	}
	return nil
}

// ResultRSRPComplete carries a complete ResultRSRP encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultRSRPComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s12.ResultRSRP
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *ResultRSRPComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s12.BridgeMarshalAPERResultRSRPTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ResultRSRP from APER format.
func (v *ResultRSRPComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ResultRSRPComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRP")
	}
	bb.EnterComponent("ResultRSRP")
	value, err := BridgeUnmarshalAPERResultRSRPFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRP")
	}
	padding, err := aper.CaptureFinalBits(bb, "ResultRSRP")
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRP")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERResultRSRP encodes a ResultRSRP list to APER.
func BridgeMarshalAPERResultRSRP(list ResultRSRPComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERResultRSRP decodes a ResultRSRP list from APER.
func BridgeUnmarshalAPERResultRSRP(data []byte) (ResultRSRPComplete, error) {
	var value ResultRSRPComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERResultRSRPFrom decodes a ResultRSRP list from bb.
func BridgeUnmarshalAPERResultRSRPFrom(bb *aper.BitBuffer) (s12.ResultRSRP, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s12.BridgeAsn1cAPERResultRSRPListValue
	if err := BridgeUnmarshalAPERResultRSRPInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERResultRSRPInto(v *s12.BridgeAsn1cAPERResultRSRPListValue, bb *aper.BitBuffer) error {
	v.Value = make(s12.ResultRSRP, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s12.ResultRSRPItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s12.BridgeResultRSRPItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return errCollection_value
	}
	return nil
}

// ResultRSRQComplete carries a complete ResultRSRQ encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultRSRQComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s13.ResultRSRQ
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *ResultRSRQComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s13.BridgeMarshalAPERResultRSRQTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ResultRSRQ from APER format.
func (v *ResultRSRQComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ResultRSRQComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRQ")
	}
	bb.EnterComponent("ResultRSRQ")
	value, err := BridgeUnmarshalAPERResultRSRQFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRQ")
	}
	padding, err := aper.CaptureFinalBits(bb, "ResultRSRQ")
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRQ")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERResultRSRQ encodes a ResultRSRQ list to APER.
func BridgeMarshalAPERResultRSRQ(list ResultRSRQComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERResultRSRQ decodes a ResultRSRQ list from APER.
func BridgeUnmarshalAPERResultRSRQ(data []byte) (ResultRSRQComplete, error) {
	var value ResultRSRQComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERResultRSRQFrom decodes a ResultRSRQ list from bb.
func BridgeUnmarshalAPERResultRSRQFrom(bb *aper.BitBuffer) (s13.ResultRSRQ, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s13.BridgeAsn1cAPERResultRSRQListValue
	if err := BridgeUnmarshalAPERResultRSRQInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERResultRSRQInto(v *s13.BridgeAsn1cAPERResultRSRQListValue, bb *aper.BitBuffer) error {
	v.Value = make(s13.ResultRSRQ, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s13.ResultRSRQItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s13.BridgeResultRSRQItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return errCollection_value
	}
	return nil
}

// ResultGERANComplete carries a complete ResultGERAN encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultGERANComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s12.ResultGERAN
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *ResultGERANComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s12.BridgeMarshalAPERResultGERANTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ResultGERAN from APER format.
func (v *ResultGERANComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ResultGERANComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ResultGERAN")
	}
	bb.EnterComponent("ResultGERAN")
	value, err := BridgeUnmarshalAPERResultGERANFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultGERAN")
	}
	padding, err := aper.CaptureFinalBits(bb, "ResultGERAN")
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultGERAN")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERResultGERAN encodes a ResultGERAN list to APER.
func BridgeMarshalAPERResultGERAN(list ResultGERANComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERResultGERAN decodes a ResultGERAN list from APER.
func BridgeUnmarshalAPERResultGERAN(data []byte) (ResultGERANComplete, error) {
	var value ResultGERANComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERResultGERANFrom decodes a ResultGERAN list from bb.
func BridgeUnmarshalAPERResultGERANFrom(bb *aper.BitBuffer) (s12.ResultGERAN, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s12.BridgeAsn1cAPERResultGERANListValue
	if err := BridgeUnmarshalAPERResultGERANInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERResultGERANInto(v *s12.BridgeAsn1cAPERResultGERANListValue, bb *aper.BitBuffer) error {
	v.Value = make(s12.ResultGERAN, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s12.ResultGERANItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s12.BridgeResultGERANItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return errCollection_value
	}
	return nil
}

// ResultUTRANComplete carries a complete ResultUTRAN encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultUTRANComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s14.ResultUTRAN
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *ResultUTRANComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s14.BridgeMarshalAPERResultUTRANTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ResultUTRAN from APER format.
func (v *ResultUTRANComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ResultUTRANComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ResultUTRAN")
	}
	bb.EnterComponent("ResultUTRAN")
	value, err := BridgeUnmarshalAPERResultUTRANFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultUTRAN")
	}
	padding, err := aper.CaptureFinalBits(bb, "ResultUTRAN")
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultUTRAN")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERResultUTRAN encodes a ResultUTRAN list to APER.
func BridgeMarshalAPERResultUTRAN(list ResultUTRANComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERResultUTRAN decodes a ResultUTRAN list from APER.
func BridgeUnmarshalAPERResultUTRAN(data []byte) (ResultUTRANComplete, error) {
	var value ResultUTRANComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERResultUTRANFrom decodes a ResultUTRAN list from bb.
func BridgeUnmarshalAPERResultUTRANFrom(bb *aper.BitBuffer) (s14.ResultUTRAN, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s14.BridgeAsn1cAPERResultUTRANListValue
	if err := BridgeUnmarshalAPERResultUTRANInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERResultUTRANInto(v *s14.BridgeAsn1cAPERResultUTRANListValue, bb *aper.BitBuffer) error {
	v.Value = make(s14.ResultUTRAN, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s14.ResultUTRANItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s14.BridgeResultUTRANItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return errCollection_value
	}
	return nil
}

type BridgeAsn1cAPERResultNRListValue struct{ Value ResultNR }

// MarshalAPER encodes ResultNRItem to APER format.
func (v *ResultNRItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ResultNRItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.SSNRRSRP != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.SSNRRSRQ != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.NRARFCN), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(3279165), false); err != nil {
		return fmt.Errorf("encoding nRARFCN: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.NRPCI), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(1007), false); err != nil {
		return fmt.Errorf("encoding nRPCI: %w", err)
	}
	if v.SSNRRSRP != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.SSNRRSRP), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(127), false); err != nil {
			return fmt.Errorf("encoding sS-NRRSRP: %w", err)
		}
	}
	if v.SSNRRSRQ != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.SSNRRSRQ), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(127), false); err != nil {
			return fmt.Errorf("encoding sS-NRRSRQ: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:443
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:447
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:454
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
	return nil
}

// UnmarshalAPER decodes ResultNRItem from APER format.
func (v *ResultNRItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ResultNRItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ResultNRItem")
	}
	bb.EnterComponent("ResultNRItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResultNRItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ResultNRItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultNRItem")
	}
	v.perPadding = padding
	return nil
}
func (v *ResultNRItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultNRItem{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ssnrrsrp, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ssnrrsrq, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_nrarfcn, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(3279165), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "NRARFCN")
	}
	v.NRARFCN = s00.NRARFCN(val_nrarfcn)
	val_nrpci, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(1007), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "NRPCI")
	}
	v.NRPCI = s00.NRPCI(val_nrpci)
	if opt_ssnrrsrp {
		val_ssnrrsrp, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(127), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "SSNRRSRP")
		}
		tmp_ssnrrsrp := s00.SSNRRSRP(val_ssnrrsrp)
		if err := aper.ChargeValue(bb, tmp_ssnrrsrp); err != nil {
			return err
		}
		v.SSNRRSRP = (*s00.SSNRRSRP)(bb.OwnInt64(int64(tmp_ssnrrsrp)))
	}
	if opt_ssnrrsrq {
		val_ssnrrsrq, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(127), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "SSNRRSRQ")
		}
		tmp_ssnrrsrq := s00.SSNRRSRQ(val_ssnrrsrq)
		if err := aper.ChargeValue(bb, tmp_ssnrrsrq); err != nil {
			return err
		}
		v.SSNRRSRQ = (*s00.SSNRRSRQ)(bb.OwnInt64(int64(tmp_ssnrrsrq)))
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(ResultNRItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ResultNRItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := elem.unmarshalAPERFrom(bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:629
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:632
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] {
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
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// ResultsPerSSBIndexListComplete carries a complete ResultsPerSSBIndexList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultsPerSSBIndexListComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s14.ResultsPerSSBIndexList
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *ResultsPerSSBIndexListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s14.BridgeMarshalAPERResultsPerSSBIndexListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ResultsPerSSBIndexList from APER format.
func (v *ResultsPerSSBIndexListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ResultsPerSSBIndexListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ResultsPerSSBIndexList")
	}
	bb.EnterComponent("ResultsPerSSBIndexList")
	value, err := BridgeUnmarshalAPERResultsPerSSBIndexListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultsPerSSBIndexList")
	}
	padding, err := aper.CaptureFinalBits(bb, "ResultsPerSSBIndexList")
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultsPerSSBIndexList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERResultsPerSSBIndexList encodes a ResultsPerSSBIndexList list to APER.
func BridgeMarshalAPERResultsPerSSBIndexList(list ResultsPerSSBIndexListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERResultsPerSSBIndexListFrom decodes a ResultsPerSSBIndexList list from bb.
func BridgeUnmarshalAPERResultsPerSSBIndexListFrom(bb *aper.BitBuffer) (s14.ResultsPerSSBIndexList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s14.BridgeAsn1cAPERResultsPerSSBIndexListListValue
	if err := BridgeUnmarshalAPERResultsPerSSBIndexListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERResultsPerSSBIndexListInto(v *s14.BridgeAsn1cAPERResultsPerSSBIndexListListValue, bb *aper.BitBuffer) error {
	v.Value = make(s14.ResultsPerSSBIndexList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s14.ResultsPerSSBIndexItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s14.BridgeResultsPerSSBIndexItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return errCollection_value
	}
	return nil
}

// PRSFrequencyHoppingConfigurationBandPositionsComplete carries a complete PRSFrequencyHoppingConfigurationBandPositions encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type PRSFrequencyHoppingConfigurationBandPositionsComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s00.PRSFrequencyHoppingConfigurationBandPositions
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s05.BridgeMarshalAPERPRSFrequencyHoppingConfigurationBandPositionsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes PRSFrequencyHoppingConfigurationBandPositions from APER format.
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "PRSFrequencyHoppingConfigurationBandPositions")
	}
	bb.EnterComponent("PRSFrequencyHoppingConfigurationBandPositions")
	value, err := s18.BridgeUnmarshalAPERPRSFrequencyHoppingConfigurationBandPositionsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "PRSFrequencyHoppingConfigurationBandPositions")
	}
	padding, err := aper.CaptureFinalBits(bb, "PRSFrequencyHoppingConfigurationBandPositions")
	if err != nil {
		return runtime.WrapDecodePath(err, "PRSFrequencyHoppingConfigurationBandPositions")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERPRSFrequencyHoppingConfigurationBandPositions encodes a PRSFrequencyHoppingConfigurationBandPositions list to APER.
func BridgeMarshalAPERPRSFrequencyHoppingConfigurationBandPositions(list PRSFrequencyHoppingConfigurationBandPositionsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERPRSFrequencyHoppingConfigurationBandPositions decodes a PRSFrequencyHoppingConfigurationBandPositions list from APER.
func BridgeUnmarshalAPERPRSFrequencyHoppingConfigurationBandPositions(data []byte) (PRSFrequencyHoppingConfigurationBandPositionsComplete, error) {
	var value PRSFrequencyHoppingConfigurationBandPositionsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *InterRATMeasuredResultsValue) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "InterRATMeasuredResultsValue", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InterRATMeasuredResultsValue) WithoutReplay() InterRATMeasuredResultsValue {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero InterRATMeasuredResultsValue
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "PRSFrequencyHoppingConfigurationBandPositionsComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PRSFrequencyHoppingConfigurationBandPositionsComplete) WithoutReplay() PRSFrequencyHoppingConfigurationBandPositionsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero PRSFrequencyHoppingConfigurationBandPositionsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PosSIBSegmentsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "PosSIBSegmentsComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PosSIBSegmentsComplete) WithoutReplay() PosSIBSegmentsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero PosSIBSegmentsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PosSIBsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "PosSIBsComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PosSIBsComplete) WithoutReplay() PosSIBsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero PosSIBsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultGERANComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultGERANComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultGERANComplete) WithoutReplay() ResultGERANComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ResultGERANComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultNRItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultNRItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultNRItem) WithoutReplay() ResultNRItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ResultNRItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultRSRPComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultRSRPComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultRSRPComplete) WithoutReplay() ResultRSRPComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ResultRSRPComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultRSRQComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultRSRQComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultRSRQComplete) WithoutReplay() ResultRSRQComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ResultRSRQComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultUTRANComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultUTRANComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultUTRANComplete) WithoutReplay() ResultUTRANComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ResultUTRANComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultsPerSSBIndexListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultsPerSSBIndexListComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultsPerSSBIndexListComplete) WithoutReplay() ResultsPerSSBIndexListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ResultsPerSSBIndexListComplete
	v.perPadding = zero.perPadding
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ResultNRItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ResultNRItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResultNRItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResultNRItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ResultNRItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResultNRItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResultNRItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *InterRATMeasuredResultsValue) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "InterRATMeasuredResultsValue")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "InterRATMeasuredResultsValue")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaInterRATMeasuredResultsValue(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "InterRATMeasuredResultsValue")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "InterRATMeasuredResultsValue")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "InterRATMeasuredResultsValue")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "InterRATMeasuredResultsValue")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "InterRATMeasuredResultsValue")
}
func (v *InterRATMeasuredResultsValue) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *InterRATMeasuredResultsValue) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *InterRATMeasuredResultsValue) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaInterRATMeasuredResultsValue(v, &s)
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
func (v *InterRATMeasuredResultsValue) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *InterRATMeasuredResultsValue) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaPRSFrequencyHoppingConfigurationBandPositionsComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
}
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaPRSFrequencyHoppingConfigurationBandPositionsComplete(v, &s)
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
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s05.BridgeMarshalAPERPRSFrequencyHoppingConfigurationBandPositionsTo(value.Value, bb, fresh); err != nil {
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
func (v *PosSIBSegmentsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PosSIBSegmentsComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "PosSIBSegmentsComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaPosSIBSegmentsComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "PosSIBSegmentsComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "PosSIBSegmentsComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "PosSIBSegmentsComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "PosSIBSegmentsComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "PosSIBSegmentsComplete")
}
func (v *PosSIBSegmentsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *PosSIBSegmentsComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *PosSIBSegmentsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaPosSIBSegmentsComplete(v, &s)
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
func (v *PosSIBSegmentsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *PosSIBSegmentsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s11.BridgeMarshalAPERPosSIBSegmentsTo(value.Value, bb, fresh); err != nil {
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
func (v *PosSIBsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "PosSIBsComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "PosSIBsComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaPosSIBsComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "PosSIBsComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "PosSIBsComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "PosSIBsComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "PosSIBsComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "PosSIBsComplete")
}
func (v *PosSIBsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *PosSIBsComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *PosSIBsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaPosSIBsComplete(v, &s)
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
func (v *PosSIBsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *PosSIBsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s11.BridgeMarshalAPERPosSIBsTo(value.Value, bb, fresh); err != nil {
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
func (v *ResultGERANComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ResultGERANComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ResultGERANComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaResultGERANComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ResultGERANComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ResultGERANComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ResultGERANComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ResultGERANComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ResultGERANComplete")
}
func (v *ResultGERANComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultGERANComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultGERANComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaResultGERANComplete(v, &s)
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
func (v *ResultGERANComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultGERANComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s12.BridgeMarshalAPERResultGERANTo(value.Value, bb, fresh); err != nil {
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
func (v *ResultNRItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ResultNRItem")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ResultNRItem")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaResultNRItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ResultNRItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ResultNRItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ResultNRItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ResultNRItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ResultNRItem")
}
func (v *ResultNRItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultNRItem) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultNRItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaResultNRItem(v, &s)
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
func (v *ResultNRItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultNRItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ResultRSRPComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ResultRSRPComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ResultRSRPComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaResultRSRPComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ResultRSRPComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ResultRSRPComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ResultRSRPComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ResultRSRPComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ResultRSRPComplete")
}
func (v *ResultRSRPComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultRSRPComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultRSRPComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaResultRSRPComplete(v, &s)
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
func (v *ResultRSRPComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultRSRPComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s12.BridgeMarshalAPERResultRSRPTo(value.Value, bb, fresh); err != nil {
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
func (v *ResultRSRQComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ResultRSRQComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ResultRSRQComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaResultRSRQComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ResultRSRQComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ResultRSRQComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ResultRSRQComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ResultRSRQComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ResultRSRQComplete")
}
func (v *ResultRSRQComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultRSRQComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultRSRQComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaResultRSRQComplete(v, &s)
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
func (v *ResultRSRQComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultRSRQComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s13.BridgeMarshalAPERResultRSRQTo(value.Value, bb, fresh); err != nil {
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
func (v *ResultUTRANComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ResultUTRANComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ResultUTRANComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaResultUTRANComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ResultUTRANComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ResultUTRANComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ResultUTRANComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ResultUTRANComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ResultUTRANComplete")
}
func (v *ResultUTRANComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultUTRANComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultUTRANComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaResultUTRANComplete(v, &s)
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
func (v *ResultUTRANComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultUTRANComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s14.BridgeMarshalAPERResultUTRANTo(value.Value, bb, fresh); err != nil {
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
func (v *ResultsPerSSBIndexListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ResultsPerSSBIndexListComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ResultsPerSSBIndexListComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaResultsPerSSBIndexListComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ResultsPerSSBIndexListComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ResultsPerSSBIndexListComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ResultsPerSSBIndexListComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ResultsPerSSBIndexListComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ResultsPerSSBIndexListComplete")
}
func (v *ResultsPerSSBIndexListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultsPerSSBIndexListComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultsPerSSBIndexListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaResultsPerSSBIndexListComplete(v, &s)
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
func (v *ResultsPerSSBIndexListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultsPerSSBIndexListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s14.BridgeMarshalAPERResultsPerSSBIndexListTo(value.Value, bb, fresh); err != nil {
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
func (v *InterRATMeasuredResultsValue) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "InterRATMeasuredResultsValue")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded InterRATMeasuredResultsValue
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaInterRATMeasuredResultsValue(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = InterRATMeasuredResultsValue{}
		return report, aper.OperationError(err, "InterRATMeasuredResultsValue")
	}
	*v = decoded
	return report, aper.OperationError(nil, "InterRATMeasuredResultsValue")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded PRSFrequencyHoppingConfigurationBandPositionsComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaPRSFrequencyHoppingConfigurationBandPositionsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = PRSFrequencyHoppingConfigurationBandPositionsComplete{}
		return report, aper.OperationError(err, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *PosSIBSegmentsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PosSIBSegmentsComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded PosSIBSegmentsComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaPosSIBSegmentsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = PosSIBSegmentsComplete{}
		return report, aper.OperationError(err, "PosSIBSegmentsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PosSIBSegmentsComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *PosSIBsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "PosSIBsComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded PosSIBsComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaPosSIBsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = PosSIBsComplete{}
		return report, aper.OperationError(err, "PosSIBsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "PosSIBsComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultGERANComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ResultGERANComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ResultGERANComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultGERANComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ResultGERANComplete{}
		return report, aper.OperationError(err, "ResultGERANComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ResultGERANComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultNRItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ResultNRItem")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ResultNRItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultNRItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ResultNRItem{}
		return report, aper.OperationError(err, "ResultNRItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ResultNRItem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultRSRPComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ResultRSRPComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ResultRSRPComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultRSRPComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ResultRSRPComplete{}
		return report, aper.OperationError(err, "ResultRSRPComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ResultRSRPComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultRSRQComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ResultRSRQComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ResultRSRQComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultRSRQComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ResultRSRQComplete{}
		return report, aper.OperationError(err, "ResultRSRQComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ResultRSRQComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultUTRANComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ResultUTRANComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ResultUTRANComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultUTRANComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ResultUTRANComplete{}
		return report, aper.OperationError(err, "ResultUTRANComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ResultUTRANComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultsPerSSBIndexListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ResultsPerSSBIndexListComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ResultsPerSSBIndexListComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultsPerSSBIndexListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ResultsPerSSBIndexListComplete{}
		return report, aper.OperationError(err, "ResultsPerSSBIndexListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ResultsPerSSBIndexListComplete")
}

// MarshalAPERPosSIBs encodes a complete named list.
func MarshalAPERPosSIBs(v PosSIBsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERPosSIBSegments encodes a complete named list.
func MarshalAPERPosSIBSegments(v PosSIBSegmentsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERResultRSRP encodes a complete named list.
func MarshalAPERResultRSRP(v ResultRSRPComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERResultRSRQ encodes a complete named list.
func MarshalAPERResultRSRQ(v ResultRSRQComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERResultGERAN encodes a complete named list.
func MarshalAPERResultGERAN(v ResultGERANComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERResultUTRAN encodes a complete named list.
func MarshalAPERResultUTRAN(v ResultUTRANComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERResultsPerSSBIndexList encodes a complete named list.
func MarshalAPERResultsPerSSBIndexList(v ResultsPerSSBIndexListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERPRSFrequencyHoppingConfigurationBandPositions encodes a complete named list.
func MarshalAPERPRSFrequencyHoppingConfigurationBandPositions(v PRSFrequencyHoppingConfigurationBandPositionsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERPosSIBs decodes a complete named list.
func UnmarshalAPERPosSIBs(data []byte, options ...aper.DecodeOption) (PosSIBsComplete, aper.DecodeReport, error) {
	var v PosSIBsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERPosSIBSegments decodes a complete named list.
func UnmarshalAPERPosSIBSegments(data []byte, options ...aper.DecodeOption) (PosSIBSegmentsComplete, aper.DecodeReport, error) {
	var v PosSIBSegmentsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERResultRSRP decodes a complete named list.
func UnmarshalAPERResultRSRP(data []byte, options ...aper.DecodeOption) (ResultRSRPComplete, aper.DecodeReport, error) {
	var v ResultRSRPComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERResultRSRQ decodes a complete named list.
func UnmarshalAPERResultRSRQ(data []byte, options ...aper.DecodeOption) (ResultRSRQComplete, aper.DecodeReport, error) {
	var v ResultRSRQComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERResultGERAN decodes a complete named list.
func UnmarshalAPERResultGERAN(data []byte, options ...aper.DecodeOption) (ResultGERANComplete, aper.DecodeReport, error) {
	var v ResultGERANComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERResultUTRAN decodes a complete named list.
func UnmarshalAPERResultUTRAN(data []byte, options ...aper.DecodeOption) (ResultUTRANComplete, aper.DecodeReport, error) {
	var v ResultUTRANComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERResultsPerSSBIndexList decodes a complete named list.
func UnmarshalAPERResultsPerSSBIndexList(data []byte, options ...aper.DecodeOption) (ResultsPerSSBIndexListComplete, aper.DecodeReport, error) {
	var v ResultsPerSSBIndexListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERPRSFrequencyHoppingConfigurationBandPositions decodes a complete named list.
func UnmarshalAPERPRSFrequencyHoppingConfigurationBandPositions(data []byte, options ...aper.DecodeOption) (PRSFrequencyHoppingConfigurationBandPositionsComplete, aper.DecodeReport, error) {
	var v PRSFrequencyHoppingConfigurationBandPositionsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}
func BridgeCaptureLPPaInterRATMeasuredResultsValue(v *InterRATMeasuredResultsValue, s *aper.SemanticCapture) {
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
	case s00.InterRATMeasuredResultsValueChoiceResultGERAN:
		s12.BridgeCaptureLPPaResultGERAN(&v.ResultGERAN, s)
	case s00.InterRATMeasuredResultsValueChoiceResultUTRAN:
		s14.BridgeCaptureLPPaResultUTRAN(&v.ResultUTRAN, s)
	case s00.InterRATMeasuredResultsValueChoiceResultNR:
		BridgeCaptureLPPaResultNR(&v.ResultNR, s)
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaInterRATMeasuredResultsValue(v *InterRATMeasuredResultsValue, s *aper.SemanticComparison) {
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
	case s00.InterRATMeasuredResultsValueChoiceResultGERAN:
		s12.BridgeCompareLPPaResultGERAN(&v.ResultGERAN, s)
	case s00.InterRATMeasuredResultsValueChoiceResultUTRAN:
		s14.BridgeCompareLPPaResultUTRAN(&v.ResultUTRAN, s)
	case s00.InterRATMeasuredResultsValueChoiceResultNR:
		BridgeCompareLPPaResultNR(&v.ResultNR, s)
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaPRSFrequencyHoppingConfigurationBandPositionsComplete(v *PRSFrequencyHoppingConfigurationBandPositionsComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaPRSFrequencyHoppingConfigurationBandPositions(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaPRSFrequencyHoppingConfigurationBandPositionsComplete(v *PRSFrequencyHoppingConfigurationBandPositionsComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaPRSFrequencyHoppingConfigurationBandPositions(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaPosSIBSegmentsComplete(v *PosSIBSegmentsComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s09.BridgeCaptureLPPaPosSIBSegments(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaPosSIBSegmentsComplete(v *PosSIBSegmentsComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s10.BridgeCompareLPPaPosSIBSegments(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaPosSIBsComplete(v *PosSIBsComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s10.BridgeCaptureLPPaPosSIBs(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaPosSIBsComplete(v *PosSIBsComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s10.BridgeCompareLPPaPosSIBs(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultGERANComplete(v *ResultGERANComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s12.BridgeCaptureLPPaResultGERAN(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultGERANComplete(v *ResultGERANComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s12.BridgeCompareLPPaResultGERAN(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultNR(v *ResultNR, s *aper.SemanticCapture) {
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
			BridgeCaptureLPPaResultNRItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaResultNR(v *ResultNR, s *aper.SemanticComparison) {
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
			BridgeCompareLPPaResultNRItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaResultNRItem(v *ResultNRItem, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaNRARFCN(&v.NRARFCN, s)
	s00.BridgeCaptureLPPaNRPCI(&v.NRPCI, s)
	{
		f := s.Begin()
		s.Bool(v.SSNRRSRP == nil)
		if v.SSNRRSRP != nil {
			s00.BridgeCaptureLPPaSSNRRSRP(v.SSNRRSRP, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.SSNRRSRQ == nil)
		if v.SSNRRSRQ != nil {
			s00.BridgeCaptureLPPaSSNRRSRQ(v.SSNRRSRQ, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeResultNRItemExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultNRItem(v *ResultNRItem, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaNRARFCN(&v.NRARFCN, s)
	s02.BridgeCompareLPPaNRPCI(&v.NRPCI, s)
	{
		f := s.Begin()
		s.Bool(v.SSNRRSRP == nil)
		if v.SSNRRSRP != nil {
			s03.BridgeCompareLPPaSSNRRSRP(v.SSNRRSRP, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.SSNRRSRQ == nil)
		if v.SSNRRSRQ != nil {
			s03.BridgeCompareLPPaSSNRRSRQ(v.SSNRRSRQ, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeResultNRItemExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultNRItemExtIEsValue(v *ResultNRItemExtIEsValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(25):
			{
				f := s.Begin()
				s.Bool(v.rowResultsPerSSBIndexList == nil)
				if v.rowResultsPerSSBIndexList != nil {
					s14.BridgeCaptureLPPaResultsPerSSBIndexList(v.rowResultsPerSSBIndexList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(27):
			{
				f := s.Begin()
				s.Bool(v.rowNRCGI == nil)
				if v.rowNRCGI != nil {
					s07.BridgeCaptureLPPaNRCGI(v.rowNRCGI, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ResultNRItemExtIEsValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v ResultNRItemExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ResultNRItemExtIEsValue) captureSemantics(s aper.SemanticCapture) ResultNRItemExtIEsValue {
	BridgeCaptureLPPaResultNRItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaResultNRItemExtIEsValue(v *ResultNRItemExtIEsValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProtocolIEID(&v.id, s)
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
		case s00.ProtocolIEID(25):
			{
				f := s.Begin()
				s.Bool(v.rowResultsPerSSBIndexList == nil)
				if v.rowResultsPerSSBIndexList != nil {
					s14.BridgeCompareLPPaResultsPerSSBIndexList(v.rowResultsPerSSBIndexList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(27):
			{
				f := s.Begin()
				s.Bool(v.rowNRCGI == nil)
				if v.rowNRCGI != nil {
					s07.BridgeCompareLPPaNRCGI(v.rowNRCGI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v ResultNRItemExtIEsValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaResultNRItemExtIEsValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultNRItemExtIEsValue) WithoutReplay() ResultNRItemExtIEsValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaResultRSRPComplete(v *ResultRSRPComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s12.BridgeCaptureLPPaResultRSRP(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultRSRPComplete(v *ResultRSRPComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s12.BridgeCompareLPPaResultRSRP(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultRSRQComplete(v *ResultRSRQComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s13.BridgeCaptureLPPaResultRSRQ(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultRSRQComplete(v *ResultRSRQComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s13.BridgeCompareLPPaResultRSRQ(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultUTRANComplete(v *ResultUTRANComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s14.BridgeCaptureLPPaResultUTRAN(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultUTRANComplete(v *ResultUTRANComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s14.BridgeCompareLPPaResultUTRAN(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultsPerSSBIndexListComplete(v *ResultsPerSSBIndexListComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s14.BridgeCaptureLPPaResultsPerSSBIndexList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultsPerSSBIndexListComplete(v *ResultsPerSSBIndexListComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s14.BridgeCompareLPPaResultsPerSSBIndexList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}

type ResultNRItemExtIEsValue struct {
	id                        s00.ProtocolIEID
	withoutReplay             bool
	received                  aper.WireSpan
	replay                    aper.Snapshot
	opaque                    *aper.OpaqueOpenType
	isOpaque                  bool
	rowResultsPerSSBIndexList *s14.ResultsPerSSBIndexList
	rowNRCGI                  *s07.NRCGI
}

func (v ResultNRItemExtIEsValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case s00.ProtocolIEID(25):
		return v.rowResultsPerSSBIndexList != nil
	case s00.ProtocolIEID(27):
		return v.rowNRCGI != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *ResultNRItemExtIEsValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ResultNRItemExtIEsValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultNR-Item-ExtIEs"}}
}
func (ResultNRItemExtIEsValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(25):
		return aper.UnknownSelector
	case s00.ProtocolIEID(27):
		return aper.UnknownSelector
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
	default:
		return aper.UnknownSelector
	}
}

// AsResultsPerSSBIndexList returns the selected ResultsPerSSBIndexList value and reports whether that alternative is active.
func (v *ResultNRItemExtIEsValue) AsResultsPerSSBIndexList() (*s14.ResultsPerSSBIndexList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(25) || v.rowResultsPerSSBIndexList == nil {
		return nil, false
	}
	return v.rowResultsPerSSBIndexList, true
}

// AsNRCGI returns the selected NRCGI value and reports whether that alternative is active.
func (v *ResultNRItemExtIEsValue) AsNRCGI() (*s07.NRCGI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(27) || v.rowNRCGI == nil {
		return nil, false
	}
	return v.rowNRCGI, true
}
func (v ResultNRItemExtIEsValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ResultNRItemExtIEsValue, error) {
	out := ResultNRItemExtIEsValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 25, 27:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case s00.ProtocolIEID(25):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := BridgeUnmarshalAPERResultsPerSSBIndexListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ResultsPerSSBIndexList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := ResultsPerSSBIndexListComplete{Value: list, perPadding: padding}
		value := complete.Value
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowResultsPerSSBIndexList = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case s00.ProtocolIEID(27):
		replayUsage := scope.Usage()
		var value s07.NRCGI
		child := raw.ChildDecodeBuffer()
		if err := s07.BridgeNRCGIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NRCGI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NRCGI")
		if err != nil {
			return out, err
		}
		*s07.BridgeNRCGIFieldPerPadding(&value) = padding
		*s07.BridgeNRCGIFieldReceived(&value) = true
		raw.RetainContents(s07.BridgeNRCGIFieldReceivedBytes(&value))
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowNRCGI = &value
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
func (v ResultNRItemExtIEsValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ResultNRItemExtIEsValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(25):
		if v.rowResultsPerSSBIndexList == nil {
			return nil, fmt.Errorf("%s missing value", "ResultNR-Item-ExtIEs.id-ResultsPerSSB-Index-List:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		complete := ResultsPerSSBIndexListComplete{Value: *v.rowResultsPerSSBIndexList}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(27):
		if v.rowNRCGI == nil {
			return nil, fmt.Errorf("%s missing value", "ResultNR-Item-ExtIEs.id-NR-CGI:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := s07.BridgeNRCGIMethodMarshalAPERBudget(v.rowNRCGI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ResultNRItemExtIEsValue:", v.id)
	}
}

type ResultNRItemExtIETable struct{}

func ResultNRItemExtIEs() ResultNRItemExtIETable { return ResultNRItemExtIETable{} }

// ID returns the ASN.1 source assignment identifying this table.
func (ResultNRItemExtIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultNR-Item-ExtIEs"}
		return sealed
	}()
}
func (ResultNRItemExtIETable) infoResultsPerSSBIndexList() s00.FieldInfo {
	return s00.FieldInfo{Table: ResultNRItemExtIEs().ID(), ID: s00.ProtocolIEID(25), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultsPerSSBIndexList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultNR-Item-ExtIEs", Row: "id-ResultsPerSSB-Index-List"}}}
}

// ResultsPerSSBIndexList returns the typed binding for the ResultsPerSSBIndexList row of this table.
func (t ResultNRItemExtIETable) ResultsPerSSBIndexList() ResultNRItemExtIEsResultsPerSSBIndexListExtBinding {
	return ResultNRItemExtIEsResultsPerSSBIndexListExtBinding{info: t.infoResultsPerSSBIndexList(), codec: func() s14.ResultsPerSSBIndexListValueCodec {
		sealed := s14.ResultsPerSSBIndexListValueCodec{}
		*s14.BridgeResultsPerSSBIndexListValueCodecFieldPath(&sealed) = "ResultsPerSSBIndexList"
		*s14.BridgeResultsPerSSBIndexListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.ResultsPerSSBIndexList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s14.ResultsPerSSBIndexList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ResultsPerSSBIndexList")
			var zero ResultNRItemExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(25), raw)
			if err != nil {
				var empty s14.ResultsPerSSBIndexList
				return empty, runtime.WrapDecodePath(err, "ResultsPerSSBIndexList")
			}
			value, ok := decoded.AsResultsPerSSBIndexList()
			if !ok {
				var empty s14.ResultsPerSSBIndexList
				return empty, fmt.Errorf("binding ResultNR-Item-ExtIEs.id-ResultsPerSSB-Index-List: no selected value")
			}
			return *value, nil
		}
		*s14.BridgeResultsPerSSBIndexListValueCodecFieldEncode(&sealed) = func(value s14.ResultsPerSSBIndexList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ResultNRItemExtIEsValue{id: s00.ProtocolIEID(25), rowResultsPerSSBIndexList: &value}).encodeFresh(fresh, budget)
		}
		*s14.BridgeResultsPerSSBIndexListValueCodecFieldCapture(&sealed) = func(v s14.ResultsPerSSBIndexList, options aper.DecodeState) (s14.ResultsPerSSBIndexList, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s14.BridgeCaptureLPPaResultsPerSSBIndexList(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s14.BridgeResultsPerSSBIndexListValueCodecFieldCompare(&sealed) = func(v s14.ResultsPerSSBIndexList, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s14.BridgeCompareLPPaResultsPerSSBIndexList(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s14.BridgeResultsPerSSBIndexListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ResultsPerSSBIndexList"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s14.ResultsPerSSBIndexList) ResultNRItemExtIEsValue {
			return ResultNRItemExtIEsValue{id: s00.ProtocolIEID(25), rowResultsPerSSBIndexList: &value}
		}, get: func(value *ResultNRItemExtIEsValue) (*s14.ResultsPerSSBIndexList, bool) {
			return value.AsResultsPerSSBIndexList()
		}}
}
func (ResultNRItemExtIETable) infoNRCGI() s00.FieldInfo {
	return s00.FieldInfo{Table: ResultNRItemExtIEs().ID(), ID: s00.ProtocolIEID(27), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "NRCGI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultNR-Item-ExtIEs", Row: "id-NR-CGI"}}}
}

// NRCGI returns the typed binding for the NRCGI row of this table.
func (t ResultNRItemExtIETable) NRCGI() ResultNRItemExtIEsNRCGIExtBinding {
	return ResultNRItemExtIEsNRCGIExtBinding{info: t.infoNRCGI(), codec: func() s07.NRCGIValueCodec {
		sealed := s07.NRCGIValueCodec{}
		*s07.BridgeNRCGIValueCodecFieldPath(&sealed) = "NRCGI"
		*s07.BridgeNRCGIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s07.NRCGI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s07.NRCGI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NRCGI")
			var zero ResultNRItemExtIEsValue
			decoded, err := zero.decode(s00.ProtocolIEID(27), raw)
			if err != nil {
				var empty s07.NRCGI
				return empty, runtime.WrapDecodePath(err, "NRCGI")
			}
			value, ok := decoded.AsNRCGI()
			if !ok {
				var empty s07.NRCGI
				return empty, fmt.Errorf("binding ResultNR-Item-ExtIEs.id-NR-CGI: no selected value")
			}
			return *value, nil
		}
		*s07.BridgeNRCGIValueCodecFieldEncode(&sealed) = func(value s07.NRCGI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ResultNRItemExtIEsValue{id: s00.ProtocolIEID(27), rowNRCGI: &value}).encodeFresh(fresh, budget)
		}
		*s07.BridgeNRCGIValueCodecFieldCapture(&sealed) = func(v s07.NRCGI, options aper.DecodeState) (s07.NRCGI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s07.BridgeCaptureLPPaNRCGI(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s07.BridgeNRCGIValueCodecFieldCompare(&sealed) = func(v s07.NRCGI, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			s07.BridgeCompareLPPaNRCGI(&v, &s)
			s.End(
				f, root, false)
			return s.Plan()
		}
		*s07.BridgeNRCGIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRCGI"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s07.NRCGI) ResultNRItemExtIEsValue {
			return ResultNRItemExtIEsValue{id: s00.ProtocolIEID(27), rowNRCGI: &value}
		}, get: func(value *ResultNRItemExtIEsValue) (*s07.NRCGI, bool) { return value.AsNRCGI() }}
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t ResultNRItemExtIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ResultNRItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ResultNRItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(25):
		return ResultNRItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-ResultsPerSSB-Index-List requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(27):
		return ResultNRItemExtIEsExtField{}, aper.OperationError(fmt.Errorf("known extension id-NR-CGI requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ResultNRItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ResultNRItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ResultNRItemExtIEsExtField{}, aper.OperationError(err, "Opaque")
		}
		return ResultNRItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: ResultNRItemExtIEsValue{id: id, opaque: retained, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// NRCGICodec binds the complete APER value type.
func NRCGICodec() s07.NRCGIValueCodec { return ResultNRItemExtIEs().NRCGI().Codec() }

// PRSFrequencyHoppingConfigurationBandPositionsCodec binds the complete source value type.
func PRSFrequencyHoppingConfigurationBandPositionsCodec() s01.PRSFrequencyHoppingConfigurationBandPositionsValueCodec {
	return func() s01.PRSFrequencyHoppingConfigurationBandPositionsValueCodec {
		sealed := s01.PRSFrequencyHoppingConfigurationBandPositionsValueCodec{}
		*s01.BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldPath(&sealed) = "PRSFrequencyHoppingConfigurationBandPositions"
		*s01.BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PRSFrequencyHoppingConfigurationBandPositions, error) {
			var complete PRSFrequencyHoppingConfigurationBandPositionsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.PRSFrequencyHoppingConfigurationBandPositions
				return zero, err
			}
			return complete.Value, nil
		}
		*s01.BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldEncode(&sealed) = func(value s00.PRSFrequencyHoppingConfigurationBandPositions, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := PRSFrequencyHoppingConfigurationBandPositionsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s01.BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldCapture(&sealed) = func(v s00.PRSFrequencyHoppingConfigurationBandPositions, options aper.DecodeState) (s00.PRSFrequencyHoppingConfigurationBandPositions, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaPRSFrequencyHoppingConfigurationBandPositions(&v, &s)
			var root aper.Snapshot
			s.
				OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldCompare(&sealed) = func(v s00.PRSFrequencyHoppingConfigurationBandPositions, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f :=
				s.Begin()
			s02.BridgeCompareLPPaPRSFrequencyHoppingConfigurationBandPositions(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PRSFrequencyHoppingConfigurationBandPositions"
			return sealed
		}()
		return sealed
	}()

}

// PosSIBSegmentsCodec binds the complete source value type.
func PosSIBSegmentsCodec() s08.PosSIBSegmentsValueCodec {
	return func() s08.PosSIBSegmentsValueCodec {
		sealed := s08.PosSIBSegmentsValueCodec{}
		*s08.BridgePosSIBSegmentsValueCodecFieldPath(&sealed) = "PosSIBSegments"
		*s08.BridgePosSIBSegmentsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s08.PosSIBSegments, error) {
			var complete PosSIBSegmentsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s08.PosSIBSegments
				return zero, err
			}
			return complete.Value, nil
		}
		*s08.BridgePosSIBSegmentsValueCodecFieldEncode(&sealed) = func(value s08.PosSIBSegments, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := PosSIBSegmentsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s08.BridgePosSIBSegmentsValueCodecFieldCapture(&sealed) = func(v s08.PosSIBSegments, options aper.DecodeState) (s08.PosSIBSegments, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s09.BridgeCaptureLPPaPosSIBSegments(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s08.BridgePosSIBSegmentsValueCodecFieldCompare(&sealed) = func(v s08.PosSIBSegments, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s10.BridgeCompareLPPaPosSIBSegments(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s08.BridgePosSIBSegmentsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PosSIBSegments"
			return sealed
		}()
		return sealed
	}()

}

// PosSIBsCodec binds the complete source value type.
func PosSIBsCodec() s10.PosSIBsValueCodec {
	return func() s10.PosSIBsValueCodec {
		sealed := s10.PosSIBsValueCodec{}
		*s10.BridgePosSIBsValueCodecFieldPath(&sealed) = "PosSIBs"
		*s10.BridgePosSIBsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.PosSIBs, error) {
			var complete PosSIBsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s10.PosSIBs
				return zero, err
			}
			return complete.Value, nil
		}
		*s10.BridgePosSIBsValueCodecFieldEncode(&sealed) = func(value s10.PosSIBs, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := PosSIBsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s10.BridgePosSIBsValueCodecFieldCapture(&sealed) = func(v s10.PosSIBs, options aper.DecodeState) (s10.PosSIBs, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s10.BridgeCaptureLPPaPosSIBs(&v, &s)
			var root aper.Snapshot
			s.
				OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgePosSIBsValueCodecFieldCompare(&sealed) = func(v s10.PosSIBs, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(
				root, limits)
			f := s.Begin()
			s10.BridgeCompareLPPaPosSIBs(&v, &s)
			s.
				End(f, root, false)
			return s.Plan()
		}
		*s10.BridgePosSIBsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PosSIBs"
			return sealed
		}()
		return sealed
	}()

}

// ResultGERANCodec binds the complete source value type.
func ResultGERANCodec() s12.ResultGERANValueCodec {
	return func() s12.ResultGERANValueCodec {
		sealed := s12.ResultGERANValueCodec{}
		*s12.BridgeResultGERANValueCodecFieldPath(&sealed) = "ResultGERAN"
		*s12.BridgeResultGERANValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.ResultGERAN, error) {
			var complete ResultGERANComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s12.ResultGERAN
				return zero, err
			}
			return complete.Value, nil
		}
		*s12.BridgeResultGERANValueCodecFieldEncode(&sealed) = func(value s12.ResultGERAN, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ResultGERANComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s12.BridgeResultGERANValueCodecFieldCapture(&sealed) = func(v s12.ResultGERAN, options aper.DecodeState) (s12.ResultGERAN, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s12.BridgeCaptureLPPaResultGERAN(&v, &s)
			var root aper.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v,
				root
		}
		*s12.BridgeResultGERANValueCodecFieldCompare(&sealed) = func(v s12.ResultGERAN, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s12.BridgeCompareLPPaResultGERAN(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s12.BridgeResultGERANValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ResultGERAN"
			return sealed
		}()
		return sealed
	}()

}

// ResultNRItemCodec binds the complete source value type.
func ResultNRItemCodec() ResultNRItemValueCodec {
	return ResultNRItemValueCodec{path: "ResultNRItem", decode: func(data []byte, options aper.DecodeState) (ResultNRItem, error) {
		var value ResultNRItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ResultNRItem{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ResultNRItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ResultNRItem, options aper.DecodeState) (ResultNRItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaResultNRItem(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResultNRItem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaResultNRItem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ResultNRItem"
		return sealed
	}(),
	}
}

// ResultRSRPCodec binds the complete source value type.
func ResultRSRPCodec() s12.ResultRSRPValueCodec {
	return func() s12.ResultRSRPValueCodec {
		sealed := s12.ResultRSRPValueCodec{}
		*s12.BridgeResultRSRPValueCodecFieldPath(&sealed) = "ResultRSRP"
		*s12.BridgeResultRSRPValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.ResultRSRP, error) {
			var complete ResultRSRPComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s12.ResultRSRP
				return zero, err
			}
			return complete.Value, nil
		}
		*s12.BridgeResultRSRPValueCodecFieldEncode(&sealed) = func(value s12.ResultRSRP, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ResultRSRPComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s12.BridgeResultRSRPValueCodecFieldCapture(&sealed) = func(v s12.ResultRSRP, options aper.DecodeState) (s12.ResultRSRP, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s12.BridgeCaptureLPPaResultRSRP(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root

		}
		*s12.BridgeResultRSRPValueCodecFieldCompare(&sealed) = func(v s12.ResultRSRP, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s12.BridgeCompareLPPaResultRSRP(&v,
				&s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s12.BridgeResultRSRPValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ResultRSRP"
			return sealed
		}()
		return sealed
	}()

}

// ResultRSRQCodec binds the complete source value type.
func ResultRSRQCodec() s13.ResultRSRQValueCodec {
	return func() s13.ResultRSRQValueCodec {
		sealed := s13.ResultRSRQValueCodec{}
		*s13.BridgeResultRSRQValueCodecFieldPath(&sealed) = "ResultRSRQ"
		*s13.BridgeResultRSRQValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.ResultRSRQ, error) {
			var complete ResultRSRQComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s13.ResultRSRQ
				return zero, err
			}
			return complete.Value, nil
		}
		*s13.BridgeResultRSRQValueCodecFieldEncode(&sealed) = func(value s13.ResultRSRQ, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ResultRSRQComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s13.BridgeResultRSRQValueCodecFieldCapture(&sealed) = func(v s13.ResultRSRQ, options aper.DecodeState) (s13.ResultRSRQ, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f :=
				s.Begin()
			s13.BridgeCaptureLPPaResultRSRQ(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root

		}
		*s13.BridgeResultRSRQValueCodecFieldCompare(&sealed) = func(v s13.ResultRSRQ, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s13.BridgeCompareLPPaResultRSRQ(&v,
				&s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s13.BridgeResultRSRQValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ResultRSRQ"
			return sealed
		}()
		return sealed
	}()

}

// ResultUTRANCodec binds the complete source value type.
func ResultUTRANCodec() s14.ResultUTRANValueCodec {
	return func() s14.ResultUTRANValueCodec {
		sealed := s14.ResultUTRANValueCodec{}
		*s14.BridgeResultUTRANValueCodecFieldPath(&sealed) = "ResultUTRAN"
		*s14.BridgeResultUTRANValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.ResultUTRAN, error) {
			var complete ResultUTRANComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s14.ResultUTRAN
				return zero, err
			}
			return complete.Value, nil
		}
		*s14.BridgeResultUTRANValueCodecFieldEncode(&sealed) = func(value s14.ResultUTRAN, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ResultUTRANComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s14.BridgeResultUTRANValueCodecFieldCapture(&sealed) = func(v s14.ResultUTRAN, options aper.DecodeState) (s14.ResultUTRAN, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s14.BridgeCaptureLPPaResultUTRAN(&v, &s)
			var root aper.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v,
				root
		}
		*s14.BridgeResultUTRANValueCodecFieldCompare(&sealed) = func(v s14.ResultUTRAN, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s14.BridgeCompareLPPaResultUTRAN(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s14.BridgeResultUTRANValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ResultUTRAN"
			return sealed
		}()
		return sealed
	}()

}

// ResultsPerSSBIndexListCodec binds the complete APER value type.
func ResultsPerSSBIndexListCodec() s14.ResultsPerSSBIndexListValueCodec {
	return ResultNRItemExtIEs().ResultsPerSSBIndexList().Codec()
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *ResultNRItemExtIEsValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 25:
		if v.rowResultsPerSSBIndexList != nil {
			return v.rowResultsPerSSBIndexList, true
		}
	case 27:
		if v.rowNRCGI != nil {
			return v.rowNRCGI, true
		}
	}
	return nil, false
}

func BridgeInterRATMeasuredResultsValueAPERValueFieldContext(v *InterRATMeasuredResultsValueAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterRATMeasuredResultsValueAPERValueFieldReceived(v *InterRATMeasuredResultsValueAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInterRATMeasuredResultsValueAPERValueFieldReplay(v *InterRATMeasuredResultsValueAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasuredResultsValueAPERValueFieldWithoutReplay(v *InterRATMeasuredResultsValueAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasuredResultsValueFieldKnownOpenBytes(v *InterRATMeasuredResultsValue) *uint64 {
	return &v.knownOpenBytes
}
func BridgeInterRATMeasuredResultsValueFieldPerOpenTypePadding(v *InterRATMeasuredResultsValue) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeInterRATMeasuredResultsValueFieldPerPadding(v *InterRATMeasuredResultsValue) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeInterRATMeasuredResultsValueFieldReceived(v *InterRATMeasuredResultsValue) *bool {
	return &v.received
}
func BridgeInterRATMeasuredResultsValueFieldReceivedBytes(v *InterRATMeasuredResultsValue) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeInterRATMeasuredResultsValueFieldReplay(v *InterRATMeasuredResultsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasuredResultsValueFieldStream(v *InterRATMeasuredResultsValue) *aper.WireSpan {
	return &v.stream
}
func BridgeInterRATMeasuredResultsValueFieldWithoutReplay(v *InterRATMeasuredResultsValue) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasuredResultsValueMethodMarshalAPERBudget(v *InterRATMeasuredResultsValue, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInterRATMeasuredResultsValueMethodMarshalAPERChanged(v *InterRATMeasuredResultsValue, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeInterRATMeasuredResultsValueMethodMarshalAPERChangedValue(v *InterRATMeasuredResultsValue, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeInterRATMeasuredResultsValueMethodMarshalAPERFreshValue(v *InterRATMeasuredResultsValue, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeInterRATMeasuredResultsValueMethodMarshalAPERLegacy(v *InterRATMeasuredResultsValue) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeInterRATMeasuredResultsValueMethodMarshalAPERPlanned(v *InterRATMeasuredResultsValue, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeInterRATMeasuredResultsValueMethodMarshalAPERTo(v *InterRATMeasuredResultsValue, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInterRATMeasuredResultsValueMethodUnmarshalAPERFrom(v *InterRATMeasuredResultsValue, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInterRATMeasuredResultsValueMethodUnmarshalAPERLegacy(v *InterRATMeasuredResultsValue, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeInterRATMeasuredResultsValueMethodUnmarshalAPERWithOptions(v *InterRATMeasuredResultsValue, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteFieldPerPadding(v *PRSFrequencyHoppingConfigurationBandPositionsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteFieldReceived(v *PRSFrequencyHoppingConfigurationBandPositionsComplete) *bool {
	return &v.received
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteFieldReceivedBytes(v *PRSFrequencyHoppingConfigurationBandPositionsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteFieldReplay(v *PRSFrequencyHoppingConfigurationBandPositionsComplete) *aper.Snapshot {
	return &v.replay
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteFieldStream(v *PRSFrequencyHoppingConfigurationBandPositionsComplete) *aper.WireSpan {
	return &v.stream
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteFieldWithoutReplay(v *PRSFrequencyHoppingConfigurationBandPositionsComplete) *bool {
	return &v.withoutReplay
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteMethodMarshalAPERBudget(v *PRSFrequencyHoppingConfigurationBandPositionsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteMethodMarshalAPERChanged(v *PRSFrequencyHoppingConfigurationBandPositionsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteMethodMarshalAPERChangedValue(v *PRSFrequencyHoppingConfigurationBandPositionsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteMethodMarshalAPERFreshValue(v *PRSFrequencyHoppingConfigurationBandPositionsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteMethodMarshalAPERLegacy(v *PRSFrequencyHoppingConfigurationBandPositionsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteMethodMarshalAPERPlanned(v *PRSFrequencyHoppingConfigurationBandPositionsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteMethodUnmarshalAPERLegacy(v *PRSFrequencyHoppingConfigurationBandPositionsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteMethodUnmarshalAPERWithOptions(v *PRSFrequencyHoppingConfigurationBandPositionsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePosSIBSegmentsCompleteFieldPerPadding(v *PosSIBSegmentsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgePosSIBSegmentsCompleteFieldReceived(v *PosSIBSegmentsComplete) *bool { return &v.received }
func BridgePosSIBSegmentsCompleteFieldReceivedBytes(v *PosSIBSegmentsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePosSIBSegmentsCompleteFieldReplay(v *PosSIBSegmentsComplete) *aper.Snapshot {
	return &v.replay
}
func BridgePosSIBSegmentsCompleteFieldStream(v *PosSIBSegmentsComplete) *aper.WireSpan {
	return &v.stream
}
func BridgePosSIBSegmentsCompleteFieldWithoutReplay(v *PosSIBSegmentsComplete) *bool {
	return &v.withoutReplay
}
func BridgePosSIBSegmentsCompleteMethodMarshalAPERBudget(v *PosSIBSegmentsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePosSIBSegmentsCompleteMethodMarshalAPERChanged(v *PosSIBSegmentsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePosSIBSegmentsCompleteMethodMarshalAPERChangedValue(v *PosSIBSegmentsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePosSIBSegmentsCompleteMethodMarshalAPERFreshValue(v *PosSIBSegmentsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgePosSIBSegmentsCompleteMethodMarshalAPERLegacy(v *PosSIBSegmentsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePosSIBSegmentsCompleteMethodMarshalAPERPlanned(v *PosSIBSegmentsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgePosSIBSegmentsCompleteMethodUnmarshalAPERLegacy(v *PosSIBSegmentsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePosSIBSegmentsCompleteMethodUnmarshalAPERWithOptions(v *PosSIBSegmentsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePosSIBsCompleteFieldPerPadding(v *PosSIBsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgePosSIBsCompleteFieldReceived(v *PosSIBsComplete) *bool { return &v.received }
func BridgePosSIBsCompleteFieldReceivedBytes(v *PosSIBsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgePosSIBsCompleteFieldReplay(v *PosSIBsComplete) *aper.Snapshot { return &v.replay }
func BridgePosSIBsCompleteFieldStream(v *PosSIBsComplete) *aper.WireSpan { return &v.stream }
func BridgePosSIBsCompleteFieldWithoutReplay(v *PosSIBsComplete) *bool   { return &v.withoutReplay }
func BridgePosSIBsCompleteMethodMarshalAPERBudget(v *PosSIBsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePosSIBsCompleteMethodMarshalAPERChanged(v *PosSIBsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePosSIBsCompleteMethodMarshalAPERChangedValue(v *PosSIBsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePosSIBsCompleteMethodMarshalAPERFreshValue(v *PosSIBsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgePosSIBsCompleteMethodMarshalAPERLegacy(v *PosSIBsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePosSIBsCompleteMethodMarshalAPERPlanned(v *PosSIBsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgePosSIBsCompleteMethodUnmarshalAPERLegacy(v *PosSIBsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePosSIBsCompleteMethodUnmarshalAPERWithOptions(v *PosSIBsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultGERANCompleteFieldPerPadding(v *ResultGERANComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeResultGERANCompleteFieldReceived(v *ResultGERANComplete) *bool { return &v.received }
func BridgeResultGERANCompleteFieldReceivedBytes(v *ResultGERANComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeResultGERANCompleteFieldReplay(v *ResultGERANComplete) *aper.Snapshot { return &v.replay }
func BridgeResultGERANCompleteFieldStream(v *ResultGERANComplete) *aper.WireSpan { return &v.stream }
func BridgeResultGERANCompleteFieldWithoutReplay(v *ResultGERANComplete) *bool {
	return &v.withoutReplay
}
func BridgeResultGERANCompleteMethodMarshalAPERBudget(v *ResultGERANComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultGERANCompleteMethodMarshalAPERChanged(v *ResultGERANComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultGERANCompleteMethodMarshalAPERChangedValue(v *ResultGERANComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultGERANCompleteMethodMarshalAPERFreshValue(v *ResultGERANComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultGERANCompleteMethodMarshalAPERLegacy(v *ResultGERANComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultGERANCompleteMethodMarshalAPERPlanned(v *ResultGERANComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultGERANCompleteMethodUnmarshalAPERLegacy(v *ResultGERANComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultGERANCompleteMethodUnmarshalAPERWithOptions(v *ResultGERANComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultNRAPERValueFieldContext(v *ResultNRAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultNRAPERValueFieldReceived(v *ResultNRAPERValue) *aper.WireSpan { return &v.received }
func BridgeResultNRAPERValueFieldReplay(v *ResultNRAPERValue) *aper.Snapshot   { return &v.replay }
func BridgeResultNRAPERValueFieldWithoutReplay(v *ResultNRAPERValue) *bool     { return &v.withoutReplay }
func BridgeResultNRItemAPERValueFieldContext(v *ResultNRItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultNRItemAPERValueFieldReceived(v *ResultNRItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResultNRItemAPERValueFieldReplay(v *ResultNRItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResultNRItemAPERValueFieldWithoutReplay(v *ResultNRItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultNRItemExtIETableMethodInfoNRCGI(v ResultNRItemExtIETable) s00.FieldInfo {
	return v.infoNRCGI()
}
func BridgeResultNRItemExtIETableMethodInfoResultsPerSSBIndexList(v ResultNRItemExtIETable) s00.FieldInfo {
	return v.infoResultsPerSSBIndexList()
}
func BridgeResultNRItemExtIEsExtFieldFieldReceived(v *ResultNRItemExtIEsExtField) *aper.CompletePadding {
	return &v.received
}
func BridgeResultNRItemExtIEsExtFieldFieldReplay(v *ResultNRItemExtIEsExtField) *aper.Snapshot {
	return &v.replay
}
func BridgeResultNRItemExtIEsExtFieldFieldStream(v *ResultNRItemExtIEsExtField) *aper.WireSpan {
	return &v.stream
}
func BridgeResultNRItemExtIEsExtFieldFieldWithoutReplay(v *ResultNRItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeResultNRItemExtIEsExtFieldMethodMarshalAPERTo(v *ResultNRItemExtIEsExtField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultNRItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ResultNRItemExtIEsExtField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultNRItemExtIEsIEFieldFieldReceived(v *ResultNRItemExtIEsIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeResultNRItemExtIEsIEFieldFieldReplay(v *ResultNRItemExtIEsIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeResultNRItemExtIEsIEFieldFieldStream(v *ResultNRItemExtIEsIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeResultNRItemExtIEsIEFieldFieldWithoutReplay(v *ResultNRItemExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeResultNRItemExtIEsIEFieldMethodMarshalAPERTo(v *ResultNRItemExtIEsIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultNRItemExtIEsIEFieldMethodUnmarshalAPERFrom(v *ResultNRItemExtIEsIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultNRItemExtIEsNRCGIExtBindingFieldCodec(v *ResultNRItemExtIEsNRCGIExtBinding) *s07.NRCGIValueCodec {
	return &v.codec
}
func BridgeResultNRItemExtIEsNRCGIExtBindingFieldGet(v *ResultNRItemExtIEsNRCGIExtBinding) *func(*ResultNRItemExtIEsValue) (*s07.NRCGI, bool) {
	return &v.get
}
func BridgeResultNRItemExtIEsNRCGIExtBindingFieldInfo(v *ResultNRItemExtIEsNRCGIExtBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeResultNRItemExtIEsNRCGIExtBindingFieldInject(v *ResultNRItemExtIEsNRCGIExtBinding) *func(s07.NRCGI) ResultNRItemExtIEsValue {
	return &v.inject
}
func BridgeResultNRItemExtIEsResultsPerSSBIndexListExtBindingFieldCodec(v *ResultNRItemExtIEsResultsPerSSBIndexListExtBinding) *s14.ResultsPerSSBIndexListValueCodec {
	return &v.codec
}
func BridgeResultNRItemExtIEsResultsPerSSBIndexListExtBindingFieldGet(v *ResultNRItemExtIEsResultsPerSSBIndexListExtBinding) *func(*ResultNRItemExtIEsValue) (*s14.ResultsPerSSBIndexList, bool) {
	return &v.get
}
func BridgeResultNRItemExtIEsResultsPerSSBIndexListExtBindingFieldInfo(v *ResultNRItemExtIEsResultsPerSSBIndexListExtBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeResultNRItemExtIEsResultsPerSSBIndexListExtBindingFieldInject(v *ResultNRItemExtIEsResultsPerSSBIndexListExtBinding) *func(s14.ResultsPerSSBIndexList) ResultNRItemExtIEsValue {
	return &v.inject
}
func BridgeResultNRItemExtIEsValueFieldId(v *ResultNRItemExtIEsValue) *s00.ProtocolIEID { return &v.id }
func BridgeResultNRItemExtIEsValueFieldIsOpaque(v *ResultNRItemExtIEsValue) *bool       { return &v.isOpaque }
func BridgeResultNRItemExtIEsValueFieldOpaque(v *ResultNRItemExtIEsValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeResultNRItemExtIEsValueFieldReceived(v *ResultNRItemExtIEsValue) *aper.WireSpan {
	return &v.received
}
func BridgeResultNRItemExtIEsValueFieldReplay(v *ResultNRItemExtIEsValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResultNRItemExtIEsValueFieldRowNRCGI(v *ResultNRItemExtIEsValue) **s07.NRCGI {
	return &v.rowNRCGI
}
func BridgeResultNRItemExtIEsValueFieldRowResultsPerSSBIndexList(v *ResultNRItemExtIEsValue) **s14.ResultsPerSSBIndexList {
	return &v.rowResultsPerSSBIndexList
}
func BridgeResultNRItemExtIEsValueFieldWithoutReplay(v *ResultNRItemExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeResultNRItemExtIEsValueMethodCaptureFraming(v ResultNRItemExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeResultNRItemExtIEsValueMethodCaptureSemantics(v ResultNRItemExtIEsValue, a0 aper.SemanticCapture) ResultNRItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeResultNRItemExtIEsValueMethodCaptureSnapshot(v ResultNRItemExtIEsValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeResultNRItemExtIEsValueMethodCompareSemantics(v ResultNRItemExtIEsValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeResultNRItemExtIEsValueMethodDecode(v ResultNRItemExtIEsValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ResultNRItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeResultNRItemExtIEsValueMethodEncode(v ResultNRItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeResultNRItemExtIEsValueMethodEncodeFresh(v ResultNRItemExtIEsValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeResultNRItemExtIEsValueMethodMatchesID(v ResultNRItemExtIEsValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeResultNRItemExtIEsValueMethodReason(v ResultNRItemExtIEsValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeResultNRItemExtIEsValueMethodRule(v ResultNRItemExtIEsValue) aper.SourceRule {
	return v.rule()
}
func BridgeResultNRItemFieldExtCount(v *ResultNRItem) *int64                { return &v.extCount }
func BridgeResultNRItemFieldExtData(v *ResultNRItem) *[][]byte              { return &v.extData }
func BridgeResultNRItemFieldExtOrigin(v *ResultNRItem) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeResultNRItemFieldExtPresent(v *ResultNRItem) *[]bool             { return &v.extPresent }
func BridgeResultNRItemFieldExtWire(v *ResultNRItem) *[]aper.WireSpan       { return &v.extWire }
func BridgeResultNRItemFieldIEExtensionsIndef(v *ResultNRItem) *bool        { return &v.iEExtensionsIndef }
func BridgeResultNRItemFieldPerExtPadding(v *ResultNRItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeResultNRItemFieldPerPadding(v *ResultNRItem) *aper.FinalPadding { return &v.perPadding }
func BridgeResultNRItemFieldReceived(v *ResultNRItem) *bool                { return &v.received }
func BridgeResultNRItemFieldReceivedBytes(v *ResultNRItem) *aper.WireSpan  { return &v.receivedBytes }
func BridgeResultNRItemFieldReplay(v *ResultNRItem) *aper.Snapshot         { return &v.replay }
func BridgeResultNRItemFieldStream(v *ResultNRItem) *aper.WireSpan         { return &v.stream }
func BridgeResultNRItemFieldWithoutReplay(v *ResultNRItem) *bool           { return &v.withoutReplay }
func BridgeResultNRItemMethodMarshalAPERBudget(v *ResultNRItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultNRItemMethodMarshalAPERChanged(v *ResultNRItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultNRItemMethodMarshalAPERChangedValue(v *ResultNRItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultNRItemMethodMarshalAPERFreshValue(v *ResultNRItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultNRItemMethodMarshalAPERLegacy(v *ResultNRItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultNRItemMethodMarshalAPERPlanned(v *ResultNRItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultNRItemMethodMarshalAPERTo(v *ResultNRItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultNRItemMethodUnmarshalAPERFrom(v *ResultNRItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultNRItemMethodUnmarshalAPERLegacy(v *ResultNRItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultNRItemMethodUnmarshalAPERWithOptions(v *ResultNRItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultNRItemValueCodecFieldCapture(v *ResultNRItemValueCodec) *func(ResultNRItem, aper.DecodeState) (ResultNRItem, aper.Snapshot) {
	return &v.capture
}
func BridgeResultNRItemValueCodecFieldCompare(v *ResultNRItemValueCodec) *func(ResultNRItem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeResultNRItemValueCodecFieldContext(v *ResultNRItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultNRItemValueCodecFieldDecode(v *ResultNRItemValueCodec) *func([]byte, aper.DecodeState) (ResultNRItem, error) {
	return &v.decode
}
func BridgeResultNRItemValueCodecFieldEncode(v *ResultNRItemValueCodec) *func(ResultNRItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultNRItemValueCodecFieldPath(v *ResultNRItemValueCodec) *aper.Path { return &v.path }
func BridgeResultNRItemValueCodecMethodEncodeBudget(v ResultNRItemValueCodec, a0 ResultNRItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultNRItemValueCodecMethodEncodeChanged(v ResultNRItemValueCodec, a0 ResultNRItem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultNRValueCodecFieldCapture(v *ResultNRValueCodec) *func(ResultNR, aper.DecodeState) (ResultNR, aper.Snapshot) {
	return &v.capture
}
func BridgeResultNRValueCodecFieldCompare(v *ResultNRValueCodec) *func(ResultNR, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeResultNRValueCodecFieldContext(v *ResultNRValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultNRValueCodecFieldDecode(v *ResultNRValueCodec) *func([]byte, aper.DecodeState) (ResultNR, error) {
	return &v.decode
}
func BridgeResultNRValueCodecFieldEncode(v *ResultNRValueCodec) *func(ResultNR, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultNRValueCodecFieldPath(v *ResultNRValueCodec) *aper.Path { return &v.path }
func BridgeResultNRValueCodecMethodEncodeBudget(v ResultNRValueCodec, a0 ResultNR, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultNRValueCodecMethodEncodeChanged(v ResultNRValueCodec, a0 ResultNR, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultRSRPCompleteFieldPerPadding(v *ResultRSRPComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeResultRSRPCompleteFieldReceived(v *ResultRSRPComplete) *bool { return &v.received }
func BridgeResultRSRPCompleteFieldReceivedBytes(v *ResultRSRPComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeResultRSRPCompleteFieldReplay(v *ResultRSRPComplete) *aper.Snapshot { return &v.replay }
func BridgeResultRSRPCompleteFieldStream(v *ResultRSRPComplete) *aper.WireSpan { return &v.stream }
func BridgeResultRSRPCompleteFieldWithoutReplay(v *ResultRSRPComplete) *bool   { return &v.withoutReplay }
func BridgeResultRSRPCompleteMethodMarshalAPERBudget(v *ResultRSRPComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultRSRPCompleteMethodMarshalAPERChanged(v *ResultRSRPComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultRSRPCompleteMethodMarshalAPERChangedValue(v *ResultRSRPComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultRSRPCompleteMethodMarshalAPERFreshValue(v *ResultRSRPComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultRSRPCompleteMethodMarshalAPERLegacy(v *ResultRSRPComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultRSRPCompleteMethodMarshalAPERPlanned(v *ResultRSRPComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultRSRPCompleteMethodUnmarshalAPERLegacy(v *ResultRSRPComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultRSRPCompleteMethodUnmarshalAPERWithOptions(v *ResultRSRPComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultRSRQCompleteFieldPerPadding(v *ResultRSRQComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeResultRSRQCompleteFieldReceived(v *ResultRSRQComplete) *bool { return &v.received }
func BridgeResultRSRQCompleteFieldReceivedBytes(v *ResultRSRQComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeResultRSRQCompleteFieldReplay(v *ResultRSRQComplete) *aper.Snapshot { return &v.replay }
func BridgeResultRSRQCompleteFieldStream(v *ResultRSRQComplete) *aper.WireSpan { return &v.stream }
func BridgeResultRSRQCompleteFieldWithoutReplay(v *ResultRSRQComplete) *bool   { return &v.withoutReplay }
func BridgeResultRSRQCompleteMethodMarshalAPERBudget(v *ResultRSRQComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultRSRQCompleteMethodMarshalAPERChanged(v *ResultRSRQComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultRSRQCompleteMethodMarshalAPERChangedValue(v *ResultRSRQComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultRSRQCompleteMethodMarshalAPERFreshValue(v *ResultRSRQComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultRSRQCompleteMethodMarshalAPERLegacy(v *ResultRSRQComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultRSRQCompleteMethodMarshalAPERPlanned(v *ResultRSRQComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultRSRQCompleteMethodUnmarshalAPERLegacy(v *ResultRSRQComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultRSRQCompleteMethodUnmarshalAPERWithOptions(v *ResultRSRQComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultUTRANCompleteFieldPerPadding(v *ResultUTRANComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeResultUTRANCompleteFieldReceived(v *ResultUTRANComplete) *bool { return &v.received }
func BridgeResultUTRANCompleteFieldReceivedBytes(v *ResultUTRANComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeResultUTRANCompleteFieldReplay(v *ResultUTRANComplete) *aper.Snapshot { return &v.replay }
func BridgeResultUTRANCompleteFieldStream(v *ResultUTRANComplete) *aper.WireSpan { return &v.stream }
func BridgeResultUTRANCompleteFieldWithoutReplay(v *ResultUTRANComplete) *bool {
	return &v.withoutReplay
}
func BridgeResultUTRANCompleteMethodMarshalAPERBudget(v *ResultUTRANComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultUTRANCompleteMethodMarshalAPERChanged(v *ResultUTRANComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultUTRANCompleteMethodMarshalAPERChangedValue(v *ResultUTRANComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultUTRANCompleteMethodMarshalAPERFreshValue(v *ResultUTRANComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultUTRANCompleteMethodMarshalAPERLegacy(v *ResultUTRANComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultUTRANCompleteMethodMarshalAPERPlanned(v *ResultUTRANComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultUTRANCompleteMethodUnmarshalAPERLegacy(v *ResultUTRANComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultUTRANCompleteMethodUnmarshalAPERWithOptions(v *ResultUTRANComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultsPerSSBIndexListCompleteFieldPerPadding(v *ResultsPerSSBIndexListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeResultsPerSSBIndexListCompleteFieldReceived(v *ResultsPerSSBIndexListComplete) *bool {
	return &v.received
}
func BridgeResultsPerSSBIndexListCompleteFieldReceivedBytes(v *ResultsPerSSBIndexListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeResultsPerSSBIndexListCompleteFieldReplay(v *ResultsPerSSBIndexListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeResultsPerSSBIndexListCompleteFieldStream(v *ResultsPerSSBIndexListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeResultsPerSSBIndexListCompleteFieldWithoutReplay(v *ResultsPerSSBIndexListComplete) *bool {
	return &v.withoutReplay
}
func BridgeResultsPerSSBIndexListCompleteMethodMarshalAPERBudget(v *ResultsPerSSBIndexListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultsPerSSBIndexListCompleteMethodMarshalAPERChanged(v *ResultsPerSSBIndexListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultsPerSSBIndexListCompleteMethodMarshalAPERChangedValue(v *ResultsPerSSBIndexListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultsPerSSBIndexListCompleteMethodMarshalAPERFreshValue(v *ResultsPerSSBIndexListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultsPerSSBIndexListCompleteMethodMarshalAPERLegacy(v *ResultsPerSSBIndexListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultsPerSSBIndexListCompleteMethodMarshalAPERPlanned(v *ResultsPerSSBIndexListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultsPerSSBIndexListCompleteMethodUnmarshalAPERLegacy(v *ResultsPerSSBIndexListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultsPerSSBIndexListCompleteMethodUnmarshalAPERWithOptions(v *ResultsPerSSBIndexListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
