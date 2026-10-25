// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s20 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s20

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s12"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s14"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s15"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s19"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

func NewPrivateMessage(fields s08.PrivateMessageIEsValuePrivateIEContainer, options ...aper.BuildOption) (s12.PrivateMessage, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s12.PrivateMessage{}, aper.OperationError(err, "PrivateMessage")
	}
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s08.PrivateMessageIEsValuePrivateIEField](bb, uint64(len(fields))); err != nil {
		return s12.PrivateMessage{}, aper.OperationError(err, "PrivateMessage")
	}
	v := s12.PrivateMessage{PrivateIEs: append(s08.PrivateMessageIEsValuePrivateIEContainer(nil), fields...)}
	report, err := BridgeValidatePrivateMessageBudget(&v, budget)
	if err != nil {
		return s12.PrivateMessage{}, aper.OperationError(err, "PrivateMessage")
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		return s12.PrivateMessage{}, aper.OperationError(*s09.BridgeValidationReportFieldErr(&report), "PrivateMessage")
	}
	if issues := s09.BridgeBuildBlockingIssues(report); len(issues) != 0 {
		return s12.PrivateMessage{}, aper.OperationError(&s09.BuildError{Issues: issues}, "PrivateMessage")
	}
	if _, err := s12.BridgePrivateMessageMethodMarshalAPERBudget(&v, budget, false); err != nil {
		return s12.PrivateMessage{}, aper.OperationError(fmt.Errorf("%s %w", "PrivateMessage.privateIEs:", err), "PrivateMessage")
	}
	return v, aper.OperationError(nil, "PrivateMessage")
}

// WLANMeasurementQuantitiesItemIEValueProtocolIESingleContainer is the concrete ProtocolIESingleContainer[WLANMeasurementQuantitiesItemIEValue].
type WLANMeasurementQuantitiesItemIEValueProtocolIESingleContainer = WLANMeasurementQuantitiesItemIEField

func BridgeWLANMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIESingleContainer(v *WLANMeasurementQuantitiesItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	BridgeWLANMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIEField(v, s)
}
func BridgeWLANMeasurementQuantitiesItemIEValueCompareLPPaProtocolIESingleContainer(v *WLANMeasurementQuantitiesItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	BridgeWLANMeasurementQuantitiesItemIEValueCompareLPPaProtocolIEField(v, s)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s04.WLANMeasurementQuantitiesValueExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeWLANMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionContainer(v *s04.WLANMeasurementQuantitiesValueExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeWLANMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}

// WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding is the concrete IEBinding[WLANMeasurementQuantitiesItem, WLANMeasurementQuantitiesItemIEValue].
type WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding struct {
	info   s00.FieldInfo
	codec  WLANMeasurementQuantitiesItemValueCodec
	inject func(WLANMeasurementQuantitiesItem,

	) WLANMeasurementQuantitiesItemIEValue

	get func(*WLANMeasurementQuantitiesItemIEValue,

	) (*WLANMeasurementQuantitiesItem,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete APER codec for this binding's value type.
func (b WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding) Codec() WLANMeasurementQuantitiesItemValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding) New(value WLANMeasurementQuantitiesItem,

) (WLANMeasurementQuantitiesItemIEField, error) {
	if b.inject == nil {
		return WLANMeasurementQuantitiesItemIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WLANMeasurementQuantitiesItemIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return WLANMeasurementQuantitiesItemIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return WLANMeasurementQuantitiesItemIEField{}, aper.OperationError(err, "Value.New")
	}
	return WLANMeasurementQuantitiesItemIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding) Get(field *WLANMeasurementQuantitiesItemIEField) (*WLANMeasurementQuantitiesItem,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WLANMeasurementQuantitiesItemValueCodec is the concrete ValueCodec[WLANMeasurementQuantitiesItem].
type WLANMeasurementQuantitiesItemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(WLANMeasurementQuantitiesItem, aper.DecodeState,

	) (WLANMeasurementQuantitiesItem, aper.Snapshot,

	)
	compare func(WLANMeasurementQuantitiesItem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (WLANMeasurementQuantitiesItem,

		error)
	encode func(WLANMeasurementQuantitiesItem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c WLANMeasurementQuantitiesItemValueCodec) New(value WLANMeasurementQuantitiesItem,

) (WLANMeasurementQuantitiesItemAPERValue, error) {
	if c.encode == nil {
		return WLANMeasurementQuantitiesItemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WLANMeasurementQuantitiesItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANMeasurementQuantitiesItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return WLANMeasurementQuantitiesItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c WLANMeasurementQuantitiesItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WLANMeasurementQuantitiesItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANMeasurementQuantitiesItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return WLANMeasurementQuantitiesItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANMeasurementQuantitiesItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return WLANMeasurementQuantitiesItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return WLANMeasurementQuantitiesItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c WLANMeasurementQuantitiesItemValueCodec) EncodeAPER(value WLANMeasurementQuantitiesItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c WLANMeasurementQuantitiesItemValueCodec) encodeBudget(value WLANMeasurementQuantitiesItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANMeasurementQuantitiesItemValueCodec) encodeChanged(value WLANMeasurementQuantitiesItem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// WLANMeasurementQuantitiesItemIEField is the concrete ProtocolIEField[WLANMeasurementQuantitiesItemIEValue].
type WLANMeasurementQuantitiesItemIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         WLANMeasurementQuantitiesItemIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v WLANMeasurementQuantitiesItemIEField) WithoutReplay() WLANMeasurementQuantitiesItemIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *WLANMeasurementQuantitiesItemIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *WLANMeasurementQuantitiesItemIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *WLANMeasurementQuantitiesItemIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WLANMeasurementQuantitiesItemIEField{}
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
	var zero WLANMeasurementQuantitiesItemIEValue

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

// WLANMeasurementQuantitiesConcreteValueCodec is the concrete ValueCodec[WLANMeasurementQuantities].
type WLANMeasurementQuantitiesConcreteValueCodec struct {
	context s00.BridgeCodecContext
	capture func(WLANMeasurementQuantities, aper.DecodeState,

	) (WLANMeasurementQuantities, aper.Snapshot,

	)
	compare func(WLANMeasurementQuantities, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (WLANMeasurementQuantities,

		error)
	encode func(WLANMeasurementQuantities,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c WLANMeasurementQuantitiesConcreteValueCodec) New(value WLANMeasurementQuantities,

) (WLANMeasurementQuantitiesAPERValue, error) {
	if c.encode == nil {
		return WLANMeasurementQuantitiesAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WLANMeasurementQuantitiesAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANMeasurementQuantitiesAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return WLANMeasurementQuantitiesAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c WLANMeasurementQuantitiesConcreteValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WLANMeasurementQuantitiesAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANMeasurementQuantitiesAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return WLANMeasurementQuantitiesAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANMeasurementQuantitiesAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return WLANMeasurementQuantitiesAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return WLANMeasurementQuantitiesAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c WLANMeasurementQuantitiesConcreteValueCodec) EncodeAPER(value WLANMeasurementQuantitiesAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c WLANMeasurementQuantitiesConcreteValueCodec) encodeBudget(value WLANMeasurementQuantities,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANMeasurementQuantitiesConcreteValueCodec) encodeChanged(value WLANMeasurementQuantities,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// InterRATMeasurementResultValueCodec is the concrete ValueCodec[InterRATMeasurementResult].
type InterRATMeasurementResultValueCodec struct {
	context s00.BridgeCodecContext
	capture func(InterRATMeasurementResult, aper.DecodeState,

	) (InterRATMeasurementResult, aper.Snapshot,

	)
	compare func(InterRATMeasurementResult, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (InterRATMeasurementResult,

		error)
	encode func(InterRATMeasurementResult,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c InterRATMeasurementResultValueCodec) New(value InterRATMeasurementResult,

) (InterRATMeasurementResultAPERValue, error) {
	if c.encode == nil {
		return InterRATMeasurementResultAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InterRATMeasurementResultAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InterRATMeasurementResultAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return InterRATMeasurementResultAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c InterRATMeasurementResultValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InterRATMeasurementResultAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return InterRATMeasurementResultAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return InterRATMeasurementResultAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return InterRATMeasurementResultAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return InterRATMeasurementResultAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return InterRATMeasurementResultAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c InterRATMeasurementResultValueCodec) EncodeAPER(value InterRATMeasurementResultAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c InterRATMeasurementResultValueCodec) encodeBudget(value InterRATMeasurementResult,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c InterRATMeasurementResultValueCodec) encodeChanged(value InterRATMeasurementResult,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// InterRATMeasuredResultsValueValueCodec is the concrete ValueCodec[InterRATMeasuredResultsValue].
type InterRATMeasuredResultsValueValueCodec struct {
	context s00.BridgeCodecContext
	capture func(InterRATMeasuredResultsValue, aper.DecodeState,

	) (InterRATMeasuredResultsValue, aper.Snapshot,

	)
	compare func(InterRATMeasuredResultsValue, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (InterRATMeasuredResultsValue,

		error)
	encode func(InterRATMeasuredResultsValue,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c InterRATMeasuredResultsValueValueCodec) New(value InterRATMeasuredResultsValue,

) (InterRATMeasuredResultsValueAPERValue, error) {
	if c.encode == nil {
		return InterRATMeasuredResultsValueAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InterRATMeasuredResultsValueAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InterRATMeasuredResultsValueAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return InterRATMeasuredResultsValueAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c InterRATMeasuredResultsValueValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InterRATMeasuredResultsValueAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return InterRATMeasuredResultsValueAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return InterRATMeasuredResultsValueAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return InterRATMeasuredResultsValueAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return InterRATMeasuredResultsValueAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return InterRATMeasuredResultsValueAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c InterRATMeasuredResultsValueValueCodec) EncodeAPER(value InterRATMeasuredResultsValueAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c InterRATMeasuredResultsValueValueCodec) encodeBudget(value InterRATMeasuredResultsValue,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c InterRATMeasuredResultsValueValueCodec) encodeChanged(value InterRATMeasuredResultsValue,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}
func BridgeResultNRItemExtIEsValueValidateLPPaExtensionContainer(fields s19.ResultNRItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s19.ResultNRItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s19.ResultNRItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeResultNRItemExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// WLANMeasurementQuantitiesItemIEContainer is the concrete ProtocolIEContainer[WLANMeasurementQuantitiesItemIEValue].
type WLANMeasurementQuantitiesItemIEContainer []WLANMeasurementQuantitiesItemIEField

// resultNRItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ResultNRItemExtIEsValue].
type ResultNRItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s19.ResultNRItemExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s19.ResultNRItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeWLANMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIEField(v *WLANMeasurementQuantitiesItemIEField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(v.Value.captureFraming())
	v.Value = v.Value.captureSemantics(*s)
	s.Child(v.Value.captureSnapshot())
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeWLANMeasurementQuantitiesItemIEValueCompareLPPaProtocolIEField(v *WLANMeasurementQuantitiesItemIEField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionField(v *s04.WLANMeasurementQuantitiesValueExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s04.BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s03.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s03.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s03.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s04.BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldFieldReplay(v), *s04.BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeWLANMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionField(v *s04.WLANMeasurementQuantitiesValueExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s03.BridgeWLANMeasurementQuantitiesValueExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s04.BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldFieldReplay(v), *s04.BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldFieldWithoutReplay(v))
}

// WLANMeasurementQuantitiesItemAPERValue is the concrete APERValue[WLANMeasurementQuantitiesItem].
type WLANMeasurementQuantitiesItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   WLANMeasurementQuantitiesItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v WLANMeasurementQuantitiesItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v WLANMeasurementQuantitiesItemAPERValue) WithoutReplay() WLANMeasurementQuantitiesItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WLANMeasurementQuantitiesAPERValue is the concrete APERValue[WLANMeasurementQuantities].
type WLANMeasurementQuantitiesAPERValue struct {
	context s00.BridgeCodecContext
	Value   WLANMeasurementQuantities

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v WLANMeasurementQuantitiesAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v WLANMeasurementQuantitiesAPERValue) WithoutReplay() WLANMeasurementQuantitiesAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InterRATMeasurementResultAPERValue is the concrete APERValue[InterRATMeasurementResult].
type InterRATMeasurementResultAPERValue struct {
	context s00.BridgeCodecContext
	Value   InterRATMeasurementResult

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v InterRATMeasurementResultAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v InterRATMeasurementResultAPERValue) WithoutReplay() InterRATMeasurementResultAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
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

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeResultNRItemExtIEsValueValidateLPPaIEContainer(fields s19.ResultNRItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s09.ValidationReport {
	report := func() s09.ValidationReport {
		sealed := s09.ValidationReport{Complete: true}
		*s09.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s09.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s09.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !s19.BridgeResultNRItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s19.BridgeResultNRItemExtIEsValueMethodRule(field.Value)
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		aper.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row s00.FieldInfo
			related := []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s05.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.NotAllowed), RelatedRules: s05.BridgeLppaHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s05.BridgeLppaValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s05.BridgeLppaValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s05.BridgeLppaAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s09.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s09.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

type InterRATMeasurementResult = []InterRATMeasuredResultsValue

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
	ResultNR           s19.ResultNR          `json:"ResultNR,omitzero"`
}

// NewInterRATMeasuredResultsValueResultGERAN creates a InterRATMeasuredResultsValue with the resultGERAN alternative.
func BridgeNewInterRATMeasuredResultsValueResultGERANLegacy(v s12.ResultGERAN) InterRATMeasuredResultsValue {
	return InterRATMeasuredResultsValue{
		Choice:      s00.InterRATMeasuredResultsValueChoiceResultGERAN,
		ResultGERAN: v,
	}
}

// NewInterRATMeasuredResultsValueResultUTRAN creates a InterRATMeasuredResultsValue with the resultUTRAN alternative.
func BridgeNewInterRATMeasuredResultsValueResultUTRANLegacy(v s14.ResultUTRAN) InterRATMeasuredResultsValue {
	return InterRATMeasuredResultsValue{
		Choice:      s00.InterRATMeasuredResultsValueChoiceResultUTRAN,
		ResultUTRAN: v,
	}
}

// NewInterRATMeasuredResultsValueResultNR creates a InterRATMeasuredResultsValue with the resultNR alternative.
func BridgeNewInterRATMeasuredResultsValueResultNRLegacy(v s19.ResultNR) InterRATMeasuredResultsValue {
	return InterRATMeasuredResultsValue{
		Choice:   s00.InterRATMeasuredResultsValueChoiceResultNR,
		ResultNR: v,
	}
}

type WLANMeasurementQuantities = []WLANMeasurementQuantitiesItemIEValueProtocolIESingleContainer

// WLANMeasurementQuantitiesItem represents the ASN.1 type WLANMeasurementQuantities-Item (SEQUENCE).
type WLANMeasurementQuantitiesItem struct {
	replay                         aper.Snapshot
	stream                         aper.WireSpan
	withoutReplay                  bool
	received                       bool
	receivedBytes                  aper.WireSpan
	WLANMeasurementQuantitiesValue s00.WLANMeasurementQuantitiesValue                   `asn1:"tag:0,context,implicit"`
	IEExtensions                   s04.WLANMeasurementQuantitiesValueExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef              bool                                                 `asn1:"-" json:"-"`
	extCount                       int64                                                `asn1:"-" json:"-"`
	extPresent                     []bool                                               `asn1:"-" json:"-"`
	extData                        [][]byte                                             `asn1:"-" json:"-"`
	perPadding                     aper.FinalPadding                                    `asn1:"-" json:"-"`
	perExtPadding                  []aper.CompletePadding                               `asn1:"-" json:"-"`
	extOrigin                      []aper.OpaqueOrigin
	extWire                        []aper.WireSpan
}
type BridgeAsn1cAPERInterRATMeasurementResultListValue struct{ Value InterRATMeasurementResult }

// InterRATMeasurementResultComplete carries a complete InterRATMeasurementResult encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type InterRATMeasurementResultComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         InterRATMeasurementResult
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *InterRATMeasurementResultComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := BridgeMarshalAPERInterRATMeasurementResultTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes InterRATMeasurementResult from APER format.
func (v *InterRATMeasurementResultComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes InterRATMeasurementResult with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *InterRATMeasurementResultComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasurementResult")
	}
	bb.EnterComponent("InterRATMeasurementResult")
	value, err := BridgeUnmarshalAPERInterRATMeasurementResultFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasurementResult")
	}
	padding, err := aper.CaptureFinalBits(bb, "InterRATMeasurementResult")
	if err != nil {
		return runtime.WrapDecodePath(err, "InterRATMeasurementResult")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERInterRATMeasurementResult encodes a InterRATMeasurementResult list to APER.
func BridgeMarshalAPERInterRATMeasurementResult(list InterRATMeasurementResultComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// MarshalAPERInterRATMeasurementResultTo appends a InterRATMeasurementResult list to bb.
func BridgeMarshalAPERInterRATMeasurementResultTo(list InterRATMeasurementResult, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERInterRATMeasurementResultListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERInterRATMeasurementResult decodes a InterRATMeasurementResult list from APER.
func BridgeUnmarshalAPERInterRATMeasurementResult(data []byte) (InterRATMeasurementResultComplete, error) {
	var value InterRATMeasurementResultComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERInterRATMeasurementResultFrom decodes a InterRATMeasurementResult list from bb.
func BridgeUnmarshalAPERInterRATMeasurementResultFrom(bb *aper.BitBuffer) (InterRATMeasurementResult, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v BridgeAsn1cAPERInterRATMeasurementResultListValue
	if err := BridgeUnmarshalAPERInterRATMeasurementResultInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERInterRATMeasurementResultInto(v *BridgeAsn1cAPERInterRATMeasurementResultListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(InterRATMeasurementResult, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem InterRATMeasuredResultsValue
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
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
					if err := s19.BridgeResultNRItemMethodMarshalAPERTo(&elem, inner, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPERWithOptions decodes InterRATMeasuredResultsValue with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
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
			tmp_resultnr := make(s19.ResultNR, 0)
			_, errCollection_resultnr := aper.DecodeCollection(inner, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_resultnr, fragmentLength_resultnr int64) error {
				// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
				if fragmentOffset_resultnr < 0 || fragmentLength_resultnr < 0 || fragmentLength_resultnr > int64(^uint(0)>>1) || fragmentOffset_resultnr > int64(^uint(0)>>1)-fragmentLength_resultnr {
					return fmt.Errorf("collection fragment count out of range")
				}
				for i := int64(0); i < fragmentLength_resultnr; i++ {
					var elem s19.ResultNRItem
					elementMark := inner.EnterIndex(fragmentOffset_resultnr + i)
					if err := s19.BridgeResultNRItemMethodUnmarshalAPERFrom(&elem, inner); err != nil {
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
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
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
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
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

// ResultNRComplete carries a complete ResultNR encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultNRComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s19.ResultNR
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *ResultNRComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := BridgeMarshalAPERResultNRTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ResultNR from APER format.
func (v *ResultNRComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResultNR with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResultNRComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ResultNR")
	}
	bb.EnterComponent("ResultNR")
	value, err := BridgeUnmarshalAPERResultNRFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultNR")
	}
	padding, err := aper.CaptureFinalBits(bb, "ResultNR")
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultNR")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERResultNR encodes a ResultNR list to APER.
func BridgeMarshalAPERResultNR(list ResultNRComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// MarshalAPERResultNRTo appends a ResultNR list to bb.
func BridgeMarshalAPERResultNRTo(list s19.ResultNR, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s19.BridgeAsn1cAPERResultNRListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s19.BridgeResultNRItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERResultNR decodes a ResultNR list from APER.
func BridgeUnmarshalAPERResultNR(data []byte) (ResultNRComplete, error) {
	var value ResultNRComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERResultNRFrom decodes a ResultNR list from bb.
func BridgeUnmarshalAPERResultNRFrom(bb *aper.BitBuffer) (s19.ResultNR, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s19.BridgeAsn1cAPERResultNRListValue
	if err := BridgeUnmarshalAPERResultNRInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERResultNRInto(v *s19.BridgeAsn1cAPERResultNRListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s19.ResultNR, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s19.ResultNRItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s19.BridgeResultNRItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// UnmarshalAPERResultsPerSSBIndexList decodes a ResultsPerSSBIndexList list from APER.
func BridgeUnmarshalAPERResultsPerSSBIndexList(data []byte) (s19.ResultsPerSSBIndexListComplete, error) {
	var value s19.ResultsPerSSBIndexListComplete
	if err := s19.BridgeResultsPerSSBIndexListCompleteMethodUnmarshalAPERLegacy(&value, data); err != nil {
		return value, err
	}
	return value, nil
}

// SRSConfigurationForAllCellsComplete carries a complete SRSConfigurationForAllCells encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type SRSConfigurationForAllCellsComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s09.SRSConfigurationForAllCells
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *SRSConfigurationForAllCellsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s11.BridgeMarshalAPERSRSConfigurationForAllCellsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes SRSConfigurationForAllCells from APER format.
func (v *SRSConfigurationForAllCellsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SRSConfigurationForAllCells with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SRSConfigurationForAllCellsComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SRSConfigurationForAllCells")
	}
	bb.EnterComponent("SRSConfigurationForAllCells")
	value, err := BridgeUnmarshalAPERSRSConfigurationForAllCellsFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "SRSConfigurationForAllCells")
	}
	padding, err := aper.CaptureFinalBits(bb, "SRSConfigurationForAllCells")
	if err != nil {
		return runtime.WrapDecodePath(err, "SRSConfigurationForAllCells")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERSRSConfigurationForAllCells encodes a SRSConfigurationForAllCells list to APER.
func BridgeMarshalAPERSRSConfigurationForAllCells(list SRSConfigurationForAllCellsComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERSRSConfigurationForAllCells decodes a SRSConfigurationForAllCells list from APER.
func BridgeUnmarshalAPERSRSConfigurationForAllCells(data []byte) (SRSConfigurationForAllCellsComplete, error) {
	var value SRSConfigurationForAllCellsComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERSRSConfigurationForAllCellsFrom decodes a SRSConfigurationForAllCells list from bb.
func BridgeUnmarshalAPERSRSConfigurationForAllCellsFrom(bb *aper.BitBuffer) (s09.SRSConfigurationForAllCells, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s09.BridgeAsn1cAPERSRSConfigurationForAllCellsListValue
	if err := BridgeUnmarshalAPERSRSConfigurationForAllCellsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERSRSConfigurationForAllCellsInto(v *s09.BridgeAsn1cAPERSRSConfigurationForAllCellsListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s09.SRSConfigurationForAllCells, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 5, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s09.SRSConfigurationForOneCell
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s09.BridgeSRSConfigurationForOneCellMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// SystemInformationComplete carries a complete SystemInformation encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type SystemInformationComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s14.SystemInformation
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *SystemInformationComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s15.BridgeMarshalAPERSystemInformationTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes SystemInformation from APER format.
func (v *SystemInformationComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SystemInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SystemInformationComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SystemInformation")
	}
	bb.EnterComponent("SystemInformation")
	value, err := BridgeUnmarshalAPERSystemInformationFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "SystemInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "SystemInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "SystemInformation")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERSystemInformation encodes a SystemInformation list to APER.
func BridgeMarshalAPERSystemInformation(list SystemInformationComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERSystemInformation decodes a SystemInformation list from APER.
func BridgeUnmarshalAPERSystemInformation(data []byte) (SystemInformationComplete, error) {
	var value SystemInformationComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERSystemInformationFrom decodes a SystemInformation list from bb.
func BridgeUnmarshalAPERSystemInformationFrom(bb *aper.BitBuffer) (s14.SystemInformation, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s14.BridgeAsn1cAPERSystemInformationListValue
	if err := BridgeUnmarshalAPERSystemInformationInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERSystemInformationInto(v *s14.BridgeAsn1cAPERSystemInformationListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s14.SystemInformation, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem s14.SystemInformationElem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := s14.BridgeSystemInformationElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

type BridgeAsn1cAPERWLANMeasurementQuantitiesListValue struct{ Value WLANMeasurementQuantities }

// WLANMeasurementQuantitiesComplete carries a complete WLANMeasurementQuantities encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type WLANMeasurementQuantitiesComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         WLANMeasurementQuantities
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *WLANMeasurementQuantitiesComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := BridgeMarshalAPERWLANMeasurementQuantitiesTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes WLANMeasurementQuantities from APER format.
func (v *WLANMeasurementQuantitiesComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes WLANMeasurementQuantities with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *WLANMeasurementQuantitiesComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementQuantities")
	}
	bb.EnterComponent("WLANMeasurementQuantities")
	value, err := BridgeUnmarshalAPERWLANMeasurementQuantitiesFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementQuantities")
	}
	padding, err := aper.CaptureFinalBits(bb, "WLANMeasurementQuantities")
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementQuantities")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERWLANMeasurementQuantitiesTo appends a WLANMeasurementQuantities list to bb.
func BridgeMarshalAPERWLANMeasurementQuantitiesTo(list WLANMeasurementQuantities, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERWLANMeasurementQuantitiesListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERWLANMeasurementQuantitiesFrom decodes a WLANMeasurementQuantities list from bb.
func BridgeUnmarshalAPERWLANMeasurementQuantitiesFrom(bb *aper.BitBuffer) (WLANMeasurementQuantities, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v BridgeAsn1cAPERWLANMeasurementQuantitiesListValue
	if err := BridgeUnmarshalAPERWLANMeasurementQuantitiesInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERWLANMeasurementQuantitiesInto(v *BridgeAsn1cAPERWLANMeasurementQuantitiesListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(WLANMeasurementQuantities, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem WLANMeasurementQuantitiesItemIEValueProtocolIESingleContainer
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
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
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// MarshalAPER encodes WLANMeasurementQuantitiesItem to APER format.
func (v *WLANMeasurementQuantitiesItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *WLANMeasurementQuantitiesItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.WLANMeasurementQuantitiesValue), 1, true); err != nil {
		return fmt.Errorf("encoding wLANMeasurementQuantitiesValue: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s04.BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes WLANMeasurementQuantitiesItem from APER format.
func (v *WLANMeasurementQuantitiesItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes WLANMeasurementQuantitiesItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *WLANMeasurementQuantitiesItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementQuantitiesItem")
	}
	bb.EnterComponent("WLANMeasurementQuantitiesItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementQuantitiesItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "WLANMeasurementQuantitiesItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementQuantitiesItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *WLANMeasurementQuantitiesItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WLANMeasurementQuantitiesItem{}
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
	val_wlanmeasurementquantitiesvalue, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "WLANMeasurementQuantitiesValue"})
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementQuantitiesValue")
	}
	v.WLANMeasurementQuantitiesValue = s00.WLANMeasurementQuantitiesValue(val_wlanmeasurementquantitiesvalue)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s04.WLANMeasurementQuantitiesValueExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s04.WLANMeasurementQuantitiesValueExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s04.BridgeWLANMeasurementQuantitiesValueExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// WLANChannelListComplete carries a complete WLANChannelList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type WLANChannelListComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         s00.WLANChannelList
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *WLANChannelListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := s05.BridgeMarshalAPERWLANChannelListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes WLANChannelList from APER format.
func (v *WLANChannelListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes WLANChannelList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *WLANChannelListComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "WLANChannelList")
	}
	bb.EnterComponent("WLANChannelList")
	value, err := BridgeUnmarshalAPERWLANChannelListFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANChannelList")
	}
	padding, err := aper.CaptureFinalBits(bb, "WLANChannelList")
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANChannelList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERWLANChannelList encodes a WLANChannelList list to APER.
func BridgeMarshalAPERWLANChannelList(list WLANChannelListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERWLANChannelList decodes a WLANChannelList list from APER.
func BridgeUnmarshalAPERWLANChannelList(data []byte) (WLANChannelListComplete, error) {
	var value WLANChannelListComplete
	if err := value.unmarshalAPERLegacy(data); err != nil {
		return value, err
	}
	return value, nil
}

// UnmarshalAPERWLANChannelListFrom decodes a WLANChannelList list from bb.
func BridgeUnmarshalAPERWLANChannelListFrom(bb *aper.BitBuffer) (s00.WLANChannelList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v s00.BridgeAsn1cAPERWLANChannelListListValue
	if err := BridgeUnmarshalAPERWLANChannelListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERWLANChannelListInto(v *s00.BridgeAsn1cAPERWLANChannelListListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(s00.WLANChannelList, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_2: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1136
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			val, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false)
			if err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			if next, err := aper.AppendValues(bb, v.Value, s00.WLANChannel(val)); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return runtime.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
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
func (v *InterRATMeasurementResultComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "InterRATMeasurementResultComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InterRATMeasurementResultComplete) WithoutReplay() InterRATMeasurementResultComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero InterRATMeasurementResultComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultNRComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultNRComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultNRComplete) WithoutReplay() ResultNRComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ResultNRComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SRSConfigurationForAllCellsComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "SRSConfigurationForAllCellsComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SRSConfigurationForAllCellsComplete) WithoutReplay() SRSConfigurationForAllCellsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero SRSConfigurationForAllCellsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SystemInformationComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "SystemInformationComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SystemInformationComplete) WithoutReplay() SystemInformationComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero SystemInformationComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WLANChannelListComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "WLANChannelListComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WLANChannelListComplete) WithoutReplay() WLANChannelListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero WLANChannelListComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WLANMeasurementQuantitiesComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "WLANMeasurementQuantitiesComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WLANMeasurementQuantitiesComplete) WithoutReplay() WLANMeasurementQuantitiesComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero WLANMeasurementQuantitiesComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WLANMeasurementQuantitiesItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "WLANMeasurementQuantitiesItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WLANMeasurementQuantitiesItem) WithoutReplay() WLANMeasurementQuantitiesItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero WLANMeasurementQuantitiesItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *WLANMeasurementQuantitiesItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *WLANMeasurementQuantitiesItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("WLANMeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("WLANMeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *WLANMeasurementQuantitiesItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("WLANMeasurementQuantitiesItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("WLANMeasurementQuantitiesItem.Extensions[%d]", index))
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
func (v *InterRATMeasurementResultComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "InterRATMeasurementResultComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "InterRATMeasurementResultComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaInterRATMeasurementResultComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "InterRATMeasurementResultComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "InterRATMeasurementResultComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "InterRATMeasurementResultComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "InterRATMeasurementResultComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "InterRATMeasurementResultComplete")
}
func (v *InterRATMeasurementResultComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *InterRATMeasurementResultComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *InterRATMeasurementResultComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaInterRATMeasurementResultComplete(v, &s)
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
func (v *InterRATMeasurementResultComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *InterRATMeasurementResultComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := BridgeMarshalAPERInterRATMeasurementResultTo(value.Value, bb, fresh); err != nil {
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
func (v *ResultNRComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ResultNRComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ResultNRComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaResultNRComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ResultNRComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ResultNRComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ResultNRComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ResultNRComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ResultNRComplete")
}
func (v *ResultNRComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultNRComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultNRComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaResultNRComplete(v, &s)
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
func (v *ResultNRComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultNRComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := BridgeMarshalAPERResultNRTo(value.Value, bb, fresh); err != nil {
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
func (v *SRSConfigurationForAllCellsComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SRSConfigurationForAllCellsComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "SRSConfigurationForAllCellsComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaSRSConfigurationForAllCellsComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "SRSConfigurationForAllCellsComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "SRSConfigurationForAllCellsComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "SRSConfigurationForAllCellsComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "SRSConfigurationForAllCellsComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "SRSConfigurationForAllCellsComplete")
}
func (v *SRSConfigurationForAllCellsComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *SRSConfigurationForAllCellsComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *SRSConfigurationForAllCellsComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaSRSConfigurationForAllCellsComplete(v, &s)
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
func (v *SRSConfigurationForAllCellsComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *SRSConfigurationForAllCellsComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s11.BridgeMarshalAPERSRSConfigurationForAllCellsTo(value.Value, bb, fresh); err != nil {
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
func (v *SystemInformationComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SystemInformationComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "SystemInformationComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaSystemInformationComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "SystemInformationComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "SystemInformationComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "SystemInformationComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "SystemInformationComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "SystemInformationComplete")
}
func (v *SystemInformationComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *SystemInformationComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *SystemInformationComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaSystemInformationComplete(v, &s)
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
func (v *SystemInformationComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *SystemInformationComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s15.BridgeMarshalAPERSystemInformationTo(value.Value, bb, fresh); err != nil {
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
func (v *WLANChannelListComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "WLANChannelListComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "WLANChannelListComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaWLANChannelListComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "WLANChannelListComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "WLANChannelListComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "WLANChannelListComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "WLANChannelListComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "WLANChannelListComplete")
}
func (v *WLANChannelListComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *WLANChannelListComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *WLANChannelListComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaWLANChannelListComplete(v, &s)
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
func (v *WLANChannelListComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *WLANChannelListComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := s05.BridgeMarshalAPERWLANChannelListTo(value.Value, bb, fresh); err != nil {
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
func (v *WLANMeasurementQuantitiesComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "WLANMeasurementQuantitiesComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "WLANMeasurementQuantitiesComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaWLANMeasurementQuantitiesComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "WLANMeasurementQuantitiesComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "WLANMeasurementQuantitiesComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "WLANMeasurementQuantitiesComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "WLANMeasurementQuantitiesComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "WLANMeasurementQuantitiesComplete")
}
func (v *WLANMeasurementQuantitiesComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *WLANMeasurementQuantitiesComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *WLANMeasurementQuantitiesComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaWLANMeasurementQuantitiesComplete(v, &s)
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
func (v *WLANMeasurementQuantitiesComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *WLANMeasurementQuantitiesComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := BridgeMarshalAPERWLANMeasurementQuantitiesTo(value.Value, bb, fresh); err != nil {
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
func (v *WLANMeasurementQuantitiesItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "WLANMeasurementQuantitiesItem")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "WLANMeasurementQuantitiesItem")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaWLANMeasurementQuantitiesItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "WLANMeasurementQuantitiesItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "WLANMeasurementQuantitiesItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "WLANMeasurementQuantitiesItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "WLANMeasurementQuantitiesItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "WLANMeasurementQuantitiesItem")
}
func (v *WLANMeasurementQuantitiesItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *WLANMeasurementQuantitiesItem) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *WLANMeasurementQuantitiesItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaWLANMeasurementQuantitiesItem(v, &s)
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
func (v *WLANMeasurementQuantitiesItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *WLANMeasurementQuantitiesItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *InterRATMeasurementResultComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "InterRATMeasurementResultComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded InterRATMeasurementResultComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaInterRATMeasurementResultComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = InterRATMeasurementResultComplete{}
		return report, aper.OperationError(err, "InterRATMeasurementResultComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "InterRATMeasurementResultComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultNRComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ResultNRComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ResultNRComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultNRComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ResultNRComplete{}
		return report, aper.OperationError(err, "ResultNRComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ResultNRComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *SRSConfigurationForAllCellsComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SRSConfigurationForAllCellsComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded SRSConfigurationForAllCellsComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaSRSConfigurationForAllCellsComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = SRSConfigurationForAllCellsComplete{}
		return report, aper.OperationError(err, "SRSConfigurationForAllCellsComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SRSConfigurationForAllCellsComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *SystemInformationComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SystemInformationComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded SystemInformationComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaSystemInformationComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = SystemInformationComplete{}
		return report, aper.OperationError(err, "SystemInformationComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SystemInformationComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *WLANChannelListComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "WLANChannelListComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded WLANChannelListComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaWLANChannelListComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = WLANChannelListComplete{}
		return report, aper.OperationError(err, "WLANChannelListComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "WLANChannelListComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *WLANMeasurementQuantitiesComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "WLANMeasurementQuantitiesComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded WLANMeasurementQuantitiesComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaWLANMeasurementQuantitiesComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = WLANMeasurementQuantitiesComplete{}
		return report, aper.OperationError(err, "WLANMeasurementQuantitiesComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "WLANMeasurementQuantitiesComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *WLANMeasurementQuantitiesItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "WLANMeasurementQuantitiesItem")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded WLANMeasurementQuantitiesItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaWLANMeasurementQuantitiesItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = WLANMeasurementQuantitiesItem{}
		return report, aper.OperationError(err, "WLANMeasurementQuantitiesItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "WLANMeasurementQuantitiesItem")
}

// NewInterRATMeasuredResultsValueResultGERAN constructs a checked complete value.
func NewInterRATMeasuredResultsValueResultGERAN(v s12.ResultGERAN, options ...aper.BuildOption) (InterRATMeasuredResultsValue, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InterRATMeasuredResultsValue{}, aper.OperationError(err, "InterRATMeasuredResultsValueResultGERAN")
	}
	value := BridgeNewInterRATMeasuredResultsValueResultGERANLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return InterRATMeasuredResultsValue{}, aper.OperationError(err, "InterRATMeasuredResultsValueResultGERAN")
	}
	return value, aper.OperationError(nil, "InterRATMeasuredResultsValueResultGERAN")
}

// NewInterRATMeasuredResultsValueResultUTRAN constructs a checked complete value.
func NewInterRATMeasuredResultsValueResultUTRAN(v s14.ResultUTRAN, options ...aper.BuildOption) (InterRATMeasuredResultsValue, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InterRATMeasuredResultsValue{}, aper.OperationError(err, "InterRATMeasuredResultsValueResultUTRAN")
	}
	value := BridgeNewInterRATMeasuredResultsValueResultUTRANLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return InterRATMeasuredResultsValue{}, aper.OperationError(err, "InterRATMeasuredResultsValueResultUTRAN")
	}
	return value, aper.OperationError(nil, "InterRATMeasuredResultsValueResultUTRAN")
}

// NewInterRATMeasuredResultsValueResultNR constructs a checked complete value.
func NewInterRATMeasuredResultsValueResultNR(v s19.ResultNR, options ...aper.BuildOption) (InterRATMeasuredResultsValue, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InterRATMeasuredResultsValue{}, aper.OperationError(err, "InterRATMeasuredResultsValueResultNR")
	}
	value := BridgeNewInterRATMeasuredResultsValueResultNRLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return InterRATMeasuredResultsValue{}, aper.OperationError(err, "InterRATMeasuredResultsValueResultNR")
	}
	return value, aper.OperationError(nil, "InterRATMeasuredResultsValueResultNR")
}

// NewInterRATMeasuredResultsValueUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewInterRATMeasuredResultsValueUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (InterRATMeasuredResultsValue, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return InterRATMeasuredResultsValue{}, aper.OperationError(err, "InterRATMeasuredResultsValueUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return InterRATMeasuredResultsValue{}, aper.OperationError(err, "InterRATMeasuredResultsValueUnknownExtension")
	}
	value := InterRATMeasuredResultsValue{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return InterRATMeasuredResultsValue{}, aper.OperationError(err, "InterRATMeasuredResultsValueUnknownExtension")
	}
	return value, aper.OperationError(nil, "InterRATMeasuredResultsValueUnknownExtension")
}

// MarshalAPERInterRATMeasurementResult encodes a complete named list.
func MarshalAPERInterRATMeasurementResult(v InterRATMeasurementResultComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERResultNR encodes a complete named list.
func MarshalAPERResultNR(v ResultNRComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERSRSConfigurationForAllCells encodes a complete named list.
func MarshalAPERSRSConfigurationForAllCells(v SRSConfigurationForAllCellsComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERSystemInformation encodes a complete named list.
func MarshalAPERSystemInformation(v SystemInformationComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERWLANChannelList encodes a complete named list.
func MarshalAPERWLANChannelList(v WLANChannelListComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERInterRATMeasurementResult decodes a complete named list.
func UnmarshalAPERInterRATMeasurementResult(data []byte, options ...aper.DecodeOption) (InterRATMeasurementResultComplete, aper.DecodeReport, error) {
	var v InterRATMeasurementResultComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERResultNR decodes a complete named list.
func UnmarshalAPERResultNR(data []byte, options ...aper.DecodeOption) (ResultNRComplete, aper.DecodeReport, error) {
	var v ResultNRComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERSRSConfigurationForAllCells decodes a complete named list.
func UnmarshalAPERSRSConfigurationForAllCells(data []byte, options ...aper.DecodeOption) (SRSConfigurationForAllCellsComplete, aper.DecodeReport, error) {
	var v SRSConfigurationForAllCellsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERSystemInformation decodes a complete named list.
func UnmarshalAPERSystemInformation(data []byte, options ...aper.DecodeOption) (SystemInformationComplete, aper.DecodeReport, error) {
	var v SystemInformationComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERWLANChannelList decodes a complete named list.
func UnmarshalAPERWLANChannelList(data []byte, options ...aper.DecodeOption) (WLANChannelListComplete, aper.DecodeReport, error) {
	var v WLANChannelListComplete
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
		s19.BridgeCaptureLPPaResultNR(&v.ResultNR, s)
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
		s19.BridgeCompareLPPaResultNR(&v.ResultNR, s)
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaInterRATMeasurementResult(v *InterRATMeasurementResult, s *aper.SemanticCapture) {
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
			BridgeCaptureLPPaInterRATMeasuredResultsValue(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaInterRATMeasurementResult(v *InterRATMeasurementResult, s *aper.SemanticComparison) {
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
			BridgeCompareLPPaInterRATMeasuredResultsValue(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaInterRATMeasurementResultComplete(v *InterRATMeasurementResultComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	BridgeCaptureLPPaInterRATMeasurementResult(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaInterRATMeasurementResultComplete(v *InterRATMeasurementResultComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaInterRATMeasurementResult(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultNRComplete(v *ResultNRComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s19.BridgeCaptureLPPaResultNR(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultNRComplete(v *ResultNRComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s19.BridgeCompareLPPaResultNR(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaSRSConfigurationForAllCellsComplete(v *SRSConfigurationForAllCellsComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s09.BridgeCaptureLPPaSRSConfigurationForAllCells(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaSRSConfigurationForAllCellsComplete(v *SRSConfigurationForAllCellsComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s10.BridgeCompareLPPaSRSConfigurationForAllCells(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaSystemInformationComplete(v *SystemInformationComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s14.BridgeCaptureLPPaSystemInformation(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaSystemInformationComplete(v *SystemInformationComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s14.BridgeCompareLPPaSystemInformation(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaWLANChannelListComplete(v *WLANChannelListComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaWLANChannelList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaWLANChannelListComplete(v *WLANChannelListComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s03.BridgeCompareLPPaWLANChannelList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaWLANMeasurementQuantities(v *WLANMeasurementQuantities, s *aper.SemanticCapture) {
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
			BridgeWLANMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaWLANMeasurementQuantities(v *WLANMeasurementQuantities, s *aper.SemanticComparison) {
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
			BridgeWLANMeasurementQuantitiesItemIEValueCompareLPPaProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaWLANMeasurementQuantitiesComplete(v *WLANMeasurementQuantitiesComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	BridgeCaptureLPPaWLANMeasurementQuantities(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaWLANMeasurementQuantitiesComplete(v *WLANMeasurementQuantitiesComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaWLANMeasurementQuantities(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaWLANMeasurementQuantitiesItem(v *WLANMeasurementQuantitiesItem, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaWLANMeasurementQuantitiesValue(&v.WLANMeasurementQuantitiesValue, s)
	s.Bool(v.IEExtensions == nil)
	BridgeWLANMeasurementQuantitiesValueExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaWLANMeasurementQuantitiesItem(v *WLANMeasurementQuantitiesItem, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s03.BridgeCompareLPPaWLANMeasurementQuantitiesValue(&v.WLANMeasurementQuantitiesValue, s)
	s.Bool(v.IEExtensions == nil)
	BridgeWLANMeasurementQuantitiesValueExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaWLANMeasurementQuantitiesItemIEValue(v *WLANMeasurementQuantitiesItemIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(20):
			{
				f := s.Begin()
				s.Bool(v.rowWLANMeasurementQuantitiesItem == nil)
				if v.rowWLANMeasurementQuantitiesItem != nil {
					BridgeCaptureLPPaWLANMeasurementQuantitiesItem(v.rowWLANMeasurementQuantitiesItem, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v WLANMeasurementQuantitiesItemIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v WLANMeasurementQuantitiesItemIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v WLANMeasurementQuantitiesItemIEValue) captureSemantics(s aper.SemanticCapture) WLANMeasurementQuantitiesItemIEValue {
	BridgeCaptureLPPaWLANMeasurementQuantitiesItemIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaWLANMeasurementQuantitiesItemIEValue(v *WLANMeasurementQuantitiesItemIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(20):
			{
				f := s.Begin()
				s.Bool(v.rowWLANMeasurementQuantitiesItem == nil)
				if v.rowWLANMeasurementQuantitiesItem != nil {
					BridgeCompareLPPaWLANMeasurementQuantitiesItem(v.rowWLANMeasurementQuantitiesItem, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v WLANMeasurementQuantitiesItemIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaWLANMeasurementQuantitiesItemIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v WLANMeasurementQuantitiesItemIEValue) WithoutReplay() WLANMeasurementQuantitiesItemIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}

type WLANMeasurementQuantitiesItemIEValue struct {
	id                               s00.ProtocolIEID
	withoutReplay                    bool
	received                         aper.WireSpan
	replay                           aper.Snapshot
	opaque                           *aper.OpaqueOpenType
	isOpaque                         bool
	rowWLANMeasurementQuantitiesItem *WLANMeasurementQuantitiesItem
}

func (v WLANMeasurementQuantitiesItemIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case s00.ProtocolIEID(20):
		return v.rowWLANMeasurementQuantitiesItem != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *WLANMeasurementQuantitiesItemIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (WLANMeasurementQuantitiesItemIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementQuantities-ItemIEs"}}
}
func (WLANMeasurementQuantitiesItemIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(20):
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

// AsWLANMeasurementQuantitiesItem returns the selected WLANMeasurementQuantitiesItem value and reports whether that alternative is active.
func (v *WLANMeasurementQuantitiesItemIEValue) AsWLANMeasurementQuantitiesItem() (*WLANMeasurementQuantitiesItem, bool) {
	if v == nil || v.id != s00.ProtocolIEID(20) || v.rowWLANMeasurementQuantitiesItem == nil {
		return nil, false
	}
	return v.rowWLANMeasurementQuantitiesItem, true
}
func (v WLANMeasurementQuantitiesItemIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (WLANMeasurementQuantitiesItemIEValue, error) {
	out := WLANMeasurementQuantitiesItemIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 20:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case s00.ProtocolIEID(20):
		replayUsage := scope.Usage()
		var value WLANMeasurementQuantitiesItem
		child := raw.ChildDecodeBuffer()
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "WLANMeasurementQuantitiesItem:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "WLANMeasurementQuantitiesItem")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowWLANMeasurementQuantitiesItem = &value
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
func (v WLANMeasurementQuantitiesItemIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v WLANMeasurementQuantitiesItemIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(20):
		if v.rowWLANMeasurementQuantitiesItem == nil {
			return nil, fmt.Errorf("%s missing value", "WLANMeasurementQuantities-ItemIEs.id-WLANMeasurementQuantities-Item:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := v.rowWLANMeasurementQuantitiesItem.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "WLANMeasurementQuantitiesItemIEValue:", v.id)
	}
}

type WLANMeasurementQuantitiesItemIETable struct{}

func WLANMeasurementQuantitiesItemIEs() WLANMeasurementQuantitiesItemIETable {
	return WLANMeasurementQuantitiesItemIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (WLANMeasurementQuantitiesItemIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementQuantities-ItemIEs"}
		return sealed
	}()
}
func (WLANMeasurementQuantitiesItemIETable) infoWLANMeasurementQuantitiesItem() s00.FieldInfo {
	return s00.FieldInfo{Table: WLANMeasurementQuantitiesItemIEs().ID(), ID: s00.ProtocolIEID(20), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementQuantitiesItem"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementQuantities-ItemIEs", Row: "id-WLANMeasurementQuantities-Item"}}}
}

// WLANMeasurementQuantitiesItem returns the typed binding for the WLANMeasurementQuantitiesItem row of this table.
func (t WLANMeasurementQuantitiesItemIETable) WLANMeasurementQuantitiesItem() WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding {
	return WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding{info: t.infoWLANMeasurementQuantitiesItem(), codec: WLANMeasurementQuantitiesItemValueCodec{path: "WLANMeasurementQuantitiesItem",
		decode: func(data []byte, options aper.DecodeState) (WLANMeasurementQuantitiesItem, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty WLANMeasurementQuantitiesItem
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("WLANMeasurementQuantitiesItem")
			var zero WLANMeasurementQuantitiesItemIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(20), raw)
			if err != nil {
				var empty WLANMeasurementQuantitiesItem
				return empty, err
			}
			value, ok := decoded.AsWLANMeasurementQuantitiesItem()
			if !ok {
				var empty WLANMeasurementQuantitiesItem
				return empty, fmt.Errorf("binding WLANMeasurementQuantities-ItemIEs.id-WLANMeasurementQuantities-Item: no selected value")
			}
			return *value, nil
		},
		encode: func(value WLANMeasurementQuantitiesItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (WLANMeasurementQuantitiesItemIEValue{id: s00.ProtocolIEID(20), rowWLANMeasurementQuantitiesItem: &value}).encodeFresh(fresh, budget)
		}, capture: func(v WLANMeasurementQuantitiesItem, options aper.DecodeState) (WLANMeasurementQuantitiesItem, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureLPPaWLANMeasurementQuantitiesItem(&v, &s)
			var root aper.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v,

				root
		}, compare: func(v WLANMeasurementQuantitiesItem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaWLANMeasurementQuantitiesItem(&v, &s)
			s.End(f, root, false)

			return s.Plan()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WLANMeasurementQuantitiesItem"
			return sealed
		}(),
	}, inject: func(value WLANMeasurementQuantitiesItem) WLANMeasurementQuantitiesItemIEValue {
		return WLANMeasurementQuantitiesItemIEValue{id: s00.ProtocolIEID(20), rowWLANMeasurementQuantitiesItem: &value}
	}, get: func(value *WLANMeasurementQuantitiesItemIEValue) (*WLANMeasurementQuantitiesItem, bool) {
		return value.AsWLANMeasurementQuantitiesItem()
	}}
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t WLANMeasurementQuantitiesItemIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (WLANMeasurementQuantitiesItemIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return WLANMeasurementQuantitiesItemIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(20):
		return WLANMeasurementQuantitiesItemIEField{}, aper.OperationError(fmt.Errorf("known IE id-WLANMeasurementQuantities-Item requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return WLANMeasurementQuantitiesItemIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return WLANMeasurementQuantitiesItemIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return WLANMeasurementQuantitiesItemIEField{}, aper.OperationError(err, "Opaque")
		}
		return WLANMeasurementQuantitiesItemIEField{Id: id, Criticality: criticality, Value: WLANMeasurementQuantitiesItemIEValue{id: id, opaque: retained, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// InterRATMeasuredResultsValueCodec binds the complete source value type.
func InterRATMeasuredResultsValueCodec() InterRATMeasuredResultsValueValueCodec {
	return InterRATMeasuredResultsValueValueCodec{path: "InterRATMeasuredResultsValue", decode: func(data []byte, options aper.DecodeState) (InterRATMeasuredResultsValue, error) {
		var value InterRATMeasuredResultsValue
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return InterRATMeasuredResultsValue{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value InterRATMeasuredResultsValue, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v InterRATMeasuredResultsValue, options aper.DecodeState) (InterRATMeasuredResultsValue, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaInterRATMeasuredResultsValue(&v, &s)
		var root aper.Snapshot

		s.OperationCounts()
		s.End(f, &root, false)
		return v, root

	}, compare: func(v InterRATMeasuredResultsValue, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaInterRATMeasuredResultsValue(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InterRATMeasuredResultsValue"
		return sealed
	}(),
	}
}

// ResultNRCodec binds the complete source value type.
func ResultNRCodec() s19.ResultNRValueCodec {
	return func() s19.ResultNRValueCodec {
		sealed := s19.ResultNRValueCodec{}
		*s19.BridgeResultNRValueCodecFieldPath(&sealed) = "ResultNR"
		*s19.BridgeResultNRValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.ResultNR, error) {
			var complete ResultNRComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s19.ResultNR
				return zero, err
			}
			return complete.Value, nil
		}
		*s19.BridgeResultNRValueCodecFieldEncode(&sealed) = func(value s19.ResultNR, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := ResultNRComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s19.BridgeResultNRValueCodecFieldCapture(&sealed) = func(v s19.ResultNR, options aper.DecodeState) (s19.ResultNR, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s19.BridgeCaptureLPPaResultNR(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s19.BridgeResultNRValueCodecFieldCompare(&sealed) = func(v s19.ResultNR, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s19.BridgeCompareLPPaResultNR(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s19.BridgeResultNRValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ResultNR"
			return sealed
		}()
		return sealed
	}()

}

// SRSConfigurationForAllCellsCodec binds the complete source value type.
func SRSConfigurationForAllCellsCodec() s09.SRSConfigurationForAllCellsValueCodec {
	return func() s09.SRSConfigurationForAllCellsValueCodec {
		sealed := s09.SRSConfigurationForAllCellsValueCodec{}
		*s09.BridgeSRSConfigurationForAllCellsValueCodecFieldPath(&sealed) = "SRSConfigurationForAllCells"
		*s09.BridgeSRSConfigurationForAllCellsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.SRSConfigurationForAllCells, error) {
			var complete SRSConfigurationForAllCellsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s09.SRSConfigurationForAllCells
				return zero, err
			}
			return complete.Value, nil
		}
		*s09.BridgeSRSConfigurationForAllCellsValueCodecFieldEncode(&sealed) = func(value s09.SRSConfigurationForAllCells, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := SRSConfigurationForAllCellsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s09.BridgeSRSConfigurationForAllCellsValueCodecFieldCapture(&sealed) = func(v s09.SRSConfigurationForAllCells, options aper.DecodeState) (s09.SRSConfigurationForAllCells, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s09.BridgeCaptureLPPaSRSConfigurationForAllCells(&v, &s)
			var root aper.Snapshot
			s.
				OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeSRSConfigurationForAllCellsValueCodecFieldCompare(&sealed) = func(v s09.SRSConfigurationForAllCells, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s10.BridgeCompareLPPaSRSConfigurationForAllCells(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s09.BridgeSRSConfigurationForAllCellsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SRSConfigurationForAllCells"
			return sealed
		}()
		return sealed
	}()

}

// SystemInformationCodec binds the complete source value type.
func SystemInformationCodec() s14.SystemInformationValueCodec {
	return func() s14.SystemInformationValueCodec {
		sealed := s14.SystemInformationValueCodec{}
		*s14.BridgeSystemInformationValueCodecFieldPath(&sealed) = "SystemInformation"
		*s14.BridgeSystemInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.SystemInformation, error) {
			var complete SystemInformationComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s14.SystemInformation
				return zero, err
			}
			return complete.Value, nil
		}
		*s14.BridgeSystemInformationValueCodecFieldEncode(&sealed) = func(value s14.SystemInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := SystemInformationComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s14.BridgeSystemInformationValueCodecFieldCapture(&sealed) = func(v s14.SystemInformation, options aper.DecodeState) (s14.SystemInformation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s14.BridgeCaptureLPPaSystemInformation(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root,

				false)
			return v, root
		}
		*s14.BridgeSystemInformationValueCodecFieldCompare(&sealed) = func(v s14.SystemInformation, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s14.BridgeCompareLPPaSystemInformation(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s14.BridgeSystemInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SystemInformation"
			return sealed
		}()
		return sealed
	}()

}

// WLANChannelListCodec binds the complete source value type.
func WLANChannelListCodec() s01.WLANChannelListValueCodec {
	return func() s01.WLANChannelListValueCodec {
		sealed := s01.WLANChannelListValueCodec{}
		*s01.BridgeWLANChannelListValueCodecFieldPath(&sealed) = "WLANChannelList"
		*s01.BridgeWLANChannelListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.WLANChannelList, error) {
			var complete WLANChannelListComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero s00.WLANChannelList
				return zero, err
			}
			return complete.Value, nil
		}
		*s01.BridgeWLANChannelListValueCodecFieldEncode(&sealed) = func(value s00.WLANChannelList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			complete := WLANChannelListComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*s01.BridgeWLANChannelListValueCodecFieldCapture(&sealed) = func(v s00.WLANChannelList, options aper.DecodeState) (s00.WLANChannelList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaWLANChannelList(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeWLANChannelListValueCodecFieldCompare(&sealed) = func(v s00.WLANChannelList, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s03.BridgeCompareLPPaWLANChannelList(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s01.BridgeWLANChannelListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WLANChannelList"
			return sealed
		}()
		return sealed
	}()

}

// WLANMeasurementQuantitiesItemCodec binds the complete APER value type.
func WLANMeasurementQuantitiesItemCodec() WLANMeasurementQuantitiesItemValueCodec {
	return WLANMeasurementQuantitiesItemIEs().WLANMeasurementQuantitiesItem().Codec()
}
func BridgeValidationHasValueMismatch(report s09.ValidationReport) bool {
	for _, issue := range report.Issues {
		if issue.Code == s00.ValueIDMismatch {
			return true
		}
	}
	return false
}
func BridgeValidatePrivateMessageBudget(v *s12.PrivateMessage, budget *aper.DecodeBudget,

) (s09.ValidationReport, error) {
	if v == nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}(), fmt.Errorf("nil PrivateMessage")
	}
	report := func() s09.ValidationReport {
		report := func() s09.ValidationReport {
			sealed := s09.ValidationReport{Complete: false}
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
		s09.BridgeValidationReportMethodAddUnchecked(&report, aper.Location{Path: "PrivateMessage.privateIEs"})
		return report
	}()
	for i, field := range v.PrivateIEs {
		if *s09.BridgeValidationReportFieldErr(&report) != nil {
			return report, *s09.BridgeValidationReportFieldErr(&report)
		}
		if !s08.BridgePrivateMessageIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			id := field.Id
			s09.BridgeValidationReportMethodAddIssue(&report, s09.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("PrivateMessage.privateIEs[%d].id", i))}, PrivateID: &id, Rule: s05.BridgeLppaValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{s08.BridgePrivateMessageIEsValueMethodRule(field.Value)}})
		}
	}
	return report, nil
}
func ValidatePrivateMessage(v *s12.PrivateMessage, options ...aper.ValidationOption) (s09.ValidationReport, error) {
	budget, err := aper.ValidationBudget(options...)
	if err != nil {
		return s09.ValidationReport{}, aper.OperationError(err, "PrivateMessage")
	}
	report, err := BridgeValidatePrivateMessageBudget(v, budget)
	if err == nil && !BridgeValidationHasValueMismatch(report) {
		_, err = s12.BridgePrivateMessageMethodMarshalAPERBudget(v, budget, false)
	}
	if *s09.BridgeValidationReportFieldErr(&report) != nil {
		err = *s09.BridgeValidationReportFieldErr(&report)
	}
	*s09.BridgeValidationReportFieldBudget(&report) = nil
	*s09.BridgeValidationReportFieldErr(&report) = nil
	return report, aper.OperationError(err, "PrivateMessage")
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
func BridgeInterRATMeasuredResultsValueValueCodecFieldCapture(v *InterRATMeasuredResultsValueValueCodec) *func(InterRATMeasuredResultsValue, aper.DecodeState) (InterRATMeasuredResultsValue, aper.Snapshot) {
	return &v.capture
}
func BridgeInterRATMeasuredResultsValueValueCodecFieldCompare(v *InterRATMeasuredResultsValueValueCodec) *func(InterRATMeasuredResultsValue, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeInterRATMeasuredResultsValueValueCodecFieldContext(v *InterRATMeasuredResultsValueValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterRATMeasuredResultsValueValueCodecFieldDecode(v *InterRATMeasuredResultsValueValueCodec) *func([]byte, aper.DecodeState) (InterRATMeasuredResultsValue, error) {
	return &v.decode
}
func BridgeInterRATMeasuredResultsValueValueCodecFieldEncode(v *InterRATMeasuredResultsValueValueCodec) *func(InterRATMeasuredResultsValue, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInterRATMeasuredResultsValueValueCodecFieldPath(v *InterRATMeasuredResultsValueValueCodec) *aper.Path {
	return &v.path
}
func BridgeInterRATMeasuredResultsValueValueCodecMethodEncodeBudget(v InterRATMeasuredResultsValueValueCodec, a0 InterRATMeasuredResultsValue, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeInterRATMeasuredResultsValueValueCodecMethodEncodeChanged(v InterRATMeasuredResultsValueValueCodec, a0 InterRATMeasuredResultsValue, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInterRATMeasurementResultAPERValueFieldContext(v *InterRATMeasurementResultAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterRATMeasurementResultAPERValueFieldReceived(v *InterRATMeasurementResultAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInterRATMeasurementResultAPERValueFieldReplay(v *InterRATMeasurementResultAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementResultAPERValueFieldWithoutReplay(v *InterRATMeasurementResultAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementResultCompleteFieldPerPadding(v *InterRATMeasurementResultComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeInterRATMeasurementResultCompleteFieldReceived(v *InterRATMeasurementResultComplete) *bool {
	return &v.received
}
func BridgeInterRATMeasurementResultCompleteFieldReceivedBytes(v *InterRATMeasurementResultComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeInterRATMeasurementResultCompleteFieldReplay(v *InterRATMeasurementResultComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasurementResultCompleteFieldStream(v *InterRATMeasurementResultComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeInterRATMeasurementResultCompleteFieldWithoutReplay(v *InterRATMeasurementResultComplete) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasurementResultCompleteMethodMarshalAPERBudget(v *InterRATMeasurementResultComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInterRATMeasurementResultCompleteMethodMarshalAPERChanged(v *InterRATMeasurementResultComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeInterRATMeasurementResultCompleteMethodMarshalAPERChangedValue(v *InterRATMeasurementResultComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeInterRATMeasurementResultCompleteMethodMarshalAPERFreshValue(v *InterRATMeasurementResultComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeInterRATMeasurementResultCompleteMethodMarshalAPERLegacy(v *InterRATMeasurementResultComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeInterRATMeasurementResultCompleteMethodMarshalAPERPlanned(v *InterRATMeasurementResultComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeInterRATMeasurementResultCompleteMethodUnmarshalAPERLegacy(v *InterRATMeasurementResultComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeInterRATMeasurementResultCompleteMethodUnmarshalAPERWithOptions(v *InterRATMeasurementResultComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeInterRATMeasurementResultValueCodecFieldCapture(v *InterRATMeasurementResultValueCodec) *func(InterRATMeasurementResult, aper.DecodeState) (InterRATMeasurementResult, aper.Snapshot) {
	return &v.capture
}
func BridgeInterRATMeasurementResultValueCodecFieldCompare(v *InterRATMeasurementResultValueCodec) *func(InterRATMeasurementResult, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeInterRATMeasurementResultValueCodecFieldContext(v *InterRATMeasurementResultValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInterRATMeasurementResultValueCodecFieldDecode(v *InterRATMeasurementResultValueCodec) *func([]byte, aper.DecodeState) (InterRATMeasurementResult, error) {
	return &v.decode
}
func BridgeInterRATMeasurementResultValueCodecFieldEncode(v *InterRATMeasurementResultValueCodec) *func(InterRATMeasurementResult, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInterRATMeasurementResultValueCodecFieldPath(v *InterRATMeasurementResultValueCodec) *aper.Path {
	return &v.path
}
func BridgeInterRATMeasurementResultValueCodecMethodEncodeBudget(v InterRATMeasurementResultValueCodec, a0 InterRATMeasurementResult, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeInterRATMeasurementResultValueCodecMethodEncodeChanged(v InterRATMeasurementResultValueCodec, a0 InterRATMeasurementResult, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultNRCompleteFieldPerPadding(v *ResultNRComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeResultNRCompleteFieldReceived(v *ResultNRComplete) *bool { return &v.received }
func BridgeResultNRCompleteFieldReceivedBytes(v *ResultNRComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeResultNRCompleteFieldReplay(v *ResultNRComplete) *aper.Snapshot { return &v.replay }
func BridgeResultNRCompleteFieldStream(v *ResultNRComplete) *aper.WireSpan { return &v.stream }
func BridgeResultNRCompleteFieldWithoutReplay(v *ResultNRComplete) *bool   { return &v.withoutReplay }
func BridgeResultNRCompleteMethodMarshalAPERBudget(v *ResultNRComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultNRCompleteMethodMarshalAPERChanged(v *ResultNRComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultNRCompleteMethodMarshalAPERChangedValue(v *ResultNRComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultNRCompleteMethodMarshalAPERFreshValue(v *ResultNRComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultNRCompleteMethodMarshalAPERLegacy(v *ResultNRComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultNRCompleteMethodMarshalAPERPlanned(v *ResultNRComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultNRCompleteMethodUnmarshalAPERLegacy(v *ResultNRComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultNRCompleteMethodUnmarshalAPERWithOptions(v *ResultNRComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSRSConfigurationForAllCellsCompleteFieldPerPadding(v *SRSConfigurationForAllCellsComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeSRSConfigurationForAllCellsCompleteFieldReceived(v *SRSConfigurationForAllCellsComplete) *bool {
	return &v.received
}
func BridgeSRSConfigurationForAllCellsCompleteFieldReceivedBytes(v *SRSConfigurationForAllCellsComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSRSConfigurationForAllCellsCompleteFieldReplay(v *SRSConfigurationForAllCellsComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeSRSConfigurationForAllCellsCompleteFieldStream(v *SRSConfigurationForAllCellsComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeSRSConfigurationForAllCellsCompleteFieldWithoutReplay(v *SRSConfigurationForAllCellsComplete) *bool {
	return &v.withoutReplay
}
func BridgeSRSConfigurationForAllCellsCompleteMethodMarshalAPERBudget(v *SRSConfigurationForAllCellsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSRSConfigurationForAllCellsCompleteMethodMarshalAPERChanged(v *SRSConfigurationForAllCellsComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSRSConfigurationForAllCellsCompleteMethodMarshalAPERChangedValue(v *SRSConfigurationForAllCellsComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSRSConfigurationForAllCellsCompleteMethodMarshalAPERFreshValue(v *SRSConfigurationForAllCellsComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeSRSConfigurationForAllCellsCompleteMethodMarshalAPERLegacy(v *SRSConfigurationForAllCellsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSRSConfigurationForAllCellsCompleteMethodMarshalAPERPlanned(v *SRSConfigurationForAllCellsComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeSRSConfigurationForAllCellsCompleteMethodUnmarshalAPERLegacy(v *SRSConfigurationForAllCellsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSRSConfigurationForAllCellsCompleteMethodUnmarshalAPERWithOptions(v *SRSConfigurationForAllCellsComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSystemInformationCompleteFieldPerPadding(v *SystemInformationComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeSystemInformationCompleteFieldReceived(v *SystemInformationComplete) *bool {
	return &v.received
}
func BridgeSystemInformationCompleteFieldReceivedBytes(v *SystemInformationComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSystemInformationCompleteFieldReplay(v *SystemInformationComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeSystemInformationCompleteFieldStream(v *SystemInformationComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeSystemInformationCompleteFieldWithoutReplay(v *SystemInformationComplete) *bool {
	return &v.withoutReplay
}
func BridgeSystemInformationCompleteMethodMarshalAPERBudget(v *SystemInformationComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSystemInformationCompleteMethodMarshalAPERChanged(v *SystemInformationComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSystemInformationCompleteMethodMarshalAPERChangedValue(v *SystemInformationComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSystemInformationCompleteMethodMarshalAPERFreshValue(v *SystemInformationComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeSystemInformationCompleteMethodMarshalAPERLegacy(v *SystemInformationComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSystemInformationCompleteMethodMarshalAPERPlanned(v *SystemInformationComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeSystemInformationCompleteMethodUnmarshalAPERLegacy(v *SystemInformationComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSystemInformationCompleteMethodUnmarshalAPERWithOptions(v *SystemInformationComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeWLANChannelListCompleteFieldPerPadding(v *WLANChannelListComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeWLANChannelListCompleteFieldReceived(v *WLANChannelListComplete) *bool { return &v.received }
func BridgeWLANChannelListCompleteFieldReceivedBytes(v *WLANChannelListComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeWLANChannelListCompleteFieldReplay(v *WLANChannelListComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANChannelListCompleteFieldStream(v *WLANChannelListComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeWLANChannelListCompleteFieldWithoutReplay(v *WLANChannelListComplete) *bool {
	return &v.withoutReplay
}
func BridgeWLANChannelListCompleteMethodMarshalAPERBudget(v *WLANChannelListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeWLANChannelListCompleteMethodMarshalAPERChanged(v *WLANChannelListComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeWLANChannelListCompleteMethodMarshalAPERChangedValue(v *WLANChannelListComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeWLANChannelListCompleteMethodMarshalAPERFreshValue(v *WLANChannelListComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeWLANChannelListCompleteMethodMarshalAPERLegacy(v *WLANChannelListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeWLANChannelListCompleteMethodMarshalAPERPlanned(v *WLANChannelListComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeWLANChannelListCompleteMethodUnmarshalAPERLegacy(v *WLANChannelListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeWLANChannelListCompleteMethodUnmarshalAPERWithOptions(v *WLANChannelListComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeWLANMeasurementQuantitiesAPERValueFieldContext(v *WLANMeasurementQuantitiesAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementQuantitiesAPERValueFieldReceived(v *WLANMeasurementQuantitiesAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesAPERValueFieldReplay(v *WLANMeasurementQuantitiesAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesAPERValueFieldWithoutReplay(v *WLANMeasurementQuantitiesAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesCompleteFieldPerPadding(v *WLANMeasurementQuantitiesComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeWLANMeasurementQuantitiesCompleteFieldReceived(v *WLANMeasurementQuantitiesComplete) *bool {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesCompleteFieldReceivedBytes(v *WLANMeasurementQuantitiesComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeWLANMeasurementQuantitiesCompleteFieldReplay(v *WLANMeasurementQuantitiesComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesCompleteFieldStream(v *WLANMeasurementQuantitiesComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeWLANMeasurementQuantitiesCompleteFieldWithoutReplay(v *WLANMeasurementQuantitiesComplete) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesCompleteMethodMarshalAPERBudget(v *WLANMeasurementQuantitiesComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeWLANMeasurementQuantitiesCompleteMethodMarshalAPERChanged(v *WLANMeasurementQuantitiesComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeWLANMeasurementQuantitiesCompleteMethodMarshalAPERChangedValue(v *WLANMeasurementQuantitiesComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeWLANMeasurementQuantitiesCompleteMethodMarshalAPERFreshValue(v *WLANMeasurementQuantitiesComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeWLANMeasurementQuantitiesCompleteMethodMarshalAPERLegacy(v *WLANMeasurementQuantitiesComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeWLANMeasurementQuantitiesCompleteMethodMarshalAPERPlanned(v *WLANMeasurementQuantitiesComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeWLANMeasurementQuantitiesCompleteMethodUnmarshalAPERLegacy(v *WLANMeasurementQuantitiesComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeWLANMeasurementQuantitiesCompleteMethodUnmarshalAPERWithOptions(v *WLANMeasurementQuantitiesComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldCapture(v *WLANMeasurementQuantitiesConcreteValueCodec) *func(WLANMeasurementQuantities, aper.DecodeState) (WLANMeasurementQuantities, aper.Snapshot) {
	return &v.capture
}
func BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldCompare(v *WLANMeasurementQuantitiesConcreteValueCodec) *func(WLANMeasurementQuantities, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldContext(v *WLANMeasurementQuantitiesConcreteValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldDecode(v *WLANMeasurementQuantitiesConcreteValueCodec) *func([]byte, aper.DecodeState) (WLANMeasurementQuantities, error) {
	return &v.decode
}
func BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldEncode(v *WLANMeasurementQuantitiesConcreteValueCodec) *func(WLANMeasurementQuantities, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANMeasurementQuantitiesConcreteValueCodecFieldPath(v *WLANMeasurementQuantitiesConcreteValueCodec) *aper.Path {
	return &v.path
}
func BridgeWLANMeasurementQuantitiesConcreteValueCodecMethodEncodeBudget(v WLANMeasurementQuantitiesConcreteValueCodec, a0 WLANMeasurementQuantities, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANMeasurementQuantitiesConcreteValueCodecMethodEncodeChanged(v WLANMeasurementQuantitiesConcreteValueCodec, a0 WLANMeasurementQuantities, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANMeasurementQuantitiesItemAPERValueFieldContext(v *WLANMeasurementQuantitiesItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementQuantitiesItemAPERValueFieldReceived(v *WLANMeasurementQuantitiesItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesItemAPERValueFieldReplay(v *WLANMeasurementQuantitiesItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesItemAPERValueFieldWithoutReplay(v *WLANMeasurementQuantitiesItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesItemFieldExtCount(v *WLANMeasurementQuantitiesItem) *int64 {
	return &v.extCount
}
func BridgeWLANMeasurementQuantitiesItemFieldExtData(v *WLANMeasurementQuantitiesItem) *[][]byte {
	return &v.extData
}
func BridgeWLANMeasurementQuantitiesItemFieldExtOrigin(v *WLANMeasurementQuantitiesItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeWLANMeasurementQuantitiesItemFieldExtPresent(v *WLANMeasurementQuantitiesItem) *[]bool {
	return &v.extPresent
}
func BridgeWLANMeasurementQuantitiesItemFieldExtWire(v *WLANMeasurementQuantitiesItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeWLANMeasurementQuantitiesItemFieldIEExtensionsIndef(v *WLANMeasurementQuantitiesItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeWLANMeasurementQuantitiesItemFieldPerExtPadding(v *WLANMeasurementQuantitiesItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeWLANMeasurementQuantitiesItemFieldPerPadding(v *WLANMeasurementQuantitiesItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeWLANMeasurementQuantitiesItemFieldReceived(v *WLANMeasurementQuantitiesItem) *bool {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesItemFieldReceivedBytes(v *WLANMeasurementQuantitiesItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeWLANMeasurementQuantitiesItemFieldReplay(v *WLANMeasurementQuantitiesItem) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesItemFieldStream(v *WLANMeasurementQuantitiesItem) *aper.WireSpan {
	return &v.stream
}
func BridgeWLANMeasurementQuantitiesItemFieldWithoutReplay(v *WLANMeasurementQuantitiesItem) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesItemIEFieldFieldReceived(v *WLANMeasurementQuantitiesItemIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesItemIEFieldFieldReplay(v *WLANMeasurementQuantitiesItemIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesItemIEFieldFieldStream(v *WLANMeasurementQuantitiesItemIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeWLANMeasurementQuantitiesItemIEFieldFieldWithoutReplay(v *WLANMeasurementQuantitiesItemIEField) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesItemIEFieldMethodMarshalAPERTo(v *WLANMeasurementQuantitiesItemIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWLANMeasurementQuantitiesItemIEFieldMethodUnmarshalAPERFrom(v *WLANMeasurementQuantitiesItemIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWLANMeasurementQuantitiesItemIETableMethodInfoWLANMeasurementQuantitiesItem(v WLANMeasurementQuantitiesItemIETable) s00.FieldInfo {
	return v.infoWLANMeasurementQuantitiesItem()
}
func BridgeWLANMeasurementQuantitiesItemIEValueFieldId(v *WLANMeasurementQuantitiesItemIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeWLANMeasurementQuantitiesItemIEValueFieldIsOpaque(v *WLANMeasurementQuantitiesItemIEValue) *bool {
	return &v.isOpaque
}
func BridgeWLANMeasurementQuantitiesItemIEValueFieldOpaque(v *WLANMeasurementQuantitiesItemIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeWLANMeasurementQuantitiesItemIEValueFieldReceived(v *WLANMeasurementQuantitiesItemIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeWLANMeasurementQuantitiesItemIEValueFieldReplay(v *WLANMeasurementQuantitiesItemIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementQuantitiesItemIEValueFieldRowWLANMeasurementQuantitiesItem(v *WLANMeasurementQuantitiesItemIEValue) **WLANMeasurementQuantitiesItem {
	return &v.rowWLANMeasurementQuantitiesItem
}
func BridgeWLANMeasurementQuantitiesItemIEValueFieldWithoutReplay(v *WLANMeasurementQuantitiesItemIEValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodCaptureFraming(v WLANMeasurementQuantitiesItemIEValue) uint64 {
	return v.captureFraming()
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodCaptureSemantics(v WLANMeasurementQuantitiesItemIEValue, a0 aper.SemanticCapture) WLANMeasurementQuantitiesItemIEValue {
	return v.captureSemantics(a0)
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodCaptureSnapshot(v WLANMeasurementQuantitiesItemIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodCompareSemantics(v WLANMeasurementQuantitiesItemIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodDecode(v WLANMeasurementQuantitiesItemIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (WLANMeasurementQuantitiesItemIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodEncode(v WLANMeasurementQuantitiesItemIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodEncodeFresh(v WLANMeasurementQuantitiesItemIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodMatchesID(v WLANMeasurementQuantitiesItemIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodReason(v WLANMeasurementQuantitiesItemIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeWLANMeasurementQuantitiesItemIEValueMethodRule(v WLANMeasurementQuantitiesItemIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeWLANMeasurementQuantitiesItemMethodMarshalAPERBudget(v *WLANMeasurementQuantitiesItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeWLANMeasurementQuantitiesItemMethodMarshalAPERChanged(v *WLANMeasurementQuantitiesItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeWLANMeasurementQuantitiesItemMethodMarshalAPERChangedValue(v *WLANMeasurementQuantitiesItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeWLANMeasurementQuantitiesItemMethodMarshalAPERFreshValue(v *WLANMeasurementQuantitiesItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeWLANMeasurementQuantitiesItemMethodMarshalAPERLegacy(v *WLANMeasurementQuantitiesItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeWLANMeasurementQuantitiesItemMethodMarshalAPERPlanned(v *WLANMeasurementQuantitiesItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeWLANMeasurementQuantitiesItemMethodMarshalAPERTo(v *WLANMeasurementQuantitiesItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWLANMeasurementQuantitiesItemMethodUnmarshalAPERFrom(v *WLANMeasurementQuantitiesItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWLANMeasurementQuantitiesItemMethodUnmarshalAPERLegacy(v *WLANMeasurementQuantitiesItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeWLANMeasurementQuantitiesItemMethodUnmarshalAPERWithOptions(v *WLANMeasurementQuantitiesItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeWLANMeasurementQuantitiesItemValueCodecFieldCapture(v *WLANMeasurementQuantitiesItemValueCodec) *func(WLANMeasurementQuantitiesItem, aper.DecodeState) (WLANMeasurementQuantitiesItem, aper.Snapshot) {
	return &v.capture
}
func BridgeWLANMeasurementQuantitiesItemValueCodecFieldCompare(v *WLANMeasurementQuantitiesItemValueCodec) *func(WLANMeasurementQuantitiesItem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeWLANMeasurementQuantitiesItemValueCodecFieldContext(v *WLANMeasurementQuantitiesItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementQuantitiesItemValueCodecFieldDecode(v *WLANMeasurementQuantitiesItemValueCodec) *func([]byte, aper.DecodeState) (WLANMeasurementQuantitiesItem, error) {
	return &v.decode
}
func BridgeWLANMeasurementQuantitiesItemValueCodecFieldEncode(v *WLANMeasurementQuantitiesItemValueCodec) *func(WLANMeasurementQuantitiesItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANMeasurementQuantitiesItemValueCodecFieldPath(v *WLANMeasurementQuantitiesItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeWLANMeasurementQuantitiesItemValueCodecMethodEncodeBudget(v WLANMeasurementQuantitiesItemValueCodec, a0 WLANMeasurementQuantitiesItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANMeasurementQuantitiesItemValueCodecMethodEncodeChanged(v WLANMeasurementQuantitiesItemValueCodec, a0 WLANMeasurementQuantitiesItem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBindingFieldCodec(v *WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding) *WLANMeasurementQuantitiesItemValueCodec {
	return &v.codec
}
func BridgeWLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBindingFieldGet(v *WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding) *func(*WLANMeasurementQuantitiesItemIEValue) (*WLANMeasurementQuantitiesItem, bool) {
	return &v.get
}
func BridgeWLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBindingFieldInfo(v *WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeWLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBindingFieldInject(v *WLANMeasurementQuantitiesItemWLANMeasurementQuantitiesItemIEBinding) *func(WLANMeasurementQuantitiesItem) WLANMeasurementQuantitiesItemIEValue {
	return &v.inject
}
