// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s13 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s13

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s12"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// ECIDMeasurementReportIEContainer is ProtocolIE-Container {{E-CIDMeasurementReport-IEs}} of TS 36.455: a list of ECIDMeasurementReportIEField values.
type ECIDMeasurementReportIEContainer []ECIDMeasurementReportIEField

// ECIDMeasurementReportIEField is ProtocolIE-Field {{E-CIDMeasurementReport-IEs}} of TS 36.455: a field carrying a value of ECIDMeasurementReportIEValue.
type ECIDMeasurementReportIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ECIDMeasurementReportIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECIDMeasurementReportIEField) WithoutReplay() ECIDMeasurementReportIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ECIDMeasurementReportIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ECIDMeasurementReportIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ECIDMeasurementReportIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementReportIEField{}
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
	var zero ECIDMeasurementReportIEValue

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
func BridgeECIDMeasurementReportIEValueCaptureLPPaProtocolIEContainer(v *ECIDMeasurementReportIEContainer, s *aper.SemanticCapture) {
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
			BridgeECIDMeasurementReportIEValueCaptureLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeECIDMeasurementReportIEValueCompareLPPaProtocolIEContainer(v *ECIDMeasurementReportIEContainer, s *aper.SemanticComparison) {
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
			BridgeECIDMeasurementReportIEValueCompareLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeResultUTRANItemExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s04.ResultUTRANItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
			BridgeResultUTRANItemExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeResultUTRANItemExtIEsValueCompareLPPaProtocolExtensionContainer(v *s04.ResultUTRANItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
			BridgeResultUTRANItemExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}

// ECIDMeasurementResultValueCodec is the concrete ValueCodec[ECIDMeasurementResult].
type ECIDMeasurementResultValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ECIDMeasurementResult, aper.DecodeState,

	) (ECIDMeasurementResult, aper.Snapshot,

	)
	compare func(ECIDMeasurementResult, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ECIDMeasurementResult,

		error)
	encode func(ECIDMeasurementResult,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ECIDMeasurementResultValueCodec) New(value ECIDMeasurementResult,

) (ECIDMeasurementResultAPERValue, error) {
	if c.encode == nil {
		return ECIDMeasurementResultAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementResultAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ECIDMeasurementResultAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementResultAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ECIDMeasurementResultValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ECIDMeasurementResultAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ECIDMeasurementResultAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ECIDMeasurementResultAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ECIDMeasurementResultAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ECIDMeasurementResultAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ECIDMeasurementResultAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ECIDMeasurementResultValueCodec) EncodeAPER(value ECIDMeasurementResultAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ECIDMeasurementResultValueCodec) encodeBudget(value ECIDMeasurementResult,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ECIDMeasurementResultValueCodec) encodeChanged(value ECIDMeasurementResult,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ECIDMeasurementReportMeasurementIDIEBinding binds MeasurementID to ProtocolIE-Field {{E-CIDMeasurementReport-IEs}} of TS 36.455.
type ECIDMeasurementReportMeasurementIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.MeasurementIDValueCodec
	inject func(s00.MeasurementID,

	) ECIDMeasurementReportIEValue

	get func(*ECIDMeasurementReportIEValue,

	) (*s00.MeasurementID,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementReportMeasurementIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementReportMeasurementIDIEBinding) Codec() s00.MeasurementIDValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementReportMeasurementIDIEBinding) New(value s00.MeasurementID,

) (ECIDMeasurementReportIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementReportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementReportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeMeasurementIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementReportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementReportIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementReportMeasurementIDIEBinding) Get(field *ECIDMeasurementReportIEField) (*s00.MeasurementID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementReportECIDMeasurementResultIEBinding binds ECIDMeasurementResult to ProtocolIE-Field {{E-CIDMeasurementReport-IEs}} of TS 36.455.
type ECIDMeasurementReportECIDMeasurementResultIEBinding struct {
	info   s00.FieldInfo
	codec  ECIDMeasurementResultValueCodec
	inject func(ECIDMeasurementResult,

	) ECIDMeasurementReportIEValue

	get func(*ECIDMeasurementReportIEValue,

	) (*ECIDMeasurementResult,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementReportECIDMeasurementResultIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementReportECIDMeasurementResultIEBinding) Codec() ECIDMeasurementResultValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementReportECIDMeasurementResultIEBinding) New(value ECIDMeasurementResult,

) (ECIDMeasurementReportIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementReportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementReportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ECIDMeasurementReportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementReportIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementReportECIDMeasurementResultIEBinding) Get(field *ECIDMeasurementReportIEField) (*ECIDMeasurementResult,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementReportCellPortionIDIEBinding binds CellPortionID to ProtocolIE-Field {{E-CIDMeasurementReport-IEs}} of TS 36.455.
type ECIDMeasurementReportCellPortionIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CellPortionIDValueCodec
	inject func(s00.CellPortionID,

	) ECIDMeasurementReportIEValue

	get func(*ECIDMeasurementReportIEValue,

	) (*s00.CellPortionID,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementReportCellPortionIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementReportCellPortionIDIEBinding) Codec() s00.CellPortionIDValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementReportCellPortionIDIEBinding) New(value s00.CellPortionID,

) (ECIDMeasurementReportIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementReportIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementReportIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCellPortionIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementReportIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementReportIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementReportCellPortionIDIEBinding) Get(field *ECIDMeasurementReportIEField) (*s00.CellPortionID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementReportValueCodec is the concrete ValueCodec[ECIDMeasurementReport].
type ECIDMeasurementReportValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ECIDMeasurementReport, aper.DecodeState,

	) (ECIDMeasurementReport, aper.Snapshot,

	)
	compare func(ECIDMeasurementReport, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ECIDMeasurementReport,

		error)
	encode func(ECIDMeasurementReport,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ECIDMeasurementReportValueCodec) New(value ECIDMeasurementReport,

) (ECIDMeasurementReportAPERValue, error) {
	if c.encode == nil {
		return ECIDMeasurementReportAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementReportAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ECIDMeasurementReportAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementReportAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ECIDMeasurementReportValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ECIDMeasurementReportAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ECIDMeasurementReportAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ECIDMeasurementReportAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ECIDMeasurementReportAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ECIDMeasurementReportAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ECIDMeasurementReportAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ECIDMeasurementReportValueCodec) EncodeAPER(value ECIDMeasurementReportAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ECIDMeasurementReportValueCodec) encodeBudget(value ECIDMeasurementReport,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ECIDMeasurementReportValueCodec) encodeChanged(value ECIDMeasurementReport,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// MeasuredResultsConcreteValueCodec is the concrete ValueCodec[MeasuredResults].
type MeasuredResultsConcreteValueCodec struct {
	context s00.BridgeCodecContext
	capture func(MeasuredResults, aper.DecodeState,

	) (MeasuredResults, aper.Snapshot,

	)
	compare func(MeasuredResults, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (MeasuredResults,

		error)
	encode func(MeasuredResults,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c MeasuredResultsConcreteValueCodec) New(value MeasuredResults,

) (MeasuredResultsAPERValue, error) {
	if c.encode == nil {
		return MeasuredResultsAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MeasuredResultsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MeasuredResultsAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return MeasuredResultsAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c MeasuredResultsConcreteValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MeasuredResultsAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return MeasuredResultsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return MeasuredResultsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return MeasuredResultsAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return MeasuredResultsAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return MeasuredResultsAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c MeasuredResultsConcreteValueCodec) EncodeAPER(value MeasuredResultsAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MeasuredResultsConcreteValueCodec) encodeBudget(value MeasuredResults,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c MeasuredResultsConcreteValueCodec) encodeChanged(value MeasuredResults,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// MeasuredResultsValueValueCodec is the concrete ValueCodec[MeasuredResultsValue].
type MeasuredResultsValueValueCodec struct {
	context s00.BridgeCodecContext
	capture func(MeasuredResultsValue, aper.DecodeState,

	) (MeasuredResultsValue, aper.Snapshot,

	)
	compare func(MeasuredResultsValue, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (MeasuredResultsValue,

		error)
	encode func(MeasuredResultsValue,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c MeasuredResultsValueValueCodec) New(value MeasuredResultsValue,

) (MeasuredResultsValueAPERValue, error) {
	if c.encode == nil {
		return MeasuredResultsValueAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return MeasuredResultsValueAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MeasuredResultsValueAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return MeasuredResultsValueAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c MeasuredResultsValueValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (MeasuredResultsValueAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return MeasuredResultsValueAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return MeasuredResultsValueAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return MeasuredResultsValueAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return MeasuredResultsValueAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return MeasuredResultsValueAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c MeasuredResultsValueValueCodec) EncodeAPER(value MeasuredResultsValueAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c MeasuredResultsValueValueCodec) encodeBudget(value MeasuredResultsValue,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c MeasuredResultsValueValueCodec) encodeChanged(value MeasuredResultsValue,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ResultRSRQValueCodec is the concrete ValueCodec[ResultRSRQ].
type ResultRSRQValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ResultRSRQ, aper.DecodeState,

	) (ResultRSRQ, aper.Snapshot,

	)
	compare func(ResultRSRQ, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ResultRSRQ,

		error)
	encode func(ResultRSRQ,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ResultRSRQValueCodec) New(value ResultRSRQ,

) (ResultRSRQAPERValue, error) {
	if c.encode == nil {
		return ResultRSRQAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResultRSRQAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultRSRQAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ResultRSRQAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ResultRSRQValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResultRSRQAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultRSRQAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ResultRSRQAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultRSRQAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ResultRSRQAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ResultRSRQAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ResultRSRQValueCodec) EncodeAPER(value ResultRSRQAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResultRSRQValueCodec) encodeBudget(value ResultRSRQ,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultRSRQValueCodec) encodeChanged(value ResultRSRQ,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ResultRSRQItemValueCodec is the concrete ValueCodec[ResultRSRQItem].
type ResultRSRQItemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ResultRSRQItem, aper.DecodeState,

	) (ResultRSRQItem, aper.Snapshot,

	)
	compare func(ResultRSRQItem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ResultRSRQItem,

		error)
	encode func(ResultRSRQItem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ResultRSRQItemValueCodec) New(value ResultRSRQItem,

) (ResultRSRQItemAPERValue, error) {
	if c.encode == nil {
		return ResultRSRQItemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResultRSRQItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultRSRQItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ResultRSRQItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ResultRSRQItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResultRSRQItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultRSRQItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ResultRSRQItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultRSRQItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ResultRSRQItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ResultRSRQItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ResultRSRQItemValueCodec) EncodeAPER(value ResultRSRQItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResultRSRQItemValueCodec) encodeBudget(value ResultRSRQItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultRSRQItemValueCodec) encodeChanged(value ResultRSRQItem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeECIDMeasurementReportIEValueValidateLPPaIEContainer(fields ECIDMeasurementReportIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
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
func BridgeResultRSRQItemExtIEsValueValidateLPPaExtensionContainer(fields s04.ResultRSRQItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s04.ResultRSRQItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s04.ResultRSRQItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeResultRSRQItemExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// eCIDMeasurementReportIEValueProtocolOpenValue is the concrete protocolOpenValue[ECIDMeasurementReportIEValue].
type ECIDMeasurementReportIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) ECIDMeasurementReportIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (ECIDMeasurementReportIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeECIDMeasurementReportIEValueCaptureLPPaProtocolIEField(v *ECIDMeasurementReportIEField, s *aper.SemanticCapture) {
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
func BridgeECIDMeasurementReportIEValueCompareLPPaProtocolIEField(v *ECIDMeasurementReportIEField, s *aper.SemanticComparison) {
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

// resultRSRQItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ResultRSRQItemExtIEsValue].
type ResultRSRQItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.ResultRSRQItemExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.ResultRSRQItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeResultUTRANItemExtIEsValueCaptureLPPaProtocolExtensionField(v *s04.ResultUTRANItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s04.BridgeResultUTRANItemExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s03.BridgeResultUTRANItemExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s03.BridgeResultUTRANItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s03.BridgeResultUTRANItemExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s04.BridgeResultUTRANItemExtIEsExtFieldFieldReplay(v), *s04.BridgeResultUTRANItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeResultUTRANItemExtIEsValueCompareLPPaProtocolExtensionField(v *s04.ResultUTRANItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s03.BridgeResultUTRANItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s04.BridgeResultUTRANItemExtIEsExtFieldFieldReplay(v), *s04.BridgeResultUTRANItemExtIEsExtFieldFieldWithoutReplay(v))
}

// ECIDMeasurementResultAPERValue is the concrete APERValue[ECIDMeasurementResult].
type ECIDMeasurementResultAPERValue struct {
	context s00.BridgeCodecContext
	Value   ECIDMeasurementResult

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ECIDMeasurementResultAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECIDMeasurementResultAPERValue) WithoutReplay() ECIDMeasurementResultAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ECIDMeasurementReportAPERValue is the concrete APERValue[ECIDMeasurementReport].
type ECIDMeasurementReportAPERValue struct {
	context s00.BridgeCodecContext
	Value   ECIDMeasurementReport

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ECIDMeasurementReportAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECIDMeasurementReportAPERValue) WithoutReplay() ECIDMeasurementReportAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasuredResultsAPERValue is the concrete APERValue[MeasuredResults].
type MeasuredResultsAPERValue struct {
	context s00.BridgeCodecContext
	Value   MeasuredResults

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v MeasuredResultsAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v MeasuredResultsAPERValue) WithoutReplay() MeasuredResultsAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasuredResultsValueAPERValue is the concrete APERValue[MeasuredResultsValue].
type MeasuredResultsValueAPERValue struct {
	context s00.BridgeCodecContext
	Value   MeasuredResultsValue

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v MeasuredResultsValueAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v MeasuredResultsValueAPERValue) WithoutReplay() MeasuredResultsValueAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultRSRQAPERValue is the concrete APERValue[ResultRSRQ].
type ResultRSRQAPERValue struct {
	context s00.BridgeCodecContext
	Value   ResultRSRQ

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ResultRSRQAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultRSRQAPERValue) WithoutReplay() ResultRSRQAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultRSRQItemAPERValue is the concrete APERValue[ResultRSRQItem].
type ResultRSRQItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ResultRSRQItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ResultRSRQItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultRSRQItemAPERValue) WithoutReplay() ResultRSRQItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeResultRSRQItemExtIEsValueValidateLPPaIEContainer(fields s04.ResultRSRQItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s03.BridgeResultRSRQItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s03.BridgeResultRSRQItemExtIEsValueMethodRule(field.Value)
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

// ECIDMeasurementResult represents the ASN.1 type E-CID-MeasurementResult (SEQUENCE).
type ECIDMeasurementResult struct {
	replay                    aper.Snapshot
	stream                    aper.WireSpan
	withoutReplay             bool
	received                  bool
	receivedBytes             aper.WireSpan
	ServingCellID             s05.ECGI                       `asn1:"tag:0,context,implicit"`
	ServingCellTAC            s00.TAC                        `asn1:"tag:1,context,implicit"`
	EUTRANAccessPointPosition *s06.EUTRANAccessPointPosition `asn1:"tag:2,context,implicit,optional" json:"EUTRANAccessPointPosition,omitempty"`
	MeasuredResults           MeasuredResults                `asn1:"tag:3,context,implicit,optional" json:"MeasuredResults,omitzero"`
	measuredResultsIndef      bool                           `asn1:"-" json:"-"`
	extCount                  int64                          `asn1:"-" json:"-"`
	extPresent                []bool                         `asn1:"-" json:"-"`
	extData                   [][]byte                       `asn1:"-" json:"-"`
	perPadding                aper.FinalPadding              `asn1:"-" json:"-"`
	perExtPadding             []aper.CompletePadding         `asn1:"-" json:"-"`
	extOrigin                 []aper.OpaqueOrigin
	extWire                   []aper.WireSpan
}
type MeasuredResults = []MeasuredResultsValue

// MeasuredResultsValue represents the ASN.1 CHOICE type MeasuredResultsValue.
type MeasuredResultsValue struct {
	knownOpenBytes          uint64
	replay                  aper.Snapshot
	stream                  aper.WireSpan
	withoutReplay           bool
	received                bool
	receivedBytes           aper.WireSpan
	Choice                  int
	perPadding              aper.CompletePadding  `json:"-"`
	perOpenTypePadding      aper.CompletePadding  `json:"-"`
	UnknownExtension        *aper.ChoiceExtension `json:"UnknownExtension,omitempty"`
	ValueAngleOfArrival     *int64                `json:"ValueAngleOfArrival,omitempty"`
	ValueTimingAdvanceType1 *int64                `json:"ValueTimingAdvanceType1,omitempty"`
	ValueTimingAdvanceType2 *int64                `json:"ValueTimingAdvanceType2,omitempty"`
	ResultRSRP              s12.ResultRSRP        `json:"ResultRSRP,omitzero"`
	ResultRSRQ              ResultRSRQ            `json:"ResultRSRQ,omitzero"`
}

// NewMeasuredResultsValueValueAngleOfArrival creates a MeasuredResultsValue with the valueAngleOfArrival alternative.
func BridgeNewMeasuredResultsValueValueAngleOfArrivalLegacy(v int64) MeasuredResultsValue {
	return MeasuredResultsValue{
		Choice:              s00.MeasuredResultsValueChoiceValueAngleOfArrival,
		ValueAngleOfArrival: &v,
	}
}

// NewMeasuredResultsValueValueTimingAdvanceType1 creates a MeasuredResultsValue with the valueTimingAdvanceType1 alternative.
func BridgeNewMeasuredResultsValueValueTimingAdvanceType1Legacy(v int64) MeasuredResultsValue {
	return MeasuredResultsValue{
		Choice:                  s00.MeasuredResultsValueChoiceValueTimingAdvanceType1,
		ValueTimingAdvanceType1: &v,
	}
}

// NewMeasuredResultsValueValueTimingAdvanceType2 creates a MeasuredResultsValue with the valueTimingAdvanceType2 alternative.
func BridgeNewMeasuredResultsValueValueTimingAdvanceType2Legacy(v int64) MeasuredResultsValue {
	return MeasuredResultsValue{
		Choice:                  s00.MeasuredResultsValueChoiceValueTimingAdvanceType2,
		ValueTimingAdvanceType2: &v,
	}
}

// NewMeasuredResultsValueResultRSRP creates a MeasuredResultsValue with the resultRSRP alternative.
func BridgeNewMeasuredResultsValueResultRSRPLegacy(v s12.ResultRSRP) MeasuredResultsValue {
	return MeasuredResultsValue{
		Choice:     s00.MeasuredResultsValueChoiceResultRSRP,
		ResultRSRP: v,
	}
}

// NewMeasuredResultsValueResultRSRQ creates a MeasuredResultsValue with the resultRSRQ alternative.
func BridgeNewMeasuredResultsValueResultRSRQLegacy(v ResultRSRQ) MeasuredResultsValue {
	return MeasuredResultsValue{
		Choice:     s00.MeasuredResultsValueChoiceResultRSRQ,
		ResultRSRQ: v,
	}
}

type ResultRSRQ = []ResultRSRQItem

// ResultRSRQItem represents the ASN.1 type ResultRSRQ-Item (SEQUENCE).
type ResultRSRQItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     aper.WireSpan
	PCI               s00.PCI                              `asn1:"tag:0,context,implicit"`
	EARFCN            s00.EARFCN                           `asn1:"tag:1,context,implicit"`
	ECGI              *s05.ECGI                            `asn1:"tag:2,context,implicit,optional" json:"ECGI,omitempty"`
	ValueRSRQ         s00.ValueRSRQ                        `asn1:"tag:3,context,implicit"`
	IEExtensions      s04.ResultRSRQItemExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                 `asn1:"-" json:"-"`
	extCount          int64                                `asn1:"-" json:"-"`
	extPresent        []bool                               `asn1:"-" json:"-"`
	extData           [][]byte                             `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                    `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding               `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}

// MarshalAPER encodes ECIDMeasurementResult to APER format.
func (v *ECIDMeasurementResult) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ECIDMeasurementResult) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.EUTRANAccessPointPosition != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.MeasuredResults != nil); err != nil {
		return err
	}
	if err := s05.BridgeECGIMethodMarshalAPERTo(&v.ServingCellID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding servingCell-ID: %w", err)
	}
	if err := aper.EncodeOctetStringAligned(bb, []byte(v.ServingCellTAC), 2, 2, true); err != nil {
		return fmt.Errorf("encoding servingCellTAC: %w", err)
	}
	if v.EUTRANAccessPointPosition != nil {
		if err := s06.BridgeEUTRANAccessPointPositionMethodMarshalAPERTo(v.EUTRANAccessPointPosition, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding e-UTRANAccessPointPosition: %w", err)
		}
	}
	if v.MeasuredResults != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.MeasuredResults)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_measuredresults, fragmentLength_measuredresults int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_measuredresults < 0 || fragmentOffset_measuredresults > int64(len(v.MeasuredResults)) || fragmentLength_measuredresults < 0 || fragmentLength_measuredresults > int64(len(v.MeasuredResults[fragmentOffset_measuredresults:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.MeasuredResults[fragmentOffset_measuredresults : fragmentOffset_measuredresults+fragmentLength_measuredresults] {
				if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding measuredResults element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding measuredResults: %w", err)
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

// UnmarshalAPER decodes ECIDMeasurementResult from APER format.
func (v *ECIDMeasurementResult) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ECIDMeasurementResult) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementResult")
	}
	bb.EnterComponent("ECIDMeasurementResult")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementResult")
	}
	padding, err := aper.CaptureFinalBits(bb, "ECIDMeasurementResult")
	if err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementResult")
	}
	v.perPadding = padding
	return nil
}
func (v *ECIDMeasurementResult) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementResult{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_eutranaccesspointposition, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_measuredresults, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_servingcellid := bb.EnterComponent("ServingCellID")
	if err := s05.BridgeECGIMethodUnmarshalAPERFrom(&v.ServingCellID, bb); err != nil {
		return runtime.WrapDecodePath(err, "ServingCellID")
	}
	bb.LeaveComponent(toleranceMark_servingcellid)
	val_servingcelltac, err := aper.DecodeOctetStringAligned(bb, 2, 2, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ServingCellTAC")
	}
	v.ServingCellTAC = s00.TAC(val_servingcelltac)
	if opt_eutranaccesspointposition {
		toleranceMark_eutranaccesspointposition := bb.EnterComponent("EUTRANAccessPointPosition")
		var dec_eutranaccesspointposition s06.EUTRANAccessPointPosition
		if err := s06.BridgeEUTRANAccessPointPositionMethodUnmarshalAPERFrom(&dec_eutranaccesspointposition, bb); err != nil {
			return runtime.WrapDecodePath(err, "EUTRANAccessPointPosition")
		}
		if err := aper.ChargeValue(bb, dec_eutranaccesspointposition); err != nil {
			return err
		}
		v.EUTRANAccessPointPosition = &dec_eutranaccesspointposition
		bb.LeaveComponent(toleranceMark_eutranaccesspointposition)
	}
	if opt_measuredresults {
		toleranceMark_measuredresults := bb.EnterComponent("MeasuredResults")
		tmp_measuredresults := make(MeasuredResults, 0)
		_, errCollection_measuredresults := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_measuredresults, fragmentLength_measuredresults int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
			if fragmentOffset_measuredresults < 0 || fragmentLength_measuredresults < 0 || fragmentLength_measuredresults > int64(^uint(0)>>1) || fragmentOffset_measuredresults > int64(^uint(0)>>1)-fragmentLength_measuredresults {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_measuredresults; i++ {
				var elem MeasuredResultsValue
				elementMark := bb.EnterIndex(fragmentOffset_measuredresults + i)
				if err := elem.unmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("MeasuredResults[%d]", fragmentOffset_measuredresults+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_measuredresults, elem); err != nil {
					return err
				} else {
					tmp_measuredresults = next
				}
			}
			return nil
		})
		if errCollection_measuredresults != nil {
			return runtime.WrapDecodePath(errCollection_measuredresults, "MeasuredResults")
		}
		v.MeasuredResults = tmp_measuredresults
		bb.LeaveComponent(toleranceMark_measuredresults)
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

type BridgeAsn1cAPERMeasuredResultsListValue struct{ Value MeasuredResults }

// MarshalAPERMeasuredResultsTo appends a MeasuredResults list to bb.
func BridgeMarshalAPERMeasuredResultsTo(list MeasuredResults, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERMeasuredResultsListValue{Value: list}
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

// MarshalAPER encodes MeasuredResultsValue to APER format.
func (v *MeasuredResultsValue) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *MeasuredResultsValue) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			return fmt.Errorf("%s known choice %d and unknown extension are both selected", "MeasuredResultsValue:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return fmt.Errorf("%s extension index %d must be non-negative", "MeasuredResultsValue:", v.UnknownExtension.Index())
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
		return fmt.Errorf("%s choice %d must be positive", "MeasuredResultsValue:", v.Choice)
	}
	isExtension := v.Choice > 5
	if err := aper.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return fmt.Errorf("%s extension choice %d not supported", "MeasuredResultsValue:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return fmt.Errorf("choice index outside root")
	}
	if err := aper.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 4); err != nil {
		return err
	}
	switch v.Choice {
	case s00.MeasuredResultsValueChoiceValueAngleOfArrival:
		if v.ValueAngleOfArrival == nil {
			return fmt.Errorf("choice alternative valueAngleOfArrival is nil")
		}
		if err := aper.EncodeIntegerAligned(bb, int64(*v.ValueAngleOfArrival), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(719), false); err != nil {
			return fmt.Errorf("encoding valueAngleOfArrival: %w", err)
		}
	case s00.MeasuredResultsValueChoiceValueTimingAdvanceType1:
		if v.ValueTimingAdvanceType1 == nil {
			return fmt.Errorf("choice alternative valueTimingAdvanceType1 is nil")
		}
		if err := aper.EncodeIntegerAligned(bb, int64(*v.ValueTimingAdvanceType1), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(7690), false); err != nil {
			return fmt.Errorf("encoding valueTimingAdvanceType1: %w", err)
		}
	case s00.MeasuredResultsValueChoiceValueTimingAdvanceType2:
		if v.ValueTimingAdvanceType2 == nil {
			return fmt.Errorf("choice alternative valueTimingAdvanceType2 is nil")
		}
		if err := aper.EncodeIntegerAligned(bb, int64(*v.ValueTimingAdvanceType2), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(7690), false); err != nil {
			return fmt.Errorf("encoding valueTimingAdvanceType2: %w", err)
		}
	case s00.MeasuredResultsValueChoiceResultRSRP:
		if err := aper.EncodeCollection(bb, int64(len(v.ResultRSRP)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_resultrsrp, fragmentLength_resultrsrp int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_resultrsrp < 0 || fragmentOffset_resultrsrp > int64(len(v.ResultRSRP)) || fragmentLength_resultrsrp < 0 || fragmentLength_resultrsrp > int64(len(v.ResultRSRP[fragmentOffset_resultrsrp:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.ResultRSRP[fragmentOffset_resultrsrp : fragmentOffset_resultrsrp+fragmentLength_resultrsrp] {
				if err := s12.BridgeResultRSRPItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding resultRSRP element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding resultRSRP: %w", err)
		}
	case s00.MeasuredResultsValueChoiceResultRSRQ:
		if err := aper.EncodeCollection(bb, int64(len(v.ResultRSRQ)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_resultrsrq, fragmentLength_resultrsrq int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_resultrsrq < 0 || fragmentOffset_resultrsrq > int64(len(v.ResultRSRQ)) || fragmentLength_resultrsrq < 0 || fragmentLength_resultrsrq > int64(len(v.ResultRSRQ[fragmentOffset_resultrsrq:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.ResultRSRQ[fragmentOffset_resultrsrq : fragmentOffset_resultrsrq+fragmentLength_resultrsrq] {
				if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
					return fmt.Errorf("encoding resultRSRQ element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding resultRSRQ: %w", err)
		}
	default:
		return fmt.Errorf("unknown MeasuredResultsValue choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes MeasuredResultsValue from APER format.
func (v *MeasuredResultsValue) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *MeasuredResultsValue) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "MeasuredResultsValue")
	}
	bb.EnterComponent("MeasuredResultsValue")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "MeasuredResultsValue")
	}
	padding, err := aper.CaptureFinalBits(bb, "MeasuredResultsValue")
	if err != nil {
		return runtime.WrapDecodePath(err, "MeasuredResultsValue")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *MeasuredResultsValue) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MeasuredResultsValue{}
	isExtension, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := aper.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := aper.DecodeChoiceExtensionAligned(bb, extIdx, 0)
		if extIdx < 0 {
			v.knownOpenBytes = max(v.knownOpenBytes, openExtension.ContentLength())
		}
		if err != nil {
			return runtime.WrapDecodePath(err, "UnknownExtension")
		}
		v.UnknownExtension = &openExtension
		v.stream = bb.CaptureWireSpan(replayStart)
		v.
			stream.RecordUsage(replayUsage,

			bb)

		return nil
	}
	idx, err := aper.DecodeConstrainedWholeNumberAligned(bb, 0, 4)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return fmt.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case s00.MeasuredResultsValueChoiceValueAngleOfArrival:
		val_valueangleofarrival, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(719), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ValueAngleOfArrival")
		}
		if err := aper.ChargeValue(bb, val_valueangleofarrival); err != nil {
			return err
		}
		v.ValueAngleOfArrival = (*int64)(bb.OwnInt64(int64(val_valueangleofarrival)))
	case s00.MeasuredResultsValueChoiceValueTimingAdvanceType1:
		val_valuetimingadvancetype1, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(7690), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ValueTimingAdvanceType1")
		}
		if err := aper.ChargeValue(bb, val_valuetimingadvancetype1); err != nil {
			return err
		}
		v.ValueTimingAdvanceType1 = (*int64)(bb.OwnInt64(int64(val_valuetimingadvancetype1)))
	case s00.MeasuredResultsValueChoiceValueTimingAdvanceType2:
		val_valuetimingadvancetype2, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(7690), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "ValueTimingAdvanceType2")
		}
		if err := aper.ChargeValue(bb, val_valuetimingadvancetype2); err != nil {
			return err
		}
		v.ValueTimingAdvanceType2 = (*int64)(bb.OwnInt64(int64(val_valuetimingadvancetype2)))
	case s00.MeasuredResultsValueChoiceResultRSRP:
		toleranceMark_resultrsrp := bb.EnterComponent("ResultRSRP")
		tmp_resultrsrp := make(s12.ResultRSRP, 0)
		_, errCollection_resultrsrp := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_resultrsrp, fragmentLength_resultrsrp int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
			if fragmentOffset_resultrsrp < 0 || fragmentLength_resultrsrp < 0 || fragmentLength_resultrsrp > int64(^uint(0)>>1) || fragmentOffset_resultrsrp > int64(^uint(0)>>1)-fragmentLength_resultrsrp {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_resultrsrp; i++ {
				var elem s12.ResultRSRPItem
				elementMark := bb.EnterIndex(fragmentOffset_resultrsrp + i)
				if err := s12.BridgeResultRSRPItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ResultRSRP[%d]", fragmentOffset_resultrsrp+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_resultrsrp, elem); err != nil {
					return err
				} else {
					tmp_resultrsrp = next
				}
			}
			return nil
		})
		if errCollection_resultrsrp != nil {
			return runtime.WrapDecodePath(errCollection_resultrsrp, "ResultRSRP")
		}
		v.ResultRSRP = tmp_resultrsrp
		bb.LeaveComponent(toleranceMark_resultrsrp)
	case s00.MeasuredResultsValueChoiceResultRSRQ:
		toleranceMark_resultrsrq := bb.EnterComponent("ResultRSRQ")
		tmp_resultrsrq := make(ResultRSRQ, 0)
		_, errCollection_resultrsrq := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_resultrsrq, fragmentLength_resultrsrq int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
			if fragmentOffset_resultrsrq < 0 || fragmentLength_resultrsrq < 0 || fragmentLength_resultrsrq > int64(^uint(0)>>1) || fragmentOffset_resultrsrq > int64(^uint(0)>>1)-fragmentLength_resultrsrq {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_resultrsrq; i++ {
				var elem ResultRSRQItem
				elementMark := bb.EnterIndex(fragmentOffset_resultrsrq + i)
				if err := elem.unmarshalAPERFrom(bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("ResultRSRQ[%d]", fragmentOffset_resultrsrq+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := aper.AppendValues(bb, tmp_resultrsrq, elem); err != nil {
					return err
				} else {
					tmp_resultrsrq = next
				}
			}
			return nil
		})
		if errCollection_resultrsrq != nil {
			return runtime.WrapDecodePath(errCollection_resultrsrq, "ResultRSRQ")
		}
		v.ResultRSRQ = tmp_resultrsrq
		bb.LeaveComponent(toleranceMark_resultrsrq)
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

type BridgeAsn1cAPERResultRSRQListValue struct{ Value ResultRSRQ }

// MarshalAPERResultRSRQTo appends a ResultRSRQ list to bb.
func BridgeMarshalAPERResultRSRQTo(list ResultRSRQ, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERResultRSRQListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ResultRSRQItem to APER format.
func (v *ResultRSRQItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ResultRSRQItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.ECGI != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.PCI, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound17, true); err != nil {
		return fmt.Errorf("encoding pCI: %w", err)
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.EARFCN, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound20, true); err != nil {
		return fmt.Errorf("encoding eARFCN: %w", err)
	}
	if v.ECGI != nil {
		if err := s05.BridgeECGIMethodMarshalAPERTo(v.ECGI, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return fmt.Errorf("encoding eCGI: %w", err)
		}
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.ValueRSRQ, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound13, true); err != nil {
		return fmt.Errorf("encoding valueRSRQ: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s04.BridgeResultRSRQItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ResultRSRQItem from APER format.
func (v *ResultRSRQItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ResultRSRQItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRQItem")
	}
	bb.EnterComponent("ResultRSRQItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRQItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ResultRSRQItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultRSRQItem")
	}
	v.perPadding = padding
	return nil
}
func (v *ResultRSRQItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultRSRQItem{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ecgi, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pci, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound17, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "PCI")
	}
	v.PCI = val_pci
	val_earfcn, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound20, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "EARFCN")
	}
	v.EARFCN = val_earfcn
	if opt_ecgi {
		toleranceMark_ecgi := bb.EnterComponent("ECGI")
		var dec_ecgi s05.ECGI
		if err := s05.BridgeECGIMethodUnmarshalAPERFrom(&dec_ecgi, bb); err != nil {
			return runtime.WrapDecodePath(err, "ECGI")
		}
		if err := aper.ChargeValue(bb, dec_ecgi); err != nil {
			return err
		}
		v.ECGI = &dec_ecgi
		bb.LeaveComponent(toleranceMark_ecgi)
	}
	val_valuersrq, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound13, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "ValueRSRQ")
	}
	v.ValueRSRQ = val_valuersrq
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s04.ResultRSRQItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s04.ResultRSRQItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s04.BridgeResultRSRQItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ECIDMeasurementResult) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ECIDMeasurementResult", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ECIDMeasurementResult) WithoutReplay() ECIDMeasurementResult {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ECIDMeasurementResult
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MeasuredResultsValue) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "MeasuredResultsValue", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MeasuredResultsValue) WithoutReplay() MeasuredResultsValue {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero MeasuredResultsValue
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultRSRQItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultRSRQItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultRSRQItem) WithoutReplay() ResultRSRQItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ResultRSRQItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ECIDMeasurementResult) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ECIDMeasurementResult) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ECIDMeasurementResult.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ECIDMeasurementResult.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ECIDMeasurementResult) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ECIDMeasurementResult.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ECIDMeasurementResult.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ResultRSRQItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ResultRSRQItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResultRSRQItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResultRSRQItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ResultRSRQItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResultRSRQItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResultRSRQItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *ECIDMeasurementResult) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ECIDMeasurementResult")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ECIDMeasurementResult")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaECIDMeasurementResult(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ECIDMeasurementResult")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ECIDMeasurementResult")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ECIDMeasurementResult")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ECIDMeasurementResult")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ECIDMeasurementResult")
}
func (v *ECIDMeasurementResult) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ECIDMeasurementResult) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ECIDMeasurementResult) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaECIDMeasurementResult(v, &s)
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
func (v *ECIDMeasurementResult) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ECIDMeasurementResult) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *MeasuredResultsValue) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "MeasuredResultsValue")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "MeasuredResultsValue")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaMeasuredResultsValue(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "MeasuredResultsValue")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "MeasuredResultsValue")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "MeasuredResultsValue")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "MeasuredResultsValue")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "MeasuredResultsValue")
}
func (v *MeasuredResultsValue) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *MeasuredResultsValue) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *MeasuredResultsValue) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaMeasuredResultsValue(v, &s)
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
func (v *MeasuredResultsValue) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *MeasuredResultsValue) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ResultRSRQItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ResultRSRQItem")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ResultRSRQItem")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaResultRSRQItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ResultRSRQItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ResultRSRQItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ResultRSRQItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ResultRSRQItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ResultRSRQItem")
}
func (v *ResultRSRQItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultRSRQItem) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultRSRQItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaResultRSRQItem(v, &s)
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
func (v *ResultRSRQItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultRSRQItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ECIDMeasurementResult) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ECIDMeasurementResult")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ECIDMeasurementResult
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaECIDMeasurementResult(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ECIDMeasurementResult{}
		return report, aper.OperationError(err, "ECIDMeasurementResult")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ECIDMeasurementResult")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *MeasuredResultsValue) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "MeasuredResultsValue")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded MeasuredResultsValue
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaMeasuredResultsValue(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = MeasuredResultsValue{}
		return report, aper.OperationError(err, "MeasuredResultsValue")
	}
	*v = decoded
	return report, aper.OperationError(nil, "MeasuredResultsValue")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultRSRQItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ResultRSRQItem")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ResultRSRQItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultRSRQItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ResultRSRQItem{}
		return report, aper.OperationError(err, "ResultRSRQItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ResultRSRQItem")
}

// NewMeasuredResultsValueValueAngleOfArrival constructs a checked complete value.
func NewMeasuredResultsValueValueAngleOfArrival(v int64, options ...aper.BuildOption) (MeasuredResultsValue, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return MeasuredResultsValue{}, aper.OperationError(err, "MeasuredResultsValueValueAngleOfArrival")
	}
	value := BridgeNewMeasuredResultsValueValueAngleOfArrivalLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return MeasuredResultsValue{}, aper.OperationError(err, "MeasuredResultsValueValueAngleOfArrival")
	}
	return value, aper.OperationError(nil, "MeasuredResultsValueValueAngleOfArrival")
}

// NewMeasuredResultsValueValueTimingAdvanceType1 constructs a checked complete value.
func NewMeasuredResultsValueValueTimingAdvanceType1(v int64, options ...aper.BuildOption) (MeasuredResultsValue, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return MeasuredResultsValue{}, aper.OperationError(err, "MeasuredResultsValueValueTimingAdvanceType1")
	}
	value := BridgeNewMeasuredResultsValueValueTimingAdvanceType1Legacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return MeasuredResultsValue{}, aper.OperationError(err, "MeasuredResultsValueValueTimingAdvanceType1")
	}
	return value, aper.OperationError(nil, "MeasuredResultsValueValueTimingAdvanceType1")
}

// NewMeasuredResultsValueValueTimingAdvanceType2 constructs a checked complete value.
func NewMeasuredResultsValueValueTimingAdvanceType2(v int64, options ...aper.BuildOption) (MeasuredResultsValue, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return MeasuredResultsValue{}, aper.OperationError(err, "MeasuredResultsValueValueTimingAdvanceType2")
	}
	value := BridgeNewMeasuredResultsValueValueTimingAdvanceType2Legacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return MeasuredResultsValue{}, aper.OperationError(err, "MeasuredResultsValueValueTimingAdvanceType2")
	}
	return value, aper.OperationError(nil, "MeasuredResultsValueValueTimingAdvanceType2")
}

// NewMeasuredResultsValueResultRSRP constructs a checked complete value.
func NewMeasuredResultsValueResultRSRP(v s12.ResultRSRP, options ...aper.BuildOption) (MeasuredResultsValue, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return MeasuredResultsValue{}, aper.OperationError(err, "MeasuredResultsValueResultRSRP")
	}
	value := BridgeNewMeasuredResultsValueResultRSRPLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return MeasuredResultsValue{}, aper.OperationError(err, "MeasuredResultsValueResultRSRP")
	}
	return value, aper.OperationError(nil, "MeasuredResultsValueResultRSRP")
}

// NewMeasuredResultsValueResultRSRQ constructs a checked complete value.
func NewMeasuredResultsValueResultRSRQ(v ResultRSRQ, options ...aper.BuildOption) (MeasuredResultsValue, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return MeasuredResultsValue{}, aper.OperationError(err, "MeasuredResultsValueResultRSRQ")
	}
	value := BridgeNewMeasuredResultsValueResultRSRQLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return MeasuredResultsValue{}, aper.OperationError(err, "MeasuredResultsValueResultRSRQ")
	}
	return value, aper.OperationError(nil, "MeasuredResultsValueResultRSRQ")
}

// NewMeasuredResultsValueUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewMeasuredResultsValueUnknownExtension(index uint64, contents []byte, options ...aper.BuildOption) (MeasuredResultsValue, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return MeasuredResultsValue{}, aper.OperationError(err, "MeasuredResultsValueUnknownExtension")
	}
	extension, err := aper.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return MeasuredResultsValue{}, aper.OperationError(err, "MeasuredResultsValueUnknownExtension")
	}
	value := MeasuredResultsValue{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return MeasuredResultsValue{}, aper.OperationError(err, "MeasuredResultsValueUnknownExtension")
	}
	return value, aper.OperationError(nil, "MeasuredResultsValueUnknownExtension")
}

// ECIDMeasurementReport represents the ASN.1 type E-CIDMeasurementReport (SEQUENCE).
type ECIDMeasurementReport struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    aper.WireSpan
	ProtocolIEs      ECIDMeasurementReportIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                             `asn1:"-" json:"-"`
	extCount         int64                            `asn1:"-" json:"-"`
	extPresent       []bool                           `asn1:"-" json:"-"`
	extData          [][]byte                         `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding           `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes ECIDMeasurementReport to APER format.
func (v *ECIDMeasurementReport) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ECIDMeasurementReport) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.
			RestoreReplayPlan(previous)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.
			replay.
			ReplayTo(v.stream, bb); ok ||
			err !=
				nil {
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
	if err := aper.EncodeCollection(bb, int64(len(v.ProtocolIEs)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding protocolIEs: %w", err)
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

// UnmarshalAPER decodes ECIDMeasurementReport from APER format.
func (v *ECIDMeasurementReport) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ECIDMeasurementReport) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementReport")
	}
	bb.EnterComponent("ECIDMeasurementReport")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementReport")
	}
	padding, err := aper.CaptureFinalBits(bb, "ECIDMeasurementReport")
	if err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementReport")
	}
	v.perPadding = padding
	return nil
}
func (v *ECIDMeasurementReport) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementReport{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(ECIDMeasurementReportIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ECIDMeasurementReportIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return runtime.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	bb.LeaveComponent(toleranceMark_protocolies)
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
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
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
	v.stream.RecordUsage(replayUsage,

		bb,
	)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ECIDMeasurementReport) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ECIDMeasurementReport", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ECIDMeasurementReport) WithoutReplay() ECIDMeasurementReport {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ECIDMeasurementReport
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ECIDMeasurementReport) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ECIDMeasurementReport) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ECIDMeasurementReport.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ECIDMeasurementReport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ECIDMeasurementReport) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ECIDMeasurementReport.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ECIDMeasurementReport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *ECIDMeasurementReport) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ECIDMeasurementReport")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ECIDMeasurementReport")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaECIDMeasurementReport(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ECIDMeasurementReport")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ECIDMeasurementReport")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ECIDMeasurementReport")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ECIDMeasurementReport")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ECIDMeasurementReport")
}
func (v *ECIDMeasurementReport) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ECIDMeasurementReport) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ECIDMeasurementReport) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaECIDMeasurementReport(v, &s)
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
func (v *ECIDMeasurementReport) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ECIDMeasurementReport) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ECIDMeasurementReport) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ECIDMeasurementReport")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ECIDMeasurementReport
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaECIDMeasurementReport(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ECIDMeasurementReport{}
		return report, aper.OperationError(err, "ECIDMeasurementReport")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ECIDMeasurementReport")
}
func BridgeCaptureLPPaECIDMeasurementReport(v *ECIDMeasurementReport, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgeECIDMeasurementReportIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaECIDMeasurementReport(v *ECIDMeasurementReport, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeECIDMeasurementReportIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaECIDMeasurementReportIEValue(v *ECIDMeasurementReportIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(7):
			{
				f := s.Begin()
				s.Bool(v.rowECIDMeasurementResult == nil)
				if v.rowECIDMeasurementResult != nil {
					BridgeCaptureLPPaECIDMeasurementResult(v.rowECIDMeasurementResult, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(14):
			{
				f := s.Begin()
				s.Bool(v.rowCellPortionID == nil)
				if v.rowCellPortionID != nil {
					s00.BridgeCaptureLPPaCellPortionID(v.rowCellPortionID, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ECIDMeasurementReportIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v ECIDMeasurementReportIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ECIDMeasurementReportIEValue) captureSemantics(s aper.SemanticCapture) ECIDMeasurementReportIEValue {
	BridgeCaptureLPPaECIDMeasurementReportIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaECIDMeasurementReportIEValue(v *ECIDMeasurementReportIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowESMLCUEMeasurementID == nil)
				if v.rowESMLCUEMeasurementID != nil {
					s02.BridgeCompareLPPaMeasurementID(v.rowESMLCUEMeasurementID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(6):
			{
				f := s.Begin()
				s.Bool(v.rowENBUEMeasurementID == nil)
				if v.rowENBUEMeasurementID != nil {
					s02.BridgeCompareLPPaMeasurementID(v.rowENBUEMeasurementID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(7):
			{
				f := s.Begin()
				s.Bool(v.rowECIDMeasurementResult == nil)
				if v.rowECIDMeasurementResult != nil {
					BridgeCompareLPPaECIDMeasurementResult(v.rowECIDMeasurementResult, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(14):
			{
				f := s.Begin()
				s.Bool(v.rowCellPortionID == nil)
				if v.rowCellPortionID != nil {
					s02.BridgeCompareLPPaCellPortionID(v.rowCellPortionID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v ECIDMeasurementReportIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaECIDMeasurementReportIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECIDMeasurementReportIEValue) WithoutReplay() ECIDMeasurementReportIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaECIDMeasurementResult(v *ECIDMeasurementResult, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s05.BridgeCaptureLPPaECGI(&v.ServingCellID, s)
	s00.BridgeCaptureLPPaTAC(&v.ServingCellTAC, s)
	{
		f := s.Begin()
		s.Bool(v.EUTRANAccessPointPosition == nil)
		if v.EUTRANAccessPointPosition != nil {
			s06.BridgeCaptureLPPaEUTRANAccessPointPosition(v.EUTRANAccessPointPosition, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.MeasuredResults == nil)
	BridgeCaptureLPPaMeasuredResults(&v.MeasuredResults, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaECIDMeasurementResult(v *ECIDMeasurementResult, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s05.BridgeCompareLPPaECGI(&v.ServingCellID, s)
	s03.BridgeCompareLPPaTAC(&v.ServingCellTAC, s)
	{
		f := s.Begin()
		s.Bool(v.EUTRANAccessPointPosition == nil)
		if v.EUTRANAccessPointPosition != nil {
			s06.BridgeCompareLPPaEUTRANAccessPointPosition(v.EUTRANAccessPointPosition, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.MeasuredResults == nil)
	BridgeCompareLPPaMeasuredResults(&v.MeasuredResults, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaMeasuredResults(v *MeasuredResults, s *aper.SemanticCapture) {
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
			BridgeCaptureLPPaMeasuredResultsValue(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaMeasuredResults(v *MeasuredResults, s *aper.SemanticComparison) {
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
			BridgeCompareLPPaMeasuredResultsValue(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaMeasuredResultsValue(v *MeasuredResultsValue, s *aper.SemanticCapture) {
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
	case s00.MeasuredResultsValueChoiceValueAngleOfArrival:
		{
			f := s.Begin()
			s.Bool(v.ValueAngleOfArrival == nil)
			if v.ValueAngleOfArrival != nil {
				s.Int(int64((*v.ValueAngleOfArrival)))
			}
			s.End(f, nil, false)
		}
	case s00.MeasuredResultsValueChoiceValueTimingAdvanceType1:
		{
			f := s.Begin()
			s.Bool(v.ValueTimingAdvanceType1 == nil)
			if v.ValueTimingAdvanceType1 != nil {
				s.Int(int64((*v.ValueTimingAdvanceType1)))
			}
			s.End(f, nil, false)
		}
	case s00.MeasuredResultsValueChoiceValueTimingAdvanceType2:
		{
			f := s.Begin()
			s.Bool(v.ValueTimingAdvanceType2 == nil)
			if v.ValueTimingAdvanceType2 != nil {
				s.Int(int64((*v.ValueTimingAdvanceType2)))
			}
			s.End(f, nil, false)
		}
	case s00.MeasuredResultsValueChoiceResultRSRP:
		s12.BridgeCaptureLPPaResultRSRP(&v.ResultRSRP, s)
	case s00.MeasuredResultsValueChoiceResultRSRQ:
		BridgeCaptureLPPaResultRSRQ(&v.ResultRSRQ, s)
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaMeasuredResultsValue(v *MeasuredResultsValue, s *aper.SemanticComparison) {
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
	case s00.MeasuredResultsValueChoiceValueAngleOfArrival:
		{
			f := s.Begin()
			s.Bool(v.ValueAngleOfArrival == nil)
			if v.ValueAngleOfArrival != nil {
				s.Int(int64((*v.ValueAngleOfArrival)))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.MeasuredResultsValueChoiceValueTimingAdvanceType1:
		{
			f := s.Begin()
			s.Bool(v.ValueTimingAdvanceType1 == nil)
			if v.ValueTimingAdvanceType1 != nil {
				s.Int(int64((*v.ValueTimingAdvanceType1)))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.MeasuredResultsValueChoiceValueTimingAdvanceType2:
		{
			f := s.Begin()
			s.Bool(v.ValueTimingAdvanceType2 == nil)
			if v.ValueTimingAdvanceType2 != nil {
				s.Int(int64((*v.ValueTimingAdvanceType2)))
			}
			s.End(f, aper.Snapshot{}, false)
		}
	case s00.MeasuredResultsValueChoiceResultRSRP:
		s12.BridgeCompareLPPaResultRSRP(&v.ResultRSRP, s)
	case s00.MeasuredResultsValueChoiceResultRSRQ:
		BridgeCompareLPPaResultRSRQ(&v.ResultRSRQ, s)
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultRSRQ(v *ResultRSRQ, s *aper.SemanticCapture) {
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
			BridgeCaptureLPPaResultRSRQItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaResultRSRQ(v *ResultRSRQ, s *aper.SemanticComparison) {
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
			BridgeCompareLPPaResultRSRQItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaResultRSRQItem(v *ResultRSRQItem, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaPCI(&v.PCI, s)
	s00.BridgeCaptureLPPaEARFCN(&v.EARFCN, s)
	{
		f := s.Begin()
		s.Bool(v.ECGI == nil)
		if v.ECGI != nil {
			s05.BridgeCaptureLPPaECGI(v.ECGI, s)
		}
		s.End(f, nil, false)
	}
	s00.BridgeCaptureLPPaValueRSRQ(&v.ValueRSRQ, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeResultRSRQItemExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultRSRQItem(v *ResultRSRQItem, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaPCI(&v.PCI, s)
	s02.BridgeCompareLPPaEARFCN(&v.EARFCN, s)
	{
		f := s.Begin()
		s.Bool(v.ECGI == nil)
		if v.ECGI != nil {
			s05.BridgeCompareLPPaECGI(v.ECGI, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s03.BridgeCompareLPPaValueRSRQ(&v.ValueRSRQ, s)
	s.Bool(v.IEExtensions == nil)
	s12.BridgeResultRSRQItemExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}

type ECIDMeasurementReportIEValue struct {
	id                       s00.ProtocolIEID
	withoutReplay            bool
	received                 aper.WireSpan
	replay                   aper.Snapshot
	opaque                   *aper.OpaqueOpenType
	isOpaque                 bool
	rowESMLCUEMeasurementID  *s00.MeasurementID
	rowENBUEMeasurementID    *s00.MeasurementID
	rowECIDMeasurementResult *ECIDMeasurementResult
	rowCellPortionID         *s00.CellPortionID
}

func (v ECIDMeasurementReportIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(7):
		return v.rowECIDMeasurementResult != nil
	case s00.ProtocolIEID(14):
		return v.rowCellPortionID != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *ECIDMeasurementReportIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ECIDMeasurementReportIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementReport-IEs"}}
}
func (ECIDMeasurementReportIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(6):
		return aper.UnknownSelector
	case s00.ProtocolIEID(7):
		return aper.UnknownSelector
	case s00.ProtocolIEID(14):
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
func (v *ECIDMeasurementReportIEValue) AsESMLCUEMeasurementID() (*s00.MeasurementID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowESMLCUEMeasurementID == nil {
		return nil, false
	}
	return v.rowESMLCUEMeasurementID, true
}

// AsENBUEMeasurementID returns the selected ENBUEMeasurementID value and reports whether that alternative is active.
func (v *ECIDMeasurementReportIEValue) AsENBUEMeasurementID() (*s00.MeasurementID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(6) || v.rowENBUEMeasurementID == nil {
		return nil, false
	}
	return v.rowENBUEMeasurementID, true
}

// AsECIDMeasurementResult returns the selected ECIDMeasurementResult value and reports whether that alternative is active.
func (v *ECIDMeasurementReportIEValue) AsECIDMeasurementResult() (*ECIDMeasurementResult, bool) {
	if v == nil || v.id != s00.ProtocolIEID(7) || v.rowECIDMeasurementResult == nil {
		return nil, false
	}
	return v.rowECIDMeasurementResult, true
}

// AsCellPortionID returns the selected CellPortionID value and reports whether that alternative is active.
func (v *ECIDMeasurementReportIEValue) AsCellPortionID() (*s00.CellPortionID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(14) || v.rowCellPortionID == nil {
		return nil, false
	}
	return v.rowCellPortionID, true
}
func (v ECIDMeasurementReportIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ECIDMeasurementReportIEValue, error) {
	out := ECIDMeasurementReportIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 2, 6, 7, 14:
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
	case s00.ProtocolIEID(7):
		replayUsage := scope.Usage()
		var value ECIDMeasurementResult
		child := raw.ChildDecodeBuffer()
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "ECIDMeasurementResult:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ECIDMeasurementResult")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowECIDMeasurementResult = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case s00.ProtocolIEID(14):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound12, true)
		value := s00.CellPortionID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CellPortionID:", err)
		}
		if _, err := aper.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCellPortionID = &value
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
func (v ECIDMeasurementReportIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ECIDMeasurementReportIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementReport-IEs.id-E-SMLC-UE-Measurement-ID:")
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
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementReport-IEs.id-eNB-UE-Measurement-ID:")
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
	case s00.ProtocolIEID(7):
		if v.rowECIDMeasurementResult == nil {
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementReport-IEs.id-E-CID-MeasurementResult:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := v.rowECIDMeasurementResult.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(14):
		if v.rowCellPortionID == nil {
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementReport-IEs.id-Cell-Portion-ID:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerBigBoundsAligned(encodeBB, *v.rowCellPortionID, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound12, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ECIDMeasurementReportIEValue:", v.id)
	}
}

type ECIDMeasurementReportIETable struct{}

func ECIDMeasurementReportIEs() ECIDMeasurementReportIETable { return ECIDMeasurementReportIETable{} }

// ID returns the ASN.1 source assignment identifying this table.
func (ECIDMeasurementReportIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementReport-IEs"}
		return sealed
	}()
}
func (ECIDMeasurementReportIETable) infoESMLCUEMeasurementID() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementReportIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementReport-IEs", Row: "id-E-SMLC-UE-Measurement-ID"}}}
}

// ESMLCUEMeasurementID returns the typed binding for the ESMLCUEMeasurementID row of this table.
func (t ECIDMeasurementReportIETable) ESMLCUEMeasurementID() ECIDMeasurementReportMeasurementIDIEBinding {
	return ECIDMeasurementReportMeasurementIDIEBinding{info: t.infoESMLCUEMeasurementID(), codec: func() s00.MeasurementIDValueCodec {
		sealed := s00.MeasurementIDValueCodec{}
		*s00.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*s00.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MeasurementID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MeasurementID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MeasurementID")
			var zero ECIDMeasurementReportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s00.MeasurementID
				return empty, runtime.WrapDecodePath(err, "MeasurementID")
			}
			value, ok := decoded.AsESMLCUEMeasurementID()
			if !ok {
				var empty s00.MeasurementID
				return empty, fmt.Errorf("binding E-CIDMeasurementReport-IEs.id-E-SMLC-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value s00.MeasurementID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementReportIEValue{id: s00.ProtocolIEID(2), rowESMLCUEMeasurementID: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeMeasurementIDValueCodecFieldCapture(&sealed) = func(v s00.MeasurementID, options aper.DecodeState) (s00.MeasurementID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaMeasurementID(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeMeasurementIDValueCodecFieldCompare(&sealed) = func(v s00.MeasurementID, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s02.BridgeCompareLPPaMeasurementID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeMeasurementIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementID"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MeasurementID) ECIDMeasurementReportIEValue {
			return ECIDMeasurementReportIEValue{id: s00.ProtocolIEID(2), rowESMLCUEMeasurementID: &value}
		}, get: func(value *ECIDMeasurementReportIEValue) (*s00.MeasurementID, bool) {
			return value.AsESMLCUEMeasurementID()
		}}
}
func (ECIDMeasurementReportIETable) infoENBUEMeasurementID() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementReportIEs().ID(), ID: s00.ProtocolIEID(6), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementReport-IEs", Row: "id-eNB-UE-Measurement-ID"}}}
}

// ENBUEMeasurementID returns the typed binding for the ENBUEMeasurementID row of this table.
func (t ECIDMeasurementReportIETable) ENBUEMeasurementID() ECIDMeasurementReportMeasurementIDIEBinding {
	return ECIDMeasurementReportMeasurementIDIEBinding{info: t.infoENBUEMeasurementID(), codec: func() s00.MeasurementIDValueCodec {
		sealed := s00.MeasurementIDValueCodec{}
		*s00.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*s00.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MeasurementID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MeasurementID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MeasurementID")
			var zero ECIDMeasurementReportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(6), raw)
			if err != nil {
				var empty s00.MeasurementID
				return empty, runtime.WrapDecodePath(err, "MeasurementID")
			}
			value, ok := decoded.AsENBUEMeasurementID()
			if !ok {
				var empty s00.MeasurementID
				return empty, fmt.Errorf("binding E-CIDMeasurementReport-IEs.id-eNB-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value s00.MeasurementID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementReportIEValue{id: s00.ProtocolIEID(6), rowENBUEMeasurementID: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeMeasurementIDValueCodecFieldCapture(&sealed) = func(v s00.MeasurementID, options aper.DecodeState) (s00.MeasurementID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaMeasurementID(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeMeasurementIDValueCodecFieldCompare(&sealed) = func(v s00.MeasurementID, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s02.BridgeCompareLPPaMeasurementID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeMeasurementIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementID"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MeasurementID) ECIDMeasurementReportIEValue {
			return ECIDMeasurementReportIEValue{id: s00.ProtocolIEID(6), rowENBUEMeasurementID: &value}
		}, get: func(value *ECIDMeasurementReportIEValue) (*s00.MeasurementID, bool) {
			return value.AsENBUEMeasurementID()
		}}
}
func (ECIDMeasurementReportIETable) infoECIDMeasurementResult() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementReportIEs().ID(), ID: s00.ProtocolIEID(7), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ECIDMeasurementResult"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementReport-IEs", Row: "id-E-CID-MeasurementResult"}}}
}

// ECIDMeasurementResult returns the typed binding for the ECIDMeasurementResult row of this table.
func (t ECIDMeasurementReportIETable) ECIDMeasurementResult() ECIDMeasurementReportECIDMeasurementResultIEBinding {
	return ECIDMeasurementReportECIDMeasurementResultIEBinding{info: t.infoECIDMeasurementResult(), codec: ECIDMeasurementResultValueCodec{path: "ECIDMeasurementResult",
		decode: func(data []byte, options aper.DecodeState) (ECIDMeasurementResult, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ECIDMeasurementResult
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ECIDMeasurementResult")
			var zero ECIDMeasurementReportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(7), raw)
			if err != nil {
				var empty ECIDMeasurementResult
				return empty, runtime.WrapDecodePath(err, "ECIDMeasurementResult")
			}
			value, ok := decoded.AsECIDMeasurementResult()
			if !ok {
				var empty ECIDMeasurementResult
				return empty, fmt.Errorf("binding E-CIDMeasurementReport-IEs.id-E-CID-MeasurementResult: no selected value")
			}
			return *value, nil
		},
		encode: func(value ECIDMeasurementResult, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementReportIEValue{id: s00.ProtocolIEID(7), rowECIDMeasurementResult: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ECIDMeasurementResult, options aper.DecodeState) (ECIDMeasurementResult, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureLPPaECIDMeasurementResult(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}, compare: func(v ECIDMeasurementResult, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaECIDMeasurementResult(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ECIDMeasurementResult"
			return sealed
		}(),
	}, inject: func(value ECIDMeasurementResult) ECIDMeasurementReportIEValue {
		return ECIDMeasurementReportIEValue{id: s00.ProtocolIEID(7), rowECIDMeasurementResult: &value}
	}, get: func(value *ECIDMeasurementReportIEValue) (*ECIDMeasurementResult, bool) {
		return value.AsECIDMeasurementResult()
	}}
}
func (ECIDMeasurementReportIETable) infoCellPortionID() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementReportIEs().ID(), ID: s00.ProtocolIEID(14), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "CellPortionID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementReport-IEs", Row: "id-Cell-Portion-ID"}}}
}

// CellPortionID returns the typed binding for the CellPortionID row of this table.
func (t ECIDMeasurementReportIETable) CellPortionID() ECIDMeasurementReportCellPortionIDIEBinding {
	return ECIDMeasurementReportCellPortionIDIEBinding{info: t.infoCellPortionID(), codec: func() s00.CellPortionIDValueCodec {
		sealed := s00.CellPortionIDValueCodec{}
		*s00.BridgeCellPortionIDValueCodecFieldPath(&sealed) = "CellPortionID"
		*s00.BridgeCellPortionIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CellPortionID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CellPortionID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CellPortionID")
			var zero ECIDMeasurementReportIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(14), raw)
			if err != nil {
				var empty s00.CellPortionID
				return empty, runtime.WrapDecodePath(err, "CellPortionID")
			}
			value, ok := decoded.AsCellPortionID()
			if !ok {
				var empty s00.CellPortionID
				return empty, fmt.Errorf("binding E-CIDMeasurementReport-IEs.id-Cell-Portion-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCellPortionIDValueCodecFieldEncode(&sealed) = func(value s00.CellPortionID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementReportIEValue{id: s00.ProtocolIEID(14), rowCellPortionID: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCellPortionIDValueCodecFieldCapture(&sealed) = func(v s00.CellPortionID, options aper.DecodeState) (s00.CellPortionID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureLPPaCellPortionID(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCellPortionIDValueCodecFieldCompare(&sealed) = func(v s00.CellPortionID, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s02.BridgeCompareLPPaCellPortionID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeCellPortionIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CellPortionID"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CellPortionID) ECIDMeasurementReportIEValue {
			return ECIDMeasurementReportIEValue{id: s00.ProtocolIEID(14), rowCellPortionID: &value}
		}, get: func(value *ECIDMeasurementReportIEValue) (*s00.CellPortionID, bool) { return value.AsCellPortionID() }}
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t ECIDMeasurementReportIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ECIDMeasurementReportIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ECIDMeasurementReportIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(2):
		return ECIDMeasurementReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-SMLC-UE-Measurement-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(6):
		return ECIDMeasurementReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-Measurement-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(7):
		return ECIDMeasurementReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-CID-MeasurementResult requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(14):
		return ECIDMeasurementReportIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cell-Portion-ID requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ECIDMeasurementReportIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ECIDMeasurementReportIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ECIDMeasurementReportIEField{}, aper.OperationError(err, "Opaque")
		}
		return ECIDMeasurementReportIEField{Id: id, Criticality: criticality, Value: ECIDMeasurementReportIEValue{id: id, opaque: retained, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// MeasuredResultsValueCodec binds the complete source value type.
func MeasuredResultsValueCodec() MeasuredResultsValueValueCodec {
	return MeasuredResultsValueValueCodec{path: "MeasuredResultsValue", decode: func(data []byte, options aper.DecodeState) (MeasuredResultsValue, error) {
		var value MeasuredResultsValue
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return MeasuredResultsValue{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value MeasuredResultsValue, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v MeasuredResultsValue, options aper.DecodeState) (MeasuredResultsValue, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaMeasuredResultsValue(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v MeasuredResultsValue, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaMeasuredResultsValue(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MeasuredResultsValue"
		return sealed
	}(),
	}
}

// ResultRSRQItemCodec binds the complete source value type.
func ResultRSRQItemCodec() ResultRSRQItemValueCodec {
	return ResultRSRQItemValueCodec{path: "ResultRSRQItem", decode: func(data []byte, options aper.DecodeState) (ResultRSRQItem, error) {
		var value ResultRSRQItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ResultRSRQItem{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ResultRSRQItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ResultRSRQItem, options aper.DecodeState) (ResultRSRQItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaResultRSRQItem(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResultRSRQItem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaResultRSRQItem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ResultRSRQItem"
		return sealed
	}(),
	}
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives that share a Go type.
func (v *ECIDMeasurementReportIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 2:
		if v.rowESMLCUEMeasurementID != nil {
			return v.rowESMLCUEMeasurementID, true
		}
	case 6:
		if v.rowENBUEMeasurementID != nil {
			return v.rowENBUEMeasurementID, true
		}
	case 7:
		if v.rowECIDMeasurementResult != nil {
			return v.rowECIDMeasurementResult, true
		}
	case 14:
		if v.rowCellPortionID != nil {
			return v.rowCellPortionID, true
		}
	}
	return nil, false
}

func BridgeECIDMeasurementReportAPERValueFieldContext(v *ECIDMeasurementReportAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementReportAPERValueFieldReceived(v *ECIDMeasurementReportAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementReportAPERValueFieldReplay(v *ECIDMeasurementReportAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementReportAPERValueFieldWithoutReplay(v *ECIDMeasurementReportAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementReportCellPortionIDIEBindingFieldCodec(v *ECIDMeasurementReportCellPortionIDIEBinding) *s00.CellPortionIDValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementReportCellPortionIDIEBindingFieldGet(v *ECIDMeasurementReportCellPortionIDIEBinding) *func(*ECIDMeasurementReportIEValue) (*s00.CellPortionID, bool) {
	return &v.get
}
func BridgeECIDMeasurementReportCellPortionIDIEBindingFieldInfo(v *ECIDMeasurementReportCellPortionIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementReportCellPortionIDIEBindingFieldInject(v *ECIDMeasurementReportCellPortionIDIEBinding) *func(s00.CellPortionID) ECIDMeasurementReportIEValue {
	return &v.inject
}
func BridgeECIDMeasurementReportECIDMeasurementResultIEBindingFieldCodec(v *ECIDMeasurementReportECIDMeasurementResultIEBinding) *ECIDMeasurementResultValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementReportECIDMeasurementResultIEBindingFieldGet(v *ECIDMeasurementReportECIDMeasurementResultIEBinding) *func(*ECIDMeasurementReportIEValue) (*ECIDMeasurementResult, bool) {
	return &v.get
}
func BridgeECIDMeasurementReportECIDMeasurementResultIEBindingFieldInfo(v *ECIDMeasurementReportECIDMeasurementResultIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementReportECIDMeasurementResultIEBindingFieldInject(v *ECIDMeasurementReportECIDMeasurementResultIEBinding) *func(ECIDMeasurementResult) ECIDMeasurementReportIEValue {
	return &v.inject
}
func BridgeECIDMeasurementReportFieldExtCount(v *ECIDMeasurementReport) *int64   { return &v.extCount }
func BridgeECIDMeasurementReportFieldExtData(v *ECIDMeasurementReport) *[][]byte { return &v.extData }
func BridgeECIDMeasurementReportFieldExtOrigin(v *ECIDMeasurementReport) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeECIDMeasurementReportFieldExtPresent(v *ECIDMeasurementReport) *[]bool {
	return &v.extPresent
}
func BridgeECIDMeasurementReportFieldExtWire(v *ECIDMeasurementReport) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeECIDMeasurementReportFieldPerExtPadding(v *ECIDMeasurementReport) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeECIDMeasurementReportFieldPerPadding(v *ECIDMeasurementReport) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeECIDMeasurementReportFieldProtocolIEsIndef(v *ECIDMeasurementReport) *bool {
	return &v.protocolIEsIndef
}
func BridgeECIDMeasurementReportFieldReceived(v *ECIDMeasurementReport) *bool { return &v.received }
func BridgeECIDMeasurementReportFieldReceivedBytes(v *ECIDMeasurementReport) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeECIDMeasurementReportFieldReplay(v *ECIDMeasurementReport) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementReportFieldStream(v *ECIDMeasurementReport) *aper.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementReportFieldWithoutReplay(v *ECIDMeasurementReport) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementReportIEFieldFieldReceived(v *ECIDMeasurementReportIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeECIDMeasurementReportIEFieldFieldReplay(v *ECIDMeasurementReportIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementReportIEFieldFieldStream(v *ECIDMeasurementReportIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementReportIEFieldFieldWithoutReplay(v *ECIDMeasurementReportIEField) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementReportIEFieldMethodMarshalAPERTo(v *ECIDMeasurementReportIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementReportIEFieldMethodUnmarshalAPERFrom(v *ECIDMeasurementReportIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementReportIETableMethodInfoCellPortionID(v ECIDMeasurementReportIETable) s00.FieldInfo {
	return v.infoCellPortionID()
}
func BridgeECIDMeasurementReportIETableMethodInfoECIDMeasurementResult(v ECIDMeasurementReportIETable) s00.FieldInfo {
	return v.infoECIDMeasurementResult()
}
func BridgeECIDMeasurementReportIETableMethodInfoENBUEMeasurementID(v ECIDMeasurementReportIETable) s00.FieldInfo {
	return v.infoENBUEMeasurementID()
}
func BridgeECIDMeasurementReportIETableMethodInfoESMLCUEMeasurementID(v ECIDMeasurementReportIETable) s00.FieldInfo {
	return v.infoESMLCUEMeasurementID()
}
func BridgeECIDMeasurementReportIEValueFieldId(v *ECIDMeasurementReportIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeECIDMeasurementReportIEValueFieldIsOpaque(v *ECIDMeasurementReportIEValue) *bool {
	return &v.isOpaque
}
func BridgeECIDMeasurementReportIEValueFieldOpaque(v *ECIDMeasurementReportIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeECIDMeasurementReportIEValueFieldReceived(v *ECIDMeasurementReportIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementReportIEValueFieldReplay(v *ECIDMeasurementReportIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementReportIEValueFieldRowCellPortionID(v *ECIDMeasurementReportIEValue) **s00.CellPortionID {
	return &v.rowCellPortionID
}
func BridgeECIDMeasurementReportIEValueFieldRowECIDMeasurementResult(v *ECIDMeasurementReportIEValue) **ECIDMeasurementResult {
	return &v.rowECIDMeasurementResult
}
func BridgeECIDMeasurementReportIEValueFieldRowENBUEMeasurementID(v *ECIDMeasurementReportIEValue) **s00.MeasurementID {
	return &v.rowENBUEMeasurementID
}
func BridgeECIDMeasurementReportIEValueFieldRowESMLCUEMeasurementID(v *ECIDMeasurementReportIEValue) **s00.MeasurementID {
	return &v.rowESMLCUEMeasurementID
}
func BridgeECIDMeasurementReportIEValueFieldWithoutReplay(v *ECIDMeasurementReportIEValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementReportIEValueMethodCaptureFraming(v ECIDMeasurementReportIEValue) uint64 {
	return v.captureFraming()
}
func BridgeECIDMeasurementReportIEValueMethodCaptureSemantics(v ECIDMeasurementReportIEValue, a0 aper.SemanticCapture) ECIDMeasurementReportIEValue {
	return v.captureSemantics(a0)
}
func BridgeECIDMeasurementReportIEValueMethodCaptureSnapshot(v ECIDMeasurementReportIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeECIDMeasurementReportIEValueMethodCompareSemantics(v ECIDMeasurementReportIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeECIDMeasurementReportIEValueMethodDecode(v ECIDMeasurementReportIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ECIDMeasurementReportIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeECIDMeasurementReportIEValueMethodEncode(v ECIDMeasurementReportIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeECIDMeasurementReportIEValueMethodEncodeFresh(v ECIDMeasurementReportIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeECIDMeasurementReportIEValueMethodMatchesID(v ECIDMeasurementReportIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeECIDMeasurementReportIEValueMethodReason(v ECIDMeasurementReportIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeECIDMeasurementReportIEValueMethodRule(v ECIDMeasurementReportIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeECIDMeasurementReportMeasurementIDIEBindingFieldCodec(v *ECIDMeasurementReportMeasurementIDIEBinding) *s00.MeasurementIDValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementReportMeasurementIDIEBindingFieldGet(v *ECIDMeasurementReportMeasurementIDIEBinding) *func(*ECIDMeasurementReportIEValue) (*s00.MeasurementID, bool) {
	return &v.get
}
func BridgeECIDMeasurementReportMeasurementIDIEBindingFieldInfo(v *ECIDMeasurementReportMeasurementIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementReportMeasurementIDIEBindingFieldInject(v *ECIDMeasurementReportMeasurementIDIEBinding) *func(s00.MeasurementID) ECIDMeasurementReportIEValue {
	return &v.inject
}
func BridgeECIDMeasurementReportMethodMarshalAPERBudget(v *ECIDMeasurementReport, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeECIDMeasurementReportMethodMarshalAPERChanged(v *ECIDMeasurementReport, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeECIDMeasurementReportMethodMarshalAPERChangedValue(v *ECIDMeasurementReport, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeECIDMeasurementReportMethodMarshalAPERFreshValue(v *ECIDMeasurementReport, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeECIDMeasurementReportMethodMarshalAPERLegacy(v *ECIDMeasurementReport) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeECIDMeasurementReportMethodMarshalAPERPlanned(v *ECIDMeasurementReport, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeECIDMeasurementReportMethodMarshalAPERTo(v *ECIDMeasurementReport, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementReportMethodUnmarshalAPERFrom(v *ECIDMeasurementReport, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementReportMethodUnmarshalAPERLegacy(v *ECIDMeasurementReport, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeECIDMeasurementReportMethodUnmarshalAPERWithOptions(v *ECIDMeasurementReport, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeECIDMeasurementReportValueCodecFieldCapture(v *ECIDMeasurementReportValueCodec) *func(ECIDMeasurementReport, aper.DecodeState) (ECIDMeasurementReport, aper.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementReportValueCodecFieldCompare(v *ECIDMeasurementReportValueCodec) *func(ECIDMeasurementReport, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementReportValueCodecFieldContext(v *ECIDMeasurementReportValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementReportValueCodecFieldDecode(v *ECIDMeasurementReportValueCodec) *func([]byte, aper.DecodeState) (ECIDMeasurementReport, error) {
	return &v.decode
}
func BridgeECIDMeasurementReportValueCodecFieldEncode(v *ECIDMeasurementReportValueCodec) *func(ECIDMeasurementReport, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementReportValueCodecFieldPath(v *ECIDMeasurementReportValueCodec) *aper.Path {
	return &v.path
}
func BridgeECIDMeasurementReportValueCodecMethodEncodeBudget(v ECIDMeasurementReportValueCodec, a0 ECIDMeasurementReport, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeECIDMeasurementReportValueCodecMethodEncodeChanged(v ECIDMeasurementReportValueCodec, a0 ECIDMeasurementReport, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeECIDMeasurementResultAPERValueFieldContext(v *ECIDMeasurementResultAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementResultAPERValueFieldReceived(v *ECIDMeasurementResultAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementResultAPERValueFieldReplay(v *ECIDMeasurementResultAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementResultAPERValueFieldWithoutReplay(v *ECIDMeasurementResultAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementResultFieldExtCount(v *ECIDMeasurementResult) *int64   { return &v.extCount }
func BridgeECIDMeasurementResultFieldExtData(v *ECIDMeasurementResult) *[][]byte { return &v.extData }
func BridgeECIDMeasurementResultFieldExtOrigin(v *ECIDMeasurementResult) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeECIDMeasurementResultFieldExtPresent(v *ECIDMeasurementResult) *[]bool {
	return &v.extPresent
}
func BridgeECIDMeasurementResultFieldExtWire(v *ECIDMeasurementResult) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeECIDMeasurementResultFieldMeasuredResultsIndef(v *ECIDMeasurementResult) *bool {
	return &v.measuredResultsIndef
}
func BridgeECIDMeasurementResultFieldPerExtPadding(v *ECIDMeasurementResult) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeECIDMeasurementResultFieldPerPadding(v *ECIDMeasurementResult) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeECIDMeasurementResultFieldReceived(v *ECIDMeasurementResult) *bool { return &v.received }
func BridgeECIDMeasurementResultFieldReceivedBytes(v *ECIDMeasurementResult) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeECIDMeasurementResultFieldReplay(v *ECIDMeasurementResult) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementResultFieldStream(v *ECIDMeasurementResult) *aper.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementResultFieldWithoutReplay(v *ECIDMeasurementResult) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementResultMethodMarshalAPERBudget(v *ECIDMeasurementResult, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeECIDMeasurementResultMethodMarshalAPERChanged(v *ECIDMeasurementResult, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeECIDMeasurementResultMethodMarshalAPERChangedValue(v *ECIDMeasurementResult, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeECIDMeasurementResultMethodMarshalAPERFreshValue(v *ECIDMeasurementResult, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeECIDMeasurementResultMethodMarshalAPERLegacy(v *ECIDMeasurementResult) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeECIDMeasurementResultMethodMarshalAPERPlanned(v *ECIDMeasurementResult, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeECIDMeasurementResultMethodMarshalAPERTo(v *ECIDMeasurementResult, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementResultMethodUnmarshalAPERFrom(v *ECIDMeasurementResult, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementResultMethodUnmarshalAPERLegacy(v *ECIDMeasurementResult, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeECIDMeasurementResultMethodUnmarshalAPERWithOptions(v *ECIDMeasurementResult, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeECIDMeasurementResultValueCodecFieldCapture(v *ECIDMeasurementResultValueCodec) *func(ECIDMeasurementResult, aper.DecodeState) (ECIDMeasurementResult, aper.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementResultValueCodecFieldCompare(v *ECIDMeasurementResultValueCodec) *func(ECIDMeasurementResult, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementResultValueCodecFieldContext(v *ECIDMeasurementResultValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementResultValueCodecFieldDecode(v *ECIDMeasurementResultValueCodec) *func([]byte, aper.DecodeState) (ECIDMeasurementResult, error) {
	return &v.decode
}
func BridgeECIDMeasurementResultValueCodecFieldEncode(v *ECIDMeasurementResultValueCodec) *func(ECIDMeasurementResult, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementResultValueCodecFieldPath(v *ECIDMeasurementResultValueCodec) *aper.Path {
	return &v.path
}
func BridgeECIDMeasurementResultValueCodecMethodEncodeBudget(v ECIDMeasurementResultValueCodec, a0 ECIDMeasurementResult, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeECIDMeasurementResultValueCodecMethodEncodeChanged(v ECIDMeasurementResultValueCodec, a0 ECIDMeasurementResult, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMeasuredResultsAPERValueFieldContext(v *MeasuredResultsAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMeasuredResultsAPERValueFieldReceived(v *MeasuredResultsAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMeasuredResultsAPERValueFieldReplay(v *MeasuredResultsAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMeasuredResultsAPERValueFieldWithoutReplay(v *MeasuredResultsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMeasuredResultsConcreteValueCodecFieldCapture(v *MeasuredResultsConcreteValueCodec) *func(MeasuredResults, aper.DecodeState) (MeasuredResults, aper.Snapshot) {
	return &v.capture
}
func BridgeMeasuredResultsConcreteValueCodecFieldCompare(v *MeasuredResultsConcreteValueCodec) *func(MeasuredResults, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeMeasuredResultsConcreteValueCodecFieldContext(v *MeasuredResultsConcreteValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMeasuredResultsConcreteValueCodecFieldDecode(v *MeasuredResultsConcreteValueCodec) *func([]byte, aper.DecodeState) (MeasuredResults, error) {
	return &v.decode
}
func BridgeMeasuredResultsConcreteValueCodecFieldEncode(v *MeasuredResultsConcreteValueCodec) *func(MeasuredResults, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMeasuredResultsConcreteValueCodecFieldPath(v *MeasuredResultsConcreteValueCodec) *aper.Path {
	return &v.path
}
func BridgeMeasuredResultsConcreteValueCodecMethodEncodeBudget(v MeasuredResultsConcreteValueCodec, a0 MeasuredResults, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeMeasuredResultsConcreteValueCodecMethodEncodeChanged(v MeasuredResultsConcreteValueCodec, a0 MeasuredResults, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMeasuredResultsValueAPERValueFieldContext(v *MeasuredResultsValueAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMeasuredResultsValueAPERValueFieldReceived(v *MeasuredResultsValueAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeMeasuredResultsValueAPERValueFieldReplay(v *MeasuredResultsValueAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeMeasuredResultsValueAPERValueFieldWithoutReplay(v *MeasuredResultsValueAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMeasuredResultsValueFieldKnownOpenBytes(v *MeasuredResultsValue) *uint64 {
	return &v.knownOpenBytes
}
func BridgeMeasuredResultsValueFieldPerOpenTypePadding(v *MeasuredResultsValue) *aper.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeMeasuredResultsValueFieldPerPadding(v *MeasuredResultsValue) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeMeasuredResultsValueFieldReceived(v *MeasuredResultsValue) *bool { return &v.received }
func BridgeMeasuredResultsValueFieldReceivedBytes(v *MeasuredResultsValue) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeMeasuredResultsValueFieldReplay(v *MeasuredResultsValue) *aper.Snapshot { return &v.replay }
func BridgeMeasuredResultsValueFieldStream(v *MeasuredResultsValue) *aper.WireSpan { return &v.stream }
func BridgeMeasuredResultsValueFieldWithoutReplay(v *MeasuredResultsValue) *bool {
	return &v.withoutReplay
}
func BridgeMeasuredResultsValueMethodMarshalAPERBudget(v *MeasuredResultsValue, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMeasuredResultsValueMethodMarshalAPERChanged(v *MeasuredResultsValue, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMeasuredResultsValueMethodMarshalAPERChangedValue(v *MeasuredResultsValue, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMeasuredResultsValueMethodMarshalAPERFreshValue(v *MeasuredResultsValue, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeMeasuredResultsValueMethodMarshalAPERLegacy(v *MeasuredResultsValue) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMeasuredResultsValueMethodMarshalAPERPlanned(v *MeasuredResultsValue, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeMeasuredResultsValueMethodMarshalAPERTo(v *MeasuredResultsValue, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMeasuredResultsValueMethodUnmarshalAPERFrom(v *MeasuredResultsValue, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMeasuredResultsValueMethodUnmarshalAPERLegacy(v *MeasuredResultsValue, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMeasuredResultsValueMethodUnmarshalAPERWithOptions(v *MeasuredResultsValue, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMeasuredResultsValueValueCodecFieldCapture(v *MeasuredResultsValueValueCodec) *func(MeasuredResultsValue, aper.DecodeState) (MeasuredResultsValue, aper.Snapshot) {
	return &v.capture
}
func BridgeMeasuredResultsValueValueCodecFieldCompare(v *MeasuredResultsValueValueCodec) *func(MeasuredResultsValue, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeMeasuredResultsValueValueCodecFieldContext(v *MeasuredResultsValueValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeMeasuredResultsValueValueCodecFieldDecode(v *MeasuredResultsValueValueCodec) *func([]byte, aper.DecodeState) (MeasuredResultsValue, error) {
	return &v.decode
}
func BridgeMeasuredResultsValueValueCodecFieldEncode(v *MeasuredResultsValueValueCodec) *func(MeasuredResultsValue, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMeasuredResultsValueValueCodecFieldPath(v *MeasuredResultsValueValueCodec) *aper.Path {
	return &v.path
}
func BridgeMeasuredResultsValueValueCodecMethodEncodeBudget(v MeasuredResultsValueValueCodec, a0 MeasuredResultsValue, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeMeasuredResultsValueValueCodecMethodEncodeChanged(v MeasuredResultsValueValueCodec, a0 MeasuredResultsValue, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultRSRQAPERValueFieldContext(v *ResultRSRQAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultRSRQAPERValueFieldReceived(v *ResultRSRQAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResultRSRQAPERValueFieldReplay(v *ResultRSRQAPERValue) *aper.Snapshot { return &v.replay }
func BridgeResultRSRQAPERValueFieldWithoutReplay(v *ResultRSRQAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRQItemAPERValueFieldContext(v *ResultRSRQItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultRSRQItemAPERValueFieldReceived(v *ResultRSRQItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResultRSRQItemAPERValueFieldReplay(v *ResultRSRQItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResultRSRQItemAPERValueFieldWithoutReplay(v *ResultRSRQItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRQItemFieldExtCount(v *ResultRSRQItem) *int64                { return &v.extCount }
func BridgeResultRSRQItemFieldExtData(v *ResultRSRQItem) *[][]byte              { return &v.extData }
func BridgeResultRSRQItemFieldExtOrigin(v *ResultRSRQItem) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeResultRSRQItemFieldExtPresent(v *ResultRSRQItem) *[]bool             { return &v.extPresent }
func BridgeResultRSRQItemFieldExtWire(v *ResultRSRQItem) *[]aper.WireSpan       { return &v.extWire }
func BridgeResultRSRQItemFieldIEExtensionsIndef(v *ResultRSRQItem) *bool        { return &v.iEExtensionsIndef }
func BridgeResultRSRQItemFieldPerExtPadding(v *ResultRSRQItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeResultRSRQItemFieldPerPadding(v *ResultRSRQItem) *aper.FinalPadding { return &v.perPadding }
func BridgeResultRSRQItemFieldReceived(v *ResultRSRQItem) *bool                { return &v.received }
func BridgeResultRSRQItemFieldReceivedBytes(v *ResultRSRQItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeResultRSRQItemFieldReplay(v *ResultRSRQItem) *aper.Snapshot { return &v.replay }
func BridgeResultRSRQItemFieldStream(v *ResultRSRQItem) *aper.WireSpan { return &v.stream }
func BridgeResultRSRQItemFieldWithoutReplay(v *ResultRSRQItem) *bool   { return &v.withoutReplay }
func BridgeResultRSRQItemMethodMarshalAPERBudget(v *ResultRSRQItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultRSRQItemMethodMarshalAPERChanged(v *ResultRSRQItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultRSRQItemMethodMarshalAPERChangedValue(v *ResultRSRQItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultRSRQItemMethodMarshalAPERFreshValue(v *ResultRSRQItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultRSRQItemMethodMarshalAPERLegacy(v *ResultRSRQItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultRSRQItemMethodMarshalAPERPlanned(v *ResultRSRQItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultRSRQItemMethodMarshalAPERTo(v *ResultRSRQItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultRSRQItemMethodUnmarshalAPERFrom(v *ResultRSRQItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultRSRQItemMethodUnmarshalAPERLegacy(v *ResultRSRQItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultRSRQItemMethodUnmarshalAPERWithOptions(v *ResultRSRQItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultRSRQItemValueCodecFieldCapture(v *ResultRSRQItemValueCodec) *func(ResultRSRQItem, aper.DecodeState) (ResultRSRQItem, aper.Snapshot) {
	return &v.capture
}
func BridgeResultRSRQItemValueCodecFieldCompare(v *ResultRSRQItemValueCodec) *func(ResultRSRQItem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeResultRSRQItemValueCodecFieldContext(v *ResultRSRQItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultRSRQItemValueCodecFieldDecode(v *ResultRSRQItemValueCodec) *func([]byte, aper.DecodeState) (ResultRSRQItem, error) {
	return &v.decode
}
func BridgeResultRSRQItemValueCodecFieldEncode(v *ResultRSRQItemValueCodec) *func(ResultRSRQItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultRSRQItemValueCodecFieldPath(v *ResultRSRQItemValueCodec) *aper.Path { return &v.path }
func BridgeResultRSRQItemValueCodecMethodEncodeBudget(v ResultRSRQItemValueCodec, a0 ResultRSRQItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultRSRQItemValueCodecMethodEncodeChanged(v ResultRSRQItemValueCodec, a0 ResultRSRQItem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultRSRQValueCodecFieldCapture(v *ResultRSRQValueCodec) *func(ResultRSRQ, aper.DecodeState) (ResultRSRQ, aper.Snapshot) {
	return &v.capture
}
func BridgeResultRSRQValueCodecFieldCompare(v *ResultRSRQValueCodec) *func(ResultRSRQ, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeResultRSRQValueCodecFieldContext(v *ResultRSRQValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultRSRQValueCodecFieldDecode(v *ResultRSRQValueCodec) *func([]byte, aper.DecodeState) (ResultRSRQ, error) {
	return &v.decode
}
func BridgeResultRSRQValueCodecFieldEncode(v *ResultRSRQValueCodec) *func(ResultRSRQ, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultRSRQValueCodecFieldPath(v *ResultRSRQValueCodec) *aper.Path { return &v.path }
func BridgeResultRSRQValueCodecMethodEncodeBudget(v ResultRSRQValueCodec, a0 ResultRSRQ, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultRSRQValueCodecMethodEncodeChanged(v ResultRSRQValueCodec, a0 ResultRSRQ, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
