// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s22 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s22

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s13"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s17"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s18"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s20"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// ECIDMeasurementInitiationResponseIEContainer is the concrete ProtocolIEContainer[ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseIEContainer []ECIDMeasurementInitiationResponseIEField

// ECIDMeasurementInitiationResponseIEField is the concrete ProtocolIEField[ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         ECIDMeasurementInitiationResponseIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECIDMeasurementInitiationResponseIEField) WithoutReplay() ECIDMeasurementInitiationResponseIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *ECIDMeasurementInitiationResponseIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ECIDMeasurementInitiationResponseIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *ECIDMeasurementInitiationResponseIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementInitiationResponseIEField{}
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
	var zero ECIDMeasurementInitiationResponseIEValue

	raw, err := aper.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return runtime.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}
func BridgeECIDMeasurementInitiationResponseIEValueCaptureLPPaProtocolIEContainer(v *ECIDMeasurementInitiationResponseIEContainer, s *aper.SemanticCapture) {
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
			BridgeECIDMeasurementInitiationResponseIEValueCaptureLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeECIDMeasurementInitiationResponseIEValueCompareLPPaProtocolIEContainer(v *ECIDMeasurementInitiationResponseIEContainer, s *aper.SemanticComparison) {
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
			BridgeECIDMeasurementInitiationResponseIEValueCompareLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}

// ECIDMeasurementInitiationResponseMeasurementIDIEBinding is the concrete IEBinding[MeasurementID, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseMeasurementIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.MeasurementIDValueCodec
	inject func(s00.MeasurementID,

	) ECIDMeasurementInitiationResponseIEValue

	get func(*ECIDMeasurementInitiationResponseIEValue,

	) (*s00.MeasurementID,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementInitiationResponseMeasurementIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementInitiationResponseMeasurementIDIEBinding) Codec() s00.MeasurementIDValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementInitiationResponseMeasurementIDIEBinding) New(value s00.MeasurementID,

) (ECIDMeasurementInitiationResponseIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeMeasurementIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementInitiationResponseMeasurementIDIEBinding) Get(field *ECIDMeasurementInitiationResponseIEField) (*s00.MeasurementID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding is the concrete IEBinding[ECIDMeasurementResult, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding struct {
	info   s00.FieldInfo
	codec  s13.ECIDMeasurementResultValueCodec
	inject func(s13.ECIDMeasurementResult,

	) ECIDMeasurementInitiationResponseIEValue

	get func(*ECIDMeasurementInitiationResponseIEValue,

	) (*s13.ECIDMeasurementResult,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding) Codec() s13.ECIDMeasurementResultValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding) New(value s13.ECIDMeasurementResult,

) (ECIDMeasurementInitiationResponseIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s13.BridgeECIDMeasurementResultValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding) Get(field *ECIDMeasurementInitiationResponseIEField) (*s13.ECIDMeasurementResult,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding struct {
	info   s00.FieldInfo
	codec  s09.CriticalityDiagnosticsValueCodec
	inject func(s09.CriticalityDiagnostics,

	) ECIDMeasurementInitiationResponseIEValue

	get func(*ECIDMeasurementInitiationResponseIEValue,

	) (*s09.CriticalityDiagnostics,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding) Codec() s09.CriticalityDiagnosticsValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding) New(value s09.CriticalityDiagnostics,

) (ECIDMeasurementInitiationResponseIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s09.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding) Get(field *ECIDMeasurementInitiationResponseIEField) (*s09.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationResponseCellPortionIDIEBinding is the concrete IEBinding[CellPortionID, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseCellPortionIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CellPortionIDValueCodec
	inject func(s00.CellPortionID,

	) ECIDMeasurementInitiationResponseIEValue

	get func(*ECIDMeasurementInitiationResponseIEValue,

	) (*s00.CellPortionID,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementInitiationResponseCellPortionIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementInitiationResponseCellPortionIDIEBinding) Codec() s00.CellPortionIDValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementInitiationResponseCellPortionIDIEBinding) New(value s00.CellPortionID,

) (ECIDMeasurementInitiationResponseIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCellPortionIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementInitiationResponseCellPortionIDIEBinding) Get(field *ECIDMeasurementInitiationResponseIEField) (*s00.CellPortionID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding is the concrete IEBinding[InterRATMeasurementResult, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding struct {
	info   s00.FieldInfo
	codec  s20.InterRATMeasurementResultValueCodec
	inject func(s20.InterRATMeasurementResult,

	) ECIDMeasurementInitiationResponseIEValue

	get func(*ECIDMeasurementInitiationResponseIEValue,

	) (*s20.InterRATMeasurementResult,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding) Codec() s20.InterRATMeasurementResultValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding) New(value s20.InterRATMeasurementResult,

) (ECIDMeasurementInitiationResponseIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgeInterRATMeasurementResultValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding) Get(field *ECIDMeasurementInitiationResponseIEField) (*s20.InterRATMeasurementResult,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding is the concrete IEBinding[WLANMeasurementResult, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding struct {
	info   s00.FieldInfo
	codec  WLANMeasurementResultValueCodec
	inject func(WLANMeasurementResult,

	) ECIDMeasurementInitiationResponseIEValue

	get func(*ECIDMeasurementInitiationResponseIEValue,

	) (*WLANMeasurementResult,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete APER codec for this binding's value type.
func (b ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding) Codec() WLANMeasurementResultValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding) New(value WLANMeasurementResult,

) (ECIDMeasurementInitiationResponseIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding) Get(field *ECIDMeasurementInitiationResponseIEField) (*WLANMeasurementResult,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WLANMeasurementResultValueCodec is the concrete ValueCodec[WLANMeasurementResult].
type WLANMeasurementResultValueCodec struct {
	context s00.BridgeCodecContext
	capture func(WLANMeasurementResult, aper.DecodeState,

	) (WLANMeasurementResult, aper.Snapshot,

	)
	compare func(WLANMeasurementResult, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (WLANMeasurementResult,

		error)
	encode func(WLANMeasurementResult,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c WLANMeasurementResultValueCodec) New(value WLANMeasurementResult,

) (WLANMeasurementResultAPERValue, error) {
	if c.encode == nil {
		return WLANMeasurementResultAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WLANMeasurementResultAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANMeasurementResultAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return WLANMeasurementResultAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c WLANMeasurementResultValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WLANMeasurementResultAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANMeasurementResultAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return WLANMeasurementResultAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANMeasurementResultAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return WLANMeasurementResultAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return WLANMeasurementResultAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c WLANMeasurementResultValueCodec) EncodeAPER(value WLANMeasurementResultAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c WLANMeasurementResultValueCodec) encodeBudget(value WLANMeasurementResult,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANMeasurementResultValueCodec) encodeChanged(value WLANMeasurementResult,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ECIDMeasurementInitiationResponseValueCodec is the concrete ValueCodec[ECIDMeasurementInitiationResponse].
type ECIDMeasurementInitiationResponseValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ECIDMeasurementInitiationResponse, aper.DecodeState,

	) (ECIDMeasurementInitiationResponse, aper.Snapshot,

	)
	compare func(ECIDMeasurementInitiationResponse, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ECIDMeasurementInitiationResponse,

		error)
	encode func(ECIDMeasurementInitiationResponse,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ECIDMeasurementInitiationResponseValueCodec) New(value ECIDMeasurementInitiationResponse,

) (ECIDMeasurementInitiationResponseAPERValue, error) {
	if c.encode == nil {
		return ECIDMeasurementInitiationResponseAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ECIDMeasurementInitiationResponseAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationResponseAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ECIDMeasurementInitiationResponseValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ECIDMeasurementInitiationResponseAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ECIDMeasurementInitiationResponseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ECIDMeasurementInitiationResponseAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ECIDMeasurementInitiationResponseAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ECIDMeasurementInitiationResponseAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ECIDMeasurementInitiationResponseAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ECIDMeasurementInitiationResponseValueCodec) EncodeAPER(value ECIDMeasurementInitiationResponseAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ECIDMeasurementInitiationResponseValueCodec) encodeBudget(value ECIDMeasurementInitiationResponse,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ECIDMeasurementInitiationResponseValueCodec) encodeChanged(value ECIDMeasurementInitiationResponse,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// WLANMeasurementResultItemValueCodec is the concrete ValueCodec[WLANMeasurementResultItem].
type WLANMeasurementResultItemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(WLANMeasurementResultItem, aper.DecodeState,

	) (WLANMeasurementResultItem, aper.Snapshot,

	)
	compare func(WLANMeasurementResultItem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (WLANMeasurementResultItem,

		error)
	encode func(WLANMeasurementResultItem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c WLANMeasurementResultItemValueCodec) New(value WLANMeasurementResultItem,

) (WLANMeasurementResultItemAPERValue, error) {
	if c.encode == nil {
		return WLANMeasurementResultItemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return WLANMeasurementResultItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANMeasurementResultItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return WLANMeasurementResultItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c WLANMeasurementResultItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (WLANMeasurementResultItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANMeasurementResultItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return WLANMeasurementResultItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANMeasurementResultItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return WLANMeasurementResultItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return WLANMeasurementResultItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c WLANMeasurementResultItemValueCodec) EncodeAPER(value WLANMeasurementResultItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c WLANMeasurementResultItemValueCodec) encodeBudget(value WLANMeasurementResultItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANMeasurementResultItemValueCodec) encodeChanged(value WLANMeasurementResultItem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}
func BridgeECIDMeasurementInitiationResponseIEValueCaptureLPPaProtocolIEField(v *ECIDMeasurementInitiationResponseIEField, s *aper.SemanticCapture) {
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
func BridgeECIDMeasurementInitiationResponseIEValueCompareLPPaProtocolIEField(v *ECIDMeasurementInitiationResponseIEField, s *aper.SemanticComparison) {
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

// WLANMeasurementResultAPERValue is the concrete APERValue[WLANMeasurementResult].
type WLANMeasurementResultAPERValue struct {
	context s00.BridgeCodecContext
	Value   WLANMeasurementResult

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v WLANMeasurementResultAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v WLANMeasurementResultAPERValue) WithoutReplay() WLANMeasurementResultAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ECIDMeasurementInitiationResponseAPERValue is the concrete APERValue[ECIDMeasurementInitiationResponse].
type ECIDMeasurementInitiationResponseAPERValue struct {
	context s00.BridgeCodecContext
	Value   ECIDMeasurementInitiationResponse

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ECIDMeasurementInitiationResponseAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECIDMeasurementInitiationResponseAPERValue) WithoutReplay() ECIDMeasurementInitiationResponseAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// WLANMeasurementResultItemAPERValue is the concrete APERValue[WLANMeasurementResultItem].
type WLANMeasurementResultItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   WLANMeasurementResultItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v WLANMeasurementResultItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v WLANMeasurementResultItemAPERValue) WithoutReplay() WLANMeasurementResultItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

type WLANMeasurementResult = []WLANMeasurementResultItem

// WLANMeasurementResultItem represents the ASN.1 type WLANMeasurementResult-Item (SEQUENCE).
type WLANMeasurementResultItem struct {
	replay               aper.Snapshot
	stream               aper.WireSpan
	withoutReplay        bool
	received             bool
	receivedBytes        aper.WireSpan
	WLANRSSI             s00.WLANRSSI                                    `asn1:"tag:0,context,implicit"`
	SSID                 *s00.SSID                                       `asn1:"tag:1,context,implicit,optional" json:"SSID,omitempty"`
	BSSID                *s00.BSSID                                      `asn1:"tag:2,context,implicit,optional" json:"BSSID,omitempty"`
	HESSID               *s00.HESSID                                     `asn1:"tag:3,context,implicit,optional" json:"HESSID,omitempty"`
	OperatingClass       *s00.WLANOperatingClass                         `asn1:"tag:4,context,implicit,optional" json:"OperatingClass,omitempty"`
	CountryCode          *s00.WLANCountryCode                            `asn1:"tag:5,context,implicit,optional" json:"CountryCode,omitempty"`
	WLANChannelList      s00.WLANChannelList                             `asn1:"tag:6,context,implicit,optional" json:"WLANChannelList,omitzero"`
	wLANChannelListIndef bool                                            `asn1:"-" json:"-"`
	WLANBand             *s00.WLANBand                                   `asn1:"tag:7,context,implicit,optional" json:"WLANBand,omitempty"`
	IEExtensions         s04.WLANMeasurementResultItemExtIEsExtContainer `asn1:"tag:8,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef    bool                                            `asn1:"-" json:"-"`
	extCount             int64                                           `asn1:"-" json:"-"`
	extPresent           []bool                                          `asn1:"-" json:"-"`
	extData              [][]byte                                        `asn1:"-" json:"-"`
	perPadding           aper.FinalPadding                               `asn1:"-" json:"-"`
	perExtPadding        []aper.CompletePadding                          `asn1:"-" json:"-"`
	extOrigin            []aper.OpaqueOrigin
	extWire              []aper.WireSpan
}
type BridgeAsn1cAPERWLANMeasurementResultListValue struct{ Value WLANMeasurementResult }

// WLANMeasurementResultComplete carries a complete WLANMeasurementResult encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type WLANMeasurementResultComplete struct {
	replay        aper.Snapshot
	stream        aper.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes aper.WireSpan
	Value         WLANMeasurementResult
	perPadding    aper.CompletePadding `json:"-"`
}

func (v *WLANMeasurementResultComplete) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := BridgeMarshalAPERWLANMeasurementResultTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes WLANMeasurementResult from APER format.
func (v *WLANMeasurementResultComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes WLANMeasurementResult with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *WLANMeasurementResultComplete) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementResult")
	}
	value, err := BridgeUnmarshalAPERWLANMeasurementResultFrom(bb)
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementResult")
	}
	padding, err := aper.CaptureFinalBits(bb, "WLANMeasurementResult")
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementResult")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERWLANMeasurementResultTo appends a WLANMeasurementResult list to bb.
func BridgeMarshalAPERWLANMeasurementResultTo(list WLANMeasurementResult, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERWLANMeasurementResultListValue{Value: list}
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

// UnmarshalAPERWLANMeasurementResultFrom decodes a WLANMeasurementResult list from bb.
func BridgeUnmarshalAPERWLANMeasurementResultFrom(bb *aper.BitBuffer) (WLANMeasurementResult, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v BridgeAsn1cAPERWLANMeasurementResultListValue
	if err := BridgeUnmarshalAPERWLANMeasurementResultInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERWLANMeasurementResultInto(v *BridgeAsn1cAPERWLANMeasurementResultListValue, bb *aper.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(WLANMeasurementResult, 0)
	_, errCollection_value := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem WLANMeasurementResultItem
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

// MarshalAPER encodes WLANMeasurementResultItem to APER format.
func (v *WLANMeasurementResultItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *WLANMeasurementResultItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.SSID != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.BSSID != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.HESSID != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.OperatingClass != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.CountryCode != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.WLANChannelList != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.WLANBand != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.WLANRSSI, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound6, true); err != nil {
		return fmt.Errorf("encoding wLAN-RSSI: %w", err)
	}
	if v.SSID != nil {
		if err := aper.EncodeOctetStringAligned(bb, []byte(*v.SSID), 1, 32, true); err != nil {
			return fmt.Errorf("encoding sSID: %w", err)
		}
	}
	if v.BSSID != nil {
		if err := aper.EncodeOctetStringAligned(bb, []byte(*v.BSSID), 6, 6, true); err != nil {
			return fmt.Errorf("encoding bSSID: %w", err)
		}
	}
	if v.HESSID != nil {
		if err := aper.EncodeOctetStringAligned(bb, []byte(*v.HESSID), 6, 6, true); err != nil {
			return fmt.Errorf("encoding hESSID: %w", err)
		}
	}
	if v.OperatingClass != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.OperatingClass), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false); err != nil {
			return fmt.Errorf("encoding operatingClass: %w", err)
		}
	}
	if v.CountryCode != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.CountryCode), 4, true); err != nil {
			return fmt.Errorf("encoding countryCode: %w", err)
		}
	}
	if v.WLANChannelList != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.WLANChannelList)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_wlanchannellist, fragmentLength_wlanchannellist int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_wlanchannellist < 0 || fragmentOffset_wlanchannellist > int64(len(v.WLANChannelList)) || fragmentLength_wlanchannellist < 0 || fragmentLength_wlanchannellist > int64(len(v.WLANChannelList[fragmentOffset_wlanchannellist:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.WLANChannelList[fragmentOffset_wlanchannellist : fragmentOffset_wlanchannellist+fragmentLength_wlanchannellist] {
				if err := aper.EncodeIntegerAligned(bb, int64(elem), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false); err != nil {
					return fmt.Errorf("encoding wLANChannelList element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("encoding wLANChannelList: %w", err)
		}
	}
	if v.WLANBand != nil {
		if err := aper.EncodeEnumeratedAligned(bb, int64(*v.WLANBand), 2, true); err != nil {
			return fmt.Errorf("encoding wLANBand: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s04.BridgeWLANMeasurementResultItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes WLANMeasurementResultItem from APER format.
func (v *WLANMeasurementResultItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes WLANMeasurementResultItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *WLANMeasurementResultItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementResultItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementResultItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "WLANMeasurementResultItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANMeasurementResultItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *WLANMeasurementResultItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WLANMeasurementResultItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ssid, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_bssid, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_hessid, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_operatingclass, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_countrycode, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_wlanchannellist, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_wlanband, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_wlanrssi, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound6, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "WLANRSSI")
	}
	v.WLANRSSI = val_wlanrssi
	if opt_ssid {
		val_ssid, err := aper.DecodeOctetStringAligned(bb, 1, 32, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "SSID")
		}
		tmp_ssid := s00.SSID(val_ssid)
		if err := aper.ChargeValue(bb, tmp_ssid); err != nil {
			return err
		}
		v.SSID = &tmp_ssid
	}
	if opt_bssid {
		val_bssid, err := aper.DecodeOctetStringAligned(bb, 6, 6, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "BSSID")
		}
		tmp_bssid := s00.BSSID(val_bssid)
		if err := aper.ChargeValue(bb, tmp_bssid); err != nil {
			return err
		}
		v.BSSID = &tmp_bssid
	}
	if opt_hessid {
		val_hessid, err := aper.DecodeOctetStringAligned(bb, 6, 6, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "HESSID")
		}
		tmp_hessid := s00.HESSID(val_hessid)
		if err := aper.ChargeValue(bb, tmp_hessid); err != nil {
			return err
		}
		v.HESSID = &tmp_hessid
	}
	if opt_operatingclass {
		val_operatingclass, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "OperatingClass")
		}
		tmp_operatingclass := s00.WLANOperatingClass(val_operatingclass)
		if err := aper.ChargeValue(bb, tmp_operatingclass); err != nil {
			return err
		}
		v.OperatingClass = (*s00.WLANOperatingClass)(bb.OwnInt64(int64(tmp_operatingclass)))
	}
	if opt_countrycode {
		val_countrycode, err := aper.DecodeEnumeratedAligned(bb, 4, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CountryCode"})
		if err != nil {
			return runtime.WrapDecodePath(err, "CountryCode")
		}
		tmp_countrycode := s00.WLANCountryCode(val_countrycode)
		if err := aper.ChargeValue(bb, tmp_countrycode); err != nil {
			return err
		}
		v.CountryCode = (*s00.WLANCountryCode)(bb.OwnInt64(int64(tmp_countrycode)))
	}
	if opt_wlanchannellist {
		tmp_wlanchannellist := make(s00.WLANChannelList, 0)
		_, errCollection_wlanchannellist := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_wlanchannellist, fragmentLength_wlanchannellist int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_2: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1136
			if fragmentOffset_wlanchannellist < 0 || fragmentLength_wlanchannellist < 0 || fragmentLength_wlanchannellist > int64(^uint(0)>>1) || fragmentOffset_wlanchannellist > int64(^uint(0)>>1)-fragmentLength_wlanchannellist {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_wlanchannellist; i++ {
				val, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("WLANChannelList[%d]", fragmentOffset_wlanchannellist+i))
				}
				if next, err := aper.AppendValues(bb, tmp_wlanchannellist, s00.WLANChannel(val)); err != nil {
					return err
				} else {
					tmp_wlanchannellist = next
				}
			}
			return nil
		})
		if errCollection_wlanchannellist != nil {
			return runtime.WrapDecodePath(errCollection_wlanchannellist, "WLANChannelList")
		}
		v.WLANChannelList = tmp_wlanchannellist
	}
	if opt_wlanband {
		val_wlanband, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "WLANBand"})
		if err != nil {
			return runtime.WrapDecodePath(err, "WLANBand")
		}
		tmp_wlanband := s00.WLANBand(val_wlanband)
		if err := aper.ChargeValue(bb, tmp_wlanband); err != nil {
			return err
		}
		v.WLANBand = (*s00.WLANBand)(bb.OwnInt64(int64(tmp_wlanband)))
	}
	if opt_ieextensions {
		tmp_ieextensions := make(s04.WLANMeasurementResultItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s04.WLANMeasurementResultItemExtIEsExtField
				if err := s04.BridgeWLANMeasurementResultItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WLANMeasurementResultComplete) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "WLANMeasurementResultComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WLANMeasurementResultComplete) WithoutReplay() WLANMeasurementResultComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero WLANMeasurementResultComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WLANMeasurementResultItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "WLANMeasurementResultItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WLANMeasurementResultItem) WithoutReplay() WLANMeasurementResultItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero WLANMeasurementResultItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *WLANMeasurementResultItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *WLANMeasurementResultItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("WLANMeasurementResultItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("WLANMeasurementResultItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *WLANMeasurementResultItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("WLANMeasurementResultItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("WLANMeasurementResultItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *WLANMeasurementResultComplete) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "WLANMeasurementResultComplete")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "WLANMeasurementResultComplete")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaWLANMeasurementResultComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "WLANMeasurementResultComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "WLANMeasurementResultComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "WLANMeasurementResultComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "WLANMeasurementResultComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "WLANMeasurementResultComplete")
}
func (v *WLANMeasurementResultComplete) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *WLANMeasurementResultComplete) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *WLANMeasurementResultComplete) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaWLANMeasurementResultComplete(v, &s)
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
func (v *WLANMeasurementResultComplete) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *WLANMeasurementResultComplete) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	bb := aper.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := BridgeMarshalAPERWLANMeasurementResultTo(value.Value, bb, fresh); err != nil {
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
func (v *WLANMeasurementResultItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "WLANMeasurementResultItem")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "WLANMeasurementResultItem")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaWLANMeasurementResultItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "WLANMeasurementResultItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "WLANMeasurementResultItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "WLANMeasurementResultItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "WLANMeasurementResultItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "WLANMeasurementResultItem")
}
func (v *WLANMeasurementResultItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *WLANMeasurementResultItem) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *WLANMeasurementResultItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaWLANMeasurementResultItem(v, &s)
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
func (v *WLANMeasurementResultItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *WLANMeasurementResultItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *WLANMeasurementResultComplete) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "WLANMeasurementResultComplete")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded WLANMeasurementResultComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaWLANMeasurementResultComplete(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = WLANMeasurementResultComplete{}
		return report, aper.OperationError(err, "WLANMeasurementResultComplete")
	}
	*v = decoded
	return report, aper.OperationError(nil, "WLANMeasurementResultComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *WLANMeasurementResultItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "WLANMeasurementResultItem")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded WLANMeasurementResultItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaWLANMeasurementResultItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = WLANMeasurementResultItem{}
		return report, aper.OperationError(err, "WLANMeasurementResultItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "WLANMeasurementResultItem")
}

// MarshalAPERWLANMeasurementResult encodes a complete named list.
func MarshalAPERWLANMeasurementResult(v WLANMeasurementResultComplete, options ...aper.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERWLANMeasurementResult decodes a complete named list.
func UnmarshalAPERWLANMeasurementResult(data []byte, options ...aper.DecodeOption) (WLANMeasurementResultComplete, aper.DecodeReport, error) {
	var v WLANMeasurementResultComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// ECIDMeasurementInitiationResponse represents the ASN.1 type E-CIDMeasurementInitiationResponse (SEQUENCE).
type ECIDMeasurementInitiationResponse struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    aper.WireSpan
	ProtocolIEs      ECIDMeasurementInitiationResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                         `asn1:"-" json:"-"`
	extCount         int64                                        `asn1:"-" json:"-"`
	extPresent       []bool                                       `asn1:"-" json:"-"`
	extData          [][]byte                                     `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes ECIDMeasurementInitiationResponse to APER format.
func (v *ECIDMeasurementInitiationResponse) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ECIDMeasurementInitiationResponse) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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

// UnmarshalAPER decodes ECIDMeasurementInitiationResponse from APER format.
func (v *ECIDMeasurementInitiationResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ECIDMeasurementInitiationResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ECIDMeasurementInitiationResponse) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementInitiationResponse")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementInitiationResponse")
	}
	padding, err := aper.CaptureFinalBits(bb, "ECIDMeasurementInitiationResponse")
	if err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementInitiationResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ECIDMeasurementInitiationResponse) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementInitiationResponse{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ECIDMeasurementInitiationResponseIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ECIDMeasurementInitiationResponseIEField
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
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
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage,

		bb,
	)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ECIDMeasurementInitiationResponse) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ECIDMeasurementInitiationResponse", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ECIDMeasurementInitiationResponse) WithoutReplay() ECIDMeasurementInitiationResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ECIDMeasurementInitiationResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ECIDMeasurementInitiationResponse) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ECIDMeasurementInitiationResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ECIDMeasurementInitiationResponse.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ECIDMeasurementInitiationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ECIDMeasurementInitiationResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ECIDMeasurementInitiationResponse.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ECIDMeasurementInitiationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *ECIDMeasurementInitiationResponse) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ECIDMeasurementInitiationResponse")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ECIDMeasurementInitiationResponse")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaECIDMeasurementInitiationResponse(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ECIDMeasurementInitiationResponse")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ECIDMeasurementInitiationResponse")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ECIDMeasurementInitiationResponse")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ECIDMeasurementInitiationResponse")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ECIDMeasurementInitiationResponse")
}
func (v *ECIDMeasurementInitiationResponse) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ECIDMeasurementInitiationResponse) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ECIDMeasurementInitiationResponse) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaECIDMeasurementInitiationResponse(v, &s)
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
func (v *ECIDMeasurementInitiationResponse) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ECIDMeasurementInitiationResponse) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ECIDMeasurementInitiationResponse) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ECIDMeasurementInitiationResponse")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ECIDMeasurementInitiationResponse
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaECIDMeasurementInitiationResponse(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ECIDMeasurementInitiationResponse{}
		return report, aper.OperationError(err, "ECIDMeasurementInitiationResponse")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ECIDMeasurementInitiationResponse")
}

// SuccessfulOutcome represents the ASN.1 type SuccessfulOutcome (SEQUENCE).
type SuccessfulOutcome struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     aper.WireSpan
	ProcedureCode     s00.ProcedureCode     `asn1:"tag:0,context,implicit"`
	Criticality       s00.Criticality       `asn1:"tag:1,context,implicit"`
	LppatransactionID s00.LPPATransactionID `asn1:"tag:2,context,implicit"`
	Value             SuccessfulValue       `asn1:"tag:3,context,explicit" asn1c:"raw-preserve"`
	perPadding        aper.CompletePadding  `asn1:"-" json:"-"`
}

// MarshalAPER encodes SuccessfulOutcome to APER format.
func (v *SuccessfulOutcome) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *SuccessfulOutcome) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
	if v.withoutReplay {
		fresh = []bool{true}
	}
	if len(fresh) > 0 && fresh[0] {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(
			previous,
		)
	}
	if v != nil && bb.ReplayPlan() != nil && bb.ReplayPlan().Unchanged(v.replay) && !v.withoutReplay {
		if ok, err := v.replay.
			ReplayTo(v.stream, bb); ok || err !=
			nil {
			return err
		}
	}

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	if v.Value.code != v.ProcedureCode {
		return runtime.WrapDecodePath(fmt.Errorf("%w: procedure code %d does not match its value selector", aper.ErrInvalidValue, v.ProcedureCode), "SuccessfulOutcome.ProcedureCode")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.ProcedureCode), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false); err != nil {
		return fmt.Errorf("encoding procedureCode: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.LppatransactionID), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(32767), false); err != nil {
		return fmt.Errorf("encoding lppatransactionID: %w", err)
	}
	openData_value, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, openData_value); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes SuccessfulOutcome from APER format.
func (v *SuccessfulOutcome) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SuccessfulOutcome with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SuccessfulOutcome) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SuccessfulOutcome")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SuccessfulOutcome")
	}
	padding, err := aper.CaptureFinalBits(bb, "SuccessfulOutcome")
	if err != nil {
		return runtime.WrapDecodePath(err, "SuccessfulOutcome")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *SuccessfulOutcome) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SuccessfulOutcome{}
	val_procedurecode, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(255), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "ProcedureCode")
	}
	v.ProcedureCode = s00.ProcedureCode(val_procedurecode)
	val_criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false, aper.EnumerationSource{KnownExtensions: 0, Path: "Criticality"})
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Criticality")
	}
	v.Criticality = s00.Criticality(val_criticality)
	val_lppatransactionid, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(32767), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "LppatransactionID")
	}
	v.LppatransactionID = s00.LPPATransactionID(val_lppatransactionid)
	opaque_value, err := aper.DecodeOpaqueOpenTypeAligned(bb, s00.SuccessfulReason(v.ProcedureCode), aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "Successful"}})
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	opaque_value = opaque_value.WithPath("SuccessfulOutcome.Value")
	decoded_value, err := BridgeDecodeSuccessfulValue(v.ProcedureCode, opaque_value)
	if err != nil {
		return runtime.WrapDecodePath(fmt.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	v.Value = decoded_value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SuccessfulOutcome) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "SuccessfulOutcome", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SuccessfulOutcome) WithoutReplay() SuccessfulOutcome {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero SuccessfulOutcome
	v.perPadding = zero.perPadding
	return v
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *SuccessfulOutcome) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SuccessfulOutcome")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "SuccessfulOutcome")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaSuccessfulOutcome(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "SuccessfulOutcome")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "SuccessfulOutcome")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "SuccessfulOutcome")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "SuccessfulOutcome")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "SuccessfulOutcome")
}
func (v *SuccessfulOutcome) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *SuccessfulOutcome) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *SuccessfulOutcome) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaSuccessfulOutcome(v, &s)
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
func (v *SuccessfulOutcome) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *SuccessfulOutcome) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *SuccessfulOutcome) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SuccessfulOutcome")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded SuccessfulOutcome
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaSuccessfulOutcome(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = SuccessfulOutcome{}
		return report, aper.OperationError(err, "SuccessfulOutcome")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SuccessfulOutcome")
}

type SuccessfulValue struct {
	code                                  s00.ProcedureCode
	withoutReplay                         bool
	received                              aper.WireSpan
	replay                                aper.Snapshot
	opaque                                *aper.OpaqueOpenType
	isOpaque                              bool
	bodyECIDMeasurementInitiationResponse *ECIDMeasurementInitiationResponse
	bodyOTDOAInformationResponse          *s18.OTDOAInformationResponse
	bodyUTDOAInformationResponse          *s17.UTDOAInformationResponse
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *SuccessfulValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}

// AsECIDMeasurementInitiationResponse returns the selected ECIDMeasurementInitiationResponse value and reports whether that alternative is active.
func (v *SuccessfulValue) AsECIDMeasurementInitiationResponse() (*ECIDMeasurementInitiationResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(2) || v.bodyECIDMeasurementInitiationResponse == nil {
		return nil, false
	}
	return v.bodyECIDMeasurementInitiationResponse, true
}

// AsOTDOAInformationResponse returns the selected OTDOAInformationResponse value and reports whether that alternative is active.
func (v *SuccessfulValue) AsOTDOAInformationResponse() (*s18.OTDOAInformationResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(6) || v.bodyOTDOAInformationResponse == nil {
		return nil, false
	}
	return v.bodyOTDOAInformationResponse, true
}

// AsUTDOAInformationResponse returns the selected UTDOAInformationResponse value and reports whether that alternative is active.
func (v *SuccessfulValue) AsUTDOAInformationResponse() (*s17.UTDOAInformationResponse, bool) {
	if v == nil || v.code != s00.ProcedureCode(7) || v.bodyUTDOAInformationResponse == nil {
		return nil, false
	}
	return v.bodyUTDOAInformationResponse, true
}
func BridgeDecodeSuccessfulValue(code s00.ProcedureCode, raw aper.OpaqueOpenType) (SuccessfulValue, error) {
	v := SuccessfulValue{code: code}
	var scope *aper.BitBuffer
	switch code {
	case 2, 6, 7:
		scope = raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return v, err
		}
		defer scope.LeaveOpenType()
	}
	switch code {
	case s00.ProcedureCode(2):
		var body ECIDMeasurementInitiationResponse
		child := scope
		replayUsage := child.Usage()
		if err := body.unmarshalAPERFrom(child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.ECIDMeasurementInitiationResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ECIDMeasurementInitiationResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyECIDMeasurementInitiationResponse = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case s00.ProcedureCode(6):
		var body s18.OTDOAInformationResponse
		child := scope
		replayUsage := child.Usage()
		if err := s18.BridgeOTDOAInformationResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.OTDOAInformationResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "OTDOAInformationResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s18.BridgeOTDOAInformationResponseFieldPerPadding(&body) = padding
		*s18.BridgeOTDOAInformationResponseFieldReceived(&body) = true
		raw.RetainContents(s18.BridgeOTDOAInformationResponseFieldReceivedBytes(&body))
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyOTDOAInformationResponse = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case s00.ProcedureCode(7):
		var body s17.UTDOAInformationResponse
		child := scope
		replayUsage := child.Usage()
		if err := s17.BridgeUTDOAInformationResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, fmt.Errorf("%s %w", "SuccessfulMessage.value.UTDOAInformationResponse:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UTDOAInformationResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*s17.BridgeUTDOAInformationResponseFieldPerPadding(&body) = padding
		*s17.BridgeUTDOAInformationResponseFieldReceived(&body) = true
		raw.RetainContents(s17.BridgeUTDOAInformationResponseFieldReceivedBytes(&body))
		if err := aper.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyUTDOAInformationResponse = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	default:
		if err := raw.Observe(aper.UnknownProcedure); err != nil {
			return v, err
		}
		retained, err := raw.Retained()
		if err != nil {
			return v, err
		}
		v.opaque = retained
		v.isOpaque = true
	}
	return v, nil
}
func (v SuccessfulValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v SuccessfulValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	switch v.code {
	case s00.ProcedureCode(2):
		if v.bodyECIDMeasurementInitiationResponse == nil {
			return nil, fmt.Errorf("%s value: missing ECIDMeasurementInitiationResponse", "Successful")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return v.bodyECIDMeasurementInitiationResponse.marshalAPERBudget(budget, fresh)
	case s00.ProcedureCode(6):
		if v.bodyOTDOAInformationResponse == nil {
			return nil, fmt.Errorf("%s value: missing OTDOAInformationResponse", "Successful")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return s18.BridgeOTDOAInformationResponseMethodMarshalAPERBudget(v.bodyOTDOAInformationResponse, budget, fresh)
	case s00.ProcedureCode(7):
		if v.bodyUTDOAInformationResponse == nil {
			return nil, fmt.Errorf("%s value: missing UTDOAInformationResponse", "Successful")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return s17.BridgeUTDOAInformationResponseMethodMarshalAPERBudget(v.bodyUTDOAInformationResponse, budget, fresh)
	default:
		return nil, fmt.Errorf("%s value: unknown code %d without opaque content", "Successful", v.code)
	}
}
func BridgeCaptureLPPaECIDMeasurementInitiationResponse(v *ECIDMeasurementInitiationResponse, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgeECIDMeasurementInitiationResponseIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaECIDMeasurementInitiationResponse(v *ECIDMeasurementInitiationResponse, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeECIDMeasurementInitiationResponseIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaECIDMeasurementInitiationResponseIEValue(v *ECIDMeasurementInitiationResponseIEValue, s *aper.SemanticCapture) {
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
					s13.BridgeCaptureLPPaECIDMeasurementResult(v.rowECIDMeasurementResult, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s09.BridgeCaptureLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
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
		case s00.ProtocolIEID(17):
			{
				f := s.Begin()
				s.Bool(v.rowInterRATMeasurementResult == nil)
				if v.rowInterRATMeasurementResult != nil {
					s20.BridgeCaptureLPPaInterRATMeasurementResult(v.rowInterRATMeasurementResult, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(21):
			{
				f := s.Begin()
				s.Bool(v.rowWLANMeasurementResult == nil)
				if v.rowWLANMeasurementResult != nil {
					BridgeCaptureLPPaWLANMeasurementResult(v.rowWLANMeasurementResult, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ECIDMeasurementInitiationResponseIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v ECIDMeasurementInitiationResponseIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ECIDMeasurementInitiationResponseIEValue) captureSemantics(s aper.SemanticCapture) ECIDMeasurementInitiationResponseIEValue {
	BridgeCaptureLPPaECIDMeasurementInitiationResponseIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaECIDMeasurementInitiationResponseIEValue(v *ECIDMeasurementInitiationResponseIEValue, s *aper.SemanticComparison) {
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
					s13.BridgeCompareLPPaECIDMeasurementResult(v.rowECIDMeasurementResult, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					s09.BridgeCompareLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
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
		case s00.ProtocolIEID(17):
			{
				f := s.Begin()
				s.Bool(v.rowInterRATMeasurementResult == nil)
				if v.rowInterRATMeasurementResult != nil {
					s20.BridgeCompareLPPaInterRATMeasurementResult(v.rowInterRATMeasurementResult, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(21):
			{
				f := s.Begin()
				s.Bool(v.rowWLANMeasurementResult == nil)
				if v.rowWLANMeasurementResult != nil {
					BridgeCompareLPPaWLANMeasurementResult(v.rowWLANMeasurementResult, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v ECIDMeasurementInitiationResponseIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaECIDMeasurementInitiationResponseIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECIDMeasurementInitiationResponseIEValue) WithoutReplay() ECIDMeasurementInitiationResponseIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaSuccessfulOutcome(v *SuccessfulOutcome, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaProcedureCode(&v.ProcedureCode, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s00.BridgeCaptureLPPaLPPATransactionID(&v.LppatransactionID, s)
	s.OpenBytes(v.Value.captureFraming())
	BridgeCaptureLPPaSuccessfulValue(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaSuccessfulOutcome(v *SuccessfulOutcome, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProcedureCode(&v.ProcedureCode, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)
	s02.BridgeCompareLPPaLPPATransactionID(&v.LppatransactionID, s)
	BridgeCompareLPPaSuccessfulValue(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaSuccessfulValue(v *SuccessfulValue, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	s00.BridgeCaptureLPPaProcedureCode(&v.code, s)
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
		switch v.code {
		case s00.ProcedureCode(2):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementInitiationResponse == nil)
				if v.bodyECIDMeasurementInitiationResponse != nil {
					BridgeCaptureLPPaECIDMeasurementInitiationResponse(v.bodyECIDMeasurementInitiationResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyOTDOAInformationResponse == nil)
				if v.bodyOTDOAInformationResponse != nil {
					s18.BridgeCaptureLPPaOTDOAInformationResponse(v.bodyOTDOAInformationResponse, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProcedureCode(7):
			{
				f := s.Begin()
				s.Bool(v.bodyUTDOAInformationResponse == nil)
				if v.bodyUTDOAInformationResponse != nil {
					s17.BridgeCaptureLPPaUTDOAInformationResponse(v.bodyUTDOAInformationResponse, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v SuccessfulValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v SuccessfulValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v SuccessfulValue) captureSemantics(s aper.SemanticCapture) SuccessfulValue {
	BridgeCaptureLPPaSuccessfulValue(&v, &s)
	return v
}
func BridgeCompareLPPaSuccessfulValue(v *SuccessfulValue, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s02.BridgeCompareLPPaProcedureCode(&v.code, s)
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
		switch v.code {
		case s00.ProcedureCode(2):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementInitiationResponse == nil)
				if v.bodyECIDMeasurementInitiationResponse != nil {
					BridgeCompareLPPaECIDMeasurementInitiationResponse(v.bodyECIDMeasurementInitiationResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyOTDOAInformationResponse == nil)
				if v.bodyOTDOAInformationResponse != nil {
					s18.BridgeCompareLPPaOTDOAInformationResponse(v.bodyOTDOAInformationResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProcedureCode(7):
			{
				f := s.Begin()
				s.Bool(v.bodyUTDOAInformationResponse == nil)
				if v.bodyUTDOAInformationResponse != nil {
					s17.BridgeCompareLPPaUTDOAInformationResponse(v.bodyUTDOAInformationResponse, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v SuccessfulValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaSuccessfulValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v SuccessfulValue) WithoutReplay() SuccessfulValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaWLANMeasurementResult(v *WLANMeasurementResult, s *aper.SemanticCapture) {
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
			BridgeCaptureLPPaWLANMeasurementResultItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaWLANMeasurementResult(v *WLANMeasurementResult, s *aper.SemanticComparison) {
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
			BridgeCompareLPPaWLANMeasurementResultItem(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaWLANMeasurementResultComplete(v *WLANMeasurementResultComplete, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	BridgeCaptureLPPaWLANMeasurementResult(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaWLANMeasurementResultComplete(v *WLANMeasurementResultComplete, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaWLANMeasurementResult(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaWLANMeasurementResultItem(v *WLANMeasurementResultItem, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaWLANRSSI(&v.WLANRSSI, s)
	{
		f := s.Begin()
		s.Bool(v.SSID == nil)
		if v.SSID != nil {
			s00.BridgeCaptureLPPaSSID(v.SSID, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.BSSID == nil)
		if v.BSSID != nil {
			s00.BridgeCaptureLPPaBSSID(v.BSSID, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.HESSID == nil)
		if v.HESSID != nil {
			s00.BridgeCaptureLPPaHESSID(v.HESSID, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.OperatingClass == nil)
		if v.OperatingClass != nil {
			s00.BridgeCaptureLPPaWLANOperatingClass(v.OperatingClass, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.CountryCode == nil)
		if v.CountryCode != nil {
			s00.BridgeCaptureLPPaWLANCountryCode(v.CountryCode, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.WLANChannelList == nil)
	s00.BridgeCaptureLPPaWLANChannelList(&v.WLANChannelList, s)
	{
		f := s.Begin()
		s.Bool(v.WLANBand == nil)
		if v.WLANBand != nil {
			s00.BridgeCaptureLPPaWLANBand(v.WLANBand, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	s21.BridgeWLANMeasurementResultItemExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaWLANMeasurementResultItem(v *WLANMeasurementResultItem, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s03.BridgeCompareLPPaWLANRSSI(&v.WLANRSSI, s)
	{
		f := s.Begin()
		s.Bool(v.SSID == nil)
		if v.SSID != nil {
			s03.BridgeCompareLPPaSSID(v.SSID, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.BSSID == nil)
		if v.BSSID != nil {
			s02.BridgeCompareLPPaBSSID(v.BSSID, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.HESSID == nil)
		if v.HESSID != nil {
			s02.BridgeCompareLPPaHESSID(v.HESSID, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.OperatingClass == nil)
		if v.OperatingClass != nil {
			s03.BridgeCompareLPPaWLANOperatingClass(v.OperatingClass, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.CountryCode == nil)
		if v.CountryCode != nil {
			s03.BridgeCompareLPPaWLANCountryCode(v.CountryCode, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.WLANChannelList == nil)
	s03.BridgeCompareLPPaWLANChannelList(&v.WLANChannelList, s)
	{
		f := s.Begin()
		s.Bool(v.WLANBand == nil)
		if v.WLANBand != nil {
			s03.BridgeCompareLPPaWLANBand(v.WLANBand, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	s21.BridgeWLANMeasurementResultItemExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}

type ECIDMeasurementInitiationResponseIEValue struct {
	id                           s00.ProtocolIEID
	withoutReplay                bool
	received                     aper.WireSpan
	replay                       aper.Snapshot
	opaque                       *aper.OpaqueOpenType
	isOpaque                     bool
	rowESMLCUEMeasurementID      *s00.MeasurementID
	rowENBUEMeasurementID        *s00.MeasurementID
	rowECIDMeasurementResult     *s13.ECIDMeasurementResult
	rowCriticalityDiagnostics    *s09.CriticalityDiagnostics
	rowCellPortionID             *s00.CellPortionID
	rowInterRATMeasurementResult *s20.InterRATMeasurementResult
	rowWLANMeasurementResult     *WLANMeasurementResult
}

func (v ECIDMeasurementInitiationResponseIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
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
	case s00.ProtocolIEID(1):
		return v.rowCriticalityDiagnostics != nil
	case s00.ProtocolIEID(14):
		return v.rowCellPortionID != nil
	case s00.ProtocolIEID(17):
		return v.rowInterRATMeasurementResult != nil
	case s00.ProtocolIEID(21):
		return v.rowWLANMeasurementResult != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *ECIDMeasurementInitiationResponseIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ECIDMeasurementInitiationResponseIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationResponse-IEs"}}
}
func (ECIDMeasurementInitiationResponseIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(2):
		return aper.UnknownSelector
	case s00.ProtocolIEID(6):
		return aper.UnknownSelector
	case s00.ProtocolIEID(7):
		return aper.UnknownSelector
	case s00.ProtocolIEID(1):
		return aper.UnknownSelector
	case s00.ProtocolIEID(14):
		return aper.UnknownSelector
	case s00.ProtocolIEID(17):
		return aper.UnknownSelector
	case s00.ProtocolIEID(21):
		return aper.UnknownSelector
	case s00.ProtocolIEID(0):
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
	case s00.ProtocolIEID(18):
		return aper.NotInTable
	case s00.ProtocolIEID(19):
		return aper.NotInTable
	case s00.ProtocolIEID(20):
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
func (v *ECIDMeasurementInitiationResponseIEValue) AsESMLCUEMeasurementID() (*s00.MeasurementID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(2) || v.rowESMLCUEMeasurementID == nil {
		return nil, false
	}
	return v.rowESMLCUEMeasurementID, true
}

// AsENBUEMeasurementID returns the selected ENBUEMeasurementID value and reports whether that alternative is active.
func (v *ECIDMeasurementInitiationResponseIEValue) AsENBUEMeasurementID() (*s00.MeasurementID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(6) || v.rowENBUEMeasurementID == nil {
		return nil, false
	}
	return v.rowENBUEMeasurementID, true
}

// AsECIDMeasurementResult returns the selected ECIDMeasurementResult value and reports whether that alternative is active.
func (v *ECIDMeasurementInitiationResponseIEValue) AsECIDMeasurementResult() (*s13.ECIDMeasurementResult, bool) {
	if v == nil || v.id != s00.ProtocolIEID(7) || v.rowECIDMeasurementResult == nil {
		return nil, false
	}
	return v.rowECIDMeasurementResult, true
}

// AsCriticalityDiagnostics returns the selected CriticalityDiagnostics value and reports whether that alternative is active.
func (v *ECIDMeasurementInitiationResponseIEValue) AsCriticalityDiagnostics() (*s09.CriticalityDiagnostics, bool) {
	if v == nil || v.id != s00.ProtocolIEID(1) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}

// AsCellPortionID returns the selected CellPortionID value and reports whether that alternative is active.
func (v *ECIDMeasurementInitiationResponseIEValue) AsCellPortionID() (*s00.CellPortionID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(14) || v.rowCellPortionID == nil {
		return nil, false
	}
	return v.rowCellPortionID, true
}

// AsInterRATMeasurementResult returns the selected InterRATMeasurementResult value and reports whether that alternative is active.
func (v *ECIDMeasurementInitiationResponseIEValue) AsInterRATMeasurementResult() (*s20.InterRATMeasurementResult, bool) {
	if v == nil || v.id != s00.ProtocolIEID(17) || v.rowInterRATMeasurementResult == nil {
		return nil, false
	}
	return v.rowInterRATMeasurementResult, true
}

// AsWLANMeasurementResult returns the selected WLANMeasurementResult value and reports whether that alternative is active.
func (v *ECIDMeasurementInitiationResponseIEValue) AsWLANMeasurementResult() (*WLANMeasurementResult, bool) {
	if v == nil || v.id != s00.ProtocolIEID(21) || v.rowWLANMeasurementResult == nil {
		return nil, false
	}
	return v.rowWLANMeasurementResult, true
}
func (v ECIDMeasurementInitiationResponseIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (ECIDMeasurementInitiationResponseIEValue, error) {
	out := ECIDMeasurementInitiationResponseIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 2, 6, 7, 1, 14, 17, 21:
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
		var value s13.ECIDMeasurementResult
		child := raw.ChildDecodeBuffer()
		if err := s13.BridgeECIDMeasurementResultMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "ECIDMeasurementResult:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ECIDMeasurementResult")
		if err != nil {
			return out, err
		}
		*s13.BridgeECIDMeasurementResultFieldPerPadding(&value) = padding
		*s13.BridgeECIDMeasurementResultFieldReceived(&value) = true
		raw.RetainContents(s13.BridgeECIDMeasurementResultFieldReceivedBytes(&value))
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowECIDMeasurementResult = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case s00.ProtocolIEID(1):
		replayUsage := scope.Usage()
		var value s09.CriticalityDiagnostics
		child := raw.ChildDecodeBuffer()
		if err := s09.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*s09.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*s09.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(s09.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCriticalityDiagnostics = &value
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
	case s00.ProtocolIEID(17):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := s20.BridgeUnmarshalAPERInterRATMeasurementResultFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "InterRATMeasurementResult:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := func() s20.InterRATMeasurementResultComplete {
			sealed := s20.InterRATMeasurementResultComplete{Value: list}
			*s20.BridgeInterRATMeasurementResultCompleteFieldPerPadding(&sealed) = padding
			return sealed
		}()
		value := complete.Value
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowInterRATMeasurementResult = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case s00.ProtocolIEID(21):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := BridgeUnmarshalAPERWLANMeasurementResultFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "WLANMeasurementResult:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := WLANMeasurementResultComplete{Value: list, perPadding: padding}
		value := complete.Value
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowWLANMeasurementResult = &value
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
func (v ECIDMeasurementInitiationResponseIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ECIDMeasurementInitiationResponseIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementInitiationResponse-IEs.id-E-SMLC-UE-Measurement-ID:")
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
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementInitiationResponse-IEs.id-eNB-UE-Measurement-ID:")
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
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementInitiationResponse-IEs.id-E-CID-MeasurementResult:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := s13.BridgeECIDMeasurementResultMethodMarshalAPERBudget(v.rowECIDMeasurementResult, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(1):
		if v.rowCriticalityDiagnostics == nil {
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementInitiationResponse-IEs.id-CriticalityDiagnostics:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := s09.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(14):
		if v.rowCellPortionID == nil {
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementInitiationResponse-IEs.id-Cell-Portion-ID:")
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
	case s00.ProtocolIEID(17):
		if v.rowInterRATMeasurementResult == nil {
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementInitiationResponse-IEs.id-InterRATMeasurementResult:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		complete := s20.InterRATMeasurementResultComplete{Value: *v.rowInterRATMeasurementResult}
		candidate, err := s20.BridgeInterRATMeasurementResultCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(21):
		if v.rowWLANMeasurementResult == nil {
			return nil, fmt.Errorf("%s missing value", "E-CIDMeasurementInitiationResponse-IEs.id-WLANMeasurementResult:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		complete := WLANMeasurementResultComplete{Value: *v.rowWLANMeasurementResult}
		candidate, err := complete.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "ECIDMeasurementInitiationResponseIEValue:", v.id)
	}
}

type ECIDMeasurementInitiationResponseIETable struct{}

func ECIDMeasurementInitiationResponseIEs() ECIDMeasurementInitiationResponseIETable {
	return ECIDMeasurementInitiationResponseIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (ECIDMeasurementInitiationResponseIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationResponse-IEs"}
		return sealed
	}()
}
func (ECIDMeasurementInitiationResponseIETable) infoESMLCUEMeasurementID() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementInitiationResponseIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationResponse-IEs", Row: "id-E-SMLC-UE-Measurement-ID"}}}
}

// ESMLCUEMeasurementID returns the typed binding for the ESMLCUEMeasurementID row of this table.
func (t ECIDMeasurementInitiationResponseIETable) ESMLCUEMeasurementID() ECIDMeasurementInitiationResponseMeasurementIDIEBinding {
	return ECIDMeasurementInitiationResponseMeasurementIDIEBinding{info: t.infoESMLCUEMeasurementID(), codec: func() s00.MeasurementIDValueCodec {
		sealed := s00.MeasurementIDValueCodec{}
		*s00.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*s00.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MeasurementID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MeasurementID
				return empty, err
			}
			var zero ECIDMeasurementInitiationResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(2), raw)
			if err != nil {
				var empty s00.MeasurementID
				return empty, err
			}
			value, ok := decoded.AsESMLCUEMeasurementID()
			if !ok {
				var empty s00.MeasurementID
				return empty, fmt.Errorf("binding E-CIDMeasurementInitiationResponse-IEs.id-E-SMLC-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value s00.MeasurementID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationResponseIEValue{id: s00.ProtocolIEID(2), rowESMLCUEMeasurementID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MeasurementID) ECIDMeasurementInitiationResponseIEValue {
			return ECIDMeasurementInitiationResponseIEValue{id: s00.ProtocolIEID(2), rowESMLCUEMeasurementID: &value}
		}, get: func(value *ECIDMeasurementInitiationResponseIEValue) (*s00.MeasurementID, bool) {
			return value.AsESMLCUEMeasurementID()
		}}
}
func (ECIDMeasurementInitiationResponseIETable) infoENBUEMeasurementID() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementInitiationResponseIEs().ID(), ID: s00.ProtocolIEID(6), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationResponse-IEs", Row: "id-eNB-UE-Measurement-ID"}}}
}

// ENBUEMeasurementID returns the typed binding for the ENBUEMeasurementID row of this table.
func (t ECIDMeasurementInitiationResponseIETable) ENBUEMeasurementID() ECIDMeasurementInitiationResponseMeasurementIDIEBinding {
	return ECIDMeasurementInitiationResponseMeasurementIDIEBinding{info: t.infoENBUEMeasurementID(), codec: func() s00.MeasurementIDValueCodec {
		sealed := s00.MeasurementIDValueCodec{}
		*s00.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*s00.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MeasurementID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MeasurementID
				return empty, err
			}
			var zero ECIDMeasurementInitiationResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(6), raw)
			if err != nil {
				var empty s00.MeasurementID
				return empty, err
			}
			value, ok := decoded.AsENBUEMeasurementID()
			if !ok {
				var empty s00.MeasurementID
				return empty, fmt.Errorf("binding E-CIDMeasurementInitiationResponse-IEs.id-eNB-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value s00.MeasurementID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationResponseIEValue{id: s00.ProtocolIEID(6), rowENBUEMeasurementID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.MeasurementID) ECIDMeasurementInitiationResponseIEValue {
			return ECIDMeasurementInitiationResponseIEValue{id: s00.ProtocolIEID(6), rowENBUEMeasurementID: &value}
		}, get: func(value *ECIDMeasurementInitiationResponseIEValue) (*s00.MeasurementID, bool) {
			return value.AsENBUEMeasurementID()
		}}
}
func (ECIDMeasurementInitiationResponseIETable) infoECIDMeasurementResult() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementInitiationResponseIEs().ID(), ID: s00.ProtocolIEID(7), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ECIDMeasurementResult"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationResponse-IEs", Row: "id-E-CID-MeasurementResult"}}}
}

// ECIDMeasurementResult returns the typed binding for the ECIDMeasurementResult row of this table.
func (t ECIDMeasurementInitiationResponseIETable) ECIDMeasurementResult() ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding {
	return ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding{info: t.infoECIDMeasurementResult(), codec: func() s13.ECIDMeasurementResultValueCodec {
		sealed := s13.ECIDMeasurementResultValueCodec{}
		*s13.BridgeECIDMeasurementResultValueCodecFieldPath(&sealed) = "ECIDMeasurementResult"
		*s13.BridgeECIDMeasurementResultValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s13.ECIDMeasurementResult, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s13.ECIDMeasurementResult
				return empty, err
			}
			var zero ECIDMeasurementInitiationResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(7), raw)
			if err != nil {
				var empty s13.ECIDMeasurementResult
				return empty, err
			}
			value, ok := decoded.AsECIDMeasurementResult()
			if !ok {
				var empty s13.ECIDMeasurementResult
				return empty, fmt.Errorf("binding E-CIDMeasurementInitiationResponse-IEs.id-E-CID-MeasurementResult: no selected value")
			}
			return *value, nil
		}
		*s13.BridgeECIDMeasurementResultValueCodecFieldEncode(&sealed) = func(value s13.ECIDMeasurementResult, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationResponseIEValue{id: s00.ProtocolIEID(7), rowECIDMeasurementResult: &value}).encodeFresh(fresh, budget)
		}
		*s13.BridgeECIDMeasurementResultValueCodecFieldCapture(&sealed) = func(v s13.ECIDMeasurementResult, options aper.DecodeState) (s13.ECIDMeasurementResult, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s13.BridgeCaptureLPPaECIDMeasurementResult(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*s13.BridgeECIDMeasurementResultValueCodecFieldCompare(&sealed) = func(v s13.ECIDMeasurementResult, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s13.BridgeCompareLPPaECIDMeasurementResult(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s13.BridgeECIDMeasurementResultValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ECIDMeasurementResult"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s13.ECIDMeasurementResult) ECIDMeasurementInitiationResponseIEValue {
			return ECIDMeasurementInitiationResponseIEValue{id: s00.ProtocolIEID(7), rowECIDMeasurementResult: &value}
		}, get: func(value *ECIDMeasurementInitiationResponseIEValue) (*s13.ECIDMeasurementResult, bool) {
			return value.AsECIDMeasurementResult()
		}}
}
func (ECIDMeasurementInitiationResponseIETable) infoCriticalityDiagnostics() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementInitiationResponseIEs().ID(), ID: s00.ProtocolIEID(1), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationResponse-IEs", Row: "id-CriticalityDiagnostics"}}}
}

// CriticalityDiagnostics returns the typed binding for the CriticalityDiagnostics row of this table.
func (t ECIDMeasurementInitiationResponseIETable) CriticalityDiagnostics() ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding {
	return ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() s09.CriticalityDiagnosticsValueCodec {
		sealed := s09.CriticalityDiagnosticsValueCodec{}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s09.CriticalityDiagnostics, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s09.CriticalityDiagnostics
				return empty, err
			}
			var zero ECIDMeasurementInitiationResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(1), raw)
			if err != nil {
				var empty s09.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty s09.CriticalityDiagnostics
				return empty, fmt.Errorf("binding E-CIDMeasurementInitiationResponse-IEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value s09.CriticalityDiagnostics, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationResponseIEValue{id: s00.ProtocolIEID(1), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v s09.CriticalityDiagnostics, options aper.DecodeState) (s09.CriticalityDiagnostics, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s09.BridgeCaptureLPPaCriticalityDiagnostics(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v s09.CriticalityDiagnostics, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s09.BridgeCompareLPPaCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s09.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s09.CriticalityDiagnostics) ECIDMeasurementInitiationResponseIEValue {
			return ECIDMeasurementInitiationResponseIEValue{id: s00.ProtocolIEID(1), rowCriticalityDiagnostics: &value}
		}, get: func(value *ECIDMeasurementInitiationResponseIEValue) (*s09.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (ECIDMeasurementInitiationResponseIETable) infoCellPortionID() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementInitiationResponseIEs().ID(), ID: s00.ProtocolIEID(14), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "CellPortionID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationResponse-IEs", Row: "id-Cell-Portion-ID"}}}
}

// CellPortionID returns the typed binding for the CellPortionID row of this table.
func (t ECIDMeasurementInitiationResponseIETable) CellPortionID() ECIDMeasurementInitiationResponseCellPortionIDIEBinding {
	return ECIDMeasurementInitiationResponseCellPortionIDIEBinding{info: t.infoCellPortionID(), codec: func() s00.CellPortionIDValueCodec {
		sealed := s00.CellPortionIDValueCodec{}
		*s00.BridgeCellPortionIDValueCodecFieldPath(&sealed) = "CellPortionID"
		*s00.BridgeCellPortionIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CellPortionID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CellPortionID
				return empty, err
			}
			var zero ECIDMeasurementInitiationResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(14), raw)
			if err != nil {
				var empty s00.CellPortionID
				return empty, err
			}
			value, ok := decoded.AsCellPortionID()
			if !ok {
				var empty s00.CellPortionID
				return empty, fmt.Errorf("binding E-CIDMeasurementInitiationResponse-IEs.id-Cell-Portion-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCellPortionIDValueCodecFieldEncode(&sealed) = func(value s00.CellPortionID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationResponseIEValue{id: s00.ProtocolIEID(14), rowCellPortionID: &value}).encodeFresh(fresh, budget)
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
		inject: func(value s00.CellPortionID) ECIDMeasurementInitiationResponseIEValue {
			return ECIDMeasurementInitiationResponseIEValue{id: s00.ProtocolIEID(14), rowCellPortionID: &value}
		}, get: func(value *ECIDMeasurementInitiationResponseIEValue) (*s00.CellPortionID, bool) {
			return value.AsCellPortionID()
		}}
}
func (ECIDMeasurementInitiationResponseIETable) infoInterRATMeasurementResult() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementInitiationResponseIEs().ID(), ID: s00.ProtocolIEID(17), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "InterRATMeasurementResult"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationResponse-IEs", Row: "id-InterRATMeasurementResult"}}}
}

// InterRATMeasurementResult returns the typed binding for the InterRATMeasurementResult row of this table.
func (t ECIDMeasurementInitiationResponseIETable) InterRATMeasurementResult() ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding {
	return ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding{info: t.infoInterRATMeasurementResult(), codec: func() s20.InterRATMeasurementResultValueCodec {
		sealed := s20.InterRATMeasurementResultValueCodec{}
		*s20.BridgeInterRATMeasurementResultValueCodecFieldPath(&sealed) = "InterRATMeasurementResult"
		*s20.BridgeInterRATMeasurementResultValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.InterRATMeasurementResult, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s20.InterRATMeasurementResult
				return empty, err
			}
			var zero ECIDMeasurementInitiationResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(17), raw)
			if err != nil {
				var empty s20.InterRATMeasurementResult
				return empty, err
			}
			value, ok := decoded.AsInterRATMeasurementResult()
			if !ok {
				var empty s20.InterRATMeasurementResult
				return empty, fmt.Errorf("binding E-CIDMeasurementInitiationResponse-IEs.id-InterRATMeasurementResult: no selected value")
			}
			return *value, nil
		}
		*s20.BridgeInterRATMeasurementResultValueCodecFieldEncode(&sealed) = func(value s20.InterRATMeasurementResult, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationResponseIEValue{id: s00.ProtocolIEID(17), rowInterRATMeasurementResult: &value}).encodeFresh(fresh, budget)
		}
		*s20.BridgeInterRATMeasurementResultValueCodecFieldCapture(&sealed) = func(v s20.InterRATMeasurementResult, options aper.DecodeState) (s20.InterRATMeasurementResult, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s20.BridgeCaptureLPPaInterRATMeasurementResult(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeInterRATMeasurementResultValueCodecFieldCompare(&sealed) = func(v s20.InterRATMeasurementResult, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s20.BridgeCompareLPPaInterRATMeasurementResult(&v, &s)
			s.End(f, root, false)
			return s.
				Plan()
		}
		*s20.BridgeInterRATMeasurementResultValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:InterRATMeasurementResult"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s20.InterRATMeasurementResult) ECIDMeasurementInitiationResponseIEValue {
			return ECIDMeasurementInitiationResponseIEValue{id: s00.ProtocolIEID(17), rowInterRATMeasurementResult: &value}
		}, get: func(value *ECIDMeasurementInitiationResponseIEValue) (*s20.InterRATMeasurementResult, bool) {
			return value.AsInterRATMeasurementResult()
		}}
}
func (ECIDMeasurementInitiationResponseIETable) infoWLANMeasurementResult() s00.FieldInfo {
	return s00.FieldInfo{Table: ECIDMeasurementInitiationResponseIEs().ID(), ID: s00.ProtocolIEID(21), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementResult"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationResponse-IEs", Row: "id-WLANMeasurementResult"}}}
}

// WLANMeasurementResult returns the typed binding for the WLANMeasurementResult row of this table.
func (t ECIDMeasurementInitiationResponseIETable) WLANMeasurementResult() ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding {
	return ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding{info: t.infoWLANMeasurementResult(), codec: WLANMeasurementResultValueCodec{path: "WLANMeasurementResult",
		decode: func(data []byte, options aper.DecodeState) (WLANMeasurementResult, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty WLANMeasurementResult
				return empty, err
			}
			var zero ECIDMeasurementInitiationResponseIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(21), raw)
			if err != nil {
				var empty WLANMeasurementResult
				return empty, err
			}
			value, ok := decoded.AsWLANMeasurementResult()
			if !ok {
				var empty WLANMeasurementResult
				return empty, fmt.Errorf("binding E-CIDMeasurementInitiationResponse-IEs.id-WLANMeasurementResult: no selected value")
			}
			return *value, nil
		},
		encode: func(value WLANMeasurementResult, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationResponseIEValue{id: s00.ProtocolIEID(21), rowWLANMeasurementResult: &value}).encodeFresh(fresh, budget)
		}, capture: func(v WLANMeasurementResult, options aper.DecodeState) (WLANMeasurementResult, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureLPPaWLANMeasurementResult(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}, compare: func(v WLANMeasurementResult, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaWLANMeasurementResult(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WLANMeasurementResult"
			return sealed
		}(),
	}, inject: func(value WLANMeasurementResult) ECIDMeasurementInitiationResponseIEValue {
		return ECIDMeasurementInitiationResponseIEValue{id: s00.ProtocolIEID(21), rowWLANMeasurementResult: &value}
	}, get: func(value *ECIDMeasurementInitiationResponseIEValue) (*WLANMeasurementResult, bool) {
		return value.AsWLANMeasurementResult()
	}}
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t ECIDMeasurementInitiationResponseIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (ECIDMeasurementInitiationResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(2):
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-SMLC-UE-Measurement-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(6):
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-Measurement-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(7):
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-CID-MeasurementResult requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(1):
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(14):
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cell-Portion-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(17):
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-InterRATMeasurementResult requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(21):
		return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(fmt.Errorf("known IE id-WLANMeasurementResult requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ECIDMeasurementInitiationResponseIEField{}, aper.OperationError(err, "Opaque")
		}
		return ECIDMeasurementInitiationResponseIEField{Id: id, Criticality: criticality, Value: ECIDMeasurementInitiationResponseIEValue{id: id, opaque: retained, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// CellPortionIDCodec binds the complete APER value type.
func CellPortionIDCodec() s00.CellPortionIDValueCodec {
	return ECIDMeasurementInitiationResponseIEs().CellPortionID().Codec()
}

// ECIDMeasurementResultCodec binds the complete APER value type.
func ECIDMeasurementResultCodec() s13.ECIDMeasurementResultValueCodec {
	return ECIDMeasurementInitiationResponseIEs().ECIDMeasurementResult().Codec()
}

// InterRATMeasurementResultCodec binds the complete APER value type.
func InterRATMeasurementResultCodec() s20.InterRATMeasurementResultValueCodec {
	return ECIDMeasurementInitiationResponseIEs().InterRATMeasurementResult().Codec()
}

// WLANMeasurementResultCodec binds the complete APER value type.
func WLANMeasurementResultCodec() WLANMeasurementResultValueCodec {
	return ECIDMeasurementInitiationResponseIEs().WLANMeasurementResult().Codec()
}

// WLANMeasurementResultItemCodec binds the complete source value type.
func WLANMeasurementResultItemCodec() WLANMeasurementResultItemValueCodec {
	return WLANMeasurementResultItemValueCodec{path: "WLANMeasurementResultItem", decode: func(data []byte, options aper.DecodeState) (WLANMeasurementResultItem, error) {
		var value WLANMeasurementResultItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return WLANMeasurementResultItem{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value WLANMeasurementResultItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v WLANMeasurementResultItem, options aper.DecodeState) (WLANMeasurementResultItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaWLANMeasurementResultItem(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v WLANMeasurementResultItem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaWLANMeasurementResultItem(&v, &s)
		s.End(f, root, false)
		return s.
			Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:WLANMeasurementResultItem"
		return sealed
	}(),
	}
}
func BridgeECIDMeasurementInitiationResponseAPERValueFieldContext(v *ECIDMeasurementInitiationResponseAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementInitiationResponseAPERValueFieldReceived(v *ECIDMeasurementInitiationResponseAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementInitiationResponseAPERValueFieldReplay(v *ECIDMeasurementInitiationResponseAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationResponseAPERValueFieldWithoutReplay(v *ECIDMeasurementInitiationResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationResponseCellPortionIDIEBindingFieldCodec(v *ECIDMeasurementInitiationResponseCellPortionIDIEBinding) *s00.CellPortionIDValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationResponseCellPortionIDIEBindingFieldGet(v *ECIDMeasurementInitiationResponseCellPortionIDIEBinding) *func(*ECIDMeasurementInitiationResponseIEValue) (*s00.CellPortionID, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationResponseCellPortionIDIEBindingFieldInfo(v *ECIDMeasurementInitiationResponseCellPortionIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationResponseCellPortionIDIEBindingFieldInject(v *ECIDMeasurementInitiationResponseCellPortionIDIEBinding) *func(s00.CellPortionID) ECIDMeasurementInitiationResponseIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBindingFieldCodec(v *ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding) *s09.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBindingFieldGet(v *ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding) *func(*ECIDMeasurementInitiationResponseIEValue) (*s09.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBindingFieldInfo(v *ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBindingFieldInject(v *ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding) *func(s09.CriticalityDiagnostics) ECIDMeasurementInitiationResponseIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationResponseECIDMeasurementResultIEBindingFieldCodec(v *ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding) *s13.ECIDMeasurementResultValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationResponseECIDMeasurementResultIEBindingFieldGet(v *ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding) *func(*ECIDMeasurementInitiationResponseIEValue) (*s13.ECIDMeasurementResult, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationResponseECIDMeasurementResultIEBindingFieldInfo(v *ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationResponseECIDMeasurementResultIEBindingFieldInject(v *ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding) *func(s13.ECIDMeasurementResult) ECIDMeasurementInitiationResponseIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationResponseFieldExtCount(v *ECIDMeasurementInitiationResponse) *int64 {
	return &v.extCount
}
func BridgeECIDMeasurementInitiationResponseFieldExtData(v *ECIDMeasurementInitiationResponse) *[][]byte {
	return &v.extData
}
func BridgeECIDMeasurementInitiationResponseFieldExtOrigin(v *ECIDMeasurementInitiationResponse) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeECIDMeasurementInitiationResponseFieldExtPresent(v *ECIDMeasurementInitiationResponse) *[]bool {
	return &v.extPresent
}
func BridgeECIDMeasurementInitiationResponseFieldExtWire(v *ECIDMeasurementInitiationResponse) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeECIDMeasurementInitiationResponseFieldPerExtPadding(v *ECIDMeasurementInitiationResponse) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeECIDMeasurementInitiationResponseFieldPerPadding(v *ECIDMeasurementInitiationResponse) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeECIDMeasurementInitiationResponseFieldProtocolIEsIndef(v *ECIDMeasurementInitiationResponse) *bool {
	return &v.protocolIEsIndef
}
func BridgeECIDMeasurementInitiationResponseFieldReceived(v *ECIDMeasurementInitiationResponse) *bool {
	return &v.received
}
func BridgeECIDMeasurementInitiationResponseFieldReceivedBytes(v *ECIDMeasurementInitiationResponse) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeECIDMeasurementInitiationResponseFieldReplay(v *ECIDMeasurementInitiationResponse) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationResponseFieldStream(v *ECIDMeasurementInitiationResponse) *aper.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementInitiationResponseFieldWithoutReplay(v *ECIDMeasurementInitiationResponse) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationResponseIEFieldFieldReceived(v *ECIDMeasurementInitiationResponseIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeECIDMeasurementInitiationResponseIEFieldFieldReplay(v *ECIDMeasurementInitiationResponseIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationResponseIEFieldFieldStream(v *ECIDMeasurementInitiationResponseIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementInitiationResponseIEFieldFieldWithoutReplay(v *ECIDMeasurementInitiationResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationResponseIEFieldMethodMarshalAPERTo(v *ECIDMeasurementInitiationResponseIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementInitiationResponseIEFieldMethodUnmarshalAPERFrom(v *ECIDMeasurementInitiationResponseIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementInitiationResponseIETableMethodInfoCellPortionID(v ECIDMeasurementInitiationResponseIETable) s00.FieldInfo {
	return v.infoCellPortionID()
}
func BridgeECIDMeasurementInitiationResponseIETableMethodInfoCriticalityDiagnostics(v ECIDMeasurementInitiationResponseIETable) s00.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeECIDMeasurementInitiationResponseIETableMethodInfoECIDMeasurementResult(v ECIDMeasurementInitiationResponseIETable) s00.FieldInfo {
	return v.infoECIDMeasurementResult()
}
func BridgeECIDMeasurementInitiationResponseIETableMethodInfoENBUEMeasurementID(v ECIDMeasurementInitiationResponseIETable) s00.FieldInfo {
	return v.infoENBUEMeasurementID()
}
func BridgeECIDMeasurementInitiationResponseIETableMethodInfoESMLCUEMeasurementID(v ECIDMeasurementInitiationResponseIETable) s00.FieldInfo {
	return v.infoESMLCUEMeasurementID()
}
func BridgeECIDMeasurementInitiationResponseIETableMethodInfoInterRATMeasurementResult(v ECIDMeasurementInitiationResponseIETable) s00.FieldInfo {
	return v.infoInterRATMeasurementResult()
}
func BridgeECIDMeasurementInitiationResponseIETableMethodInfoWLANMeasurementResult(v ECIDMeasurementInitiationResponseIETable) s00.FieldInfo {
	return v.infoWLANMeasurementResult()
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldId(v *ECIDMeasurementInitiationResponseIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldIsOpaque(v *ECIDMeasurementInitiationResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldOpaque(v *ECIDMeasurementInitiationResponseIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldReceived(v *ECIDMeasurementInitiationResponseIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldReplay(v *ECIDMeasurementInitiationResponseIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldRowCellPortionID(v *ECIDMeasurementInitiationResponseIEValue) **s00.CellPortionID {
	return &v.rowCellPortionID
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldRowCriticalityDiagnostics(v *ECIDMeasurementInitiationResponseIEValue) **s09.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldRowECIDMeasurementResult(v *ECIDMeasurementInitiationResponseIEValue) **s13.ECIDMeasurementResult {
	return &v.rowECIDMeasurementResult
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldRowENBUEMeasurementID(v *ECIDMeasurementInitiationResponseIEValue) **s00.MeasurementID {
	return &v.rowENBUEMeasurementID
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldRowESMLCUEMeasurementID(v *ECIDMeasurementInitiationResponseIEValue) **s00.MeasurementID {
	return &v.rowESMLCUEMeasurementID
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldRowInterRATMeasurementResult(v *ECIDMeasurementInitiationResponseIEValue) **s20.InterRATMeasurementResult {
	return &v.rowInterRATMeasurementResult
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldRowWLANMeasurementResult(v *ECIDMeasurementInitiationResponseIEValue) **WLANMeasurementResult {
	return &v.rowWLANMeasurementResult
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldWithoutReplay(v *ECIDMeasurementInitiationResponseIEValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationResponseIEValueMethodCaptureFraming(v ECIDMeasurementInitiationResponseIEValue) uint64 {
	return v.captureFraming()
}
func BridgeECIDMeasurementInitiationResponseIEValueMethodCaptureSemantics(v ECIDMeasurementInitiationResponseIEValue, a0 aper.SemanticCapture) ECIDMeasurementInitiationResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeECIDMeasurementInitiationResponseIEValueMethodCaptureSnapshot(v ECIDMeasurementInitiationResponseIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeECIDMeasurementInitiationResponseIEValueMethodCompareSemantics(v ECIDMeasurementInitiationResponseIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeECIDMeasurementInitiationResponseIEValueMethodDecode(v ECIDMeasurementInitiationResponseIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (ECIDMeasurementInitiationResponseIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeECIDMeasurementInitiationResponseIEValueMethodEncode(v ECIDMeasurementInitiationResponseIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeECIDMeasurementInitiationResponseIEValueMethodEncodeFresh(v ECIDMeasurementInitiationResponseIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeECIDMeasurementInitiationResponseIEValueMethodMatchesID(v ECIDMeasurementInitiationResponseIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeECIDMeasurementInitiationResponseIEValueMethodReason(v ECIDMeasurementInitiationResponseIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeECIDMeasurementInitiationResponseIEValueMethodRule(v ECIDMeasurementInitiationResponseIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeECIDMeasurementInitiationResponseInterRATMeasurementResultIEBindingFieldCodec(v *ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding) *s20.InterRATMeasurementResultValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationResponseInterRATMeasurementResultIEBindingFieldGet(v *ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding) *func(*ECIDMeasurementInitiationResponseIEValue) (*s20.InterRATMeasurementResult, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationResponseInterRATMeasurementResultIEBindingFieldInfo(v *ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationResponseInterRATMeasurementResultIEBindingFieldInject(v *ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding) *func(s20.InterRATMeasurementResult) ECIDMeasurementInitiationResponseIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationResponseMeasurementIDIEBindingFieldCodec(v *ECIDMeasurementInitiationResponseMeasurementIDIEBinding) *s00.MeasurementIDValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationResponseMeasurementIDIEBindingFieldGet(v *ECIDMeasurementInitiationResponseMeasurementIDIEBinding) *func(*ECIDMeasurementInitiationResponseIEValue) (*s00.MeasurementID, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationResponseMeasurementIDIEBindingFieldInfo(v *ECIDMeasurementInitiationResponseMeasurementIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationResponseMeasurementIDIEBindingFieldInject(v *ECIDMeasurementInitiationResponseMeasurementIDIEBinding) *func(s00.MeasurementID) ECIDMeasurementInitiationResponseIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationResponseMethodMarshalAPERBudget(v *ECIDMeasurementInitiationResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeECIDMeasurementInitiationResponseMethodMarshalAPERChanged(v *ECIDMeasurementInitiationResponse, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeECIDMeasurementInitiationResponseMethodMarshalAPERChangedValue(v *ECIDMeasurementInitiationResponse, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeECIDMeasurementInitiationResponseMethodMarshalAPERFreshValue(v *ECIDMeasurementInitiationResponse, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeECIDMeasurementInitiationResponseMethodMarshalAPERLegacy(v *ECIDMeasurementInitiationResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeECIDMeasurementInitiationResponseMethodMarshalAPERPlanned(v *ECIDMeasurementInitiationResponse, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeECIDMeasurementInitiationResponseMethodMarshalAPERTo(v *ECIDMeasurementInitiationResponse, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementInitiationResponseMethodUnmarshalAPERFrom(v *ECIDMeasurementInitiationResponse, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementInitiationResponseMethodUnmarshalAPERLegacy(v *ECIDMeasurementInitiationResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeECIDMeasurementInitiationResponseMethodUnmarshalAPERWithOptions(v *ECIDMeasurementInitiationResponse, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeECIDMeasurementInitiationResponseValueCodecFieldCapture(v *ECIDMeasurementInitiationResponseValueCodec) *func(ECIDMeasurementInitiationResponse, aper.DecodeState) (ECIDMeasurementInitiationResponse, aper.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementInitiationResponseValueCodecFieldCompare(v *ECIDMeasurementInitiationResponseValueCodec) *func(ECIDMeasurementInitiationResponse, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementInitiationResponseValueCodecFieldContext(v *ECIDMeasurementInitiationResponseValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementInitiationResponseValueCodecFieldDecode(v *ECIDMeasurementInitiationResponseValueCodec) *func([]byte, aper.DecodeState) (ECIDMeasurementInitiationResponse, error) {
	return &v.decode
}
func BridgeECIDMeasurementInitiationResponseValueCodecFieldEncode(v *ECIDMeasurementInitiationResponseValueCodec) *func(ECIDMeasurementInitiationResponse, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementInitiationResponseValueCodecFieldPath(v *ECIDMeasurementInitiationResponseValueCodec) *aper.Path {
	return &v.path
}
func BridgeECIDMeasurementInitiationResponseValueCodecMethodEncodeBudget(v ECIDMeasurementInitiationResponseValueCodec, a0 ECIDMeasurementInitiationResponse, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeECIDMeasurementInitiationResponseValueCodecMethodEncodeChanged(v ECIDMeasurementInitiationResponseValueCodec, a0 ECIDMeasurementInitiationResponse, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeECIDMeasurementInitiationResponseWLANMeasurementResultIEBindingFieldCodec(v *ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding) *WLANMeasurementResultValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationResponseWLANMeasurementResultIEBindingFieldGet(v *ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding) *func(*ECIDMeasurementInitiationResponseIEValue) (*WLANMeasurementResult, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationResponseWLANMeasurementResultIEBindingFieldInfo(v *ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationResponseWLANMeasurementResultIEBindingFieldInject(v *ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding) *func(WLANMeasurementResult) ECIDMeasurementInitiationResponseIEValue {
	return &v.inject
}
func BridgeSuccessfulOutcomeFieldPerPadding(v *SuccessfulOutcome) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeSuccessfulOutcomeFieldReceived(v *SuccessfulOutcome) *bool { return &v.received }
func BridgeSuccessfulOutcomeFieldReceivedBytes(v *SuccessfulOutcome) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSuccessfulOutcomeFieldReplay(v *SuccessfulOutcome) *aper.Snapshot { return &v.replay }
func BridgeSuccessfulOutcomeFieldStream(v *SuccessfulOutcome) *aper.WireSpan { return &v.stream }
func BridgeSuccessfulOutcomeFieldWithoutReplay(v *SuccessfulOutcome) *bool   { return &v.withoutReplay }
func BridgeSuccessfulOutcomeMethodMarshalAPERBudget(v *SuccessfulOutcome, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSuccessfulOutcomeMethodMarshalAPERChanged(v *SuccessfulOutcome, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSuccessfulOutcomeMethodMarshalAPERChangedValue(v *SuccessfulOutcome, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSuccessfulOutcomeMethodMarshalAPERFreshValue(v *SuccessfulOutcome, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeSuccessfulOutcomeMethodMarshalAPERLegacy(v *SuccessfulOutcome) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSuccessfulOutcomeMethodMarshalAPERPlanned(v *SuccessfulOutcome, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeSuccessfulOutcomeMethodMarshalAPERTo(v *SuccessfulOutcome, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSuccessfulOutcomeMethodUnmarshalAPERFrom(v *SuccessfulOutcome, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSuccessfulOutcomeMethodUnmarshalAPERLegacy(v *SuccessfulOutcome, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSuccessfulOutcomeMethodUnmarshalAPERWithOptions(v *SuccessfulOutcome, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSuccessfulValueFieldBodyECIDMeasurementInitiationResponse(v *SuccessfulValue) **ECIDMeasurementInitiationResponse {
	return &v.bodyECIDMeasurementInitiationResponse
}
func BridgeSuccessfulValueFieldBodyOTDOAInformationResponse(v *SuccessfulValue) **s18.OTDOAInformationResponse {
	return &v.bodyOTDOAInformationResponse
}
func BridgeSuccessfulValueFieldBodyUTDOAInformationResponse(v *SuccessfulValue) **s17.UTDOAInformationResponse {
	return &v.bodyUTDOAInformationResponse
}
func BridgeSuccessfulValueFieldCode(v *SuccessfulValue) *s00.ProcedureCode      { return &v.code }
func BridgeSuccessfulValueFieldIsOpaque(v *SuccessfulValue) *bool               { return &v.isOpaque }
func BridgeSuccessfulValueFieldOpaque(v *SuccessfulValue) **aper.OpaqueOpenType { return &v.opaque }
func BridgeSuccessfulValueFieldReceived(v *SuccessfulValue) *aper.WireSpan      { return &v.received }
func BridgeSuccessfulValueFieldReplay(v *SuccessfulValue) *aper.Snapshot        { return &v.replay }
func BridgeSuccessfulValueFieldWithoutReplay(v *SuccessfulValue) *bool          { return &v.withoutReplay }
func BridgeSuccessfulValueMethodCaptureFraming(v SuccessfulValue) uint64        { return v.captureFraming() }
func BridgeSuccessfulValueMethodCaptureSemantics(v SuccessfulValue, a0 aper.SemanticCapture) SuccessfulValue {
	return v.captureSemantics(a0)
}
func BridgeSuccessfulValueMethodCaptureSnapshot(v SuccessfulValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeSuccessfulValueMethodCompareSemantics(v SuccessfulValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeSuccessfulValueMethodEncode(v SuccessfulValue) ([]byte, error) { return v.encode() }
func BridgeSuccessfulValueMethodEncodeFresh(v SuccessfulValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeWLANMeasurementResultAPERValueFieldContext(v *WLANMeasurementResultAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementResultAPERValueFieldReceived(v *WLANMeasurementResultAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWLANMeasurementResultAPERValueFieldReplay(v *WLANMeasurementResultAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementResultAPERValueFieldWithoutReplay(v *WLANMeasurementResultAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementResultCompleteFieldPerPadding(v *WLANMeasurementResultComplete) *aper.CompletePadding {
	return &v.perPadding
}
func BridgeWLANMeasurementResultCompleteFieldReceived(v *WLANMeasurementResultComplete) *bool {
	return &v.received
}
func BridgeWLANMeasurementResultCompleteFieldReceivedBytes(v *WLANMeasurementResultComplete) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeWLANMeasurementResultCompleteFieldReplay(v *WLANMeasurementResultComplete) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementResultCompleteFieldStream(v *WLANMeasurementResultComplete) *aper.WireSpan {
	return &v.stream
}
func BridgeWLANMeasurementResultCompleteFieldWithoutReplay(v *WLANMeasurementResultComplete) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementResultCompleteMethodMarshalAPERBudget(v *WLANMeasurementResultComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeWLANMeasurementResultCompleteMethodMarshalAPERChanged(v *WLANMeasurementResultComplete, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeWLANMeasurementResultCompleteMethodMarshalAPERChangedValue(v *WLANMeasurementResultComplete, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeWLANMeasurementResultCompleteMethodMarshalAPERFreshValue(v *WLANMeasurementResultComplete, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeWLANMeasurementResultCompleteMethodMarshalAPERLegacy(v *WLANMeasurementResultComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeWLANMeasurementResultCompleteMethodMarshalAPERPlanned(v *WLANMeasurementResultComplete, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeWLANMeasurementResultCompleteMethodUnmarshalAPERLegacy(v *WLANMeasurementResultComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeWLANMeasurementResultCompleteMethodUnmarshalAPERWithOptions(v *WLANMeasurementResultComplete, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeWLANMeasurementResultItemAPERValueFieldContext(v *WLANMeasurementResultItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementResultItemAPERValueFieldReceived(v *WLANMeasurementResultItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeWLANMeasurementResultItemAPERValueFieldReplay(v *WLANMeasurementResultItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementResultItemAPERValueFieldWithoutReplay(v *WLANMeasurementResultItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementResultItemFieldExtCount(v *WLANMeasurementResultItem) *int64 {
	return &v.extCount
}
func BridgeWLANMeasurementResultItemFieldExtData(v *WLANMeasurementResultItem) *[][]byte {
	return &v.extData
}
func BridgeWLANMeasurementResultItemFieldExtOrigin(v *WLANMeasurementResultItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeWLANMeasurementResultItemFieldExtPresent(v *WLANMeasurementResultItem) *[]bool {
	return &v.extPresent
}
func BridgeWLANMeasurementResultItemFieldExtWire(v *WLANMeasurementResultItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeWLANMeasurementResultItemFieldIEExtensionsIndef(v *WLANMeasurementResultItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeWLANMeasurementResultItemFieldPerExtPadding(v *WLANMeasurementResultItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeWLANMeasurementResultItemFieldPerPadding(v *WLANMeasurementResultItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeWLANMeasurementResultItemFieldReceived(v *WLANMeasurementResultItem) *bool {
	return &v.received
}
func BridgeWLANMeasurementResultItemFieldReceivedBytes(v *WLANMeasurementResultItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeWLANMeasurementResultItemFieldReplay(v *WLANMeasurementResultItem) *aper.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementResultItemFieldStream(v *WLANMeasurementResultItem) *aper.WireSpan {
	return &v.stream
}
func BridgeWLANMeasurementResultItemFieldWLANChannelListIndef(v *WLANMeasurementResultItem) *bool {
	return &v.wLANChannelListIndef
}
func BridgeWLANMeasurementResultItemFieldWithoutReplay(v *WLANMeasurementResultItem) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementResultItemMethodMarshalAPERBudget(v *WLANMeasurementResultItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeWLANMeasurementResultItemMethodMarshalAPERChanged(v *WLANMeasurementResultItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeWLANMeasurementResultItemMethodMarshalAPERChangedValue(v *WLANMeasurementResultItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeWLANMeasurementResultItemMethodMarshalAPERFreshValue(v *WLANMeasurementResultItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeWLANMeasurementResultItemMethodMarshalAPERLegacy(v *WLANMeasurementResultItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeWLANMeasurementResultItemMethodMarshalAPERPlanned(v *WLANMeasurementResultItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeWLANMeasurementResultItemMethodMarshalAPERTo(v *WLANMeasurementResultItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWLANMeasurementResultItemMethodUnmarshalAPERFrom(v *WLANMeasurementResultItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWLANMeasurementResultItemMethodUnmarshalAPERLegacy(v *WLANMeasurementResultItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeWLANMeasurementResultItemMethodUnmarshalAPERWithOptions(v *WLANMeasurementResultItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeWLANMeasurementResultItemValueCodecFieldCapture(v *WLANMeasurementResultItemValueCodec) *func(WLANMeasurementResultItem, aper.DecodeState) (WLANMeasurementResultItem, aper.Snapshot) {
	return &v.capture
}
func BridgeWLANMeasurementResultItemValueCodecFieldCompare(v *WLANMeasurementResultItemValueCodec) *func(WLANMeasurementResultItem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeWLANMeasurementResultItemValueCodecFieldContext(v *WLANMeasurementResultItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementResultItemValueCodecFieldDecode(v *WLANMeasurementResultItemValueCodec) *func([]byte, aper.DecodeState) (WLANMeasurementResultItem, error) {
	return &v.decode
}
func BridgeWLANMeasurementResultItemValueCodecFieldEncode(v *WLANMeasurementResultItemValueCodec) *func(WLANMeasurementResultItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANMeasurementResultItemValueCodecFieldPath(v *WLANMeasurementResultItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeWLANMeasurementResultItemValueCodecMethodEncodeBudget(v WLANMeasurementResultItemValueCodec, a0 WLANMeasurementResultItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANMeasurementResultItemValueCodecMethodEncodeChanged(v WLANMeasurementResultItemValueCodec, a0 WLANMeasurementResultItem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANMeasurementResultValueCodecFieldCapture(v *WLANMeasurementResultValueCodec) *func(WLANMeasurementResult, aper.DecodeState) (WLANMeasurementResult, aper.Snapshot) {
	return &v.capture
}
func BridgeWLANMeasurementResultValueCodecFieldCompare(v *WLANMeasurementResultValueCodec) *func(WLANMeasurementResult, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeWLANMeasurementResultValueCodecFieldContext(v *WLANMeasurementResultValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementResultValueCodecFieldDecode(v *WLANMeasurementResultValueCodec) *func([]byte, aper.DecodeState) (WLANMeasurementResult, error) {
	return &v.decode
}
func BridgeWLANMeasurementResultValueCodecFieldEncode(v *WLANMeasurementResultValueCodec) *func(WLANMeasurementResult, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANMeasurementResultValueCodecFieldPath(v *WLANMeasurementResultValueCodec) *aper.Path {
	return &v.path
}
func BridgeWLANMeasurementResultValueCodecMethodEncodeBudget(v WLANMeasurementResultValueCodec, a0 WLANMeasurementResult, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANMeasurementResultValueCodecMethodEncodeChanged(v WLANMeasurementResultValueCodec, a0 WLANMeasurementResult, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
