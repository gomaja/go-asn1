// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s11 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s11

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// UTDOAInformationUpdateIEContainer is ProtocolIE-Container {{UTDOAInformationUpdate-IEs}} of TS 36.455: a list of UTDOAInformationUpdateIEField values.
type UTDOAInformationUpdateIEContainer []UTDOAInformationUpdateIEField

// UTDOAInformationUpdateIEField is ProtocolIE-Field {{UTDOAInformationUpdate-IEs}} of TS 36.455: a field carrying a value of UTDOAInformationUpdateIEValue.
type UTDOAInformationUpdateIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         UTDOAInformationUpdateIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v UTDOAInformationUpdateIEField) WithoutReplay() UTDOAInformationUpdateIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *UTDOAInformationUpdateIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *UTDOAInformationUpdateIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *UTDOAInformationUpdateIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UTDOAInformationUpdateIEField{}
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
	var zero UTDOAInformationUpdateIEValue

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
func BridgeECIDMeasurementFailureIndicationIEValueCaptureLPPaProtocolIEContainer(v *s06.ECIDMeasurementFailureIndicationIEContainer, s *aper.SemanticCapture) {
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
			BridgeECIDMeasurementFailureIndicationIEValueCaptureLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeECIDMeasurementFailureIndicationIEValueCompareLPPaProtocolIEContainer(v *s06.ECIDMeasurementFailureIndicationIEContainer, s *aper.SemanticComparison) {
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
			BridgeECIDMeasurementFailureIndicationIEValueCompareLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeECIDMeasurementInitiationFailureIEValueCaptureLPPaProtocolIEContainer(v *s09.ECIDMeasurementInitiationFailureIEContainer, s *aper.SemanticCapture) {
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
			BridgeECIDMeasurementInitiationFailureIEValueCaptureLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeECIDMeasurementInitiationFailureIEValueCompareLPPaProtocolIEContainer(v *s09.ECIDMeasurementInitiationFailureIEContainer, s *aper.SemanticComparison) {
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
			BridgeECIDMeasurementInitiationFailureIEValueCompareLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeErrorIndicationIEValueCaptureLPPaProtocolIEContainer(v *s10.ErrorIndicationIEContainer, s *aper.SemanticCapture) {
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
			BridgeErrorIndicationIEValueCaptureLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeErrorIndicationIEValueCompareLPPaProtocolIEContainer(v *s10.ErrorIndicationIEContainer, s *aper.SemanticComparison) {
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
			BridgeErrorIndicationIEValueCompareLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeInterRATMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIESingleContainer(v *s06.InterRATMeasurementQuantitiesItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	BridgeInterRATMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIEField(v, s)
}
func BridgeInterRATMeasurementQuantitiesItemIEValueCompareLPPaProtocolIESingleContainer(v *s06.InterRATMeasurementQuantitiesItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	BridgeInterRATMeasurementQuantitiesItemIEValueCompareLPPaProtocolIEField(v, s)
}
func BridgeMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIESingleContainer(v *s06.MeasurementQuantitiesItemIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	BridgeMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIEField(v, s)
}
func BridgeMeasurementQuantitiesItemIEValueCompareLPPaProtocolIESingleContainer(v *s06.MeasurementQuantitiesItemIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	BridgeMeasurementQuantitiesItemIEValueCompareLPPaProtocolIEField(v, s)
}

// UTDOAInformationUpdateULConfigurationIEBinding binds ULConfiguration to ProtocolIE-Field {{UTDOAInformationUpdate-IEs}} of TS 36.455.
type UTDOAInformationUpdateULConfigurationIEBinding struct {
	info   s00.FieldInfo
	codec  s10.ULConfigurationValueCodec
	inject func(s10.ULConfiguration,

	) UTDOAInformationUpdateIEValue

	get func(*UTDOAInformationUpdateIEValue,

	) (*s10.ULConfiguration,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b UTDOAInformationUpdateULConfigurationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b UTDOAInformationUpdateULConfigurationIEBinding) Codec() s10.ULConfigurationValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b UTDOAInformationUpdateULConfigurationIEBinding) New(value s10.ULConfiguration,

) (UTDOAInformationUpdateIEField, error) {
	if b.inject == nil {
		return UTDOAInformationUpdateIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return UTDOAInformationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s10.BridgeULConfigurationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UTDOAInformationUpdateIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return UTDOAInformationUpdateIEField{}, aper.OperationError(err, "Value.New")
	}
	return UTDOAInformationUpdateIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b UTDOAInformationUpdateULConfigurationIEBinding) Get(field *UTDOAInformationUpdateIEField) (*s10.ULConfiguration,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementFailureIndicationValueCodec is the concrete ValueCodec[ECIDMeasurementFailureIndication].
type ECIDMeasurementFailureIndicationValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ECIDMeasurementFailureIndication, aper.DecodeState,

	) (ECIDMeasurementFailureIndication, aper.Snapshot,

	)
	compare func(ECIDMeasurementFailureIndication, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ECIDMeasurementFailureIndication,

		error)
	encode func(ECIDMeasurementFailureIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ECIDMeasurementFailureIndicationValueCodec) New(value ECIDMeasurementFailureIndication,

) (ECIDMeasurementFailureIndicationAPERValue, error) {
	if c.encode == nil {
		return ECIDMeasurementFailureIndicationAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementFailureIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ECIDMeasurementFailureIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementFailureIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ECIDMeasurementFailureIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ECIDMeasurementFailureIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ECIDMeasurementFailureIndicationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ECIDMeasurementFailureIndicationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ECIDMeasurementFailureIndicationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ECIDMeasurementFailureIndicationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ECIDMeasurementFailureIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ECIDMeasurementFailureIndicationValueCodec) EncodeAPER(value ECIDMeasurementFailureIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ECIDMeasurementFailureIndicationValueCodec) encodeBudget(value ECIDMeasurementFailureIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ECIDMeasurementFailureIndicationValueCodec) encodeChanged(value ECIDMeasurementFailureIndication,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ECIDMeasurementInitiationFailureValueCodec is the concrete ValueCodec[ECIDMeasurementInitiationFailure].
type ECIDMeasurementInitiationFailureValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ECIDMeasurementInitiationFailure, aper.DecodeState,

	) (ECIDMeasurementInitiationFailure, aper.Snapshot,

	)
	compare func(ECIDMeasurementInitiationFailure, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ECIDMeasurementInitiationFailure,

		error)
	encode func(ECIDMeasurementInitiationFailure,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ECIDMeasurementInitiationFailureValueCodec) New(value ECIDMeasurementInitiationFailure,

) (ECIDMeasurementInitiationFailureAPERValue, error) {
	if c.encode == nil {
		return ECIDMeasurementInitiationFailureAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationFailureAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ECIDMeasurementInitiationFailureAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationFailureAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ECIDMeasurementInitiationFailureValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ECIDMeasurementInitiationFailureAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ECIDMeasurementInitiationFailureAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ECIDMeasurementInitiationFailureAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ECIDMeasurementInitiationFailureAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ECIDMeasurementInitiationFailureAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ECIDMeasurementInitiationFailureAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ECIDMeasurementInitiationFailureValueCodec) EncodeAPER(value ECIDMeasurementInitiationFailureAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ECIDMeasurementInitiationFailureValueCodec) encodeBudget(value ECIDMeasurementInitiationFailure,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ECIDMeasurementInitiationFailureValueCodec) encodeChanged(value ECIDMeasurementInitiationFailure,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ErrorIndicationValueCodec is the concrete ValueCodec[ErrorIndication].
type ErrorIndicationValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ErrorIndication, aper.DecodeState,

	) (ErrorIndication, aper.Snapshot,

	)
	compare func(ErrorIndication, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ErrorIndication,

		error)
	encode func(ErrorIndication,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ErrorIndicationValueCodec) New(value ErrorIndication,

) (ErrorIndicationAPERValue, error) {
	if c.encode == nil {
		return ErrorIndicationAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ErrorIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ErrorIndicationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ErrorIndicationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ErrorIndicationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ErrorIndicationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ErrorIndicationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ErrorIndicationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ErrorIndicationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ErrorIndicationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ErrorIndicationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ErrorIndicationValueCodec) EncodeAPER(value ErrorIndicationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ErrorIndicationValueCodec) encodeBudget(value ErrorIndication,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ErrorIndicationValueCodec) encodeChanged(value ErrorIndication,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeErrorIndicationIEValueValidateLPPaIEContainer(fields s10.ErrorIndicationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s10.BridgeErrorIndicationIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s10.BridgeErrorIndicationIEValueMethodRule(field.Value)
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

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeECIDMeasurementInitiationFailureIEValueValidateLPPaIEContainer(fields s09.ECIDMeasurementInitiationFailureIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s09.BridgeECIDMeasurementInitiationFailureIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s09.BridgeECIDMeasurementInitiationFailureIEValueMethodRule(field.Value)
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

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeECIDMeasurementFailureIndicationIEValueValidateLPPaIEContainer(fields s06.ECIDMeasurementFailureIndicationIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeECIDMeasurementFailureIndicationIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeECIDMeasurementFailureIndicationIEValueMethodRule(field.Value)
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

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeECIDMeasurementTerminationCommandIEValueValidateLPPaIEContainer(fields s03.ECIDMeasurementTerminationCommandIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s02.BridgeECIDMeasurementTerminationCommandIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s02.BridgeECIDMeasurementTerminationCommandIEValueMethodRule(field.Value)
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
func BridgeCriticalityDiagnosticsExtIEsValueValidateLPPaExtensionContainer(fields s03.CriticalityDiagnosticsExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s03.CriticalityDiagnosticsExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s03.CriticalityDiagnosticsExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeCriticalityDiagnosticsExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueValidateLPPaExtensionContainer(fields s03.CriticalityDiagnosticsIEListExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s03.CriticalityDiagnosticsIEListExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s03.CriticalityDiagnosticsIEListExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeCriticalityDiagnosticsIEListExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeECGIExtIEsValueValidateLPPaExtensionContainer(fields s03.ECGIExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s03.ECGIExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s03.ECGIExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeECGIExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeInterRATMeasurementQuantitiesItemIEValueValidateLPPaIEContainer(fields s06.InterRATMeasurementQuantitiesItemIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeInterRATMeasurementQuantitiesItemIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeInterRATMeasurementQuantitiesItemIEValueMethodRule(field.Value)
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
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueValidateLPPaExtensionContainer(fields s03.InterRATMeasurementQuantitiesValueExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s04.InterRATMeasurementQuantitiesValueExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s04.InterRATMeasurementQuantitiesValueExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeInterRATMeasurementQuantitiesValueExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeMeasurementQuantitiesItemIEValueValidateLPPaIEContainer(fields s06.MeasurementQuantitiesItemIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s06.BridgeMeasurementQuantitiesItemIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeMeasurementQuantitiesItemIEValueMethodRule(field.Value)
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
func BridgeMeasurementQuantitiesValueExtIEsValueValidateLPPaExtensionContainer(fields s04.MeasurementQuantitiesValueExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s04.MeasurementQuantitiesValueExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s04.MeasurementQuantitiesValueExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeMeasurementQuantitiesValueExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeNRCGIExtIEsValueValidateLPPaExtensionContainer(fields s04.NRCGIExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s04.NRCGIExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s04.NRCGIExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeNRCGIExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// eCIDMeasurementFailureIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[ECIDMeasurementFailureIndicationIEValue].
type ECIDMeasurementFailureIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.ECIDMeasurementFailureIndicationIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.ECIDMeasurementFailureIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeECIDMeasurementFailureIndicationIEValueCaptureLPPaProtocolIEField(v *s06.ECIDMeasurementFailureIndicationIEField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s06.BridgeECIDMeasurementFailureIndicationIEFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s06.BridgeECIDMeasurementFailureIndicationIEValueMethodCaptureFraming(v.Value))
	v.Value = s06.BridgeECIDMeasurementFailureIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(s06.BridgeECIDMeasurementFailureIndicationIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, s06.BridgeECIDMeasurementFailureIndicationIEFieldFieldReplay(v), *s06.BridgeECIDMeasurementFailureIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeECIDMeasurementFailureIndicationIEValueCompareLPPaProtocolIEField(v *s06.ECIDMeasurementFailureIndicationIEField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s06.BridgeECIDMeasurementFailureIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s06.BridgeECIDMeasurementFailureIndicationIEFieldFieldReplay(v), *s06.BridgeECIDMeasurementFailureIndicationIEFieldFieldWithoutReplay(v))
}

// eCIDMeasurementInitiationFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[ECIDMeasurementInitiationFailureIEValue].
type ECIDMeasurementInitiationFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s09.ECIDMeasurementInitiationFailureIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s09.ECIDMeasurementInitiationFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeECIDMeasurementInitiationFailureIEValueCaptureLPPaProtocolIEField(v *s09.ECIDMeasurementInitiationFailureIEField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s09.BridgeECIDMeasurementInitiationFailureIEFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s09.BridgeECIDMeasurementInitiationFailureIEValueMethodCaptureFraming(v.Value))
	v.Value = s09.BridgeECIDMeasurementInitiationFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(s09.BridgeECIDMeasurementInitiationFailureIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, s09.BridgeECIDMeasurementInitiationFailureIEFieldFieldReplay(v), *s09.BridgeECIDMeasurementInitiationFailureIEFieldFieldWithoutReplay(v))
}
func BridgeECIDMeasurementInitiationFailureIEValueCompareLPPaProtocolIEField(v *s09.ECIDMeasurementInitiationFailureIEField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s09.BridgeECIDMeasurementInitiationFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s09.BridgeECIDMeasurementInitiationFailureIEFieldFieldReplay(v), *s09.BridgeECIDMeasurementInitiationFailureIEFieldFieldWithoutReplay(v))
}

// errorIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[ErrorIndicationIEValue].
type ErrorIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s10.ErrorIndicationIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s10.ErrorIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeErrorIndicationIEValueCaptureLPPaProtocolIEField(v *s10.ErrorIndicationIEField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s10.BridgeErrorIndicationIEFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s10.BridgeErrorIndicationIEValueMethodCaptureFraming(v.Value))
	v.Value = s10.BridgeErrorIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(s10.BridgeErrorIndicationIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, s10.BridgeErrorIndicationIEFieldFieldReplay(v), *s10.BridgeErrorIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeErrorIndicationIEValueCompareLPPaProtocolIEField(v *s10.ErrorIndicationIEField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s10.BridgeErrorIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s10.BridgeErrorIndicationIEFieldFieldReplay(v), *s10.BridgeErrorIndicationIEFieldFieldWithoutReplay(v))
}

// interRATMeasurementQuantitiesItemIEValueProtocolOpenValue is the concrete protocolOpenValue[InterRATMeasurementQuantitiesItemIEValue].
type InterRATMeasurementQuantitiesItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.InterRATMeasurementQuantitiesItemIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.InterRATMeasurementQuantitiesItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeInterRATMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIEField(v *s06.InterRATMeasurementQuantitiesItemIEField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s06.BridgeInterRATMeasurementQuantitiesItemIEFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s06.BridgeInterRATMeasurementQuantitiesItemIEValueMethodCaptureFraming(v.Value))
	v.Value = s06.BridgeInterRATMeasurementQuantitiesItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(s06.BridgeInterRATMeasurementQuantitiesItemIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, s06.BridgeInterRATMeasurementQuantitiesItemIEFieldFieldReplay(v), *s06.BridgeInterRATMeasurementQuantitiesItemIEFieldFieldWithoutReplay(v))
}
func BridgeInterRATMeasurementQuantitiesItemIEValueCompareLPPaProtocolIEField(v *s06.InterRATMeasurementQuantitiesItemIEField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s06.BridgeInterRATMeasurementQuantitiesItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s06.BridgeInterRATMeasurementQuantitiesItemIEFieldFieldReplay(v), *s06.BridgeInterRATMeasurementQuantitiesItemIEFieldFieldWithoutReplay(v))
}

// measurementQuantitiesItemIEValueProtocolOpenValue is the concrete protocolOpenValue[MeasurementQuantitiesItemIEValue].
type MeasurementQuantitiesItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.MeasurementQuantitiesItemIEValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.MeasurementQuantitiesItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIEField(v *s06.MeasurementQuantitiesItemIEField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s06.BridgeMeasurementQuantitiesItemIEFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s06.BridgeMeasurementQuantitiesItemIEValueMethodCaptureFraming(v.Value))
	v.Value = s06.BridgeMeasurementQuantitiesItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(s06.BridgeMeasurementQuantitiesItemIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, s06.BridgeMeasurementQuantitiesItemIEFieldFieldReplay(v), *s06.BridgeMeasurementQuantitiesItemIEFieldFieldWithoutReplay(v))
}
func BridgeMeasurementQuantitiesItemIEValueCompareLPPaProtocolIEField(v *s06.MeasurementQuantitiesItemIEField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s06.BridgeMeasurementQuantitiesItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s06.BridgeMeasurementQuantitiesItemIEFieldFieldReplay(v), *s06.BridgeMeasurementQuantitiesItemIEFieldFieldWithoutReplay(v))
}

// ECIDMeasurementFailureIndicationAPERValue is the concrete APERValue[ECIDMeasurementFailureIndication].
type ECIDMeasurementFailureIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   ECIDMeasurementFailureIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ECIDMeasurementFailureIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECIDMeasurementFailureIndicationAPERValue) WithoutReplay() ECIDMeasurementFailureIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ECIDMeasurementInitiationFailureAPERValue is the concrete APERValue[ECIDMeasurementInitiationFailure].
type ECIDMeasurementInitiationFailureAPERValue struct {
	context s00.BridgeCodecContext
	Value   ECIDMeasurementInitiationFailure

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ECIDMeasurementInitiationFailureAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ECIDMeasurementInitiationFailureAPERValue) WithoutReplay() ECIDMeasurementInitiationFailureAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ErrorIndicationAPERValue is the concrete APERValue[ErrorIndication].
type ErrorIndicationAPERValue struct {
	context s00.BridgeCodecContext
	Value   ErrorIndication

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ErrorIndicationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ErrorIndicationAPERValue) WithoutReplay() ErrorIndicationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeCriticalityDiagnosticsExtIEsValueValidateLPPaIEContainer(fields s03.CriticalityDiagnosticsExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s02.BridgeCriticalityDiagnosticsExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s02.BridgeCriticalityDiagnosticsExtIEsValueMethodRule(field.Value)
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

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeCriticalityDiagnosticsIEListExtIEsValueValidateLPPaIEContainer(fields s03.CriticalityDiagnosticsIEListExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s02.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s02.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodRule(field.Value)
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

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeECGIExtIEsValueValidateLPPaIEContainer(fields s03.ECGIExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s02.BridgeECGIExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s02.BridgeECGIExtIEsValueMethodRule(field.Value)
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

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueValidateLPPaIEContainer(fields s04.InterRATMeasurementQuantitiesValueExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s02.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s02.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodRule(field.Value)
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

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeMeasurementQuantitiesValueExtIEsValueValidateLPPaIEContainer(fields s04.MeasurementQuantitiesValueExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s02.BridgeMeasurementQuantitiesValueExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s02.BridgeMeasurementQuantitiesValueExtIEsValueMethodRule(field.Value)
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

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeNRCGIExtIEsValueValidateLPPaIEContainer(fields s04.NRCGIExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s02.BridgeNRCGIExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s02.BridgeNRCGIExtIEsValueMethodRule(field.Value)
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

// NewBitmapsforNPRSTen creates a BitmapsforNPRS with the ten alternative.
func BridgeNewBitmapsforNPRSTenLegacy(v runtime.BitString) s05.BitmapsforNPRS {
	return s05.BitmapsforNPRS{
		Choice: s00.BitmapsforNPRSChoiceTen,
		Ten:    &v,
	}
}

// NewBitmapsforNPRSForty creates a BitmapsforNPRS with the forty alternative.
func BridgeNewBitmapsforNPRSFortyLegacy(v runtime.BitString) s05.BitmapsforNPRS {
	return s05.BitmapsforNPRS{
		Choice: s00.BitmapsforNPRSChoiceForty,
		Forty:  &v,
	}
}

// NewBitmapsforNPRSTenTdd creates a BitmapsforNPRS with the ten-tdd alternative.
func BridgeNewBitmapsforNPRSTenTddLegacy(v runtime.BitString) s05.BitmapsforNPRS {
	return s05.BitmapsforNPRS{
		Choice: s00.BitmapsforNPRSChoiceTenTdd,
		TenTdd: &v,
	}
}

// NewBitmapsforNPRSFortyTdd creates a BitmapsforNPRS with the forty-tdd alternative.
func BridgeNewBitmapsforNPRSFortyTddLegacy(v runtime.BitString) s05.BitmapsforNPRS {
	return s05.BitmapsforNPRS{
		Choice:   s00.BitmapsforNPRSChoiceFortyTdd,
		FortyTdd: &v,
	}
}

// NewCauseRadioNetwork creates a Cause with the radioNetwork alternative.
func BridgeNewCauseRadioNetworkLegacy(v s00.CauseRadioNetwork) s05.Cause {
	return s05.Cause{
		Choice:       s00.CauseChoiceRadioNetwork,
		RadioNetwork: &v,
	}
}

// NewCauseProtocol creates a Cause with the protocol alternative.
func BridgeNewCauseProtocolLegacy(v s00.CauseProtocol) s05.Cause {
	return s05.Cause{
		Choice:   s00.CauseChoiceProtocol,
		Protocol: &v,
	}
}

// NewCauseMisc creates a Cause with the misc alternative.
func BridgeNewCauseMiscLegacy(v s00.CauseMisc) s05.Cause {
	return s05.Cause{
		Choice: s00.CauseChoiceMisc,
		Misc:   &v,
	}
}

// NewNPRSMutingConfigurationTwo creates a NPRSMutingConfiguration with the two alternative.
func BridgeNewNPRSMutingConfigurationTwoLegacy(v runtime.BitString) s07.NPRSMutingConfiguration {
	return s07.NPRSMutingConfiguration{
		Choice: s00.NPRSMutingConfigurationChoiceTwo,
		Two:    &v,
	}
}

// NewNPRSMutingConfigurationFour creates a NPRSMutingConfiguration with the four alternative.
func BridgeNewNPRSMutingConfigurationFourLegacy(v runtime.BitString) s07.NPRSMutingConfiguration {
	return s07.NPRSMutingConfiguration{
		Choice: s00.NPRSMutingConfigurationChoiceFour,
		Four:   &v,
	}
}

// NewNPRSMutingConfigurationEight creates a NPRSMutingConfiguration with the eight alternative.
func BridgeNewNPRSMutingConfigurationEightLegacy(v runtime.BitString) s07.NPRSMutingConfiguration {
	return s07.NPRSMutingConfiguration{
		Choice: s00.NPRSMutingConfigurationChoiceEight,
		Eight:  &v,
	}
}

// NewNPRSMutingConfigurationSixteen creates a NPRSMutingConfiguration with the sixteen alternative.
func BridgeNewNPRSMutingConfigurationSixteenLegacy(v runtime.BitString) s07.NPRSMutingConfiguration {
	return s07.NPRSMutingConfiguration{
		Choice:  s00.NPRSMutingConfigurationChoiceSixteen,
		Sixteen: &v,
	}
}

// NewPRSMutingConfigurationFour creates a PRSMutingConfiguration with the four alternative.
func BridgeNewPRSMutingConfigurationFourLegacy(v runtime.BitString) s08.PRSMutingConfiguration {
	return s08.PRSMutingConfiguration{
		Choice: s00.PRSMutingConfigurationChoiceFour,
		Four:   &v,
	}
}

// NewPRSMutingConfigurationEight creates a PRSMutingConfiguration with the eight alternative.
func BridgeNewPRSMutingConfigurationEightLegacy(v runtime.BitString) s08.PRSMutingConfiguration {
	return s08.PRSMutingConfiguration{
		Choice: s00.PRSMutingConfigurationChoiceEight,
		Eight:  &v,
	}
}

// NewPRSMutingConfigurationFiveHundredAndTwelve creates a PRSMutingConfiguration with the five-hundred-and-twelve alternative.
func BridgeNewPRSMutingConfigurationFiveHundredAndTwelveLegacy(v runtime.BitString) s08.PRSMutingConfiguration {
	return s08.PRSMutingConfiguration{
		Choice:               s00.PRSMutingConfigurationChoiceFiveHundredAndTwelve,
		FiveHundredAndTwelve: &v,
	}
}

// MarshalAPERAssistanceInformationFailureListTo appends a AssistanceInformationFailureList list to bb.
func BridgeMarshalAPERAssistanceInformationFailureListTo(list s05.AssistanceInformationFailureList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s09.BridgeAsn1cAPERAssistanceInformationFailureListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s05.BridgeAssistanceInformationFailureListElemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERCriticalityDiagnosticsIEListTo appends a CriticalityDiagnosticsIEList list to bb.
func BridgeMarshalAPERCriticalityDiagnosticsIEListTo(list s05.CriticalityDiagnosticsIEList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s09.BridgeAsn1cAPERCriticalityDiagnosticsIEListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s05.BridgeCriticalityDiagnosticsIEListElemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERInterRATMeasurementQuantitiesTo appends a InterRATMeasurementQuantities list to bb.
func BridgeMarshalAPERInterRATMeasurementQuantitiesTo(list s06.InterRATMeasurementQuantities, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s09.BridgeAsn1cAPERInterRATMeasurementQuantitiesListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s06.BridgeInterRATMeasurementQuantitiesItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERMeasurementQuantitiesTo appends a MeasurementQuantities list to bb.
func BridgeMarshalAPERMeasurementQuantitiesTo(list s06.MeasurementQuantities, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s09.BridgeAsn1cAPERMeasurementQuantitiesListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s06.BridgeMeasurementQuantitiesItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERMBSFNsubframeConfigurationTo appends a MBSFNsubframeConfiguration list to bb.
func BridgeMarshalAPERMBSFNsubframeConfigurationTo(list s09.MBSFNsubframeConfiguration, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s09.BridgeAsn1cAPERMBSFNsubframeConfigurationListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s09.BridgeMBSFNsubframeConfigurationValueMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERPosSIBsTo appends a PosSIBs list to bb.
func BridgeMarshalAPERPosSIBsTo(list s10.PosSIBs, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s10.BridgeAsn1cAPERPosSIBsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s10.BridgePosSIBsElemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERPosSIBSegmentsTo appends a PosSIBSegments list to bb.
func BridgeMarshalAPERPosSIBSegmentsTo(list s08.PosSIBSegments, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s09.BridgeAsn1cAPERPosSIBSegmentsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s08.BridgePosSIBSegmentsElemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERSRSConfigurationForAllCellsTo appends a SRSConfigurationForAllCells list to bb.
func BridgeMarshalAPERSRSConfigurationForAllCellsTo(list s09.SRSConfigurationForAllCells, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s09.BridgeAsn1cAPERSRSConfigurationForAllCellsListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 5, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s09.BridgeSRSConfigurationForOneCellMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// NewBitmapsforNPRSTen constructs a checked complete value.
func NewBitmapsforNPRSTen(v runtime.BitString, options ...aper.BuildOption) (s05.BitmapsforNPRS, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s05.BitmapsforNPRS{}, aper.OperationError(err, "BitmapsforNPRSTen")
	}
	value := BridgeNewBitmapsforNPRSTenLegacy(v)
	if _, err := s05.BridgeBitmapsforNPRSMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s05.BitmapsforNPRS{}, aper.OperationError(err, "BitmapsforNPRSTen")
	}
	return value, aper.OperationError(nil, "BitmapsforNPRSTen")
}

// NewBitmapsforNPRSForty constructs a checked complete value.
func NewBitmapsforNPRSForty(v runtime.BitString, options ...aper.BuildOption) (s05.BitmapsforNPRS, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s05.BitmapsforNPRS{}, aper.OperationError(err, "BitmapsforNPRSForty")
	}
	value := BridgeNewBitmapsforNPRSFortyLegacy(v)
	if _, err := s05.BridgeBitmapsforNPRSMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s05.BitmapsforNPRS{}, aper.OperationError(err, "BitmapsforNPRSForty")
	}
	return value, aper.OperationError(nil, "BitmapsforNPRSForty")
}

// NewBitmapsforNPRSTenTdd constructs a checked complete value.
func NewBitmapsforNPRSTenTdd(v runtime.BitString, options ...aper.BuildOption) (s05.BitmapsforNPRS, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s05.BitmapsforNPRS{}, aper.OperationError(err, "BitmapsforNPRSTenTdd")
	}
	value := BridgeNewBitmapsforNPRSTenTddLegacy(v)
	if _, err := s05.BridgeBitmapsforNPRSMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s05.BitmapsforNPRS{}, aper.OperationError(err, "BitmapsforNPRSTenTdd")
	}
	return value, aper.OperationError(nil, "BitmapsforNPRSTenTdd")
}

// NewBitmapsforNPRSFortyTdd constructs a checked complete value.
func NewBitmapsforNPRSFortyTdd(v runtime.BitString, options ...aper.BuildOption) (s05.BitmapsforNPRS, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s05.BitmapsforNPRS{}, aper.OperationError(err, "BitmapsforNPRSFortyTdd")
	}
	value := BridgeNewBitmapsforNPRSFortyTddLegacy(v)
	if _, err := s05.BridgeBitmapsforNPRSMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s05.BitmapsforNPRS{}, aper.OperationError(err, "BitmapsforNPRSFortyTdd")
	}
	return value, aper.OperationError(nil, "BitmapsforNPRSFortyTdd")
}

// NewCauseRadioNetwork constructs a checked complete value.
func NewCauseRadioNetwork(v s00.CauseRadioNetwork, options ...aper.BuildOption) (s05.Cause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s05.Cause{}, aper.OperationError(err, "CauseRadioNetwork")
	}
	value := BridgeNewCauseRadioNetworkLegacy(v)
	if _, err := s05.BridgeCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s05.Cause{}, aper.OperationError(err, "CauseRadioNetwork")
	}
	return value, aper.OperationError(nil, "CauseRadioNetwork")
}

// NewCauseProtocol constructs a checked complete value.
func NewCauseProtocol(v s00.CauseProtocol, options ...aper.BuildOption) (s05.Cause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s05.Cause{}, aper.OperationError(err, "CauseProtocol")
	}
	value := BridgeNewCauseProtocolLegacy(v)
	if _, err := s05.BridgeCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s05.Cause{}, aper.OperationError(err, "CauseProtocol")
	}
	return value, aper.OperationError(nil, "CauseProtocol")
}

// NewCauseMisc constructs a checked complete value.
func NewCauseMisc(v s00.CauseMisc, options ...aper.BuildOption) (s05.Cause, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s05.Cause{}, aper.OperationError(err, "CauseMisc")
	}
	value := BridgeNewCauseMiscLegacy(v)
	if _, err := s05.BridgeCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s05.Cause{}, aper.OperationError(err, "CauseMisc")
	}
	return value, aper.OperationError(nil, "CauseMisc")
}

// NewNPRSMutingConfigurationTwo constructs a checked complete value.
func NewNPRSMutingConfigurationTwo(v runtime.BitString, options ...aper.BuildOption) (s07.NPRSMutingConfiguration, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s07.NPRSMutingConfiguration{}, aper.OperationError(err, "NPRSMutingConfigurationTwo")
	}
	value := BridgeNewNPRSMutingConfigurationTwoLegacy(v)
	if _, err := s07.BridgeNPRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s07.NPRSMutingConfiguration{}, aper.OperationError(err, "NPRSMutingConfigurationTwo")
	}
	return value, aper.OperationError(nil, "NPRSMutingConfigurationTwo")
}

// NewNPRSMutingConfigurationFour constructs a checked complete value.
func NewNPRSMutingConfigurationFour(v runtime.BitString, options ...aper.BuildOption) (s07.NPRSMutingConfiguration, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s07.NPRSMutingConfiguration{}, aper.OperationError(err, "NPRSMutingConfigurationFour")
	}
	value := BridgeNewNPRSMutingConfigurationFourLegacy(v)
	if _, err := s07.BridgeNPRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s07.NPRSMutingConfiguration{}, aper.OperationError(err, "NPRSMutingConfigurationFour")
	}
	return value, aper.OperationError(nil, "NPRSMutingConfigurationFour")
}

// NewNPRSMutingConfigurationEight constructs a checked complete value.
func NewNPRSMutingConfigurationEight(v runtime.BitString, options ...aper.BuildOption) (s07.NPRSMutingConfiguration, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s07.NPRSMutingConfiguration{}, aper.OperationError(err, "NPRSMutingConfigurationEight")
	}
	value := BridgeNewNPRSMutingConfigurationEightLegacy(v)
	if _, err := s07.BridgeNPRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s07.NPRSMutingConfiguration{}, aper.OperationError(err, "NPRSMutingConfigurationEight")
	}
	return value, aper.OperationError(nil, "NPRSMutingConfigurationEight")
}

// NewNPRSMutingConfigurationSixteen constructs a checked complete value.
func NewNPRSMutingConfigurationSixteen(v runtime.BitString, options ...aper.BuildOption) (s07.NPRSMutingConfiguration, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s07.NPRSMutingConfiguration{}, aper.OperationError(err, "NPRSMutingConfigurationSixteen")
	}
	value := BridgeNewNPRSMutingConfigurationSixteenLegacy(v)
	if _, err := s07.BridgeNPRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s07.NPRSMutingConfiguration{}, aper.OperationError(err, "NPRSMutingConfigurationSixteen")
	}
	return value, aper.OperationError(nil, "NPRSMutingConfigurationSixteen")
}

// NewPRSMutingConfigurationFour constructs a checked complete value.
func NewPRSMutingConfigurationFour(v runtime.BitString, options ...aper.BuildOption) (s08.PRSMutingConfiguration, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationFour")
	}
	value := BridgeNewPRSMutingConfigurationFourLegacy(v)
	if _, err := s08.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationFour")
	}
	return value, aper.OperationError(nil, "PRSMutingConfigurationFour")
}

// NewPRSMutingConfigurationEight constructs a checked complete value.
func NewPRSMutingConfigurationEight(v runtime.BitString, options ...aper.BuildOption) (s08.PRSMutingConfiguration, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationEight")
	}
	value := BridgeNewPRSMutingConfigurationEightLegacy(v)
	if _, err := s08.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationEight")
	}
	return value, aper.OperationError(nil, "PRSMutingConfigurationEight")
}

// NewPRSMutingConfigurationFiveHundredAndTwelve constructs a checked complete value.
func NewPRSMutingConfigurationFiveHundredAndTwelve(v runtime.BitString, options ...aper.BuildOption) (s08.PRSMutingConfiguration, error) {
	budget, err := aper.BuildBudget(options...)
	if err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationFiveHundredAndTwelve")
	}
	value := BridgeNewPRSMutingConfigurationFiveHundredAndTwelveLegacy(v)
	if _, err := s08.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return s08.PRSMutingConfiguration{}, aper.OperationError(err, "PRSMutingConfigurationFiveHundredAndTwelve")
	}
	return value, aper.OperationError(nil, "PRSMutingConfigurationFiveHundredAndTwelve")
}

// ECIDMeasurementInitiationFailure represents the ASN.1 type E-CIDMeasurementInitiationFailure (SEQUENCE).
type ECIDMeasurementInitiationFailure struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    aper.WireSpan
	ProtocolIEs      s09.ECIDMeasurementInitiationFailureIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                            `asn1:"-" json:"-"`
	extCount         int64                                           `asn1:"-" json:"-"`
	extPresent       []bool                                          `asn1:"-" json:"-"`
	extData          [][]byte                                        `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                               `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                          `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ECIDMeasurementFailureIndication represents the ASN.1 type E-CIDMeasurementFailureIndication (SEQUENCE).
type ECIDMeasurementFailureIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    aper.WireSpan
	ProtocolIEs      s06.ECIDMeasurementFailureIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                            `asn1:"-" json:"-"`
	extCount         int64                                           `asn1:"-" json:"-"`
	extPresent       []bool                                          `asn1:"-" json:"-"`
	extData          [][]byte                                        `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                               `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                          `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// ErrorIndication represents the ASN.1 type ErrorIndication (SEQUENCE).
type ErrorIndication struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    aper.WireSpan
	ProtocolIEs      s10.ErrorIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                           `asn1:"-" json:"-"`
	extCount         int64                          `asn1:"-" json:"-"`
	extPresent       []bool                         `asn1:"-" json:"-"`
	extData          [][]byte                       `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding              `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding         `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes ECIDMeasurementInitiationFailure to APER format.
func (v *ECIDMeasurementInitiationFailure) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ECIDMeasurementInitiationFailure) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s09.BridgeECIDMeasurementInitiationFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ECIDMeasurementInitiationFailure from APER format.
func (v *ECIDMeasurementInitiationFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ECIDMeasurementInitiationFailure) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementInitiationFailure")
	}
	bb.EnterComponent("ECIDMeasurementInitiationFailure")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementInitiationFailure")
	}
	padding, err := aper.CaptureFinalBits(bb, "ECIDMeasurementInitiationFailure")
	if err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementInitiationFailure")
	}
	v.perPadding = padding
	return nil
}
func (v *ECIDMeasurementInitiationFailure) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementInitiationFailure{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s09.ECIDMeasurementInitiationFailureIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s09.ECIDMeasurementInitiationFailureIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s09.BridgeECIDMeasurementInitiationFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPER encodes ECIDMeasurementFailureIndication to APER format.
func (v *ECIDMeasurementFailureIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ECIDMeasurementFailureIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s06.BridgeECIDMeasurementFailureIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ECIDMeasurementFailureIndication from APER format.
func (v *ECIDMeasurementFailureIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ECIDMeasurementFailureIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementFailureIndication")
	}
	bb.EnterComponent("ECIDMeasurementFailureIndication")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementFailureIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "ECIDMeasurementFailureIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "ECIDMeasurementFailureIndication")
	}
	v.perPadding = padding
	return nil
}
func (v *ECIDMeasurementFailureIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementFailureIndication{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s06.ECIDMeasurementFailureIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s06.ECIDMeasurementFailureIndicationIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s06.BridgeECIDMeasurementFailureIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// MarshalAPEROTDOAInformationTypeTo appends a OTDOAInformationType list to bb.
func BridgeMarshalAPEROTDOAInformationTypeTo(list s07.OTDOAInformationType, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := s09.BridgeAsn1cAPEROTDOAInformationTypeListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := s07.BridgeOTDOAInformationTypeIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes ErrorIndication to APER format.
func (v *ErrorIndication) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ErrorIndication) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			if err := s10.BridgeErrorIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ErrorIndication from APER format.
func (v *ErrorIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}
func (v *ErrorIndication) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ErrorIndication")
	}
	bb.EnterComponent("ErrorIndication")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ErrorIndication")
	}
	padding, err := aper.CaptureFinalBits(bb, "ErrorIndication")
	if err != nil {
		return runtime.WrapDecodePath(err, "ErrorIndication")
	}
	v.perPadding = padding
	return nil
}
func (v *ErrorIndication) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ErrorIndication{}
	var extAdditions aper.ExtensionAdditions
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s10.ErrorIndicationIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1115
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s10.ErrorIndicationIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s10.BridgeErrorIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ECIDMeasurementFailureIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ECIDMeasurementFailureIndication", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ECIDMeasurementFailureIndication) WithoutReplay() ECIDMeasurementFailureIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ECIDMeasurementFailureIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ECIDMeasurementInitiationFailure) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ECIDMeasurementInitiationFailure", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ECIDMeasurementInitiationFailure) WithoutReplay() ECIDMeasurementInitiationFailure {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ECIDMeasurementInitiationFailure
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ErrorIndication) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ErrorIndication", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ErrorIndication) WithoutReplay() ErrorIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ErrorIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ECIDMeasurementFailureIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ECIDMeasurementFailureIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ECIDMeasurementFailureIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ECIDMeasurementFailureIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ECIDMeasurementFailureIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ECIDMeasurementFailureIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ECIDMeasurementFailureIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ECIDMeasurementInitiationFailure) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ECIDMeasurementInitiationFailure) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ECIDMeasurementInitiationFailure.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ECIDMeasurementInitiationFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ECIDMeasurementInitiationFailure) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ECIDMeasurementInitiationFailure.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ECIDMeasurementInitiationFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ErrorIndication) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ErrorIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ErrorIndication.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ErrorIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ErrorIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ErrorIndication.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ErrorIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *ECIDMeasurementFailureIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ECIDMeasurementFailureIndication")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ECIDMeasurementFailureIndication")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaECIDMeasurementFailureIndication(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ECIDMeasurementFailureIndication")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ECIDMeasurementFailureIndication")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ECIDMeasurementFailureIndication")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ECIDMeasurementFailureIndication")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ECIDMeasurementFailureIndication")
}
func (v *ECIDMeasurementFailureIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ECIDMeasurementFailureIndication) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ECIDMeasurementFailureIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaECIDMeasurementFailureIndication(v, &s)
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
func (v *ECIDMeasurementFailureIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ECIDMeasurementFailureIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ECIDMeasurementInitiationFailure) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ECIDMeasurementInitiationFailure")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ECIDMeasurementInitiationFailure")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaECIDMeasurementInitiationFailure(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ECIDMeasurementInitiationFailure")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ECIDMeasurementInitiationFailure")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ECIDMeasurementInitiationFailure")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ECIDMeasurementInitiationFailure")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ECIDMeasurementInitiationFailure")
}
func (v *ECIDMeasurementInitiationFailure) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ECIDMeasurementInitiationFailure) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ECIDMeasurementInitiationFailure) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaECIDMeasurementInitiationFailure(v, &s)
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
func (v *ECIDMeasurementInitiationFailure) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ECIDMeasurementInitiationFailure) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ErrorIndication) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ErrorIndication")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ErrorIndication")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaErrorIndication(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ErrorIndication")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ErrorIndication")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ErrorIndication")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ErrorIndication")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ErrorIndication")
}
func (v *ErrorIndication) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ErrorIndication) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ErrorIndication) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
		BridgeCompareLPPaErrorIndication(v, &s)
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
func (v *ErrorIndication) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ErrorIndication) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ECIDMeasurementFailureIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ECIDMeasurementFailureIndication")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ECIDMeasurementFailureIndication
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaECIDMeasurementFailureIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ECIDMeasurementFailureIndication{}
		return report, aper.OperationError(err, "ECIDMeasurementFailureIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ECIDMeasurementFailureIndication")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ECIDMeasurementInitiationFailure) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ECIDMeasurementInitiationFailure")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ECIDMeasurementInitiationFailure
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaECIDMeasurementInitiationFailure(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ECIDMeasurementInitiationFailure{}
		return report, aper.OperationError(err, "ECIDMeasurementInitiationFailure")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ECIDMeasurementInitiationFailure")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ErrorIndication) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ErrorIndication")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ErrorIndication
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaErrorIndication(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ErrorIndication{}
		return report, aper.OperationError(err, "ErrorIndication")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ErrorIndication")
}
func BridgeCaptureLPPaECIDMeasurementFailureIndication(v *ECIDMeasurementFailureIndication, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgeECIDMeasurementFailureIndicationIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaECIDMeasurementFailureIndication(v *ECIDMeasurementFailureIndication, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeECIDMeasurementFailureIndicationIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaECIDMeasurementInitiationFailure(v *ECIDMeasurementInitiationFailure, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgeECIDMeasurementInitiationFailureIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaECIDMeasurementInitiationFailure(v *ECIDMeasurementInitiationFailure, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeECIDMeasurementInitiationFailureIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaErrorIndication(v *ErrorIndication, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgeErrorIndicationIEValueCaptureLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaErrorIndication(v *ErrorIndication, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeErrorIndicationIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaInterRATMeasurementQuantities(v *s06.InterRATMeasurementQuantities, s *aper.SemanticCapture) {
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
			BridgeInterRATMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaInterRATMeasurementQuantities(v *s06.InterRATMeasurementQuantities, s *aper.SemanticComparison) {
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
			BridgeInterRATMeasurementQuantitiesItemIEValueCompareLPPaProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaMeasurementQuantities(v *s06.MeasurementQuantities, s *aper.SemanticCapture) {
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
			BridgeMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaMeasurementQuantities(v *s06.MeasurementQuantities, s *aper.SemanticComparison) {
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
			BridgeMeasurementQuantitiesItemIEValueCompareLPPaProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaUTDOAInformationUpdateIEValue(v *UTDOAInformationUpdateIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(13):
			{
				f := s.Begin()
				s.Bool(v.rowULConfiguration == nil)
				if v.rowULConfiguration != nil {
					s10.BridgeCaptureLPPaULConfiguration(v.rowULConfiguration, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v UTDOAInformationUpdateIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v UTDOAInformationUpdateIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v UTDOAInformationUpdateIEValue) captureSemantics(s aper.SemanticCapture) UTDOAInformationUpdateIEValue {
	BridgeCaptureLPPaUTDOAInformationUpdateIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaUTDOAInformationUpdateIEValue(v *UTDOAInformationUpdateIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(13):
			{
				f := s.Begin()
				s.Bool(v.rowULConfiguration == nil)
				if v.rowULConfiguration != nil {
					s10.BridgeCompareLPPaULConfiguration(v.rowULConfiguration, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v UTDOAInformationUpdateIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaUTDOAInformationUpdateIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v UTDOAInformationUpdateIEValue) WithoutReplay() UTDOAInformationUpdateIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}

type UTDOAInformationUpdateIEValue struct {
	id                 s00.ProtocolIEID
	withoutReplay      bool
	received           aper.WireSpan
	replay             aper.Snapshot
	opaque             *aper.OpaqueOpenType
	isOpaque           bool
	rowULConfiguration *s10.ULConfiguration
}

func (v UTDOAInformationUpdateIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case s00.ProtocolIEID(13):
		return v.rowULConfiguration != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *UTDOAInformationUpdateIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (UTDOAInformationUpdateIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationUpdate-IEs"}}
}
func (UTDOAInformationUpdateIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(13):
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

// AsULConfiguration returns the selected ULConfiguration value and reports whether that alternative is active.
func (v *UTDOAInformationUpdateIEValue) AsULConfiguration() (*s10.ULConfiguration, bool) {
	if v == nil || v.id != s00.ProtocolIEID(13) || v.rowULConfiguration == nil {
		return nil, false
	}
	return v.rowULConfiguration, true
}
func (v UTDOAInformationUpdateIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (UTDOAInformationUpdateIEValue, error) {
	out := UTDOAInformationUpdateIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 13:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case s00.ProtocolIEID(13):
		replayUsage := scope.Usage()
		var value s10.ULConfiguration
		child := raw.ChildDecodeBuffer()
		if err := s10.BridgeULConfigurationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "ULConfiguration:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ULConfiguration")
		if err != nil {
			return out, err
		}
		*s10.BridgeULConfigurationFieldPerPadding(&value) = padding
		*s10.BridgeULConfigurationFieldReceived(&value) = true
		raw.RetainContents(s10.BridgeULConfigurationFieldReceivedBytes(&value))
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowULConfiguration = &value
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
func (v UTDOAInformationUpdateIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v UTDOAInformationUpdateIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(13):
		if v.rowULConfiguration == nil {
			return nil, fmt.Errorf("%s missing value", "UTDOAInformationUpdate-IEs.id-ULConfiguration:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := s10.BridgeULConfigurationMethodMarshalAPERBudget(v.rowULConfiguration, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "UTDOAInformationUpdateIEValue:", v.id)
	}
}

type UTDOAInformationUpdateIETable struct{}

func UTDOAInformationUpdateIEs() UTDOAInformationUpdateIETable {
	return UTDOAInformationUpdateIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (UTDOAInformationUpdateIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationUpdate-IEs"}
		return sealed
	}()
}
func (UTDOAInformationUpdateIETable) infoULConfiguration() s00.FieldInfo {
	return s00.FieldInfo{Table: UTDOAInformationUpdateIEs().ID(), ID: s00.ProtocolIEID(13), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "ULConfiguration"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationUpdate-IEs", Row: "id-ULConfiguration"}}}
}

// ULConfiguration returns the typed binding for the ULConfiguration row of this table.
func (t UTDOAInformationUpdateIETable) ULConfiguration() UTDOAInformationUpdateULConfigurationIEBinding {
	return UTDOAInformationUpdateULConfigurationIEBinding{info: t.infoULConfiguration(), codec: func() s10.ULConfigurationValueCodec {
		sealed := s10.ULConfigurationValueCodec{}
		*s10.BridgeULConfigurationValueCodecFieldPath(&sealed) = "ULConfiguration"
		*s10.BridgeULConfigurationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s10.ULConfiguration, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s10.ULConfiguration
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ULConfiguration")
			var zero UTDOAInformationUpdateIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(13), raw)
			if err != nil {
				var empty s10.ULConfiguration
				return empty, runtime.WrapDecodePath(err, "ULConfiguration")
			}
			value, ok := decoded.AsULConfiguration()
			if !ok {
				var empty s10.ULConfiguration
				return empty, fmt.Errorf("binding UTDOAInformationUpdate-IEs.id-ULConfiguration: no selected value")
			}
			return *value, nil
		}
		*s10.BridgeULConfigurationValueCodecFieldEncode(&sealed) = func(value s10.ULConfiguration, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (UTDOAInformationUpdateIEValue{id: s00.ProtocolIEID(13), rowULConfiguration: &value}).encodeFresh(fresh, budget)
		}
		*s10.BridgeULConfigurationValueCodecFieldCapture(&sealed) = func(v s10.ULConfiguration, options aper.DecodeState) (s10.ULConfiguration, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s10.BridgeCaptureLPPaULConfiguration(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s10.BridgeULConfigurationValueCodecFieldCompare(&sealed) = func(v s10.ULConfiguration, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s10.BridgeCompareLPPaULConfiguration(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s10.BridgeULConfigurationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ULConfiguration"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s10.ULConfiguration) UTDOAInformationUpdateIEValue {
			return UTDOAInformationUpdateIEValue{id: s00.ProtocolIEID(13), rowULConfiguration: &value}
		}, get: func(value *UTDOAInformationUpdateIEValue) (*s10.ULConfiguration, bool) {
			return value.AsULConfiguration()
		}}
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t UTDOAInformationUpdateIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (UTDOAInformationUpdateIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UTDOAInformationUpdateIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(13):
		return UTDOAInformationUpdateIEField{}, aper.OperationError(fmt.Errorf("known IE id-ULConfiguration requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return UTDOAInformationUpdateIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UTDOAInformationUpdateIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return UTDOAInformationUpdateIEField{}, aper.OperationError(err, "Opaque")
		}
		return UTDOAInformationUpdateIEField{Id: id, Criticality: criticality, Value: UTDOAInformationUpdateIEValue{id: id, opaque: retained, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}
func BridgeMergeNestedValidation(dst *s09.ValidationReport, src s09.ValidationReport) {
	if *s09.BridgeValidationReportFieldErr(dst) != nil {
		return
	}
	if *s09.BridgeValidationReportFieldErr(&src) != nil {
		*s09.BridgeValidationReportFieldErr(dst) = *s09.BridgeValidationReportFieldErr(&src)
		return
	}
	bb := aper.NewBudgetBuffer(*s09.BridgeValidationReportFieldBudget(dst))
	var err error
	dst.Issues, err = aper.AppendValues(bb, dst.Issues, src.Issues...)
	if err != nil {
		*s09.BridgeValidationReportFieldErr(dst) = err
		return
	}
	dst.Deferred, err = aper.AppendValues(bb, dst.Deferred, src.Deferred...)
	if err != nil {
		*s09.BridgeValidationReportFieldErr(dst) = err
		return
	}
	dst.Unchecked, err = aper.AppendValues(bb, dst.Unchecked, src.Unchecked...)
	if err != nil {
		*s09.BridgeValidationReportFieldErr(dst) = err
		return
	}
	if !src.Complete {
		dst.Complete = false
	}
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *UTDOAInformationUpdateIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 13:
		if v.rowULConfiguration != nil {
			return v.rowULConfiguration, true
		}
	}
	return nil, false
}

func BridgeECIDMeasurementFailureIndicationAPERValueFieldContext(v *ECIDMeasurementFailureIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementFailureIndicationAPERValueFieldReceived(v *ECIDMeasurementFailureIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementFailureIndicationAPERValueFieldReplay(v *ECIDMeasurementFailureIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementFailureIndicationAPERValueFieldWithoutReplay(v *ECIDMeasurementFailureIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementFailureIndicationFieldExtCount(v *ECIDMeasurementFailureIndication) *int64 {
	return &v.extCount
}
func BridgeECIDMeasurementFailureIndicationFieldExtData(v *ECIDMeasurementFailureIndication) *[][]byte {
	return &v.extData
}
func BridgeECIDMeasurementFailureIndicationFieldExtOrigin(v *ECIDMeasurementFailureIndication) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeECIDMeasurementFailureIndicationFieldExtPresent(v *ECIDMeasurementFailureIndication) *[]bool {
	return &v.extPresent
}
func BridgeECIDMeasurementFailureIndicationFieldExtWire(v *ECIDMeasurementFailureIndication) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeECIDMeasurementFailureIndicationFieldPerExtPadding(v *ECIDMeasurementFailureIndication) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeECIDMeasurementFailureIndicationFieldPerPadding(v *ECIDMeasurementFailureIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeECIDMeasurementFailureIndicationFieldProtocolIEsIndef(v *ECIDMeasurementFailureIndication) *bool {
	return &v.protocolIEsIndef
}
func BridgeECIDMeasurementFailureIndicationFieldReceived(v *ECIDMeasurementFailureIndication) *bool {
	return &v.received
}
func BridgeECIDMeasurementFailureIndicationFieldReceivedBytes(v *ECIDMeasurementFailureIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeECIDMeasurementFailureIndicationFieldReplay(v *ECIDMeasurementFailureIndication) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementFailureIndicationFieldStream(v *ECIDMeasurementFailureIndication) *aper.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementFailureIndicationFieldWithoutReplay(v *ECIDMeasurementFailureIndication) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementFailureIndicationMethodMarshalAPERBudget(v *ECIDMeasurementFailureIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeECIDMeasurementFailureIndicationMethodMarshalAPERChanged(v *ECIDMeasurementFailureIndication, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeECIDMeasurementFailureIndicationMethodMarshalAPERChangedValue(v *ECIDMeasurementFailureIndication, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeECIDMeasurementFailureIndicationMethodMarshalAPERFreshValue(v *ECIDMeasurementFailureIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeECIDMeasurementFailureIndicationMethodMarshalAPERLegacy(v *ECIDMeasurementFailureIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeECIDMeasurementFailureIndicationMethodMarshalAPERPlanned(v *ECIDMeasurementFailureIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeECIDMeasurementFailureIndicationMethodMarshalAPERTo(v *ECIDMeasurementFailureIndication, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementFailureIndicationMethodUnmarshalAPERFrom(v *ECIDMeasurementFailureIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementFailureIndicationMethodUnmarshalAPERLegacy(v *ECIDMeasurementFailureIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeECIDMeasurementFailureIndicationMethodUnmarshalAPERWithOptions(v *ECIDMeasurementFailureIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeECIDMeasurementFailureIndicationValueCodecFieldCapture(v *ECIDMeasurementFailureIndicationValueCodec) *func(ECIDMeasurementFailureIndication, aper.DecodeState) (ECIDMeasurementFailureIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementFailureIndicationValueCodecFieldCompare(v *ECIDMeasurementFailureIndicationValueCodec) *func(ECIDMeasurementFailureIndication, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementFailureIndicationValueCodecFieldContext(v *ECIDMeasurementFailureIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementFailureIndicationValueCodecFieldDecode(v *ECIDMeasurementFailureIndicationValueCodec) *func([]byte, aper.DecodeState) (ECIDMeasurementFailureIndication, error) {
	return &v.decode
}
func BridgeECIDMeasurementFailureIndicationValueCodecFieldEncode(v *ECIDMeasurementFailureIndicationValueCodec) *func(ECIDMeasurementFailureIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementFailureIndicationValueCodecFieldPath(v *ECIDMeasurementFailureIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeECIDMeasurementFailureIndicationValueCodecMethodEncodeBudget(v ECIDMeasurementFailureIndicationValueCodec, a0 ECIDMeasurementFailureIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeECIDMeasurementFailureIndicationValueCodecMethodEncodeChanged(v ECIDMeasurementFailureIndicationValueCodec, a0 ECIDMeasurementFailureIndication, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeECIDMeasurementInitiationFailureAPERValueFieldContext(v *ECIDMeasurementInitiationFailureAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementInitiationFailureAPERValueFieldReceived(v *ECIDMeasurementInitiationFailureAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementInitiationFailureAPERValueFieldReplay(v *ECIDMeasurementInitiationFailureAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationFailureAPERValueFieldWithoutReplay(v *ECIDMeasurementInitiationFailureAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationFailureFieldExtCount(v *ECIDMeasurementInitiationFailure) *int64 {
	return &v.extCount
}
func BridgeECIDMeasurementInitiationFailureFieldExtData(v *ECIDMeasurementInitiationFailure) *[][]byte {
	return &v.extData
}
func BridgeECIDMeasurementInitiationFailureFieldExtOrigin(v *ECIDMeasurementInitiationFailure) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeECIDMeasurementInitiationFailureFieldExtPresent(v *ECIDMeasurementInitiationFailure) *[]bool {
	return &v.extPresent
}
func BridgeECIDMeasurementInitiationFailureFieldExtWire(v *ECIDMeasurementInitiationFailure) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeECIDMeasurementInitiationFailureFieldPerExtPadding(v *ECIDMeasurementInitiationFailure) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeECIDMeasurementInitiationFailureFieldPerPadding(v *ECIDMeasurementInitiationFailure) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeECIDMeasurementInitiationFailureFieldProtocolIEsIndef(v *ECIDMeasurementInitiationFailure) *bool {
	return &v.protocolIEsIndef
}
func BridgeECIDMeasurementInitiationFailureFieldReceived(v *ECIDMeasurementInitiationFailure) *bool {
	return &v.received
}
func BridgeECIDMeasurementInitiationFailureFieldReceivedBytes(v *ECIDMeasurementInitiationFailure) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeECIDMeasurementInitiationFailureFieldReplay(v *ECIDMeasurementInitiationFailure) *aper.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationFailureFieldStream(v *ECIDMeasurementInitiationFailure) *aper.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementInitiationFailureFieldWithoutReplay(v *ECIDMeasurementInitiationFailure) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationFailureMethodMarshalAPERBudget(v *ECIDMeasurementInitiationFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeECIDMeasurementInitiationFailureMethodMarshalAPERChanged(v *ECIDMeasurementInitiationFailure, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeECIDMeasurementInitiationFailureMethodMarshalAPERChangedValue(v *ECIDMeasurementInitiationFailure, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeECIDMeasurementInitiationFailureMethodMarshalAPERFreshValue(v *ECIDMeasurementInitiationFailure, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeECIDMeasurementInitiationFailureMethodMarshalAPERLegacy(v *ECIDMeasurementInitiationFailure) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeECIDMeasurementInitiationFailureMethodMarshalAPERPlanned(v *ECIDMeasurementInitiationFailure, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeECIDMeasurementInitiationFailureMethodMarshalAPERTo(v *ECIDMeasurementInitiationFailure, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementInitiationFailureMethodUnmarshalAPERFrom(v *ECIDMeasurementInitiationFailure, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementInitiationFailureMethodUnmarshalAPERLegacy(v *ECIDMeasurementInitiationFailure, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeECIDMeasurementInitiationFailureMethodUnmarshalAPERWithOptions(v *ECIDMeasurementInitiationFailure, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeECIDMeasurementInitiationFailureValueCodecFieldCapture(v *ECIDMeasurementInitiationFailureValueCodec) *func(ECIDMeasurementInitiationFailure, aper.DecodeState) (ECIDMeasurementInitiationFailure, aper.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementInitiationFailureValueCodecFieldCompare(v *ECIDMeasurementInitiationFailureValueCodec) *func(ECIDMeasurementInitiationFailure, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementInitiationFailureValueCodecFieldContext(v *ECIDMeasurementInitiationFailureValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementInitiationFailureValueCodecFieldDecode(v *ECIDMeasurementInitiationFailureValueCodec) *func([]byte, aper.DecodeState) (ECIDMeasurementInitiationFailure, error) {
	return &v.decode
}
func BridgeECIDMeasurementInitiationFailureValueCodecFieldEncode(v *ECIDMeasurementInitiationFailureValueCodec) *func(ECIDMeasurementInitiationFailure, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementInitiationFailureValueCodecFieldPath(v *ECIDMeasurementInitiationFailureValueCodec) *aper.Path {
	return &v.path
}
func BridgeECIDMeasurementInitiationFailureValueCodecMethodEncodeBudget(v ECIDMeasurementInitiationFailureValueCodec, a0 ECIDMeasurementInitiationFailure, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeECIDMeasurementInitiationFailureValueCodecMethodEncodeChanged(v ECIDMeasurementInitiationFailureValueCodec, a0 ECIDMeasurementInitiationFailure, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeErrorIndicationAPERValueFieldContext(v *ErrorIndicationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeErrorIndicationAPERValueFieldReceived(v *ErrorIndicationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeErrorIndicationAPERValueFieldReplay(v *ErrorIndicationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeErrorIndicationAPERValueFieldWithoutReplay(v *ErrorIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeErrorIndicationFieldExtCount(v *ErrorIndication) *int64   { return &v.extCount }
func BridgeErrorIndicationFieldExtData(v *ErrorIndication) *[][]byte { return &v.extData }
func BridgeErrorIndicationFieldExtOrigin(v *ErrorIndication) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeErrorIndicationFieldExtPresent(v *ErrorIndication) *[]bool       { return &v.extPresent }
func BridgeErrorIndicationFieldExtWire(v *ErrorIndication) *[]aper.WireSpan { return &v.extWire }
func BridgeErrorIndicationFieldPerExtPadding(v *ErrorIndication) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeErrorIndicationFieldPerPadding(v *ErrorIndication) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeErrorIndicationFieldProtocolIEsIndef(v *ErrorIndication) *bool { return &v.protocolIEsIndef }
func BridgeErrorIndicationFieldReceived(v *ErrorIndication) *bool         { return &v.received }
func BridgeErrorIndicationFieldReceivedBytes(v *ErrorIndication) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeErrorIndicationFieldReplay(v *ErrorIndication) *aper.Snapshot { return &v.replay }
func BridgeErrorIndicationFieldStream(v *ErrorIndication) *aper.WireSpan { return &v.stream }
func BridgeErrorIndicationFieldWithoutReplay(v *ErrorIndication) *bool   { return &v.withoutReplay }
func BridgeErrorIndicationMethodMarshalAPERBudget(v *ErrorIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeErrorIndicationMethodMarshalAPERChanged(v *ErrorIndication, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeErrorIndicationMethodMarshalAPERChangedValue(v *ErrorIndication, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeErrorIndicationMethodMarshalAPERFreshValue(v *ErrorIndication, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeErrorIndicationMethodMarshalAPERLegacy(v *ErrorIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeErrorIndicationMethodMarshalAPERPlanned(v *ErrorIndication, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeErrorIndicationMethodMarshalAPERTo(v *ErrorIndication, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeErrorIndicationMethodUnmarshalAPERFrom(v *ErrorIndication, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeErrorIndicationMethodUnmarshalAPERLegacy(v *ErrorIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeErrorIndicationMethodUnmarshalAPERWithOptions(v *ErrorIndication, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeErrorIndicationValueCodecFieldCapture(v *ErrorIndicationValueCodec) *func(ErrorIndication, aper.DecodeState) (ErrorIndication, aper.Snapshot) {
	return &v.capture
}
func BridgeErrorIndicationValueCodecFieldCompare(v *ErrorIndicationValueCodec) *func(ErrorIndication, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeErrorIndicationValueCodecFieldContext(v *ErrorIndicationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeErrorIndicationValueCodecFieldDecode(v *ErrorIndicationValueCodec) *func([]byte, aper.DecodeState) (ErrorIndication, error) {
	return &v.decode
}
func BridgeErrorIndicationValueCodecFieldEncode(v *ErrorIndicationValueCodec) *func(ErrorIndication, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeErrorIndicationValueCodecFieldPath(v *ErrorIndicationValueCodec) *aper.Path {
	return &v.path
}
func BridgeErrorIndicationValueCodecMethodEncodeBudget(v ErrorIndicationValueCodec, a0 ErrorIndication, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeErrorIndicationValueCodecMethodEncodeChanged(v ErrorIndicationValueCodec, a0 ErrorIndication, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUTDOAInformationUpdateIEFieldFieldReceived(v *UTDOAInformationUpdateIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeUTDOAInformationUpdateIEFieldFieldReplay(v *UTDOAInformationUpdateIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationUpdateIEFieldFieldStream(v *UTDOAInformationUpdateIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeUTDOAInformationUpdateIEFieldFieldWithoutReplay(v *UTDOAInformationUpdateIEField) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationUpdateIEFieldMethodMarshalAPERTo(v *UTDOAInformationUpdateIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUTDOAInformationUpdateIEFieldMethodUnmarshalAPERFrom(v *UTDOAInformationUpdateIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUTDOAInformationUpdateIETableMethodInfoULConfiguration(v UTDOAInformationUpdateIETable) s00.FieldInfo {
	return v.infoULConfiguration()
}
func BridgeUTDOAInformationUpdateIEValueFieldId(v *UTDOAInformationUpdateIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeUTDOAInformationUpdateIEValueFieldIsOpaque(v *UTDOAInformationUpdateIEValue) *bool {
	return &v.isOpaque
}
func BridgeUTDOAInformationUpdateIEValueFieldOpaque(v *UTDOAInformationUpdateIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeUTDOAInformationUpdateIEValueFieldReceived(v *UTDOAInformationUpdateIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeUTDOAInformationUpdateIEValueFieldReplay(v *UTDOAInformationUpdateIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationUpdateIEValueFieldRowULConfiguration(v *UTDOAInformationUpdateIEValue) **s10.ULConfiguration {
	return &v.rowULConfiguration
}
func BridgeUTDOAInformationUpdateIEValueFieldWithoutReplay(v *UTDOAInformationUpdateIEValue) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationUpdateIEValueMethodCaptureFraming(v UTDOAInformationUpdateIEValue) uint64 {
	return v.captureFraming()
}
func BridgeUTDOAInformationUpdateIEValueMethodCaptureSemantics(v UTDOAInformationUpdateIEValue, a0 aper.SemanticCapture) UTDOAInformationUpdateIEValue {
	return v.captureSemantics(a0)
}
func BridgeUTDOAInformationUpdateIEValueMethodCaptureSnapshot(v UTDOAInformationUpdateIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeUTDOAInformationUpdateIEValueMethodCompareSemantics(v UTDOAInformationUpdateIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUTDOAInformationUpdateIEValueMethodDecode(v UTDOAInformationUpdateIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (UTDOAInformationUpdateIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUTDOAInformationUpdateIEValueMethodEncode(v UTDOAInformationUpdateIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUTDOAInformationUpdateIEValueMethodEncodeFresh(v UTDOAInformationUpdateIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUTDOAInformationUpdateIEValueMethodMatchesID(v UTDOAInformationUpdateIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeUTDOAInformationUpdateIEValueMethodReason(v UTDOAInformationUpdateIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeUTDOAInformationUpdateIEValueMethodRule(v UTDOAInformationUpdateIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeUTDOAInformationUpdateULConfigurationIEBindingFieldCodec(v *UTDOAInformationUpdateULConfigurationIEBinding) *s10.ULConfigurationValueCodec {
	return &v.codec
}
func BridgeUTDOAInformationUpdateULConfigurationIEBindingFieldGet(v *UTDOAInformationUpdateULConfigurationIEBinding) *func(*UTDOAInformationUpdateIEValue) (*s10.ULConfiguration, bool) {
	return &v.get
}
func BridgeUTDOAInformationUpdateULConfigurationIEBindingFieldInfo(v *UTDOAInformationUpdateULConfigurationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeUTDOAInformationUpdateULConfigurationIEBindingFieldInject(v *UTDOAInformationUpdateULConfigurationIEBinding) *func(s10.ULConfiguration) UTDOAInformationUpdateIEValue {
	return &v.inject
}
