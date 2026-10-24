// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s11 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s11

import (
	q6 "fmt"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q13 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	q15 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	q16 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	q11 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	q7 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// UTDOAInformationUpdateIEContainer is the concrete ProtocolIEContainer[UTDOAInformationUpdateIEValue].
type UTDOAInformationUpdateIEContainer []UTDOAInformationUpdateIEField

// UTDOAInformationUpdateIEField is the concrete ProtocolIEField[UTDOAInformationUpdateIEValue].
type UTDOAInformationUpdateIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         UTDOAInformationUpdateIEValue

	received q4.CompletePadding
}

func (v UTDOAInformationUpdateIEField) WithoutReplay() UTDOAInformationUpdateIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *UTDOAInformationUpdateIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *UTDOAInformationUpdateIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q6.Errorf("nil ProtocolIEField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return q7.WrapDecodePath(q6.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false); err != nil {
		return q6.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q6.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}
func (v *UTDOAInformationUpdateIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = UTDOAInformationUpdateIEField{}
	id, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false)
	if err != nil {
		return q7.WrapDecodePath(err, "Id")
	}
	v.Id = q5.ProtocolIEID(id)
	criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return q7.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = q5.Criticality(criticality)
	var zero UTDOAInformationUpdateIEValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return q7.WrapDecodePath(err, "Value")
	}
	raw = raw.WithPath("ProtocolIEField.Value")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return q7.WrapDecodePath(err, "Value")
	}
	v.Value = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}
func BridgeECIDMeasurementFailureIndicationIEValueCaptureLPPaProtocolIEContainer(v *q9.ECIDMeasurementFailureIndicationIEContainer, s *q4.SemanticCapture) {
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
func BridgeECIDMeasurementFailureIndicationIEValueCompareLPPaProtocolIEContainer(v *q9.ECIDMeasurementFailureIndicationIEContainer, s *q4.SemanticComparison) {
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
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeECIDMeasurementInitiationFailureIEValueCaptureLPPaProtocolIEContainer(v *q10.ECIDMeasurementInitiationFailureIEContainer, s *q4.SemanticCapture) {
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
func BridgeECIDMeasurementInitiationFailureIEValueCompareLPPaProtocolIEContainer(v *q10.ECIDMeasurementInitiationFailureIEContainer, s *q4.SemanticComparison) {
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
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeErrorIndicationIEValueCaptureLPPaProtocolIEContainer(v *q11.ErrorIndicationIEContainer, s *q4.SemanticCapture) {
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
func BridgeErrorIndicationIEValueCompareLPPaProtocolIEContainer(v *q11.ErrorIndicationIEContainer, s *q4.SemanticComparison) {
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
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeInterRATMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIESingleContainer(v *q9.InterRATMeasurementQuantitiesItemIEValueProtocolIESingleContainer, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	BridgeInterRATMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIEField(v, s)
}
func BridgeInterRATMeasurementQuantitiesItemIEValueCompareLPPaProtocolIESingleContainer(v *q9.InterRATMeasurementQuantitiesItemIEValueProtocolIESingleContainer, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	BridgeInterRATMeasurementQuantitiesItemIEValueCompareLPPaProtocolIEField(v, s)
}
func BridgeMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIESingleContainer(v *q9.MeasurementQuantitiesItemIEValueProtocolIESingleContainer, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	BridgeMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIEField(v, s)
}
func BridgeMeasurementQuantitiesItemIEValueCompareLPPaProtocolIESingleContainer(v *q9.MeasurementQuantitiesItemIEValueProtocolIESingleContainer, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	BridgeMeasurementQuantitiesItemIEValueCompareLPPaProtocolIEField(v, s)
}

// UTDOAInformationUpdateULConfigurationIEBinding is the concrete IEBinding[ULConfiguration, UTDOAInformationUpdateIEValue].
type UTDOAInformationUpdateULConfigurationIEBinding struct {
	info   q5.FieldInfo
	codec  q11.ULConfigurationValueCodec
	inject func(q11.ULConfiguration,

	) UTDOAInformationUpdateIEValue

	get func(*UTDOAInformationUpdateIEValue,

	) (*q11.ULConfiguration,

		bool)
}

func (b UTDOAInformationUpdateULConfigurationIEBinding) Info() q5.FieldInfo { return b.info }
func (b UTDOAInformationUpdateULConfigurationIEBinding) Codec() q11.ULConfigurationValueCodec {
	return b.codec
}
func (b UTDOAInformationUpdateULConfigurationIEBinding) New(value q11.ULConfiguration,

) (UTDOAInformationUpdateIEField, error) {
	if b.inject == nil {
		return UTDOAInformationUpdateIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return UTDOAInformationUpdateIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q11.BridgeULConfigurationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return UTDOAInformationUpdateIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return UTDOAInformationUpdateIEField{}, q4.OperationError(err, "Value.New")
	}
	return UTDOAInformationUpdateIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b UTDOAInformationUpdateULConfigurationIEBinding) Get(field *UTDOAInformationUpdateIEField) (*q11.ULConfiguration,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementFailureIndicationValueCodec is the concrete ValueCodec[ECIDMeasurementFailureIndication].
type ECIDMeasurementFailureIndicationValueCodec struct {
	context q5.BridgeCodecContext
	capture func(ECIDMeasurementFailureIndication, q4.DecodeState,

	) (ECIDMeasurementFailureIndication, q4.Snapshot,

	)
	compare func(ECIDMeasurementFailureIndication, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (ECIDMeasurementFailureIndication,

		error)
	encode func(ECIDMeasurementFailureIndication,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c ECIDMeasurementFailureIndicationValueCodec) New(value ECIDMeasurementFailureIndication,

) (ECIDMeasurementFailureIndicationAPERValue, error) {
	if c.encode == nil {
		return ECIDMeasurementFailureIndicationAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementFailureIndicationAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ECIDMeasurementFailureIndicationAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementFailureIndicationAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c ECIDMeasurementFailureIndicationValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (ECIDMeasurementFailureIndicationAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ECIDMeasurementFailureIndicationAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return ECIDMeasurementFailureIndicationAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ECIDMeasurementFailureIndicationAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return ECIDMeasurementFailureIndicationAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return ECIDMeasurementFailureIndicationAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ECIDMeasurementFailureIndicationValueCodec) EncodeAPER(value ECIDMeasurementFailureIndicationAPERValue, options ...q4.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q4.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q4.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q4.OperationError(err, c.path)
}
func (c ECIDMeasurementFailureIndicationValueCodec) encodeBudget(value ECIDMeasurementFailureIndication,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ECIDMeasurementFailureIndicationValueCodec) encodeChanged(value ECIDMeasurementFailureIndication,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// ECIDMeasurementInitiationFailureValueCodec is the concrete ValueCodec[ECIDMeasurementInitiationFailure].
type ECIDMeasurementInitiationFailureValueCodec struct {
	context q5.BridgeCodecContext
	capture func(ECIDMeasurementInitiationFailure, q4.DecodeState,

	) (ECIDMeasurementInitiationFailure, q4.Snapshot,

	)
	compare func(ECIDMeasurementInitiationFailure, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (ECIDMeasurementInitiationFailure,

		error)
	encode func(ECIDMeasurementInitiationFailure,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c ECIDMeasurementInitiationFailureValueCodec) New(value ECIDMeasurementInitiationFailure,

) (ECIDMeasurementInitiationFailureAPERValue, error) {
	if c.encode == nil {
		return ECIDMeasurementInitiationFailureAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationFailureAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ECIDMeasurementInitiationFailureAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationFailureAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c ECIDMeasurementInitiationFailureValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (ECIDMeasurementInitiationFailureAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ECIDMeasurementInitiationFailureAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return ECIDMeasurementInitiationFailureAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ECIDMeasurementInitiationFailureAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return ECIDMeasurementInitiationFailureAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return ECIDMeasurementInitiationFailureAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ECIDMeasurementInitiationFailureValueCodec) EncodeAPER(value ECIDMeasurementInitiationFailureAPERValue, options ...q4.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q4.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q4.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q4.OperationError(err, c.path)
}
func (c ECIDMeasurementInitiationFailureValueCodec) encodeBudget(value ECIDMeasurementInitiationFailure,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ECIDMeasurementInitiationFailureValueCodec) encodeChanged(value ECIDMeasurementInitiationFailure,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// ErrorIndicationValueCodec is the concrete ValueCodec[ErrorIndication].
type ErrorIndicationValueCodec struct {
	context q5.BridgeCodecContext
	capture func(ErrorIndication, q4.DecodeState,

	) (ErrorIndication, q4.Snapshot,

	)
	compare func(ErrorIndication, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (ErrorIndication,

		error)
	encode func(ErrorIndication,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c ErrorIndicationValueCodec) New(value ErrorIndication,

) (ErrorIndicationAPERValue, error) {
	if c.encode == nil {
		return ErrorIndicationAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ErrorIndicationAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ErrorIndicationAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return ErrorIndicationAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c ErrorIndicationValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (ErrorIndicationAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ErrorIndicationAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return ErrorIndicationAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ErrorIndicationAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return ErrorIndicationAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return ErrorIndicationAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ErrorIndicationValueCodec) EncodeAPER(value ErrorIndicationAPERValue, options ...q4.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	fresh := value.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, c.path)
	}
	if !fresh && value.context == c.context && value.replay.Present() {

		plan := c.compare(value.Value, value.replay, q4.ComparisonBudget(&budget))
		if err := plan.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			if err := value.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, c.path)
			}
			out, err := value.received.ReplayBytes(&budget)
			return out, q4.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, false, plan, budget)
	}
	out, err := c.encodeBudget(value.Value, fresh, budget)
	return out, q4.OperationError(err, c.path)
}
func (c ErrorIndicationValueCodec) encodeBudget(value ErrorIndication,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ErrorIndicationValueCodec) encodeChanged(value ErrorIndication,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeErrorIndicationIEValueValidateLPPaIEContainer(fields q11.ErrorIndicationIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

) q10.ValidationReport {
	report := func() q10.ValidationReport {
		sealed := q10.ValidationReport{Complete: true}
		*q10.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q10.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q5.ProtocolIEID]int, len(rows))
	counts := make(map[q5.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q10.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q10.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q4.Location{Path: q4.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q11.BridgeErrorIndicationIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q11.BridgeErrorIndicationIEValueMethodRule(field.Value)
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.ValueIDMismatch, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q5.TableID {
				sealed := q5.TableID{}
				*q5.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q5.FieldInfo
			related := []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.RepeatedIE, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q5.ValidationSeverityUnrecognized
			if _, globallyKnown := q12.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q5.ValidationSeverityError
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.NotAllowed), RelatedRules: q12.BridgeLppaHandlingRules(q5.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongCriticality, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q12.BridgeLppaValidationRule(q5.WrongCriticality), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongOrder, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.WrongOrder), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q5.PresenceMandatory && counts[row.ID] == 0 {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.MissingMandatory, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.MissingMandatory), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.MissingMandatory), row.Rule}})
		}
		if row.Presence == q5.PresenceConditional {
			q10.BridgeValidationReportMethodAddDeferred(&report, q5.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q10.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeECIDMeasurementInitiationFailureIEValueValidateLPPaIEContainer(fields q10.ECIDMeasurementInitiationFailureIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

) q10.ValidationReport {
	report := func() q10.ValidationReport {
		sealed := q10.ValidationReport{Complete: true}
		*q10.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q10.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q5.ProtocolIEID]int, len(rows))
	counts := make(map[q5.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q10.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q10.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q4.Location{Path: q4.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q10.BridgeECIDMeasurementInitiationFailureIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q10.BridgeECIDMeasurementInitiationFailureIEValueMethodRule(field.Value)
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.ValueIDMismatch, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q5.TableID {
				sealed := q5.TableID{}
				*q5.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q5.FieldInfo
			related := []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.RepeatedIE, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q5.ValidationSeverityUnrecognized
			if _, globallyKnown := q12.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q5.ValidationSeverityError
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.NotAllowed), RelatedRules: q12.BridgeLppaHandlingRules(q5.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongCriticality, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q12.BridgeLppaValidationRule(q5.WrongCriticality), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongOrder, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.WrongOrder), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q5.PresenceMandatory && counts[row.ID] == 0 {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.MissingMandatory, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.MissingMandatory), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.MissingMandatory), row.Rule}})
		}
		if row.Presence == q5.PresenceConditional {
			q10.BridgeValidationReportMethodAddDeferred(&report, q5.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q10.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeECIDMeasurementFailureIndicationIEValueValidateLPPaIEContainer(fields q9.ECIDMeasurementFailureIndicationIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

) q10.ValidationReport {
	report := func() q10.ValidationReport {
		sealed := q10.ValidationReport{Complete: true}
		*q10.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q10.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q5.ProtocolIEID]int, len(rows))
	counts := make(map[q5.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q10.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q10.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q4.Location{Path: q4.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q9.BridgeECIDMeasurementFailureIndicationIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q9.BridgeECIDMeasurementFailureIndicationIEValueMethodRule(field.Value)
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.ValueIDMismatch, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q5.TableID {
				sealed := q5.TableID{}
				*q5.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q5.FieldInfo
			related := []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.RepeatedIE, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q5.ValidationSeverityUnrecognized
			if _, globallyKnown := q12.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q5.ValidationSeverityError
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.NotAllowed), RelatedRules: q12.BridgeLppaHandlingRules(q5.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongCriticality, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q12.BridgeLppaValidationRule(q5.WrongCriticality), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongOrder, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.WrongOrder), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q5.PresenceMandatory && counts[row.ID] == 0 {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.MissingMandatory, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.MissingMandatory), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.MissingMandatory), row.Rule}})
		}
		if row.Presence == q5.PresenceConditional {
			q10.BridgeValidationReportMethodAddDeferred(&report, q5.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q10.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeECIDMeasurementTerminationCommandIEValueValidateLPPaIEContainer(fields q8.ECIDMeasurementTerminationCommandIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

) q10.ValidationReport {
	report := func() q10.ValidationReport {
		sealed := q10.ValidationReport{Complete: true}
		*q10.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q10.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q5.ProtocolIEID]int, len(rows))
	counts := make(map[q5.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q10.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q10.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q4.Location{Path: q4.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q13.BridgeECIDMeasurementTerminationCommandIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q13.BridgeECIDMeasurementTerminationCommandIEValueMethodRule(field.Value)
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.ValueIDMismatch, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q5.TableID {
				sealed := q5.TableID{}
				*q5.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q5.FieldInfo
			related := []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.RepeatedIE, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q5.ValidationSeverityUnrecognized
			if _, globallyKnown := q12.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q5.ValidationSeverityError
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.NotAllowed), RelatedRules: q12.BridgeLppaHandlingRules(q5.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongCriticality, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q12.BridgeLppaValidationRule(q5.WrongCriticality), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongOrder, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.WrongOrder), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q5.PresenceMandatory && counts[row.ID] == 0 {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.MissingMandatory, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.MissingMandatory), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.MissingMandatory), row.Rule}})
		}
		if row.Presence == q5.PresenceConditional {
			q10.BridgeValidationReportMethodAddDeferred(&report, q5.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q10.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeCriticalityDiagnosticsExtIEsValueValidateLPPaExtensionContainer(fields q8.CriticalityDiagnosticsExtIEsExtContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget) q10.ValidationReport {
	bb := q4.NewBudgetBuffer(budget)
	if err := q4.ChargeSlice[q8.CriticalityDiagnosticsExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q10.ValidationReport {
			sealed := q10.ValidationReport{}
			*q10.BridgeValidationReportFieldErr(&sealed) = err
			*q10.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q8.CriticalityDiagnosticsExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeCriticalityDiagnosticsExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeCriticalityDiagnosticsIEListExtIEsValueValidateLPPaExtensionContainer(fields q8.CriticalityDiagnosticsIEListExtIEsExtContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget) q10.ValidationReport {
	bb := q4.NewBudgetBuffer(budget)
	if err := q4.ChargeSlice[q8.CriticalityDiagnosticsIEListExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q10.ValidationReport {
			sealed := q10.ValidationReport{}
			*q10.BridgeValidationReportFieldErr(&sealed) = err
			*q10.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q8.CriticalityDiagnosticsIEListExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeCriticalityDiagnosticsIEListExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeECGIExtIEsValueValidateLPPaExtensionContainer(fields q8.ECGIExtIEsExtContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget) q10.ValidationReport {
	bb := q4.NewBudgetBuffer(budget)
	if err := q4.ChargeSlice[q8.ECGIExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q10.ValidationReport {
			sealed := q10.ValidationReport{}
			*q10.BridgeValidationReportFieldErr(&sealed) = err
			*q10.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q8.ECGIExtIEsIEContainer, len(fields))
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
func BridgeInterRATMeasurementQuantitiesItemIEValueValidateLPPaIEContainer(fields q9.InterRATMeasurementQuantitiesItemIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

) q10.ValidationReport {
	report := func() q10.ValidationReport {
		sealed := q10.ValidationReport{Complete: true}
		*q10.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q10.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q5.ProtocolIEID]int, len(rows))
	counts := make(map[q5.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q10.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q10.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q4.Location{Path: q4.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q9.BridgeInterRATMeasurementQuantitiesItemIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q9.BridgeInterRATMeasurementQuantitiesItemIEValueMethodRule(field.Value)
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.ValueIDMismatch, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q5.TableID {
				sealed := q5.TableID{}
				*q5.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q5.FieldInfo
			related := []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.RepeatedIE, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q5.ValidationSeverityUnrecognized
			if _, globallyKnown := q12.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q5.ValidationSeverityError
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.NotAllowed), RelatedRules: q12.BridgeLppaHandlingRules(q5.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongCriticality, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q12.BridgeLppaValidationRule(q5.WrongCriticality), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongOrder, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.WrongOrder), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q5.PresenceMandatory && counts[row.ID] == 0 {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.MissingMandatory, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.MissingMandatory), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.MissingMandatory), row.Rule}})
		}
		if row.Presence == q5.PresenceConditional {
			q10.BridgeValidationReportMethodAddDeferred(&report, q5.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q10.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueValidateLPPaExtensionContainer(fields q8.InterRATMeasurementQuantitiesValueExtIEsExtContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget) q10.ValidationReport {
	bb := q4.NewBudgetBuffer(budget)
	if err := q4.ChargeSlice[q8.InterRATMeasurementQuantitiesValueExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q10.ValidationReport {
			sealed := q10.ValidationReport{}
			*q10.BridgeValidationReportFieldErr(&sealed) = err
			*q10.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q8.InterRATMeasurementQuantitiesValueExtIEsIEContainer, len(fields))
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
func BridgeMeasurementQuantitiesItemIEValueValidateLPPaIEContainer(fields q9.MeasurementQuantitiesItemIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

) q10.ValidationReport {
	report := func() q10.ValidationReport {
		sealed := q10.ValidationReport{Complete: true}
		*q10.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q10.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q5.ProtocolIEID]int, len(rows))
	counts := make(map[q5.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q10.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q10.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q4.Location{Path: q4.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q9.BridgeMeasurementQuantitiesItemIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q9.BridgeMeasurementQuantitiesItemIEValueMethodRule(field.Value)
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.ValueIDMismatch, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q5.TableID {
				sealed := q5.TableID{}
				*q5.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q5.FieldInfo
			related := []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.RepeatedIE, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q5.ValidationSeverityUnrecognized
			if _, globallyKnown := q12.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q5.ValidationSeverityError
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.NotAllowed), RelatedRules: q12.BridgeLppaHandlingRules(q5.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongCriticality, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q12.BridgeLppaValidationRule(q5.WrongCriticality), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongOrder, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.WrongOrder), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q5.PresenceMandatory && counts[row.ID] == 0 {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.MissingMandatory, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.MissingMandatory), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.MissingMandatory), row.Rule}})
		}
		if row.Presence == q5.PresenceConditional {
			q10.BridgeValidationReportMethodAddDeferred(&report, q5.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q10.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeMeasurementQuantitiesValueExtIEsValueValidateLPPaExtensionContainer(fields q12.MeasurementQuantitiesValueExtIEsExtContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget) q10.ValidationReport {
	bb := q4.NewBudgetBuffer(budget)
	if err := q4.ChargeSlice[q12.MeasurementQuantitiesValueExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q10.ValidationReport {
			sealed := q10.ValidationReport{}
			*q10.BridgeValidationReportFieldErr(&sealed) = err
			*q10.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q12.MeasurementQuantitiesValueExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeMeasurementQuantitiesValueExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeNRCGIExtIEsValueValidateLPPaExtensionContainer(fields q12.NRCGIExtIEsExtContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget) q10.ValidationReport {
	bb := q4.NewBudgetBuffer(budget)
	if err := q4.ChargeSlice[q12.NRCGIExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q10.ValidationReport {
			sealed := q10.ValidationReport{}
			*q10.BridgeValidationReportFieldErr(&sealed) = err
			*q10.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q12.NRCGIExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeNRCGIExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// eCIDMeasurementFailureIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[ECIDMeasurementFailureIndicationIEValue].
type ECIDMeasurementFailureIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) q9.ECIDMeasurementFailureIndicationIEValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (q9.ECIDMeasurementFailureIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

func BridgeECIDMeasurementFailureIndicationIEValueCaptureLPPaProtocolIEField(v *q9.ECIDMeasurementFailureIndicationIEField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q9.BridgeECIDMeasurementFailureIndicationIEFieldFieldStream(v))
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q9.BridgeECIDMeasurementFailureIndicationIEValueMethodCaptureFraming(v.Value))
	v.Value = q9.BridgeECIDMeasurementFailureIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(q9.BridgeECIDMeasurementFailureIndicationIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, q9.BridgeECIDMeasurementFailureIndicationIEFieldFieldReplay(v), *q9.BridgeECIDMeasurementFailureIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeECIDMeasurementFailureIndicationIEValueCompareLPPaProtocolIEField(v *q9.ECIDMeasurementFailureIndicationIEField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q13.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q13.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q9.BridgeECIDMeasurementFailureIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *q9.BridgeECIDMeasurementFailureIndicationIEFieldFieldReplay(v), *q9.BridgeECIDMeasurementFailureIndicationIEFieldFieldWithoutReplay(v))
}

// eCIDMeasurementInitiationFailureIEValueProtocolOpenValue is the concrete protocolOpenValue[ECIDMeasurementInitiationFailureIEValue].
type ECIDMeasurementInitiationFailureIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) q10.ECIDMeasurementInitiationFailureIEValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (q10.ECIDMeasurementInitiationFailureIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

func BridgeECIDMeasurementInitiationFailureIEValueCaptureLPPaProtocolIEField(v *q10.ECIDMeasurementInitiationFailureIEField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q10.BridgeECIDMeasurementInitiationFailureIEFieldFieldStream(v))
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q10.BridgeECIDMeasurementInitiationFailureIEValueMethodCaptureFraming(v.Value))
	v.Value = q10.BridgeECIDMeasurementInitiationFailureIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(q10.BridgeECIDMeasurementInitiationFailureIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, q10.BridgeECIDMeasurementInitiationFailureIEFieldFieldReplay(v), *q10.BridgeECIDMeasurementInitiationFailureIEFieldFieldWithoutReplay(v))
}
func BridgeECIDMeasurementInitiationFailureIEValueCompareLPPaProtocolIEField(v *q10.ECIDMeasurementInitiationFailureIEField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q13.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q13.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q10.BridgeECIDMeasurementInitiationFailureIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *q10.BridgeECIDMeasurementInitiationFailureIEFieldFieldReplay(v), *q10.BridgeECIDMeasurementInitiationFailureIEFieldFieldWithoutReplay(v))
}

// errorIndicationIEValueProtocolOpenValue is the concrete protocolOpenValue[ErrorIndicationIEValue].
type ErrorIndicationIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) q11.ErrorIndicationIEValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (q11.ErrorIndicationIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

func BridgeErrorIndicationIEValueCaptureLPPaProtocolIEField(v *q11.ErrorIndicationIEField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q11.BridgeErrorIndicationIEFieldFieldStream(v))
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q11.BridgeErrorIndicationIEValueMethodCaptureFraming(v.Value))
	v.Value = q11.BridgeErrorIndicationIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(q11.BridgeErrorIndicationIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, q11.BridgeErrorIndicationIEFieldFieldReplay(v), *q11.BridgeErrorIndicationIEFieldFieldWithoutReplay(v))
}
func BridgeErrorIndicationIEValueCompareLPPaProtocolIEField(v *q11.ErrorIndicationIEField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q13.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q13.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q11.BridgeErrorIndicationIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *q11.BridgeErrorIndicationIEFieldFieldReplay(v), *q11.BridgeErrorIndicationIEFieldFieldWithoutReplay(v))
}

// interRATMeasurementQuantitiesItemIEValueProtocolOpenValue is the concrete protocolOpenValue[InterRATMeasurementQuantitiesItemIEValue].
type InterRATMeasurementQuantitiesItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) q9.InterRATMeasurementQuantitiesItemIEValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (q9.InterRATMeasurementQuantitiesItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

func BridgeInterRATMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIEField(v *q9.InterRATMeasurementQuantitiesItemIEField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q9.BridgeInterRATMeasurementQuantitiesItemIEFieldFieldStream(v))
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q9.BridgeInterRATMeasurementQuantitiesItemIEValueMethodCaptureFraming(v.Value))
	v.Value = q9.BridgeInterRATMeasurementQuantitiesItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(q9.BridgeInterRATMeasurementQuantitiesItemIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, q9.BridgeInterRATMeasurementQuantitiesItemIEFieldFieldReplay(v), *q9.BridgeInterRATMeasurementQuantitiesItemIEFieldFieldWithoutReplay(v))
}
func BridgeInterRATMeasurementQuantitiesItemIEValueCompareLPPaProtocolIEField(v *q9.InterRATMeasurementQuantitiesItemIEField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q13.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q13.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q9.BridgeInterRATMeasurementQuantitiesItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *q9.BridgeInterRATMeasurementQuantitiesItemIEFieldFieldReplay(v), *q9.BridgeInterRATMeasurementQuantitiesItemIEFieldFieldWithoutReplay(v))
}

// measurementQuantitiesItemIEValueProtocolOpenValue is the concrete protocolOpenValue[MeasurementQuantitiesItemIEValue].
type MeasurementQuantitiesItemIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) q9.MeasurementQuantitiesItemIEValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (q9.MeasurementQuantitiesItemIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

func BridgeMeasurementQuantitiesItemIEValueCaptureLPPaProtocolIEField(v *q9.MeasurementQuantitiesItemIEField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q9.BridgeMeasurementQuantitiesItemIEFieldFieldStream(v))
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q9.BridgeMeasurementQuantitiesItemIEValueMethodCaptureFraming(v.Value))
	v.Value = q9.BridgeMeasurementQuantitiesItemIEValueMethodCaptureSemantics(v.Value, *s)
	s.Child(q9.BridgeMeasurementQuantitiesItemIEValueMethodCaptureSnapshot(v.Value))
	s.End(f, q9.BridgeMeasurementQuantitiesItemIEFieldFieldReplay(v), *q9.BridgeMeasurementQuantitiesItemIEFieldFieldWithoutReplay(v))
}
func BridgeMeasurementQuantitiesItemIEValueCompareLPPaProtocolIEField(v *q9.MeasurementQuantitiesItemIEField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q13.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q13.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q9.BridgeMeasurementQuantitiesItemIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *q9.BridgeMeasurementQuantitiesItemIEFieldFieldReplay(v), *q9.BridgeMeasurementQuantitiesItemIEFieldFieldWithoutReplay(v))
}

// ECIDMeasurementFailureIndicationAPERValue is the concrete APERValue[ECIDMeasurementFailureIndication].
type ECIDMeasurementFailureIndicationAPERValue struct {
	context q5.BridgeCodecContext
	Value   ECIDMeasurementFailureIndication

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v ECIDMeasurementFailureIndicationAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v ECIDMeasurementFailureIndicationAPERValue) WithoutReplay() ECIDMeasurementFailureIndicationAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// ECIDMeasurementInitiationFailureAPERValue is the concrete APERValue[ECIDMeasurementInitiationFailure].
type ECIDMeasurementInitiationFailureAPERValue struct {
	context q5.BridgeCodecContext
	Value   ECIDMeasurementInitiationFailure

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v ECIDMeasurementInitiationFailureAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v ECIDMeasurementInitiationFailureAPERValue) WithoutReplay() ECIDMeasurementInitiationFailureAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// ErrorIndicationAPERValue is the concrete APERValue[ErrorIndication].
type ErrorIndicationAPERValue struct {
	context q5.BridgeCodecContext
	Value   ErrorIndication

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v ErrorIndicationAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v ErrorIndicationAPERValue) WithoutReplay() ErrorIndicationAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeCriticalityDiagnosticsExtIEsValueValidateLPPaIEContainer(fields q8.CriticalityDiagnosticsExtIEsIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

) q10.ValidationReport {
	report := func() q10.ValidationReport {
		sealed := q10.ValidationReport{Complete: true}
		*q10.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q10.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q5.ProtocolIEID]int, len(rows))
	counts := make(map[q5.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q10.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q10.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q4.Location{Path: q4.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q13.BridgeCriticalityDiagnosticsExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q13.BridgeCriticalityDiagnosticsExtIEsValueMethodRule(field.Value)
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.ValueIDMismatch, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q5.TableID {
				sealed := q5.TableID{}
				*q5.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q5.FieldInfo
			related := []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.RepeatedIE, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q5.ValidationSeverityUnrecognized
			if _, globallyKnown := q12.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q5.ValidationSeverityError
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.NotAllowed), RelatedRules: q12.BridgeLppaHandlingRules(q5.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongCriticality, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q12.BridgeLppaValidationRule(q5.WrongCriticality), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongOrder, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.WrongOrder), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q5.PresenceMandatory && counts[row.ID] == 0 {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.MissingMandatory, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.MissingMandatory), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.MissingMandatory), row.Rule}})
		}
		if row.Presence == q5.PresenceConditional {
			q10.BridgeValidationReportMethodAddDeferred(&report, q5.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q10.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeCriticalityDiagnosticsIEListExtIEsValueValidateLPPaIEContainer(fields q8.CriticalityDiagnosticsIEListExtIEsIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

) q10.ValidationReport {
	report := func() q10.ValidationReport {
		sealed := q10.ValidationReport{Complete: true}
		*q10.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q10.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q5.ProtocolIEID]int, len(rows))
	counts := make(map[q5.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q10.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q10.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q4.Location{Path: q4.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q13.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q13.BridgeCriticalityDiagnosticsIEListExtIEsValueMethodRule(field.Value)
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.ValueIDMismatch, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q5.TableID {
				sealed := q5.TableID{}
				*q5.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q5.FieldInfo
			related := []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.RepeatedIE, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q5.ValidationSeverityUnrecognized
			if _, globallyKnown := q12.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q5.ValidationSeverityError
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.NotAllowed), RelatedRules: q12.BridgeLppaHandlingRules(q5.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongCriticality, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q12.BridgeLppaValidationRule(q5.WrongCriticality), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongOrder, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.WrongOrder), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q5.PresenceMandatory && counts[row.ID] == 0 {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.MissingMandatory, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.MissingMandatory), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.MissingMandatory), row.Rule}})
		}
		if row.Presence == q5.PresenceConditional {
			q10.BridgeValidationReportMethodAddDeferred(&report, q5.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q10.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeECGIExtIEsValueValidateLPPaIEContainer(fields q8.ECGIExtIEsIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

) q10.ValidationReport {
	report := func() q10.ValidationReport {
		sealed := q10.ValidationReport{Complete: true}
		*q10.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q10.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q5.ProtocolIEID]int, len(rows))
	counts := make(map[q5.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q10.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q10.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q4.Location{Path: q4.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q13.BridgeECGIExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q13.BridgeECGIExtIEsValueMethodRule(field.Value)
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.ValueIDMismatch, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q5.TableID {
				sealed := q5.TableID{}
				*q5.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q5.FieldInfo
			related := []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.RepeatedIE, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q5.ValidationSeverityUnrecognized
			if _, globallyKnown := q12.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q5.ValidationSeverityError
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.NotAllowed), RelatedRules: q12.BridgeLppaHandlingRules(q5.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongCriticality, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q12.BridgeLppaValidationRule(q5.WrongCriticality), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongOrder, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.WrongOrder), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q5.PresenceMandatory && counts[row.ID] == 0 {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.MissingMandatory, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.MissingMandatory), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.MissingMandatory), row.Rule}})
		}
		if row.Presence == q5.PresenceConditional {
			q10.BridgeValidationReportMethodAddDeferred(&report, q5.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q10.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeInterRATMeasurementQuantitiesValueExtIEsValueValidateLPPaIEContainer(fields q8.InterRATMeasurementQuantitiesValueExtIEsIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

) q10.ValidationReport {
	report := func() q10.ValidationReport {
		sealed := q10.ValidationReport{Complete: true}
		*q10.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q10.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q5.ProtocolIEID]int, len(rows))
	counts := make(map[q5.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q10.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q10.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q4.Location{Path: q4.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q13.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q13.BridgeInterRATMeasurementQuantitiesValueExtIEsValueMethodRule(field.Value)
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.ValueIDMismatch, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q5.TableID {
				sealed := q5.TableID{}
				*q5.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q5.FieldInfo
			related := []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.RepeatedIE, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q5.ValidationSeverityUnrecognized
			if _, globallyKnown := q12.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q5.ValidationSeverityError
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.NotAllowed), RelatedRules: q12.BridgeLppaHandlingRules(q5.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongCriticality, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q12.BridgeLppaValidationRule(q5.WrongCriticality), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongOrder, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.WrongOrder), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q5.PresenceMandatory && counts[row.ID] == 0 {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.MissingMandatory, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.MissingMandatory), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.MissingMandatory), row.Rule}})
		}
		if row.Presence == q5.PresenceConditional {
			q10.BridgeValidationReportMethodAddDeferred(&report, q5.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q10.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeMeasurementQuantitiesValueExtIEsValueValidateLPPaIEContainer(fields q12.MeasurementQuantitiesValueExtIEsIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

) q10.ValidationReport {
	report := func() q10.ValidationReport {
		sealed := q10.ValidationReport{Complete: true}
		*q10.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q10.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q5.ProtocolIEID]int, len(rows))
	counts := make(map[q5.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q10.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q10.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q4.Location{Path: q4.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q13.BridgeMeasurementQuantitiesValueExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q13.BridgeMeasurementQuantitiesValueExtIEsValueMethodRule(field.Value)
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.ValueIDMismatch, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q5.TableID {
				sealed := q5.TableID{}
				*q5.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q5.FieldInfo
			related := []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.RepeatedIE, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q5.ValidationSeverityUnrecognized
			if _, globallyKnown := q12.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q5.ValidationSeverityError
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.NotAllowed), RelatedRules: q12.BridgeLppaHandlingRules(q5.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongCriticality, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q12.BridgeLppaValidationRule(q5.WrongCriticality), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongOrder, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.WrongOrder), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q5.PresenceMandatory && counts[row.ID] == 0 {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.MissingMandatory, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.MissingMandatory), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.MissingMandatory), row.Rule}})
		}
		if row.Presence == q5.PresenceConditional {
			q10.BridgeValidationReportMethodAddDeferred(&report, q5.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q10.BridgeValidationReportFieldErr(&report) != nil {
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
func BridgeNRCGIExtIEsValueValidateLPPaIEContainer(fields q12.NRCGIExtIEsIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

) q10.ValidationReport {
	report := func() q10.ValidationReport {
		sealed := q10.ValidationReport{Complete: true}
		*q10.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := q4.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*q10.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[q5.ProtocolIEID]int, len(rows))
	counts := make(map[q5.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *q10.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*q10.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := q4.Location{Path: q4.Path(q6.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.455 V19.0.0 §9.3.8 binds the selected value to @id.
		if !q13.BridgeNRCGIExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q13.BridgeNRCGIExtIEsValueMethodRule(field.Value)
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.ValueIDMismatch, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q5.TableID {
				sealed := q5.TableID{}
				*q5.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q5.FieldInfo
			related := []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.RepeatedIE, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q5.ValidationSeverityUnrecognized
			if _, globallyKnown := q12.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q5.ValidationSeverityError
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.NotAllowed), RelatedRules: q12.BridgeLppaHandlingRules(q5.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongCriticality, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q12.BridgeLppaValidationRule(q5.WrongCriticality), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongOrder, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.WrongOrder), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q5.PresenceMandatory && counts[row.ID] == 0 {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.MissingMandatory, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q12.BridgeLppaValidationRule(q5.MissingMandatory), RelatedRules: []q4.SourceRule{q12.BridgeLppaAdoptedRule(q5.MissingMandatory), row.Rule}})
		}
		if row.Presence == q5.PresenceConditional {
			q10.BridgeValidationReportMethodAddDeferred(&report, q5.DeferredCondition{Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *q10.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// NewBitmapsforNPRSTen creates a BitmapsforNPRS with the ten alternative.
func BridgeNewBitmapsforNPRSTenLegacy(v q7.BitString) q14.BitmapsforNPRS {
	return q14.BitmapsforNPRS{
		Choice: q5.BitmapsforNPRSChoiceTen,
		Ten:    &v,
	}
}

// NewBitmapsforNPRSForty creates a BitmapsforNPRS with the forty alternative.
func BridgeNewBitmapsforNPRSFortyLegacy(v q7.BitString) q14.BitmapsforNPRS {
	return q14.BitmapsforNPRS{
		Choice: q5.BitmapsforNPRSChoiceForty,
		Forty:  &v,
	}
}

// NewBitmapsforNPRSTenTdd creates a BitmapsforNPRS with the ten-tdd alternative.
func BridgeNewBitmapsforNPRSTenTddLegacy(v q7.BitString) q14.BitmapsforNPRS {
	return q14.BitmapsforNPRS{
		Choice: q5.BitmapsforNPRSChoiceTenTdd,
		TenTdd: &v,
	}
}

// NewBitmapsforNPRSFortyTdd creates a BitmapsforNPRS with the forty-tdd alternative.
func BridgeNewBitmapsforNPRSFortyTddLegacy(v q7.BitString) q14.BitmapsforNPRS {
	return q14.BitmapsforNPRS{
		Choice:   q5.BitmapsforNPRSChoiceFortyTdd,
		FortyTdd: &v,
	}
}

// NewCauseRadioNetwork creates a Cause with the radioNetwork alternative.
func BridgeNewCauseRadioNetworkLegacy(v q5.CauseRadioNetwork) q14.Cause {
	return q14.Cause{
		Choice:       q5.CauseChoiceRadioNetwork,
		RadioNetwork: &v,
	}
}

// NewCauseProtocol creates a Cause with the protocol alternative.
func BridgeNewCauseProtocolLegacy(v q5.CauseProtocol) q14.Cause {
	return q14.Cause{
		Choice:   q5.CauseChoiceProtocol,
		Protocol: &v,
	}
}

// NewCauseMisc creates a Cause with the misc alternative.
func BridgeNewCauseMiscLegacy(v q5.CauseMisc) q14.Cause {
	return q14.Cause{
		Choice: q5.CauseChoiceMisc,
		Misc:   &v,
	}
}

// NewNPRSMutingConfigurationTwo creates a NPRSMutingConfiguration with the two alternative.
func BridgeNewNPRSMutingConfigurationTwoLegacy(v q7.BitString) q15.NPRSMutingConfiguration {
	return q15.NPRSMutingConfiguration{
		Choice: q5.NPRSMutingConfigurationChoiceTwo,
		Two:    &v,
	}
}

// NewNPRSMutingConfigurationFour creates a NPRSMutingConfiguration with the four alternative.
func BridgeNewNPRSMutingConfigurationFourLegacy(v q7.BitString) q15.NPRSMutingConfiguration {
	return q15.NPRSMutingConfiguration{
		Choice: q5.NPRSMutingConfigurationChoiceFour,
		Four:   &v,
	}
}

// NewNPRSMutingConfigurationEight creates a NPRSMutingConfiguration with the eight alternative.
func BridgeNewNPRSMutingConfigurationEightLegacy(v q7.BitString) q15.NPRSMutingConfiguration {
	return q15.NPRSMutingConfiguration{
		Choice: q5.NPRSMutingConfigurationChoiceEight,
		Eight:  &v,
	}
}

// NewNPRSMutingConfigurationSixteen creates a NPRSMutingConfiguration with the sixteen alternative.
func BridgeNewNPRSMutingConfigurationSixteenLegacy(v q7.BitString) q15.NPRSMutingConfiguration {
	return q15.NPRSMutingConfiguration{
		Choice:  q5.NPRSMutingConfigurationChoiceSixteen,
		Sixteen: &v,
	}
}

// NewPRSMutingConfigurationEight creates a PRSMutingConfiguration with the eight alternative.
func BridgeNewPRSMutingConfigurationEightLegacy(v q7.BitString) q16.PRSMutingConfiguration {
	return q16.PRSMutingConfiguration{
		Choice: q5.PRSMutingConfigurationChoiceEight,
		Eight:  &v,
	}
}

// NewPRSMutingConfigurationFiveHundredAndTwelve creates a PRSMutingConfiguration with the five-hundred-and-twelve alternative.
func BridgeNewPRSMutingConfigurationFiveHundredAndTwelveLegacy(v q7.BitString) q16.PRSMutingConfiguration {
	return q16.PRSMutingConfiguration{
		Choice:               q5.PRSMutingConfigurationChoiceFiveHundredAndTwelve,
		FiveHundredAndTwelve: &v,
	}
}

// MarshalAPERAssistanceInformationFailureListTo appends a AssistanceInformationFailureList list to bb.
func BridgeMarshalAPERAssistanceInformationFailureListTo(list q14.AssistanceInformationFailureList, bb *q4.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := q10.BridgeAsn1cAPERAssistanceInformationFailureListListValue{Value: list}
	if err := q4.EncodeCollection(bb, int64(len(v.Value)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := q14.BridgeAssistanceInformationFailureListElemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERCriticalityDiagnosticsIEListTo appends a CriticalityDiagnosticsIEList list to bb.
func BridgeMarshalAPERCriticalityDiagnosticsIEListTo(list q14.CriticalityDiagnosticsIEList, bb *q4.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := q10.BridgeAsn1cAPERCriticalityDiagnosticsIEListListValue{Value: list}
	if err := q4.EncodeCollection(bb, int64(len(v.Value)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 256, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := q14.BridgeCriticalityDiagnosticsIEListElemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERInterRATMeasurementQuantitiesTo appends a InterRATMeasurementQuantities list to bb.
func BridgeMarshalAPERInterRATMeasurementQuantitiesTo(list q9.InterRATMeasurementQuantities, bb *q4.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := q10.BridgeAsn1cAPERInterRATMeasurementQuantitiesListValue{Value: list}
	if err := q4.EncodeCollection(bb, int64(len(v.Value)), q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := q9.BridgeInterRATMeasurementQuantitiesItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERMeasurementQuantitiesTo appends a MeasurementQuantities list to bb.
func BridgeMarshalAPERMeasurementQuantitiesTo(list q9.MeasurementQuantities, bb *q4.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := q10.BridgeAsn1cAPERMeasurementQuantitiesListValue{Value: list}
	if err := q4.EncodeCollection(bb, int64(len(v.Value)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := q9.BridgeMeasurementQuantitiesItemIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERMBSFNsubframeConfigurationTo appends a MBSFNsubframeConfiguration list to bb.
func BridgeMarshalAPERMBSFNsubframeConfigurationTo(list q10.MBSFNsubframeConfiguration, bb *q4.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := q10.BridgeAsn1cAPERMBSFNsubframeConfigurationListValue{Value: list}
	if err := q4.EncodeCollection(bb, int64(len(v.Value)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := q10.BridgeMBSFNsubframeConfigurationValueMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERPosSIBsTo appends a PosSIBs list to bb.
func BridgeMarshalAPERPosSIBsTo(list q11.PosSIBs, bb *q4.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := q11.BridgeAsn1cAPERPosSIBsListValue{Value: list}
	if err := q4.EncodeCollection(bb, int64(len(v.Value)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := q11.BridgePosSIBsElemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERPosSIBSegmentsTo appends a PosSIBSegments list to bb.
func BridgeMarshalAPERPosSIBSegmentsTo(list q16.PosSIBSegments, bb *q4.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := q10.BridgeAsn1cAPERPosSIBSegmentsListValue{Value: list}
	if err := q4.EncodeCollection(bb, int64(len(v.Value)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := q16.BridgePosSIBSegmentsElemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPERSRSConfigurationForAllCellsTo appends a SRSConfigurationForAllCells list to bb.
func BridgeMarshalAPERSRSConfigurationForAllCellsTo(list q10.SRSConfigurationForAllCells, bb *q4.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := q10.BridgeAsn1cAPERSRSConfigurationForAllCellsListValue{Value: list}
	if err := q4.EncodeCollection(bb, int64(len(v.Value)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 5, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := q10.BridgeSRSConfigurationForOneCellMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}

// NewBitmapsforNPRSTen constructs a checked complete value.
func NewBitmapsforNPRSTen(v q7.BitString, options ...q4.BuildOption) (q14.BitmapsforNPRS, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return q14.BitmapsforNPRS{}, q4.OperationError(err, "BitmapsforNPRSTen")
	}
	value := BridgeNewBitmapsforNPRSTenLegacy(v)
	if _, err := q14.BridgeBitmapsforNPRSMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.BitmapsforNPRS{}, q4.OperationError(err, "BitmapsforNPRSTen")
	}
	return value, q4.OperationError(nil, "BitmapsforNPRSTen")
}

// NewBitmapsforNPRSForty constructs a checked complete value.
func NewBitmapsforNPRSForty(v q7.BitString, options ...q4.BuildOption) (q14.BitmapsforNPRS, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return q14.BitmapsforNPRS{}, q4.OperationError(err, "BitmapsforNPRSForty")
	}
	value := BridgeNewBitmapsforNPRSFortyLegacy(v)
	if _, err := q14.BridgeBitmapsforNPRSMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.BitmapsforNPRS{}, q4.OperationError(err, "BitmapsforNPRSForty")
	}
	return value, q4.OperationError(nil, "BitmapsforNPRSForty")
}

// NewBitmapsforNPRSTenTdd constructs a checked complete value.
func NewBitmapsforNPRSTenTdd(v q7.BitString, options ...q4.BuildOption) (q14.BitmapsforNPRS, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return q14.BitmapsforNPRS{}, q4.OperationError(err, "BitmapsforNPRSTenTdd")
	}
	value := BridgeNewBitmapsforNPRSTenTddLegacy(v)
	if _, err := q14.BridgeBitmapsforNPRSMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.BitmapsforNPRS{}, q4.OperationError(err, "BitmapsforNPRSTenTdd")
	}
	return value, q4.OperationError(nil, "BitmapsforNPRSTenTdd")
}

// NewBitmapsforNPRSFortyTdd constructs a checked complete value.
func NewBitmapsforNPRSFortyTdd(v q7.BitString, options ...q4.BuildOption) (q14.BitmapsforNPRS, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return q14.BitmapsforNPRS{}, q4.OperationError(err, "BitmapsforNPRSFortyTdd")
	}
	value := BridgeNewBitmapsforNPRSFortyTddLegacy(v)
	if _, err := q14.BridgeBitmapsforNPRSMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.BitmapsforNPRS{}, q4.OperationError(err, "BitmapsforNPRSFortyTdd")
	}
	return value, q4.OperationError(nil, "BitmapsforNPRSFortyTdd")
}

// NewCauseRadioNetwork constructs a checked complete value.
func NewCauseRadioNetwork(v q5.CauseRadioNetwork, options ...q4.BuildOption) (q14.Cause, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return q14.Cause{}, q4.OperationError(err, "CauseRadioNetwork")
	}
	value := BridgeNewCauseRadioNetworkLegacy(v)
	if _, err := q14.BridgeCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.Cause{}, q4.OperationError(err, "CauseRadioNetwork")
	}
	return value, q4.OperationError(nil, "CauseRadioNetwork")
}

// NewCauseProtocol constructs a checked complete value.
func NewCauseProtocol(v q5.CauseProtocol, options ...q4.BuildOption) (q14.Cause, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return q14.Cause{}, q4.OperationError(err, "CauseProtocol")
	}
	value := BridgeNewCauseProtocolLegacy(v)
	if _, err := q14.BridgeCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.Cause{}, q4.OperationError(err, "CauseProtocol")
	}
	return value, q4.OperationError(nil, "CauseProtocol")
}

// NewCauseMisc constructs a checked complete value.
func NewCauseMisc(v q5.CauseMisc, options ...q4.BuildOption) (q14.Cause, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return q14.Cause{}, q4.OperationError(err, "CauseMisc")
	}
	value := BridgeNewCauseMiscLegacy(v)
	if _, err := q14.BridgeCauseMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q14.Cause{}, q4.OperationError(err, "CauseMisc")
	}
	return value, q4.OperationError(nil, "CauseMisc")
}

// NewNPRSMutingConfigurationTwo constructs a checked complete value.
func NewNPRSMutingConfigurationTwo(v q7.BitString, options ...q4.BuildOption) (q15.NPRSMutingConfiguration, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return q15.NPRSMutingConfiguration{}, q4.OperationError(err, "NPRSMutingConfigurationTwo")
	}
	value := BridgeNewNPRSMutingConfigurationTwoLegacy(v)
	if _, err := q15.BridgeNPRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q15.NPRSMutingConfiguration{}, q4.OperationError(err, "NPRSMutingConfigurationTwo")
	}
	return value, q4.OperationError(nil, "NPRSMutingConfigurationTwo")
}

// NewNPRSMutingConfigurationFour constructs a checked complete value.
func NewNPRSMutingConfigurationFour(v q7.BitString, options ...q4.BuildOption) (q15.NPRSMutingConfiguration, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return q15.NPRSMutingConfiguration{}, q4.OperationError(err, "NPRSMutingConfigurationFour")
	}
	value := BridgeNewNPRSMutingConfigurationFourLegacy(v)
	if _, err := q15.BridgeNPRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q15.NPRSMutingConfiguration{}, q4.OperationError(err, "NPRSMutingConfigurationFour")
	}
	return value, q4.OperationError(nil, "NPRSMutingConfigurationFour")
}

// NewNPRSMutingConfigurationEight constructs a checked complete value.
func NewNPRSMutingConfigurationEight(v q7.BitString, options ...q4.BuildOption) (q15.NPRSMutingConfiguration, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return q15.NPRSMutingConfiguration{}, q4.OperationError(err, "NPRSMutingConfigurationEight")
	}
	value := BridgeNewNPRSMutingConfigurationEightLegacy(v)
	if _, err := q15.BridgeNPRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q15.NPRSMutingConfiguration{}, q4.OperationError(err, "NPRSMutingConfigurationEight")
	}
	return value, q4.OperationError(nil, "NPRSMutingConfigurationEight")
}

// NewNPRSMutingConfigurationSixteen constructs a checked complete value.
func NewNPRSMutingConfigurationSixteen(v q7.BitString, options ...q4.BuildOption) (q15.NPRSMutingConfiguration, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return q15.NPRSMutingConfiguration{}, q4.OperationError(err, "NPRSMutingConfigurationSixteen")
	}
	value := BridgeNewNPRSMutingConfigurationSixteenLegacy(v)
	if _, err := q15.BridgeNPRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q15.NPRSMutingConfiguration{}, q4.OperationError(err, "NPRSMutingConfigurationSixteen")
	}
	return value, q4.OperationError(nil, "NPRSMutingConfigurationSixteen")
}

// NewPRSMutingConfigurationEight constructs a checked complete value.
func NewPRSMutingConfigurationEight(v q7.BitString, options ...q4.BuildOption) (q16.PRSMutingConfiguration, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return q16.PRSMutingConfiguration{}, q4.OperationError(err, "PRSMutingConfigurationEight")
	}
	value := BridgeNewPRSMutingConfigurationEightLegacy(v)
	if _, err := q16.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q16.PRSMutingConfiguration{}, q4.OperationError(err, "PRSMutingConfigurationEight")
	}
	return value, q4.OperationError(nil, "PRSMutingConfigurationEight")
}

// NewPRSMutingConfigurationFiveHundredAndTwelve constructs a checked complete value.
func NewPRSMutingConfigurationFiveHundredAndTwelve(v q7.BitString, options ...q4.BuildOption) (q16.PRSMutingConfiguration, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return q16.PRSMutingConfiguration{}, q4.OperationError(err, "PRSMutingConfigurationFiveHundredAndTwelve")
	}
	value := BridgeNewPRSMutingConfigurationFiveHundredAndTwelveLegacy(v)
	if _, err := q16.BridgePRSMutingConfigurationMethodMarshalAPERBudget((&value), budget, false); err != nil {
		return q16.PRSMutingConfiguration{}, q4.OperationError(err, "PRSMutingConfigurationFiveHundredAndTwelve")
	}
	return value, q4.OperationError(nil, "PRSMutingConfigurationFiveHundredAndTwelve")
}

// ECIDMeasurementInitiationFailure represents the ASN.1 type E-CIDMeasurementInitiationFailure (SEQUENCE).
type ECIDMeasurementInitiationFailure struct {
	replay           q4.Snapshot
	stream           q4.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    q4.WireSpan
	ProtocolIEs      q10.ECIDMeasurementInitiationFailureIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                            `asn1:"-" json:"-"`
	extCount         int64                                           `asn1:"-" json:"-"`
	extPresent       []bool                                          `asn1:"-" json:"-"`
	extData          [][]byte                                        `asn1:"-" json:"-"`
	perPadding       q4.FinalPadding                                 `asn1:"-" json:"-"`
	perExtPadding    []q4.CompletePadding                            `asn1:"-" json:"-"`
	extOrigin        []q4.OpaqueOrigin
	extWire          []q4.WireSpan
}

// ECIDMeasurementFailureIndication represents the ASN.1 type E-CIDMeasurementFailureIndication (SEQUENCE).
type ECIDMeasurementFailureIndication struct {
	replay           q4.Snapshot
	stream           q4.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    q4.WireSpan
	ProtocolIEs      q9.ECIDMeasurementFailureIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                           `asn1:"-" json:"-"`
	extCount         int64                                          `asn1:"-" json:"-"`
	extPresent       []bool                                         `asn1:"-" json:"-"`
	extData          [][]byte                                       `asn1:"-" json:"-"`
	perPadding       q4.FinalPadding                                `asn1:"-" json:"-"`
	perExtPadding    []q4.CompletePadding                           `asn1:"-" json:"-"`
	extOrigin        []q4.OpaqueOrigin
	extWire          []q4.WireSpan
}

// ErrorIndication represents the ASN.1 type ErrorIndication (SEQUENCE).
type ErrorIndication struct {
	replay           q4.Snapshot
	stream           q4.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    q4.WireSpan
	ProtocolIEs      q11.ErrorIndicationIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                           `asn1:"-" json:"-"`
	extCount         int64                          `asn1:"-" json:"-"`
	extPresent       []bool                         `asn1:"-" json:"-"`
	extData          [][]byte                       `asn1:"-" json:"-"`
	perPadding       q4.FinalPadding                `asn1:"-" json:"-"`
	perExtPadding    []q4.CompletePadding           `asn1:"-" json:"-"`
	extOrigin        []q4.OpaqueOrigin
	extWire          []q4.WireSpan
}

// MarshalAPER encodes ECIDMeasurementInitiationFailure to APER format.
func (v *ECIDMeasurementInitiationFailure) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ECIDMeasurementInitiationFailure) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := q4.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = q14.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := q4.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := q4.EncodeCollection(bb, int64(len(v.ProtocolIEs)), q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := q10.BridgeECIDMeasurementInitiationFailureIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q6.Errorf("%w: extension bitmap index %d", q4.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q4.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q4.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	q4.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	q4.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes ECIDMeasurementInitiationFailure from APER format.
func (v *ECIDMeasurementInitiationFailure) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ECIDMeasurementInitiationFailure with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ECIDMeasurementInitiationFailure) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "ECIDMeasurementInitiationFailure")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "ECIDMeasurementInitiationFailure")
	}
	padding, err := q4.CaptureFinalBits(bb, "ECIDMeasurementInitiationFailure")
	if err != nil {
		return q7.WrapDecodePath(err, "ECIDMeasurementInitiationFailure")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ECIDMeasurementInitiationFailure) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementInitiationFailure{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(q10.ECIDMeasurementInitiationFailureIEContainer, 0)
	_, errCollection_protocolies := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem q10.ECIDMeasurementInitiationFailureIEField
			if err := q10.BridgeECIDMeasurementInitiationFailureIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			if next, err := q4.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return q7.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q7.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		if err := q4.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := q4.ChargeSlice[q4.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]q4.OpaqueOrigin, len(v.extData))
		if err := q4.ChargeSlice[q4.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]q4.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q4.DecodeOpaqueOpenTypeAligned(bb, q4.UnknownSelector, q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
				if err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(q4.UnknownExtension, i); err != nil {
					return err
				}
				var retained q4.WireSpan
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

// MarshalAPER encodes ECIDMeasurementFailureIndication to APER format.
func (v *ECIDMeasurementFailureIndication) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ECIDMeasurementFailureIndication) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := q4.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = q14.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := q4.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := q4.EncodeCollection(bb, int64(len(v.ProtocolIEs)), q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := q9.BridgeECIDMeasurementFailureIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q6.Errorf("%w: extension bitmap index %d", q4.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q4.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q4.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	q4.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	q4.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes ECIDMeasurementFailureIndication from APER format.
func (v *ECIDMeasurementFailureIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ECIDMeasurementFailureIndication with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ECIDMeasurementFailureIndication) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "ECIDMeasurementFailureIndication")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "ECIDMeasurementFailureIndication")
	}
	padding, err := q4.CaptureFinalBits(bb, "ECIDMeasurementFailureIndication")
	if err != nil {
		return q7.WrapDecodePath(err, "ECIDMeasurementFailureIndication")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ECIDMeasurementFailureIndication) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementFailureIndication{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(q9.ECIDMeasurementFailureIndicationIEContainer, 0)
	_, errCollection_protocolies := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem q9.ECIDMeasurementFailureIndicationIEField
			if err := q9.BridgeECIDMeasurementFailureIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			if next, err := q4.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return q7.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q7.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		if err := q4.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := q4.ChargeSlice[q4.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]q4.OpaqueOrigin, len(v.extData))
		if err := q4.ChargeSlice[q4.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]q4.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q4.DecodeOpaqueOpenTypeAligned(bb, q4.UnknownSelector, q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
				if err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(q4.UnknownExtension, i); err != nil {
					return err
				}
				var retained q4.WireSpan
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

// MarshalAPEROTDOAInformationTypeTo appends a OTDOAInformationType list to bb.
func BridgeMarshalAPEROTDOAInformationTypeTo(list q15.OTDOAInformationType, bb *q4.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := q10.BridgeAsn1cAPEROTDOAInformationTypeListValue{Value: list}
	if err := q4.EncodeCollection(bb, int64(len(v.Value)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := q15.BridgeOTDOAInformationTypeIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}

// MarshalAPER encodes ErrorIndication to APER format.
func (v *ErrorIndication) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ErrorIndication) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	extensionEncodingData, extensionCopyErr := q4.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = q14.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := q4.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	if err := q4.EncodeCollection(bb, int64(len(v.ProtocolIEs)), q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_protocolies < 0 || fragmentOffset_protocolies > int64(len(v.ProtocolIEs)) || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(len(v.ProtocolIEs[fragmentOffset_protocolies:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.ProtocolIEs[fragmentOffset_protocolies : fragmentOffset_protocolies+fragmentLength_protocolies] {
			if err := q11.BridgeErrorIndicationIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding protocolIEs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding protocolIEs: %w", err)
	}
	if hasExtensions {
		extCount := extensionCount
		// ITU-T X.691 (02/2021) 19.8 and 11.9.3.4: bitmap length is extCount+1.
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:444
		if extCount < 0 || extCount >= 16383 {
			return q6.Errorf("%w: extension bitmap index %d", q4.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := q4.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:448
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := q4.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:455
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil) {
				var data []byte
				if i < int64(len(extensionEncodingData)) {
					data = extensionEncodingData[i]
				}
				if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
					return err
				}
			}
		}
	}
	q4.AppendExtensionRecovery(bb, v.perPadding, recoveryStart)
	q4.AppendTruncatedExtension(bb, v.perPadding)
	return nil
}

// UnmarshalAPER decodes ErrorIndication from APER format.
func (v *ErrorIndication) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ErrorIndication with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ErrorIndication) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "ErrorIndication")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "ErrorIndication")
	}
	padding, err := q4.CaptureFinalBits(bb, "ErrorIndication")
	if err != nil {
		return q7.WrapDecodePath(err, "ErrorIndication")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ErrorIndication) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ErrorIndication{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(q11.ErrorIndicationIEContainer, 0)
	_, errCollection_protocolies := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem q11.ErrorIndicationIEField
			if err := q11.BridgeErrorIndicationIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("ProtocolIEs[%d]", fragmentOffset_protocolies+i))
			}
			if next, err := q4.AppendValues(bb, v.ProtocolIEs, elem); err != nil {
				return err
			} else {
				v.ProtocolIEs = next
			}
		}
		return nil
	})
	if errCollection_protocolies != nil {
		return q7.WrapDecodePath(errCollection_protocolies, "ProtocolIEs")
	}
	if hasExtensions {
		extCount, extPresent, err := extAdditions.DecodeBitmapAligned(bb)
		if err != nil {
			return q7.WrapDecodePath(err, "ExtData_")
		}
		v.extCount = extCount
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:630
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		if err := q4.ChargeSlice[[]byte](bb, uint64(len(extPresent))); err != nil {
			return err
		}
		v.extData = make([][]byte, len(extPresent))
		if err := q4.ChargeSlice[q4.OpaqueOrigin](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extOrigin = make([]q4.OpaqueOrigin, len(v.extData))
		if err := q4.ChargeSlice[q4.WireSpan](bb, uint64(len(v.extData))); err != nil {
			return err
		}
		v.extWire = make([]q4.WireSpan, len(v.extData))
		v.extPresent = extPresent
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:633
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return q6.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := q4.DecodeOpaqueOpenTypeAligned(bb, q4.UnknownSelector, q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4"})
				if err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("ExtData_[%d]", i))
				}
				opaque = opaque.WithPath("Extensions")
				if err := opaque.ObserveIndexed(q4.UnknownExtension, i); err != nil {
					return err
				}
				var retained q4.WireSpan
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
func (v *ECIDMeasurementFailureIndication) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ECIDMeasurementFailureIndication", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ECIDMeasurementFailureIndication) WithoutReplay() ECIDMeasurementFailureIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero ECIDMeasurementFailureIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ECIDMeasurementInitiationFailure) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ECIDMeasurementInitiationFailure", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ECIDMeasurementInitiationFailure) WithoutReplay() ECIDMeasurementInitiationFailure {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero ECIDMeasurementInitiationFailure
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ErrorIndication) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ErrorIndication", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ErrorIndication) WithoutReplay() ErrorIndication {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero ErrorIndication
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ECIDMeasurementFailureIndication) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ECIDMeasurementFailureIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ECIDMeasurementFailureIndication.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ECIDMeasurementFailureIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ECIDMeasurementFailureIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ECIDMeasurementFailureIndication.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ECIDMeasurementFailureIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ECIDMeasurementInitiationFailure) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ECIDMeasurementInitiationFailure) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ECIDMeasurementInitiationFailure.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ECIDMeasurementInitiationFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ECIDMeasurementInitiationFailure) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ECIDMeasurementInitiationFailure.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ECIDMeasurementInitiationFailure.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ErrorIndication) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ErrorIndication) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ErrorIndication.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ErrorIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ErrorIndication) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ErrorIndication.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ErrorIndication.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *ECIDMeasurementFailureIndication) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "ECIDMeasurementFailureIndication")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "ECIDMeasurementFailureIndication")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaECIDMeasurementFailureIndication(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "ECIDMeasurementFailureIndication")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "ECIDMeasurementFailureIndication")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "ECIDMeasurementFailureIndication")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "ECIDMeasurementFailureIndication")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "ECIDMeasurementFailureIndication")
}
func (v *ECIDMeasurementFailureIndication) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ECIDMeasurementFailureIndication) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ECIDMeasurementFailureIndication) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *ECIDMeasurementFailureIndication) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ECIDMeasurementFailureIndication) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
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
func (v *ECIDMeasurementInitiationFailure) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "ECIDMeasurementInitiationFailure")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "ECIDMeasurementInitiationFailure")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaECIDMeasurementInitiationFailure(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "ECIDMeasurementInitiationFailure")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "ECIDMeasurementInitiationFailure")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "ECIDMeasurementInitiationFailure")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "ECIDMeasurementInitiationFailure")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "ECIDMeasurementInitiationFailure")
}
func (v *ECIDMeasurementInitiationFailure) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ECIDMeasurementInitiationFailure) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ECIDMeasurementInitiationFailure) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *ECIDMeasurementInitiationFailure) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ECIDMeasurementInitiationFailure) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
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
func (v *ErrorIndication) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "ErrorIndication")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "ErrorIndication")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaErrorIndication(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "ErrorIndication")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "ErrorIndication")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "ErrorIndication")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "ErrorIndication")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "ErrorIndication")
}
func (v *ErrorIndication) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ErrorIndication) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ErrorIndication) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *ErrorIndication) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ErrorIndication) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
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
func (v *ECIDMeasurementFailureIndication) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "ECIDMeasurementFailureIndication")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded ECIDMeasurementFailureIndication
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaECIDMeasurementFailureIndication(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = ECIDMeasurementFailureIndication{}
		return report, q4.OperationError(err, "ECIDMeasurementFailureIndication")
	}
	*v = decoded
	return report, q4.OperationError(nil, "ECIDMeasurementFailureIndication")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ECIDMeasurementInitiationFailure) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "ECIDMeasurementInitiationFailure")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded ECIDMeasurementInitiationFailure
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaECIDMeasurementInitiationFailure(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = ECIDMeasurementInitiationFailure{}
		return report, q4.OperationError(err, "ECIDMeasurementInitiationFailure")
	}
	*v = decoded
	return report, q4.OperationError(nil, "ECIDMeasurementInitiationFailure")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ErrorIndication) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "ErrorIndication")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded ErrorIndication
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaErrorIndication(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = ErrorIndication{}
		return report, q4.OperationError(err, "ErrorIndication")
	}
	*v = decoded
	return report, q4.OperationError(nil, "ErrorIndication")
}
func BridgeCaptureLPPaECIDMeasurementFailureIndication(v *ECIDMeasurementFailureIndication, s *q4.SemanticCapture) {
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
func BridgeCompareLPPaECIDMeasurementFailureIndication(v *ECIDMeasurementFailureIndication, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeECIDMeasurementFailureIndicationIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaECIDMeasurementInitiationFailure(v *ECIDMeasurementInitiationFailure, s *q4.SemanticCapture) {
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
func BridgeCompareLPPaECIDMeasurementInitiationFailure(v *ECIDMeasurementInitiationFailure, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeECIDMeasurementInitiationFailureIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaErrorIndication(v *ErrorIndication, s *q4.SemanticCapture) {
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
func BridgeCompareLPPaErrorIndication(v *ErrorIndication, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeErrorIndicationIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaInterRATMeasurementQuantities(v *q9.InterRATMeasurementQuantities, s *q4.SemanticCapture) {
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
func BridgeCompareLPPaInterRATMeasurementQuantities(v *q9.InterRATMeasurementQuantities, s *q4.SemanticComparison) {
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
		s.End(f, q4.Snapshot{}, false)
	}
	s.End(f, q4.Snapshot{}, false)
}
func BridgeCaptureLPPaMeasurementQuantities(v *q9.MeasurementQuantities, s *q4.SemanticCapture) {
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
func BridgeCompareLPPaMeasurementQuantities(v *q9.MeasurementQuantities, s *q4.SemanticComparison) {
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
		s.End(f, q4.Snapshot{}, false)
	}
	s.End(f, q4.Snapshot{}, false)
}
func BridgeCaptureLPPaUTDOAInformationUpdateIEValue(v *UTDOAInformationUpdateIEValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q5.BridgeCaptureLPPaProtocolIEID(&v.id, s)
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
		case q5.ProtocolIEID(13):
			{
				f := s.Begin()
				s.Bool(v.rowULConfiguration == nil)
				if v.rowULConfiguration != nil {
					q11.BridgeCaptureLPPaULConfiguration(v.rowULConfiguration, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v UTDOAInformationUpdateIEValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v UTDOAInformationUpdateIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v UTDOAInformationUpdateIEValue) captureSemantics(s q4.SemanticCapture) UTDOAInformationUpdateIEValue {
	BridgeCaptureLPPaUTDOAInformationUpdateIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaUTDOAInformationUpdateIEValue(v *UTDOAInformationUpdateIEValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q13.BridgeCompareLPPaProtocolIEID(&v.id, s)
	if v.isOpaque {
		{
			f := s.Begin()
			s.Bool(v.opaque == nil)
			if v.opaque != nil {
				s.Opaque((*v.opaque))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case q5.ProtocolIEID(13):
			{
				f := s.Begin()
				s.Bool(v.rowULConfiguration == nil)
				if v.rowULConfiguration != nil {
					q11.BridgeCompareLPPaULConfiguration(v.rowULConfiguration, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v UTDOAInformationUpdateIEValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaUTDOAInformationUpdateIEValue(&v, &s)
	return s
}
func (v UTDOAInformationUpdateIEValue) WithoutReplay() UTDOAInformationUpdateIEValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}

type UTDOAInformationUpdateIEValue struct {
	id                 q5.ProtocolIEID
	withoutReplay      bool
	received           q4.WireSpan
	replay             q4.Snapshot
	opaque             *q4.OpaqueOpenType
	isOpaque           bool
	rowULConfiguration *q11.ULConfiguration
}

func (v UTDOAInformationUpdateIEValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q5.ProtocolIEID(13):
		return v.rowULConfiguration != nil
	default:
		return false
	}
}
func (v *UTDOAInformationUpdateIEValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (UTDOAInformationUpdateIEValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationUpdate-IEs"}}
}
func (UTDOAInformationUpdateIEValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(13):
		return q4.UnknownSelector
	case q5.ProtocolIEID(0):
		return q4.NotInTable
	case q5.ProtocolIEID(1):
		return q4.NotInTable
	case q5.ProtocolIEID(2):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
		return q4.NotInTable
	case q5.ProtocolIEID(6):
		return q4.NotInTable
	case q5.ProtocolIEID(7):
		return q4.NotInTable
	case q5.ProtocolIEID(8):
		return q4.NotInTable
	case q5.ProtocolIEID(9):
		return q4.NotInTable
	case q5.ProtocolIEID(10):
		return q4.NotInTable
	case q5.ProtocolIEID(11):
		return q4.NotInTable
	case q5.ProtocolIEID(12):
		return q4.NotInTable
	case q5.ProtocolIEID(14):
		return q4.NotInTable
	case q5.ProtocolIEID(15):
		return q4.NotInTable
	case q5.ProtocolIEID(16):
		return q4.NotInTable
	case q5.ProtocolIEID(17):
		return q4.NotInTable
	case q5.ProtocolIEID(18):
		return q4.NotInTable
	case q5.ProtocolIEID(19):
		return q4.NotInTable
	case q5.ProtocolIEID(20):
		return q4.NotInTable
	case q5.ProtocolIEID(21):
		return q4.NotInTable
	case q5.ProtocolIEID(22):
		return q4.NotInTable
	case q5.ProtocolIEID(23):
		return q4.NotInTable
	case q5.ProtocolIEID(24):
		return q4.NotInTable
	case q5.ProtocolIEID(25):
		return q4.NotInTable
	case q5.ProtocolIEID(27):
		return q4.NotInTable
	default:
		return q4.UnknownSelector
	}
}
func (v *UTDOAInformationUpdateIEValue) AsULConfiguration() (*q11.ULConfiguration, bool) {
	if v == nil || v.id != q5.ProtocolIEID(13) || v.rowULConfiguration == nil {
		return nil, false
	}
	return v.rowULConfiguration, true
}
func (v UTDOAInformationUpdateIEValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (UTDOAInformationUpdateIEValue, error) {
	out := UTDOAInformationUpdateIEValue{id: id}
	var scope *q4.BitBuffer
	switch id {
	case 13:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q5.ProtocolIEID(13):
		replayUsage := scope.Usage()
		var value q11.ULConfiguration
		child := raw.ChildDecodeBuffer()
		if err := q11.BridgeULConfigurationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, q6.Errorf("%s %w", "ULConfiguration:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "ULConfiguration")
		if err != nil {
			return out, err
		}
		*q11.BridgeULConfigurationFieldPerPadding(&value) = padding
		*q11.BridgeULConfigurationFieldReceived(&value) = true
		raw.RetainContents(q11.BridgeULConfigurationFieldReceivedBytes(&value))
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowULConfiguration = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	default:
		if err := raw.Observe(q4.UnknownIE); err != nil {
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
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v UTDOAInformationUpdateIEValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
	fresh = fresh || v.withoutReplay
	if fresh {
		bb := q4.NewBudgetBuffer(budget)
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
	}
	if v.isOpaque {
		if v.opaque == nil {
			return nil, q4.ErrInvalidValue
		}
		return v.opaque.EncodeBytes(budget)
	}
	switch v.id {
	case q5.ProtocolIEID(13):
		if v.rowULConfiguration == nil {
			return nil, q6.Errorf("%s missing value", "UTDOAInformationUpdate-IEs.id-ULConfiguration:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := q11.BridgeULConfigurationMethodMarshalAPERBudget(v.rowULConfiguration, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, q6.Errorf("%s id %d has no value", "UTDOAInformationUpdateIEValue:", v.id)
	}
}

type UTDOAInformationUpdateIETable struct{}

func UTDOAInformationUpdateIEs() UTDOAInformationUpdateIETable {
	return UTDOAInformationUpdateIETable{}
}
func (UTDOAInformationUpdateIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationUpdate-IEs"}
		return sealed
	}()
}
func (UTDOAInformationUpdateIETable) infoULConfiguration() q5.FieldInfo {
	return q5.FieldInfo{Table: UTDOAInformationUpdateIEs().ID(), ID: q5.ProtocolIEID(13), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ULConfiguration"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "UTDOAInformationUpdate-IEs", Row: "id-ULConfiguration"}}}
}
func (t UTDOAInformationUpdateIETable) ULConfiguration() UTDOAInformationUpdateULConfigurationIEBinding {
	return UTDOAInformationUpdateULConfigurationIEBinding{info: t.infoULConfiguration(), codec: func() q11.ULConfigurationValueCodec {
		sealed := q11.ULConfigurationValueCodec{}
		*q11.BridgeULConfigurationValueCodecFieldPath(&sealed) = "ULConfiguration"
		*q11.BridgeULConfigurationValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q11.ULConfiguration, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q11.ULConfiguration
				return empty, err
			}
			var zero UTDOAInformationUpdateIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(13), raw)
			if err != nil {
				var empty q11.ULConfiguration
				return empty, err
			}
			value, ok := decoded.AsULConfiguration()
			if !ok {
				var empty q11.ULConfiguration
				return empty, q6.Errorf("binding UTDOAInformationUpdate-IEs.id-ULConfiguration: no selected value")
			}
			return *value, nil
		}
		*q11.BridgeULConfigurationValueCodecFieldEncode(&sealed) = func(value q11.ULConfiguration, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (UTDOAInformationUpdateIEValue{id: q5.ProtocolIEID(13), rowULConfiguration: &value}).encodeFresh(fresh, budget)
		}
		*q11.BridgeULConfigurationValueCodecFieldCapture(&sealed) = func(v q11.ULConfiguration, options q4.DecodeState) (q11.ULConfiguration, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q11.BridgeCaptureLPPaULConfiguration(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q11.BridgeULConfigurationValueCodecFieldCompare(&sealed) = func(v q11.ULConfiguration, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q11.BridgeCompareLPPaULConfiguration(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q11.BridgeULConfigurationValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:ULConfiguration"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q11.ULConfiguration) UTDOAInformationUpdateIEValue {
			return UTDOAInformationUpdateIEValue{id: q5.ProtocolIEID(13), rowULConfiguration: &value}
		}, get: func(value *UTDOAInformationUpdateIEValue) (*q11.ULConfiguration, bool) {
			return value.AsULConfiguration()
		}}
}
func (t UTDOAInformationUpdateIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (UTDOAInformationUpdateIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return UTDOAInformationUpdateIEField{}, q4.OperationError(q6.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q5.ProtocolIEID(13):
		return UTDOAInformationUpdateIEField{}, q4.OperationError(q6.Errorf("known IE id-ULConfiguration requires its typed binding"), "Opaque")
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return UTDOAInformationUpdateIEField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return UTDOAInformationUpdateIEField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return UTDOAInformationUpdateIEField{}, q4.OperationError(err, "Opaque")
		}
		return UTDOAInformationUpdateIEField{Id: id, Criticality: criticality, Value: UTDOAInformationUpdateIEValue{id: id, opaque: retained, isOpaque: true}}, q4.OperationError(nil, "Opaque")
	}
}
func BridgeMergeNestedValidation(dst *q10.ValidationReport, src q10.ValidationReport) {
	if *q10.BridgeValidationReportFieldErr(dst) != nil {
		return
	}
	if *q10.BridgeValidationReportFieldErr(&src) != nil {
		*q10.BridgeValidationReportFieldErr(dst) = *q10.BridgeValidationReportFieldErr(&src)
		return
	}
	bb := q4.NewBudgetBuffer(*q10.BridgeValidationReportFieldBudget(dst))
	var err error
	dst.Issues, err = q4.AppendValues(bb, dst.Issues, src.Issues...)
	if err != nil {
		*q10.BridgeValidationReportFieldErr(dst) = err
		return
	}
	dst.Deferred, err = q4.AppendValues(bb, dst.Deferred, src.Deferred...)
	if err != nil {
		*q10.BridgeValidationReportFieldErr(dst) = err
		return
	}
	dst.Unchecked, err = q4.AppendValues(bb, dst.Unchecked, src.Unchecked...)
	if err != nil {
		*q10.BridgeValidationReportFieldErr(dst) = err
		return
	}
	if !src.Complete {
		dst.Complete = false
	}
}
func BridgeECIDMeasurementFailureIndicationAPERValueFieldContext(v *ECIDMeasurementFailureIndicationAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementFailureIndicationAPERValueFieldReceived(v *ECIDMeasurementFailureIndicationAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementFailureIndicationAPERValueFieldReplay(v *ECIDMeasurementFailureIndicationAPERValue) *q4.Snapshot {
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
func BridgeECIDMeasurementFailureIndicationFieldExtOrigin(v *ECIDMeasurementFailureIndication) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeECIDMeasurementFailureIndicationFieldExtPresent(v *ECIDMeasurementFailureIndication) *[]bool {
	return &v.extPresent
}
func BridgeECIDMeasurementFailureIndicationFieldExtWire(v *ECIDMeasurementFailureIndication) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeECIDMeasurementFailureIndicationFieldPerExtPadding(v *ECIDMeasurementFailureIndication) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeECIDMeasurementFailureIndicationFieldPerPadding(v *ECIDMeasurementFailureIndication) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeECIDMeasurementFailureIndicationFieldProtocolIEsIndef(v *ECIDMeasurementFailureIndication) *bool {
	return &v.protocolIEsIndef
}
func BridgeECIDMeasurementFailureIndicationFieldReceived(v *ECIDMeasurementFailureIndication) *bool {
	return &v.received
}
func BridgeECIDMeasurementFailureIndicationFieldReceivedBytes(v *ECIDMeasurementFailureIndication) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeECIDMeasurementFailureIndicationFieldReplay(v *ECIDMeasurementFailureIndication) *q4.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementFailureIndicationFieldStream(v *ECIDMeasurementFailureIndication) *q4.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementFailureIndicationFieldWithoutReplay(v *ECIDMeasurementFailureIndication) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementFailureIndicationMethodMarshalAPERBudget(v *ECIDMeasurementFailureIndication, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeECIDMeasurementFailureIndicationMethodMarshalAPERChanged(v *ECIDMeasurementFailureIndication, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeECIDMeasurementFailureIndicationMethodMarshalAPERChangedValue(v *ECIDMeasurementFailureIndication, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeECIDMeasurementFailureIndicationMethodMarshalAPERFreshValue(v *ECIDMeasurementFailureIndication, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeECIDMeasurementFailureIndicationMethodMarshalAPERLegacy(v *ECIDMeasurementFailureIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeECIDMeasurementFailureIndicationMethodMarshalAPERPlanned(v *ECIDMeasurementFailureIndication, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeECIDMeasurementFailureIndicationMethodMarshalAPERTo(v *ECIDMeasurementFailureIndication, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementFailureIndicationMethodUnmarshalAPERFrom(v *ECIDMeasurementFailureIndication, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementFailureIndicationMethodUnmarshalAPERLegacy(v *ECIDMeasurementFailureIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeECIDMeasurementFailureIndicationMethodUnmarshalAPERWithOptions(v *ECIDMeasurementFailureIndication, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeECIDMeasurementFailureIndicationValueCodecFieldCapture(v *ECIDMeasurementFailureIndicationValueCodec) *func(ECIDMeasurementFailureIndication, q4.DecodeState) (ECIDMeasurementFailureIndication, q4.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementFailureIndicationValueCodecFieldCompare(v *ECIDMeasurementFailureIndicationValueCodec) *func(ECIDMeasurementFailureIndication, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementFailureIndicationValueCodecFieldContext(v *ECIDMeasurementFailureIndicationValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementFailureIndicationValueCodecFieldDecode(v *ECIDMeasurementFailureIndicationValueCodec) *func([]byte, q4.DecodeState) (ECIDMeasurementFailureIndication, error) {
	return &v.decode
}
func BridgeECIDMeasurementFailureIndicationValueCodecFieldEncode(v *ECIDMeasurementFailureIndicationValueCodec) *func(ECIDMeasurementFailureIndication, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementFailureIndicationValueCodecFieldPath(v *ECIDMeasurementFailureIndicationValueCodec) *q4.Path {
	return &v.path
}
func BridgeECIDMeasurementFailureIndicationValueCodecMethodEncodeBudget(v ECIDMeasurementFailureIndicationValueCodec, a0 ECIDMeasurementFailureIndication, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeECIDMeasurementFailureIndicationValueCodecMethodEncodeChanged(v ECIDMeasurementFailureIndicationValueCodec, a0 ECIDMeasurementFailureIndication, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeECIDMeasurementInitiationFailureAPERValueFieldContext(v *ECIDMeasurementInitiationFailureAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementInitiationFailureAPERValueFieldReceived(v *ECIDMeasurementInitiationFailureAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementInitiationFailureAPERValueFieldReplay(v *ECIDMeasurementInitiationFailureAPERValue) *q4.Snapshot {
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
func BridgeECIDMeasurementInitiationFailureFieldExtOrigin(v *ECIDMeasurementInitiationFailure) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeECIDMeasurementInitiationFailureFieldExtPresent(v *ECIDMeasurementInitiationFailure) *[]bool {
	return &v.extPresent
}
func BridgeECIDMeasurementInitiationFailureFieldExtWire(v *ECIDMeasurementInitiationFailure) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeECIDMeasurementInitiationFailureFieldPerExtPadding(v *ECIDMeasurementInitiationFailure) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeECIDMeasurementInitiationFailureFieldPerPadding(v *ECIDMeasurementInitiationFailure) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeECIDMeasurementInitiationFailureFieldProtocolIEsIndef(v *ECIDMeasurementInitiationFailure) *bool {
	return &v.protocolIEsIndef
}
func BridgeECIDMeasurementInitiationFailureFieldReceived(v *ECIDMeasurementInitiationFailure) *bool {
	return &v.received
}
func BridgeECIDMeasurementInitiationFailureFieldReceivedBytes(v *ECIDMeasurementInitiationFailure) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeECIDMeasurementInitiationFailureFieldReplay(v *ECIDMeasurementInitiationFailure) *q4.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationFailureFieldStream(v *ECIDMeasurementInitiationFailure) *q4.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementInitiationFailureFieldWithoutReplay(v *ECIDMeasurementInitiationFailure) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationFailureMethodMarshalAPERBudget(v *ECIDMeasurementInitiationFailure, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeECIDMeasurementInitiationFailureMethodMarshalAPERChanged(v *ECIDMeasurementInitiationFailure, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeECIDMeasurementInitiationFailureMethodMarshalAPERChangedValue(v *ECIDMeasurementInitiationFailure, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeECIDMeasurementInitiationFailureMethodMarshalAPERFreshValue(v *ECIDMeasurementInitiationFailure, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeECIDMeasurementInitiationFailureMethodMarshalAPERLegacy(v *ECIDMeasurementInitiationFailure) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeECIDMeasurementInitiationFailureMethodMarshalAPERPlanned(v *ECIDMeasurementInitiationFailure, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeECIDMeasurementInitiationFailureMethodMarshalAPERTo(v *ECIDMeasurementInitiationFailure, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementInitiationFailureMethodUnmarshalAPERFrom(v *ECIDMeasurementInitiationFailure, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementInitiationFailureMethodUnmarshalAPERLegacy(v *ECIDMeasurementInitiationFailure, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeECIDMeasurementInitiationFailureMethodUnmarshalAPERWithOptions(v *ECIDMeasurementInitiationFailure, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeECIDMeasurementInitiationFailureValueCodecFieldCapture(v *ECIDMeasurementInitiationFailureValueCodec) *func(ECIDMeasurementInitiationFailure, q4.DecodeState) (ECIDMeasurementInitiationFailure, q4.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementInitiationFailureValueCodecFieldCompare(v *ECIDMeasurementInitiationFailureValueCodec) *func(ECIDMeasurementInitiationFailure, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementInitiationFailureValueCodecFieldContext(v *ECIDMeasurementInitiationFailureValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementInitiationFailureValueCodecFieldDecode(v *ECIDMeasurementInitiationFailureValueCodec) *func([]byte, q4.DecodeState) (ECIDMeasurementInitiationFailure, error) {
	return &v.decode
}
func BridgeECIDMeasurementInitiationFailureValueCodecFieldEncode(v *ECIDMeasurementInitiationFailureValueCodec) *func(ECIDMeasurementInitiationFailure, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementInitiationFailureValueCodecFieldPath(v *ECIDMeasurementInitiationFailureValueCodec) *q4.Path {
	return &v.path
}
func BridgeECIDMeasurementInitiationFailureValueCodecMethodEncodeBudget(v ECIDMeasurementInitiationFailureValueCodec, a0 ECIDMeasurementInitiationFailure, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeECIDMeasurementInitiationFailureValueCodecMethodEncodeChanged(v ECIDMeasurementInitiationFailureValueCodec, a0 ECIDMeasurementInitiationFailure, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeErrorIndicationAPERValueFieldContext(v *ErrorIndicationAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeErrorIndicationAPERValueFieldReceived(v *ErrorIndicationAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeErrorIndicationAPERValueFieldReplay(v *ErrorIndicationAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeErrorIndicationAPERValueFieldWithoutReplay(v *ErrorIndicationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeErrorIndicationFieldExtCount(v *ErrorIndication) *int64              { return &v.extCount }
func BridgeErrorIndicationFieldExtData(v *ErrorIndication) *[][]byte            { return &v.extData }
func BridgeErrorIndicationFieldExtOrigin(v *ErrorIndication) *[]q4.OpaqueOrigin { return &v.extOrigin }
func BridgeErrorIndicationFieldExtPresent(v *ErrorIndication) *[]bool           { return &v.extPresent }
func BridgeErrorIndicationFieldExtWire(v *ErrorIndication) *[]q4.WireSpan       { return &v.extWire }
func BridgeErrorIndicationFieldPerExtPadding(v *ErrorIndication) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeErrorIndicationFieldPerPadding(v *ErrorIndication) *q4.FinalPadding { return &v.perPadding }
func BridgeErrorIndicationFieldProtocolIEsIndef(v *ErrorIndication) *bool      { return &v.protocolIEsIndef }
func BridgeErrorIndicationFieldReceived(v *ErrorIndication) *bool              { return &v.received }
func BridgeErrorIndicationFieldReceivedBytes(v *ErrorIndication) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeErrorIndicationFieldReplay(v *ErrorIndication) *q4.Snapshot { return &v.replay }
func BridgeErrorIndicationFieldStream(v *ErrorIndication) *q4.WireSpan { return &v.stream }
func BridgeErrorIndicationFieldWithoutReplay(v *ErrorIndication) *bool { return &v.withoutReplay }
func BridgeErrorIndicationMethodMarshalAPERBudget(v *ErrorIndication, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeErrorIndicationMethodMarshalAPERChanged(v *ErrorIndication, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeErrorIndicationMethodMarshalAPERChangedValue(v *ErrorIndication, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeErrorIndicationMethodMarshalAPERFreshValue(v *ErrorIndication, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeErrorIndicationMethodMarshalAPERLegacy(v *ErrorIndication) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeErrorIndicationMethodMarshalAPERPlanned(v *ErrorIndication, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeErrorIndicationMethodMarshalAPERTo(v *ErrorIndication, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeErrorIndicationMethodUnmarshalAPERFrom(v *ErrorIndication, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeErrorIndicationMethodUnmarshalAPERLegacy(v *ErrorIndication, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeErrorIndicationMethodUnmarshalAPERWithOptions(v *ErrorIndication, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeErrorIndicationValueCodecFieldCapture(v *ErrorIndicationValueCodec) *func(ErrorIndication, q4.DecodeState) (ErrorIndication, q4.Snapshot) {
	return &v.capture
}
func BridgeErrorIndicationValueCodecFieldCompare(v *ErrorIndicationValueCodec) *func(ErrorIndication, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeErrorIndicationValueCodecFieldContext(v *ErrorIndicationValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeErrorIndicationValueCodecFieldDecode(v *ErrorIndicationValueCodec) *func([]byte, q4.DecodeState) (ErrorIndication, error) {
	return &v.decode
}
func BridgeErrorIndicationValueCodecFieldEncode(v *ErrorIndicationValueCodec) *func(ErrorIndication, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeErrorIndicationValueCodecFieldPath(v *ErrorIndicationValueCodec) *q4.Path { return &v.path }
func BridgeErrorIndicationValueCodecMethodEncodeBudget(v ErrorIndicationValueCodec, a0 ErrorIndication, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeErrorIndicationValueCodecMethodEncodeChanged(v ErrorIndicationValueCodec, a0 ErrorIndication, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeUTDOAInformationUpdateIEFieldFieldReceived(v *UTDOAInformationUpdateIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeUTDOAInformationUpdateIEFieldFieldReplay(v *UTDOAInformationUpdateIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationUpdateIEFieldFieldStream(v *UTDOAInformationUpdateIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeUTDOAInformationUpdateIEFieldFieldWithoutReplay(v *UTDOAInformationUpdateIEField) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationUpdateIEFieldMethodMarshalAPERTo(v *UTDOAInformationUpdateIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeUTDOAInformationUpdateIEFieldMethodUnmarshalAPERFrom(v *UTDOAInformationUpdateIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeUTDOAInformationUpdateIETableMethodInfoULConfiguration(v UTDOAInformationUpdateIETable) q5.FieldInfo {
	return v.infoULConfiguration()
}
func BridgeUTDOAInformationUpdateIEValueFieldId(v *UTDOAInformationUpdateIEValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeUTDOAInformationUpdateIEValueFieldIsOpaque(v *UTDOAInformationUpdateIEValue) *bool {
	return &v.isOpaque
}
func BridgeUTDOAInformationUpdateIEValueFieldOpaque(v *UTDOAInformationUpdateIEValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeUTDOAInformationUpdateIEValueFieldReceived(v *UTDOAInformationUpdateIEValue) *q4.WireSpan {
	return &v.received
}
func BridgeUTDOAInformationUpdateIEValueFieldReplay(v *UTDOAInformationUpdateIEValue) *q4.Snapshot {
	return &v.replay
}
func BridgeUTDOAInformationUpdateIEValueFieldRowULConfiguration(v *UTDOAInformationUpdateIEValue) **q11.ULConfiguration {
	return &v.rowULConfiguration
}
func BridgeUTDOAInformationUpdateIEValueFieldWithoutReplay(v *UTDOAInformationUpdateIEValue) *bool {
	return &v.withoutReplay
}
func BridgeUTDOAInformationUpdateIEValueMethodCaptureFraming(v UTDOAInformationUpdateIEValue) uint64 {
	return v.captureFraming()
}
func BridgeUTDOAInformationUpdateIEValueMethodCaptureSemantics(v UTDOAInformationUpdateIEValue, a0 q4.SemanticCapture) UTDOAInformationUpdateIEValue {
	return v.captureSemantics(a0)
}
func BridgeUTDOAInformationUpdateIEValueMethodCaptureSnapshot(v UTDOAInformationUpdateIEValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeUTDOAInformationUpdateIEValueMethodCompareSemantics(v UTDOAInformationUpdateIEValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeUTDOAInformationUpdateIEValueMethodDecode(v UTDOAInformationUpdateIEValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (UTDOAInformationUpdateIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeUTDOAInformationUpdateIEValueMethodEncode(v UTDOAInformationUpdateIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeUTDOAInformationUpdateIEValueMethodEncodeFresh(v UTDOAInformationUpdateIEValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeUTDOAInformationUpdateIEValueMethodMatchesID(v UTDOAInformationUpdateIEValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeUTDOAInformationUpdateIEValueMethodReason(v UTDOAInformationUpdateIEValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeUTDOAInformationUpdateIEValueMethodRule(v UTDOAInformationUpdateIEValue) q4.SourceRule {
	return v.rule()
}
func BridgeUTDOAInformationUpdateULConfigurationIEBindingFieldCodec(v *UTDOAInformationUpdateULConfigurationIEBinding) *q11.ULConfigurationValueCodec {
	return &v.codec
}
func BridgeUTDOAInformationUpdateULConfigurationIEBindingFieldGet(v *UTDOAInformationUpdateULConfigurationIEBinding) *func(*UTDOAInformationUpdateIEValue) (*q11.ULConfiguration, bool) {
	return &v.get
}
func BridgeUTDOAInformationUpdateULConfigurationIEBindingFieldInfo(v *UTDOAInformationUpdateULConfigurationIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeUTDOAInformationUpdateULConfigurationIEBindingFieldInject(v *UTDOAInformationUpdateULConfigurationIEBinding) *func(q11.ULConfiguration) UTDOAInformationUpdateIEValue {
	return &v.inject
}
