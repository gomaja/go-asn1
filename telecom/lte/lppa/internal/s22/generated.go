// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s22 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s22

import (
	q6 "fmt"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q13 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s13"
	q16 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s17"
	q15 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s18"
	q11 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s20"
	q17 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s21"
	q7 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// ECIDMeasurementInitiationResponseIEContainer is the concrete ProtocolIEContainer[ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseIEContainer []ECIDMeasurementInitiationResponseIEField

// ECIDMeasurementInitiationResponseIEField is the concrete ProtocolIEField[ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         ECIDMeasurementInitiationResponseIEValue

	received q4.CompletePadding
}

func (v ECIDMeasurementInitiationResponseIEField) WithoutReplay() ECIDMeasurementInitiationResponseIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ECIDMeasurementInitiationResponseIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ECIDMeasurementInitiationResponseIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
func (v *ECIDMeasurementInitiationResponseIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementInitiationResponseIEField{}
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
	var zero ECIDMeasurementInitiationResponseIEValue

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
func BridgeECIDMeasurementInitiationResponseIEValueCaptureLPPaProtocolIEContainer(v *ECIDMeasurementInitiationResponseIEContainer, s *q4.SemanticCapture) {
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
func BridgeECIDMeasurementInitiationResponseIEValueCompareLPPaProtocolIEContainer(v *ECIDMeasurementInitiationResponseIEContainer, s *q4.SemanticComparison) {
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
		s.End(f, q4.Snapshot{}, false)
	}
}

// ECIDMeasurementInitiationResponseMeasurementIDIEBinding is the concrete IEBinding[MeasurementID, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseMeasurementIDIEBinding struct {
	info   q5.FieldInfo
	codec  q5.MeasurementIDValueCodec
	inject func(q5.MeasurementID,

	) ECIDMeasurementInitiationResponseIEValue

	get func(*ECIDMeasurementInitiationResponseIEValue,

	) (*q5.MeasurementID,

		bool)
}

func (b ECIDMeasurementInitiationResponseMeasurementIDIEBinding) Info() q5.FieldInfo { return b.info }
func (b ECIDMeasurementInitiationResponseMeasurementIDIEBinding) Codec() q5.MeasurementIDValueCodec {
	return b.codec
}
func (b ECIDMeasurementInitiationResponseMeasurementIDIEBinding) New(value q5.MeasurementID,

) (ECIDMeasurementInitiationResponseIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q5.BridgeMeasurementIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementInitiationResponseMeasurementIDIEBinding) Get(field *ECIDMeasurementInitiationResponseIEField) (*q5.MeasurementID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding is the concrete IEBinding[ECIDMeasurementResult, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding struct {
	info   q5.FieldInfo
	codec  q9.ECIDMeasurementResultValueCodec
	inject func(q9.ECIDMeasurementResult,

	) ECIDMeasurementInitiationResponseIEValue

	get func(*ECIDMeasurementInitiationResponseIEValue,

	) (*q9.ECIDMeasurementResult,

		bool)
}

func (b ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding) Info() q5.FieldInfo {
	return b.info
}
func (b ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding) Codec() q9.ECIDMeasurementResultValueCodec {
	return b.codec
}
func (b ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding) New(value q9.ECIDMeasurementResult,

) (ECIDMeasurementInitiationResponseIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q9.BridgeECIDMeasurementResultValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding) Get(field *ECIDMeasurementInitiationResponseIEField) (*q9.ECIDMeasurementResult,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding is the concrete IEBinding[CriticalityDiagnostics, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding struct {
	info   q5.FieldInfo
	codec  q10.CriticalityDiagnosticsValueCodec
	inject func(q10.CriticalityDiagnostics,

	) ECIDMeasurementInitiationResponseIEValue

	get func(*ECIDMeasurementInitiationResponseIEValue,

	) (*q10.CriticalityDiagnostics,

		bool)
}

func (b ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding) Info() q5.FieldInfo {
	return b.info
}
func (b ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding) Codec() q10.CriticalityDiagnosticsValueCodec {
	return b.codec
}
func (b ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding) New(value q10.CriticalityDiagnostics,

) (ECIDMeasurementInitiationResponseIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q10.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding) Get(field *ECIDMeasurementInitiationResponseIEField) (*q10.CriticalityDiagnostics,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationResponseCellPortionIDIEBinding is the concrete IEBinding[CellPortionID, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseCellPortionIDIEBinding struct {
	info   q5.FieldInfo
	codec  q5.CellPortionIDValueCodec
	inject func(q5.CellPortionID,

	) ECIDMeasurementInitiationResponseIEValue

	get func(*ECIDMeasurementInitiationResponseIEValue,

	) (*q5.CellPortionID,

		bool)
}

func (b ECIDMeasurementInitiationResponseCellPortionIDIEBinding) Info() q5.FieldInfo { return b.info }
func (b ECIDMeasurementInitiationResponseCellPortionIDIEBinding) Codec() q5.CellPortionIDValueCodec {
	return b.codec
}
func (b ECIDMeasurementInitiationResponseCellPortionIDIEBinding) New(value q5.CellPortionID,

) (ECIDMeasurementInitiationResponseIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q5.BridgeCellPortionIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementInitiationResponseCellPortionIDIEBinding) Get(field *ECIDMeasurementInitiationResponseIEField) (*q5.CellPortionID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding is the concrete IEBinding[InterRATMeasurementResult, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding struct {
	info   q5.FieldInfo
	codec  q11.InterRATMeasurementResultValueCodec
	inject func(q11.InterRATMeasurementResult,

	) ECIDMeasurementInitiationResponseIEValue

	get func(*ECIDMeasurementInitiationResponseIEValue,

	) (*q11.InterRATMeasurementResult,

		bool)
}

func (b ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding) Info() q5.FieldInfo {
	return b.info
}
func (b ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding) Codec() q11.InterRATMeasurementResultValueCodec {
	return b.codec
}
func (b ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding) New(value q11.InterRATMeasurementResult,

) (ECIDMeasurementInitiationResponseIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q11.BridgeInterRATMeasurementResultValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding) Get(field *ECIDMeasurementInitiationResponseIEField) (*q11.InterRATMeasurementResult,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding is the concrete IEBinding[WLANMeasurementResult, ECIDMeasurementInitiationResponseIEValue].
type ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding struct {
	info   q5.FieldInfo
	codec  WLANMeasurementResultValueCodec
	inject func(WLANMeasurementResult,

	) ECIDMeasurementInitiationResponseIEValue

	get func(*ECIDMeasurementInitiationResponseIEValue,

	) (*WLANMeasurementResult,

		bool)
}

func (b ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding) Info() q5.FieldInfo {
	return b.info
}
func (b ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding) Codec() WLANMeasurementResultValueCodec {
	return b.codec
}
func (b ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding) New(value WLANMeasurementResult,

) (ECIDMeasurementInitiationResponseIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationResponseIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding) Get(field *ECIDMeasurementInitiationResponseIEField) (*WLANMeasurementResult,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// WLANMeasurementResultValueCodec is the concrete ValueCodec[WLANMeasurementResult].
type WLANMeasurementResultValueCodec struct {
	context q5.BridgeCodecContext
	capture func(WLANMeasurementResult, q4.DecodeState,

	) (WLANMeasurementResult, q4.Snapshot,

	)
	compare func(WLANMeasurementResult, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (WLANMeasurementResult,

		error)
	encode func(WLANMeasurementResult,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c WLANMeasurementResultValueCodec) New(value WLANMeasurementResult,

) (WLANMeasurementResultAPERValue, error) {
	if c.encode == nil {
		return WLANMeasurementResultAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return WLANMeasurementResultAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANMeasurementResultAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return WLANMeasurementResultAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c WLANMeasurementResultValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (WLANMeasurementResultAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANMeasurementResultAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return WLANMeasurementResultAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANMeasurementResultAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return WLANMeasurementResultAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return WLANMeasurementResultAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c WLANMeasurementResultValueCodec) EncodeAPER(value WLANMeasurementResultAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c WLANMeasurementResultValueCodec) encodeBudget(value WLANMeasurementResult,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANMeasurementResultValueCodec) encodeChanged(value WLANMeasurementResult,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// ECIDMeasurementInitiationResponseValueCodec is the concrete ValueCodec[ECIDMeasurementInitiationResponse].
type ECIDMeasurementInitiationResponseValueCodec struct {
	context q5.BridgeCodecContext
	capture func(ECIDMeasurementInitiationResponse, q4.DecodeState,

	) (ECIDMeasurementInitiationResponse, q4.Snapshot,

	)
	compare func(ECIDMeasurementInitiationResponse, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (ECIDMeasurementInitiationResponse,

		error)
	encode func(ECIDMeasurementInitiationResponse,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c ECIDMeasurementInitiationResponseValueCodec) New(value ECIDMeasurementInitiationResponse,

) (ECIDMeasurementInitiationResponseAPERValue, error) {
	if c.encode == nil {
		return ECIDMeasurementInitiationResponseAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementInitiationResponseAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ECIDMeasurementInitiationResponseAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementInitiationResponseAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c ECIDMeasurementInitiationResponseValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (ECIDMeasurementInitiationResponseAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ECIDMeasurementInitiationResponseAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return ECIDMeasurementInitiationResponseAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ECIDMeasurementInitiationResponseAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return ECIDMeasurementInitiationResponseAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return ECIDMeasurementInitiationResponseAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ECIDMeasurementInitiationResponseValueCodec) EncodeAPER(value ECIDMeasurementInitiationResponseAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c ECIDMeasurementInitiationResponseValueCodec) encodeBudget(value ECIDMeasurementInitiationResponse,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ECIDMeasurementInitiationResponseValueCodec) encodeChanged(value ECIDMeasurementInitiationResponse,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// WLANMeasurementResultItemValueCodec is the concrete ValueCodec[WLANMeasurementResultItem].
type WLANMeasurementResultItemValueCodec struct {
	context q5.BridgeCodecContext
	capture func(WLANMeasurementResultItem, q4.DecodeState,

	) (WLANMeasurementResultItem, q4.Snapshot,

	)
	compare func(WLANMeasurementResultItem, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (WLANMeasurementResultItem,

		error)
	encode func(WLANMeasurementResultItem,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c WLANMeasurementResultItemValueCodec) New(value WLANMeasurementResultItem,

) (WLANMeasurementResultItemAPERValue, error) {
	if c.encode == nil {
		return WLANMeasurementResultItemAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return WLANMeasurementResultItemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return WLANMeasurementResultItemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return WLANMeasurementResultItemAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c WLANMeasurementResultItemValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (WLANMeasurementResultItemAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return WLANMeasurementResultItemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return WLANMeasurementResultItemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return WLANMeasurementResultItemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return WLANMeasurementResultItemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return WLANMeasurementResultItemAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c WLANMeasurementResultItemValueCodec) EncodeAPER(value WLANMeasurementResultItemAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c WLANMeasurementResultItemValueCodec) encodeBudget(value WLANMeasurementResultItem,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c WLANMeasurementResultItemValueCodec) encodeChanged(value WLANMeasurementResultItem,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}
func BridgeECIDMeasurementInitiationResponseIEValueCaptureLPPaProtocolIEField(v *ECIDMeasurementInitiationResponseIEField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(v.Value.captureFraming())
	v.Value = v.Value.captureSemantics(*s)
	s.Child(v.Value.captureSnapshot())
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeECIDMeasurementInitiationResponseIEValueCompareLPPaProtocolIEField(v *ECIDMeasurementInitiationResponseIEField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q12.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q12.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// WLANMeasurementResultAPERValue is the concrete APERValue[WLANMeasurementResult].
type WLANMeasurementResultAPERValue struct {
	context q5.BridgeCodecContext
	Value   WLANMeasurementResult

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v WLANMeasurementResultAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v WLANMeasurementResultAPERValue) WithoutReplay() WLANMeasurementResultAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// ECIDMeasurementInitiationResponseAPERValue is the concrete APERValue[ECIDMeasurementInitiationResponse].
type ECIDMeasurementInitiationResponseAPERValue struct {
	context q5.BridgeCodecContext
	Value   ECIDMeasurementInitiationResponse

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v ECIDMeasurementInitiationResponseAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v ECIDMeasurementInitiationResponseAPERValue) WithoutReplay() ECIDMeasurementInitiationResponseAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// WLANMeasurementResultItemAPERValue is the concrete APERValue[WLANMeasurementResultItem].
type WLANMeasurementResultItemAPERValue struct {
	context q5.BridgeCodecContext
	Value   WLANMeasurementResultItem

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v WLANMeasurementResultItemAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v WLANMeasurementResultItemAPERValue) WithoutReplay() WLANMeasurementResultItemAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

type WLANMeasurementResult = []WLANMeasurementResultItem

// WLANMeasurementResultItem represents the ASN.1 type WLANMeasurementResult-Item (SEQUENCE).
type WLANMeasurementResultItem struct {
	replay               q4.Snapshot
	stream               q4.WireSpan
	withoutReplay        bool
	received             bool
	receivedBytes        q4.WireSpan
	WLANRSSI             q5.WLANRSSI                                     `asn1:"tag:0,context,implicit"`
	SSID                 *q5.SSID                                        `asn1:"tag:1,context,implicit,optional" json:"SSID,omitempty"`
	BSSID                *q5.BSSID                                       `asn1:"tag:2,context,implicit,optional" json:"BSSID,omitempty"`
	HESSID               *q5.HESSID                                      `asn1:"tag:3,context,implicit,optional" json:"HESSID,omitempty"`
	OperatingClass       *q5.WLANOperatingClass                          `asn1:"tag:4,context,implicit,optional" json:"OperatingClass,omitempty"`
	CountryCode          *q5.WLANCountryCode                             `asn1:"tag:5,context,implicit,optional" json:"CountryCode,omitempty"`
	WLANChannelList      q5.WLANChannelList                              `asn1:"tag:6,context,implicit,optional" json:"WLANChannelList,omitzero"`
	wLANChannelListIndef bool                                            `asn1:"-" json:"-"`
	WLANBand             *q5.WLANBand                                    `asn1:"tag:7,context,implicit,optional" json:"WLANBand,omitempty"`
	IEExtensions         q13.WLANMeasurementResultItemExtIEsExtContainer `asn1:"tag:8,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef    bool                                            `asn1:"-" json:"-"`
	extCount             int64                                           `asn1:"-" json:"-"`
	extPresent           []bool                                          `asn1:"-" json:"-"`
	extData              [][]byte                                        `asn1:"-" json:"-"`
	perPadding           q4.FinalPadding                                 `asn1:"-" json:"-"`
	perExtPadding        []q4.CompletePadding                            `asn1:"-" json:"-"`
	extOrigin            []q4.OpaqueOrigin
	extWire              []q4.WireSpan
}
type BridgeAsn1cAPERWLANMeasurementResultListValue struct{ Value WLANMeasurementResult }

// WLANMeasurementResultComplete carries a complete WLANMeasurementResult encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type WLANMeasurementResultComplete struct {
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         WLANMeasurementResult
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *WLANMeasurementResultComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := BridgeMarshalAPERWLANMeasurementResultTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes WLANMeasurementResult from APER format.
func (v *WLANMeasurementResultComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes WLANMeasurementResult with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *WLANMeasurementResultComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "WLANMeasurementResult")
	}
	value, err := BridgeUnmarshalAPERWLANMeasurementResultFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "WLANMeasurementResult")
	}
	padding, err := q4.CaptureFinalBits(bb, "WLANMeasurementResult")
	if err != nil {
		return q7.WrapDecodePath(err, "WLANMeasurementResult")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERWLANMeasurementResultTo appends a WLANMeasurementResult list to bb.
func BridgeMarshalAPERWLANMeasurementResultTo(list WLANMeasurementResult, bb *q4.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERWLANMeasurementResultListValue{Value: list}
	if err := q4.EncodeCollection(bb, int64(len(v.Value)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_value < 0 || fragmentOffset_value > int64(len(v.Value)) || fragmentLength_value < 0 || fragmentLength_value > int64(len(v.Value[fragmentOffset_value:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.Value[fragmentOffset_value : fragmentOffset_value+fragmentLength_value] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding value element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERWLANMeasurementResultFrom decodes a WLANMeasurementResult list from bb.
func BridgeUnmarshalAPERWLANMeasurementResultFrom(bb *q4.BitBuffer) (WLANMeasurementResult, error) {
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
func BridgeUnmarshalAPERWLANMeasurementResultInto(v *BridgeAsn1cAPERWLANMeasurementResultListValue, bb *q4.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(WLANMeasurementResult, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem WLANMeasurementResultItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("Value[%d]", fragmentOffset_value+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := q4.AppendValues(bb, v.Value, elem); err != nil {
				return err
			} else {
				v.Value = next
			}
		}
		return nil
	})
	if errCollection_value != nil {
		return q7.WrapDecodePath(errCollection_value, "Value")
	}
	bb.LeaveComponent(toleranceMark_value)
	return nil
}

// MarshalAPER encodes WLANMeasurementResultItem to APER format.
func (v *WLANMeasurementResultItem) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *WLANMeasurementResultItem) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	// Preamble bitmap for optional root fields
	if err := q4.EncodeBoolean(bb, v.SSID != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.BSSID != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.HESSID != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.OperatingClass != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.CountryCode != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.WLANChannelList != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.WLANBand != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q4.EncodeIntegerBigBoundsAligned(bb, v.WLANRSSI, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound6, true); err != nil {
		return q6.Errorf("encoding wLAN-RSSI: %w", err)
	}
	if v.SSID != nil {
		if err := q4.EncodeOctetStringAligned(bb, []byte(*v.SSID), 1, 32, true); err != nil {
			return q6.Errorf("encoding sSID: %w", err)
		}
	}
	if v.BSSID != nil {
		if err := q4.EncodeOctetStringAligned(bb, []byte(*v.BSSID), 6, 6, true); err != nil {
			return q6.Errorf("encoding bSSID: %w", err)
		}
	}
	if v.HESSID != nil {
		if err := q4.EncodeOctetStringAligned(bb, []byte(*v.HESSID), 6, 6, true); err != nil {
			return q6.Errorf("encoding hESSID: %w", err)
		}
	}
	if v.OperatingClass != nil {
		if err := q4.EncodeIntegerAligned(bb, int64(*v.OperatingClass), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(255), false); err != nil {
			return q6.Errorf("encoding operatingClass: %w", err)
		}
	}
	if v.CountryCode != nil {
		if err := q4.EncodeEnumeratedAligned(bb, int64(*v.CountryCode), 4, true); err != nil {
			return q6.Errorf("encoding countryCode: %w", err)
		}
	}
	if v.WLANChannelList != nil {
		if err := q4.EncodeCollection(bb, int64(len(v.WLANChannelList)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_wlanchannellist, fragmentLength_wlanchannellist int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_wlanchannellist < 0 || fragmentOffset_wlanchannellist > int64(len(v.WLANChannelList)) || fragmentLength_wlanchannellist < 0 || fragmentLength_wlanchannellist > int64(len(v.WLANChannelList[fragmentOffset_wlanchannellist:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.WLANChannelList[fragmentOffset_wlanchannellist : fragmentOffset_wlanchannellist+fragmentLength_wlanchannellist] {
				if err := q4.EncodeIntegerAligned(bb, int64(elem), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(255), false); err != nil {
					return q6.Errorf("encoding wLANChannelList element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return q6.Errorf("encoding wLANChannelList: %w", err)
		}
	}
	if v.WLANBand != nil {
		if err := q4.EncodeEnumeratedAligned(bb, int64(*v.WLANBand), 2, true); err != nil {
			return q6.Errorf("encoding wLANBand: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := q4.EncodeCollection(bb, int64(len(v.IEExtensions)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q13.BridgeWLANMeasurementResultItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return q6.Errorf("encoding iE-Extensions element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return q6.Errorf("encoding iE-Extensions: %w", err)
		}
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

// UnmarshalAPER decodes WLANMeasurementResultItem from APER format.
func (v *WLANMeasurementResultItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes WLANMeasurementResultItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *WLANMeasurementResultItem) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "WLANMeasurementResultItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "WLANMeasurementResultItem")
	}
	padding, err := q4.CaptureFinalBits(bb, "WLANMeasurementResultItem")
	if err != nil {
		return q7.WrapDecodePath(err, "WLANMeasurementResultItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *WLANMeasurementResultItem) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WLANMeasurementResultItem{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ssid, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_bssid, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_hessid, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_operatingclass, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_countrycode, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_wlanchannellist, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_wlanband, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_wlanrssi, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound6, true)
	if err != nil {
		return q7.WrapDecodePath(err, "WLANRSSI")
	}
	v.WLANRSSI = val_wlanrssi
	if opt_ssid {
		val_ssid, err := q4.DecodeOctetStringAligned(bb, 1, 32, true)
		if err != nil {
			return q7.WrapDecodePath(err, "SSID")
		}
		tmp_ssid := q5.SSID(val_ssid)
		if err := q4.ChargeValue(bb, tmp_ssid); err != nil {
			return err
		}
		v.SSID = &tmp_ssid
	}
	if opt_bssid {
		val_bssid, err := q4.DecodeOctetStringAligned(bb, 6, 6, true)
		if err != nil {
			return q7.WrapDecodePath(err, "BSSID")
		}
		tmp_bssid := q5.BSSID(val_bssid)
		if err := q4.ChargeValue(bb, tmp_bssid); err != nil {
			return err
		}
		v.BSSID = &tmp_bssid
	}
	if opt_hessid {
		val_hessid, err := q4.DecodeOctetStringAligned(bb, 6, 6, true)
		if err != nil {
			return q7.WrapDecodePath(err, "HESSID")
		}
		tmp_hessid := q5.HESSID(val_hessid)
		if err := q4.ChargeValue(bb, tmp_hessid); err != nil {
			return err
		}
		v.HESSID = &tmp_hessid
	}
	if opt_operatingclass {
		val_operatingclass, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(255), false)
		if err != nil {
			return q7.WrapDecodePath(err, "OperatingClass")
		}
		tmp_operatingclass := q5.WLANOperatingClass(val_operatingclass)
		if err := q4.ChargeValue(bb, tmp_operatingclass); err != nil {
			return err
		}
		v.OperatingClass = (*q5.WLANOperatingClass)(bb.OwnInt64(int64(tmp_operatingclass)))
	}
	if opt_countrycode {
		val_countrycode, err := q4.DecodeEnumeratedAligned(bb, 4, true, q4.EnumerationSource{KnownExtensions: 0, Path: "CountryCode"})
		if err != nil {
			return q7.WrapDecodePath(err, "CountryCode")
		}
		tmp_countrycode := q5.WLANCountryCode(val_countrycode)
		if err := q4.ChargeValue(bb, tmp_countrycode); err != nil {
			return err
		}
		v.CountryCode = (*q5.WLANCountryCode)(bb.OwnInt64(int64(tmp_countrycode)))
	}
	if opt_wlanchannellist {
		tmp_wlanchannellist := make(q5.WLANChannelList, 0)
		_, errCollection_wlanchannellist := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 16, HasUpper: true}, true, func(fragmentOffset_wlanchannellist, fragmentLength_wlanchannellist int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_2: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1136
			if fragmentOffset_wlanchannellist < 0 || fragmentLength_wlanchannellist < 0 || fragmentLength_wlanchannellist > int64(^uint(0)>>1) || fragmentOffset_wlanchannellist > int64(^uint(0)>>1)-fragmentLength_wlanchannellist {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_wlanchannellist; i++ {
				val, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(255), false)
				if err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("WLANChannelList[%d]", fragmentOffset_wlanchannellist+i))
				}
				if next, err := q4.AppendValues(bb, tmp_wlanchannellist, q5.WLANChannel(val)); err != nil {
					return err
				} else {
					tmp_wlanchannellist = next
				}
			}
			return nil
		})
		if errCollection_wlanchannellist != nil {
			return q7.WrapDecodePath(errCollection_wlanchannellist, "WLANChannelList")
		}
		v.WLANChannelList = tmp_wlanchannellist
	}
	if opt_wlanband {
		val_wlanband, err := q4.DecodeEnumeratedAligned(bb, 2, true, q4.EnumerationSource{KnownExtensions: 0, Path: "WLANBand"})
		if err != nil {
			return q7.WrapDecodePath(err, "WLANBand")
		}
		tmp_wlanband := q5.WLANBand(val_wlanband)
		if err := q4.ChargeValue(bb, tmp_wlanband); err != nil {
			return err
		}
		v.WLANBand = (*q5.WLANBand)(bb.OwnInt64(int64(tmp_wlanband)))
	}
	if opt_ieextensions {
		tmp_ieextensions := make(q13.WLANMeasurementResultItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q13.WLANMeasurementResultItemExtIEsExtField
				if err := q13.BridgeWLANMeasurementResultItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("IEExtensions[%d]", fragmentOffset_ieextensions+i))
				}
				if next, err := q4.AppendValues(bb, tmp_ieextensions, elem); err != nil {
					return err
				} else {
					tmp_ieextensions = next
				}
			}
			return nil
		})
		if errCollection_ieextensions != nil {
			return q7.WrapDecodePath(errCollection_ieextensions, "IEExtensions")
		}
		v.IEExtensions = tmp_ieextensions
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
				opaque, err := q4.DecodeOpaqueOpenTypeAligned(bb, q4.UnknownSelector, q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5"})
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
	v.
		stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WLANMeasurementResultComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q14.BridgeReceivedFormAt(v.received, v.receivedBytes, "WLANMeasurementResultComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WLANMeasurementResultComplete) WithoutReplay() WLANMeasurementResultComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero WLANMeasurementResultComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WLANMeasurementResultItem) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q14.BridgeReceivedFormAt(v.received, v.receivedBytes, "WLANMeasurementResultItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WLANMeasurementResultItem) WithoutReplay() WLANMeasurementResultItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero WLANMeasurementResultItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *WLANMeasurementResultItem) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *WLANMeasurementResultItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("WLANMeasurementResultItem.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("WLANMeasurementResultItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *WLANMeasurementResultItem) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("WLANMeasurementResultItem.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("WLANMeasurementResultItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *WLANMeasurementResultComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "WLANMeasurementResultComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "WLANMeasurementResultComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaWLANMeasurementResultComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "WLANMeasurementResultComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "WLANMeasurementResultComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "WLANMeasurementResultComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "WLANMeasurementResultComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "WLANMeasurementResultComplete")
}
func (v *WLANMeasurementResultComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *WLANMeasurementResultComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *WLANMeasurementResultComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *WLANMeasurementResultComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *WLANMeasurementResultComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
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
func (v *WLANMeasurementResultItem) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "WLANMeasurementResultItem")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "WLANMeasurementResultItem")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaWLANMeasurementResultItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "WLANMeasurementResultItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "WLANMeasurementResultItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "WLANMeasurementResultItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "WLANMeasurementResultItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "WLANMeasurementResultItem")
}
func (v *WLANMeasurementResultItem) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *WLANMeasurementResultItem) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *WLANMeasurementResultItem) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *WLANMeasurementResultItem) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *WLANMeasurementResultItem) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *WLANMeasurementResultComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "WLANMeasurementResultComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded WLANMeasurementResultComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaWLANMeasurementResultComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = WLANMeasurementResultComplete{}
		return report, q4.OperationError(err, "WLANMeasurementResultComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "WLANMeasurementResultComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *WLANMeasurementResultItem) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "WLANMeasurementResultItem")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded WLANMeasurementResultItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaWLANMeasurementResultItem(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = WLANMeasurementResultItem{}
		return report, q4.OperationError(err, "WLANMeasurementResultItem")
	}
	*v = decoded
	return report, q4.OperationError(nil, "WLANMeasurementResultItem")
}

// MarshalAPERWLANMeasurementResult encodes a complete named list.
func MarshalAPERWLANMeasurementResult(v WLANMeasurementResultComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERWLANMeasurementResult decodes a complete named list.
func UnmarshalAPERWLANMeasurementResult(data []byte, options ...q4.DecodeOption) (WLANMeasurementResultComplete, q4.DecodeReport, error) {
	var v WLANMeasurementResultComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// ECIDMeasurementInitiationResponse represents the ASN.1 type E-CIDMeasurementInitiationResponse (SEQUENCE).
type ECIDMeasurementInitiationResponse struct {
	replay           q4.Snapshot
	stream           q4.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    q4.WireSpan
	ProtocolIEs      ECIDMeasurementInitiationResponseIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                         `asn1:"-" json:"-"`
	extCount         int64                                        `asn1:"-" json:"-"`
	extPresent       []bool                                       `asn1:"-" json:"-"`
	extData          [][]byte                                     `asn1:"-" json:"-"`
	perPadding       q4.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding    []q4.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin        []q4.OpaqueOrigin
	extWire          []q4.WireSpan
}

// MarshalAPER encodes ECIDMeasurementInitiationResponse to APER format.
func (v *ECIDMeasurementInitiationResponse) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ECIDMeasurementInitiationResponse) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ECIDMeasurementInitiationResponse from APER format.
func (v *ECIDMeasurementInitiationResponse) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ECIDMeasurementInitiationResponse with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ECIDMeasurementInitiationResponse) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "ECIDMeasurementInitiationResponse")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "ECIDMeasurementInitiationResponse")
	}
	padding, err := q4.CaptureFinalBits(bb, "ECIDMeasurementInitiationResponse")
	if err != nil {
		return q7.WrapDecodePath(err, "ECIDMeasurementInitiationResponse")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ECIDMeasurementInitiationResponse) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementInitiationResponse{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ECIDMeasurementInitiationResponseIEContainer, 0)
	_, errCollection_protocolies := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ECIDMeasurementInitiationResponseIEField
			if err := elem.unmarshalAPERFrom(bb); err != nil {
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
func (v *ECIDMeasurementInitiationResponse) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ECIDMeasurementInitiationResponse", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ECIDMeasurementInitiationResponse) WithoutReplay() ECIDMeasurementInitiationResponse {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero ECIDMeasurementInitiationResponse
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ECIDMeasurementInitiationResponse) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ECIDMeasurementInitiationResponse) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ECIDMeasurementInitiationResponse.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ECIDMeasurementInitiationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ECIDMeasurementInitiationResponse) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ECIDMeasurementInitiationResponse.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ECIDMeasurementInitiationResponse.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *ECIDMeasurementInitiationResponse) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "ECIDMeasurementInitiationResponse")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "ECIDMeasurementInitiationResponse")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaECIDMeasurementInitiationResponse(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "ECIDMeasurementInitiationResponse")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "ECIDMeasurementInitiationResponse")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "ECIDMeasurementInitiationResponse")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "ECIDMeasurementInitiationResponse")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "ECIDMeasurementInitiationResponse")
}
func (v *ECIDMeasurementInitiationResponse) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ECIDMeasurementInitiationResponse) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ECIDMeasurementInitiationResponse) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *ECIDMeasurementInitiationResponse) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ECIDMeasurementInitiationResponse) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ECIDMeasurementInitiationResponse) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "ECIDMeasurementInitiationResponse")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded ECIDMeasurementInitiationResponse
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaECIDMeasurementInitiationResponse(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = ECIDMeasurementInitiationResponse{}
		return report, q4.OperationError(err, "ECIDMeasurementInitiationResponse")
	}
	*v = decoded
	return report, q4.OperationError(nil, "ECIDMeasurementInitiationResponse")
}

// SuccessfulOutcome represents the ASN.1 type SuccessfulOutcome (SEQUENCE).
type SuccessfulOutcome struct {
	replay            q4.Snapshot
	stream            q4.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     q4.WireSpan
	ProcedureCode     q5.ProcedureCode     `asn1:"tag:0,context,implicit"`
	Criticality       q5.Criticality       `asn1:"tag:1,context,implicit"`
	LppatransactionID q5.LPPATransactionID `asn1:"tag:2,context,implicit"`
	Value             SuccessfulValue      `asn1:"tag:3,context,explicit" asn1c:"raw-preserve"`
	perPadding        q4.CompletePadding   `asn1:"-" json:"-"`
}

// MarshalAPER encodes SuccessfulOutcome to APER format.
func (v *SuccessfulOutcome) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *SuccessfulOutcome) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q7.WrapDecodePath(q6.Errorf("%w: procedure code %d does not match its value selector", q4.ErrInvalidValue, v.ProcedureCode), "SuccessfulOutcome.ProcedureCode")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.ProcedureCode), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(255), false); err != nil {
		return q6.Errorf("encoding procedureCode: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q6.Errorf("encoding criticality: %w", err)
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.LppatransactionID), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(32767), false); err != nil {
		return q6.Errorf("encoding lppatransactionID: %w", err)
	}
	openData_value, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, openData_value); err != nil {
		return q6.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPER decodes SuccessfulOutcome from APER format.
func (v *SuccessfulOutcome) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SuccessfulOutcome with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SuccessfulOutcome) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "SuccessfulOutcome")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "SuccessfulOutcome")
	}
	padding, err := q4.CaptureFinalBits(bb, "SuccessfulOutcome")
	if err != nil {
		return q7.WrapDecodePath(err, "SuccessfulOutcome")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *SuccessfulOutcome) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SuccessfulOutcome{}
	val_procedurecode, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(255), false)
	if err != nil {
		return q7.WrapDecodePath(err, "ProcedureCode")
	}
	v.ProcedureCode = q5.ProcedureCode(val_procedurecode)
	val_criticality, err := q4.DecodeEnumeratedAligned(bb, 3, false, q4.EnumerationSource{KnownExtensions: 0, Path: "Criticality"})
	if err != nil {
		return q7.WrapDecodePath(q6.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Criticality")
	}
	v.Criticality = q5.Criticality(val_criticality)
	val_lppatransactionid, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(32767), false)
	if err != nil {
		return q7.WrapDecodePath(err, "LppatransactionID")
	}
	v.LppatransactionID = q5.LPPATransactionID(val_lppatransactionid)
	opaque_value, err := q4.DecodeOpaqueOpenTypeAligned(bb, q5.SuccessfulReason(v.ProcedureCode), q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.3", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Descriptions", Assignment: "Successful"}})
	if err != nil {
		return q7.WrapDecodePath(q6.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	opaque_value = opaque_value.WithPath("SuccessfulOutcome.Value")
	decoded_value, err := BridgeDecodeSuccessfulValue(v.ProcedureCode, opaque_value)
	if err != nil {
		return q7.WrapDecodePath(q6.Errorf("procedureCode %v: %w", v.ProcedureCode, err), "Value")
	}
	v.Value = decoded_value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage,

		bb)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SuccessfulOutcome) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SuccessfulOutcome", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SuccessfulOutcome) WithoutReplay() SuccessfulOutcome {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero SuccessfulOutcome
	v.perPadding = zero.perPadding
	return v
}
func (v *SuccessfulOutcome) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "SuccessfulOutcome")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "SuccessfulOutcome")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaSuccessfulOutcome(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "SuccessfulOutcome")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "SuccessfulOutcome")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "SuccessfulOutcome")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "SuccessfulOutcome")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "SuccessfulOutcome")
}
func (v *SuccessfulOutcome) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *SuccessfulOutcome) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *SuccessfulOutcome) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *SuccessfulOutcome) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *SuccessfulOutcome) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *SuccessfulOutcome) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "SuccessfulOutcome")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded SuccessfulOutcome
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaSuccessfulOutcome(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = SuccessfulOutcome{}
		return report, q4.OperationError(err, "SuccessfulOutcome")
	}
	*v = decoded
	return report, q4.OperationError(nil, "SuccessfulOutcome")
}

type SuccessfulValue struct {
	code                                  q5.ProcedureCode
	withoutReplay                         bool
	received                              q4.WireSpan
	replay                                q4.Snapshot
	opaque                                *q4.OpaqueOpenType
	isOpaque                              bool
	bodyECIDMeasurementInitiationResponse *ECIDMeasurementInitiationResponse
	bodyOTDOAInformationResponse          *q15.OTDOAInformationResponse
	bodyUTDOAInformationResponse          *q16.UTDOAInformationResponse
}

func (v *SuccessfulValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (v *SuccessfulValue) AsECIDMeasurementInitiationResponse() (*ECIDMeasurementInitiationResponse, bool) {
	if v == nil || v.code != q5.ProcedureCode(2) || v.bodyECIDMeasurementInitiationResponse == nil {
		return nil, false
	}
	return v.bodyECIDMeasurementInitiationResponse, true
}
func (v *SuccessfulValue) AsOTDOAInformationResponse() (*q15.OTDOAInformationResponse, bool) {
	if v == nil || v.code != q5.ProcedureCode(6) || v.bodyOTDOAInformationResponse == nil {
		return nil, false
	}
	return v.bodyOTDOAInformationResponse, true
}
func (v *SuccessfulValue) AsUTDOAInformationResponse() (*q16.UTDOAInformationResponse, bool) {
	if v == nil || v.code != q5.ProcedureCode(7) || v.bodyUTDOAInformationResponse == nil {
		return nil, false
	}
	return v.bodyUTDOAInformationResponse, true
}
func BridgeDecodeSuccessfulValue(code q5.ProcedureCode, raw q4.OpaqueOpenType) (SuccessfulValue, error) {
	v := SuccessfulValue{code: code}
	var scope *q4.BitBuffer
	switch code {
	case 2, 6, 7:
		scope = raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return v, err
		}
		defer scope.LeaveOpenType()
	}
	switch code {
	case q5.ProcedureCode(2):
		var body ECIDMeasurementInitiationResponse
		child := scope
		replayUsage := child.Usage()
		if err := body.unmarshalAPERFrom(child); err != nil {
			return SuccessfulValue{}, q6.Errorf("%s %w", "SuccessfulMessage.value.ECIDMeasurementInitiationResponse:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "ECIDMeasurementInitiationResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		body.perPadding = padding
		body.received = true
		raw.RetainContents(&body.receivedBytes)
		if err := q4.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyECIDMeasurementInitiationResponse = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case q5.ProcedureCode(6):
		var body q15.OTDOAInformationResponse
		child := scope
		replayUsage := child.Usage()
		if err := q15.BridgeOTDOAInformationResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, q6.Errorf("%s %w", "SuccessfulMessage.value.OTDOAInformationResponse:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "OTDOAInformationResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*q15.BridgeOTDOAInformationResponseFieldPerPadding(&body) = padding
		*q15.BridgeOTDOAInformationResponseFieldReceived(&body) = true
		raw.RetainContents(q15.BridgeOTDOAInformationResponseFieldReceivedBytes(&body))
		if err := q4.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyOTDOAInformationResponse = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	case q5.ProcedureCode(7):
		var body q16.UTDOAInformationResponse
		child := scope
		replayUsage := child.Usage()
		if err := q16.BridgeUTDOAInformationResponseMethodUnmarshalAPERFrom(&body, child); err != nil {
			return SuccessfulValue{}, q6.Errorf("%s %w", "SuccessfulMessage.value.UTDOAInformationResponse:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "UTDOAInformationResponse")
		if err != nil {
			return SuccessfulValue{}, err
		}
		*q16.BridgeUTDOAInformationResponseFieldPerPadding(&body) = padding
		*q16.BridgeUTDOAInformationResponseFieldReceived(&body) = true
		raw.RetainContents(q16.BridgeUTDOAInformationResponseFieldReceivedBytes(&body))
		if err := q4.ChargeValue(raw.BudgetBuffer(), body); err != nil {
			return v, err
		}
		v.bodyUTDOAInformationResponse = &body
		raw.RetainContents(&v.received)
		v.received.RecordUsage(replayUsage, child)
	default:
		if err := raw.Observe(q4.UnknownProcedure); err != nil {
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
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v SuccessfulValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
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
	switch v.code {
	case q5.ProcedureCode(2):
		if v.bodyECIDMeasurementInitiationResponse == nil {
			return nil, q6.Errorf("%s value: missing ECIDMeasurementInitiationResponse", "Successful")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return v.bodyECIDMeasurementInitiationResponse.marshalAPERBudget(budget, fresh)
	case q5.ProcedureCode(6):
		if v.bodyOTDOAInformationResponse == nil {
			return nil, q6.Errorf("%s value: missing OTDOAInformationResponse", "Successful")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return q15.BridgeOTDOAInformationResponseMethodMarshalAPERBudget(v.bodyOTDOAInformationResponse, budget, fresh)
	case q5.ProcedureCode(7):
		if v.bodyUTDOAInformationResponse == nil {
			return nil, q6.Errorf("%s value: missing UTDOAInformationResponse", "Successful")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		return q16.BridgeUTDOAInformationResponseMethodMarshalAPERBudget(v.bodyUTDOAInformationResponse, budget, fresh)
	default:
		return nil, q6.Errorf("%s value: unknown code %d without opaque content", "Successful", v.code)
	}
}
func BridgeCaptureLPPaECIDMeasurementInitiationResponse(v *ECIDMeasurementInitiationResponse, s *q4.SemanticCapture) {
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
func BridgeCompareLPPaECIDMeasurementInitiationResponse(v *ECIDMeasurementInitiationResponse, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeECIDMeasurementInitiationResponseIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaECIDMeasurementInitiationResponseIEValue(v *ECIDMeasurementInitiationResponseIEValue, s *q4.SemanticCapture) {
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
		case q5.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowESMLCUEMeasurementID == nil)
				if v.rowESMLCUEMeasurementID != nil {
					q5.BridgeCaptureLPPaMeasurementID(v.rowESMLCUEMeasurementID, s)
				}
				s.End(f, nil, false)
			}
		case q5.ProtocolIEID(6):
			{
				f := s.Begin()
				s.Bool(v.rowENBUEMeasurementID == nil)
				if v.rowENBUEMeasurementID != nil {
					q5.BridgeCaptureLPPaMeasurementID(v.rowENBUEMeasurementID, s)
				}
				s.End(f, nil, false)
			}
		case q5.ProtocolIEID(7):
			{
				f := s.Begin()
				s.Bool(v.rowECIDMeasurementResult == nil)
				if v.rowECIDMeasurementResult != nil {
					q9.BridgeCaptureLPPaECIDMeasurementResult(v.rowECIDMeasurementResult, s)
				}
				s.End(f, nil, false)
			}
		case q5.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					q10.BridgeCaptureLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, nil, false)
			}
		case q5.ProtocolIEID(14):
			{
				f := s.Begin()
				s.Bool(v.rowCellPortionID == nil)
				if v.rowCellPortionID != nil {
					q5.BridgeCaptureLPPaCellPortionID(v.rowCellPortionID, s)
				}
				s.End(f, nil, false)
			}
		case q5.ProtocolIEID(17):
			{
				f := s.Begin()
				s.Bool(v.rowInterRATMeasurementResult == nil)
				if v.rowInterRATMeasurementResult != nil {
					q11.BridgeCaptureLPPaInterRATMeasurementResult(v.rowInterRATMeasurementResult, s)
				}
				s.End(f, nil, false)
			}
		case q5.ProtocolIEID(21):
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
func (v ECIDMeasurementInitiationResponseIEValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v ECIDMeasurementInitiationResponseIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ECIDMeasurementInitiationResponseIEValue) captureSemantics(s q4.SemanticCapture) ECIDMeasurementInitiationResponseIEValue {
	BridgeCaptureLPPaECIDMeasurementInitiationResponseIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaECIDMeasurementInitiationResponseIEValue(v *ECIDMeasurementInitiationResponseIEValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q12.BridgeCompareLPPaProtocolIEID(&v.id, s)
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
		case q5.ProtocolIEID(2):
			{
				f := s.Begin()
				s.Bool(v.rowESMLCUEMeasurementID == nil)
				if v.rowESMLCUEMeasurementID != nil {
					q12.BridgeCompareLPPaMeasurementID(v.rowESMLCUEMeasurementID, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(6):
			{
				f := s.Begin()
				s.Bool(v.rowENBUEMeasurementID == nil)
				if v.rowENBUEMeasurementID != nil {
					q12.BridgeCompareLPPaMeasurementID(v.rowENBUEMeasurementID, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(7):
			{
				f := s.Begin()
				s.Bool(v.rowECIDMeasurementResult == nil)
				if v.rowECIDMeasurementResult != nil {
					q9.BridgeCompareLPPaECIDMeasurementResult(v.rowECIDMeasurementResult, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(1):
			{
				f := s.Begin()
				s.Bool(v.rowCriticalityDiagnostics == nil)
				if v.rowCriticalityDiagnostics != nil {
					q10.BridgeCompareLPPaCriticalityDiagnostics(v.rowCriticalityDiagnostics, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(14):
			{
				f := s.Begin()
				s.Bool(v.rowCellPortionID == nil)
				if v.rowCellPortionID != nil {
					q12.BridgeCompareLPPaCellPortionID(v.rowCellPortionID, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(17):
			{
				f := s.Begin()
				s.Bool(v.rowInterRATMeasurementResult == nil)
				if v.rowInterRATMeasurementResult != nil {
					q11.BridgeCompareLPPaInterRATMeasurementResult(v.rowInterRATMeasurementResult, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(21):
			{
				f := s.Begin()
				s.Bool(v.rowWLANMeasurementResult == nil)
				if v.rowWLANMeasurementResult != nil {
					BridgeCompareLPPaWLANMeasurementResult(v.rowWLANMeasurementResult, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v ECIDMeasurementInitiationResponseIEValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaECIDMeasurementInitiationResponseIEValue(&v, &s)
	return s
}
func (v ECIDMeasurementInitiationResponseIEValue) WithoutReplay() ECIDMeasurementInitiationResponseIEValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCaptureLPPaSuccessfulOutcome(v *SuccessfulOutcome, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q5.BridgeCaptureLPPaProcedureCode(&v.ProcedureCode, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	q5.BridgeCaptureLPPaLPPATransactionID(&v.LppatransactionID, s)
	s.OpenBytes(v.Value.captureFraming())
	BridgeCaptureLPPaSuccessfulValue(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaSuccessfulOutcome(v *SuccessfulOutcome, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q12.BridgeCompareLPPaProcedureCode(&v.ProcedureCode, s)
	q12.BridgeCompareLPPaCriticality(&v.Criticality, s)
	q12.BridgeCompareLPPaLPPATransactionID(&v.LppatransactionID, s)
	BridgeCompareLPPaSuccessfulValue(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaSuccessfulValue(v *SuccessfulValue, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.received)
	q5.BridgeCaptureLPPaProcedureCode(&v.code, s)
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
		case q5.ProcedureCode(2):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementInitiationResponse == nil)
				if v.bodyECIDMeasurementInitiationResponse != nil {
					BridgeCaptureLPPaECIDMeasurementInitiationResponse(v.bodyECIDMeasurementInitiationResponse, s)
				}
				s.End(f, nil, false)
			}
		case q5.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyOTDOAInformationResponse == nil)
				if v.bodyOTDOAInformationResponse != nil {
					q15.BridgeCaptureLPPaOTDOAInformationResponse(v.bodyOTDOAInformationResponse, s)
				}
				s.End(f, nil, false)
			}
		case q5.ProcedureCode(7):
			{
				f := s.Begin()
				s.Bool(v.bodyUTDOAInformationResponse == nil)
				if v.bodyUTDOAInformationResponse != nil {
					q16.BridgeCaptureLPPaUTDOAInformationResponse(v.bodyUTDOAInformationResponse, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v SuccessfulValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v SuccessfulValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v SuccessfulValue) captureSemantics(s q4.SemanticCapture) SuccessfulValue {
	BridgeCaptureLPPaSuccessfulValue(&v, &s)
	return v
}
func BridgeCompareLPPaSuccessfulValue(v *SuccessfulValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q12.BridgeCompareLPPaProcedureCode(&v.code, s)
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
		switch v.code {
		case q5.ProcedureCode(2):
			{
				f := s.Begin()
				s.Bool(v.bodyECIDMeasurementInitiationResponse == nil)
				if v.bodyECIDMeasurementInitiationResponse != nil {
					BridgeCompareLPPaECIDMeasurementInitiationResponse(v.bodyECIDMeasurementInitiationResponse, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProcedureCode(6):
			{
				f := s.Begin()
				s.Bool(v.bodyOTDOAInformationResponse == nil)
				if v.bodyOTDOAInformationResponse != nil {
					q15.BridgeCompareLPPaOTDOAInformationResponse(v.bodyOTDOAInformationResponse, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProcedureCode(7):
			{
				f := s.Begin()
				s.Bool(v.bodyUTDOAInformationResponse == nil)
				if v.bodyUTDOAInformationResponse != nil {
					q16.BridgeCompareLPPaUTDOAInformationResponse(v.bodyUTDOAInformationResponse, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v SuccessfulValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaSuccessfulValue(&v, &s)
	return s
}
func (v SuccessfulValue) WithoutReplay() SuccessfulValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCaptureLPPaWLANMeasurementResult(v *WLANMeasurementResult, s *q4.SemanticCapture) {
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
func BridgeCompareLPPaWLANMeasurementResult(v *WLANMeasurementResult, s *q4.SemanticComparison) {
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
		s.End(f, q4.Snapshot{}, false)
	}
	s.End(f, q4.Snapshot{}, false)
}
func BridgeCaptureLPPaWLANMeasurementResultComplete(v *WLANMeasurementResultComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	BridgeCaptureLPPaWLANMeasurementResult(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaWLANMeasurementResultComplete(v *WLANMeasurementResultComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	BridgeCompareLPPaWLANMeasurementResult(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaWLANMeasurementResultItem(v *WLANMeasurementResultItem, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q5.BridgeCaptureLPPaWLANRSSI(&v.WLANRSSI, s)
	{
		f := s.Begin()
		s.Bool(v.SSID == nil)
		if v.SSID != nil {
			q5.BridgeCaptureLPPaSSID(v.SSID, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.BSSID == nil)
		if v.BSSID != nil {
			q5.BridgeCaptureLPPaBSSID(v.BSSID, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.HESSID == nil)
		if v.HESSID != nil {
			q5.BridgeCaptureLPPaHESSID(v.HESSID, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.OperatingClass == nil)
		if v.OperatingClass != nil {
			q5.BridgeCaptureLPPaWLANOperatingClass(v.OperatingClass, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.CountryCode == nil)
		if v.CountryCode != nil {
			q5.BridgeCaptureLPPaWLANCountryCode(v.CountryCode, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.WLANChannelList == nil)
	q5.BridgeCaptureLPPaWLANChannelList(&v.WLANChannelList, s)
	{
		f := s.Begin()
		s.Bool(v.WLANBand == nil)
		if v.WLANBand != nil {
			q5.BridgeCaptureLPPaWLANBand(v.WLANBand, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	q17.BridgeWLANMeasurementResultItemExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaWLANMeasurementResultItem(v *WLANMeasurementResultItem, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q8.BridgeCompareLPPaWLANRSSI(&v.WLANRSSI, s)
	{
		f := s.Begin()
		s.Bool(v.SSID == nil)
		if v.SSID != nil {
			q8.BridgeCompareLPPaSSID(v.SSID, s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.BSSID == nil)
		if v.BSSID != nil {
			q12.BridgeCompareLPPaBSSID(v.BSSID, s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.HESSID == nil)
		if v.HESSID != nil {
			q12.BridgeCompareLPPaHESSID(v.HESSID, s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.OperatingClass == nil)
		if v.OperatingClass != nil {
			q8.BridgeCompareLPPaWLANOperatingClass(v.OperatingClass, s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.CountryCode == nil)
		if v.CountryCode != nil {
			q8.BridgeCompareLPPaWLANCountryCode(v.CountryCode, s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	s.Bool(v.WLANChannelList == nil)
	q8.BridgeCompareLPPaWLANChannelList(&v.WLANChannelList, s)
	{
		f := s.Begin()
		s.Bool(v.WLANBand == nil)
		if v.WLANBand != nil {
			q8.BridgeCompareLPPaWLANBand(v.WLANBand, s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	q17.BridgeWLANMeasurementResultItemExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}

type ECIDMeasurementInitiationResponseIEValue struct {
	id                           q5.ProtocolIEID
	withoutReplay                bool
	received                     q4.WireSpan
	replay                       q4.Snapshot
	opaque                       *q4.OpaqueOpenType
	isOpaque                     bool
	rowESMLCUEMeasurementID      *q5.MeasurementID
	rowENBUEMeasurementID        *q5.MeasurementID
	rowECIDMeasurementResult     *q9.ECIDMeasurementResult
	rowCriticalityDiagnostics    *q10.CriticalityDiagnostics
	rowCellPortionID             *q5.CellPortionID
	rowInterRATMeasurementResult *q11.InterRATMeasurementResult
	rowWLANMeasurementResult     *WLANMeasurementResult
}

func (v ECIDMeasurementInitiationResponseIEValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q5.ProtocolIEID(2):
		return v.rowESMLCUEMeasurementID != nil
	case q5.ProtocolIEID(6):
		return v.rowENBUEMeasurementID != nil
	case q5.ProtocolIEID(7):
		return v.rowECIDMeasurementResult != nil
	case q5.ProtocolIEID(1):
		return v.rowCriticalityDiagnostics != nil
	case q5.ProtocolIEID(14):
		return v.rowCellPortionID != nil
	case q5.ProtocolIEID(17):
		return v.rowInterRATMeasurementResult != nil
	case q5.ProtocolIEID(21):
		return v.rowWLANMeasurementResult != nil
	default:
		return false
	}
}
func (v *ECIDMeasurementInitiationResponseIEValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ECIDMeasurementInitiationResponseIEValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationResponse-IEs"}}
}
func (ECIDMeasurementInitiationResponseIEValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(2):
		return q4.UnknownSelector
	case q5.ProtocolIEID(6):
		return q4.UnknownSelector
	case q5.ProtocolIEID(7):
		return q4.UnknownSelector
	case q5.ProtocolIEID(1):
		return q4.UnknownSelector
	case q5.ProtocolIEID(14):
		return q4.UnknownSelector
	case q5.ProtocolIEID(17):
		return q4.UnknownSelector
	case q5.ProtocolIEID(21):
		return q4.UnknownSelector
	case q5.ProtocolIEID(0):
		return q4.NotInTable
	case q5.ProtocolIEID(3):
		return q4.NotInTable
	case q5.ProtocolIEID(4):
		return q4.NotInTable
	case q5.ProtocolIEID(5):
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
	case q5.ProtocolIEID(13):
		return q4.NotInTable
	case q5.ProtocolIEID(15):
		return q4.NotInTable
	case q5.ProtocolIEID(16):
		return q4.NotInTable
	case q5.ProtocolIEID(18):
		return q4.NotInTable
	case q5.ProtocolIEID(19):
		return q4.NotInTable
	case q5.ProtocolIEID(20):
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
func (v *ECIDMeasurementInitiationResponseIEValue) AsESMLCUEMeasurementID() (*q5.MeasurementID, bool) {
	if v == nil || v.id != q5.ProtocolIEID(2) || v.rowESMLCUEMeasurementID == nil {
		return nil, false
	}
	return v.rowESMLCUEMeasurementID, true
}
func (v *ECIDMeasurementInitiationResponseIEValue) AsENBUEMeasurementID() (*q5.MeasurementID, bool) {
	if v == nil || v.id != q5.ProtocolIEID(6) || v.rowENBUEMeasurementID == nil {
		return nil, false
	}
	return v.rowENBUEMeasurementID, true
}
func (v *ECIDMeasurementInitiationResponseIEValue) AsECIDMeasurementResult() (*q9.ECIDMeasurementResult, bool) {
	if v == nil || v.id != q5.ProtocolIEID(7) || v.rowECIDMeasurementResult == nil {
		return nil, false
	}
	return v.rowECIDMeasurementResult, true
}
func (v *ECIDMeasurementInitiationResponseIEValue) AsCriticalityDiagnostics() (*q10.CriticalityDiagnostics, bool) {
	if v == nil || v.id != q5.ProtocolIEID(1) || v.rowCriticalityDiagnostics == nil {
		return nil, false
	}
	return v.rowCriticalityDiagnostics, true
}
func (v *ECIDMeasurementInitiationResponseIEValue) AsCellPortionID() (*q5.CellPortionID, bool) {
	if v == nil || v.id != q5.ProtocolIEID(14) || v.rowCellPortionID == nil {
		return nil, false
	}
	return v.rowCellPortionID, true
}
func (v *ECIDMeasurementInitiationResponseIEValue) AsInterRATMeasurementResult() (*q11.InterRATMeasurementResult, bool) {
	if v == nil || v.id != q5.ProtocolIEID(17) || v.rowInterRATMeasurementResult == nil {
		return nil, false
	}
	return v.rowInterRATMeasurementResult, true
}
func (v *ECIDMeasurementInitiationResponseIEValue) AsWLANMeasurementResult() (*WLANMeasurementResult, bool) {
	if v == nil || v.id != q5.ProtocolIEID(21) || v.rowWLANMeasurementResult == nil {
		return nil, false
	}
	return v.rowWLANMeasurementResult, true
}
func (v ECIDMeasurementInitiationResponseIEValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (ECIDMeasurementInitiationResponseIEValue, error) {
	out := ECIDMeasurementInitiationResponseIEValue{id: id}
	var scope *q4.BitBuffer
	switch id {
	case 2, 6, 7, 1, 14, 17, 21:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q5.ProtocolIEID(2):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound2, q5.BridgeAsn1IntegerBound7, true)
		value := q5.MeasurementID(decoded)
		if err != nil {
			return out, q6.Errorf("%s %w", "ESMLCUEMeasurementID:", err)
		}
		if _, err := q4.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowESMLCUEMeasurementID = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q5.ProtocolIEID(6):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound2, q5.BridgeAsn1IntegerBound7, true)
		value := q5.MeasurementID(decoded)
		if err != nil {
			return out, q6.Errorf("%s %w", "ENBUEMeasurementID:", err)
		}
		if _, err := q4.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowENBUEMeasurementID = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q5.ProtocolIEID(7):
		replayUsage := scope.Usage()
		var value q9.ECIDMeasurementResult
		child := raw.ChildDecodeBuffer()
		if err := q9.BridgeECIDMeasurementResultMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, q6.Errorf("%s %w", "ECIDMeasurementResult:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "ECIDMeasurementResult")
		if err != nil {
			return out, err
		}
		*q9.BridgeECIDMeasurementResultFieldPerPadding(&value) = padding
		*q9.BridgeECIDMeasurementResultFieldReceived(&value) = true
		raw.RetainContents(q9.BridgeECIDMeasurementResultFieldReceivedBytes(&value))
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowECIDMeasurementResult = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q5.ProtocolIEID(1):
		replayUsage := scope.Usage()
		var value q10.CriticalityDiagnostics
		child := raw.ChildDecodeBuffer()
		if err := q10.BridgeCriticalityDiagnosticsMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, q6.Errorf("%s %w", "CriticalityDiagnostics:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "CriticalityDiagnostics")
		if err != nil {
			return out, err
		}
		*q10.BridgeCriticalityDiagnosticsFieldPerPadding(&value) = padding
		*q10.BridgeCriticalityDiagnosticsFieldReceived(&value) = true
		raw.RetainContents(q10.BridgeCriticalityDiagnosticsFieldReceivedBytes(&value))
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCriticalityDiagnostics = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q5.ProtocolIEID(14):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound12, true)
		value := q5.CellPortionID(decoded)
		if err != nil {
			return out, q6.Errorf("%s %w", "CellPortionID:", err)
		}
		if _, err := q4.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowCellPortionID = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q5.ProtocolIEID(17):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := q11.BridgeUnmarshalAPERInterRATMeasurementResultFrom(child)
		if err != nil {
			return out, q6.Errorf("%s %w", "InterRATMeasurementResult:", err)
		}
		padding, err := q4.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := func() q11.InterRATMeasurementResultComplete {
			sealed := q11.InterRATMeasurementResultComplete{Value: list}
			*q11.BridgeInterRATMeasurementResultCompleteFieldPerPadding(&sealed) = padding
			return sealed
		}()
		value := complete.Value
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowInterRATMeasurementResult = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q5.ProtocolIEID(21):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := BridgeUnmarshalAPERWLANMeasurementResultFrom(child)
		if err != nil {
			return out, q6.Errorf("%s %w", "WLANMeasurementResult:", err)
		}
		padding, err := q4.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := WLANMeasurementResultComplete{Value: list, perPadding: padding}
		value := complete.Value
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowWLANMeasurementResult = &value
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
func (v ECIDMeasurementInitiationResponseIEValue) encode() ([]byte, error) {
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ECIDMeasurementInitiationResponseIEValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
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
	case q5.ProtocolIEID(2):
		if v.rowESMLCUEMeasurementID == nil {
			return nil, q6.Errorf("%s missing value", "E-CIDMeasurementInitiationResponse-IEs.id-E-SMLC-UE-Measurement-ID:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := q4.NewBudgetBuffer(budget)
		if err := q4.EncodeIntegerBigBoundsAligned(encodeBB, *v.rowESMLCUEMeasurementID, q5.BridgeAsn1IntegerBound2, q5.BridgeAsn1IntegerBound7, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case q5.ProtocolIEID(6):
		if v.rowENBUEMeasurementID == nil {
			return nil, q6.Errorf("%s missing value", "E-CIDMeasurementInitiationResponse-IEs.id-eNB-UE-Measurement-ID:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := q4.NewBudgetBuffer(budget)
		if err := q4.EncodeIntegerBigBoundsAligned(encodeBB, *v.rowENBUEMeasurementID, q5.BridgeAsn1IntegerBound2, q5.BridgeAsn1IntegerBound7, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case q5.ProtocolIEID(7):
		if v.rowECIDMeasurementResult == nil {
			return nil, q6.Errorf("%s missing value", "E-CIDMeasurementInitiationResponse-IEs.id-E-CID-MeasurementResult:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := q9.BridgeECIDMeasurementResultMethodMarshalAPERBudget(v.rowECIDMeasurementResult, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case q5.ProtocolIEID(1):
		if v.rowCriticalityDiagnostics == nil {
			return nil, q6.Errorf("%s missing value", "E-CIDMeasurementInitiationResponse-IEs.id-CriticalityDiagnostics:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := q10.BridgeCriticalityDiagnosticsMethodMarshalAPERBudget(v.rowCriticalityDiagnostics, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case q5.ProtocolIEID(14):
		if v.rowCellPortionID == nil {
			return nil, q6.Errorf("%s missing value", "E-CIDMeasurementInitiationResponse-IEs.id-Cell-Portion-ID:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := q4.NewBudgetBuffer(budget)
		if err := q4.EncodeIntegerBigBoundsAligned(encodeBB, *v.rowCellPortionID, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound12, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case q5.ProtocolIEID(17):
		if v.rowInterRATMeasurementResult == nil {
			return nil, q6.Errorf("%s missing value", "E-CIDMeasurementInitiationResponse-IEs.id-InterRATMeasurementResult:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		complete := q11.InterRATMeasurementResultComplete{Value: *v.rowInterRATMeasurementResult}
		candidate, err := q11.BridgeInterRATMeasurementResultCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case q5.ProtocolIEID(21):
		if v.rowWLANMeasurementResult == nil {
			return nil, q6.Errorf("%s missing value", "E-CIDMeasurementInitiationResponse-IEs.id-WLANMeasurementResult:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
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
		return nil, q6.Errorf("%s id %d has no value", "ECIDMeasurementInitiationResponseIEValue:", v.id)
	}
}

type ECIDMeasurementInitiationResponseIETable struct{}

func ECIDMeasurementInitiationResponseIEs() ECIDMeasurementInitiationResponseIETable {
	return ECIDMeasurementInitiationResponseIETable{}
}
func (ECIDMeasurementInitiationResponseIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationResponse-IEs"}
		return sealed
	}()
}
func (ECIDMeasurementInitiationResponseIETable) infoESMLCUEMeasurementID() q5.FieldInfo {
	return q5.FieldInfo{Table: ECIDMeasurementInitiationResponseIEs().ID(), ID: q5.ProtocolIEID(2), Criticality: q5.CriticalityReject, Presence: q5.PresenceMandatory, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationResponse-IEs", Row: "id-E-SMLC-UE-Measurement-ID"}}}
}
func (t ECIDMeasurementInitiationResponseIETable) ESMLCUEMeasurementID() ECIDMeasurementInitiationResponseMeasurementIDIEBinding {
	return ECIDMeasurementInitiationResponseMeasurementIDIEBinding{info: t.infoESMLCUEMeasurementID(), codec: func() q5.MeasurementIDValueCodec {
		sealed := q5.MeasurementIDValueCodec{}
		*q5.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*q5.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.MeasurementID, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q5.MeasurementID
				return empty, err
			}
			var zero ECIDMeasurementInitiationResponseIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(2), raw)
			if err != nil {
				var empty q5.MeasurementID
				return empty, err
			}
			value, ok := decoded.AsESMLCUEMeasurementID()
			if !ok {
				var empty q5.MeasurementID
				return empty, q6.Errorf("binding E-CIDMeasurementInitiationResponse-IEs.id-E-SMLC-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*q5.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value q5.MeasurementID, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationResponseIEValue{id: q5.ProtocolIEID(2), rowESMLCUEMeasurementID: &value}).encodeFresh(fresh, budget)
		}
		*q5.BridgeMeasurementIDValueCodecFieldCapture(&sealed) = func(v q5.MeasurementID, options q4.DecodeState) (q5.MeasurementID, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaMeasurementID(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q5.BridgeMeasurementIDValueCodecFieldCompare(&sealed) = func(v q5.MeasurementID, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q12.BridgeCompareLPPaMeasurementID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q5.BridgeMeasurementIDValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementID"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q5.MeasurementID) ECIDMeasurementInitiationResponseIEValue {
			return ECIDMeasurementInitiationResponseIEValue{id: q5.ProtocolIEID(2), rowESMLCUEMeasurementID: &value}
		}, get: func(value *ECIDMeasurementInitiationResponseIEValue) (*q5.MeasurementID, bool) {
			return value.AsESMLCUEMeasurementID()
		}}
}
func (ECIDMeasurementInitiationResponseIETable) infoENBUEMeasurementID() q5.FieldInfo {
	return q5.FieldInfo{Table: ECIDMeasurementInitiationResponseIEs().ID(), ID: q5.ProtocolIEID(6), Criticality: q5.CriticalityReject, Presence: q5.PresenceMandatory, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationResponse-IEs", Row: "id-eNB-UE-Measurement-ID"}}}
}
func (t ECIDMeasurementInitiationResponseIETable) ENBUEMeasurementID() ECIDMeasurementInitiationResponseMeasurementIDIEBinding {
	return ECIDMeasurementInitiationResponseMeasurementIDIEBinding{info: t.infoENBUEMeasurementID(), codec: func() q5.MeasurementIDValueCodec {
		sealed := q5.MeasurementIDValueCodec{}
		*q5.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*q5.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.MeasurementID, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q5.MeasurementID
				return empty, err
			}
			var zero ECIDMeasurementInitiationResponseIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(6), raw)
			if err != nil {
				var empty q5.MeasurementID
				return empty, err
			}
			value, ok := decoded.AsENBUEMeasurementID()
			if !ok {
				var empty q5.MeasurementID
				return empty, q6.Errorf("binding E-CIDMeasurementInitiationResponse-IEs.id-eNB-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*q5.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value q5.MeasurementID, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationResponseIEValue{id: q5.ProtocolIEID(6), rowENBUEMeasurementID: &value}).encodeFresh(fresh, budget)
		}
		*q5.BridgeMeasurementIDValueCodecFieldCapture(&sealed) = func(v q5.MeasurementID, options q4.DecodeState) (q5.MeasurementID, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaMeasurementID(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q5.BridgeMeasurementIDValueCodecFieldCompare(&sealed) = func(v q5.MeasurementID, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q12.BridgeCompareLPPaMeasurementID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q5.BridgeMeasurementIDValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:MeasurementID"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q5.MeasurementID) ECIDMeasurementInitiationResponseIEValue {
			return ECIDMeasurementInitiationResponseIEValue{id: q5.ProtocolIEID(6), rowENBUEMeasurementID: &value}
		}, get: func(value *ECIDMeasurementInitiationResponseIEValue) (*q5.MeasurementID, bool) {
			return value.AsENBUEMeasurementID()
		}}
}
func (ECIDMeasurementInitiationResponseIETable) infoECIDMeasurementResult() q5.FieldInfo {
	return q5.FieldInfo{Table: ECIDMeasurementInitiationResponseIEs().ID(), ID: q5.ProtocolIEID(7), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ECIDMeasurementResult"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationResponse-IEs", Row: "id-E-CID-MeasurementResult"}}}
}
func (t ECIDMeasurementInitiationResponseIETable) ECIDMeasurementResult() ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding {
	return ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding{info: t.infoECIDMeasurementResult(), codec: func() q9.ECIDMeasurementResultValueCodec {
		sealed := q9.ECIDMeasurementResultValueCodec{}
		*q9.BridgeECIDMeasurementResultValueCodecFieldPath(&sealed) = "ECIDMeasurementResult"
		*q9.BridgeECIDMeasurementResultValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q9.ECIDMeasurementResult, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q9.ECIDMeasurementResult
				return empty, err
			}
			var zero ECIDMeasurementInitiationResponseIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(7), raw)
			if err != nil {
				var empty q9.ECIDMeasurementResult
				return empty, err
			}
			value, ok := decoded.AsECIDMeasurementResult()
			if !ok {
				var empty q9.ECIDMeasurementResult
				return empty, q6.Errorf("binding E-CIDMeasurementInitiationResponse-IEs.id-E-CID-MeasurementResult: no selected value")
			}
			return *value, nil
		}
		*q9.BridgeECIDMeasurementResultValueCodecFieldEncode(&sealed) = func(value q9.ECIDMeasurementResult, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationResponseIEValue{id: q5.ProtocolIEID(7), rowECIDMeasurementResult: &value}).encodeFresh(fresh, budget)
		}
		*q9.BridgeECIDMeasurementResultValueCodecFieldCapture(&sealed) = func(v q9.ECIDMeasurementResult, options q4.DecodeState) (q9.ECIDMeasurementResult, q4.Snapshot,
		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q9.BridgeCaptureLPPaECIDMeasurementResult(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}
		*q9.BridgeECIDMeasurementResultValueCodecFieldCompare(&sealed) = func(v q9.ECIDMeasurementResult, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q9.BridgeCompareLPPaECIDMeasurementResult(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q9.BridgeECIDMeasurementResultValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:ECIDMeasurementResult"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q9.ECIDMeasurementResult) ECIDMeasurementInitiationResponseIEValue {
			return ECIDMeasurementInitiationResponseIEValue{id: q5.ProtocolIEID(7), rowECIDMeasurementResult: &value}
		}, get: func(value *ECIDMeasurementInitiationResponseIEValue) (*q9.ECIDMeasurementResult, bool) {
			return value.AsECIDMeasurementResult()
		}}
}
func (ECIDMeasurementInitiationResponseIETable) infoCriticalityDiagnostics() q5.FieldInfo {
	return q5.FieldInfo{Table: ECIDMeasurementInitiationResponseIEs().ID(), ID: q5.ProtocolIEID(1), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "CriticalityDiagnostics"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationResponse-IEs", Row: "id-CriticalityDiagnostics"}}}
}
func (t ECIDMeasurementInitiationResponseIETable) CriticalityDiagnostics() ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding {
	return ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding{info: t.infoCriticalityDiagnostics(), codec: func() q10.CriticalityDiagnosticsValueCodec {
		sealed := q10.CriticalityDiagnosticsValueCodec{}
		*q10.BridgeCriticalityDiagnosticsValueCodecFieldPath(&sealed) = "CriticalityDiagnostics"
		*q10.BridgeCriticalityDiagnosticsValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q10.CriticalityDiagnostics, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q10.CriticalityDiagnostics
				return empty, err
			}
			var zero ECIDMeasurementInitiationResponseIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(1), raw)
			if err != nil {
				var empty q10.CriticalityDiagnostics
				return empty, err
			}
			value, ok := decoded.AsCriticalityDiagnostics()
			if !ok {
				var empty q10.CriticalityDiagnostics
				return empty, q6.Errorf("binding E-CIDMeasurementInitiationResponse-IEs.id-CriticalityDiagnostics: no selected value")
			}
			return *value, nil
		}
		*q10.BridgeCriticalityDiagnosticsValueCodecFieldEncode(&sealed) = func(value q10.CriticalityDiagnostics, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationResponseIEValue{id: q5.ProtocolIEID(1), rowCriticalityDiagnostics: &value}).encodeFresh(fresh, budget)
		}
		*q10.BridgeCriticalityDiagnosticsValueCodecFieldCapture(&sealed) = func(v q10.CriticalityDiagnostics, options q4.DecodeState) (q10.CriticalityDiagnostics, q4.Snapshot,

		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q10.BridgeCaptureLPPaCriticalityDiagnostics(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q10.BridgeCriticalityDiagnosticsValueCodecFieldCompare(&sealed) = func(v q10.CriticalityDiagnostics, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q10.BridgeCompareLPPaCriticalityDiagnostics(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q10.BridgeCriticalityDiagnosticsValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:CriticalityDiagnostics"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q10.CriticalityDiagnostics) ECIDMeasurementInitiationResponseIEValue {
			return ECIDMeasurementInitiationResponseIEValue{id: q5.ProtocolIEID(1), rowCriticalityDiagnostics: &value}
		}, get: func(value *ECIDMeasurementInitiationResponseIEValue) (*q10.CriticalityDiagnostics, bool) {
			return value.AsCriticalityDiagnostics()
		}}
}
func (ECIDMeasurementInitiationResponseIETable) infoCellPortionID() q5.FieldInfo {
	return q5.FieldInfo{Table: ECIDMeasurementInitiationResponseIEs().ID(), ID: q5.ProtocolIEID(14), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "CellPortionID"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationResponse-IEs", Row: "id-Cell-Portion-ID"}}}
}
func (t ECIDMeasurementInitiationResponseIETable) CellPortionID() ECIDMeasurementInitiationResponseCellPortionIDIEBinding {
	return ECIDMeasurementInitiationResponseCellPortionIDIEBinding{info: t.infoCellPortionID(), codec: func() q5.CellPortionIDValueCodec {
		sealed := q5.CellPortionIDValueCodec{}
		*q5.BridgeCellPortionIDValueCodecFieldPath(&sealed) = "CellPortionID"
		*q5.BridgeCellPortionIDValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.CellPortionID, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q5.CellPortionID
				return empty, err
			}
			var zero ECIDMeasurementInitiationResponseIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(14), raw)
			if err != nil {
				var empty q5.CellPortionID
				return empty, err
			}
			value, ok := decoded.AsCellPortionID()
			if !ok {
				var empty q5.CellPortionID
				return empty, q6.Errorf("binding E-CIDMeasurementInitiationResponse-IEs.id-Cell-Portion-ID: no selected value")
			}
			return *value, nil
		}
		*q5.BridgeCellPortionIDValueCodecFieldEncode(&sealed) = func(value q5.CellPortionID, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationResponseIEValue{id: q5.ProtocolIEID(14), rowCellPortionID: &value}).encodeFresh(fresh, budget)
		}
		*q5.BridgeCellPortionIDValueCodecFieldCapture(&sealed) = func(v q5.CellPortionID, options q4.DecodeState) (q5.CellPortionID, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaCellPortionID(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q5.BridgeCellPortionIDValueCodecFieldCompare(&sealed) = func(v q5.CellPortionID, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q12.BridgeCompareLPPaCellPortionID(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q5.BridgeCellPortionIDValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:CellPortionID"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q5.CellPortionID) ECIDMeasurementInitiationResponseIEValue {
			return ECIDMeasurementInitiationResponseIEValue{id: q5.ProtocolIEID(14), rowCellPortionID: &value}
		}, get: func(value *ECIDMeasurementInitiationResponseIEValue) (*q5.CellPortionID, bool) {
			return value.AsCellPortionID()
		}}
}
func (ECIDMeasurementInitiationResponseIETable) infoInterRATMeasurementResult() q5.FieldInfo {
	return q5.FieldInfo{Table: ECIDMeasurementInitiationResponseIEs().ID(), ID: q5.ProtocolIEID(17), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "InterRATMeasurementResult"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationResponse-IEs", Row: "id-InterRATMeasurementResult"}}}
}
func (t ECIDMeasurementInitiationResponseIETable) InterRATMeasurementResult() ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding {
	return ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding{info: t.infoInterRATMeasurementResult(), codec: func() q11.InterRATMeasurementResultValueCodec {
		sealed := q11.InterRATMeasurementResultValueCodec{}
		*q11.BridgeInterRATMeasurementResultValueCodecFieldPath(&sealed) = "InterRATMeasurementResult"
		*q11.BridgeInterRATMeasurementResultValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q11.InterRATMeasurementResult, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q11.InterRATMeasurementResult
				return empty, err
			}
			var zero ECIDMeasurementInitiationResponseIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(17), raw)
			if err != nil {
				var empty q11.InterRATMeasurementResult
				return empty, err
			}
			value, ok := decoded.AsInterRATMeasurementResult()
			if !ok {
				var empty q11.InterRATMeasurementResult
				return empty, q6.Errorf("binding E-CIDMeasurementInitiationResponse-IEs.id-InterRATMeasurementResult: no selected value")
			}
			return *value, nil
		}
		*q11.BridgeInterRATMeasurementResultValueCodecFieldEncode(&sealed) = func(value q11.InterRATMeasurementResult, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationResponseIEValue{id: q5.ProtocolIEID(17), rowInterRATMeasurementResult: &value}).encodeFresh(fresh, budget)
		}
		*q11.BridgeInterRATMeasurementResultValueCodecFieldCapture(&sealed) = func(v q11.InterRATMeasurementResult, options q4.DecodeState) (q11.InterRATMeasurementResult, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q11.BridgeCaptureLPPaInterRATMeasurementResult(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q11.BridgeInterRATMeasurementResultValueCodecFieldCompare(&sealed) = func(v q11.InterRATMeasurementResult, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q11.BridgeCompareLPPaInterRATMeasurementResult(&v, &s)
			s.End(f, root, false)
			return s.
				Plan()
		}
		*q11.BridgeInterRATMeasurementResultValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:InterRATMeasurementResult"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q11.InterRATMeasurementResult) ECIDMeasurementInitiationResponseIEValue {
			return ECIDMeasurementInitiationResponseIEValue{id: q5.ProtocolIEID(17), rowInterRATMeasurementResult: &value}
		}, get: func(value *ECIDMeasurementInitiationResponseIEValue) (*q11.InterRATMeasurementResult, bool) {
			return value.AsInterRATMeasurementResult()
		}}
}
func (ECIDMeasurementInitiationResponseIETable) infoWLANMeasurementResult() q5.FieldInfo {
	return q5.FieldInfo{Table: ECIDMeasurementInitiationResponseIEs().ID(), ID: q5.ProtocolIEID(21), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "WLANMeasurementResult"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementInitiationResponse-IEs", Row: "id-WLANMeasurementResult"}}}
}
func (t ECIDMeasurementInitiationResponseIETable) WLANMeasurementResult() ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding {
	return ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding{info: t.infoWLANMeasurementResult(), codec: WLANMeasurementResultValueCodec{path: "WLANMeasurementResult",
		decode: func(data []byte, options q4.DecodeState) (WLANMeasurementResult, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty WLANMeasurementResult
				return empty, err
			}
			var zero ECIDMeasurementInitiationResponseIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(21), raw)
			if err != nil {
				var empty WLANMeasurementResult
				return empty, err
			}
			value, ok := decoded.AsWLANMeasurementResult()
			if !ok {
				var empty WLANMeasurementResult
				return empty, q6.Errorf("binding E-CIDMeasurementInitiationResponse-IEs.id-WLANMeasurementResult: no selected value")
			}
			return *value, nil
		},
		encode: func(value WLANMeasurementResult, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementInitiationResponseIEValue{id: q5.ProtocolIEID(21), rowWLANMeasurementResult: &value}).encodeFresh(fresh, budget)
		}, capture: func(v WLANMeasurementResult, options q4.DecodeState) (WLANMeasurementResult, q4.Snapshot,
		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureLPPaWLANMeasurementResult(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}, compare: func(v WLANMeasurementResult, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaWLANMeasurementResult(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}, context: func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:WLANMeasurementResult"
			return sealed
		}(),
	}, inject: func(value WLANMeasurementResult) ECIDMeasurementInitiationResponseIEValue {
		return ECIDMeasurementInitiationResponseIEValue{id: q5.ProtocolIEID(21), rowWLANMeasurementResult: &value}
	}, get: func(value *ECIDMeasurementInitiationResponseIEValue) (*WLANMeasurementResult, bool) {
		return value.AsWLANMeasurementResult()
	}}
}
func (t ECIDMeasurementInitiationResponseIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (ECIDMeasurementInitiationResponseIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q5.ProtocolIEID(2):
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("known IE id-E-SMLC-UE-Measurement-ID requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(6):
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("known IE id-eNB-UE-Measurement-ID requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(7):
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("known IE id-E-CID-MeasurementResult requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(1):
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("known IE id-CriticalityDiagnostics requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(14):
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("known IE id-Cell-Portion-ID requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(17):
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("known IE id-InterRATMeasurementResult requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(21):
		return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(q6.Errorf("known IE id-WLANMeasurementResult requires its typed binding"), "Opaque")
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ECIDMeasurementInitiationResponseIEField{}, q4.OperationError(err, "Opaque")
		}
		return ECIDMeasurementInitiationResponseIEField{Id: id, Criticality: criticality, Value: ECIDMeasurementInitiationResponseIEValue{id: id, opaque: retained, isOpaque: true}}, q4.OperationError(nil, "Opaque")
	}
}

// CellPortionIDCodec binds the complete APER value type.
func CellPortionIDCodec() q5.CellPortionIDValueCodec {
	return ECIDMeasurementInitiationResponseIEs().CellPortionID().Codec()
}

// ECIDMeasurementResultCodec binds the complete APER value type.
func ECIDMeasurementResultCodec() q9.ECIDMeasurementResultValueCodec {
	return ECIDMeasurementInitiationResponseIEs().ECIDMeasurementResult().Codec()
}

// InterRATMeasurementResultCodec binds the complete APER value type.
func InterRATMeasurementResultCodec() q11.InterRATMeasurementResultValueCodec {
	return ECIDMeasurementInitiationResponseIEs().InterRATMeasurementResult().Codec()
}

// WLANMeasurementResultCodec binds the complete APER value type.
func WLANMeasurementResultCodec() WLANMeasurementResultValueCodec {
	return ECIDMeasurementInitiationResponseIEs().WLANMeasurementResult().Codec()
}

// WLANMeasurementResultItemCodec binds the complete source value type.
func WLANMeasurementResultItemCodec() WLANMeasurementResultItemValueCodec {
	return WLANMeasurementResultItemValueCodec{path: "WLANMeasurementResultItem", decode: func(data []byte, options q4.DecodeState) (WLANMeasurementResultItem, error) {
		var value WLANMeasurementResultItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return WLANMeasurementResultItem{}, err
		}
		value.received = true
		value.receivedBytes = q4.OriginalWire(data)
		return value, nil
	}, encode: func(value WLANMeasurementResultItem, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v WLANMeasurementResultItem, options q4.DecodeState) (WLANMeasurementResultItem, q4.Snapshot) {
		s := q4.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaWLANMeasurementResultItem(&v, &s)
		var root q4.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v WLANMeasurementResultItem, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
		s := q4.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaWLANMeasurementResultItem(&v, &s)
		s.End(f, root, false)
		return s.
			Plan()
	}, context: func() q5.BridgeCodecContext {
		sealed := q5.BridgeCodecContext{}
		*q5.BridgecodecContextFieldSource(&sealed) = "source-value:WLANMeasurementResultItem"
		return sealed
	}(),
	}
}
func BridgeECIDMeasurementInitiationResponseAPERValueFieldContext(v *ECIDMeasurementInitiationResponseAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementInitiationResponseAPERValueFieldReceived(v *ECIDMeasurementInitiationResponseAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementInitiationResponseAPERValueFieldReplay(v *ECIDMeasurementInitiationResponseAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationResponseAPERValueFieldWithoutReplay(v *ECIDMeasurementInitiationResponseAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationResponseCellPortionIDIEBindingFieldCodec(v *ECIDMeasurementInitiationResponseCellPortionIDIEBinding) *q5.CellPortionIDValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationResponseCellPortionIDIEBindingFieldGet(v *ECIDMeasurementInitiationResponseCellPortionIDIEBinding) *func(*ECIDMeasurementInitiationResponseIEValue) (*q5.CellPortionID, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationResponseCellPortionIDIEBindingFieldInfo(v *ECIDMeasurementInitiationResponseCellPortionIDIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationResponseCellPortionIDIEBindingFieldInject(v *ECIDMeasurementInitiationResponseCellPortionIDIEBinding) *func(q5.CellPortionID) ECIDMeasurementInitiationResponseIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBindingFieldCodec(v *ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding) *q10.CriticalityDiagnosticsValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBindingFieldGet(v *ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding) *func(*ECIDMeasurementInitiationResponseIEValue) (*q10.CriticalityDiagnostics, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBindingFieldInfo(v *ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBindingFieldInject(v *ECIDMeasurementInitiationResponseCriticalityDiagnosticsIEBinding) *func(q10.CriticalityDiagnostics) ECIDMeasurementInitiationResponseIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationResponseECIDMeasurementResultIEBindingFieldCodec(v *ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding) *q9.ECIDMeasurementResultValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationResponseECIDMeasurementResultIEBindingFieldGet(v *ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding) *func(*ECIDMeasurementInitiationResponseIEValue) (*q9.ECIDMeasurementResult, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationResponseECIDMeasurementResultIEBindingFieldInfo(v *ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationResponseECIDMeasurementResultIEBindingFieldInject(v *ECIDMeasurementInitiationResponseECIDMeasurementResultIEBinding) *func(q9.ECIDMeasurementResult) ECIDMeasurementInitiationResponseIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationResponseFieldExtCount(v *ECIDMeasurementInitiationResponse) *int64 {
	return &v.extCount
}
func BridgeECIDMeasurementInitiationResponseFieldExtData(v *ECIDMeasurementInitiationResponse) *[][]byte {
	return &v.extData
}
func BridgeECIDMeasurementInitiationResponseFieldExtOrigin(v *ECIDMeasurementInitiationResponse) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeECIDMeasurementInitiationResponseFieldExtPresent(v *ECIDMeasurementInitiationResponse) *[]bool {
	return &v.extPresent
}
func BridgeECIDMeasurementInitiationResponseFieldExtWire(v *ECIDMeasurementInitiationResponse) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeECIDMeasurementInitiationResponseFieldPerExtPadding(v *ECIDMeasurementInitiationResponse) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeECIDMeasurementInitiationResponseFieldPerPadding(v *ECIDMeasurementInitiationResponse) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeECIDMeasurementInitiationResponseFieldProtocolIEsIndef(v *ECIDMeasurementInitiationResponse) *bool {
	return &v.protocolIEsIndef
}
func BridgeECIDMeasurementInitiationResponseFieldReceived(v *ECIDMeasurementInitiationResponse) *bool {
	return &v.received
}
func BridgeECIDMeasurementInitiationResponseFieldReceivedBytes(v *ECIDMeasurementInitiationResponse) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeECIDMeasurementInitiationResponseFieldReplay(v *ECIDMeasurementInitiationResponse) *q4.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationResponseFieldStream(v *ECIDMeasurementInitiationResponse) *q4.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementInitiationResponseFieldWithoutReplay(v *ECIDMeasurementInitiationResponse) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationResponseIEFieldFieldReceived(v *ECIDMeasurementInitiationResponseIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeECIDMeasurementInitiationResponseIEFieldFieldReplay(v *ECIDMeasurementInitiationResponseIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationResponseIEFieldFieldStream(v *ECIDMeasurementInitiationResponseIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementInitiationResponseIEFieldFieldWithoutReplay(v *ECIDMeasurementInitiationResponseIEField) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementInitiationResponseIEFieldMethodMarshalAPERTo(v *ECIDMeasurementInitiationResponseIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementInitiationResponseIEFieldMethodUnmarshalAPERFrom(v *ECIDMeasurementInitiationResponseIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementInitiationResponseIETableMethodInfoCellPortionID(v ECIDMeasurementInitiationResponseIETable) q5.FieldInfo {
	return v.infoCellPortionID()
}
func BridgeECIDMeasurementInitiationResponseIETableMethodInfoCriticalityDiagnostics(v ECIDMeasurementInitiationResponseIETable) q5.FieldInfo {
	return v.infoCriticalityDiagnostics()
}
func BridgeECIDMeasurementInitiationResponseIETableMethodInfoECIDMeasurementResult(v ECIDMeasurementInitiationResponseIETable) q5.FieldInfo {
	return v.infoECIDMeasurementResult()
}
func BridgeECIDMeasurementInitiationResponseIETableMethodInfoENBUEMeasurementID(v ECIDMeasurementInitiationResponseIETable) q5.FieldInfo {
	return v.infoENBUEMeasurementID()
}
func BridgeECIDMeasurementInitiationResponseIETableMethodInfoESMLCUEMeasurementID(v ECIDMeasurementInitiationResponseIETable) q5.FieldInfo {
	return v.infoESMLCUEMeasurementID()
}
func BridgeECIDMeasurementInitiationResponseIETableMethodInfoInterRATMeasurementResult(v ECIDMeasurementInitiationResponseIETable) q5.FieldInfo {
	return v.infoInterRATMeasurementResult()
}
func BridgeECIDMeasurementInitiationResponseIETableMethodInfoWLANMeasurementResult(v ECIDMeasurementInitiationResponseIETable) q5.FieldInfo {
	return v.infoWLANMeasurementResult()
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldId(v *ECIDMeasurementInitiationResponseIEValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldIsOpaque(v *ECIDMeasurementInitiationResponseIEValue) *bool {
	return &v.isOpaque
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldOpaque(v *ECIDMeasurementInitiationResponseIEValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldReceived(v *ECIDMeasurementInitiationResponseIEValue) *q4.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldReplay(v *ECIDMeasurementInitiationResponseIEValue) *q4.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldRowCellPortionID(v *ECIDMeasurementInitiationResponseIEValue) **q5.CellPortionID {
	return &v.rowCellPortionID
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldRowCriticalityDiagnostics(v *ECIDMeasurementInitiationResponseIEValue) **q10.CriticalityDiagnostics {
	return &v.rowCriticalityDiagnostics
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldRowECIDMeasurementResult(v *ECIDMeasurementInitiationResponseIEValue) **q9.ECIDMeasurementResult {
	return &v.rowECIDMeasurementResult
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldRowENBUEMeasurementID(v *ECIDMeasurementInitiationResponseIEValue) **q5.MeasurementID {
	return &v.rowENBUEMeasurementID
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldRowESMLCUEMeasurementID(v *ECIDMeasurementInitiationResponseIEValue) **q5.MeasurementID {
	return &v.rowESMLCUEMeasurementID
}
func BridgeECIDMeasurementInitiationResponseIEValueFieldRowInterRATMeasurementResult(v *ECIDMeasurementInitiationResponseIEValue) **q11.InterRATMeasurementResult {
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
func BridgeECIDMeasurementInitiationResponseIEValueMethodCaptureSemantics(v ECIDMeasurementInitiationResponseIEValue, a0 q4.SemanticCapture) ECIDMeasurementInitiationResponseIEValue {
	return v.captureSemantics(a0)
}
func BridgeECIDMeasurementInitiationResponseIEValueMethodCaptureSnapshot(v ECIDMeasurementInitiationResponseIEValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeECIDMeasurementInitiationResponseIEValueMethodCompareSemantics(v ECIDMeasurementInitiationResponseIEValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeECIDMeasurementInitiationResponseIEValueMethodDecode(v ECIDMeasurementInitiationResponseIEValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (ECIDMeasurementInitiationResponseIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeECIDMeasurementInitiationResponseIEValueMethodEncode(v ECIDMeasurementInitiationResponseIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeECIDMeasurementInitiationResponseIEValueMethodEncodeFresh(v ECIDMeasurementInitiationResponseIEValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeECIDMeasurementInitiationResponseIEValueMethodMatchesID(v ECIDMeasurementInitiationResponseIEValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeECIDMeasurementInitiationResponseIEValueMethodReason(v ECIDMeasurementInitiationResponseIEValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeECIDMeasurementInitiationResponseIEValueMethodRule(v ECIDMeasurementInitiationResponseIEValue) q4.SourceRule {
	return v.rule()
}
func BridgeECIDMeasurementInitiationResponseInterRATMeasurementResultIEBindingFieldCodec(v *ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding) *q11.InterRATMeasurementResultValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationResponseInterRATMeasurementResultIEBindingFieldGet(v *ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding) *func(*ECIDMeasurementInitiationResponseIEValue) (*q11.InterRATMeasurementResult, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationResponseInterRATMeasurementResultIEBindingFieldInfo(v *ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationResponseInterRATMeasurementResultIEBindingFieldInject(v *ECIDMeasurementInitiationResponseInterRATMeasurementResultIEBinding) *func(q11.InterRATMeasurementResult) ECIDMeasurementInitiationResponseIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationResponseMeasurementIDIEBindingFieldCodec(v *ECIDMeasurementInitiationResponseMeasurementIDIEBinding) *q5.MeasurementIDValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationResponseMeasurementIDIEBindingFieldGet(v *ECIDMeasurementInitiationResponseMeasurementIDIEBinding) *func(*ECIDMeasurementInitiationResponseIEValue) (*q5.MeasurementID, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationResponseMeasurementIDIEBindingFieldInfo(v *ECIDMeasurementInitiationResponseMeasurementIDIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationResponseMeasurementIDIEBindingFieldInject(v *ECIDMeasurementInitiationResponseMeasurementIDIEBinding) *func(q5.MeasurementID) ECIDMeasurementInitiationResponseIEValue {
	return &v.inject
}
func BridgeECIDMeasurementInitiationResponseMethodMarshalAPERBudget(v *ECIDMeasurementInitiationResponse, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeECIDMeasurementInitiationResponseMethodMarshalAPERChanged(v *ECIDMeasurementInitiationResponse, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeECIDMeasurementInitiationResponseMethodMarshalAPERChangedValue(v *ECIDMeasurementInitiationResponse, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeECIDMeasurementInitiationResponseMethodMarshalAPERFreshValue(v *ECIDMeasurementInitiationResponse, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeECIDMeasurementInitiationResponseMethodMarshalAPERLegacy(v *ECIDMeasurementInitiationResponse) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeECIDMeasurementInitiationResponseMethodMarshalAPERPlanned(v *ECIDMeasurementInitiationResponse, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeECIDMeasurementInitiationResponseMethodMarshalAPERTo(v *ECIDMeasurementInitiationResponse, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementInitiationResponseMethodUnmarshalAPERFrom(v *ECIDMeasurementInitiationResponse, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementInitiationResponseMethodUnmarshalAPERLegacy(v *ECIDMeasurementInitiationResponse, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeECIDMeasurementInitiationResponseMethodUnmarshalAPERWithOptions(v *ECIDMeasurementInitiationResponse, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeECIDMeasurementInitiationResponseValueCodecFieldCapture(v *ECIDMeasurementInitiationResponseValueCodec) *func(ECIDMeasurementInitiationResponse, q4.DecodeState) (ECIDMeasurementInitiationResponse, q4.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementInitiationResponseValueCodecFieldCompare(v *ECIDMeasurementInitiationResponseValueCodec) *func(ECIDMeasurementInitiationResponse, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementInitiationResponseValueCodecFieldContext(v *ECIDMeasurementInitiationResponseValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementInitiationResponseValueCodecFieldDecode(v *ECIDMeasurementInitiationResponseValueCodec) *func([]byte, q4.DecodeState) (ECIDMeasurementInitiationResponse, error) {
	return &v.decode
}
func BridgeECIDMeasurementInitiationResponseValueCodecFieldEncode(v *ECIDMeasurementInitiationResponseValueCodec) *func(ECIDMeasurementInitiationResponse, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementInitiationResponseValueCodecFieldPath(v *ECIDMeasurementInitiationResponseValueCodec) *q4.Path {
	return &v.path
}
func BridgeECIDMeasurementInitiationResponseValueCodecMethodEncodeBudget(v ECIDMeasurementInitiationResponseValueCodec, a0 ECIDMeasurementInitiationResponse, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeECIDMeasurementInitiationResponseValueCodecMethodEncodeChanged(v ECIDMeasurementInitiationResponseValueCodec, a0 ECIDMeasurementInitiationResponse, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeECIDMeasurementInitiationResponseWLANMeasurementResultIEBindingFieldCodec(v *ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding) *WLANMeasurementResultValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementInitiationResponseWLANMeasurementResultIEBindingFieldGet(v *ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding) *func(*ECIDMeasurementInitiationResponseIEValue) (*WLANMeasurementResult, bool) {
	return &v.get
}
func BridgeECIDMeasurementInitiationResponseWLANMeasurementResultIEBindingFieldInfo(v *ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementInitiationResponseWLANMeasurementResultIEBindingFieldInject(v *ECIDMeasurementInitiationResponseWLANMeasurementResultIEBinding) *func(WLANMeasurementResult) ECIDMeasurementInitiationResponseIEValue {
	return &v.inject
}
func BridgeSuccessfulOutcomeFieldPerPadding(v *SuccessfulOutcome) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeSuccessfulOutcomeFieldReceived(v *SuccessfulOutcome) *bool { return &v.received }
func BridgeSuccessfulOutcomeFieldReceivedBytes(v *SuccessfulOutcome) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeSuccessfulOutcomeFieldReplay(v *SuccessfulOutcome) *q4.Snapshot { return &v.replay }
func BridgeSuccessfulOutcomeFieldStream(v *SuccessfulOutcome) *q4.WireSpan { return &v.stream }
func BridgeSuccessfulOutcomeFieldWithoutReplay(v *SuccessfulOutcome) *bool { return &v.withoutReplay }
func BridgeSuccessfulOutcomeMethodMarshalAPERBudget(v *SuccessfulOutcome, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSuccessfulOutcomeMethodMarshalAPERChanged(v *SuccessfulOutcome, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSuccessfulOutcomeMethodMarshalAPERChangedValue(v *SuccessfulOutcome, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSuccessfulOutcomeMethodMarshalAPERFreshValue(v *SuccessfulOutcome, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeSuccessfulOutcomeMethodMarshalAPERLegacy(v *SuccessfulOutcome) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSuccessfulOutcomeMethodMarshalAPERPlanned(v *SuccessfulOutcome, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeSuccessfulOutcomeMethodMarshalAPERTo(v *SuccessfulOutcome, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSuccessfulOutcomeMethodUnmarshalAPERFrom(v *SuccessfulOutcome, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSuccessfulOutcomeMethodUnmarshalAPERLegacy(v *SuccessfulOutcome, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSuccessfulOutcomeMethodUnmarshalAPERWithOptions(v *SuccessfulOutcome, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSuccessfulValueFieldBodyECIDMeasurementInitiationResponse(v *SuccessfulValue) **ECIDMeasurementInitiationResponse {
	return &v.bodyECIDMeasurementInitiationResponse
}
func BridgeSuccessfulValueFieldBodyOTDOAInformationResponse(v *SuccessfulValue) **q15.OTDOAInformationResponse {
	return &v.bodyOTDOAInformationResponse
}
func BridgeSuccessfulValueFieldBodyUTDOAInformationResponse(v *SuccessfulValue) **q16.UTDOAInformationResponse {
	return &v.bodyUTDOAInformationResponse
}
func BridgeSuccessfulValueFieldCode(v *SuccessfulValue) *q5.ProcedureCode     { return &v.code }
func BridgeSuccessfulValueFieldIsOpaque(v *SuccessfulValue) *bool             { return &v.isOpaque }
func BridgeSuccessfulValueFieldOpaque(v *SuccessfulValue) **q4.OpaqueOpenType { return &v.opaque }
func BridgeSuccessfulValueFieldReceived(v *SuccessfulValue) *q4.WireSpan      { return &v.received }
func BridgeSuccessfulValueFieldReplay(v *SuccessfulValue) *q4.Snapshot        { return &v.replay }
func BridgeSuccessfulValueFieldWithoutReplay(v *SuccessfulValue) *bool        { return &v.withoutReplay }
func BridgeSuccessfulValueMethodCaptureFraming(v SuccessfulValue) uint64      { return v.captureFraming() }
func BridgeSuccessfulValueMethodCaptureSemantics(v SuccessfulValue, a0 q4.SemanticCapture) SuccessfulValue {
	return v.captureSemantics(a0)
}
func BridgeSuccessfulValueMethodCaptureSnapshot(v SuccessfulValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeSuccessfulValueMethodCompareSemantics(v SuccessfulValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeSuccessfulValueMethodEncode(v SuccessfulValue) ([]byte, error) { return v.encode() }
func BridgeSuccessfulValueMethodEncodeFresh(v SuccessfulValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeWLANMeasurementResultAPERValueFieldContext(v *WLANMeasurementResultAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementResultAPERValueFieldReceived(v *WLANMeasurementResultAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeWLANMeasurementResultAPERValueFieldReplay(v *WLANMeasurementResultAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementResultAPERValueFieldWithoutReplay(v *WLANMeasurementResultAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementResultCompleteFieldPerPadding(v *WLANMeasurementResultComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeWLANMeasurementResultCompleteFieldReceived(v *WLANMeasurementResultComplete) *bool {
	return &v.received
}
func BridgeWLANMeasurementResultCompleteFieldReceivedBytes(v *WLANMeasurementResultComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeWLANMeasurementResultCompleteFieldReplay(v *WLANMeasurementResultComplete) *q4.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementResultCompleteFieldStream(v *WLANMeasurementResultComplete) *q4.WireSpan {
	return &v.stream
}
func BridgeWLANMeasurementResultCompleteFieldWithoutReplay(v *WLANMeasurementResultComplete) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementResultCompleteMethodMarshalAPERBudget(v *WLANMeasurementResultComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeWLANMeasurementResultCompleteMethodMarshalAPERChanged(v *WLANMeasurementResultComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeWLANMeasurementResultCompleteMethodMarshalAPERChangedValue(v *WLANMeasurementResultComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeWLANMeasurementResultCompleteMethodMarshalAPERFreshValue(v *WLANMeasurementResultComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeWLANMeasurementResultCompleteMethodMarshalAPERLegacy(v *WLANMeasurementResultComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeWLANMeasurementResultCompleteMethodMarshalAPERPlanned(v *WLANMeasurementResultComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeWLANMeasurementResultCompleteMethodUnmarshalAPERLegacy(v *WLANMeasurementResultComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeWLANMeasurementResultCompleteMethodUnmarshalAPERWithOptions(v *WLANMeasurementResultComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeWLANMeasurementResultItemAPERValueFieldContext(v *WLANMeasurementResultItemAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementResultItemAPERValueFieldReceived(v *WLANMeasurementResultItemAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeWLANMeasurementResultItemAPERValueFieldReplay(v *WLANMeasurementResultItemAPERValue) *q4.Snapshot {
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
func BridgeWLANMeasurementResultItemFieldExtOrigin(v *WLANMeasurementResultItem) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeWLANMeasurementResultItemFieldExtPresent(v *WLANMeasurementResultItem) *[]bool {
	return &v.extPresent
}
func BridgeWLANMeasurementResultItemFieldExtWire(v *WLANMeasurementResultItem) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeWLANMeasurementResultItemFieldIEExtensionsIndef(v *WLANMeasurementResultItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeWLANMeasurementResultItemFieldPerExtPadding(v *WLANMeasurementResultItem) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeWLANMeasurementResultItemFieldPerPadding(v *WLANMeasurementResultItem) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeWLANMeasurementResultItemFieldReceived(v *WLANMeasurementResultItem) *bool {
	return &v.received
}
func BridgeWLANMeasurementResultItemFieldReceivedBytes(v *WLANMeasurementResultItem) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeWLANMeasurementResultItemFieldReplay(v *WLANMeasurementResultItem) *q4.Snapshot {
	return &v.replay
}
func BridgeWLANMeasurementResultItemFieldStream(v *WLANMeasurementResultItem) *q4.WireSpan {
	return &v.stream
}
func BridgeWLANMeasurementResultItemFieldWLANChannelListIndef(v *WLANMeasurementResultItem) *bool {
	return &v.wLANChannelListIndef
}
func BridgeWLANMeasurementResultItemFieldWithoutReplay(v *WLANMeasurementResultItem) *bool {
	return &v.withoutReplay
}
func BridgeWLANMeasurementResultItemMethodMarshalAPERBudget(v *WLANMeasurementResultItem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeWLANMeasurementResultItemMethodMarshalAPERChanged(v *WLANMeasurementResultItem, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeWLANMeasurementResultItemMethodMarshalAPERChangedValue(v *WLANMeasurementResultItem, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeWLANMeasurementResultItemMethodMarshalAPERFreshValue(v *WLANMeasurementResultItem, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeWLANMeasurementResultItemMethodMarshalAPERLegacy(v *WLANMeasurementResultItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeWLANMeasurementResultItemMethodMarshalAPERPlanned(v *WLANMeasurementResultItem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeWLANMeasurementResultItemMethodMarshalAPERTo(v *WLANMeasurementResultItem, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWLANMeasurementResultItemMethodUnmarshalAPERFrom(v *WLANMeasurementResultItem, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWLANMeasurementResultItemMethodUnmarshalAPERLegacy(v *WLANMeasurementResultItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeWLANMeasurementResultItemMethodUnmarshalAPERWithOptions(v *WLANMeasurementResultItem, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeWLANMeasurementResultItemValueCodecFieldCapture(v *WLANMeasurementResultItemValueCodec) *func(WLANMeasurementResultItem, q4.DecodeState) (WLANMeasurementResultItem, q4.Snapshot) {
	return &v.capture
}
func BridgeWLANMeasurementResultItemValueCodecFieldCompare(v *WLANMeasurementResultItemValueCodec) *func(WLANMeasurementResultItem, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeWLANMeasurementResultItemValueCodecFieldContext(v *WLANMeasurementResultItemValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementResultItemValueCodecFieldDecode(v *WLANMeasurementResultItemValueCodec) *func([]byte, q4.DecodeState) (WLANMeasurementResultItem, error) {
	return &v.decode
}
func BridgeWLANMeasurementResultItemValueCodecFieldEncode(v *WLANMeasurementResultItemValueCodec) *func(WLANMeasurementResultItem, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANMeasurementResultItemValueCodecFieldPath(v *WLANMeasurementResultItemValueCodec) *q4.Path {
	return &v.path
}
func BridgeWLANMeasurementResultItemValueCodecMethodEncodeBudget(v WLANMeasurementResultItemValueCodec, a0 WLANMeasurementResultItem, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANMeasurementResultItemValueCodecMethodEncodeChanged(v WLANMeasurementResultItemValueCodec, a0 WLANMeasurementResultItem, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWLANMeasurementResultValueCodecFieldCapture(v *WLANMeasurementResultValueCodec) *func(WLANMeasurementResult, q4.DecodeState) (WLANMeasurementResult, q4.Snapshot) {
	return &v.capture
}
func BridgeWLANMeasurementResultValueCodecFieldCompare(v *WLANMeasurementResultValueCodec) *func(WLANMeasurementResult, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeWLANMeasurementResultValueCodecFieldContext(v *WLANMeasurementResultValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeWLANMeasurementResultValueCodecFieldDecode(v *WLANMeasurementResultValueCodec) *func([]byte, q4.DecodeState) (WLANMeasurementResult, error) {
	return &v.decode
}
func BridgeWLANMeasurementResultValueCodecFieldEncode(v *WLANMeasurementResultValueCodec) *func(WLANMeasurementResult, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeWLANMeasurementResultValueCodecFieldPath(v *WLANMeasurementResultValueCodec) *q4.Path {
	return &v.path
}
func BridgeWLANMeasurementResultValueCodecMethodEncodeBudget(v WLANMeasurementResultValueCodec, a0 WLANMeasurementResult, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeWLANMeasurementResultValueCodecMethodEncodeChanged(v WLANMeasurementResultValueCodec, a0 WLANMeasurementResult, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
