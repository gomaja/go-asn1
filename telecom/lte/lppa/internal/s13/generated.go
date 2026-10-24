// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s13 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s13

import (
	q6 "fmt"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q11 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	q13 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s06"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s12"
	q7 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// ECIDMeasurementReportIEContainer is the concrete ProtocolIEContainer[ECIDMeasurementReportIEValue].
type ECIDMeasurementReportIEContainer []ECIDMeasurementReportIEField

// ECIDMeasurementReportIEField is the concrete ProtocolIEField[ECIDMeasurementReportIEValue].
type ECIDMeasurementReportIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         ECIDMeasurementReportIEValue

	received q4.CompletePadding
}

func (v ECIDMeasurementReportIEField) WithoutReplay() ECIDMeasurementReportIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ECIDMeasurementReportIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ECIDMeasurementReportIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
func (v *ECIDMeasurementReportIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementReportIEField{}
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
	var zero ECIDMeasurementReportIEValue

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
func BridgeECIDMeasurementReportIEValueCaptureLPPaProtocolIEContainer(v *ECIDMeasurementReportIEContainer, s *q4.SemanticCapture) {
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
func BridgeECIDMeasurementReportIEValueCompareLPPaProtocolIEContainer(v *ECIDMeasurementReportIEContainer, s *q4.SemanticComparison) {
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
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeResultRSRQItemExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q9.ResultRSRQItemExtIEsExtContainer, s *q4.SemanticCapture) {
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
			BridgeResultRSRQItemExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeResultRSRQItemExtIEsValueCompareLPPaProtocolExtensionContainer(v *q9.ResultRSRQItemExtIEsExtContainer, s *q4.SemanticComparison) {
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
			BridgeResultRSRQItemExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeResultUTRANItemExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q9.ResultUTRANItemExtIEsExtContainer, s *q4.SemanticCapture) {
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
func BridgeResultUTRANItemExtIEsValueCompareLPPaProtocolExtensionContainer(v *q9.ResultUTRANItemExtIEsExtContainer, s *q4.SemanticComparison) {
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
		s.End(f, q4.Snapshot{}, false)
	}
}

// ECIDMeasurementResultValueCodec is the concrete ValueCodec[ECIDMeasurementResult].
type ECIDMeasurementResultValueCodec struct {
	context q5.BridgeCodecContext
	capture func(ECIDMeasurementResult, q4.DecodeState,

	) (ECIDMeasurementResult, q4.Snapshot,

	)
	compare func(ECIDMeasurementResult, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (ECIDMeasurementResult,

		error)
	encode func(ECIDMeasurementResult,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c ECIDMeasurementResultValueCodec) New(value ECIDMeasurementResult,

) (ECIDMeasurementResultAPERValue, error) {
	if c.encode == nil {
		return ECIDMeasurementResultAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementResultAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ECIDMeasurementResultAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementResultAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c ECIDMeasurementResultValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (ECIDMeasurementResultAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ECIDMeasurementResultAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return ECIDMeasurementResultAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ECIDMeasurementResultAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return ECIDMeasurementResultAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return ECIDMeasurementResultAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ECIDMeasurementResultValueCodec) EncodeAPER(value ECIDMeasurementResultAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c ECIDMeasurementResultValueCodec) encodeBudget(value ECIDMeasurementResult,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ECIDMeasurementResultValueCodec) encodeChanged(value ECIDMeasurementResult,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// ECIDMeasurementReportMeasurementIDIEBinding is the concrete IEBinding[MeasurementID, ECIDMeasurementReportIEValue].
type ECIDMeasurementReportMeasurementIDIEBinding struct {
	info   q5.FieldInfo
	codec  q5.MeasurementIDValueCodec
	inject func(q5.MeasurementID,

	) ECIDMeasurementReportIEValue

	get func(*ECIDMeasurementReportIEValue,

	) (*q5.MeasurementID,

		bool)
}

func (b ECIDMeasurementReportMeasurementIDIEBinding) Info() q5.FieldInfo { return b.info }
func (b ECIDMeasurementReportMeasurementIDIEBinding) Codec() q5.MeasurementIDValueCodec {
	return b.codec
}
func (b ECIDMeasurementReportMeasurementIDIEBinding) New(value q5.MeasurementID,

) (ECIDMeasurementReportIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementReportIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementReportIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q5.BridgeMeasurementIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementReportIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementReportIEField{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementReportMeasurementIDIEBinding) Get(field *ECIDMeasurementReportIEField) (*q5.MeasurementID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementReportECIDMeasurementResultIEBinding is the concrete IEBinding[ECIDMeasurementResult, ECIDMeasurementReportIEValue].
type ECIDMeasurementReportECIDMeasurementResultIEBinding struct {
	info   q5.FieldInfo
	codec  ECIDMeasurementResultValueCodec
	inject func(ECIDMeasurementResult,

	) ECIDMeasurementReportIEValue

	get func(*ECIDMeasurementReportIEValue,

	) (*ECIDMeasurementResult,

		bool)
}

func (b ECIDMeasurementReportECIDMeasurementResultIEBinding) Info() q5.FieldInfo { return b.info }
func (b ECIDMeasurementReportECIDMeasurementResultIEBinding) Codec() ECIDMeasurementResultValueCodec {
	return b.codec
}
func (b ECIDMeasurementReportECIDMeasurementResultIEBinding) New(value ECIDMeasurementResult,

) (ECIDMeasurementReportIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementReportIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementReportIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return ECIDMeasurementReportIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementReportIEField{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementReportECIDMeasurementResultIEBinding) Get(field *ECIDMeasurementReportIEField) (*ECIDMeasurementResult,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementReportCellPortionIDIEBinding is the concrete IEBinding[CellPortionID, ECIDMeasurementReportIEValue].
type ECIDMeasurementReportCellPortionIDIEBinding struct {
	info   q5.FieldInfo
	codec  q5.CellPortionIDValueCodec
	inject func(q5.CellPortionID,

	) ECIDMeasurementReportIEValue

	get func(*ECIDMeasurementReportIEValue,

	) (*q5.CellPortionID,

		bool)
}

func (b ECIDMeasurementReportCellPortionIDIEBinding) Info() q5.FieldInfo { return b.info }
func (b ECIDMeasurementReportCellPortionIDIEBinding) Codec() q5.CellPortionIDValueCodec {
	return b.codec
}
func (b ECIDMeasurementReportCellPortionIDIEBinding) New(value q5.CellPortionID,

) (ECIDMeasurementReportIEField, error) {
	if b.inject == nil {
		return ECIDMeasurementReportIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementReportIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q5.BridgeCellPortionIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ECIDMeasurementReportIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return ECIDMeasurementReportIEField{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementReportIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b ECIDMeasurementReportCellPortionIDIEBinding) Get(field *ECIDMeasurementReportIEField) (*q5.CellPortionID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ECIDMeasurementReportValueCodec is the concrete ValueCodec[ECIDMeasurementReport].
type ECIDMeasurementReportValueCodec struct {
	context q5.BridgeCodecContext
	capture func(ECIDMeasurementReport, q4.DecodeState,

	) (ECIDMeasurementReport, q4.Snapshot,

	)
	compare func(ECIDMeasurementReport, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (ECIDMeasurementReport,

		error)
	encode func(ECIDMeasurementReport,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c ECIDMeasurementReportValueCodec) New(value ECIDMeasurementReport,

) (ECIDMeasurementReportAPERValue, error) {
	if c.encode == nil {
		return ECIDMeasurementReportAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ECIDMeasurementReportAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ECIDMeasurementReportAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return ECIDMeasurementReportAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c ECIDMeasurementReportValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (ECIDMeasurementReportAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ECIDMeasurementReportAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return ECIDMeasurementReportAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ECIDMeasurementReportAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return ECIDMeasurementReportAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return ECIDMeasurementReportAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ECIDMeasurementReportValueCodec) EncodeAPER(value ECIDMeasurementReportAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c ECIDMeasurementReportValueCodec) encodeBudget(value ECIDMeasurementReport,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ECIDMeasurementReportValueCodec) encodeChanged(value ECIDMeasurementReport,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// MeasuredResultsConcreteValueCodec is the concrete ValueCodec[MeasuredResults].
type MeasuredResultsConcreteValueCodec struct {
	context q5.BridgeCodecContext
	capture func(MeasuredResults, q4.DecodeState,

	) (MeasuredResults, q4.Snapshot,

	)
	compare func(MeasuredResults, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (MeasuredResults,

		error)
	encode func(MeasuredResults,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c MeasuredResultsConcreteValueCodec) New(value MeasuredResults,

) (MeasuredResultsAPERValue, error) {
	if c.encode == nil {
		return MeasuredResultsAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return MeasuredResultsAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MeasuredResultsAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return MeasuredResultsAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c MeasuredResultsConcreteValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (MeasuredResultsAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return MeasuredResultsAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return MeasuredResultsAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return MeasuredResultsAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return MeasuredResultsAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return MeasuredResultsAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c MeasuredResultsConcreteValueCodec) EncodeAPER(value MeasuredResultsAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c MeasuredResultsConcreteValueCodec) encodeBudget(value MeasuredResults,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c MeasuredResultsConcreteValueCodec) encodeChanged(value MeasuredResults,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// MeasuredResultsValueValueCodec is the concrete ValueCodec[MeasuredResultsValue].
type MeasuredResultsValueValueCodec struct {
	context q5.BridgeCodecContext
	capture func(MeasuredResultsValue, q4.DecodeState,

	) (MeasuredResultsValue, q4.Snapshot,

	)
	compare func(MeasuredResultsValue, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (MeasuredResultsValue,

		error)
	encode func(MeasuredResultsValue,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c MeasuredResultsValueValueCodec) New(value MeasuredResultsValue,

) (MeasuredResultsValueAPERValue, error) {
	if c.encode == nil {
		return MeasuredResultsValueAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return MeasuredResultsValueAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return MeasuredResultsValueAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return MeasuredResultsValueAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c MeasuredResultsValueValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (MeasuredResultsValueAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return MeasuredResultsValueAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return MeasuredResultsValueAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return MeasuredResultsValueAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return MeasuredResultsValueAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return MeasuredResultsValueAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c MeasuredResultsValueValueCodec) EncodeAPER(value MeasuredResultsValueAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c MeasuredResultsValueValueCodec) encodeBudget(value MeasuredResultsValue,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c MeasuredResultsValueValueCodec) encodeChanged(value MeasuredResultsValue,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// ResultRSRQValueCodec is the concrete ValueCodec[ResultRSRQ].
type ResultRSRQValueCodec struct {
	context q5.BridgeCodecContext
	capture func(ResultRSRQ, q4.DecodeState,

	) (ResultRSRQ, q4.Snapshot,

	)
	compare func(ResultRSRQ, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (ResultRSRQ,

		error)
	encode func(ResultRSRQ,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c ResultRSRQValueCodec) New(value ResultRSRQ,

) (ResultRSRQAPERValue, error) {
	if c.encode == nil {
		return ResultRSRQAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ResultRSRQAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultRSRQAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return ResultRSRQAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c ResultRSRQValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (ResultRSRQAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultRSRQAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return ResultRSRQAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultRSRQAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return ResultRSRQAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return ResultRSRQAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ResultRSRQValueCodec) EncodeAPER(value ResultRSRQAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c ResultRSRQValueCodec) encodeBudget(value ResultRSRQ,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultRSRQValueCodec) encodeChanged(value ResultRSRQ,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// ResultRSRQItemValueCodec is the concrete ValueCodec[ResultRSRQItem].
type ResultRSRQItemValueCodec struct {
	context q5.BridgeCodecContext
	capture func(ResultRSRQItem, q4.DecodeState,

	) (ResultRSRQItem, q4.Snapshot,

	)
	compare func(ResultRSRQItem, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (ResultRSRQItem,

		error)
	encode func(ResultRSRQItem,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c ResultRSRQItemValueCodec) New(value ResultRSRQItem,

) (ResultRSRQItemAPERValue, error) {
	if c.encode == nil {
		return ResultRSRQItemAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ResultRSRQItemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultRSRQItemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return ResultRSRQItemAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c ResultRSRQItemValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (ResultRSRQItemAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultRSRQItemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return ResultRSRQItemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultRSRQItemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return ResultRSRQItemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return ResultRSRQItemAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ResultRSRQItemValueCodec) EncodeAPER(value ResultRSRQItemAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c ResultRSRQItemValueCodec) encodeBudget(value ResultRSRQItem,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultRSRQItemValueCodec) encodeChanged(value ResultRSRQItem,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeECIDMeasurementReportIEValueValidateLPPaIEContainer(fields ECIDMeasurementReportIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

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
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.ValueIDMismatch, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q5.TableID {
				sealed := q5.TableID{}
				*q5.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q9.BridgeLppaValidationRule(q5.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q5.FieldInfo
			related := []q4.SourceRule{q9.BridgeLppaAdoptedRule(q5.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.RepeatedIE, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q9.BridgeLppaValidationRule(q5.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q5.ValidationSeverityUnrecognized
			if _, globallyKnown := q9.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q5.ValidationSeverityError
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q9.BridgeLppaValidationRule(q5.NotAllowed), RelatedRules: q9.BridgeLppaHandlingRules(q5.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongCriticality, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q9.BridgeLppaValidationRule(q5.WrongCriticality), RelatedRules: []q4.SourceRule{q9.BridgeLppaAdoptedRule(q5.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongOrder, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q9.BridgeLppaValidationRule(q5.WrongOrder), RelatedRules: []q4.SourceRule{q9.BridgeLppaAdoptedRule(q5.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q5.PresenceMandatory && counts[row.ID] == 0 {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.MissingMandatory, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q9.BridgeLppaValidationRule(q5.MissingMandatory), RelatedRules: []q4.SourceRule{q9.BridgeLppaAdoptedRule(q5.MissingMandatory), row.Rule}})
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
func BridgeResultRSRQItemExtIEsValueValidateLPPaExtensionContainer(fields q9.ResultRSRQItemExtIEsExtContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget) q10.ValidationReport {
	bb := q4.NewBudgetBuffer(budget)
	if err := q4.ChargeSlice[q9.ResultRSRQItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q10.ValidationReport {
			sealed := q10.ValidationReport{}
			*q10.BridgeValidationReportFieldErr(&sealed) = err
			*q10.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q9.ResultRSRQItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeResultRSRQItemExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}

// eCIDMeasurementReportIEValueProtocolOpenValue is the concrete protocolOpenValue[ECIDMeasurementReportIEValue].
type ECIDMeasurementReportIEValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) ECIDMeasurementReportIEValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (ECIDMeasurementReportIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

func BridgeECIDMeasurementReportIEValueCaptureLPPaProtocolIEField(v *ECIDMeasurementReportIEField, s *q4.SemanticCapture) {
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
func BridgeECIDMeasurementReportIEValueCompareLPPaProtocolIEField(v *ECIDMeasurementReportIEField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q11.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q11.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// resultRSRQItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ResultRSRQItemExtIEsValue].
type ResultRSRQItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) q8.ResultRSRQItemExtIEsValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (q8.ResultRSRQItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

func BridgeResultRSRQItemExtIEsValueCaptureLPPaProtocolExtensionField(v *q9.ResultRSRQItemExtIEsExtField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q9.BridgeResultRSRQItemExtIEsExtFieldFieldStream(v))
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q8.BridgeResultRSRQItemExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q8.BridgeResultRSRQItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q8.BridgeResultRSRQItemExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q9.BridgeResultRSRQItemExtIEsExtFieldFieldReplay(v), *q9.BridgeResultRSRQItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeResultRSRQItemExtIEsValueCompareLPPaProtocolExtensionField(v *q9.ResultRSRQItemExtIEsExtField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q11.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q11.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q8.BridgeResultRSRQItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q9.BridgeResultRSRQItemExtIEsExtFieldFieldReplay(v), *q9.BridgeResultRSRQItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeResultUTRANItemExtIEsValueCaptureLPPaProtocolExtensionField(v *q9.ResultUTRANItemExtIEsExtField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q9.BridgeResultUTRANItemExtIEsExtFieldFieldStream(v))
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q8.BridgeResultUTRANItemExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q8.BridgeResultUTRANItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q8.BridgeResultUTRANItemExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q9.BridgeResultUTRANItemExtIEsExtFieldFieldReplay(v), *q9.BridgeResultUTRANItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeResultUTRANItemExtIEsValueCompareLPPaProtocolExtensionField(v *q9.ResultUTRANItemExtIEsExtField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q11.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q11.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q8.BridgeResultUTRANItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q9.BridgeResultUTRANItemExtIEsExtFieldFieldReplay(v), *q9.BridgeResultUTRANItemExtIEsExtFieldFieldWithoutReplay(v))
}

// ECIDMeasurementResultAPERValue is the concrete APERValue[ECIDMeasurementResult].
type ECIDMeasurementResultAPERValue struct {
	context q5.BridgeCodecContext
	Value   ECIDMeasurementResult

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v ECIDMeasurementResultAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v ECIDMeasurementResultAPERValue) WithoutReplay() ECIDMeasurementResultAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// ECIDMeasurementReportAPERValue is the concrete APERValue[ECIDMeasurementReport].
type ECIDMeasurementReportAPERValue struct {
	context q5.BridgeCodecContext
	Value   ECIDMeasurementReport

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v ECIDMeasurementReportAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v ECIDMeasurementReportAPERValue) WithoutReplay() ECIDMeasurementReportAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasuredResultsAPERValue is the concrete APERValue[MeasuredResults].
type MeasuredResultsAPERValue struct {
	context q5.BridgeCodecContext
	Value   MeasuredResults

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v MeasuredResultsAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v MeasuredResultsAPERValue) WithoutReplay() MeasuredResultsAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// MeasuredResultsValueAPERValue is the concrete APERValue[MeasuredResultsValue].
type MeasuredResultsValueAPERValue struct {
	context q5.BridgeCodecContext
	Value   MeasuredResultsValue

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v MeasuredResultsValueAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v MeasuredResultsValueAPERValue) WithoutReplay() MeasuredResultsValueAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultRSRQAPERValue is the concrete APERValue[ResultRSRQ].
type ResultRSRQAPERValue struct {
	context q5.BridgeCodecContext
	Value   ResultRSRQ

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v ResultRSRQAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v ResultRSRQAPERValue) WithoutReplay() ResultRSRQAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultRSRQItemAPERValue is the concrete APERValue[ResultRSRQItem].
type ResultRSRQItemAPERValue struct {
	context q5.BridgeCodecContext
	Value   ResultRSRQItem

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v ResultRSRQItemAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v ResultRSRQItemAPERValue) WithoutReplay() ResultRSRQItemAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeResultRSRQItemExtIEsValueValidateLPPaIEContainer(fields q9.ResultRSRQItemExtIEsIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

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
		if !q8.BridgeResultRSRQItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q8.BridgeResultRSRQItemExtIEsValueMethodRule(field.Value)
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.ValueIDMismatch, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.id", location.Path))}, Table: func() q5.TableID {
				sealed := q5.TableID{}
				*q5.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: q9.BridgeLppaValidationRule(q5.ValueIDMismatch), RelatedRules: []q4.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		q4.IncrementCount( // TS 36.455 V19.0.0 §10 adopts TS 36.413 V19.2.0 §10.3.6,
			// including repetition of unknown selectors.
			counts, field.Id)
		if counts[field.Id] > 1 {
			var row q5.FieldInfo
			related := []q4.SourceRule{q9.BridgeLppaAdoptedRule(q5.RepeatedIE)}
			if allowed {
				row = rows[rank]
				related = append(related, row.Rule)
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.RepeatedIE, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q9.BridgeLppaValidationRule(q5.RepeatedIE), RelatedRules: related})
		}
		if !allowed {
			severity := q5.ValidationSeverityUnrecognized
			if _, globallyKnown := q9.BridgeKnownLPPaIEIDs[field.Id]; globallyKnown {
				severity = q5.ValidationSeverityError
			}
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.NotAllowed, Severity: severity, Location: location, IEID: field.Id, HasIEID: true, Rule: q9.BridgeLppaValidationRule(q5.NotAllowed), RelatedRules: q9.BridgeLppaHandlingRules(q5.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongCriticality, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(q6.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: q9.BridgeLppaValidationRule(q5.WrongCriticality), RelatedRules: []q4.SourceRule{q9.BridgeLppaAdoptedRule(q5.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.WrongOrder, Severity: q5.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: q9.BridgeLppaValidationRule(q5.WrongOrder), RelatedRules: []q4.SourceRule{q9.BridgeLppaAdoptedRule(q5.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == q5.PresenceMandatory && counts[row.ID] == 0 {
			q10.BridgeValidationReportMethodAddIssue(&report, q10.ValidationIssue{Code: q5.MissingMandatory, Severity: q5.ValidationSeverityError, Location: q4.Location{Path: q4.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: q9.BridgeLppaValidationRule(q5.MissingMandatory), RelatedRules: []q4.SourceRule{q9.BridgeLppaAdoptedRule(q5.MissingMandatory), row.Rule}})
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

// ECIDMeasurementResult represents the ASN.1 type E-CID-MeasurementResult (SEQUENCE).
type ECIDMeasurementResult struct {
	replay                    q4.Snapshot
	stream                    q4.WireSpan
	withoutReplay             bool
	received                  bool
	receivedBytes             q4.WireSpan
	ServingCellID             q12.ECGI                       `asn1:"tag:0,context,implicit"`
	ServingCellTAC            q5.TAC                         `asn1:"tag:1,context,implicit"`
	EUTRANAccessPointPosition *q13.EUTRANAccessPointPosition `asn1:"tag:2,context,implicit,optional" json:"EUTRANAccessPointPosition,omitempty"`
	MeasuredResults           MeasuredResults                `asn1:"tag:3,context,implicit,optional" json:"MeasuredResults,omitzero"`
	measuredResultsIndef      bool                           `asn1:"-" json:"-"`
	extCount                  int64                          `asn1:"-" json:"-"`
	extPresent                []bool                         `asn1:"-" json:"-"`
	extData                   [][]byte                       `asn1:"-" json:"-"`
	perPadding                q4.FinalPadding                `asn1:"-" json:"-"`
	perExtPadding             []q4.CompletePadding           `asn1:"-" json:"-"`
	extOrigin                 []q4.OpaqueOrigin
	extWire                   []q4.WireSpan
}
type MeasuredResults = []MeasuredResultsValue

// MeasuredResultsValue represents the ASN.1 CHOICE type MeasuredResultsValue.
type MeasuredResultsValue struct {
	knownOpenBytes          uint64
	replay                  q4.Snapshot
	stream                  q4.WireSpan
	withoutReplay           bool
	received                bool
	receivedBytes           q4.WireSpan
	Choice                  int
	perPadding              q4.CompletePadding  `json:"-"`
	perOpenTypePadding      q4.CompletePadding  `json:"-"`
	UnknownExtension        *q4.ChoiceExtension `json:"UnknownExtension,omitempty"`
	ValueAngleOfArrival     *int64              `json:"ValueAngleOfArrival,omitempty"`
	ValueTimingAdvanceType1 *int64              `json:"ValueTimingAdvanceType1,omitempty"`
	ValueTimingAdvanceType2 *int64              `json:"ValueTimingAdvanceType2,omitempty"`
	ResultRSRP              q14.ResultRSRP      `json:"ResultRSRP,omitzero"`
	ResultRSRQ              ResultRSRQ          `json:"ResultRSRQ,omitzero"`
}

// NewMeasuredResultsValueValueAngleOfArrival creates a MeasuredResultsValue with the valueAngleOfArrival alternative.
func BridgeNewMeasuredResultsValueValueAngleOfArrivalLegacy(v int64) MeasuredResultsValue {
	return MeasuredResultsValue{
		Choice:              q5.MeasuredResultsValueChoiceValueAngleOfArrival,
		ValueAngleOfArrival: &v,
	}
}

// NewMeasuredResultsValueValueTimingAdvanceType1 creates a MeasuredResultsValue with the valueTimingAdvanceType1 alternative.
func BridgeNewMeasuredResultsValueValueTimingAdvanceType1Legacy(v int64) MeasuredResultsValue {
	return MeasuredResultsValue{
		Choice:                  q5.MeasuredResultsValueChoiceValueTimingAdvanceType1,
		ValueTimingAdvanceType1: &v,
	}
}

// NewMeasuredResultsValueValueTimingAdvanceType2 creates a MeasuredResultsValue with the valueTimingAdvanceType2 alternative.
func BridgeNewMeasuredResultsValueValueTimingAdvanceType2Legacy(v int64) MeasuredResultsValue {
	return MeasuredResultsValue{
		Choice:                  q5.MeasuredResultsValueChoiceValueTimingAdvanceType2,
		ValueTimingAdvanceType2: &v,
	}
}

// NewMeasuredResultsValueResultRSRP creates a MeasuredResultsValue with the resultRSRP alternative.
func BridgeNewMeasuredResultsValueResultRSRPLegacy(v q14.ResultRSRP) MeasuredResultsValue {
	return MeasuredResultsValue{
		Choice:     q5.MeasuredResultsValueChoiceResultRSRP,
		ResultRSRP: v,
	}
}

// NewMeasuredResultsValueResultRSRQ creates a MeasuredResultsValue with the resultRSRQ alternative.
func BridgeNewMeasuredResultsValueResultRSRQLegacy(v ResultRSRQ) MeasuredResultsValue {
	return MeasuredResultsValue{
		Choice:     q5.MeasuredResultsValueChoiceResultRSRQ,
		ResultRSRQ: v,
	}
}

type ResultRSRQ = []ResultRSRQItem

// ResultRSRQItem represents the ASN.1 type ResultRSRQ-Item (SEQUENCE).
type ResultRSRQItem struct {
	replay            q4.Snapshot
	stream            q4.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     q4.WireSpan
	PCI               q5.PCI                              `asn1:"tag:0,context,implicit"`
	EARFCN            q5.EARFCN                           `asn1:"tag:1,context,implicit"`
	ECGI              *q12.ECGI                           `asn1:"tag:2,context,implicit,optional" json:"ECGI,omitempty"`
	ValueRSRQ         q5.ValueRSRQ                        `asn1:"tag:3,context,implicit"`
	IEExtensions      q9.ResultRSRQItemExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                `asn1:"-" json:"-"`
	extCount          int64                               `asn1:"-" json:"-"`
	extPresent        []bool                              `asn1:"-" json:"-"`
	extData           [][]byte                            `asn1:"-" json:"-"`
	perPadding        q4.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding     []q4.CompletePadding                `asn1:"-" json:"-"`
	extOrigin         []q4.OpaqueOrigin
	extWire           []q4.WireSpan
}

// MarshalAPER encodes ECIDMeasurementResult to APER format.
func (v *ECIDMeasurementResult) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ECIDMeasurementResult) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = q12.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := q4.EncodeBoolean(bb, v.EUTRANAccessPointPosition != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.MeasuredResults != nil); err != nil {
		return err
	}
	if err := q12.BridgeECGIMethodMarshalAPERTo(&v.ServingCellID, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return q6.Errorf("encoding servingCell-ID: %w", err)
	}
	if err := q4.EncodeOctetStringAligned(bb, []byte(v.ServingCellTAC), 2, 2, true); err != nil {
		return q6.Errorf("encoding servingCellTAC: %w", err)
	}
	if v.EUTRANAccessPointPosition != nil {
		if err := q13.BridgeEUTRANAccessPointPositionMethodMarshalAPERTo(v.EUTRANAccessPointPosition, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return q6.Errorf("encoding e-UTRANAccessPointPosition: %w", err)
		}
	}
	if v.MeasuredResults != nil {
		if err := q4.EncodeCollection(bb, int64(len(v.MeasuredResults)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_measuredresults, fragmentLength_measuredresults int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_measuredresults < 0 || fragmentOffset_measuredresults > int64(len(v.MeasuredResults)) || fragmentLength_measuredresults < 0 || fragmentLength_measuredresults > int64(len(v.MeasuredResults[fragmentOffset_measuredresults:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.MeasuredResults[fragmentOffset_measuredresults : fragmentOffset_measuredresults+fragmentLength_measuredresults] {
				if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
					return q6.Errorf("encoding measuredResults element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return q6.Errorf("encoding measuredResults: %w", err)
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

// UnmarshalAPER decodes ECIDMeasurementResult from APER format.
func (v *ECIDMeasurementResult) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ECIDMeasurementResult with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ECIDMeasurementResult) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "ECIDMeasurementResult")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "ECIDMeasurementResult")
	}
	padding, err := q4.CaptureFinalBits(bb, "ECIDMeasurementResult")
	if err != nil {
		return q7.WrapDecodePath(err, "ECIDMeasurementResult")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ECIDMeasurementResult) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementResult{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_eutranaccesspointposition, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_measuredresults, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_servingcellid := bb.EnterComponent("ServingCellID")
	if err := q12.BridgeECGIMethodUnmarshalAPERFrom(&v.ServingCellID, bb); err != nil {
		return q7.WrapDecodePath(err, "ServingCellID")
	}
	bb.LeaveComponent(toleranceMark_servingcellid)
	val_servingcelltac, err := q4.DecodeOctetStringAligned(bb, 2, 2, true)
	if err != nil {
		return q7.WrapDecodePath(err, "ServingCellTAC")
	}
	v.ServingCellTAC = q5.TAC(val_servingcelltac)
	if opt_eutranaccesspointposition {
		toleranceMark_eutranaccesspointposition := bb.EnterComponent("EUTRANAccessPointPosition")
		var dec_eutranaccesspointposition q13.EUTRANAccessPointPosition
		if err := q13.BridgeEUTRANAccessPointPositionMethodUnmarshalAPERFrom(&dec_eutranaccesspointposition, bb); err != nil {
			return q7.WrapDecodePath(err, "EUTRANAccessPointPosition")
		}
		if err := q4.ChargeValue(bb, dec_eutranaccesspointposition); err != nil {
			return err
		}
		v.EUTRANAccessPointPosition = &dec_eutranaccesspointposition
		bb.LeaveComponent(toleranceMark_eutranaccesspointposition)
	}
	if opt_measuredresults {
		toleranceMark_measuredresults := bb.EnterComponent("MeasuredResults")
		tmp_measuredresults := make(MeasuredResults, 0)
		_, errCollection_measuredresults := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 63, HasUpper: true}, true, func(fragmentOffset_measuredresults, fragmentLength_measuredresults int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_measuredresults < 0 || fragmentLength_measuredresults < 0 || fragmentLength_measuredresults > int64(^uint(0)>>1) || fragmentOffset_measuredresults > int64(^uint(0)>>1)-fragmentLength_measuredresults {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_measuredresults; i++ {
				var elem MeasuredResultsValue
				elementMark := bb.EnterIndex(fragmentOffset_measuredresults + i)
				if err := elem.unmarshalAPERFrom(bb); err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("MeasuredResults[%d]", fragmentOffset_measuredresults+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := q4.AppendValues(bb, tmp_measuredresults, elem); err != nil {
					return err
				} else {
					tmp_measuredresults = next
				}
			}
			return nil
		})
		if errCollection_measuredresults != nil {
			return q7.WrapDecodePath(errCollection_measuredresults, "MeasuredResults")
		}
		v.MeasuredResults = tmp_measuredresults
		bb.LeaveComponent(toleranceMark_measuredresults)
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

type BridgeAsn1cAPERMeasuredResultsListValue struct{ Value MeasuredResults }

// MarshalAPERMeasuredResultsTo appends a MeasuredResults list to bb.
func BridgeMarshalAPERMeasuredResultsTo(list MeasuredResults, bb *q4.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERMeasuredResultsListValue{Value: list}
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

// MarshalAPER encodes MeasuredResultsValue to APER format.
func (v *MeasuredResultsValue) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *MeasuredResultsValue) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
			return q6.Errorf("%s known choice %d and unknown extension are both selected", "MeasuredResultsValue:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return q6.Errorf("%s extension index %d must be non-negative", "MeasuredResultsValue:", v.UnknownExtension.Index())
		}
		if err := q4.EncodeBoolean(bb, true); err != nil {
			return err
		}
		if err := q4.EncodeNormallySmallNonNegativeAligned(bb, v.UnknownExtension.Index()); err != nil {
			return err
		}
		return v.UnknownExtension.EncodeTo(bb)
	}
	if v.Choice < 1 {
		return q6.Errorf("%s choice %d must be positive", "MeasuredResultsValue:", v.Choice)
	}
	isExtension := v.Choice > 5
	if err := q4.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		return q6.Errorf("%s extension choice %d not supported", "MeasuredResultsValue:", v.Choice)
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return q6.Errorf("choice index outside root")
	}
	if err := q4.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 4); err != nil {
		return err
	}
	switch v.Choice {
	case q5.MeasuredResultsValueChoiceValueAngleOfArrival:
		if v.ValueAngleOfArrival == nil {
			return q6.Errorf("choice alternative valueAngleOfArrival is nil")
		}
		if err := q4.EncodeIntegerAligned(bb, int64(*v.ValueAngleOfArrival), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(719), false); err != nil {
			return q6.Errorf("encoding valueAngleOfArrival: %w", err)
		}
	case q5.MeasuredResultsValueChoiceValueTimingAdvanceType1:
		if v.ValueTimingAdvanceType1 == nil {
			return q6.Errorf("choice alternative valueTimingAdvanceType1 is nil")
		}
		if err := q4.EncodeIntegerAligned(bb, int64(*v.ValueTimingAdvanceType1), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(7690), false); err != nil {
			return q6.Errorf("encoding valueTimingAdvanceType1: %w", err)
		}
	case q5.MeasuredResultsValueChoiceValueTimingAdvanceType2:
		if v.ValueTimingAdvanceType2 == nil {
			return q6.Errorf("choice alternative valueTimingAdvanceType2 is nil")
		}
		if err := q4.EncodeIntegerAligned(bb, int64(*v.ValueTimingAdvanceType2), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(7690), false); err != nil {
			return q6.Errorf("encoding valueTimingAdvanceType2: %w", err)
		}
	case q5.MeasuredResultsValueChoiceResultRSRP:
		if err := q4.EncodeCollection(bb, int64(len(v.ResultRSRP)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_resultrsrp, fragmentLength_resultrsrp int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_resultrsrp < 0 || fragmentOffset_resultrsrp > int64(len(v.ResultRSRP)) || fragmentLength_resultrsrp < 0 || fragmentLength_resultrsrp > int64(len(v.ResultRSRP[fragmentOffset_resultrsrp:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.ResultRSRP[fragmentOffset_resultrsrp : fragmentOffset_resultrsrp+fragmentLength_resultrsrp] {
				if err := q14.BridgeResultRSRPItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return q6.Errorf("encoding resultRSRP element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return q6.Errorf("encoding resultRSRP: %w", err)
		}
	case q5.MeasuredResultsValueChoiceResultRSRQ:
		if err := q4.EncodeCollection(bb, int64(len(v.ResultRSRQ)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_resultrsrq, fragmentLength_resultrsrq int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_resultrsrq < 0 || fragmentOffset_resultrsrq > int64(len(v.ResultRSRQ)) || fragmentLength_resultrsrq < 0 || fragmentLength_resultrsrq > int64(len(v.ResultRSRQ[fragmentOffset_resultrsrq:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.ResultRSRQ[fragmentOffset_resultrsrq : fragmentOffset_resultrsrq+fragmentLength_resultrsrq] {
				if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
					return q6.Errorf("encoding resultRSRQ element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return q6.Errorf("encoding resultRSRQ: %w", err)
		}
	default:
		return q6.Errorf("unknown MeasuredResultsValue choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes MeasuredResultsValue from APER format.
func (v *MeasuredResultsValue) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes MeasuredResultsValue with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *MeasuredResultsValue) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "MeasuredResultsValue")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "MeasuredResultsValue")
	}
	padding, err := q4.CaptureFinalBits(bb, "MeasuredResultsValue")
	if err != nil {
		return q7.WrapDecodePath(err, "MeasuredResultsValue")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *MeasuredResultsValue) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = MeasuredResultsValue{}
	isExtension, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := q4.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return q7.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := q4.DecodeChoiceExtensionAligned(bb, extIdx, 0)
		if extIdx < 0 {
			v.knownOpenBytes = max(v.knownOpenBytes, openExtension.ContentLength())
		}
		if err != nil {
			return q7.WrapDecodePath(err, "UnknownExtension")
		}
		v.UnknownExtension = &openExtension
		v.stream = bb.CaptureWireSpan(replayStart)
		v.
			stream.RecordUsage(replayUsage,

			bb)

		return nil
	}
	idx, err := q4.DecodeConstrainedWholeNumberAligned(bb, 0, 4)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return q6.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case q5.MeasuredResultsValueChoiceValueAngleOfArrival:
		val_valueangleofarrival, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(719), false)
		if err != nil {
			return q7.WrapDecodePath(err, "ValueAngleOfArrival")
		}
		if err := q4.ChargeValue(bb, val_valueangleofarrival); err != nil {
			return err
		}
		v.ValueAngleOfArrival = (*int64)(bb.OwnInt64(int64(val_valueangleofarrival)))
	case q5.MeasuredResultsValueChoiceValueTimingAdvanceType1:
		val_valuetimingadvancetype1, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(7690), false)
		if err != nil {
			return q7.WrapDecodePath(err, "ValueTimingAdvanceType1")
		}
		if err := q4.ChargeValue(bb, val_valuetimingadvancetype1); err != nil {
			return err
		}
		v.ValueTimingAdvanceType1 = (*int64)(bb.OwnInt64(int64(val_valuetimingadvancetype1)))
	case q5.MeasuredResultsValueChoiceValueTimingAdvanceType2:
		val_valuetimingadvancetype2, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(7690), false)
		if err != nil {
			return q7.WrapDecodePath(err, "ValueTimingAdvanceType2")
		}
		if err := q4.ChargeValue(bb, val_valuetimingadvancetype2); err != nil {
			return err
		}
		v.ValueTimingAdvanceType2 = (*int64)(bb.OwnInt64(int64(val_valuetimingadvancetype2)))
	case q5.MeasuredResultsValueChoiceResultRSRP:
		toleranceMark_resultrsrp := bb.EnterComponent("ResultRSRP")
		tmp_resultrsrp := make(q14.ResultRSRP, 0)
		_, errCollection_resultrsrp := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_resultrsrp, fragmentLength_resultrsrp int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_resultrsrp < 0 || fragmentLength_resultrsrp < 0 || fragmentLength_resultrsrp > int64(^uint(0)>>1) || fragmentOffset_resultrsrp > int64(^uint(0)>>1)-fragmentLength_resultrsrp {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_resultrsrp; i++ {
				var elem q14.ResultRSRPItem
				elementMark := bb.EnterIndex(fragmentOffset_resultrsrp + i)
				if err := q14.BridgeResultRSRPItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("ResultRSRP[%d]", fragmentOffset_resultrsrp+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := q4.AppendValues(bb, tmp_resultrsrp, elem); err != nil {
					return err
				} else {
					tmp_resultrsrp = next
				}
			}
			return nil
		})
		if errCollection_resultrsrp != nil {
			return q7.WrapDecodePath(errCollection_resultrsrp, "ResultRSRP")
		}
		v.ResultRSRP = tmp_resultrsrp
		bb.LeaveComponent(toleranceMark_resultrsrp)
	case q5.MeasuredResultsValueChoiceResultRSRQ:
		toleranceMark_resultrsrq := bb.EnterComponent("ResultRSRQ")
		tmp_resultrsrq := make(ResultRSRQ, 0)
		_, errCollection_resultrsrq := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_resultrsrq, fragmentLength_resultrsrq int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_resultrsrq < 0 || fragmentLength_resultrsrq < 0 || fragmentLength_resultrsrq > int64(^uint(0)>>1) || fragmentOffset_resultrsrq > int64(^uint(0)>>1)-fragmentLength_resultrsrq {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_resultrsrq; i++ {
				var elem ResultRSRQItem
				elementMark := bb.EnterIndex(fragmentOffset_resultrsrq + i)
				if err := elem.unmarshalAPERFrom(bb); err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("ResultRSRQ[%d]", fragmentOffset_resultrsrq+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := q4.AppendValues(bb, tmp_resultrsrq, elem); err != nil {
					return err
				} else {
					tmp_resultrsrq = next
				}
			}
			return nil
		})
		if errCollection_resultrsrq != nil {
			return q7.WrapDecodePath(errCollection_resultrsrq, "ResultRSRQ")
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
func BridgeMarshalAPERResultRSRQTo(list ResultRSRQ, bb *q4.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERResultRSRQListValue{Value: list}
	if err := q4.EncodeCollection(bb, int64(len(v.Value)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ResultRSRQItem to APER format.
func (v *ResultRSRQItem) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ResultRSRQItem) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = q12.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := q4.EncodeBoolean(bb, v.ECGI != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q4.EncodeIntegerBigBoundsAligned(bb, v.PCI, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound17, true); err != nil {
		return q6.Errorf("encoding pCI: %w", err)
	}
	if err := q4.EncodeIntegerBigBoundsAligned(bb, v.EARFCN, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound20, true); err != nil {
		return q6.Errorf("encoding eARFCN: %w", err)
	}
	if v.ECGI != nil {
		if err := q12.BridgeECGIMethodMarshalAPERTo(v.ECGI, bb, len(fresh) != 0 && fresh[0]); err != nil {
			return q6.Errorf("encoding eCGI: %w", err)
		}
	}
	if err := q4.EncodeIntegerBigBoundsAligned(bb, v.ValueRSRQ, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound13, true); err != nil {
		return q6.Errorf("encoding valueRSRQ: %w", err)
	}
	if v.IEExtensions != nil {
		if err := q4.EncodeCollection(bb, int64(len(v.IEExtensions)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q9.BridgeResultRSRQItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ResultRSRQItem from APER format.
func (v *ResultRSRQItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResultRSRQItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResultRSRQItem) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "ResultRSRQItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "ResultRSRQItem")
	}
	padding, err := q4.CaptureFinalBits(bb, "ResultRSRQItem")
	if err != nil {
		return q7.WrapDecodePath(err, "ResultRSRQItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ResultRSRQItem) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultRSRQItem{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ecgi, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_pci, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound17, true)
	if err != nil {
		return q7.WrapDecodePath(err, "PCI")
	}
	v.PCI = val_pci
	val_earfcn, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound20, true)
	if err != nil {
		return q7.WrapDecodePath(err, "EARFCN")
	}
	v.EARFCN = val_earfcn
	if opt_ecgi {
		toleranceMark_ecgi := bb.EnterComponent("ECGI")
		var dec_ecgi q12.ECGI
		if err := q12.BridgeECGIMethodUnmarshalAPERFrom(&dec_ecgi, bb); err != nil {
			return q7.WrapDecodePath(err, "ECGI")
		}
		if err := q4.ChargeValue(bb, dec_ecgi); err != nil {
			return err
		}
		v.ECGI = &dec_ecgi
		bb.LeaveComponent(toleranceMark_ecgi)
	}
	val_valuersrq, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound13, true)
	if err != nil {
		return q7.WrapDecodePath(err, "ValueRSRQ")
	}
	v.ValueRSRQ = val_valuersrq
	if opt_ieextensions {
		tmp_ieextensions := make(q9.ResultRSRQItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q9.ResultRSRQItemExtIEsExtField
				if err := q9.BridgeResultRSRQItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *ECIDMeasurementResult) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q12.BridgeReceivedFormAt(v.received, v.receivedBytes, "ECIDMeasurementResult", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ECIDMeasurementResult) WithoutReplay() ECIDMeasurementResult {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero ECIDMeasurementResult
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *MeasuredResultsValue) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q12.BridgeReceivedFormAt(v.received, v.receivedBytes, "MeasuredResultsValue", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v MeasuredResultsValue) WithoutReplay() MeasuredResultsValue {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero MeasuredResultsValue
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultRSRQItem) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q12.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultRSRQItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultRSRQItem) WithoutReplay() ResultRSRQItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero ResultRSRQItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ECIDMeasurementResult) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ECIDMeasurementResult) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ECIDMeasurementResult.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ECIDMeasurementResult.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ECIDMeasurementResult) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ECIDMeasurementResult.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ECIDMeasurementResult.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ResultRSRQItem) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ResultRSRQItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ResultRSRQItem.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ResultRSRQItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ResultRSRQItem) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ResultRSRQItem.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ResultRSRQItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *ECIDMeasurementResult) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "ECIDMeasurementResult")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "ECIDMeasurementResult")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaECIDMeasurementResult(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "ECIDMeasurementResult")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "ECIDMeasurementResult")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "ECIDMeasurementResult")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "ECIDMeasurementResult")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "ECIDMeasurementResult")
}
func (v *ECIDMeasurementResult) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ECIDMeasurementResult) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ECIDMeasurementResult) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *ECIDMeasurementResult) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ECIDMeasurementResult) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *MeasuredResultsValue) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "MeasuredResultsValue")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "MeasuredResultsValue")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaMeasuredResultsValue(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "MeasuredResultsValue")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "MeasuredResultsValue")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "MeasuredResultsValue")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "MeasuredResultsValue")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "MeasuredResultsValue")
}
func (v *MeasuredResultsValue) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *MeasuredResultsValue) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *MeasuredResultsValue) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *MeasuredResultsValue) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *MeasuredResultsValue) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ResultRSRQItem) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "ResultRSRQItem")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "ResultRSRQItem")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaResultRSRQItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "ResultRSRQItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "ResultRSRQItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "ResultRSRQItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "ResultRSRQItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "ResultRSRQItem")
}
func (v *ResultRSRQItem) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultRSRQItem) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultRSRQItem) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *ResultRSRQItem) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultRSRQItem) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ECIDMeasurementResult) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "ECIDMeasurementResult")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded ECIDMeasurementResult
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaECIDMeasurementResult(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = ECIDMeasurementResult{}
		return report, q4.OperationError(err, "ECIDMeasurementResult")
	}
	*v = decoded
	return report, q4.OperationError(nil, "ECIDMeasurementResult")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *MeasuredResultsValue) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "MeasuredResultsValue")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded MeasuredResultsValue
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaMeasuredResultsValue(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = MeasuredResultsValue{}
		return report, q4.OperationError(err, "MeasuredResultsValue")
	}
	*v = decoded
	return report, q4.OperationError(nil, "MeasuredResultsValue")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultRSRQItem) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "ResultRSRQItem")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded ResultRSRQItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultRSRQItem(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = ResultRSRQItem{}
		return report, q4.OperationError(err, "ResultRSRQItem")
	}
	*v = decoded
	return report, q4.OperationError(nil, "ResultRSRQItem")
}

// NewMeasuredResultsValueValueAngleOfArrival constructs a checked complete value.
func NewMeasuredResultsValueValueAngleOfArrival(v int64, options ...q4.BuildOption) (MeasuredResultsValue, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return MeasuredResultsValue{}, q4.OperationError(err, "MeasuredResultsValueValueAngleOfArrival")
	}
	value := BridgeNewMeasuredResultsValueValueAngleOfArrivalLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return MeasuredResultsValue{}, q4.OperationError(err, "MeasuredResultsValueValueAngleOfArrival")
	}
	return value, q4.OperationError(nil, "MeasuredResultsValueValueAngleOfArrival")
}

// NewMeasuredResultsValueValueTimingAdvanceType1 constructs a checked complete value.
func NewMeasuredResultsValueValueTimingAdvanceType1(v int64, options ...q4.BuildOption) (MeasuredResultsValue, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return MeasuredResultsValue{}, q4.OperationError(err, "MeasuredResultsValueValueTimingAdvanceType1")
	}
	value := BridgeNewMeasuredResultsValueValueTimingAdvanceType1Legacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return MeasuredResultsValue{}, q4.OperationError(err, "MeasuredResultsValueValueTimingAdvanceType1")
	}
	return value, q4.OperationError(nil, "MeasuredResultsValueValueTimingAdvanceType1")
}

// NewMeasuredResultsValueValueTimingAdvanceType2 constructs a checked complete value.
func NewMeasuredResultsValueValueTimingAdvanceType2(v int64, options ...q4.BuildOption) (MeasuredResultsValue, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return MeasuredResultsValue{}, q4.OperationError(err, "MeasuredResultsValueValueTimingAdvanceType2")
	}
	value := BridgeNewMeasuredResultsValueValueTimingAdvanceType2Legacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return MeasuredResultsValue{}, q4.OperationError(err, "MeasuredResultsValueValueTimingAdvanceType2")
	}
	return value, q4.OperationError(nil, "MeasuredResultsValueValueTimingAdvanceType2")
}

// NewMeasuredResultsValueResultRSRP constructs a checked complete value.
func NewMeasuredResultsValueResultRSRP(v q14.ResultRSRP, options ...q4.BuildOption) (MeasuredResultsValue, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return MeasuredResultsValue{}, q4.OperationError(err, "MeasuredResultsValueResultRSRP")
	}
	value := BridgeNewMeasuredResultsValueResultRSRPLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return MeasuredResultsValue{}, q4.OperationError(err, "MeasuredResultsValueResultRSRP")
	}
	return value, q4.OperationError(nil, "MeasuredResultsValueResultRSRP")
}

// NewMeasuredResultsValueResultRSRQ constructs a checked complete value.
func NewMeasuredResultsValueResultRSRQ(v ResultRSRQ, options ...q4.BuildOption) (MeasuredResultsValue, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return MeasuredResultsValue{}, q4.OperationError(err, "MeasuredResultsValueResultRSRQ")
	}
	value := BridgeNewMeasuredResultsValueResultRSRQLegacy(v)
	if _, err := (&value).marshalAPERBudget(budget, false); err != nil {
		return MeasuredResultsValue{}, q4.OperationError(err, "MeasuredResultsValueResultRSRQ")
	}
	return value, q4.OperationError(nil, "MeasuredResultsValueResultRSRQ")
}

// NewMeasuredResultsValueUnknownExtension builds a checked, owned unknown CHOICE alternative.
func NewMeasuredResultsValueUnknownExtension(index uint64, contents []byte, options ...q4.BuildOption) (MeasuredResultsValue, error) {
	budget, err := q4.BuildBudget(options...)
	if err != nil {
		return MeasuredResultsValue{}, q4.OperationError(err, "MeasuredResultsValueUnknownExtension")
	}
	extension, err := q4.BuildChoiceExtension(index, contents, budget)
	if err != nil {
		return MeasuredResultsValue{}, q4.OperationError(err, "MeasuredResultsValueUnknownExtension")
	}
	value := MeasuredResultsValue{UnknownExtension: &extension}
	if _, err := value.marshalAPERBudget(budget, false); err != nil {
		return MeasuredResultsValue{}, q4.OperationError(err, "MeasuredResultsValueUnknownExtension")
	}
	return value, q4.OperationError(nil, "MeasuredResultsValueUnknownExtension")
}

// ECIDMeasurementReport represents the ASN.1 type E-CIDMeasurementReport (SEQUENCE).
type ECIDMeasurementReport struct {
	replay           q4.Snapshot
	stream           q4.WireSpan
	withoutReplay    bool
	received         bool
	receivedBytes    q4.WireSpan
	ProtocolIEs      ECIDMeasurementReportIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                             `asn1:"-" json:"-"`
	extCount         int64                            `asn1:"-" json:"-"`
	extPresent       []bool                           `asn1:"-" json:"-"`
	extData          [][]byte                         `asn1:"-" json:"-"`
	perPadding       q4.FinalPadding                  `asn1:"-" json:"-"`
	perExtPadding    []q4.CompletePadding             `asn1:"-" json:"-"`
	extOrigin        []q4.OpaqueOrigin
	extWire          []q4.WireSpan
}

// MarshalAPER encodes ECIDMeasurementReport to APER format.
func (v *ECIDMeasurementReport) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ECIDMeasurementReport) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = q12.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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

// UnmarshalAPER decodes ECIDMeasurementReport from APER format.
func (v *ECIDMeasurementReport) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ECIDMeasurementReport with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ECIDMeasurementReport) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "ECIDMeasurementReport")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "ECIDMeasurementReport")
	}
	padding, err := q4.CaptureFinalBits(bb, "ECIDMeasurementReport")
	if err != nil {
		return q7.WrapDecodePath(err, "ECIDMeasurementReport")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ECIDMeasurementReport) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ECIDMeasurementReport{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	v.ProtocolIEs = make(ECIDMeasurementReportIEContainer, 0)
	_, errCollection_protocolies := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem ECIDMeasurementReportIEField
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
func (v *ECIDMeasurementReport) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q12.BridgeReceivedFormAt(v.received, v.receivedBytes, "ECIDMeasurementReport", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ECIDMeasurementReport) WithoutReplay() ECIDMeasurementReport {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero ECIDMeasurementReport
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ECIDMeasurementReport) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ECIDMeasurementReport) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ECIDMeasurementReport.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ECIDMeasurementReport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ECIDMeasurementReport) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ECIDMeasurementReport.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ECIDMeasurementReport.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *ECIDMeasurementReport) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "ECIDMeasurementReport")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "ECIDMeasurementReport")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaECIDMeasurementReport(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "ECIDMeasurementReport")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "ECIDMeasurementReport")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "ECIDMeasurementReport")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "ECIDMeasurementReport")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "ECIDMeasurementReport")
}
func (v *ECIDMeasurementReport) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ECIDMeasurementReport) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ECIDMeasurementReport) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *ECIDMeasurementReport) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ECIDMeasurementReport) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ECIDMeasurementReport) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "ECIDMeasurementReport")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded ECIDMeasurementReport
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaECIDMeasurementReport(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = ECIDMeasurementReport{}
		return report, q4.OperationError(err, "ECIDMeasurementReport")
	}
	*v = decoded
	return report, q4.OperationError(nil, "ECIDMeasurementReport")
}
func BridgeCaptureLPPaECIDMeasurementReport(v *ECIDMeasurementReport, s *q4.SemanticCapture) {
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
func BridgeCompareLPPaECIDMeasurementReport(v *ECIDMeasurementReport, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeECIDMeasurementReportIEValueCompareLPPaProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaECIDMeasurementReportIEValue(v *ECIDMeasurementReportIEValue, s *q4.SemanticCapture) {
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
					BridgeCaptureLPPaECIDMeasurementResult(v.rowECIDMeasurementResult, s)
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
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ECIDMeasurementReportIEValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v ECIDMeasurementReportIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ECIDMeasurementReportIEValue) captureSemantics(s q4.SemanticCapture) ECIDMeasurementReportIEValue {
	BridgeCaptureLPPaECIDMeasurementReportIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaECIDMeasurementReportIEValue(v *ECIDMeasurementReportIEValue, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q11.BridgeCompareLPPaProtocolIEID(&v.id, s)
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
					q11.BridgeCompareLPPaMeasurementID(v.rowESMLCUEMeasurementID, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(6):
			{
				f := s.Begin()
				s.Bool(v.rowENBUEMeasurementID == nil)
				if v.rowENBUEMeasurementID != nil {
					q11.BridgeCompareLPPaMeasurementID(v.rowENBUEMeasurementID, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(7):
			{
				f := s.Begin()
				s.Bool(v.rowECIDMeasurementResult == nil)
				if v.rowECIDMeasurementResult != nil {
					BridgeCompareLPPaECIDMeasurementResult(v.rowECIDMeasurementResult, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(14):
			{
				f := s.Begin()
				s.Bool(v.rowCellPortionID == nil)
				if v.rowCellPortionID != nil {
					q11.BridgeCompareLPPaCellPortionID(v.rowCellPortionID, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v ECIDMeasurementReportIEValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaECIDMeasurementReportIEValue(&v, &s)
	return s
}
func (v ECIDMeasurementReportIEValue) WithoutReplay() ECIDMeasurementReportIEValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCaptureLPPaECIDMeasurementResult(v *ECIDMeasurementResult, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q12.BridgeCaptureLPPaECGI(&v.ServingCellID, s)
	q5.BridgeCaptureLPPaTAC(&v.ServingCellTAC, s)
	{
		f := s.Begin()
		s.Bool(v.EUTRANAccessPointPosition == nil)
		if v.EUTRANAccessPointPosition != nil {
			q13.BridgeCaptureLPPaEUTRANAccessPointPosition(v.EUTRANAccessPointPosition, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.MeasuredResults == nil)
	BridgeCaptureLPPaMeasuredResults(&v.MeasuredResults, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaECIDMeasurementResult(v *ECIDMeasurementResult, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q12.BridgeCompareLPPaECGI(&v.ServingCellID, s)
	q8.BridgeCompareLPPaTAC(&v.ServingCellTAC, s)
	{
		f := s.Begin()
		s.Bool(v.EUTRANAccessPointPosition == nil)
		if v.EUTRANAccessPointPosition != nil {
			q13.BridgeCompareLPPaEUTRANAccessPointPosition(v.EUTRANAccessPointPosition, s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	s.Bool(v.MeasuredResults == nil)
	BridgeCompareLPPaMeasuredResults(&v.MeasuredResults, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaMeasuredResults(v *MeasuredResults, s *q4.SemanticCapture) {
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
func BridgeCompareLPPaMeasuredResults(v *MeasuredResults, s *q4.SemanticComparison) {
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
		s.End(f, q4.Snapshot{}, false)
	}
	s.End(f, q4.Snapshot{}, false)
}
func BridgeCaptureLPPaMeasuredResultsValue(v *MeasuredResultsValue, s *q4.SemanticCapture) {
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
	case q5.MeasuredResultsValueChoiceValueAngleOfArrival:
		{
			f := s.Begin()
			s.Bool(v.ValueAngleOfArrival == nil)
			if v.ValueAngleOfArrival != nil {
				s.Int(int64((*v.ValueAngleOfArrival)))
			}
			s.End(f, nil, false)
		}
	case q5.MeasuredResultsValueChoiceValueTimingAdvanceType1:
		{
			f := s.Begin()
			s.Bool(v.ValueTimingAdvanceType1 == nil)
			if v.ValueTimingAdvanceType1 != nil {
				s.Int(int64((*v.ValueTimingAdvanceType1)))
			}
			s.End(f, nil, false)
		}
	case q5.MeasuredResultsValueChoiceValueTimingAdvanceType2:
		{
			f := s.Begin()
			s.Bool(v.ValueTimingAdvanceType2 == nil)
			if v.ValueTimingAdvanceType2 != nil {
				s.Int(int64((*v.ValueTimingAdvanceType2)))
			}
			s.End(f, nil, false)
		}
	case q5.MeasuredResultsValueChoiceResultRSRP:
		q14.BridgeCaptureLPPaResultRSRP(&v.ResultRSRP, s)
	case q5.MeasuredResultsValueChoiceResultRSRQ:
		BridgeCaptureLPPaResultRSRQ(&v.ResultRSRQ, s)
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaMeasuredResultsValue(v *MeasuredResultsValue, s *q4.SemanticComparison) {
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
		s.End(f, q4.Snapshot{}, false)
	}
	switch v.Choice {
	case q5.MeasuredResultsValueChoiceValueAngleOfArrival:
		{
			f := s.Begin()
			s.Bool(v.ValueAngleOfArrival == nil)
			if v.ValueAngleOfArrival != nil {
				s.Int(int64((*v.ValueAngleOfArrival)))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	case q5.MeasuredResultsValueChoiceValueTimingAdvanceType1:
		{
			f := s.Begin()
			s.Bool(v.ValueTimingAdvanceType1 == nil)
			if v.ValueTimingAdvanceType1 != nil {
				s.Int(int64((*v.ValueTimingAdvanceType1)))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	case q5.MeasuredResultsValueChoiceValueTimingAdvanceType2:
		{
			f := s.Begin()
			s.Bool(v.ValueTimingAdvanceType2 == nil)
			if v.ValueTimingAdvanceType2 != nil {
				s.Int(int64((*v.ValueTimingAdvanceType2)))
			}
			s.End(f, q4.Snapshot{}, false)
		}
	case q5.MeasuredResultsValueChoiceResultRSRP:
		q14.BridgeCompareLPPaResultRSRP(&v.ResultRSRP, s)
	case q5.MeasuredResultsValueChoiceResultRSRQ:
		BridgeCompareLPPaResultRSRQ(&v.ResultRSRQ, s)
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultRSRQ(v *ResultRSRQ, s *q4.SemanticCapture) {
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
func BridgeCompareLPPaResultRSRQ(v *ResultRSRQ, s *q4.SemanticComparison) {
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
		s.End(f, q4.Snapshot{}, false)
	}
	s.End(f, q4.Snapshot{}, false)
}
func BridgeCaptureLPPaResultRSRQItem(v *ResultRSRQItem, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q5.BridgeCaptureLPPaPCI(&v.PCI, s)
	q5.BridgeCaptureLPPaEARFCN(&v.EARFCN, s)
	{
		f := s.Begin()
		s.Bool(v.ECGI == nil)
		if v.ECGI != nil {
			q12.BridgeCaptureLPPaECGI(v.ECGI, s)
		}
		s.End(f, nil, false)
	}
	q5.BridgeCaptureLPPaValueRSRQ(&v.ValueRSRQ, s)
	s.Bool(v.IEExtensions == nil)
	BridgeResultRSRQItemExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultRSRQItem(v *ResultRSRQItem, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q11.BridgeCompareLPPaPCI(&v.PCI, s)
	q11.BridgeCompareLPPaEARFCN(&v.EARFCN, s)
	{
		f := s.Begin()
		s.Bool(v.ECGI == nil)
		if v.ECGI != nil {
			q12.BridgeCompareLPPaECGI(v.ECGI, s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	q8.BridgeCompareLPPaValueRSRQ(&v.ValueRSRQ, s)
	s.Bool(v.IEExtensions == nil)
	BridgeResultRSRQItemExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}

type ECIDMeasurementReportIEValue struct {
	id                       q5.ProtocolIEID
	withoutReplay            bool
	received                 q4.WireSpan
	replay                   q4.Snapshot
	opaque                   *q4.OpaqueOpenType
	isOpaque                 bool
	rowESMLCUEMeasurementID  *q5.MeasurementID
	rowENBUEMeasurementID    *q5.MeasurementID
	rowECIDMeasurementResult *ECIDMeasurementResult
	rowCellPortionID         *q5.CellPortionID
}

func (v ECIDMeasurementReportIEValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
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
	case q5.ProtocolIEID(14):
		return v.rowCellPortionID != nil
	default:
		return false
	}
}
func (v *ECIDMeasurementReportIEValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ECIDMeasurementReportIEValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementReport-IEs"}}
}
func (ECIDMeasurementReportIEValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(2):
		return q4.UnknownSelector
	case q5.ProtocolIEID(6):
		return q4.UnknownSelector
	case q5.ProtocolIEID(7):
		return q4.UnknownSelector
	case q5.ProtocolIEID(14):
		return q4.UnknownSelector
	case q5.ProtocolIEID(0):
		return q4.NotInTable
	case q5.ProtocolIEID(1):
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
func (v *ECIDMeasurementReportIEValue) AsESMLCUEMeasurementID() (*q5.MeasurementID, bool) {
	if v == nil || v.id != q5.ProtocolIEID(2) || v.rowESMLCUEMeasurementID == nil {
		return nil, false
	}
	return v.rowESMLCUEMeasurementID, true
}
func (v *ECIDMeasurementReportIEValue) AsENBUEMeasurementID() (*q5.MeasurementID, bool) {
	if v == nil || v.id != q5.ProtocolIEID(6) || v.rowENBUEMeasurementID == nil {
		return nil, false
	}
	return v.rowENBUEMeasurementID, true
}
func (v *ECIDMeasurementReportIEValue) AsECIDMeasurementResult() (*ECIDMeasurementResult, bool) {
	if v == nil || v.id != q5.ProtocolIEID(7) || v.rowECIDMeasurementResult == nil {
		return nil, false
	}
	return v.rowECIDMeasurementResult, true
}
func (v *ECIDMeasurementReportIEValue) AsCellPortionID() (*q5.CellPortionID, bool) {
	if v == nil || v.id != q5.ProtocolIEID(14) || v.rowCellPortionID == nil {
		return nil, false
	}
	return v.rowCellPortionID, true
}
func (v ECIDMeasurementReportIEValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (ECIDMeasurementReportIEValue, error) {
	out := ECIDMeasurementReportIEValue{id: id}
	var scope *q4.BitBuffer
	switch id {
	case 2, 6, 7, 14:
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
		var value ECIDMeasurementResult
		child := raw.ChildDecodeBuffer()
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, q6.Errorf("%s %w", "ECIDMeasurementResult:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "ECIDMeasurementResult")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowECIDMeasurementResult = &value
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
func (v ECIDMeasurementReportIEValue) encode() ([]byte, error) {
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ECIDMeasurementReportIEValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
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
			return nil, q6.Errorf("%s missing value", "E-CIDMeasurementReport-IEs.id-E-SMLC-UE-Measurement-ID:")
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
			return nil, q6.Errorf("%s missing value", "E-CIDMeasurementReport-IEs.id-eNB-UE-Measurement-ID:")
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
			return nil, q6.Errorf("%s missing value", "E-CIDMeasurementReport-IEs.id-E-CID-MeasurementResult:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
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
	case q5.ProtocolIEID(14):
		if v.rowCellPortionID == nil {
			return nil, q6.Errorf("%s missing value", "E-CIDMeasurementReport-IEs.id-Cell-Portion-ID:")
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
	default:
		return nil, q6.Errorf("%s id %d has no value", "ECIDMeasurementReportIEValue:", v.id)
	}
}

type ECIDMeasurementReportIETable struct{}

func ECIDMeasurementReportIEs() ECIDMeasurementReportIETable { return ECIDMeasurementReportIETable{} }
func (ECIDMeasurementReportIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementReport-IEs"}
		return sealed
	}()
}
func (ECIDMeasurementReportIETable) infoESMLCUEMeasurementID() q5.FieldInfo {
	return q5.FieldInfo{Table: ECIDMeasurementReportIEs().ID(), ID: q5.ProtocolIEID(2), Criticality: q5.CriticalityReject, Presence: q5.PresenceMandatory, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementReport-IEs", Row: "id-E-SMLC-UE-Measurement-ID"}}}
}
func (t ECIDMeasurementReportIETable) ESMLCUEMeasurementID() ECIDMeasurementReportMeasurementIDIEBinding {
	return ECIDMeasurementReportMeasurementIDIEBinding{info: t.infoESMLCUEMeasurementID(), codec: func() q5.MeasurementIDValueCodec {
		sealed := q5.MeasurementIDValueCodec{}
		*q5.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*q5.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.MeasurementID, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q5.MeasurementID
				return empty, err
			}
			var zero ECIDMeasurementReportIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(2), raw)
			if err != nil {
				var empty q5.MeasurementID
				return empty, err
			}
			value, ok := decoded.AsESMLCUEMeasurementID()
			if !ok {
				var empty q5.MeasurementID
				return empty, q6.Errorf("binding E-CIDMeasurementReport-IEs.id-E-SMLC-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*q5.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value q5.MeasurementID, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementReportIEValue{id: q5.ProtocolIEID(2), rowESMLCUEMeasurementID: &value}).encodeFresh(fresh, budget)
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
			q11.BridgeCompareLPPaMeasurementID(&v, &s)
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
		inject: func(value q5.MeasurementID) ECIDMeasurementReportIEValue {
			return ECIDMeasurementReportIEValue{id: q5.ProtocolIEID(2), rowESMLCUEMeasurementID: &value}
		}, get: func(value *ECIDMeasurementReportIEValue) (*q5.MeasurementID, bool) {
			return value.AsESMLCUEMeasurementID()
		}}
}
func (ECIDMeasurementReportIETable) infoENBUEMeasurementID() q5.FieldInfo {
	return q5.FieldInfo{Table: ECIDMeasurementReportIEs().ID(), ID: q5.ProtocolIEID(6), Criticality: q5.CriticalityReject, Presence: q5.PresenceMandatory, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "MeasurementID"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementReport-IEs", Row: "id-eNB-UE-Measurement-ID"}}}
}
func (t ECIDMeasurementReportIETable) ENBUEMeasurementID() ECIDMeasurementReportMeasurementIDIEBinding {
	return ECIDMeasurementReportMeasurementIDIEBinding{info: t.infoENBUEMeasurementID(), codec: func() q5.MeasurementIDValueCodec {
		sealed := q5.MeasurementIDValueCodec{}
		*q5.BridgeMeasurementIDValueCodecFieldPath(&sealed) = "MeasurementID"
		*q5.BridgeMeasurementIDValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.MeasurementID, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q5.MeasurementID
				return empty, err
			}
			var zero ECIDMeasurementReportIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(6), raw)
			if err != nil {
				var empty q5.MeasurementID
				return empty, err
			}
			value, ok := decoded.AsENBUEMeasurementID()
			if !ok {
				var empty q5.MeasurementID
				return empty, q6.Errorf("binding E-CIDMeasurementReport-IEs.id-eNB-UE-Measurement-ID: no selected value")
			}
			return *value, nil
		}
		*q5.BridgeMeasurementIDValueCodecFieldEncode(&sealed) = func(value q5.MeasurementID, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementReportIEValue{id: q5.ProtocolIEID(6), rowENBUEMeasurementID: &value}).encodeFresh(fresh, budget)
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
			q11.BridgeCompareLPPaMeasurementID(&v, &s)
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
		inject: func(value q5.MeasurementID) ECIDMeasurementReportIEValue {
			return ECIDMeasurementReportIEValue{id: q5.ProtocolIEID(6), rowENBUEMeasurementID: &value}
		}, get: func(value *ECIDMeasurementReportIEValue) (*q5.MeasurementID, bool) {
			return value.AsENBUEMeasurementID()
		}}
}
func (ECIDMeasurementReportIETable) infoECIDMeasurementResult() q5.FieldInfo {
	return q5.FieldInfo{Table: ECIDMeasurementReportIEs().ID(), ID: q5.ProtocolIEID(7), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceMandatory, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ECIDMeasurementResult"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementReport-IEs", Row: "id-E-CID-MeasurementResult"}}}
}
func (t ECIDMeasurementReportIETable) ECIDMeasurementResult() ECIDMeasurementReportECIDMeasurementResultIEBinding {
	return ECIDMeasurementReportECIDMeasurementResultIEBinding{info: t.infoECIDMeasurementResult(), codec: ECIDMeasurementResultValueCodec{path: "ECIDMeasurementResult",
		decode: func(data []byte, options q4.DecodeState) (ECIDMeasurementResult, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty ECIDMeasurementResult
				return empty, err
			}
			var zero ECIDMeasurementReportIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(7), raw)
			if err != nil {
				var empty ECIDMeasurementResult
				return empty, err
			}
			value, ok := decoded.AsECIDMeasurementResult()
			if !ok {
				var empty ECIDMeasurementResult
				return empty, q6.Errorf("binding E-CIDMeasurementReport-IEs.id-E-CID-MeasurementResult: no selected value")
			}
			return *value, nil
		},
		encode: func(value ECIDMeasurementResult, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementReportIEValue{id: q5.ProtocolIEID(7), rowECIDMeasurementResult: &value}).encodeFresh(fresh, budget)
		}, capture: func(v ECIDMeasurementResult, options q4.DecodeState) (ECIDMeasurementResult, q4.Snapshot,
		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureLPPaECIDMeasurementResult(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}, compare: func(v ECIDMeasurementResult, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaECIDMeasurementResult(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}, context: func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:ECIDMeasurementResult"
			return sealed
		}(),
	}, inject: func(value ECIDMeasurementResult) ECIDMeasurementReportIEValue {
		return ECIDMeasurementReportIEValue{id: q5.ProtocolIEID(7), rowECIDMeasurementResult: &value}
	}, get: func(value *ECIDMeasurementReportIEValue) (*ECIDMeasurementResult, bool) {
		return value.AsECIDMeasurementResult()
	}}
}
func (ECIDMeasurementReportIETable) infoCellPortionID() q5.FieldInfo {
	return q5.FieldInfo{Table: ECIDMeasurementReportIEs().ID(), ID: q5.ProtocolIEID(14), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "CellPortionID"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "E-CIDMeasurementReport-IEs", Row: "id-Cell-Portion-ID"}}}
}
func (t ECIDMeasurementReportIETable) CellPortionID() ECIDMeasurementReportCellPortionIDIEBinding {
	return ECIDMeasurementReportCellPortionIDIEBinding{info: t.infoCellPortionID(), codec: func() q5.CellPortionIDValueCodec {
		sealed := q5.CellPortionIDValueCodec{}
		*q5.BridgeCellPortionIDValueCodecFieldPath(&sealed) = "CellPortionID"
		*q5.BridgeCellPortionIDValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.CellPortionID, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q5.CellPortionID
				return empty, err
			}
			var zero ECIDMeasurementReportIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(14), raw)
			if err != nil {
				var empty q5.CellPortionID
				return empty, err
			}
			value, ok := decoded.AsCellPortionID()
			if !ok {
				var empty q5.CellPortionID
				return empty, q6.Errorf("binding E-CIDMeasurementReport-IEs.id-Cell-Portion-ID: no selected value")
			}
			return *value, nil
		}
		*q5.BridgeCellPortionIDValueCodecFieldEncode(&sealed) = func(value q5.CellPortionID, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (ECIDMeasurementReportIEValue{id: q5.ProtocolIEID(14), rowCellPortionID: &value}).encodeFresh(fresh, budget)
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
			q11.BridgeCompareLPPaCellPortionID(&v, &s)
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
		inject: func(value q5.CellPortionID) ECIDMeasurementReportIEValue {
			return ECIDMeasurementReportIEValue{id: q5.ProtocolIEID(14), rowCellPortionID: &value}
		}, get: func(value *ECIDMeasurementReportIEValue) (*q5.CellPortionID, bool) { return value.AsCellPortionID() }}
}
func (t ECIDMeasurementReportIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (ECIDMeasurementReportIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ECIDMeasurementReportIEField{}, q4.OperationError(q6.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q5.ProtocolIEID(2):
		return ECIDMeasurementReportIEField{}, q4.OperationError(q6.Errorf("known IE id-E-SMLC-UE-Measurement-ID requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(6):
		return ECIDMeasurementReportIEField{}, q4.OperationError(q6.Errorf("known IE id-eNB-UE-Measurement-ID requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(7):
		return ECIDMeasurementReportIEField{}, q4.OperationError(q6.Errorf("known IE id-E-CID-MeasurementResult requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(14):
		return ECIDMeasurementReportIEField{}, q4.OperationError(q6.Errorf("known IE id-Cell-Portion-ID requires its typed binding"), "Opaque")
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return ECIDMeasurementReportIEField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ECIDMeasurementReportIEField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ECIDMeasurementReportIEField{}, q4.OperationError(err, "Opaque")
		}
		return ECIDMeasurementReportIEField{Id: id, Criticality: criticality, Value: ECIDMeasurementReportIEValue{id: id, opaque: retained, isOpaque: true}}, q4.OperationError(nil, "Opaque")
	}
}

// MeasuredResultsValueCodec binds the complete source value type.
func MeasuredResultsValueCodec() MeasuredResultsValueValueCodec {
	return MeasuredResultsValueValueCodec{path: "MeasuredResultsValue", decode: func(data []byte, options q4.DecodeState) (MeasuredResultsValue, error) {
		var value MeasuredResultsValue
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return MeasuredResultsValue{}, err
		}
		value.received = true
		value.receivedBytes = q4.OriginalWire(data)
		return value, nil
	}, encode: func(value MeasuredResultsValue, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v MeasuredResultsValue, options q4.DecodeState) (MeasuredResultsValue, q4.Snapshot,
	) {
		s := q4.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaMeasuredResultsValue(&v, &s)
		var root q4.Snapshot
		s.OperationCounts()
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v MeasuredResultsValue, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
		s := q4.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaMeasuredResultsValue(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q5.BridgeCodecContext {
		sealed := q5.BridgeCodecContext{}
		*q5.BridgecodecContextFieldSource(&sealed) = "source-value:MeasuredResultsValue"
		return sealed
	}(),
	}
}

// ResultRSRQItemCodec binds the complete source value type.
func ResultRSRQItemCodec() ResultRSRQItemValueCodec {
	return ResultRSRQItemValueCodec{path: "ResultRSRQItem", decode: func(data []byte, options q4.DecodeState) (ResultRSRQItem, error) {
		var value ResultRSRQItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ResultRSRQItem{}, err
		}
		value.received = true
		value.receivedBytes = q4.OriginalWire(data)
		return value, nil
	}, encode: func(value ResultRSRQItem, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ResultRSRQItem, options q4.DecodeState) (ResultRSRQItem, q4.Snapshot) {
		s := q4.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaResultRSRQItem(&v, &s)
		var root q4.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResultRSRQItem, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
		s := q4.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaResultRSRQItem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q5.BridgeCodecContext {
		sealed := q5.BridgeCodecContext{}
		*q5.BridgecodecContextFieldSource(&sealed) = "source-value:ResultRSRQItem"
		return sealed
	}(),
	}
}
func BridgeECIDMeasurementReportAPERValueFieldContext(v *ECIDMeasurementReportAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementReportAPERValueFieldReceived(v *ECIDMeasurementReportAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementReportAPERValueFieldReplay(v *ECIDMeasurementReportAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementReportAPERValueFieldWithoutReplay(v *ECIDMeasurementReportAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementReportCellPortionIDIEBindingFieldCodec(v *ECIDMeasurementReportCellPortionIDIEBinding) *q5.CellPortionIDValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementReportCellPortionIDIEBindingFieldGet(v *ECIDMeasurementReportCellPortionIDIEBinding) *func(*ECIDMeasurementReportIEValue) (*q5.CellPortionID, bool) {
	return &v.get
}
func BridgeECIDMeasurementReportCellPortionIDIEBindingFieldInfo(v *ECIDMeasurementReportCellPortionIDIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementReportCellPortionIDIEBindingFieldInject(v *ECIDMeasurementReportCellPortionIDIEBinding) *func(q5.CellPortionID) ECIDMeasurementReportIEValue {
	return &v.inject
}
func BridgeECIDMeasurementReportECIDMeasurementResultIEBindingFieldCodec(v *ECIDMeasurementReportECIDMeasurementResultIEBinding) *ECIDMeasurementResultValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementReportECIDMeasurementResultIEBindingFieldGet(v *ECIDMeasurementReportECIDMeasurementResultIEBinding) *func(*ECIDMeasurementReportIEValue) (*ECIDMeasurementResult, bool) {
	return &v.get
}
func BridgeECIDMeasurementReportECIDMeasurementResultIEBindingFieldInfo(v *ECIDMeasurementReportECIDMeasurementResultIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementReportECIDMeasurementResultIEBindingFieldInject(v *ECIDMeasurementReportECIDMeasurementResultIEBinding) *func(ECIDMeasurementResult) ECIDMeasurementReportIEValue {
	return &v.inject
}
func BridgeECIDMeasurementReportFieldExtCount(v *ECIDMeasurementReport) *int64   { return &v.extCount }
func BridgeECIDMeasurementReportFieldExtData(v *ECIDMeasurementReport) *[][]byte { return &v.extData }
func BridgeECIDMeasurementReportFieldExtOrigin(v *ECIDMeasurementReport) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeECIDMeasurementReportFieldExtPresent(v *ECIDMeasurementReport) *[]bool {
	return &v.extPresent
}
func BridgeECIDMeasurementReportFieldExtWire(v *ECIDMeasurementReport) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeECIDMeasurementReportFieldPerExtPadding(v *ECIDMeasurementReport) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeECIDMeasurementReportFieldPerPadding(v *ECIDMeasurementReport) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeECIDMeasurementReportFieldProtocolIEsIndef(v *ECIDMeasurementReport) *bool {
	return &v.protocolIEsIndef
}
func BridgeECIDMeasurementReportFieldReceived(v *ECIDMeasurementReport) *bool { return &v.received }
func BridgeECIDMeasurementReportFieldReceivedBytes(v *ECIDMeasurementReport) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeECIDMeasurementReportFieldReplay(v *ECIDMeasurementReport) *q4.Snapshot { return &v.replay }
func BridgeECIDMeasurementReportFieldStream(v *ECIDMeasurementReport) *q4.WireSpan { return &v.stream }
func BridgeECIDMeasurementReportFieldWithoutReplay(v *ECIDMeasurementReport) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementReportIEFieldFieldReceived(v *ECIDMeasurementReportIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeECIDMeasurementReportIEFieldFieldReplay(v *ECIDMeasurementReportIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementReportIEFieldFieldStream(v *ECIDMeasurementReportIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeECIDMeasurementReportIEFieldFieldWithoutReplay(v *ECIDMeasurementReportIEField) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementReportIEFieldMethodMarshalAPERTo(v *ECIDMeasurementReportIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementReportIEFieldMethodUnmarshalAPERFrom(v *ECIDMeasurementReportIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementReportIETableMethodInfoCellPortionID(v ECIDMeasurementReportIETable) q5.FieldInfo {
	return v.infoCellPortionID()
}
func BridgeECIDMeasurementReportIETableMethodInfoECIDMeasurementResult(v ECIDMeasurementReportIETable) q5.FieldInfo {
	return v.infoECIDMeasurementResult()
}
func BridgeECIDMeasurementReportIETableMethodInfoENBUEMeasurementID(v ECIDMeasurementReportIETable) q5.FieldInfo {
	return v.infoENBUEMeasurementID()
}
func BridgeECIDMeasurementReportIETableMethodInfoESMLCUEMeasurementID(v ECIDMeasurementReportIETable) q5.FieldInfo {
	return v.infoESMLCUEMeasurementID()
}
func BridgeECIDMeasurementReportIEValueFieldId(v *ECIDMeasurementReportIEValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeECIDMeasurementReportIEValueFieldIsOpaque(v *ECIDMeasurementReportIEValue) *bool {
	return &v.isOpaque
}
func BridgeECIDMeasurementReportIEValueFieldOpaque(v *ECIDMeasurementReportIEValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeECIDMeasurementReportIEValueFieldReceived(v *ECIDMeasurementReportIEValue) *q4.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementReportIEValueFieldReplay(v *ECIDMeasurementReportIEValue) *q4.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementReportIEValueFieldRowCellPortionID(v *ECIDMeasurementReportIEValue) **q5.CellPortionID {
	return &v.rowCellPortionID
}
func BridgeECIDMeasurementReportIEValueFieldRowECIDMeasurementResult(v *ECIDMeasurementReportIEValue) **ECIDMeasurementResult {
	return &v.rowECIDMeasurementResult
}
func BridgeECIDMeasurementReportIEValueFieldRowENBUEMeasurementID(v *ECIDMeasurementReportIEValue) **q5.MeasurementID {
	return &v.rowENBUEMeasurementID
}
func BridgeECIDMeasurementReportIEValueFieldRowESMLCUEMeasurementID(v *ECIDMeasurementReportIEValue) **q5.MeasurementID {
	return &v.rowESMLCUEMeasurementID
}
func BridgeECIDMeasurementReportIEValueFieldWithoutReplay(v *ECIDMeasurementReportIEValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementReportIEValueMethodCaptureFraming(v ECIDMeasurementReportIEValue) uint64 {
	return v.captureFraming()
}
func BridgeECIDMeasurementReportIEValueMethodCaptureSemantics(v ECIDMeasurementReportIEValue, a0 q4.SemanticCapture) ECIDMeasurementReportIEValue {
	return v.captureSemantics(a0)
}
func BridgeECIDMeasurementReportIEValueMethodCaptureSnapshot(v ECIDMeasurementReportIEValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeECIDMeasurementReportIEValueMethodCompareSemantics(v ECIDMeasurementReportIEValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeECIDMeasurementReportIEValueMethodDecode(v ECIDMeasurementReportIEValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (ECIDMeasurementReportIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeECIDMeasurementReportIEValueMethodEncode(v ECIDMeasurementReportIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeECIDMeasurementReportIEValueMethodEncodeFresh(v ECIDMeasurementReportIEValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeECIDMeasurementReportIEValueMethodMatchesID(v ECIDMeasurementReportIEValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeECIDMeasurementReportIEValueMethodReason(v ECIDMeasurementReportIEValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeECIDMeasurementReportIEValueMethodRule(v ECIDMeasurementReportIEValue) q4.SourceRule {
	return v.rule()
}
func BridgeECIDMeasurementReportMeasurementIDIEBindingFieldCodec(v *ECIDMeasurementReportMeasurementIDIEBinding) *q5.MeasurementIDValueCodec {
	return &v.codec
}
func BridgeECIDMeasurementReportMeasurementIDIEBindingFieldGet(v *ECIDMeasurementReportMeasurementIDIEBinding) *func(*ECIDMeasurementReportIEValue) (*q5.MeasurementID, bool) {
	return &v.get
}
func BridgeECIDMeasurementReportMeasurementIDIEBindingFieldInfo(v *ECIDMeasurementReportMeasurementIDIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeECIDMeasurementReportMeasurementIDIEBindingFieldInject(v *ECIDMeasurementReportMeasurementIDIEBinding) *func(q5.MeasurementID) ECIDMeasurementReportIEValue {
	return &v.inject
}
func BridgeECIDMeasurementReportMethodMarshalAPERBudget(v *ECIDMeasurementReport, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeECIDMeasurementReportMethodMarshalAPERChanged(v *ECIDMeasurementReport, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeECIDMeasurementReportMethodMarshalAPERChangedValue(v *ECIDMeasurementReport, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeECIDMeasurementReportMethodMarshalAPERFreshValue(v *ECIDMeasurementReport, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeECIDMeasurementReportMethodMarshalAPERLegacy(v *ECIDMeasurementReport) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeECIDMeasurementReportMethodMarshalAPERPlanned(v *ECIDMeasurementReport, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeECIDMeasurementReportMethodMarshalAPERTo(v *ECIDMeasurementReport, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementReportMethodUnmarshalAPERFrom(v *ECIDMeasurementReport, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementReportMethodUnmarshalAPERLegacy(v *ECIDMeasurementReport, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeECIDMeasurementReportMethodUnmarshalAPERWithOptions(v *ECIDMeasurementReport, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeECIDMeasurementReportValueCodecFieldCapture(v *ECIDMeasurementReportValueCodec) *func(ECIDMeasurementReport, q4.DecodeState) (ECIDMeasurementReport, q4.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementReportValueCodecFieldCompare(v *ECIDMeasurementReportValueCodec) *func(ECIDMeasurementReport, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementReportValueCodecFieldContext(v *ECIDMeasurementReportValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementReportValueCodecFieldDecode(v *ECIDMeasurementReportValueCodec) *func([]byte, q4.DecodeState) (ECIDMeasurementReport, error) {
	return &v.decode
}
func BridgeECIDMeasurementReportValueCodecFieldEncode(v *ECIDMeasurementReportValueCodec) *func(ECIDMeasurementReport, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementReportValueCodecFieldPath(v *ECIDMeasurementReportValueCodec) *q4.Path {
	return &v.path
}
func BridgeECIDMeasurementReportValueCodecMethodEncodeBudget(v ECIDMeasurementReportValueCodec, a0 ECIDMeasurementReport, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeECIDMeasurementReportValueCodecMethodEncodeChanged(v ECIDMeasurementReportValueCodec, a0 ECIDMeasurementReport, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeECIDMeasurementResultAPERValueFieldContext(v *ECIDMeasurementResultAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementResultAPERValueFieldReceived(v *ECIDMeasurementResultAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeECIDMeasurementResultAPERValueFieldReplay(v *ECIDMeasurementResultAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeECIDMeasurementResultAPERValueFieldWithoutReplay(v *ECIDMeasurementResultAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementResultFieldExtCount(v *ECIDMeasurementResult) *int64   { return &v.extCount }
func BridgeECIDMeasurementResultFieldExtData(v *ECIDMeasurementResult) *[][]byte { return &v.extData }
func BridgeECIDMeasurementResultFieldExtOrigin(v *ECIDMeasurementResult) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeECIDMeasurementResultFieldExtPresent(v *ECIDMeasurementResult) *[]bool {
	return &v.extPresent
}
func BridgeECIDMeasurementResultFieldExtWire(v *ECIDMeasurementResult) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeECIDMeasurementResultFieldMeasuredResultsIndef(v *ECIDMeasurementResult) *bool {
	return &v.measuredResultsIndef
}
func BridgeECIDMeasurementResultFieldPerExtPadding(v *ECIDMeasurementResult) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeECIDMeasurementResultFieldPerPadding(v *ECIDMeasurementResult) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeECIDMeasurementResultFieldReceived(v *ECIDMeasurementResult) *bool { return &v.received }
func BridgeECIDMeasurementResultFieldReceivedBytes(v *ECIDMeasurementResult) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeECIDMeasurementResultFieldReplay(v *ECIDMeasurementResult) *q4.Snapshot { return &v.replay }
func BridgeECIDMeasurementResultFieldStream(v *ECIDMeasurementResult) *q4.WireSpan { return &v.stream }
func BridgeECIDMeasurementResultFieldWithoutReplay(v *ECIDMeasurementResult) *bool {
	return &v.withoutReplay
}
func BridgeECIDMeasurementResultMethodMarshalAPERBudget(v *ECIDMeasurementResult, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeECIDMeasurementResultMethodMarshalAPERChanged(v *ECIDMeasurementResult, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeECIDMeasurementResultMethodMarshalAPERChangedValue(v *ECIDMeasurementResult, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeECIDMeasurementResultMethodMarshalAPERFreshValue(v *ECIDMeasurementResult, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeECIDMeasurementResultMethodMarshalAPERLegacy(v *ECIDMeasurementResult) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeECIDMeasurementResultMethodMarshalAPERPlanned(v *ECIDMeasurementResult, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeECIDMeasurementResultMethodMarshalAPERTo(v *ECIDMeasurementResult, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeECIDMeasurementResultMethodUnmarshalAPERFrom(v *ECIDMeasurementResult, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeECIDMeasurementResultMethodUnmarshalAPERLegacy(v *ECIDMeasurementResult, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeECIDMeasurementResultMethodUnmarshalAPERWithOptions(v *ECIDMeasurementResult, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeECIDMeasurementResultValueCodecFieldCapture(v *ECIDMeasurementResultValueCodec) *func(ECIDMeasurementResult, q4.DecodeState) (ECIDMeasurementResult, q4.Snapshot) {
	return &v.capture
}
func BridgeECIDMeasurementResultValueCodecFieldCompare(v *ECIDMeasurementResultValueCodec) *func(ECIDMeasurementResult, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeECIDMeasurementResultValueCodecFieldContext(v *ECIDMeasurementResultValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeECIDMeasurementResultValueCodecFieldDecode(v *ECIDMeasurementResultValueCodec) *func([]byte, q4.DecodeState) (ECIDMeasurementResult, error) {
	return &v.decode
}
func BridgeECIDMeasurementResultValueCodecFieldEncode(v *ECIDMeasurementResultValueCodec) *func(ECIDMeasurementResult, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeECIDMeasurementResultValueCodecFieldPath(v *ECIDMeasurementResultValueCodec) *q4.Path {
	return &v.path
}
func BridgeECIDMeasurementResultValueCodecMethodEncodeBudget(v ECIDMeasurementResultValueCodec, a0 ECIDMeasurementResult, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeECIDMeasurementResultValueCodecMethodEncodeChanged(v ECIDMeasurementResultValueCodec, a0 ECIDMeasurementResult, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMeasuredResultsAPERValueFieldContext(v *MeasuredResultsAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeMeasuredResultsAPERValueFieldReceived(v *MeasuredResultsAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeMeasuredResultsAPERValueFieldReplay(v *MeasuredResultsAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeMeasuredResultsAPERValueFieldWithoutReplay(v *MeasuredResultsAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMeasuredResultsConcreteValueCodecFieldCapture(v *MeasuredResultsConcreteValueCodec) *func(MeasuredResults, q4.DecodeState) (MeasuredResults, q4.Snapshot) {
	return &v.capture
}
func BridgeMeasuredResultsConcreteValueCodecFieldCompare(v *MeasuredResultsConcreteValueCodec) *func(MeasuredResults, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeMeasuredResultsConcreteValueCodecFieldContext(v *MeasuredResultsConcreteValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeMeasuredResultsConcreteValueCodecFieldDecode(v *MeasuredResultsConcreteValueCodec) *func([]byte, q4.DecodeState) (MeasuredResults, error) {
	return &v.decode
}
func BridgeMeasuredResultsConcreteValueCodecFieldEncode(v *MeasuredResultsConcreteValueCodec) *func(MeasuredResults, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMeasuredResultsConcreteValueCodecFieldPath(v *MeasuredResultsConcreteValueCodec) *q4.Path {
	return &v.path
}
func BridgeMeasuredResultsConcreteValueCodecMethodEncodeBudget(v MeasuredResultsConcreteValueCodec, a0 MeasuredResults, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeMeasuredResultsConcreteValueCodecMethodEncodeChanged(v MeasuredResultsConcreteValueCodec, a0 MeasuredResults, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeMeasuredResultsValueAPERValueFieldContext(v *MeasuredResultsValueAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeMeasuredResultsValueAPERValueFieldReceived(v *MeasuredResultsValueAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeMeasuredResultsValueAPERValueFieldReplay(v *MeasuredResultsValueAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeMeasuredResultsValueAPERValueFieldWithoutReplay(v *MeasuredResultsValueAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeMeasuredResultsValueFieldKnownOpenBytes(v *MeasuredResultsValue) *uint64 {
	return &v.knownOpenBytes
}
func BridgeMeasuredResultsValueFieldPerOpenTypePadding(v *MeasuredResultsValue) *q4.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeMeasuredResultsValueFieldPerPadding(v *MeasuredResultsValue) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeMeasuredResultsValueFieldReceived(v *MeasuredResultsValue) *bool { return &v.received }
func BridgeMeasuredResultsValueFieldReceivedBytes(v *MeasuredResultsValue) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeMeasuredResultsValueFieldReplay(v *MeasuredResultsValue) *q4.Snapshot { return &v.replay }
func BridgeMeasuredResultsValueFieldStream(v *MeasuredResultsValue) *q4.WireSpan { return &v.stream }
func BridgeMeasuredResultsValueFieldWithoutReplay(v *MeasuredResultsValue) *bool {
	return &v.withoutReplay
}
func BridgeMeasuredResultsValueMethodMarshalAPERBudget(v *MeasuredResultsValue, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeMeasuredResultsValueMethodMarshalAPERChanged(v *MeasuredResultsValue, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeMeasuredResultsValueMethodMarshalAPERChangedValue(v *MeasuredResultsValue, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeMeasuredResultsValueMethodMarshalAPERFreshValue(v *MeasuredResultsValue, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeMeasuredResultsValueMethodMarshalAPERLegacy(v *MeasuredResultsValue) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeMeasuredResultsValueMethodMarshalAPERPlanned(v *MeasuredResultsValue, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeMeasuredResultsValueMethodMarshalAPERTo(v *MeasuredResultsValue, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeMeasuredResultsValueMethodUnmarshalAPERFrom(v *MeasuredResultsValue, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeMeasuredResultsValueMethodUnmarshalAPERLegacy(v *MeasuredResultsValue, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeMeasuredResultsValueMethodUnmarshalAPERWithOptions(v *MeasuredResultsValue, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeMeasuredResultsValueValueCodecFieldCapture(v *MeasuredResultsValueValueCodec) *func(MeasuredResultsValue, q4.DecodeState) (MeasuredResultsValue, q4.Snapshot) {
	return &v.capture
}
func BridgeMeasuredResultsValueValueCodecFieldCompare(v *MeasuredResultsValueValueCodec) *func(MeasuredResultsValue, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeMeasuredResultsValueValueCodecFieldContext(v *MeasuredResultsValueValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeMeasuredResultsValueValueCodecFieldDecode(v *MeasuredResultsValueValueCodec) *func([]byte, q4.DecodeState) (MeasuredResultsValue, error) {
	return &v.decode
}
func BridgeMeasuredResultsValueValueCodecFieldEncode(v *MeasuredResultsValueValueCodec) *func(MeasuredResultsValue, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeMeasuredResultsValueValueCodecFieldPath(v *MeasuredResultsValueValueCodec) *q4.Path {
	return &v.path
}
func BridgeMeasuredResultsValueValueCodecMethodEncodeBudget(v MeasuredResultsValueValueCodec, a0 MeasuredResultsValue, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeMeasuredResultsValueValueCodecMethodEncodeChanged(v MeasuredResultsValueValueCodec, a0 MeasuredResultsValue, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultRSRQAPERValueFieldContext(v *ResultRSRQAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeResultRSRQAPERValueFieldReceived(v *ResultRSRQAPERValue) *q4.WireSpan { return &v.received }
func BridgeResultRSRQAPERValueFieldReplay(v *ResultRSRQAPERValue) *q4.Snapshot   { return &v.replay }
func BridgeResultRSRQAPERValueFieldWithoutReplay(v *ResultRSRQAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRQItemAPERValueFieldContext(v *ResultRSRQItemAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeResultRSRQItemAPERValueFieldReceived(v *ResultRSRQItemAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeResultRSRQItemAPERValueFieldReplay(v *ResultRSRQItemAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeResultRSRQItemAPERValueFieldWithoutReplay(v *ResultRSRQItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultRSRQItemFieldExtCount(v *ResultRSRQItem) *int64              { return &v.extCount }
func BridgeResultRSRQItemFieldExtData(v *ResultRSRQItem) *[][]byte            { return &v.extData }
func BridgeResultRSRQItemFieldExtOrigin(v *ResultRSRQItem) *[]q4.OpaqueOrigin { return &v.extOrigin }
func BridgeResultRSRQItemFieldExtPresent(v *ResultRSRQItem) *[]bool           { return &v.extPresent }
func BridgeResultRSRQItemFieldExtWire(v *ResultRSRQItem) *[]q4.WireSpan       { return &v.extWire }
func BridgeResultRSRQItemFieldIEExtensionsIndef(v *ResultRSRQItem) *bool      { return &v.iEExtensionsIndef }
func BridgeResultRSRQItemFieldPerExtPadding(v *ResultRSRQItem) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeResultRSRQItemFieldPerPadding(v *ResultRSRQItem) *q4.FinalPadding { return &v.perPadding }
func BridgeResultRSRQItemFieldReceived(v *ResultRSRQItem) *bool              { return &v.received }
func BridgeResultRSRQItemFieldReceivedBytes(v *ResultRSRQItem) *q4.WireSpan  { return &v.receivedBytes }
func BridgeResultRSRQItemFieldReplay(v *ResultRSRQItem) *q4.Snapshot         { return &v.replay }
func BridgeResultRSRQItemFieldStream(v *ResultRSRQItem) *q4.WireSpan         { return &v.stream }
func BridgeResultRSRQItemFieldWithoutReplay(v *ResultRSRQItem) *bool         { return &v.withoutReplay }
func BridgeResultRSRQItemMethodMarshalAPERBudget(v *ResultRSRQItem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultRSRQItemMethodMarshalAPERChanged(v *ResultRSRQItem, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultRSRQItemMethodMarshalAPERChangedValue(v *ResultRSRQItem, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultRSRQItemMethodMarshalAPERFreshValue(v *ResultRSRQItem, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultRSRQItemMethodMarshalAPERLegacy(v *ResultRSRQItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultRSRQItemMethodMarshalAPERPlanned(v *ResultRSRQItem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultRSRQItemMethodMarshalAPERTo(v *ResultRSRQItem, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultRSRQItemMethodUnmarshalAPERFrom(v *ResultRSRQItem, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultRSRQItemMethodUnmarshalAPERLegacy(v *ResultRSRQItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultRSRQItemMethodUnmarshalAPERWithOptions(v *ResultRSRQItem, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultRSRQItemValueCodecFieldCapture(v *ResultRSRQItemValueCodec) *func(ResultRSRQItem, q4.DecodeState) (ResultRSRQItem, q4.Snapshot) {
	return &v.capture
}
func BridgeResultRSRQItemValueCodecFieldCompare(v *ResultRSRQItemValueCodec) *func(ResultRSRQItem, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeResultRSRQItemValueCodecFieldContext(v *ResultRSRQItemValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeResultRSRQItemValueCodecFieldDecode(v *ResultRSRQItemValueCodec) *func([]byte, q4.DecodeState) (ResultRSRQItem, error) {
	return &v.decode
}
func BridgeResultRSRQItemValueCodecFieldEncode(v *ResultRSRQItemValueCodec) *func(ResultRSRQItem, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultRSRQItemValueCodecFieldPath(v *ResultRSRQItemValueCodec) *q4.Path { return &v.path }
func BridgeResultRSRQItemValueCodecMethodEncodeBudget(v ResultRSRQItemValueCodec, a0 ResultRSRQItem, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultRSRQItemValueCodecMethodEncodeChanged(v ResultRSRQItemValueCodec, a0 ResultRSRQItem, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultRSRQValueCodecFieldCapture(v *ResultRSRQValueCodec) *func(ResultRSRQ, q4.DecodeState) (ResultRSRQ, q4.Snapshot) {
	return &v.capture
}
func BridgeResultRSRQValueCodecFieldCompare(v *ResultRSRQValueCodec) *func(ResultRSRQ, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeResultRSRQValueCodecFieldContext(v *ResultRSRQValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeResultRSRQValueCodecFieldDecode(v *ResultRSRQValueCodec) *func([]byte, q4.DecodeState) (ResultRSRQ, error) {
	return &v.decode
}
func BridgeResultRSRQValueCodecFieldEncode(v *ResultRSRQValueCodec) *func(ResultRSRQ, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultRSRQValueCodecFieldPath(v *ResultRSRQValueCodec) *q4.Path { return &v.path }
func BridgeResultRSRQValueCodecMethodEncodeBudget(v ResultRSRQValueCodec, a0 ResultRSRQ, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultRSRQValueCodecMethodEncodeChanged(v ResultRSRQValueCodec, a0 ResultRSRQ, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
