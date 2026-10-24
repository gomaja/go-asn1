// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s19 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s19

import (
	q6 "fmt"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q21 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s01"
	q11 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q19 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q18 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s07"
	q15 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	q16 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	q13 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s11"
	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s12"
	q17 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s13"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s14"
	q20 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s18"
	q7 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// ResultNRItemExtIEsExtContainer is the concrete ProtocolExtensionContainer[ResultNRItemExtIEsValue].
type ResultNRItemExtIEsExtContainer []ResultNRItemExtIEsExtField

// ResultNRItemExtIEsExtField is the concrete ProtocolExtensionField[ResultNRItemExtIEsValue].
type ResultNRItemExtIEsExtField struct {
	withoutReplay  bool
	replay         q4.Snapshot
	stream         q4.WireSpan
	Id             q5.ProtocolIEID
	Criticality    q5.Criticality
	ExtensionValue ResultNRItemExtIEsValue

	received q4.CompletePadding
}

func (v ResultNRItemExtIEsExtField) WithoutReplay() ResultNRItemExtIEsExtField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ResultNRItemExtIEsExtField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultNRItemExtIEsExtField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		return q6.Errorf("nil ProtocolExtensionField")
	}
	// TS 36.455 V19.0.0 §9.3.8 binds the table-selected value to @id.
	if !v.ExtensionValue.matchesID(v.Id, bb.Budget()) {
		return q7.WrapDecodePath(q6.Errorf("%w: field id %d does not match its value selector", q4.ErrInvalidValue, v.Id), "ProtocolExtensionField.Id")
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.Id), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(65535), false); err != nil {
		return q6.Errorf("encoding id: %w", err)
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return q6.Errorf("encoding criticality: %w", err)
	}
	data, err := v.ExtensionValue.encodeFresh(len(fresh) != 0 && fresh[0],

		bb.Budget())
	if err != nil {
		return q6.Errorf("encoding extensionValue: %w", err)
	}
	if err := q4.EncodeOpenTypeAligned(bb, data); err != nil {
		return q6.Errorf("encoding extensionValue: %w", err)
	}
	return nil
}
func (v *ResultNRItemExtIEsExtField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil ProtocolExtensionField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultNRItemExtIEsExtField{}
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
	var zero ResultNRItemExtIEsValue

	raw, err := q4.DecodeOpaqueOpenTypeAligned(bb, zero.reason(v.Id), zero.rule())
	if err != nil {
		return q7.WrapDecodePath(err, "ExtensionValue")
	}
	raw = raw.WithPath("ProtocolExtensionField.ExtensionValue")
	value, err := zero.decode(v.Id, raw)
	if err != nil {
		return q7.WrapDecodePath(err, "ExtensionValue")
	}
	v.ExtensionValue = value
	v.stream = bb.CaptureWireSpan(replayStart)
	v.stream.RecordUsage(replayUsage, bb)

	return nil
}
func BridgeResultNRItemExtIEsValueCaptureLPPaProtocolExtensionContainer(v *ResultNRItemExtIEsExtContainer, s *q4.SemanticCapture) {
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
func BridgeResultNRItemExtIEsValueCompareLPPaProtocolExtensionContainer(v *ResultNRItemExtIEsExtContainer, s *q4.SemanticComparison) {
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
		s.End(f, q4.Snapshot{}, false)
	}
}

// ResultNRItemExtIEsResultsPerSSBIndexListExtBinding is the concrete ExtensionBinding[ResultsPerSSBIndexList, ResultNRItemExtIEsValue].
type ResultNRItemExtIEsResultsPerSSBIndexListExtBinding struct {
	info   q5.FieldInfo
	codec  q9.ResultsPerSSBIndexListValueCodec
	inject func(q9.ResultsPerSSBIndexList,

	) ResultNRItemExtIEsValue

	get func(*ResultNRItemExtIEsValue,

	) (*q9.ResultsPerSSBIndexList,

		bool)
}

func (b ResultNRItemExtIEsResultsPerSSBIndexListExtBinding) Info() q5.FieldInfo { return b.info }
func (b ResultNRItemExtIEsResultsPerSSBIndexListExtBinding) Codec() q9.ResultsPerSSBIndexListValueCodec {
	return b.codec
}
func (b ResultNRItemExtIEsResultsPerSSBIndexListExtBinding) New(value q9.ResultsPerSSBIndexList,

) (ResultNRItemExtIEsExtField, error) {
	if b.inject == nil {
		return ResultNRItemExtIEsExtField{}, q4.OperationError(q6.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ResultNRItemExtIEsExtField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q9.BridgeResultsPerSSBIndexListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ResultNRItemExtIEsExtField{}, q4.OperationError(q6.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return ResultNRItemExtIEsExtField{}, q4.OperationError(err, "Value.New")
	}
	return ResultNRItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b ResultNRItemExtIEsResultsPerSSBIndexListExtBinding) Get(field *ResultNRItemExtIEsExtField) (*q9.ResultsPerSSBIndexList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ResultNRItemExtIEsNRCGIExtBinding is the concrete ExtensionBinding[NRCGI, ResultNRItemExtIEsValue].
type ResultNRItemExtIEsNRCGIExtBinding struct {
	info   q5.FieldInfo
	codec  q10.NRCGIValueCodec
	inject func(q10.NRCGI,

	) ResultNRItemExtIEsValue

	get func(*ResultNRItemExtIEsValue,

	) (*q10.NRCGI,

		bool)
}

func (b ResultNRItemExtIEsNRCGIExtBinding) Info() q5.FieldInfo         { return b.info }
func (b ResultNRItemExtIEsNRCGIExtBinding) Codec() q10.NRCGIValueCodec { return b.codec }
func (b ResultNRItemExtIEsNRCGIExtBinding) New(value q10.NRCGI,

) (ResultNRItemExtIEsExtField, error) {
	if b.inject == nil {
		return ResultNRItemExtIEsExtField{}, q4.OperationError(q6.Errorf("unbound extension binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ResultNRItemExtIEsExtField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q10.BridgeNRCGIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return ResultNRItemExtIEsExtField{}, q4.OperationError(q6.Errorf("extension %d: %w", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return ResultNRItemExtIEsExtField{}, q4.OperationError(err, "Value.New")
	}
	return ResultNRItemExtIEsExtField{Id: b.info.ID, Criticality: b.info.Criticality, ExtensionValue: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b ResultNRItemExtIEsNRCGIExtBinding) Get(field *ResultNRItemExtIEsExtField) (*q10.NRCGI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.ExtensionValue)
}

// ResultNRValueCodec is the concrete ValueCodec[ResultNR].
type ResultNRValueCodec struct {
	context q5.BridgeCodecContext
	capture func(ResultNR, q4.DecodeState,

	) (ResultNR, q4.Snapshot,

	)
	compare func(ResultNR, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (ResultNR,

		error)
	encode func(ResultNR,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c ResultNRValueCodec) New(value ResultNR,

) (ResultNRAPERValue, error) {
	if c.encode == nil {
		return ResultNRAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ResultNRAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultNRAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return ResultNRAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c ResultNRValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (ResultNRAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultNRAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return ResultNRAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultNRAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return ResultNRAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return ResultNRAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ResultNRValueCodec) EncodeAPER(value ResultNRAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c ResultNRValueCodec) encodeBudget(value ResultNR,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultNRValueCodec) encodeChanged(value ResultNR,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// ResultNRItemValueCodec is the concrete ValueCodec[ResultNRItem].
type ResultNRItemValueCodec struct {
	context q5.BridgeCodecContext
	capture func(ResultNRItem, q4.DecodeState,

	) (ResultNRItem, q4.Snapshot,

	)
	compare func(ResultNRItem, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (ResultNRItem,

		error)
	encode func(ResultNRItem,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c ResultNRItemValueCodec) New(value ResultNRItem,

) (ResultNRItemAPERValue, error) {
	if c.encode == nil {
		return ResultNRItemAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ResultNRItemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultNRItemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return ResultNRItemAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c ResultNRItemValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (ResultNRItemAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultNRItemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return ResultNRItemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultNRItemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return ResultNRItemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return ResultNRItemAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ResultNRItemValueCodec) EncodeAPER(value ResultNRItemAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c ResultNRItemValueCodec) encodeBudget(value ResultNRItem,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultNRItemValueCodec) encodeChanged(value ResultNRItem,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}
func BridgeResultNRItemExtIEsValueCaptureLPPaProtocolExtensionField(v *ResultNRItemExtIEsExtField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(v.ExtensionValue.captureFraming())
	v.ExtensionValue = v.ExtensionValue.captureSemantics(*s)
	s.Child(v.ExtensionValue.captureSnapshot())
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeResultNRItemExtIEsValueCompareLPPaProtocolExtensionField(v *ResultNRItemExtIEsExtField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q11.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q11.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = v.ExtensionValue.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// ResultNRAPERValue is the concrete APERValue[ResultNR].
type ResultNRAPERValue struct {
	context q5.BridgeCodecContext
	Value   ResultNR

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v ResultNRAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v ResultNRAPERValue) WithoutReplay() ResultNRAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultNRItemAPERValue is the concrete APERValue[ResultNRItem].
type ResultNRItemAPERValue struct {
	context q5.BridgeCodecContext
	Value   ResultNRItem

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v ResultNRItemAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v ResultNRItemAPERValue) WithoutReplay() ResultNRItemAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultNRItemExtIEsIEField is the concrete ProtocolIEField[ResultNRItemExtIEsValue].
type ResultNRItemExtIEsIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         ResultNRItemExtIEsValue

	received q4.CompletePadding
}

func (v ResultNRItemExtIEsIEField) WithoutReplay() ResultNRItemExtIEsIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *ResultNRItemExtIEsIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *ResultNRItemExtIEsIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
func (v *ResultNRItemExtIEsIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultNRItemExtIEsIEField{}
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
	var zero ResultNRItemExtIEsValue

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

// ResultNRItemExtIEsIEContainer is the concrete ProtocolIEContainer[ResultNRItemExtIEsValue].
type ResultNRItemExtIEsIEContainer []ResultNRItemExtIEsIEField

// InterRATMeasuredResultsValue represents the ASN.1 CHOICE type InterRATMeasuredResultsValue.
type InterRATMeasuredResultsValue struct {
	knownOpenBytes     uint64
	replay             q4.Snapshot
	stream             q4.WireSpan
	withoutReplay      bool
	received           bool
	receivedBytes      q4.WireSpan
	Choice             int
	perPadding         q4.CompletePadding  `json:"-"`
	perOpenTypePadding q4.CompletePadding  `json:"-"`
	UnknownExtension   *q4.ChoiceExtension `json:"UnknownExtension,omitempty"`
	ResultGERAN        q12.ResultGERAN     `json:"ResultGERAN,omitzero"`
	ResultUTRAN        q9.ResultUTRAN      `json:"ResultUTRAN,omitzero"`
	ResultNR           ResultNR            `json:"ResultNR,omitzero"`
}
type ResultNR = []ResultNRItem

// ResultNRItem represents the ASN.1 type ResultNR-Item (SEQUENCE).
type ResultNRItem struct {
	replay            q4.Snapshot
	stream            q4.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     q4.WireSpan
	NRARFCN           q5.NRARFCN                     `asn1:"tag:0,context,implicit"`
	NRPCI             q5.NRPCI                       `asn1:"tag:1,context,implicit"`
	SSNRRSRP          *q5.SSNRRSRP                   `asn1:"tag:2,context,implicit,optional" json:"SSNRRSRP,omitempty"`
	SSNRRSRQ          *q5.SSNRRSRQ                   `asn1:"tag:3,context,implicit,optional" json:"SSNRRSRQ,omitempty"`
	IEExtensions      ResultNRItemExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                           `asn1:"-" json:"-"`
	extCount          int64                          `asn1:"-" json:"-"`
	extPresent        []bool                         `asn1:"-" json:"-"`
	extData           [][]byte                       `asn1:"-" json:"-"`
	perPadding        q4.FinalPadding                `asn1:"-" json:"-"`
	perExtPadding     []q4.CompletePadding           `asn1:"-" json:"-"`
	extOrigin         []q4.OpaqueOrigin
	extWire           []q4.WireSpan
}

// MarshalAPER encodes InterRATMeasuredResultsValue to APER format.
func (v *InterRATMeasuredResultsValue) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}
func (v *InterRATMeasuredResultsValue) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
			return q6.Errorf("%s known choice %d and unknown extension are both selected", "InterRATMeasuredResultsValue:", v.Choice)
		}
		if v.UnknownExtension.Index() < 0 {
			return q6.Errorf("%s extension index %d must be non-negative", "InterRATMeasuredResultsValue:", v.UnknownExtension.Index())
		}
		if v.UnknownExtension.Index() < 1 {
			return q6.Errorf("%s extension index %d is known to this schema", "InterRATMeasuredResultsValue:", v.UnknownExtension.Index())
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
		return q6.Errorf("%s choice %d must be positive", "InterRATMeasuredResultsValue:", v.Choice)
	}
	isExtension := v.Choice > 2
	if err := q4.EncodeBoolean(bb, isExtension); err != nil {
		return err
	}
	if isExtension {
		// arithmetic pattern APER_CHOICE_EXT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:117
		if v.Choice <= 2 {
			return q6.Errorf("extension choice index outside root")
		}
		if err := q4.EncodeNormallySmallNonNegativeAligned(bb, int64(v.Choice-2-1)); err != nil {
			return err
		}
		inner := q4.NewBudgetBuffer(bb.Budget())
		switch v.Choice {
		case q5.InterRATMeasuredResultsValueChoiceResultNR:
			if err := q4.EncodeCollection(inner, int64(len(v.ResultNR)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_resultnr, fragmentLength_resultnr int64) error {
				// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
				if fragmentOffset_resultnr < 0 || fragmentOffset_resultnr > int64(len(v.ResultNR)) || fragmentLength_resultnr < 0 || fragmentLength_resultnr > int64(len(v.ResultNR[fragmentOffset_resultnr:])) {
					return q6.Errorf("collection fragment outside value")
				}
				for _, elem := range v.ResultNR[fragmentOffset_resultnr : fragmentOffset_resultnr+fragmentLength_resultnr] {
					if err := elem.marshalAPERTo(inner, len(fresh) != 0 && fresh[0]); err != nil {
						return q6.Errorf("encoding resultNR element: %w", err)
					}
				}
				return nil
			}); err != nil {
				return q6.Errorf("encoding resultNR: %w", err)
			}
		default:
			return q6.Errorf("unknown InterRATMeasuredResultsValue extension choice %d", v.Choice)
		}
		openBytes, err := inner.CompleteBytesWithPadding(v.perOpenTypePadding)
		if err != nil {
			return err
		}
		if err := q4.EncodeOpenTypeAligned(bb, openBytes); err != nil {
			return err
		}
		return nil
	}
	// arithmetic pattern APER_CHOICE_ROOT_ENCODE: choice index fits the emitted representation; gen/codegen_aper.go:149
	if v.Choice < 1 {
		return q6.Errorf("choice index outside root")
	}
	if err := q4.EncodeConstrainedWholeNumberAligned(bb, int64(v.Choice-1), 0, 1); err != nil {
		return err
	}
	switch v.Choice {
	case q5.InterRATMeasuredResultsValueChoiceResultGERAN:
		if err := q4.EncodeCollection(bb, int64(len(v.ResultGERAN)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_resultgeran, fragmentLength_resultgeran int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_resultgeran < 0 || fragmentOffset_resultgeran > int64(len(v.ResultGERAN)) || fragmentLength_resultgeran < 0 || fragmentLength_resultgeran > int64(len(v.ResultGERAN[fragmentOffset_resultgeran:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.ResultGERAN[fragmentOffset_resultgeran : fragmentOffset_resultgeran+fragmentLength_resultgeran] {
				if err := q12.BridgeResultGERANItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return q6.Errorf("encoding resultGERAN element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return q6.Errorf("encoding resultGERAN: %w", err)
		}
	case q5.InterRATMeasuredResultsValueChoiceResultUTRAN:
		if err := q4.EncodeCollection(bb, int64(len(v.ResultUTRAN)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_resultutran, fragmentLength_resultutran int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_resultutran < 0 || fragmentOffset_resultutran > int64(len(v.ResultUTRAN)) || fragmentLength_resultutran < 0 || fragmentLength_resultutran > int64(len(v.ResultUTRAN[fragmentOffset_resultutran:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.ResultUTRAN[fragmentOffset_resultutran : fragmentOffset_resultutran+fragmentLength_resultutran] {
				if err := q9.BridgeResultUTRANItemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
					return q6.Errorf("encoding resultUTRAN element: %w", err)
				}
			}
			return nil
		}); err != nil {
			return q6.Errorf("encoding resultUTRAN: %w", err)
		}
	default:
		return q6.Errorf("unknown InterRATMeasuredResultsValue choice %d", v.Choice)
	}
	return nil
}

// UnmarshalAPER decodes InterRATMeasuredResultsValue from APER format.
func (v *InterRATMeasuredResultsValue) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes InterRATMeasuredResultsValue with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *InterRATMeasuredResultsValue) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "InterRATMeasuredResultsValue")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "InterRATMeasuredResultsValue")
	}
	padding, err := q4.CaptureFinalBits(bb, "InterRATMeasuredResultsValue")
	if err != nil {
		return q7.WrapDecodePath(err, "InterRATMeasuredResultsValue")
	}
	v.perPadding = padding.Padding()
	return nil
}
func (v *InterRATMeasuredResultsValue) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InterRATMeasuredResultsValue{}
	isExtension, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	if isExtension {
		extIdx, err := q4.DecodeNormallySmallNonNegativeAligned(bb)
		if err != nil {
			return q7.WrapDecodePath(err, "UnknownExtension")
		}
		openExtension, err := q4.DecodeChoiceExtensionAligned(bb, extIdx, 1)
		if extIdx < 1 {
			v.knownOpenBytes = max(v.knownOpenBytes, openExtension.ContentLength())
		}
		if err != nil {
			return q7.WrapDecodePath(err, "UnknownExtension")
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
			return q6.Errorf("extension choice index exceeds host int")
		}
		v.Choice = int(extIdx) + 2 + 1
		extensionPath := "UnknownExtension"
		switch v.Choice {
		case q5.InterRATMeasuredResultsValueChoiceResultNR:
			extensionPath = "ResultNR"
			recoveryMark_resultnr := inner.RecoveryComponent("ResultNR")
			tmp_resultnr := make(ResultNR, 0)
			_, errCollection_resultnr := q4.DecodeCollection(inner, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_resultnr, fragmentLength_resultnr int64) error {
				// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
				if fragmentOffset_resultnr < 0 || fragmentLength_resultnr < 0 || fragmentLength_resultnr > int64(^uint(0)>>1) || fragmentOffset_resultnr > int64(^uint(0)>>1)-fragmentLength_resultnr {
					return q6.Errorf("collection fragment count out of range")
				}
				for i := int64(0); i < fragmentLength_resultnr; i++ {
					var elem ResultNRItem
					elementMark := inner.RecoveryIndex(fragmentOffset_resultnr + i)
					if err := elem.unmarshalAPERFrom(inner); err != nil {
						return q7.WrapDecodePath(err, q6.Sprintf("ResultNR[%d]", fragmentOffset_resultnr+i))
					}
					inner.LeaveComponent(elementMark)
					if next, err := q4.AppendValues(inner, tmp_resultnr, elem); err != nil {
						return err
					} else {
						tmp_resultnr = next
					}
				}
				return nil
			})
			if errCollection_resultnr != nil {
				return q7.WrapDecodePath(errCollection_resultnr, "ResultNR")
			}
			v.ResultNR = tmp_resultnr
			inner.LeaveComponent(recoveryMark_resultnr)
		}
		padding, err := q4.CaptureOpenTypePadding(inner)
		if err != nil {
			return q7.WrapDecodePath(err, extensionPath)
		}
		v.perOpenTypePadding = padding
		v.stream = bb.CaptureWireSpan(replayStart)
		v.
			stream.RecordUsage(replayUsage,

			bb)

		return nil
	}
	idx, err := q4.DecodeConstrainedWholeNumberAligned(bb, 0, 1)
	if err != nil {
		return err
	}
	// arithmetic pattern APER_CHOICE_ROOT_DECODE: choice index fits the emitted representation; gen/codegen_aper.go:236
	if idx < 0 || idx >= int64(^uint(0)>>1) {
		return q6.Errorf("choice index exceeds host int")
	}
	v.Choice = int(idx) + 1
	switch v.Choice {
	case q5.InterRATMeasuredResultsValueChoiceResultGERAN:
		toleranceMark_resultgeran := bb.EnterComponent("ResultGERAN")
		tmp_resultgeran := make(q12.ResultGERAN, 0)
		_, errCollection_resultgeran := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_resultgeran, fragmentLength_resultgeran int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_resultgeran < 0 || fragmentLength_resultgeran < 0 || fragmentLength_resultgeran > int64(^uint(0)>>1) || fragmentOffset_resultgeran > int64(^uint(0)>>1)-fragmentLength_resultgeran {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_resultgeran; i++ {
				var elem q12.ResultGERANItem
				elementMark := bb.EnterIndex(fragmentOffset_resultgeran + i)
				if err := q12.BridgeResultGERANItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("ResultGERAN[%d]", fragmentOffset_resultgeran+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := q4.AppendValues(bb, tmp_resultgeran, elem); err != nil {
					return err
				} else {
					tmp_resultgeran = next
				}
			}
			return nil
		})
		if errCollection_resultgeran != nil {
			return q7.WrapDecodePath(errCollection_resultgeran, "ResultGERAN")
		}
		v.ResultGERAN = tmp_resultgeran
		bb.LeaveComponent(toleranceMark_resultgeran)
	case q5.InterRATMeasuredResultsValueChoiceResultUTRAN:
		toleranceMark_resultutran := bb.EnterComponent("ResultUTRAN")
		tmp_resultutran := make(q9.ResultUTRAN, 0)
		_, errCollection_resultutran := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_resultutran, fragmentLength_resultutran int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_resultutran < 0 || fragmentLength_resultutran < 0 || fragmentLength_resultutran > int64(^uint(0)>>1) || fragmentOffset_resultutran > int64(^uint(0)>>1)-fragmentLength_resultutran {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_resultutran; i++ {
				var elem q9.ResultUTRANItem
				elementMark := bb.EnterIndex(fragmentOffset_resultutran + i)
				if err := q9.BridgeResultUTRANItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
					return q7.WrapDecodePath(err, q6.Sprintf("ResultUTRAN[%d]", fragmentOffset_resultutran+i))
				}
				bb.LeaveComponent(elementMark)
				if next, err := q4.AppendValues(bb, tmp_resultutran, elem); err != nil {
					return err
				} else {
					tmp_resultutran = next
				}
			}
			return nil
		})
		if errCollection_resultutran != nil {
			return q7.WrapDecodePath(errCollection_resultutran, "ResultUTRAN")
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
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         q13.PosSIBs
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *PosSIBsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := q14.BridgeMarshalAPERPosSIBsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes PosSIBs from APER format.
func (v *PosSIBsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PosSIBs with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PosSIBsComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "PosSIBs")
	}
	value, err := BridgeUnmarshalAPERPosSIBsFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "PosSIBs")
	}
	padding, err := q4.CaptureFinalBits(bb, "PosSIBs")
	if err != nil {
		return q7.WrapDecodePath(err, "PosSIBs")
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
func BridgeUnmarshalAPERPosSIBsFrom(bb *q4.BitBuffer) (q13.PosSIBs, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q13.BridgeAsn1cAPERPosSIBsListValue
	if err := BridgeUnmarshalAPERPosSIBsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERPosSIBsInto(v *q13.BridgeAsn1cAPERPosSIBsListValue, bb *q4.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(q13.PosSIBs, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q13.PosSIBsElem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := q13.BridgePosSIBsElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// PosSIBSegmentsComplete carries a complete PosSIBSegments encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type PosSIBSegmentsComplete struct {
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         q15.PosSIBSegments
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *PosSIBSegmentsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := q14.BridgeMarshalAPERPosSIBSegmentsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes PosSIBSegments from APER format.
func (v *PosSIBSegmentsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PosSIBSegments with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PosSIBSegmentsComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "PosSIBSegments")
	}
	value, err := BridgeUnmarshalAPERPosSIBSegmentsFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "PosSIBSegments")
	}
	padding, err := q4.CaptureFinalBits(bb, "PosSIBSegments")
	if err != nil {
		return q7.WrapDecodePath(err, "PosSIBSegments")
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
func BridgeUnmarshalAPERPosSIBSegmentsFrom(bb *q4.BitBuffer) (q15.PosSIBSegments, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q16.BridgeAsn1cAPERPosSIBSegmentsListValue
	if err := BridgeUnmarshalAPERPosSIBSegmentsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERPosSIBSegmentsInto(v *q16.BridgeAsn1cAPERPosSIBSegmentsListValue, bb *q4.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(q15.PosSIBSegments, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q15.PosSIBSegmentsElem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := q15.BridgePosSIBSegmentsElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ResultRSRPComplete carries a complete ResultRSRP encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultRSRPComplete struct {
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         q12.ResultRSRP
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *ResultRSRPComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := q12.BridgeMarshalAPERResultRSRPTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ResultRSRP from APER format.
func (v *ResultRSRPComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResultRSRP with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResultRSRPComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "ResultRSRP")
	}
	value, err := BridgeUnmarshalAPERResultRSRPFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "ResultRSRP")
	}
	padding, err := q4.CaptureFinalBits(bb, "ResultRSRP")
	if err != nil {
		return q7.WrapDecodePath(err, "ResultRSRP")
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
func BridgeUnmarshalAPERResultRSRPFrom(bb *q4.BitBuffer) (q12.ResultRSRP, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q12.BridgeAsn1cAPERResultRSRPListValue
	if err := BridgeUnmarshalAPERResultRSRPInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERResultRSRPInto(v *q12.BridgeAsn1cAPERResultRSRPListValue, bb *q4.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(q12.ResultRSRP, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q12.ResultRSRPItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := q12.BridgeResultRSRPItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ResultRSRQComplete carries a complete ResultRSRQ encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultRSRQComplete struct {
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         q17.ResultRSRQ
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *ResultRSRQComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := q17.BridgeMarshalAPERResultRSRQTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ResultRSRQ from APER format.
func (v *ResultRSRQComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResultRSRQ with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResultRSRQComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "ResultRSRQ")
	}
	value, err := BridgeUnmarshalAPERResultRSRQFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "ResultRSRQ")
	}
	padding, err := q4.CaptureFinalBits(bb, "ResultRSRQ")
	if err != nil {
		return q7.WrapDecodePath(err, "ResultRSRQ")
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
func BridgeUnmarshalAPERResultRSRQFrom(bb *q4.BitBuffer) (q17.ResultRSRQ, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q17.BridgeAsn1cAPERResultRSRQListValue
	if err := BridgeUnmarshalAPERResultRSRQInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERResultRSRQInto(v *q17.BridgeAsn1cAPERResultRSRQListValue, bb *q4.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(q17.ResultRSRQ, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 9, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q17.ResultRSRQItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := q17.BridgeResultRSRQItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ResultGERANComplete carries a complete ResultGERAN encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultGERANComplete struct {
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         q12.ResultGERAN
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *ResultGERANComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := q12.BridgeMarshalAPERResultGERANTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ResultGERAN from APER format.
func (v *ResultGERANComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResultGERAN with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResultGERANComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "ResultGERAN")
	}
	value, err := BridgeUnmarshalAPERResultGERANFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "ResultGERAN")
	}
	padding, err := q4.CaptureFinalBits(bb, "ResultGERAN")
	if err != nil {
		return q7.WrapDecodePath(err, "ResultGERAN")
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
func BridgeUnmarshalAPERResultGERANFrom(bb *q4.BitBuffer) (q12.ResultGERAN, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q12.BridgeAsn1cAPERResultGERANListValue
	if err := BridgeUnmarshalAPERResultGERANInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERResultGERANInto(v *q12.BridgeAsn1cAPERResultGERANListValue, bb *q4.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(q12.ResultGERAN, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q12.ResultGERANItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := q12.BridgeResultGERANItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ResultUTRANComplete carries a complete ResultUTRAN encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultUTRANComplete struct {
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         q9.ResultUTRAN
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *ResultUTRANComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := q9.BridgeMarshalAPERResultUTRANTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ResultUTRAN from APER format.
func (v *ResultUTRANComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResultUTRAN with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResultUTRANComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "ResultUTRAN")
	}
	value, err := BridgeUnmarshalAPERResultUTRANFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "ResultUTRAN")
	}
	padding, err := q4.CaptureFinalBits(bb, "ResultUTRAN")
	if err != nil {
		return q7.WrapDecodePath(err, "ResultUTRAN")
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
func BridgeUnmarshalAPERResultUTRANFrom(bb *q4.BitBuffer) (q9.ResultUTRAN, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q9.BridgeAsn1cAPERResultUTRANListValue
	if err := BridgeUnmarshalAPERResultUTRANInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERResultUTRANInto(v *q9.BridgeAsn1cAPERResultUTRANListValue, bb *q4.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(q9.ResultUTRAN, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q9.ResultUTRANItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := q9.BridgeResultUTRANItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERResultNRListValue struct{ Value ResultNR }

// MarshalAPER encodes ResultNRItem to APER format.
func (v *ResultNRItem) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ResultNRItem) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
		extensionCount, _ = q18.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
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
	if err := q4.EncodeBoolean(bb, v.SSNRRSRP != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.SSNRRSRQ != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.NRARFCN), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(3279165), false); err != nil {
		return q6.Errorf("encoding nRARFCN: %w", err)
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.NRPCI), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(1007), false); err != nil {
		return q6.Errorf("encoding nRPCI: %w", err)
	}
	if v.SSNRRSRP != nil {
		if err := q4.EncodeIntegerAligned(bb, int64(*v.SSNRRSRP), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(127), false); err != nil {
			return q6.Errorf("encoding sS-NRRSRP: %w", err)
		}
	}
	if v.SSNRRSRQ != nil {
		if err := q4.EncodeIntegerAligned(bb, int64(*v.SSNRRSRQ), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(127), false); err != nil {
			return q6.Errorf("encoding sS-NRRSRQ: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := q4.EncodeCollection(bb, int64(len(v.IEExtensions)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ResultNRItem from APER format.
func (v *ResultNRItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResultNRItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResultNRItem) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "ResultNRItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "ResultNRItem")
	}
	padding, err := q4.CaptureFinalBits(bb, "ResultNRItem")
	if err != nil {
		return q7.WrapDecodePath(err, "ResultNRItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ResultNRItem) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultNRItem{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ssnrrsrp, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ssnrrsrq, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_nrarfcn, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(3279165), false)
	if err != nil {
		return q7.WrapDecodePath(err, "NRARFCN")
	}
	v.NRARFCN = q5.NRARFCN(val_nrarfcn)
	val_nrpci, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(1007), false)
	if err != nil {
		return q7.WrapDecodePath(err, "NRPCI")
	}
	v.NRPCI = q5.NRPCI(val_nrpci)
	if opt_ssnrrsrp {
		val_ssnrrsrp, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(127), false)
		if err != nil {
			return q7.WrapDecodePath(err, "SSNRRSRP")
		}
		tmp_ssnrrsrp := q5.SSNRRSRP(val_ssnrrsrp)
		if err := q4.ChargeValue(bb, tmp_ssnrrsrp); err != nil {
			return err
		}
		v.SSNRRSRP = (*q5.SSNRRSRP)(bb.OwnInt64(int64(tmp_ssnrrsrp)))
	}
	if opt_ssnrrsrq {
		val_ssnrrsrq, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(127), false)
		if err != nil {
			return q7.WrapDecodePath(err, "SSNRRSRQ")
		}
		tmp_ssnrrsrq := q5.SSNRRSRQ(val_ssnrrsrq)
		if err := q4.ChargeValue(bb, tmp_ssnrrsrq); err != nil {
			return err
		}
		v.SSNRRSRQ = (*q5.SSNRRSRQ)(bb.OwnInt64(int64(tmp_ssnrrsrq)))
	}
	if opt_ieextensions {
		tmp_ieextensions := make(ResultNRItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem ResultNRItemExtIEsExtField
				if err := elem.unmarshalAPERFrom(bb); err != nil {
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

// ResultsPerSSBIndexListComplete carries a complete ResultsPerSSBIndexList encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type ResultsPerSSBIndexListComplete struct {
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         q9.ResultsPerSSBIndexList
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *ResultsPerSSBIndexListComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := q9.BridgeMarshalAPERResultsPerSSBIndexListTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes ResultsPerSSBIndexList from APER format.
func (v *ResultsPerSSBIndexListComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResultsPerSSBIndexList with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResultsPerSSBIndexListComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "ResultsPerSSBIndexList")
	}
	value, err := BridgeUnmarshalAPERResultsPerSSBIndexListFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "ResultsPerSSBIndexList")
	}
	padding, err := q4.CaptureFinalBits(bb, "ResultsPerSSBIndexList")
	if err != nil {
		return q7.WrapDecodePath(err, "ResultsPerSSBIndexList")
	}
	v.Value, v.perPadding = value, padding.Padding()
	return nil
}

// MarshalAPERResultsPerSSBIndexList encodes a ResultsPerSSBIndexList list to APER.
func BridgeMarshalAPERResultsPerSSBIndexList(list ResultsPerSSBIndexListComplete) ([]byte, error) {
	return list.marshalAPERLegacy()
}

// UnmarshalAPERResultsPerSSBIndexListFrom decodes a ResultsPerSSBIndexList list from bb.
func BridgeUnmarshalAPERResultsPerSSBIndexListFrom(bb *q4.BitBuffer) (q9.ResultsPerSSBIndexList, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q9.BridgeAsn1cAPERResultsPerSSBIndexListListValue
	if err := BridgeUnmarshalAPERResultsPerSSBIndexListInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}
func BridgeUnmarshalAPERResultsPerSSBIndexListInto(v *q9.BridgeAsn1cAPERResultsPerSSBIndexListListValue, bb *q4.BitBuffer) error {
	toleranceMark_value := bb.EnterComponent("Value")
	v.Value = make(q9.ResultsPerSSBIndexList, 0)
	_, errCollection_value := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_value < 0 || fragmentLength_value < 0 || fragmentLength_value > int64(^uint(0)>>1) || fragmentOffset_value > int64(^uint(0)>>1)-fragmentLength_value {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_value; i++ {
			var elem q9.ResultsPerSSBIndexItem
			elementMark := bb.EnterIndex(fragmentOffset_value + i)
			if err := q9.BridgeResultsPerSSBIndexItemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// PRSFrequencyHoppingConfigurationBandPositionsComplete carries a complete PRSFrequencyHoppingConfigurationBandPositions encoding, including observed terminal bits.
// ITU-T X.691 (02/2021) 11.1.3.1 and 11.1.4 require new encodings to pad with zero bits.
type PRSFrequencyHoppingConfigurationBandPositionsComplete struct {
	replay        q4.Snapshot
	stream        q4.WireSpan
	withoutReplay bool
	received      bool
	receivedBytes q4.WireSpan
	Value         q5.PRSFrequencyHoppingConfigurationBandPositions
	perPadding    q4.CompletePadding `json:"-"`
}

func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := q19.BridgeMarshalAPERPRSFrequencyHoppingConfigurationBandPositionsTo(v.Value, bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithPadding(v.perPadding)
}

// UnmarshalAPER decodes PRSFrequencyHoppingConfigurationBandPositions from APER format.
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes PRSFrequencyHoppingConfigurationBandPositions with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "PRSFrequencyHoppingConfigurationBandPositions")
	}
	value, err := BridgeUnmarshalAPERPRSFrequencyHoppingConfigurationBandPositionsFrom(bb)
	if err != nil {
		return q7.WrapDecodePath(err, "PRSFrequencyHoppingConfigurationBandPositions")
	}
	padding, err := q4.CaptureFinalBits(bb, "PRSFrequencyHoppingConfigurationBandPositions")
	if err != nil {
		return q7.WrapDecodePath(err, "PRSFrequencyHoppingConfigurationBandPositions")
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

// UnmarshalAPERPRSFrequencyHoppingConfigurationBandPositionsFrom decodes a PRSFrequencyHoppingConfigurationBandPositions list from bb.
func BridgeUnmarshalAPERPRSFrequencyHoppingConfigurationBandPositionsFrom(bb *q4.BitBuffer) (q5.PRSFrequencyHoppingConfigurationBandPositions, error) {
	if err := bb.EnterDecodeValue(); err != nil {
		return nil, err
	}
	defer bb.LeaveDecodeValue()
	var v q5.BridgeAsn1cAPERPRSFrequencyHoppingConfigurationBandPositionsListValue
	if err := q20.BridgeUnmarshalAPERPRSFrequencyHoppingConfigurationBandPositionsInto(&v, bb); err != nil {
		return nil, err
	}
	return v.Value, nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *InterRATMeasuredResultsValue) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q18.BridgeReceivedFormAt(v.received, v.receivedBytes, "InterRATMeasuredResultsValue", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InterRATMeasuredResultsValue) WithoutReplay() InterRATMeasuredResultsValue {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero InterRATMeasuredResultsValue
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q18.BridgeReceivedFormAt(v.received, v.receivedBytes, "PRSFrequencyHoppingConfigurationBandPositionsComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PRSFrequencyHoppingConfigurationBandPositionsComplete) WithoutReplay() PRSFrequencyHoppingConfigurationBandPositionsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero PRSFrequencyHoppingConfigurationBandPositionsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PosSIBSegmentsComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q18.BridgeReceivedFormAt(v.received, v.receivedBytes, "PosSIBSegmentsComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PosSIBSegmentsComplete) WithoutReplay() PosSIBSegmentsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero PosSIBSegmentsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *PosSIBsComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q18.BridgeReceivedFormAt(v.received, v.receivedBytes, "PosSIBsComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v PosSIBsComplete) WithoutReplay() PosSIBsComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero PosSIBsComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultGERANComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q18.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultGERANComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultGERANComplete) WithoutReplay() ResultGERANComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero ResultGERANComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultNRItem) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q18.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultNRItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultNRItem) WithoutReplay() ResultNRItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero ResultNRItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultRSRPComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q18.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultRSRPComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultRSRPComplete) WithoutReplay() ResultRSRPComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero ResultRSRPComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultRSRQComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q18.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultRSRQComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultRSRQComplete) WithoutReplay() ResultRSRQComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero ResultRSRQComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultUTRANComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q18.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultUTRANComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultUTRANComplete) WithoutReplay() ResultUTRANComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero ResultUTRANComplete
	v.perPadding = zero.perPadding
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultsPerSSBIndexListComplete) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q18.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultsPerSSBIndexListComplete", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultsPerSSBIndexListComplete) WithoutReplay() ResultsPerSSBIndexListComplete {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero ResultsPerSSBIndexListComplete
	v.perPadding = zero.perPadding
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *ResultNRItem) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ResultNRItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ResultNRItem.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ResultNRItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ResultNRItem) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ResultNRItem.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ResultNRItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *InterRATMeasuredResultsValue) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "InterRATMeasuredResultsValue")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "InterRATMeasuredResultsValue")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaInterRATMeasuredResultsValue(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "InterRATMeasuredResultsValue")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "InterRATMeasuredResultsValue")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "InterRATMeasuredResultsValue")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "InterRATMeasuredResultsValue")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "InterRATMeasuredResultsValue")
}
func (v *InterRATMeasuredResultsValue) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *InterRATMeasuredResultsValue) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *InterRATMeasuredResultsValue) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *InterRATMeasuredResultsValue) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *InterRATMeasuredResultsValue) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaPRSFrequencyHoppingConfigurationBandPositionsComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
}
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q19.BridgeMarshalAPERPRSFrequencyHoppingConfigurationBandPositionsTo(value.Value, bb, fresh); err != nil {
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
func (v *PosSIBSegmentsComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "PosSIBSegmentsComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "PosSIBSegmentsComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaPosSIBSegmentsComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "PosSIBSegmentsComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "PosSIBSegmentsComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "PosSIBSegmentsComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "PosSIBSegmentsComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "PosSIBSegmentsComplete")
}
func (v *PosSIBSegmentsComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *PosSIBSegmentsComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *PosSIBSegmentsComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *PosSIBSegmentsComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *PosSIBSegmentsComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q14.BridgeMarshalAPERPosSIBSegmentsTo(value.Value, bb, fresh); err != nil {
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
func (v *PosSIBsComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "PosSIBsComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "PosSIBsComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaPosSIBsComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "PosSIBsComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "PosSIBsComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "PosSIBsComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "PosSIBsComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "PosSIBsComplete")
}
func (v *PosSIBsComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *PosSIBsComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *PosSIBsComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *PosSIBsComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *PosSIBsComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q14.BridgeMarshalAPERPosSIBsTo(value.Value, bb, fresh); err != nil {
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
func (v *ResultGERANComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "ResultGERANComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "ResultGERANComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaResultGERANComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "ResultGERANComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "ResultGERANComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "ResultGERANComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "ResultGERANComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "ResultGERANComplete")
}
func (v *ResultGERANComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultGERANComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultGERANComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *ResultGERANComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultGERANComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q12.BridgeMarshalAPERResultGERANTo(value.Value, bb, fresh); err != nil {
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
func (v *ResultNRItem) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "ResultNRItem")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "ResultNRItem")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaResultNRItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "ResultNRItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "ResultNRItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "ResultNRItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "ResultNRItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "ResultNRItem")
}
func (v *ResultNRItem) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultNRItem) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultNRItem) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *ResultNRItem) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultNRItem) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ResultRSRPComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "ResultRSRPComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "ResultRSRPComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaResultRSRPComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "ResultRSRPComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "ResultRSRPComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "ResultRSRPComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "ResultRSRPComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "ResultRSRPComplete")
}
func (v *ResultRSRPComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultRSRPComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultRSRPComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *ResultRSRPComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultRSRPComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q12.BridgeMarshalAPERResultRSRPTo(value.Value, bb, fresh); err != nil {
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
func (v *ResultRSRQComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "ResultRSRQComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "ResultRSRQComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaResultRSRQComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "ResultRSRQComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "ResultRSRQComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "ResultRSRQComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "ResultRSRQComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "ResultRSRQComplete")
}
func (v *ResultRSRQComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultRSRQComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultRSRQComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *ResultRSRQComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultRSRQComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q17.BridgeMarshalAPERResultRSRQTo(value.Value, bb, fresh); err != nil {
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
func (v *ResultUTRANComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "ResultUTRANComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "ResultUTRANComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaResultUTRANComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "ResultUTRANComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "ResultUTRANComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "ResultUTRANComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "ResultUTRANComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "ResultUTRANComplete")
}
func (v *ResultUTRANComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultUTRANComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultUTRANComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *ResultUTRANComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultUTRANComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q9.BridgeMarshalAPERResultUTRANTo(value.Value, bb, fresh); err != nil {
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
func (v *ResultsPerSSBIndexListComplete) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "ResultsPerSSBIndexListComplete")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "ResultsPerSSBIndexListComplete")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaResultsPerSSBIndexListComplete(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "ResultsPerSSBIndexListComplete")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "ResultsPerSSBIndexListComplete")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "ResultsPerSSBIndexListComplete")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "ResultsPerSSBIndexListComplete")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "ResultsPerSSBIndexListComplete")
}
func (v *ResultsPerSSBIndexListComplete) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultsPerSSBIndexListComplete) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultsPerSSBIndexListComplete) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
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
func (v *ResultsPerSSBIndexListComplete) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultsPerSSBIndexListComplete) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	bb := q4.NewBudgetBuffer(budget)
	value := v
	if fresh {
		previous := bb.SuspendReplayPlan()
		defer bb.RestoreReplayPlan(previous)
		copyValue := v.WithoutReplay()
		value = &copyValue
	}
	if err := q9.BridgeMarshalAPERResultsPerSSBIndexListTo(value.Value, bb, fresh); err != nil {
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
func (v *InterRATMeasuredResultsValue) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "InterRATMeasuredResultsValue")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded InterRATMeasuredResultsValue
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaInterRATMeasuredResultsValue(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = InterRATMeasuredResultsValue{}
		return report, q4.OperationError(err, "InterRATMeasuredResultsValue")
	}
	*v = decoded
	return report, q4.OperationError(nil, "InterRATMeasuredResultsValue")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *PRSFrequencyHoppingConfigurationBandPositionsComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded PRSFrequencyHoppingConfigurationBandPositionsComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaPRSFrequencyHoppingConfigurationBandPositionsComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = PRSFrequencyHoppingConfigurationBandPositionsComplete{}
		return report, q4.OperationError(err, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "PRSFrequencyHoppingConfigurationBandPositionsComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *PosSIBSegmentsComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "PosSIBSegmentsComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded PosSIBSegmentsComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaPosSIBSegmentsComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = PosSIBSegmentsComplete{}
		return report, q4.OperationError(err, "PosSIBSegmentsComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "PosSIBSegmentsComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *PosSIBsComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "PosSIBsComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded PosSIBsComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaPosSIBsComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = PosSIBsComplete{}
		return report, q4.OperationError(err, "PosSIBsComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "PosSIBsComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultGERANComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "ResultGERANComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded ResultGERANComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultGERANComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = ResultGERANComplete{}
		return report, q4.OperationError(err, "ResultGERANComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "ResultGERANComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultNRItem) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "ResultNRItem")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded ResultNRItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultNRItem(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = ResultNRItem{}
		return report, q4.OperationError(err, "ResultNRItem")
	}
	*v = decoded
	return report, q4.OperationError(nil, "ResultNRItem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultRSRPComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "ResultRSRPComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded ResultRSRPComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultRSRPComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = ResultRSRPComplete{}
		return report, q4.OperationError(err, "ResultRSRPComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "ResultRSRPComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultRSRQComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "ResultRSRQComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded ResultRSRQComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultRSRQComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = ResultRSRQComplete{}
		return report, q4.OperationError(err, "ResultRSRQComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "ResultRSRQComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultUTRANComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "ResultUTRANComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded ResultUTRANComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultUTRANComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = ResultUTRANComplete{}
		return report, q4.OperationError(err, "ResultUTRANComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "ResultUTRANComplete")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultsPerSSBIndexListComplete) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "ResultsPerSSBIndexListComplete")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded ResultsPerSSBIndexListComplete
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultsPerSSBIndexListComplete(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = ResultsPerSSBIndexListComplete{}
		return report, q4.OperationError(err, "ResultsPerSSBIndexListComplete")
	}
	*v = decoded
	return report, q4.OperationError(nil, "ResultsPerSSBIndexListComplete")
}

// MarshalAPERPosSIBs encodes a complete named list.
func MarshalAPERPosSIBs(v PosSIBsComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERPosSIBSegments encodes a complete named list.
func MarshalAPERPosSIBSegments(v PosSIBSegmentsComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERResultRSRP encodes a complete named list.
func MarshalAPERResultRSRP(v ResultRSRPComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERResultRSRQ encodes a complete named list.
func MarshalAPERResultRSRQ(v ResultRSRQComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERResultGERAN encodes a complete named list.
func MarshalAPERResultGERAN(v ResultGERANComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERResultUTRAN encodes a complete named list.
func MarshalAPERResultUTRAN(v ResultUTRANComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERResultsPerSSBIndexList encodes a complete named list.
func MarshalAPERResultsPerSSBIndexList(v ResultsPerSSBIndexListComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// MarshalAPERPRSFrequencyHoppingConfigurationBandPositions encodes a complete named list.
func MarshalAPERPRSFrequencyHoppingConfigurationBandPositions(v PRSFrequencyHoppingConfigurationBandPositionsComplete, options ...q4.EncodeOption) ([]byte, error) {
	return v.MarshalAPER(options...)
}

// UnmarshalAPERPosSIBs decodes a complete named list.
func UnmarshalAPERPosSIBs(data []byte, options ...q4.DecodeOption) (PosSIBsComplete, q4.DecodeReport, error) {
	var v PosSIBsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERPosSIBSegments decodes a complete named list.
func UnmarshalAPERPosSIBSegments(data []byte, options ...q4.DecodeOption) (PosSIBSegmentsComplete, q4.DecodeReport, error) {
	var v PosSIBSegmentsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERResultRSRP decodes a complete named list.
func UnmarshalAPERResultRSRP(data []byte, options ...q4.DecodeOption) (ResultRSRPComplete, q4.DecodeReport, error) {
	var v ResultRSRPComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERResultRSRQ decodes a complete named list.
func UnmarshalAPERResultRSRQ(data []byte, options ...q4.DecodeOption) (ResultRSRQComplete, q4.DecodeReport, error) {
	var v ResultRSRQComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERResultGERAN decodes a complete named list.
func UnmarshalAPERResultGERAN(data []byte, options ...q4.DecodeOption) (ResultGERANComplete, q4.DecodeReport, error) {
	var v ResultGERANComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERResultUTRAN decodes a complete named list.
func UnmarshalAPERResultUTRAN(data []byte, options ...q4.DecodeOption) (ResultUTRANComplete, q4.DecodeReport, error) {
	var v ResultUTRANComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERResultsPerSSBIndexList decodes a complete named list.
func UnmarshalAPERResultsPerSSBIndexList(data []byte, options ...q4.DecodeOption) (ResultsPerSSBIndexListComplete, q4.DecodeReport, error) {
	var v ResultsPerSSBIndexListComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}

// UnmarshalAPERPRSFrequencyHoppingConfigurationBandPositions decodes a complete named list.
func UnmarshalAPERPRSFrequencyHoppingConfigurationBandPositions(data []byte, options ...q4.DecodeOption) (PRSFrequencyHoppingConfigurationBandPositionsComplete, q4.DecodeReport, error) {
	var v PRSFrequencyHoppingConfigurationBandPositionsComplete
	report, err := v.UnmarshalAPER(data, options...)
	return v, report, err
}
func BridgeCaptureLPPaInterRATMeasuredResultsValue(v *InterRATMeasuredResultsValue, s *q4.SemanticCapture) {
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
	case q5.InterRATMeasuredResultsValueChoiceResultGERAN:
		q12.BridgeCaptureLPPaResultGERAN(&v.ResultGERAN, s)
	case q5.InterRATMeasuredResultsValueChoiceResultUTRAN:
		q9.BridgeCaptureLPPaResultUTRAN(&v.ResultUTRAN, s)
	case q5.InterRATMeasuredResultsValueChoiceResultNR:
		BridgeCaptureLPPaResultNR(&v.ResultNR, s)
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaInterRATMeasuredResultsValue(v *InterRATMeasuredResultsValue, s *q4.SemanticComparison) {
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
	case q5.InterRATMeasuredResultsValueChoiceResultGERAN:
		q12.BridgeCompareLPPaResultGERAN(&v.ResultGERAN, s)
	case q5.InterRATMeasuredResultsValueChoiceResultUTRAN:
		q9.BridgeCompareLPPaResultUTRAN(&v.ResultUTRAN, s)
	case q5.InterRATMeasuredResultsValueChoiceResultNR:
		BridgeCompareLPPaResultNR(&v.ResultNR, s)
	}
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaPRSFrequencyHoppingConfigurationBandPositionsComplete(v *PRSFrequencyHoppingConfigurationBandPositionsComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q5.BridgeCaptureLPPaPRSFrequencyHoppingConfigurationBandPositions(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaPRSFrequencyHoppingConfigurationBandPositionsComplete(v *PRSFrequencyHoppingConfigurationBandPositionsComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q11.BridgeCompareLPPaPRSFrequencyHoppingConfigurationBandPositions(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaPosSIBSegmentsComplete(v *PosSIBSegmentsComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q16.BridgeCaptureLPPaPosSIBSegments(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaPosSIBSegmentsComplete(v *PosSIBSegmentsComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q13.BridgeCompareLPPaPosSIBSegments(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaPosSIBsComplete(v *PosSIBsComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q13.BridgeCaptureLPPaPosSIBs(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaPosSIBsComplete(v *PosSIBsComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q13.BridgeCompareLPPaPosSIBs(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultGERANComplete(v *ResultGERANComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q12.BridgeCaptureLPPaResultGERAN(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultGERANComplete(v *ResultGERANComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q12.BridgeCompareLPPaResultGERAN(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultNR(v *ResultNR, s *q4.SemanticCapture) {
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
func BridgeCompareLPPaResultNR(v *ResultNR, s *q4.SemanticComparison) {
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
		s.End(f, q4.Snapshot{}, false)
	}
	s.End(f, q4.Snapshot{}, false)
}
func BridgeCaptureLPPaResultNRItem(v *ResultNRItem, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q5.BridgeCaptureLPPaNRARFCN(&v.NRARFCN, s)
	q5.BridgeCaptureLPPaNRPCI(&v.NRPCI, s)
	{
		f := s.Begin()
		s.Bool(v.SSNRRSRP == nil)
		if v.SSNRRSRP != nil {
			q5.BridgeCaptureLPPaSSNRRSRP(v.SSNRRSRP, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.SSNRRSRQ == nil)
		if v.SSNRRSRQ != nil {
			q5.BridgeCaptureLPPaSSNRRSRQ(v.SSNRRSRQ, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeResultNRItemExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultNRItem(v *ResultNRItem, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q11.BridgeCompareLPPaNRARFCN(&v.NRARFCN, s)
	q11.BridgeCompareLPPaNRPCI(&v.NRPCI, s)
	{
		f := s.Begin()
		s.Bool(v.SSNRRSRP == nil)
		if v.SSNRRSRP != nil {
			q8.BridgeCompareLPPaSSNRRSRP(v.SSNRRSRP, s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.SSNRRSRQ == nil)
		if v.SSNRRSRQ != nil {
			q8.BridgeCompareLPPaSSNRRSRQ(v.SSNRRSRQ, s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeResultNRItemExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultNRItemExtIEsValue(v *ResultNRItemExtIEsValue, s *q4.SemanticCapture) {
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
		case q5.ProtocolIEID(25):
			{
				f := s.Begin()
				s.Bool(v.rowResultsPerSSBIndexList == nil)
				if v.rowResultsPerSSBIndexList != nil {
					q9.BridgeCaptureLPPaResultsPerSSBIndexList(v.rowResultsPerSSBIndexList, s)
				}
				s.End(f, nil, false)
			}
		case q5.ProtocolIEID(27):
			{
				f := s.Begin()
				s.Bool(v.rowNRCGI == nil)
				if v.rowNRCGI != nil {
					q10.BridgeCaptureLPPaNRCGI(v.rowNRCGI, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v ResultNRItemExtIEsValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v ResultNRItemExtIEsValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v ResultNRItemExtIEsValue) captureSemantics(s q4.SemanticCapture) ResultNRItemExtIEsValue {
	BridgeCaptureLPPaResultNRItemExtIEsValue(&v, &s)
	return v
}
func BridgeCompareLPPaResultNRItemExtIEsValue(v *ResultNRItemExtIEsValue, s *q4.SemanticComparison) {
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
		case q5.ProtocolIEID(25):
			{
				f := s.Begin()
				s.Bool(v.rowResultsPerSSBIndexList == nil)
				if v.rowResultsPerSSBIndexList != nil {
					q9.BridgeCompareLPPaResultsPerSSBIndexList(v.rowResultsPerSSBIndexList, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(27):
			{
				f := s.Begin()
				s.Bool(v.rowNRCGI == nil)
				if v.rowNRCGI != nil {
					q10.BridgeCompareLPPaNRCGI(v.rowNRCGI, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v ResultNRItemExtIEsValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaResultNRItemExtIEsValue(&v, &s)
	return s
}
func (v ResultNRItemExtIEsValue) WithoutReplay() ResultNRItemExtIEsValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCaptureLPPaResultRSRPComplete(v *ResultRSRPComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q12.BridgeCaptureLPPaResultRSRP(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultRSRPComplete(v *ResultRSRPComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q12.BridgeCompareLPPaResultRSRP(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultRSRQComplete(v *ResultRSRQComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q17.BridgeCaptureLPPaResultRSRQ(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultRSRQComplete(v *ResultRSRQComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q17.BridgeCompareLPPaResultRSRQ(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultUTRANComplete(v *ResultUTRANComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q9.BridgeCaptureLPPaResultUTRAN(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultUTRANComplete(v *ResultUTRANComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q9.BridgeCompareLPPaResultUTRAN(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultsPerSSBIndexListComplete(v *ResultsPerSSBIndexListComplete, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Stream(v.stream)
	q9.BridgeCaptureLPPaResultsPerSSBIndexList(&v.Value, s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultsPerSSBIndexListComplete(v *ResultsPerSSBIndexListComplete, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	q9.BridgeCompareLPPaResultsPerSSBIndexList(&v.Value, s)
	s.End(f, v.replay, v.withoutReplay)
}

type ResultNRItemExtIEsValue struct {
	id                        q5.ProtocolIEID
	withoutReplay             bool
	received                  q4.WireSpan
	replay                    q4.Snapshot
	opaque                    *q4.OpaqueOpenType
	isOpaque                  bool
	rowResultsPerSSBIndexList *q9.ResultsPerSSBIndexList
	rowNRCGI                  *q10.NRCGI
}

func (v ResultNRItemExtIEsValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q5.ProtocolIEID(25):
		return v.rowResultsPerSSBIndexList != nil
	case q5.ProtocolIEID(27):
		return v.rowNRCGI != nil
	default:
		return false
	}
}
func (v *ResultNRItemExtIEsValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (ResultNRItemExtIEsValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultNR-Item-ExtIEs"}}
}
func (ResultNRItemExtIEsValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(25):
		return q4.UnknownSelector
	case q5.ProtocolIEID(27):
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
	case q5.ProtocolIEID(13):
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
	default:
		return q4.UnknownSelector
	}
}
func (v *ResultNRItemExtIEsValue) AsResultsPerSSBIndexList() (*q9.ResultsPerSSBIndexList, bool) {
	if v == nil || v.id != q5.ProtocolIEID(25) || v.rowResultsPerSSBIndexList == nil {
		return nil, false
	}
	return v.rowResultsPerSSBIndexList, true
}
func (v *ResultNRItemExtIEsValue) AsNRCGI() (*q10.NRCGI, bool) {
	if v == nil || v.id != q5.ProtocolIEID(27) || v.rowNRCGI == nil {
		return nil, false
	}
	return v.rowNRCGI, true
}
func (v ResultNRItemExtIEsValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (ResultNRItemExtIEsValue, error) {
	out := ResultNRItemExtIEsValue{id: id}
	var scope *q4.BitBuffer
	switch id {
	case 25, 27:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q5.ProtocolIEID(25):
		replayUsage := scope.Usage()
		child := raw.ChildDecodeBuffer()
		list, err := BridgeUnmarshalAPERResultsPerSSBIndexListFrom(child)
		if err != nil {
			return out, q6.Errorf("%s %w", "ResultsPerSSBIndexList:", err)
		}
		padding, err := q4.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		complete := ResultsPerSSBIndexListComplete{Value: list, perPadding: padding}
		value := complete.Value
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowResultsPerSSBIndexList = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q5.ProtocolIEID(27):
		replayUsage := scope.Usage()
		var value q10.NRCGI
		child := raw.ChildDecodeBuffer()
		if err := q10.BridgeNRCGIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, q6.Errorf("%s %w", "NRCGI:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "NRCGI")
		if err != nil {
			return out, err
		}
		*q10.BridgeNRCGIFieldPerPadding(&value) = padding
		*q10.BridgeNRCGIFieldReceived(&value) = true
		raw.RetainContents(q10.BridgeNRCGIFieldReceivedBytes(&value))
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowNRCGI = &value
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
func (v ResultNRItemExtIEsValue) encode() ([]byte, error) {
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v ResultNRItemExtIEsValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
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
	case q5.ProtocolIEID(25):
		if v.rowResultsPerSSBIndexList == nil {
			return nil, q6.Errorf("%s missing value", "ResultNR-Item-ExtIEs.id-ResultsPerSSB-Index-List:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
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
	case q5.ProtocolIEID(27):
		if v.rowNRCGI == nil {
			return nil, q6.Errorf("%s missing value", "ResultNR-Item-ExtIEs.id-NR-CGI:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := q10.BridgeNRCGIMethodMarshalAPERBudget(v.rowNRCGI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, q6.Errorf("%s id %d has no value", "ResultNRItemExtIEsValue:", v.id)
	}
}

type ResultNRItemExtIETable struct{}

func ResultNRItemExtIEs() ResultNRItemExtIETable { return ResultNRItemExtIETable{} }
func (ResultNRItemExtIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultNR-Item-ExtIEs"}
		return sealed
	}()
}
func (ResultNRItemExtIETable) infoResultsPerSSBIndexList() q5.FieldInfo {
	return q5.FieldInfo{Table: ResultNRItemExtIEs().ID(), ID: q5.ProtocolIEID(25), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultsPerSSBIndexList"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultNR-Item-ExtIEs", Row: "id-ResultsPerSSB-Index-List"}}}
}
func (t ResultNRItemExtIETable) ResultsPerSSBIndexList() ResultNRItemExtIEsResultsPerSSBIndexListExtBinding {
	return ResultNRItemExtIEsResultsPerSSBIndexListExtBinding{info: t.infoResultsPerSSBIndexList(), codec: func() q9.ResultsPerSSBIndexListValueCodec {
		sealed := q9.ResultsPerSSBIndexListValueCodec{}
		*q9.BridgeResultsPerSSBIndexListValueCodecFieldPath(&sealed) = "ResultsPerSSBIndexList"
		*q9.BridgeResultsPerSSBIndexListValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q9.ResultsPerSSBIndexList, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q9.ResultsPerSSBIndexList
				return empty, err
			}
			var zero ResultNRItemExtIEsValue
			decoded, err := zero.decode(q5.ProtocolIEID(25), raw)
			if err != nil {
				var empty q9.ResultsPerSSBIndexList
				return empty, err
			}
			value, ok := decoded.AsResultsPerSSBIndexList()
			if !ok {
				var empty q9.ResultsPerSSBIndexList
				return empty, q6.Errorf("binding ResultNR-Item-ExtIEs.id-ResultsPerSSB-Index-List: no selected value")
			}
			return *value, nil
		}
		*q9.BridgeResultsPerSSBIndexListValueCodecFieldEncode(&sealed) = func(value q9.ResultsPerSSBIndexList, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (ResultNRItemExtIEsValue{id: q5.ProtocolIEID(25), rowResultsPerSSBIndexList: &value}).encodeFresh(fresh, budget)
		}
		*q9.BridgeResultsPerSSBIndexListValueCodecFieldCapture(&sealed) = func(v q9.ResultsPerSSBIndexList, options q4.DecodeState) (q9.ResultsPerSSBIndexList, q4.Snapshot,

		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q9.BridgeCaptureLPPaResultsPerSSBIndexList(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q9.BridgeResultsPerSSBIndexListValueCodecFieldCompare(&sealed) = func(v q9.ResultsPerSSBIndexList, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q9.BridgeCompareLPPaResultsPerSSBIndexList(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q9.BridgeResultsPerSSBIndexListValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:ResultsPerSSBIndexList"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q9.ResultsPerSSBIndexList) ResultNRItemExtIEsValue {
			return ResultNRItemExtIEsValue{id: q5.ProtocolIEID(25), rowResultsPerSSBIndexList: &value}
		}, get: func(value *ResultNRItemExtIEsValue) (*q9.ResultsPerSSBIndexList, bool) {
			return value.AsResultsPerSSBIndexList()
		}}
}
func (ResultNRItemExtIETable) infoNRCGI() q5.FieldInfo {
	return q5.FieldInfo{Table: ResultNRItemExtIEs().ID(), ID: q5.ProtocolIEID(27), Criticality: q5.CriticalityIgnore, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "NRCGI"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.5", Assignment: q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "ResultNR-Item-ExtIEs", Row: "id-NR-CGI"}}}
}
func (t ResultNRItemExtIETable) NRCGI() ResultNRItemExtIEsNRCGIExtBinding {
	return ResultNRItemExtIEsNRCGIExtBinding{info: t.infoNRCGI(), codec: func() q10.NRCGIValueCodec {
		sealed := q10.NRCGIValueCodec{}
		*q10.BridgeNRCGIValueCodecFieldPath(&sealed) = "NRCGI"
		*q10.BridgeNRCGIValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q10.NRCGI, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q10.NRCGI
				return empty, err
			}
			var zero ResultNRItemExtIEsValue
			decoded, err := zero.decode(q5.ProtocolIEID(27), raw)
			if err != nil {
				var empty q10.NRCGI
				return empty, err
			}
			value, ok := decoded.AsNRCGI()
			if !ok {
				var empty q10.NRCGI
				return empty, q6.Errorf("binding ResultNR-Item-ExtIEs.id-NR-CGI: no selected value")
			}
			return *value, nil
		}
		*q10.BridgeNRCGIValueCodecFieldEncode(&sealed) = func(value q10.NRCGI, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (ResultNRItemExtIEsValue{id: q5.ProtocolIEID(27), rowNRCGI: &value}).encodeFresh(fresh, budget)
		}
		*q10.BridgeNRCGIValueCodecFieldCapture(&sealed) = func(v q10.NRCGI, options q4.DecodeState) (q10.NRCGI, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q10.BridgeCaptureLPPaNRCGI(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q10.BridgeNRCGIValueCodecFieldCompare(&sealed) = func(v q10.NRCGI, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root,
				limits)
			f := s.Begin()
			q10.BridgeCompareLPPaNRCGI(&v, &s)
			s.End(
				f, root, false)
			return s.Plan()
		}
		*q10.BridgeNRCGIValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:NRCGI"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q10.NRCGI) ResultNRItemExtIEsValue {
			return ResultNRItemExtIEsValue{id: q5.ProtocolIEID(27), rowNRCGI: &value}
		}, get: func(value *ResultNRItemExtIEsValue) (*q10.NRCGI, bool) { return value.AsNRCGI() }}
}
func (t ResultNRItemExtIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (ResultNRItemExtIEsExtField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return ResultNRItemExtIEsExtField{}, q4.OperationError(q6.Errorf("invalid opaque extension selector or criticality"), "Opaque")
	}
	switch id {
	case q5.ProtocolIEID(25):
		return ResultNRItemExtIEsExtField{}, q4.OperationError(q6.Errorf("known extension id-ResultsPerSSB-Index-List requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(27):
		return ResultNRItemExtIEsExtField{}, q4.OperationError(q6.Errorf("known extension id-NR-CGI requires its typed binding"), "Opaque")
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return ResultNRItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return ResultNRItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return ResultNRItemExtIEsExtField{}, q4.OperationError(err, "Opaque")
		}
		return ResultNRItemExtIEsExtField{Id: id, Criticality: criticality, ExtensionValue: ResultNRItemExtIEsValue{id: id, opaque: retained, isOpaque: true}}, q4.OperationError(nil, "Opaque")
	}
}

// NRCGICodec binds the complete APER value type.
func NRCGICodec() q10.NRCGIValueCodec { return ResultNRItemExtIEs().NRCGI().Codec() }

// PRSFrequencyHoppingConfigurationBandPositionsCodec binds the complete source value type.
func PRSFrequencyHoppingConfigurationBandPositionsCodec() q21.PRSFrequencyHoppingConfigurationBandPositionsValueCodec {
	return func() q21.PRSFrequencyHoppingConfigurationBandPositionsValueCodec {
		sealed := q21.PRSFrequencyHoppingConfigurationBandPositionsValueCodec{}
		*q21.BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldPath(&sealed) = "PRSFrequencyHoppingConfigurationBandPositions"
		*q21.BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.PRSFrequencyHoppingConfigurationBandPositions, error) {
			var complete PRSFrequencyHoppingConfigurationBandPositionsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero q5.PRSFrequencyHoppingConfigurationBandPositions
				return zero, err
			}
			return complete.Value, nil
		}
		*q21.BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldEncode(&sealed) = func(value q5.PRSFrequencyHoppingConfigurationBandPositions, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			complete := PRSFrequencyHoppingConfigurationBandPositionsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*q21.BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldCapture(&sealed) = func(v q5.PRSFrequencyHoppingConfigurationBandPositions, options q4.DecodeState) (q5.PRSFrequencyHoppingConfigurationBandPositions, q4.Snapshot,
		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q5.BridgeCaptureLPPaPRSFrequencyHoppingConfigurationBandPositions(&v, &s)
			var root q4.Snapshot
			s.
				OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q21.BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldCompare(&sealed) = func(v q5.PRSFrequencyHoppingConfigurationBandPositions, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f :=
				s.Begin()
			q11.BridgeCompareLPPaPRSFrequencyHoppingConfigurationBandPositions(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q21.BridgePRSFrequencyHoppingConfigurationBandPositionsValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:PRSFrequencyHoppingConfigurationBandPositions"
			return sealed
		}()
		return sealed
	}()

}

// PosSIBSegmentsCodec binds the complete source value type.
func PosSIBSegmentsCodec() q15.PosSIBSegmentsValueCodec {
	return func() q15.PosSIBSegmentsValueCodec {
		sealed := q15.PosSIBSegmentsValueCodec{}
		*q15.BridgePosSIBSegmentsValueCodecFieldPath(&sealed) = "PosSIBSegments"
		*q15.BridgePosSIBSegmentsValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q15.PosSIBSegments, error) {
			var complete PosSIBSegmentsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero q15.PosSIBSegments
				return zero, err
			}
			return complete.Value, nil
		}
		*q15.BridgePosSIBSegmentsValueCodecFieldEncode(&sealed) = func(value q15.PosSIBSegments, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			complete := PosSIBSegmentsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*q15.BridgePosSIBSegmentsValueCodecFieldCapture(&sealed) = func(v q15.PosSIBSegments, options q4.DecodeState) (q15.PosSIBSegments, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q16.BridgeCaptureLPPaPosSIBSegments(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q15.BridgePosSIBSegmentsValueCodecFieldCompare(&sealed) = func(v q15.PosSIBSegments, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q13.BridgeCompareLPPaPosSIBSegments(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q15.BridgePosSIBSegmentsValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:PosSIBSegments"
			return sealed
		}()
		return sealed
	}()

}

// PosSIBsCodec binds the complete source value type.
func PosSIBsCodec() q13.PosSIBsValueCodec {
	return func() q13.PosSIBsValueCodec {
		sealed := q13.PosSIBsValueCodec{}
		*q13.BridgePosSIBsValueCodecFieldPath(&sealed) = "PosSIBs"
		*q13.BridgePosSIBsValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q13.PosSIBs, error) {
			var complete PosSIBsComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero q13.PosSIBs
				return zero, err
			}
			return complete.Value, nil
		}
		*q13.BridgePosSIBsValueCodecFieldEncode(&sealed) = func(value q13.PosSIBs, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			complete := PosSIBsComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*q13.BridgePosSIBsValueCodecFieldCapture(&sealed) = func(v q13.PosSIBs, options q4.DecodeState) (q13.PosSIBs, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f :=
				s.Begin()
			q13.BridgeCaptureLPPaPosSIBs(&v, &s)
			var root q4.Snapshot
			s.
				OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q13.BridgePosSIBsValueCodecFieldCompare(&sealed) = func(v q13.PosSIBs, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(
				root, limits)
			f := s.Begin()
			q13.BridgeCompareLPPaPosSIBs(&v, &s)
			s.
				End(f, root, false)
			return s.Plan()
		}
		*q13.BridgePosSIBsValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:PosSIBs"
			return sealed
		}()
		return sealed
	}()

}

// ResultGERANCodec binds the complete source value type.
func ResultGERANCodec() q12.ResultGERANValueCodec {
	return func() q12.ResultGERANValueCodec {
		sealed := q12.ResultGERANValueCodec{}
		*q12.BridgeResultGERANValueCodecFieldPath(&sealed) = "ResultGERAN"
		*q12.BridgeResultGERANValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q12.ResultGERAN, error) {
			var complete ResultGERANComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero q12.ResultGERAN
				return zero, err
			}
			return complete.Value, nil
		}
		*q12.BridgeResultGERANValueCodecFieldEncode(&sealed) = func(value q12.ResultGERAN, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			complete := ResultGERANComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*q12.BridgeResultGERANValueCodecFieldCapture(&sealed) = func(v q12.ResultGERAN, options q4.DecodeState) (q12.ResultGERAN, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q12.BridgeCaptureLPPaResultGERAN(&v, &s)
			var root q4.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v,
				root
		}
		*q12.BridgeResultGERANValueCodecFieldCompare(&sealed) = func(v q12.ResultGERAN, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q12.BridgeCompareLPPaResultGERAN(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q12.BridgeResultGERANValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:ResultGERAN"
			return sealed
		}()
		return sealed
	}()

}

// ResultNRItemCodec binds the complete source value type.
func ResultNRItemCodec() ResultNRItemValueCodec {
	return ResultNRItemValueCodec{path: "ResultNRItem", decode: func(data []byte, options q4.DecodeState) (ResultNRItem, error) {
		var value ResultNRItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ResultNRItem{}, err
		}
		value.received = true
		value.receivedBytes = q4.OriginalWire(data)
		return value, nil
	}, encode: func(value ResultNRItem, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ResultNRItem, options q4.DecodeState) (ResultNRItem, q4.Snapshot) {
		s := q4.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaResultNRItem(&v, &s)
		var root q4.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResultNRItem, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
		s := q4.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaResultNRItem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q5.BridgeCodecContext {
		sealed := q5.BridgeCodecContext{}
		*q5.BridgecodecContextFieldSource(&sealed) = "source-value:ResultNRItem"
		return sealed
	}(),
	}
}

// ResultRSRPCodec binds the complete source value type.
func ResultRSRPCodec() q12.ResultRSRPValueCodec {
	return func() q12.ResultRSRPValueCodec {
		sealed := q12.ResultRSRPValueCodec{}
		*q12.BridgeResultRSRPValueCodecFieldPath(&sealed) = "ResultRSRP"
		*q12.BridgeResultRSRPValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q12.ResultRSRP, error) {
			var complete ResultRSRPComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero q12.ResultRSRP
				return zero, err
			}
			return complete.Value, nil
		}
		*q12.BridgeResultRSRPValueCodecFieldEncode(&sealed) = func(value q12.ResultRSRP, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			complete := ResultRSRPComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*q12.BridgeResultRSRPValueCodecFieldCapture(&sealed) = func(v q12.ResultRSRP, options q4.DecodeState) (q12.ResultRSRP, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f :=
				s.Begin()
			q12.BridgeCaptureLPPaResultRSRP(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root

		}
		*q12.BridgeResultRSRPValueCodecFieldCompare(&sealed) = func(v q12.ResultRSRP, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q12.BridgeCompareLPPaResultRSRP(&v,
				&s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q12.BridgeResultRSRPValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:ResultRSRP"
			return sealed
		}()
		return sealed
	}()

}

// ResultRSRQCodec binds the complete source value type.
func ResultRSRQCodec() q17.ResultRSRQValueCodec {
	return func() q17.ResultRSRQValueCodec {
		sealed := q17.ResultRSRQValueCodec{}
		*q17.BridgeResultRSRQValueCodecFieldPath(&sealed) = "ResultRSRQ"
		*q17.BridgeResultRSRQValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q17.ResultRSRQ, error) {
			var complete ResultRSRQComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero q17.ResultRSRQ
				return zero, err
			}
			return complete.Value, nil
		}
		*q17.BridgeResultRSRQValueCodecFieldEncode(&sealed) = func(value q17.ResultRSRQ, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			complete := ResultRSRQComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*q17.BridgeResultRSRQValueCodecFieldCapture(&sealed) = func(v q17.ResultRSRQ, options q4.DecodeState) (q17.ResultRSRQ, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f :=
				s.Begin()
			q17.BridgeCaptureLPPaResultRSRQ(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root

		}
		*q17.BridgeResultRSRQValueCodecFieldCompare(&sealed) = func(v q17.ResultRSRQ, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q17.BridgeCompareLPPaResultRSRQ(&v,
				&s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q17.BridgeResultRSRQValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:ResultRSRQ"
			return sealed
		}()
		return sealed
	}()

}

// ResultUTRANCodec binds the complete source value type.
func ResultUTRANCodec() q9.ResultUTRANValueCodec {
	return func() q9.ResultUTRANValueCodec {
		sealed := q9.ResultUTRANValueCodec{}
		*q9.BridgeResultUTRANValueCodecFieldPath(&sealed) = "ResultUTRAN"
		*q9.BridgeResultUTRANValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q9.ResultUTRAN, error) {
			var complete ResultUTRANComplete
			if err := complete.unmarshalAPERWithOptions(data, options); err != nil {
				var zero q9.ResultUTRAN
				return zero, err
			}
			return complete.Value, nil
		}
		*q9.BridgeResultUTRANValueCodecFieldEncode(&sealed) = func(value q9.ResultUTRAN, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			complete := ResultUTRANComplete{Value: value}
			return complete.marshalAPERBudget(budget, fresh)
		}
		*q9.BridgeResultUTRANValueCodecFieldCapture(&sealed) = func(v q9.ResultUTRAN, options q4.DecodeState) (q9.ResultUTRAN, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			q9.BridgeCaptureLPPaResultUTRAN(&v, &s)
			var root q4.Snapshot

			s.OperationCounts()
			s.End(f, &root, false)
			return v,
				root
		}
		*q9.BridgeResultUTRANValueCodecFieldCompare(&sealed) = func(v q9.ResultUTRAN, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q9.BridgeCompareLPPaResultUTRAN(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q9.BridgeResultUTRANValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:ResultUTRAN"
			return sealed
		}()
		return sealed
	}()

}

// ResultsPerSSBIndexListCodec binds the complete APER value type.
func ResultsPerSSBIndexListCodec() q9.ResultsPerSSBIndexListValueCodec {
	return ResultNRItemExtIEs().ResultsPerSSBIndexList().Codec()
}
func BridgeInterRATMeasuredResultsValueFieldKnownOpenBytes(v *InterRATMeasuredResultsValue) *uint64 {
	return &v.knownOpenBytes
}
func BridgeInterRATMeasuredResultsValueFieldPerOpenTypePadding(v *InterRATMeasuredResultsValue) *q4.CompletePadding {
	return &v.perOpenTypePadding
}
func BridgeInterRATMeasuredResultsValueFieldPerPadding(v *InterRATMeasuredResultsValue) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeInterRATMeasuredResultsValueFieldReceived(v *InterRATMeasuredResultsValue) *bool {
	return &v.received
}
func BridgeInterRATMeasuredResultsValueFieldReceivedBytes(v *InterRATMeasuredResultsValue) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeInterRATMeasuredResultsValueFieldReplay(v *InterRATMeasuredResultsValue) *q4.Snapshot {
	return &v.replay
}
func BridgeInterRATMeasuredResultsValueFieldStream(v *InterRATMeasuredResultsValue) *q4.WireSpan {
	return &v.stream
}
func BridgeInterRATMeasuredResultsValueFieldWithoutReplay(v *InterRATMeasuredResultsValue) *bool {
	return &v.withoutReplay
}
func BridgeInterRATMeasuredResultsValueMethodMarshalAPERBudget(v *InterRATMeasuredResultsValue, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInterRATMeasuredResultsValueMethodMarshalAPERChanged(v *InterRATMeasuredResultsValue, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeInterRATMeasuredResultsValueMethodMarshalAPERChangedValue(v *InterRATMeasuredResultsValue, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeInterRATMeasuredResultsValueMethodMarshalAPERFreshValue(v *InterRATMeasuredResultsValue, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeInterRATMeasuredResultsValueMethodMarshalAPERLegacy(v *InterRATMeasuredResultsValue) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeInterRATMeasuredResultsValueMethodMarshalAPERPlanned(v *InterRATMeasuredResultsValue, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeInterRATMeasuredResultsValueMethodMarshalAPERTo(v *InterRATMeasuredResultsValue, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInterRATMeasuredResultsValueMethodUnmarshalAPERFrom(v *InterRATMeasuredResultsValue, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInterRATMeasuredResultsValueMethodUnmarshalAPERLegacy(v *InterRATMeasuredResultsValue, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeInterRATMeasuredResultsValueMethodUnmarshalAPERWithOptions(v *InterRATMeasuredResultsValue, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteFieldPerPadding(v *PRSFrequencyHoppingConfigurationBandPositionsComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteFieldReceived(v *PRSFrequencyHoppingConfigurationBandPositionsComplete) *bool {
	return &v.received
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteFieldReceivedBytes(v *PRSFrequencyHoppingConfigurationBandPositionsComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteFieldReplay(v *PRSFrequencyHoppingConfigurationBandPositionsComplete) *q4.Snapshot {
	return &v.replay
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteFieldStream(v *PRSFrequencyHoppingConfigurationBandPositionsComplete) *q4.WireSpan {
	return &v.stream
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteFieldWithoutReplay(v *PRSFrequencyHoppingConfigurationBandPositionsComplete) *bool {
	return &v.withoutReplay
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteMethodMarshalAPERBudget(v *PRSFrequencyHoppingConfigurationBandPositionsComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteMethodMarshalAPERChanged(v *PRSFrequencyHoppingConfigurationBandPositionsComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteMethodMarshalAPERChangedValue(v *PRSFrequencyHoppingConfigurationBandPositionsComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteMethodMarshalAPERFreshValue(v *PRSFrequencyHoppingConfigurationBandPositionsComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteMethodMarshalAPERLegacy(v *PRSFrequencyHoppingConfigurationBandPositionsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteMethodMarshalAPERPlanned(v *PRSFrequencyHoppingConfigurationBandPositionsComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteMethodUnmarshalAPERLegacy(v *PRSFrequencyHoppingConfigurationBandPositionsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePRSFrequencyHoppingConfigurationBandPositionsCompleteMethodUnmarshalAPERWithOptions(v *PRSFrequencyHoppingConfigurationBandPositionsComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePosSIBSegmentsCompleteFieldPerPadding(v *PosSIBSegmentsComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgePosSIBSegmentsCompleteFieldReceived(v *PosSIBSegmentsComplete) *bool { return &v.received }
func BridgePosSIBSegmentsCompleteFieldReceivedBytes(v *PosSIBSegmentsComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgePosSIBSegmentsCompleteFieldReplay(v *PosSIBSegmentsComplete) *q4.Snapshot {
	return &v.replay
}
func BridgePosSIBSegmentsCompleteFieldStream(v *PosSIBSegmentsComplete) *q4.WireSpan {
	return &v.stream
}
func BridgePosSIBSegmentsCompleteFieldWithoutReplay(v *PosSIBSegmentsComplete) *bool {
	return &v.withoutReplay
}
func BridgePosSIBSegmentsCompleteMethodMarshalAPERBudget(v *PosSIBSegmentsComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePosSIBSegmentsCompleteMethodMarshalAPERChanged(v *PosSIBSegmentsComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePosSIBSegmentsCompleteMethodMarshalAPERChangedValue(v *PosSIBSegmentsComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePosSIBSegmentsCompleteMethodMarshalAPERFreshValue(v *PosSIBSegmentsComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgePosSIBSegmentsCompleteMethodMarshalAPERLegacy(v *PosSIBSegmentsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePosSIBSegmentsCompleteMethodMarshalAPERPlanned(v *PosSIBSegmentsComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgePosSIBSegmentsCompleteMethodUnmarshalAPERLegacy(v *PosSIBSegmentsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePosSIBSegmentsCompleteMethodUnmarshalAPERWithOptions(v *PosSIBSegmentsComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgePosSIBsCompleteFieldPerPadding(v *PosSIBsComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgePosSIBsCompleteFieldReceived(v *PosSIBsComplete) *bool { return &v.received }
func BridgePosSIBsCompleteFieldReceivedBytes(v *PosSIBsComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgePosSIBsCompleteFieldReplay(v *PosSIBsComplete) *q4.Snapshot { return &v.replay }
func BridgePosSIBsCompleteFieldStream(v *PosSIBsComplete) *q4.WireSpan { return &v.stream }
func BridgePosSIBsCompleteFieldWithoutReplay(v *PosSIBsComplete) *bool { return &v.withoutReplay }
func BridgePosSIBsCompleteMethodMarshalAPERBudget(v *PosSIBsComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgePosSIBsCompleteMethodMarshalAPERChanged(v *PosSIBsComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgePosSIBsCompleteMethodMarshalAPERChangedValue(v *PosSIBsComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgePosSIBsCompleteMethodMarshalAPERFreshValue(v *PosSIBsComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgePosSIBsCompleteMethodMarshalAPERLegacy(v *PosSIBsComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgePosSIBsCompleteMethodMarshalAPERPlanned(v *PosSIBsComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgePosSIBsCompleteMethodUnmarshalAPERLegacy(v *PosSIBsComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgePosSIBsCompleteMethodUnmarshalAPERWithOptions(v *PosSIBsComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultGERANCompleteFieldPerPadding(v *ResultGERANComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeResultGERANCompleteFieldReceived(v *ResultGERANComplete) *bool { return &v.received }
func BridgeResultGERANCompleteFieldReceivedBytes(v *ResultGERANComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeResultGERANCompleteFieldReplay(v *ResultGERANComplete) *q4.Snapshot { return &v.replay }
func BridgeResultGERANCompleteFieldStream(v *ResultGERANComplete) *q4.WireSpan { return &v.stream }
func BridgeResultGERANCompleteFieldWithoutReplay(v *ResultGERANComplete) *bool {
	return &v.withoutReplay
}
func BridgeResultGERANCompleteMethodMarshalAPERBudget(v *ResultGERANComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultGERANCompleteMethodMarshalAPERChanged(v *ResultGERANComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultGERANCompleteMethodMarshalAPERChangedValue(v *ResultGERANComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultGERANCompleteMethodMarshalAPERFreshValue(v *ResultGERANComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultGERANCompleteMethodMarshalAPERLegacy(v *ResultGERANComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultGERANCompleteMethodMarshalAPERPlanned(v *ResultGERANComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultGERANCompleteMethodUnmarshalAPERLegacy(v *ResultGERANComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultGERANCompleteMethodUnmarshalAPERWithOptions(v *ResultGERANComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultNRAPERValueFieldContext(v *ResultNRAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeResultNRAPERValueFieldReceived(v *ResultNRAPERValue) *q4.WireSpan { return &v.received }
func BridgeResultNRAPERValueFieldReplay(v *ResultNRAPERValue) *q4.Snapshot   { return &v.replay }
func BridgeResultNRAPERValueFieldWithoutReplay(v *ResultNRAPERValue) *bool   { return &v.withoutReplay }
func BridgeResultNRItemAPERValueFieldContext(v *ResultNRItemAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeResultNRItemAPERValueFieldReceived(v *ResultNRItemAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeResultNRItemAPERValueFieldReplay(v *ResultNRItemAPERValue) *q4.Snapshot { return &v.replay }
func BridgeResultNRItemAPERValueFieldWithoutReplay(v *ResultNRItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultNRItemExtIETableMethodInfoNRCGI(v ResultNRItemExtIETable) q5.FieldInfo {
	return v.infoNRCGI()
}
func BridgeResultNRItemExtIETableMethodInfoResultsPerSSBIndexList(v ResultNRItemExtIETable) q5.FieldInfo {
	return v.infoResultsPerSSBIndexList()
}
func BridgeResultNRItemExtIEsExtFieldFieldReceived(v *ResultNRItemExtIEsExtField) *q4.CompletePadding {
	return &v.received
}
func BridgeResultNRItemExtIEsExtFieldFieldReplay(v *ResultNRItemExtIEsExtField) *q4.Snapshot {
	return &v.replay
}
func BridgeResultNRItemExtIEsExtFieldFieldStream(v *ResultNRItemExtIEsExtField) *q4.WireSpan {
	return &v.stream
}
func BridgeResultNRItemExtIEsExtFieldFieldWithoutReplay(v *ResultNRItemExtIEsExtField) *bool {
	return &v.withoutReplay
}
func BridgeResultNRItemExtIEsExtFieldMethodMarshalAPERTo(v *ResultNRItemExtIEsExtField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultNRItemExtIEsExtFieldMethodUnmarshalAPERFrom(v *ResultNRItemExtIEsExtField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultNRItemExtIEsIEFieldFieldReceived(v *ResultNRItemExtIEsIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeResultNRItemExtIEsIEFieldFieldReplay(v *ResultNRItemExtIEsIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeResultNRItemExtIEsIEFieldFieldStream(v *ResultNRItemExtIEsIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeResultNRItemExtIEsIEFieldFieldWithoutReplay(v *ResultNRItemExtIEsIEField) *bool {
	return &v.withoutReplay
}
func BridgeResultNRItemExtIEsIEFieldMethodMarshalAPERTo(v *ResultNRItemExtIEsIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultNRItemExtIEsIEFieldMethodUnmarshalAPERFrom(v *ResultNRItemExtIEsIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultNRItemExtIEsNRCGIExtBindingFieldCodec(v *ResultNRItemExtIEsNRCGIExtBinding) *q10.NRCGIValueCodec {
	return &v.codec
}
func BridgeResultNRItemExtIEsNRCGIExtBindingFieldGet(v *ResultNRItemExtIEsNRCGIExtBinding) *func(*ResultNRItemExtIEsValue) (*q10.NRCGI, bool) {
	return &v.get
}
func BridgeResultNRItemExtIEsNRCGIExtBindingFieldInfo(v *ResultNRItemExtIEsNRCGIExtBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeResultNRItemExtIEsNRCGIExtBindingFieldInject(v *ResultNRItemExtIEsNRCGIExtBinding) *func(q10.NRCGI) ResultNRItemExtIEsValue {
	return &v.inject
}
func BridgeResultNRItemExtIEsResultsPerSSBIndexListExtBindingFieldCodec(v *ResultNRItemExtIEsResultsPerSSBIndexListExtBinding) *q9.ResultsPerSSBIndexListValueCodec {
	return &v.codec
}
func BridgeResultNRItemExtIEsResultsPerSSBIndexListExtBindingFieldGet(v *ResultNRItemExtIEsResultsPerSSBIndexListExtBinding) *func(*ResultNRItemExtIEsValue) (*q9.ResultsPerSSBIndexList, bool) {
	return &v.get
}
func BridgeResultNRItemExtIEsResultsPerSSBIndexListExtBindingFieldInfo(v *ResultNRItemExtIEsResultsPerSSBIndexListExtBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeResultNRItemExtIEsResultsPerSSBIndexListExtBindingFieldInject(v *ResultNRItemExtIEsResultsPerSSBIndexListExtBinding) *func(q9.ResultsPerSSBIndexList) ResultNRItemExtIEsValue {
	return &v.inject
}
func BridgeResultNRItemExtIEsValueFieldId(v *ResultNRItemExtIEsValue) *q5.ProtocolIEID { return &v.id }
func BridgeResultNRItemExtIEsValueFieldIsOpaque(v *ResultNRItemExtIEsValue) *bool      { return &v.isOpaque }
func BridgeResultNRItemExtIEsValueFieldOpaque(v *ResultNRItemExtIEsValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeResultNRItemExtIEsValueFieldReceived(v *ResultNRItemExtIEsValue) *q4.WireSpan {
	return &v.received
}
func BridgeResultNRItemExtIEsValueFieldReplay(v *ResultNRItemExtIEsValue) *q4.Snapshot {
	return &v.replay
}
func BridgeResultNRItemExtIEsValueFieldRowNRCGI(v *ResultNRItemExtIEsValue) **q10.NRCGI {
	return &v.rowNRCGI
}
func BridgeResultNRItemExtIEsValueFieldRowResultsPerSSBIndexList(v *ResultNRItemExtIEsValue) **q9.ResultsPerSSBIndexList {
	return &v.rowResultsPerSSBIndexList
}
func BridgeResultNRItemExtIEsValueFieldWithoutReplay(v *ResultNRItemExtIEsValue) *bool {
	return &v.withoutReplay
}
func BridgeResultNRItemExtIEsValueMethodCaptureFraming(v ResultNRItemExtIEsValue) uint64 {
	return v.captureFraming()
}
func BridgeResultNRItemExtIEsValueMethodCaptureSemantics(v ResultNRItemExtIEsValue, a0 q4.SemanticCapture) ResultNRItemExtIEsValue {
	return v.captureSemantics(a0)
}
func BridgeResultNRItemExtIEsValueMethodCaptureSnapshot(v ResultNRItemExtIEsValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeResultNRItemExtIEsValueMethodCompareSemantics(v ResultNRItemExtIEsValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeResultNRItemExtIEsValueMethodDecode(v ResultNRItemExtIEsValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (ResultNRItemExtIEsValue, error) {
	return v.decode(a0, a1)
}
func BridgeResultNRItemExtIEsValueMethodEncode(v ResultNRItemExtIEsValue) ([]byte, error) {
	return v.encode()
}
func BridgeResultNRItemExtIEsValueMethodEncodeFresh(v ResultNRItemExtIEsValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeResultNRItemExtIEsValueMethodMatchesID(v ResultNRItemExtIEsValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeResultNRItemExtIEsValueMethodReason(v ResultNRItemExtIEsValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeResultNRItemExtIEsValueMethodRule(v ResultNRItemExtIEsValue) q4.SourceRule {
	return v.rule()
}
func BridgeResultNRItemFieldExtCount(v *ResultNRItem) *int64              { return &v.extCount }
func BridgeResultNRItemFieldExtData(v *ResultNRItem) *[][]byte            { return &v.extData }
func BridgeResultNRItemFieldExtOrigin(v *ResultNRItem) *[]q4.OpaqueOrigin { return &v.extOrigin }
func BridgeResultNRItemFieldExtPresent(v *ResultNRItem) *[]bool           { return &v.extPresent }
func BridgeResultNRItemFieldExtWire(v *ResultNRItem) *[]q4.WireSpan       { return &v.extWire }
func BridgeResultNRItemFieldIEExtensionsIndef(v *ResultNRItem) *bool      { return &v.iEExtensionsIndef }
func BridgeResultNRItemFieldPerExtPadding(v *ResultNRItem) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeResultNRItemFieldPerPadding(v *ResultNRItem) *q4.FinalPadding { return &v.perPadding }
func BridgeResultNRItemFieldReceived(v *ResultNRItem) *bool              { return &v.received }
func BridgeResultNRItemFieldReceivedBytes(v *ResultNRItem) *q4.WireSpan  { return &v.receivedBytes }
func BridgeResultNRItemFieldReplay(v *ResultNRItem) *q4.Snapshot         { return &v.replay }
func BridgeResultNRItemFieldStream(v *ResultNRItem) *q4.WireSpan         { return &v.stream }
func BridgeResultNRItemFieldWithoutReplay(v *ResultNRItem) *bool         { return &v.withoutReplay }
func BridgeResultNRItemMethodMarshalAPERBudget(v *ResultNRItem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultNRItemMethodMarshalAPERChanged(v *ResultNRItem, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultNRItemMethodMarshalAPERChangedValue(v *ResultNRItem, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultNRItemMethodMarshalAPERFreshValue(v *ResultNRItem, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultNRItemMethodMarshalAPERLegacy(v *ResultNRItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultNRItemMethodMarshalAPERPlanned(v *ResultNRItem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultNRItemMethodMarshalAPERTo(v *ResultNRItem, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultNRItemMethodUnmarshalAPERFrom(v *ResultNRItem, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultNRItemMethodUnmarshalAPERLegacy(v *ResultNRItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultNRItemMethodUnmarshalAPERWithOptions(v *ResultNRItem, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultNRItemValueCodecFieldCapture(v *ResultNRItemValueCodec) *func(ResultNRItem, q4.DecodeState) (ResultNRItem, q4.Snapshot) {
	return &v.capture
}
func BridgeResultNRItemValueCodecFieldCompare(v *ResultNRItemValueCodec) *func(ResultNRItem, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeResultNRItemValueCodecFieldContext(v *ResultNRItemValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeResultNRItemValueCodecFieldDecode(v *ResultNRItemValueCodec) *func([]byte, q4.DecodeState) (ResultNRItem, error) {
	return &v.decode
}
func BridgeResultNRItemValueCodecFieldEncode(v *ResultNRItemValueCodec) *func(ResultNRItem, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultNRItemValueCodecFieldPath(v *ResultNRItemValueCodec) *q4.Path { return &v.path }
func BridgeResultNRItemValueCodecMethodEncodeBudget(v ResultNRItemValueCodec, a0 ResultNRItem, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultNRItemValueCodecMethodEncodeChanged(v ResultNRItemValueCodec, a0 ResultNRItem, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultNRValueCodecFieldCapture(v *ResultNRValueCodec) *func(ResultNR, q4.DecodeState) (ResultNR, q4.Snapshot) {
	return &v.capture
}
func BridgeResultNRValueCodecFieldCompare(v *ResultNRValueCodec) *func(ResultNR, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeResultNRValueCodecFieldContext(v *ResultNRValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeResultNRValueCodecFieldDecode(v *ResultNRValueCodec) *func([]byte, q4.DecodeState) (ResultNR, error) {
	return &v.decode
}
func BridgeResultNRValueCodecFieldEncode(v *ResultNRValueCodec) *func(ResultNR, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultNRValueCodecFieldPath(v *ResultNRValueCodec) *q4.Path { return &v.path }
func BridgeResultNRValueCodecMethodEncodeBudget(v ResultNRValueCodec, a0 ResultNR, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultNRValueCodecMethodEncodeChanged(v ResultNRValueCodec, a0 ResultNR, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultRSRPCompleteFieldPerPadding(v *ResultRSRPComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeResultRSRPCompleteFieldReceived(v *ResultRSRPComplete) *bool { return &v.received }
func BridgeResultRSRPCompleteFieldReceivedBytes(v *ResultRSRPComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeResultRSRPCompleteFieldReplay(v *ResultRSRPComplete) *q4.Snapshot { return &v.replay }
func BridgeResultRSRPCompleteFieldStream(v *ResultRSRPComplete) *q4.WireSpan { return &v.stream }
func BridgeResultRSRPCompleteFieldWithoutReplay(v *ResultRSRPComplete) *bool { return &v.withoutReplay }
func BridgeResultRSRPCompleteMethodMarshalAPERBudget(v *ResultRSRPComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultRSRPCompleteMethodMarshalAPERChanged(v *ResultRSRPComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultRSRPCompleteMethodMarshalAPERChangedValue(v *ResultRSRPComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultRSRPCompleteMethodMarshalAPERFreshValue(v *ResultRSRPComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultRSRPCompleteMethodMarshalAPERLegacy(v *ResultRSRPComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultRSRPCompleteMethodMarshalAPERPlanned(v *ResultRSRPComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultRSRPCompleteMethodUnmarshalAPERLegacy(v *ResultRSRPComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultRSRPCompleteMethodUnmarshalAPERWithOptions(v *ResultRSRPComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultRSRQCompleteFieldPerPadding(v *ResultRSRQComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeResultRSRQCompleteFieldReceived(v *ResultRSRQComplete) *bool { return &v.received }
func BridgeResultRSRQCompleteFieldReceivedBytes(v *ResultRSRQComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeResultRSRQCompleteFieldReplay(v *ResultRSRQComplete) *q4.Snapshot { return &v.replay }
func BridgeResultRSRQCompleteFieldStream(v *ResultRSRQComplete) *q4.WireSpan { return &v.stream }
func BridgeResultRSRQCompleteFieldWithoutReplay(v *ResultRSRQComplete) *bool { return &v.withoutReplay }
func BridgeResultRSRQCompleteMethodMarshalAPERBudget(v *ResultRSRQComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultRSRQCompleteMethodMarshalAPERChanged(v *ResultRSRQComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultRSRQCompleteMethodMarshalAPERChangedValue(v *ResultRSRQComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultRSRQCompleteMethodMarshalAPERFreshValue(v *ResultRSRQComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultRSRQCompleteMethodMarshalAPERLegacy(v *ResultRSRQComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultRSRQCompleteMethodMarshalAPERPlanned(v *ResultRSRQComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultRSRQCompleteMethodUnmarshalAPERLegacy(v *ResultRSRQComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultRSRQCompleteMethodUnmarshalAPERWithOptions(v *ResultRSRQComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultUTRANCompleteFieldPerPadding(v *ResultUTRANComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeResultUTRANCompleteFieldReceived(v *ResultUTRANComplete) *bool { return &v.received }
func BridgeResultUTRANCompleteFieldReceivedBytes(v *ResultUTRANComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeResultUTRANCompleteFieldReplay(v *ResultUTRANComplete) *q4.Snapshot { return &v.replay }
func BridgeResultUTRANCompleteFieldStream(v *ResultUTRANComplete) *q4.WireSpan { return &v.stream }
func BridgeResultUTRANCompleteFieldWithoutReplay(v *ResultUTRANComplete) *bool {
	return &v.withoutReplay
}
func BridgeResultUTRANCompleteMethodMarshalAPERBudget(v *ResultUTRANComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultUTRANCompleteMethodMarshalAPERChanged(v *ResultUTRANComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultUTRANCompleteMethodMarshalAPERChangedValue(v *ResultUTRANComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultUTRANCompleteMethodMarshalAPERFreshValue(v *ResultUTRANComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultUTRANCompleteMethodMarshalAPERLegacy(v *ResultUTRANComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultUTRANCompleteMethodMarshalAPERPlanned(v *ResultUTRANComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultUTRANCompleteMethodUnmarshalAPERLegacy(v *ResultUTRANComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultUTRANCompleteMethodUnmarshalAPERWithOptions(v *ResultUTRANComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultsPerSSBIndexListCompleteFieldPerPadding(v *ResultsPerSSBIndexListComplete) *q4.CompletePadding {
	return &v.perPadding
}
func BridgeResultsPerSSBIndexListCompleteFieldReceived(v *ResultsPerSSBIndexListComplete) *bool {
	return &v.received
}
func BridgeResultsPerSSBIndexListCompleteFieldReceivedBytes(v *ResultsPerSSBIndexListComplete) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeResultsPerSSBIndexListCompleteFieldReplay(v *ResultsPerSSBIndexListComplete) *q4.Snapshot {
	return &v.replay
}
func BridgeResultsPerSSBIndexListCompleteFieldStream(v *ResultsPerSSBIndexListComplete) *q4.WireSpan {
	return &v.stream
}
func BridgeResultsPerSSBIndexListCompleteFieldWithoutReplay(v *ResultsPerSSBIndexListComplete) *bool {
	return &v.withoutReplay
}
func BridgeResultsPerSSBIndexListCompleteMethodMarshalAPERBudget(v *ResultsPerSSBIndexListComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultsPerSSBIndexListCompleteMethodMarshalAPERChanged(v *ResultsPerSSBIndexListComplete, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultsPerSSBIndexListCompleteMethodMarshalAPERChangedValue(v *ResultsPerSSBIndexListComplete, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultsPerSSBIndexListCompleteMethodMarshalAPERFreshValue(v *ResultsPerSSBIndexListComplete, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultsPerSSBIndexListCompleteMethodMarshalAPERLegacy(v *ResultsPerSSBIndexListComplete) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultsPerSSBIndexListCompleteMethodMarshalAPERPlanned(v *ResultsPerSSBIndexListComplete, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultsPerSSBIndexListCompleteMethodUnmarshalAPERLegacy(v *ResultsPerSSBIndexListComplete, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultsPerSSBIndexListCompleteMethodUnmarshalAPERWithOptions(v *ResultsPerSSBIndexListComplete, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
