// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s14 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s14

import (
	q6 "fmt"
	q5 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	q11 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	q8 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	q9 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	q14 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	q12 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	q10 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	q13 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	q15 "github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s13"
	q7 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	q4 "github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// AssistanceInformationControlIEContainer is the concrete ProtocolIEContainer[AssistanceInformationControlIEValue].
type AssistanceInformationControlIEContainer []AssistanceInformationControlIEField

// AssistanceInformationControlIEField is the concrete ProtocolIEField[AssistanceInformationControlIEValue].
type AssistanceInformationControlIEField struct {
	withoutReplay bool
	replay        q4.Snapshot
	stream        q4.WireSpan
	Id            q5.ProtocolIEID
	Criticality   q5.Criticality
	Value         AssistanceInformationControlIEValue

	received q4.CompletePadding
}

func (v AssistanceInformationControlIEField) WithoutReplay() AssistanceInformationControlIEField {
	v.withoutReplay = true
	v.stream = q4.WireSpan{}
	return v
}
func (v *AssistanceInformationControlIEField) ReceivedForm() q4.ReceivedForm {
	if v == nil || v.withoutReplay {
		return q4.ReceivedForm{}
	}
	return q4.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AssistanceInformationControlIEField) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
func (v *AssistanceInformationControlIEField) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return q6.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationControlIEField{}
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
	var zero AssistanceInformationControlIEValue

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
func BridgeAssistanceInformationControlIEValueCaptureLPPaProtocolIEContainer(v *AssistanceInformationControlIEContainer, s *q4.SemanticCapture) {
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
			BridgeAssistanceInformationControlIEValueCaptureLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeAssistanceInformationControlIEValueCompareLPPaProtocolIEContainer(v *AssistanceInformationControlIEContainer, s *q4.SemanticComparison) {
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
			BridgeAssistanceInformationControlIEValueCompareLPPaProtocolIEField(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeResultsPerSSBIndexItemExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q9.ResultsPerSSBIndexItemExtIEsExtContainer, s *q4.SemanticCapture) {
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
			BridgeResultsPerSSBIndexItemExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeResultsPerSSBIndexItemExtIEsValueCompareLPPaProtocolExtensionContainer(v *q9.ResultsPerSSBIndexItemExtIEsExtContainer, s *q4.SemanticComparison) {
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
			BridgeResultsPerSSBIndexItemExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
}
func BridgeSystemInformationExtIEsValueCaptureLPPaProtocolExtensionContainer(v *q9.SystemInformationExtIEsExtContainer, s *q4.SemanticCapture) {
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
			BridgeSystemInformationExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
}
func BridgeSystemInformationExtIEsValueCompareLPPaProtocolExtensionContainer(v *q9.SystemInformationExtIEsExtContainer, s *q4.SemanticComparison) {
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
			BridgeSystemInformationExtIEsValueCompareLPPaProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
}

// ResultsPerSSBIndexListValueCodec is the concrete ValueCodec[ResultsPerSSBIndexList].
type ResultsPerSSBIndexListValueCodec struct {
	context q5.BridgeCodecContext
	capture func(ResultsPerSSBIndexList, q4.DecodeState,

	) (ResultsPerSSBIndexList, q4.Snapshot,

	)
	compare func(ResultsPerSSBIndexList, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (ResultsPerSSBIndexList,

		error)
	encode func(ResultsPerSSBIndexList,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c ResultsPerSSBIndexListValueCodec) New(value ResultsPerSSBIndexList,

) (ResultsPerSSBIndexListAPERValue, error) {
	if c.encode == nil {
		return ResultsPerSSBIndexListAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ResultsPerSSBIndexListAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultsPerSSBIndexListAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return ResultsPerSSBIndexListAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c ResultsPerSSBIndexListValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (ResultsPerSSBIndexListAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultsPerSSBIndexListAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return ResultsPerSSBIndexListAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultsPerSSBIndexListAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return ResultsPerSSBIndexListAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return ResultsPerSSBIndexListAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ResultsPerSSBIndexListValueCodec) EncodeAPER(value ResultsPerSSBIndexListAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c ResultsPerSSBIndexListValueCodec) encodeBudget(value ResultsPerSSBIndexList,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultsPerSSBIndexListValueCodec) encodeChanged(value ResultsPerSSBIndexList,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// AssistanceInformationControlAssistanceInformationIEBinding is the concrete IEBinding[AssistanceInformation, AssistanceInformationControlIEValue].
type AssistanceInformationControlAssistanceInformationIEBinding struct {
	info   q5.FieldInfo
	codec  AssistanceInformationValueCodec
	inject func(AssistanceInformation,

	) AssistanceInformationControlIEValue

	get func(*AssistanceInformationControlIEValue,

	) (*AssistanceInformation,

		bool)
}

func (b AssistanceInformationControlAssistanceInformationIEBinding) Info() q5.FieldInfo {
	return b.info
}
func (b AssistanceInformationControlAssistanceInformationIEBinding) Codec() AssistanceInformationValueCodec {
	return b.codec
}
func (b AssistanceInformationControlAssistanceInformationIEBinding) New(value AssistanceInformation,

) (AssistanceInformationControlIEField, error) {
	if b.inject == nil {
		return AssistanceInformationControlIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return AssistanceInformationControlIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return AssistanceInformationControlIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return AssistanceInformationControlIEField{}, q4.OperationError(err, "Value.New")
	}
	return AssistanceInformationControlIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b AssistanceInformationControlAssistanceInformationIEBinding) Get(field *AssistanceInformationControlIEField) (*AssistanceInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// AssistanceInformationValueCodec is the concrete ValueCodec[AssistanceInformation].
type AssistanceInformationValueCodec struct {
	context q5.BridgeCodecContext
	capture func(AssistanceInformation, q4.DecodeState,

	) (AssistanceInformation, q4.Snapshot,

	)
	compare func(AssistanceInformation, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (AssistanceInformation,

		error)
	encode func(AssistanceInformation,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c AssistanceInformationValueCodec) New(value AssistanceInformation,

) (AssistanceInformationAPERValue, error) {
	if c.encode == nil {
		return AssistanceInformationAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return AssistanceInformationAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AssistanceInformationAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return AssistanceInformationAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c AssistanceInformationValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (AssistanceInformationAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return AssistanceInformationAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return AssistanceInformationAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return AssistanceInformationAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return AssistanceInformationAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return AssistanceInformationAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c AssistanceInformationValueCodec) EncodeAPER(value AssistanceInformationAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c AssistanceInformationValueCodec) encodeBudget(value AssistanceInformation,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c AssistanceInformationValueCodec) encodeChanged(value AssistanceInformation,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// AssistanceInformationControlBroadcastIEBinding is the concrete IEBinding[Broadcast, AssistanceInformationControlIEValue].
type AssistanceInformationControlBroadcastIEBinding struct {
	info   q5.FieldInfo
	codec  q5.BroadcastValueCodec
	inject func(q5.Broadcast,

	) AssistanceInformationControlIEValue

	get func(*AssistanceInformationControlIEValue,

	) (*q5.Broadcast,

		bool)
}

func (b AssistanceInformationControlBroadcastIEBinding) Info() q5.FieldInfo { return b.info }
func (b AssistanceInformationControlBroadcastIEBinding) Codec() q5.BroadcastValueCodec {
	return b.codec
}
func (b AssistanceInformationControlBroadcastIEBinding) New(value q5.Broadcast,

) (AssistanceInformationControlIEField, error) {
	if b.inject == nil {
		return AssistanceInformationControlIEField{}, q4.OperationError(q6.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return AssistanceInformationControlIEField{}, q4.OperationError(err, "Value.New")
	}
	if _, err := (*q5.BridgeBroadcastValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return AssistanceInformationControlIEField{}, q4.OperationError(q6.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := q4.ChargeValue(q4.NewBudgetBuffer(budget), value); err != nil {
		return AssistanceInformationControlIEField{}, q4.OperationError(err, "Value.New")
	}
	return AssistanceInformationControlIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, q4.OperationError(nil, "Value.New")
}
func (b AssistanceInformationControlBroadcastIEBinding) Get(field *AssistanceInformationControlIEField) (*q5.Broadcast,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ResultUTRANValueCodec is the concrete ValueCodec[ResultUTRAN].
type ResultUTRANValueCodec struct {
	context q5.BridgeCodecContext
	capture func(ResultUTRAN, q4.DecodeState,

	) (ResultUTRAN, q4.Snapshot,

	)
	compare func(ResultUTRAN, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (ResultUTRAN,

		error)
	encode func(ResultUTRAN,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c ResultUTRANValueCodec) New(value ResultUTRAN,

) (ResultUTRANAPERValue, error) {
	if c.encode == nil {
		return ResultUTRANAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ResultUTRANAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultUTRANAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return ResultUTRANAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c ResultUTRANValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (ResultUTRANAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultUTRANAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return ResultUTRANAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultUTRANAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return ResultUTRANAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return ResultUTRANAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ResultUTRANValueCodec) EncodeAPER(value ResultUTRANAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c ResultUTRANValueCodec) encodeBudget(value ResultUTRAN,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultUTRANValueCodec) encodeChanged(value ResultUTRAN,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// ResultUTRANItemValueCodec is the concrete ValueCodec[ResultUTRANItem].
type ResultUTRANItemValueCodec struct {
	context q5.BridgeCodecContext
	capture func(ResultUTRANItem, q4.DecodeState,

	) (ResultUTRANItem, q4.Snapshot,

	)
	compare func(ResultUTRANItem, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (ResultUTRANItem,

		error)
	encode func(ResultUTRANItem,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c ResultUTRANItemValueCodec) New(value ResultUTRANItem,

) (ResultUTRANItemAPERValue, error) {
	if c.encode == nil {
		return ResultUTRANItemAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ResultUTRANItemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultUTRANItemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return ResultUTRANItemAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c ResultUTRANItemValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (ResultUTRANItemAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultUTRANItemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return ResultUTRANItemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultUTRANItemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return ResultUTRANItemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return ResultUTRANItemAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ResultUTRANItemValueCodec) EncodeAPER(value ResultUTRANItemAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c ResultUTRANItemValueCodec) encodeBudget(value ResultUTRANItem,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultUTRANItemValueCodec) encodeChanged(value ResultUTRANItem,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// ResultsPerSSBIndexItemValueCodec is the concrete ValueCodec[ResultsPerSSBIndexItem].
type ResultsPerSSBIndexItemValueCodec struct {
	context q5.BridgeCodecContext
	capture func(ResultsPerSSBIndexItem, q4.DecodeState,

	) (ResultsPerSSBIndexItem, q4.Snapshot,

	)
	compare func(ResultsPerSSBIndexItem, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (ResultsPerSSBIndexItem,

		error)
	encode func(ResultsPerSSBIndexItem,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c ResultsPerSSBIndexItemValueCodec) New(value ResultsPerSSBIndexItem,

) (ResultsPerSSBIndexItemAPERValue, error) {
	if c.encode == nil {
		return ResultsPerSSBIndexItemAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return ResultsPerSSBIndexItemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultsPerSSBIndexItemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return ResultsPerSSBIndexItemAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c ResultsPerSSBIndexItemValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (ResultsPerSSBIndexItemAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultsPerSSBIndexItemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return ResultsPerSSBIndexItemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultsPerSSBIndexItemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return ResultsPerSSBIndexItemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return ResultsPerSSBIndexItemAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c ResultsPerSSBIndexItemValueCodec) EncodeAPER(value ResultsPerSSBIndexItemAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c ResultsPerSSBIndexItemValueCodec) encodeBudget(value ResultsPerSSBIndexItem,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultsPerSSBIndexItemValueCodec) encodeChanged(value ResultsPerSSBIndexItem,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// SystemInformationValueCodec is the concrete ValueCodec[SystemInformation].
type SystemInformationValueCodec struct {
	context q5.BridgeCodecContext
	capture func(SystemInformation, q4.DecodeState,

	) (SystemInformation, q4.Snapshot,

	)
	compare func(SystemInformation, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (SystemInformation,

		error)
	encode func(SystemInformation,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c SystemInformationValueCodec) New(value SystemInformation,

) (SystemInformationAPERValue, error) {
	if c.encode == nil {
		return SystemInformationAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return SystemInformationAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SystemInformationAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return SystemInformationAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c SystemInformationValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (SystemInformationAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SystemInformationAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return SystemInformationAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SystemInformationAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return SystemInformationAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return SystemInformationAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c SystemInformationValueCodec) EncodeAPER(value SystemInformationAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c SystemInformationValueCodec) encodeBudget(value SystemInformation,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SystemInformationValueCodec) encodeChanged(value SystemInformation,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}

// SystemInformationElemValueCodec is the concrete ValueCodec[SystemInformationElem].
type SystemInformationElemValueCodec struct {
	context q5.BridgeCodecContext
	capture func(SystemInformationElem, q4.DecodeState,

	) (SystemInformationElem, q4.Snapshot,

	)
	compare func(SystemInformationElem, q4.Snapshot, q4.ComparisonLimits,

	) q4.ReplayPlan
	path   q4.Path
	decode func([]byte, q4.DecodeState) (SystemInformationElem,

		error)
	encode func(SystemInformationElem,

		bool, *q4.DecodeBudget) ([]byte, error)
}

func (c SystemInformationElemValueCodec) New(value SystemInformationElem,

) (SystemInformationElemAPERValue, error) {
	if c.encode == nil {
		return SystemInformationElemAPERValue{}, q4.OperationError(q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue), "Value.New")
	}
	budget, err := q4.BuildBudget()
	if err != nil {
		return SystemInformationElemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SystemInformationElemAPERValue{}, q4.OperationError(err, "Value.New")
	}
	return SystemInformationElemAPERValue{Value: value}, q4.OperationError(nil, "Value.New")
}
func (c SystemInformationElemValueCodec) DecodeAPER(data []byte, options ...q4.DecodeOption) (SystemInformationElemAPERValue, q4.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SystemInformationElemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: unbound value codec", q4.ErrInvalidValue)
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := q4.FinishDecode(settings, err)
		return SystemInformationElemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SystemInformationElemAPERValue{}, q4.DecodeReport{}, q6.Errorf("%w: missing semantic capture", q4.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := q4.FinishDecode(settings, nil)
	if err != nil {
		return SystemInformationElemAPERValue{}, report, q4.OperationError(err, c.path)
	}
	return SystemInformationElemAPERValue{Value: value, received: q4.OriginalWire(data), replay: replay, context: c.context}, report, nil
}
func (c SystemInformationElemValueCodec) EncodeAPER(value SystemInformationElemAPERValue, options ...q4.EncodeOption) ([]byte, error) {
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
func (c SystemInformationElemValueCodec) encodeBudget(value SystemInformationElem,

	fresh bool, budget q4.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SystemInformationElemValueCodec) encodeChanged(value SystemInformationElem,

	fresh bool, plan q4.ReplayPlan, budget q4.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, q4.OperationError(err, c.path)
}
func BridgeResultUTRANItemExtIEsValueValidateLPPaExtensionContainer(fields q9.ResultUTRANItemExtIEsExtContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget) q10.ValidationReport {
	bb := q4.NewBudgetBuffer(budget)
	if err := q4.ChargeSlice[q9.ResultUTRANItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q10.ValidationReport {
			sealed := q10.ValidationReport{}
			*q10.BridgeValidationReportFieldErr(&sealed) = err
			*q10.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q9.ResultUTRANItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeResultUTRANItemExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeResultsPerSSBIndexItemExtIEsValueValidateLPPaExtensionContainer(fields q9.ResultsPerSSBIndexItemExtIEsExtContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget) q10.ValidationReport {
	bb := q4.NewBudgetBuffer(budget)
	if err := q4.ChargeSlice[q9.ResultsPerSSBIndexItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() q10.ValidationReport {
			sealed := q10.ValidationReport{}
			*q10.BridgeValidationReportFieldErr(&sealed) = err
			*q10.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(q9.ResultsPerSSBIndexItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeResultsPerSSBIndexItemExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeAssistanceInformationControlIEValueCaptureLPPaProtocolIEField(v *AssistanceInformationControlIEField, s *q4.SemanticCapture) {
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
func BridgeAssistanceInformationControlIEValueCompareLPPaProtocolIEField(v *AssistanceInformationControlIEField, s *q4.SemanticComparison) {
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

// resultUTRANItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ResultUTRANItemExtIEsValue].
type ResultUTRANItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) q8.ResultUTRANItemExtIEsValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (q8.ResultUTRANItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

// resultsPerSSBIndexItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ResultsPerSSBIndexItemExtIEsValue].
type ResultsPerSSBIndexItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(q4.SemanticCapture) q8.ResultsPerSSBIndexItemExtIEsValue

	captureFraming() uint64
	captureSnapshot() q4.Snapshot
	compareSemantics(q4.SemanticComparison) q4.SemanticComparison
	decode(q5.ProtocolIEID, q4.OpaqueOpenType) (q8.ResultsPerSSBIndexItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *q4.DecodeBudget) ([]byte, error)
	matchesID(q5.ProtocolIEID, *q4.DecodeBudget) bool
	reason(q5.ProtocolIEID) q4.OpaqueReason
	rule() q4.SourceRule
}

func BridgeResultsPerSSBIndexItemExtIEsValueCaptureLPPaProtocolExtensionField(v *q9.ResultsPerSSBIndexItemExtIEsExtField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q9.BridgeResultsPerSSBIndexItemExtIEsExtFieldFieldStream(v))
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q8.BridgeResultsPerSSBIndexItemExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q8.BridgeResultsPerSSBIndexItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q8.BridgeResultsPerSSBIndexItemExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q9.BridgeResultsPerSSBIndexItemExtIEsExtFieldFieldReplay(v), *q9.BridgeResultsPerSSBIndexItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeResultsPerSSBIndexItemExtIEsValueCompareLPPaProtocolExtensionField(v *q9.ResultsPerSSBIndexItemExtIEsExtField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q11.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q11.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q8.BridgeResultsPerSSBIndexItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q9.BridgeResultsPerSSBIndexItemExtIEsExtFieldFieldReplay(v), *q9.BridgeResultsPerSSBIndexItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSystemInformationExtIEsValueCaptureLPPaProtocolExtensionField(v *q9.SystemInformationExtIEsExtField, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*q9.BridgeSystemInformationExtIEsExtFieldFieldStream(v))
	q5.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	q5.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(q8.BridgeSystemInformationExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = q8.BridgeSystemInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(q8.BridgeSystemInformationExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, q9.BridgeSystemInformationExtIEsExtFieldFieldReplay(v), *q9.BridgeSystemInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSystemInformationExtIEsValueCompareLPPaProtocolExtensionField(v *q9.SystemInformationExtIEsExtField, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q11.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	q11.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = q8.BridgeSystemInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *q9.BridgeSystemInformationExtIEsExtFieldFieldReplay(v), *q9.BridgeSystemInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// ResultsPerSSBIndexListAPERValue is the concrete APERValue[ResultsPerSSBIndexList].
type ResultsPerSSBIndexListAPERValue struct {
	context q5.BridgeCodecContext
	Value   ResultsPerSSBIndexList

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v ResultsPerSSBIndexListAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v ResultsPerSSBIndexListAPERValue) WithoutReplay() ResultsPerSSBIndexListAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// AssistanceInformationAPERValue is the concrete APERValue[AssistanceInformation].
type AssistanceInformationAPERValue struct {
	context q5.BridgeCodecContext
	Value   AssistanceInformation

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v AssistanceInformationAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v AssistanceInformationAPERValue) WithoutReplay() AssistanceInformationAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultUTRANAPERValue is the concrete APERValue[ResultUTRAN].
type ResultUTRANAPERValue struct {
	context q5.BridgeCodecContext
	Value   ResultUTRAN

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v ResultUTRANAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v ResultUTRANAPERValue) WithoutReplay() ResultUTRANAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultUTRANItemAPERValue is the concrete APERValue[ResultUTRANItem].
type ResultUTRANItemAPERValue struct {
	context q5.BridgeCodecContext
	Value   ResultUTRANItem

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v ResultUTRANItemAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v ResultUTRANItemAPERValue) WithoutReplay() ResultUTRANItemAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultsPerSSBIndexItemAPERValue is the concrete APERValue[ResultsPerSSBIndexItem].
type ResultsPerSSBIndexItemAPERValue struct {
	context q5.BridgeCodecContext
	Value   ResultsPerSSBIndexItem

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v ResultsPerSSBIndexItemAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v ResultsPerSSBIndexItemAPERValue) WithoutReplay() ResultsPerSSBIndexItemAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// SystemInformationAPERValue is the concrete APERValue[SystemInformation].
type SystemInformationAPERValue struct {
	context q5.BridgeCodecContext
	Value   SystemInformation

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v SystemInformationAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v SystemInformationAPERValue) WithoutReplay() SystemInformationAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// SystemInformationElemAPERValue is the concrete APERValue[SystemInformationElem].
type SystemInformationElemAPERValue struct {
	context q5.BridgeCodecContext
	Value   SystemInformationElem

	received      q4.WireSpan
	replay        q4.Snapshot
	withoutReplay bool
}

func (v SystemInformationElemAPERValue) ReceivedForm() q4.ReceivedForm {
	return q4.NewReceivedSpanForm(v.received.Present(), v.received, q4.Location{}, nil)
}
func (v SystemInformationElemAPERValue) WithoutReplay() SystemInformationElemAPERValue {
	v.received = q4.WireSpan{}
	v.replay = q4.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeResultUTRANItemExtIEsValueValidateLPPaIEContainer(fields q9.ResultUTRANItemExtIEsIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

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
		if !q8.BridgeResultUTRANItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q8.BridgeResultUTRANItemExtIEsValueMethodRule(field.Value)
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

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeResultsPerSSBIndexItemExtIEsValueValidateLPPaIEContainer(fields q9.ResultsPerSSBIndexItemExtIEsIEContainer, rows []q5.FieldInfo, path string, budget *q4.DecodeBudget,

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
		if !q8.BridgeResultsPerSSBIndexItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := q8.BridgeResultsPerSSBIndexItemExtIEsValueMethodRule(field.Value)
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

// AssistanceInformation represents the ASN.1 type Assistance-Information (SEQUENCE).
type AssistanceInformation struct {
	replay                 q4.Snapshot
	stream                 q4.WireSpan
	withoutReplay          bool
	received               bool
	receivedBytes          q4.WireSpan
	SystemInformation      SystemInformation                          `asn1:"tag:0,context,implicit"`
	systemInformationIndef bool                                       `asn1:"-" json:"-"`
	IEExtensions           q8.AssistanceInformationExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef      bool                                       `asn1:"-" json:"-"`
	extCount               int64                                      `asn1:"-" json:"-"`
	extPresent             []bool                                     `asn1:"-" json:"-"`
	extData                [][]byte                                   `asn1:"-" json:"-"`
	perPadding             q4.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding          []q4.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin              []q4.OpaqueOrigin
	extWire                []q4.WireSpan
}
type ResultUTRAN = []ResultUTRANItem

// ResultUTRANItem represents the ASN.1 type ResultUTRAN-Item (SEQUENCE).
type ResultUTRANItem struct {
	replay            q4.Snapshot
	stream            q4.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     q4.WireSpan
	UARFCN            q5.UARFCN                            `asn1:"tag:0,context,implicit"`
	PhysCellIDUTRAN   q12.ResultUTRANItemPhysCellIDUTRAN   `asn1:"tag:1,context,explicit"`
	UTRARSCP          q5.UTRARSCP                          `asn1:"tag:2,context,implicit,optional" json:"UTRARSCP,omitzero"`
	UTRAEcN0          q5.UTRAEcN0                          `asn1:"tag:3,context,implicit,optional" json:"UTRAEcN0,omitzero"`
	IEExtensions      q9.ResultUTRANItemExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                 `asn1:"-" json:"-"`
	extCount          int64                                `asn1:"-" json:"-"`
	extPresent        []bool                               `asn1:"-" json:"-"`
	extData           [][]byte                             `asn1:"-" json:"-"`
	perPadding        q4.FinalPadding                      `asn1:"-" json:"-"`
	perExtPadding     []q4.CompletePadding                 `asn1:"-" json:"-"`
	extOrigin         []q4.OpaqueOrigin
	extWire           []q4.WireSpan
}
type ResultsPerSSBIndexList = []ResultsPerSSBIndexItem

// ResultsPerSSBIndexItem represents the ASN.1 type ResultsPerSSB-Index-Item (SEQUENCE).
type ResultsPerSSBIndexItem struct {
	replay            q4.Snapshot
	stream            q4.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     q4.WireSpan
	SSBIndex          q5.SSBIndex                                 `asn1:"tag:0,context,implicit"`
	SSNRRSRPBeamValue *q5.SSNRRSRP                                `asn1:"tag:1,context,implicit,optional" json:"SSNRRSRPBeamValue,omitempty"`
	SSNRRSRQBeamValue *q5.SSNRRSRQ                                `asn1:"tag:2,context,implicit,optional" json:"SSNRRSRQBeamValue,omitempty"`
	IEExtensions      q9.ResultsPerSSBIndexItemExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                        `asn1:"-" json:"-"`
	extCount          int64                                       `asn1:"-" json:"-"`
	extPresent        []bool                                      `asn1:"-" json:"-"`
	extData           [][]byte                                    `asn1:"-" json:"-"`
	perPadding        q4.FinalPadding                             `asn1:"-" json:"-"`
	perExtPadding     []q4.CompletePadding                        `asn1:"-" json:"-"`
	extOrigin         []q4.OpaqueOrigin
	extWire           []q4.WireSpan
}
type SystemInformation = []SystemInformationElem

// SystemInformationElem represents the ASN.1 type SystemInformation-Elem (SEQUENCE).
type SystemInformationElem struct {
	replay               q4.Snapshot
	stream               q4.WireSpan
	withoutReplay        bool
	received             bool
	receivedBytes        q4.WireSpan
	BroadcastPeriodicity q5.BroadcastPeriodicity                `asn1:"tag:0,context,implicit"`
	PosSIBs              q13.PosSIBs                            `asn1:"tag:1,context,implicit"`
	posSIBsIndef         bool                                   `asn1:"-" json:"-"`
	IEExtensions         q9.SystemInformationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef    bool                                   `asn1:"-" json:"-"`
	extCount             int64                                  `asn1:"-" json:"-"`
	extPresent           []bool                                 `asn1:"-" json:"-"`
	extData              [][]byte                               `asn1:"-" json:"-"`
	perPadding           q4.FinalPadding                        `asn1:"-" json:"-"`
	perExtPadding        []q4.CompletePadding                   `asn1:"-" json:"-"`
	extOrigin            []q4.OpaqueOrigin
	extWire              []q4.WireSpan
}

// MarshalAPER encodes AssistanceInformation to APER format.
func (v *AssistanceInformation) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *AssistanceInformation) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if err := q4.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q4.EncodeCollection(bb, int64(len(v.SystemInformation)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_systeminformation, fragmentLength_systeminformation int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_systeminformation < 0 || fragmentOffset_systeminformation > int64(len(v.SystemInformation)) || fragmentLength_systeminformation < 0 || fragmentLength_systeminformation > int64(len(v.SystemInformation[fragmentOffset_systeminformation:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.SystemInformation[fragmentOffset_systeminformation : fragmentOffset_systeminformation+fragmentLength_systeminformation] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding systemInformation element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding systemInformation: %w", err)
	}
	if v.IEExtensions != nil {
		if err := q4.EncodeCollection(bb, int64(len(v.IEExtensions)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q8.BridgeAssistanceInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes AssistanceInformation from APER format.
func (v *AssistanceInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AssistanceInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AssistanceInformation) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "AssistanceInformation")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "AssistanceInformation")
	}
	padding, err := q4.CaptureFinalBits(bb, "AssistanceInformation")
	if err != nil {
		return q7.WrapDecodePath(err, "AssistanceInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *AssistanceInformation) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformation{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_systeminformation := bb.EnterComponent("SystemInformation")
	v.SystemInformation = make(SystemInformation, 0)
	_, errCollection_systeminformation := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_systeminformation, fragmentLength_systeminformation int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_systeminformation < 0 || fragmentLength_systeminformation < 0 || fragmentLength_systeminformation > int64(^uint(0)>>1) || fragmentOffset_systeminformation > int64(^uint(0)>>1)-fragmentLength_systeminformation {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_systeminformation; i++ {
			var elem SystemInformationElem
			elementMark := bb.EnterIndex(fragmentOffset_systeminformation + i)
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("SystemInformation[%d]", fragmentOffset_systeminformation+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := q4.AppendValues(bb, v.SystemInformation, elem); err != nil {
				return err
			} else {
				v.SystemInformation = next
			}
		}
		return nil
	})
	if errCollection_systeminformation != nil {
		return q7.WrapDecodePath(errCollection_systeminformation, "SystemInformation")
	}
	bb.LeaveComponent(toleranceMark_systeminformation)
	if opt_ieextensions {
		tmp_ieextensions := make(q8.AssistanceInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q8.AssistanceInformationExtIEsExtField
				if err := q8.BridgeAssistanceInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERResultUTRANListValue struct{ Value ResultUTRAN }

// MarshalAPERResultUTRANTo appends a ResultUTRAN list to bb.
func BridgeMarshalAPERResultUTRANTo(list ResultUTRAN, bb *q4.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERResultUTRANListValue{Value: list}
	if err := q4.EncodeCollection(bb, int64(len(v.Value)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ResultUTRANItem to APER format.
func (v *ResultUTRANItem) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ResultUTRANItem) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if err := q4.EncodeBoolean(bb, v.UTRARSCP != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.UTRAEcN0 != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q4.EncodeIntegerBigBoundsAligned(bb, v.UARFCN, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound10, true); err != nil {
		return q6.Errorf("encoding uARFCN: %w", err)
	}
	if err := q12.BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERTo(&v.PhysCellIDUTRAN, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return q6.Errorf("encoding physCellIDUTRAN: %w", err)
	}
	if v.UTRARSCP != nil {
		if err := q4.EncodeIntegerBigBoundsAligned(bb, v.UTRARSCP, q5.BridgeAsn1IntegerBound0, q5.BridgeAsn1IntegerBound21, true); err != nil {
			return q6.Errorf("encoding uTRA-RSCP: %w", err)
		}
	}
	if v.UTRAEcN0 != nil {
		if err := q4.EncodeIntegerBigBoundsAligned(bb, v.UTRAEcN0, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound15, true); err != nil {
			return q6.Errorf("encoding uTRA-EcN0: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := q4.EncodeCollection(bb, int64(len(v.IEExtensions)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q9.BridgeResultUTRANItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ResultUTRANItem from APER format.
func (v *ResultUTRANItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResultUTRANItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResultUTRANItem) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "ResultUTRANItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "ResultUTRANItem")
	}
	padding, err := q4.CaptureFinalBits(bb, "ResultUTRANItem")
	if err != nil {
		return q7.WrapDecodePath(err, "ResultUTRANItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ResultUTRANItem) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultUTRANItem{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_utrarscp, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_utraecn0, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_uarfcn, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound10, true)
	if err != nil {
		return q7.WrapDecodePath(err, "UARFCN")
	}
	v.UARFCN = val_uarfcn
	if err := q12.BridgeResultUTRANItemPhysCellIDUTRANMethodUnmarshalAPERFrom(&v.PhysCellIDUTRAN, bb); err != nil {
		return q7.WrapDecodePath(err, "PhysCellIDUTRAN")
	}
	if opt_utrarscp {
		val_utrarscp, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound0, q5.BridgeAsn1IntegerBound21, true)
		if err != nil {
			return q7.WrapDecodePath(err, "UTRARSCP")
		}
		v.UTRARSCP = val_utrarscp
	}
	if opt_utraecn0 {
		val_utraecn0, err := q4.DecodeIntegerBigBoundsAligned(bb, q5.BridgeAsn1IntegerBound1, q5.BridgeAsn1IntegerBound15, true)
		if err != nil {
			return q7.WrapDecodePath(err, "UTRAEcN0")
		}
		v.UTRAEcN0 = val_utraecn0
	}
	if opt_ieextensions {
		tmp_ieextensions := make(q9.ResultUTRANItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q9.ResultUTRANItemExtIEsExtField
				if err := q9.BridgeResultUTRANItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERResultsPerSSBIndexListListValue struct{ Value ResultsPerSSBIndexList }

// MarshalAPERResultsPerSSBIndexListTo appends a ResultsPerSSBIndexList list to bb.
func BridgeMarshalAPERResultsPerSSBIndexListTo(list ResultsPerSSBIndexList, bb *q4.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERResultsPerSSBIndexListListValue{Value: list}
	if err := q4.EncodeCollection(bb, int64(len(v.Value)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ResultsPerSSBIndexItem to APER format.
func (v *ResultsPerSSBIndexItem) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ResultsPerSSBIndexItem) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if err := q4.EncodeBoolean(bb, v.SSNRRSRPBeamValue != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.SSNRRSRQBeamValue != nil); err != nil {
		return err
	}
	if err := q4.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q4.EncodeIntegerAligned(bb, int64(v.SSBIndex), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(63), false); err != nil {
		return q6.Errorf("encoding sSB-Index: %w", err)
	}
	if v.SSNRRSRPBeamValue != nil {
		if err := q4.EncodeIntegerAligned(bb, int64(*v.SSNRRSRPBeamValue), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(127), false); err != nil {
			return q6.Errorf("encoding sS-NRRSRPBeamValue: %w", err)
		}
	}
	if v.SSNRRSRQBeamValue != nil {
		if err := q4.EncodeIntegerAligned(bb, int64(*v.SSNRRSRQBeamValue), q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(127), false); err != nil {
			return q6.Errorf("encoding sS-NRRSRQBeamValue: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := q4.EncodeCollection(bb, int64(len(v.IEExtensions)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q9.BridgeResultsPerSSBIndexItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ResultsPerSSBIndexItem from APER format.
func (v *ResultsPerSSBIndexItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResultsPerSSBIndexItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResultsPerSSBIndexItem) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "ResultsPerSSBIndexItem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "ResultsPerSSBIndexItem")
	}
	padding, err := q4.CaptureFinalBits(bb, "ResultsPerSSBIndexItem")
	if err != nil {
		return q7.WrapDecodePath(err, "ResultsPerSSBIndexItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ResultsPerSSBIndexItem) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultsPerSSBIndexItem{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ssnrrsrpbeamvalue, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ssnrrsrqbeamvalue, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_ssbindex, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(63), false)
	if err != nil {
		return q7.WrapDecodePath(err, "SSBIndex")
	}
	v.SSBIndex = q5.SSBIndex(val_ssbindex)
	if opt_ssnrrsrpbeamvalue {
		val_ssnrrsrpbeamvalue, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(127), false)
		if err != nil {
			return q7.WrapDecodePath(err, "SSNRRSRPBeamValue")
		}
		tmp_ssnrrsrpbeamvalue := q5.SSNRRSRP(val_ssnrrsrpbeamvalue)
		if err := q4.ChargeValue(bb, tmp_ssnrrsrpbeamvalue); err != nil {
			return err
		}
		v.SSNRRSRPBeamValue = (*q5.SSNRRSRP)(bb.OwnInt64(int64(tmp_ssnrrsrpbeamvalue)))
	}
	if opt_ssnrrsrqbeamvalue {
		val_ssnrrsrqbeamvalue, err := q4.DecodeIntegerAligned(bb, q8.BridgeInt64Ptr(0), q8.BridgeInt64Ptr(127), false)
		if err != nil {
			return q7.WrapDecodePath(err, "SSNRRSRQBeamValue")
		}
		tmp_ssnrrsrqbeamvalue := q5.SSNRRSRQ(val_ssnrrsrqbeamvalue)
		if err := q4.ChargeValue(bb, tmp_ssnrrsrqbeamvalue); err != nil {
			return err
		}
		v.SSNRRSRQBeamValue = (*q5.SSNRRSRQ)(bb.OwnInt64(int64(tmp_ssnrrsrqbeamvalue)))
	}
	if opt_ieextensions {
		tmp_ieextensions := make(q9.ResultsPerSSBIndexItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q9.ResultsPerSSBIndexItemExtIEsExtField
				if err := q9.BridgeResultsPerSSBIndexItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERSystemInformationListValue struct{ Value SystemInformation }

// MarshalAPER encodes SystemInformationElem to APER format.
func (v *SystemInformationElem) marshalAPERLegacy() ([]byte, error) {
	bb := q4.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SystemInformationElem) marshalAPERTo(bb *q4.BitBuffer, fresh ...bool) error {
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
	if err := q4.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := q4.EncodeEnumeratedAligned(bb, int64(v.BroadcastPeriodicity), 7, true); err != nil {
		return q6.Errorf("encoding broadcastPeriodicity: %w", err)
	}
	if err := q4.EncodeCollection(bb, int64(len(v.PosSIBs)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_possibs, fragmentLength_possibs int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_possibs < 0 || fragmentOffset_possibs > int64(len(v.PosSIBs)) || fragmentLength_possibs < 0 || fragmentLength_possibs > int64(len(v.PosSIBs[fragmentOffset_possibs:])) {
			return q6.Errorf("collection fragment outside value")
		}
		for _, elem := range v.PosSIBs[fragmentOffset_possibs : fragmentOffset_possibs+fragmentLength_possibs] {
			if err := q13.BridgePosSIBsElemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return q6.Errorf("encoding posSIBs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return q6.Errorf("encoding posSIBs: %w", err)
	}
	if v.IEExtensions != nil {
		if err := q4.EncodeCollection(bb, int64(len(v.IEExtensions)), q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return q6.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := q9.BridgeSystemInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SystemInformationElem from APER format.
func (v *SystemInformationElem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, q4.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SystemInformationElem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SystemInformationElem) unmarshalAPERWithOptions(data []byte, options q4.DecodeState) error {
	bb := q4.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return q7.WrapDecodePath(err, "SystemInformationElem")
	}
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return q7.WrapDecodePath(err, "SystemInformationElem")
	}
	padding, err := q4.CaptureFinalBits(bb, "SystemInformationElem")
	if err != nil {
		return q7.WrapDecodePath(err, "SystemInformationElem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SystemInformationElem) unmarshalAPERFrom(bb *q4.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SystemInformationElem{}
	extAdditions := q4.BeginExtensionAdditions(bb)
	hasExtensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ieextensions, err := q4.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_broadcastperiodicity, err := q4.DecodeEnumeratedAligned(bb, 7, true, q4.EnumerationSource{KnownExtensions: 0, Path: "BroadcastPeriodicity"})
	if err != nil {
		return q7.WrapDecodePath(err, "BroadcastPeriodicity")
	}
	v.BroadcastPeriodicity = q5.BroadcastPeriodicity(val_broadcastperiodicity)
	toleranceMark_possibs := bb.EnterComponent("PosSIBs")
	v.PosSIBs = make(q13.PosSIBs, 0)
	_, errCollection_possibs := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_possibs, fragmentLength_possibs int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
		if fragmentOffset_possibs < 0 || fragmentLength_possibs < 0 || fragmentLength_possibs > int64(^uint(0)>>1) || fragmentOffset_possibs > int64(^uint(0)>>1)-fragmentLength_possibs {
			return q6.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_possibs; i++ {
			var elem q13.PosSIBsElem
			elementMark := bb.EnterIndex(fragmentOffset_possibs + i)
			if err := q13.BridgePosSIBsElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return q7.WrapDecodePath(err, q6.Sprintf("PosSIBs[%d]", fragmentOffset_possibs+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := q4.AppendValues(bb, v.PosSIBs, elem); err != nil {
				return err
			} else {
				v.PosSIBs = next
			}
		}
		return nil
	})
	if errCollection_possibs != nil {
		return q7.WrapDecodePath(errCollection_possibs, "PosSIBs")
	}
	bb.LeaveComponent(toleranceMark_possibs)
	if opt_ieextensions {
		tmp_ieextensions := make(q9.SystemInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := q4.DecodeCollection(bb, q4.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1108
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return q6.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem q9.SystemInformationExtIEsExtField
				if err := q9.BridgeSystemInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
func (v *AssistanceInformation) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q14.BridgeReceivedFormAt(v.received, v.receivedBytes, "AssistanceInformation", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AssistanceInformation) WithoutReplay() AssistanceInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero AssistanceInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultUTRANItem) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultUTRANItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultUTRANItem) WithoutReplay() ResultUTRANItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero ResultUTRANItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultsPerSSBIndexItem) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q14.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultsPerSSBIndexItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultsPerSSBIndexItem) WithoutReplay() ResultsPerSSBIndexItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero ResultsPerSSBIndexItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SystemInformationElem) ReceivedForm() q4.ReceivedForm {
	if v == nil {
		return q4.ReceivedForm{}
	}
	return q14.BridgeReceivedFormAt(v.received, v.receivedBytes, "SystemInformationElem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SystemInformationElem) WithoutReplay() SystemInformationElem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = q4.WireSpan{}
	var zero SystemInformationElem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *AssistanceInformation) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *AssistanceInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("AssistanceInformation.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("AssistanceInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *AssistanceInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("AssistanceInformation.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("AssistanceInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ResultUTRANItem) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ResultUTRANItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ResultUTRANItem.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ResultUTRANItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ResultUTRANItem) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ResultUTRANItem.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ResultUTRANItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ResultsPerSSBIndexItem) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ResultsPerSSBIndexItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ResultsPerSSBIndexItem.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ResultsPerSSBIndexItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ResultsPerSSBIndexItem) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("ResultsPerSSBIndexItem.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("ResultsPerSSBIndexItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SystemInformationElem) Extensions() []q4.SequenceExtension {
	if v == nil {
		return nil
	}
	views := q4.SequenceExtensionViews(v.extPresent, q4.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SystemInformationElem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("SystemInformationElem.Extensions[%d]", index))
	}
	if err := q4.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("SystemInformationElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SystemInformationElem) RemoveExtension(index uint64) error {
	if v == nil {
		return q7.WrapDecodePath(q4.ErrInvalidValue, q6.Sprintf("SystemInformationElem.Extensions[%d]", index))
	}
	if err := q4.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return q7.WrapDecodePath(err, q6.Sprintf("SystemInformationElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = q4.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}
func (v *AssistanceInformation) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "AssistanceInformation")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "AssistanceInformation")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaAssistanceInformation(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "AssistanceInformation")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "AssistanceInformation")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "AssistanceInformation")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "AssistanceInformation")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "AssistanceInformation")
}
func (v *AssistanceInformation) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *AssistanceInformation) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *AssistanceInformation) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaAssistanceInformation(v, &s)
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
func (v *AssistanceInformation) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AssistanceInformation) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ResultUTRANItem) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "ResultUTRANItem")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "ResultUTRANItem")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaResultUTRANItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "ResultUTRANItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "ResultUTRANItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "ResultUTRANItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "ResultUTRANItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "ResultUTRANItem")
}
func (v *ResultUTRANItem) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultUTRANItem) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultUTRANItem) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaResultUTRANItem(v, &s)
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
func (v *ResultUTRANItem) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultUTRANItem) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ResultsPerSSBIndexItem) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "ResultsPerSSBIndexItem")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "ResultsPerSSBIndexItem")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaResultsPerSSBIndexItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "ResultsPerSSBIndexItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "ResultsPerSSBIndexItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "ResultsPerSSBIndexItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "ResultsPerSSBIndexItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "ResultsPerSSBIndexItem")
}
func (v *ResultsPerSSBIndexItem) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultsPerSSBIndexItem) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultsPerSSBIndexItem) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaResultsPerSSBIndexItem(v, &s)
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
func (v *ResultsPerSSBIndexItem) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultsPerSSBIndexItem) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *SystemInformationElem) MarshalAPER(options ...q4.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, q4.OperationError(q4.ErrInvalidValue, "SystemInformationElem")
	}
	fresh := v.withoutReplay || q4.EncodeWithoutReplay(options...)
	var budget q4.DecodeBudget
	if err := q4.InitEncodeBudget(&budget, options...); err != nil {
		return nil, q4.OperationError(err, "SystemInformationElem")
	}
	if !fresh && v.replay.Present() {

		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(&budget))
		BridgeCompareLPPaSystemInformationElem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, q4.OperationError(err, "SystemInformationElem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, q4.OperationError(err, "SystemInformationElem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, q4.OperationError(err, "SystemInformationElem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, q4.OperationError(err, "SystemInformationElem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, q4.OperationError(err, "SystemInformationElem")
}
func (v *SystemInformationElem) marshalAPERChangedValue(budget q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *SystemInformationElem) marshalAPERFreshValue(budget q4.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *SystemInformationElem) marshalAPERBudget(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, q4.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := q4.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := q4.NewSemanticComparison(v.replay, q4.ComparisonBudget(budget))
		BridgeCompareLPPaSystemInformationElem(v, &s)
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
func (v *SystemInformationElem) marshalAPERChanged(budget *q4.DecodeBudget, fresh bool, plan q4.ReplayPlan) ([]byte, error) {
	previous := q4.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *SystemInformationElem) marshalAPERPlanned(budget *q4.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *AssistanceInformation) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "AssistanceInformation")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded AssistanceInformation
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaAssistanceInformation(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = AssistanceInformation{}
		return report, q4.OperationError(err, "AssistanceInformation")
	}
	*v = decoded
	return report, q4.OperationError(nil, "AssistanceInformation")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultUTRANItem) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "ResultUTRANItem")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded ResultUTRANItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultUTRANItem(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = ResultUTRANItem{}
		return report, q4.OperationError(err, "ResultUTRANItem")
	}
	*v = decoded
	return report, q4.OperationError(nil, "ResultUTRANItem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultsPerSSBIndexItem) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "ResultsPerSSBIndexItem")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded ResultsPerSSBIndexItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultsPerSSBIndexItem(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = ResultsPerSSBIndexItem{}
		return report, q4.OperationError(err, "ResultsPerSSBIndexItem")
	}
	*v = decoded
	return report, q4.OperationError(nil, "ResultsPerSSBIndexItem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *SystemInformationElem) UnmarshalAPER(data []byte, options ...q4.DecodeOption) (q4.DecodeReport, error) {
	if v == nil {
		return q4.DecodeReport{}, q4.OperationError(q4.ErrInvalidValue, "SystemInformationElem")
	}
	data, settings := q4.OwnDecodeInputOptions(data, options...)
	var decoded SystemInformationElem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = q4.OriginalWire(data)
		s := q4.SemanticCaptureFor(settings)
		BridgeCaptureLPPaSystemInformationElem(&decoded, &s)
	}
	report, err := q4.FinishDecode(settings, err)
	if err != nil {
		*v = SystemInformationElem{}
		return report, q4.OperationError(err, "SystemInformationElem")
	}
	*v = decoded
	return report, q4.OperationError(nil, "SystemInformationElem")
}
func BridgeCaptureLPPaAssistanceInformation(v *AssistanceInformation, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgeCaptureLPPaSystemInformation(&v.SystemInformation, s)
	s.Bool(v.IEExtensions == nil)
	q9.BridgeAssistanceInformationExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaAssistanceInformation(v *AssistanceInformation, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeCompareLPPaSystemInformation(&v.SystemInformation, s)
	s.Bool(v.IEExtensions == nil)
	q9.BridgeAssistanceInformationExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaAssistanceInformationControlIEValue(v *AssistanceInformationControlIEValue, s *q4.SemanticCapture) {
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
		case q5.ProtocolIEID(22):
			{
				f := s.Begin()
				s.Bool(v.rowAssistanceInformation == nil)
				if v.rowAssistanceInformation != nil {
					BridgeCaptureLPPaAssistanceInformation(v.rowAssistanceInformation, s)
				}
				s.End(f, nil, false)
			}
		case q5.ProtocolIEID(23):
			{
				f := s.Begin()
				s.Bool(v.rowBroadcast == nil)
				if v.rowBroadcast != nil {
					q5.BridgeCaptureLPPaBroadcast(v.rowBroadcast, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v AssistanceInformationControlIEValue) captureSnapshot() q4.Snapshot { return v.replay }
func (v AssistanceInformationControlIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v AssistanceInformationControlIEValue) captureSemantics(s q4.SemanticCapture) AssistanceInformationControlIEValue {
	BridgeCaptureLPPaAssistanceInformationControlIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaAssistanceInformationControlIEValue(v *AssistanceInformationControlIEValue, s *q4.SemanticComparison) {
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
		case q5.ProtocolIEID(22):
			{
				f := s.Begin()
				s.Bool(v.rowAssistanceInformation == nil)
				if v.rowAssistanceInformation != nil {
					BridgeCompareLPPaAssistanceInformation(v.rowAssistanceInformation, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		case q5.ProtocolIEID(23):
			{
				f := s.Begin()
				s.Bool(v.rowBroadcast == nil)
				if v.rowBroadcast != nil {
					q11.BridgeCompareLPPaBroadcast(v.rowBroadcast, s)
				}
				s.End(f, q4.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v AssistanceInformationControlIEValue) compareSemantics(s q4.SemanticComparison) q4.SemanticComparison {
	BridgeCompareLPPaAssistanceInformationControlIEValue(&v, &s)
	return s
}
func (v AssistanceInformationControlIEValue) WithoutReplay() AssistanceInformationControlIEValue {
	v.withoutReplay = true
	v.replay = q4.Snapshot{}
	return v
}
func BridgeCaptureLPPaResultUTRAN(v *ResultUTRAN, s *q4.SemanticCapture) {
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
			BridgeCaptureLPPaResultUTRANItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaResultUTRAN(v *ResultUTRAN, s *q4.SemanticComparison) {
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
			BridgeCompareLPPaResultUTRANItem(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	s.End(f, q4.Snapshot{}, false)
}
func BridgeCaptureLPPaResultUTRANItem(v *ResultUTRANItem, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q5.BridgeCaptureLPPaUARFCN(&v.UARFCN, s)
	q12.BridgeCaptureLPPaResultUTRANItemPhysCellIDUTRAN(&v.PhysCellIDUTRAN, s)
	q5.BridgeCaptureLPPaUTRARSCP(&v.UTRARSCP, s)
	q5.BridgeCaptureLPPaUTRAEcN0(&v.UTRAEcN0, s)
	s.Bool(v.IEExtensions == nil)
	q15.BridgeResultUTRANItemExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultUTRANItem(v *ResultUTRANItem, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q8.BridgeCompareLPPaUARFCN(&v.UARFCN, s)
	q12.BridgeCompareLPPaResultUTRANItemPhysCellIDUTRAN(&v.PhysCellIDUTRAN, s)
	q8.BridgeCompareLPPaUTRARSCP(&v.UTRARSCP, s)
	q8.BridgeCompareLPPaUTRAEcN0(&v.UTRAEcN0, s)
	s.Bool(v.IEExtensions == nil)
	q15.BridgeResultUTRANItemExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultsPerSSBIndexItem(v *ResultsPerSSBIndexItem, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q5.BridgeCaptureLPPaSSBIndex(&v.SSBIndex, s)
	{
		f := s.Begin()
		s.Bool(v.SSNRRSRPBeamValue == nil)
		if v.SSNRRSRPBeamValue != nil {
			q5.BridgeCaptureLPPaSSNRRSRP(v.SSNRRSRPBeamValue, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.SSNRRSRQBeamValue == nil)
		if v.SSNRRSRQBeamValue != nil {
			q5.BridgeCaptureLPPaSSNRRSRQ(v.SSNRRSRQBeamValue, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeResultsPerSSBIndexItemExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultsPerSSBIndexItem(v *ResultsPerSSBIndexItem, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q8.BridgeCompareLPPaSSBIndex(&v.SSBIndex, s)
	{
		f := s.Begin()
		s.Bool(v.SSNRRSRPBeamValue == nil)
		if v.SSNRRSRPBeamValue != nil {
			q8.BridgeCompareLPPaSSNRRSRP(v.SSNRRSRPBeamValue, s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.SSNRRSRQBeamValue == nil)
		if v.SSNRRSRQBeamValue != nil {
			q8.BridgeCompareLPPaSSNRRSRQ(v.SSNRRSRQBeamValue, s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeResultsPerSSBIndexItemExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultsPerSSBIndexList(v *ResultsPerSSBIndexList, s *q4.SemanticCapture) {
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
			BridgeCaptureLPPaResultsPerSSBIndexItem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaResultsPerSSBIndexList(v *ResultsPerSSBIndexList, s *q4.SemanticComparison) {
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
			BridgeCompareLPPaResultsPerSSBIndexItem(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	s.End(f, q4.Snapshot{}, false)
}
func BridgeCaptureLPPaSystemInformation(v *SystemInformation, s *q4.SemanticCapture) {
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
			BridgeCaptureLPPaSystemInformationElem(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeCompareLPPaSystemInformation(v *SystemInformation, s *q4.SemanticComparison) {
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
			BridgeCompareLPPaSystemInformationElem(&(*v)[i], s)
		}
		s.End(f, q4.Snapshot{}, false)
	}
	s.End(f, q4.Snapshot{}, false)
}
func BridgeCaptureLPPaSystemInformationElem(v *SystemInformationElem, s *q4.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	q5.BridgeCaptureLPPaBroadcastPeriodicity(&v.BroadcastPeriodicity, s)
	q13.BridgeCaptureLPPaPosSIBs(&v.PosSIBs, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSystemInformationExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaSystemInformationElem(v *SystemInformationElem, s *q4.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	q11.BridgeCompareLPPaBroadcastPeriodicity(&v.BroadcastPeriodicity, s)
	q13.BridgeCompareLPPaPosSIBs(&v.PosSIBs, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSystemInformationExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}

type AssistanceInformationControlIEValue struct {
	id                       q5.ProtocolIEID
	withoutReplay            bool
	received                 q4.WireSpan
	replay                   q4.Snapshot
	opaque                   *q4.OpaqueOpenType
	isOpaque                 bool
	rowAssistanceInformation *AssistanceInformation
	rowBroadcast             *q5.Broadcast
}

func (v AssistanceInformationControlIEValue) matchesID(id q5.ProtocolIEID, _ *q4.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case q5.ProtocolIEID(22):
		return v.rowAssistanceInformation != nil
	case q5.ProtocolIEID(23):
		return v.rowBroadcast != nil
	default:
		return false
	}
}
func (v *AssistanceInformationControlIEValue) Opaque() (q4.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return q4.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (AssistanceInformationControlIEValue) rule() q4.SourceRule {
	return q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "AssistanceInformationControl-IEs"}}
}
func (AssistanceInformationControlIEValue) reason(id q5.ProtocolIEID) q4.OpaqueReason {
	switch id {
	case q5.ProtocolIEID(22):
		return q4.UnknownSelector
	case q5.ProtocolIEID(23):
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
func (v *AssistanceInformationControlIEValue) AsAssistanceInformation() (*AssistanceInformation, bool) {
	if v == nil || v.id != q5.ProtocolIEID(22) || v.rowAssistanceInformation == nil {
		return nil, false
	}
	return v.rowAssistanceInformation, true
}
func (v *AssistanceInformationControlIEValue) AsBroadcast() (*q5.Broadcast, bool) {
	if v == nil || v.id != q5.ProtocolIEID(23) || v.rowBroadcast == nil {
		return nil, false
	}
	return v.rowBroadcast, true
}
func (v AssistanceInformationControlIEValue) decode(id q5.ProtocolIEID, raw q4.OpaqueOpenType) (AssistanceInformationControlIEValue, error) {
	out := AssistanceInformationControlIEValue{id: id}
	var scope *q4.BitBuffer
	switch id {
	case 22, 23:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case q5.ProtocolIEID(22):
		replayUsage := scope.Usage()
		var value AssistanceInformation
		child := raw.ChildDecodeBuffer()
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, q6.Errorf("%s %w", "AssistanceInformation:", err)
		}
		padding, err := q4.CaptureFinalBits(child, "AssistanceInformation")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		if err := q4.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowAssistanceInformation = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case q5.ProtocolIEID(23):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := q4.DecodeEnumeratedAligned(bb, 2, true, q4.EnumerationSource{KnownExtensions: 0, Path: "Broadcast"})
		value := q5.Broadcast(decoded)
		if err != nil {
			return out, q6.Errorf("%s %w", "Broadcast:", err)
		}
		if _, err := q4.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		out.rowBroadcast = (*q5.Broadcast)(scope.OwnInt64(int64(value)))
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
func (v AssistanceInformationControlIEValue) encode() ([]byte, error) {
	budget, err := q4.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v AssistanceInformationControlIEValue) encodeFresh(fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
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
	case q5.ProtocolIEID(22):
		if v.rowAssistanceInformation == nil {
			return nil, q6.Errorf("%s missing value", "AssistanceInformationControl-IEs.id-Assistance-Information:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		candidate, err := v.rowAssistanceInformation.marshalAPERBudget(budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case q5.ProtocolIEID(23):
		if v.rowBroadcast == nil {
			return nil, q6.Errorf("%s missing value", "AssistanceInformationControl-IEs.id-Broadcast:")
		}
		if !fresh && q4.NewBudgetBuffer(budget).ReplayPlan() != nil && q4.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := q4.NewBudgetBuffer(budget)
		if err := q4.EncodeEnumeratedAligned(encodeBB, int64(*v.rowBroadcast), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, q6.Errorf("%s id %d has no value", "AssistanceInformationControlIEValue:", v.id)
	}
}

type AssistanceInformationControlIETable struct{}

func AssistanceInformationControlIEs() AssistanceInformationControlIETable {
	return AssistanceInformationControlIETable{}
}
func (AssistanceInformationControlIETable) ID() q5.TableID {
	return func() q5.TableID {
		sealed := q5.TableID{}
		*q5.BridgeTableIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "AssistanceInformationControl-IEs"}
		return sealed
	}()
}
func (AssistanceInformationControlIETable) infoAssistanceInformation() q5.FieldInfo {
	return q5.FieldInfo{Table: AssistanceInformationControlIEs().ID(), ID: q5.ProtocolIEID(22), Criticality: q5.CriticalityReject, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "AssistanceInformation"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "AssistanceInformationControl-IEs", Row: "id-Assistance-Information"}}}
}
func (t AssistanceInformationControlIETable) AssistanceInformation() AssistanceInformationControlAssistanceInformationIEBinding {
	return AssistanceInformationControlAssistanceInformationIEBinding{info: t.infoAssistanceInformation(), codec: AssistanceInformationValueCodec{path: "AssistanceInformation",
		decode: func(data []byte, options q4.DecodeState) (AssistanceInformation, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty AssistanceInformation
				return empty, err
			}
			var zero AssistanceInformationControlIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(22), raw)
			if err != nil {
				var empty AssistanceInformation
				return empty, err
			}
			value, ok := decoded.AsAssistanceInformation()
			if !ok {
				var empty AssistanceInformation
				return empty, q6.Errorf("binding AssistanceInformationControl-IEs.id-Assistance-Information: no selected value")
			}
			return *value, nil
		},
		encode: func(value AssistanceInformation, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (AssistanceInformationControlIEValue{id: q5.ProtocolIEID(22), rowAssistanceInformation: &value}).encodeFresh(fresh, budget)
		}, capture: func(v AssistanceInformation, options q4.DecodeState) (AssistanceInformation, q4.Snapshot,
		) {
			s := q4.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureLPPaAssistanceInformation(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}, compare: func(v AssistanceInformation, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaAssistanceInformation(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}, context: func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:AssistanceInformation"
			return sealed
		}(),
	}, inject: func(value AssistanceInformation) AssistanceInformationControlIEValue {
		return AssistanceInformationControlIEValue{id: q5.ProtocolIEID(22), rowAssistanceInformation: &value}
	}, get: func(value *AssistanceInformationControlIEValue) (*AssistanceInformation, bool) {
		return value.AsAssistanceInformation()
	}}
}
func (AssistanceInformationControlIETable) infoBroadcast() q5.FieldInfo {
	return q5.FieldInfo{Table: AssistanceInformationControlIEs().ID(), ID: q5.ProtocolIEID(23), Criticality: q5.CriticalityReject, Presence: q5.PresenceOptional, ValueType: func() q5.TypeID {
		sealed := q5.TypeID{}
		*q5.BridgeTypeIDFieldSource(&sealed) = q4.SourceAssignment{Module: "LPPA-IEs", Assignment: "Broadcast"}
		return sealed
	}(), Rule: q4.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: q4.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "AssistanceInformationControl-IEs", Row: "id-Broadcast"}}}
}
func (t AssistanceInformationControlIETable) Broadcast() AssistanceInformationControlBroadcastIEBinding {
	return AssistanceInformationControlBroadcastIEBinding{info: t.infoBroadcast(), codec: func() q5.BroadcastValueCodec {
		sealed := q5.BroadcastValueCodec{}
		*q5.BridgeBroadcastValueCodecFieldPath(&sealed) = "Broadcast"
		*q5.BridgeBroadcastValueCodecFieldDecode(&sealed) = func(data []byte, options q4.DecodeState) (q5.Broadcast, error) {
			raw, err := q4.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty q5.Broadcast
				return empty, err
			}
			var zero AssistanceInformationControlIEValue
			decoded, err := zero.decode(q5.ProtocolIEID(23), raw)
			if err != nil {
				var empty q5.Broadcast
				return empty, err
			}
			value, ok := decoded.AsBroadcast()
			if !ok {
				var empty q5.Broadcast
				return empty, q6.Errorf("binding AssistanceInformationControl-IEs.id-Broadcast: no selected value")
			}
			return *value, nil
		}
		*q5.BridgeBroadcastValueCodecFieldEncode(&sealed) = func(value q5.Broadcast, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
			return (AssistanceInformationControlIEValue{id: q5.ProtocolIEID(23), rowBroadcast: &value}).encodeFresh(fresh, budget)
		}
		*q5.BridgeBroadcastValueCodecFieldCapture(&sealed) = func(v q5.Broadcast, options q4.DecodeState) (q5.Broadcast, q4.Snapshot) {
			s := q4.SemanticCaptureFor(options)
			f := s.
				Begin()
			q5.BridgeCaptureLPPaBroadcast(&v, &s)
			var root q4.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*q5.BridgeBroadcastValueCodecFieldCompare(&sealed) = func(v q5.Broadcast, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
			s := q4.NewSemanticComparison(root, limits)
			f := s.Begin()
			q11.BridgeCompareLPPaBroadcast(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*q5.BridgeBroadcastValueCodecFieldContext(&sealed) = func() q5.BridgeCodecContext {
			sealed := q5.BridgeCodecContext{}
			*q5.BridgecodecContextFieldSource(&sealed) = "source-value:Broadcast"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value q5.Broadcast) AssistanceInformationControlIEValue {
			return AssistanceInformationControlIEValue{id: q5.ProtocolIEID(23), rowBroadcast: &value}
		}, get: func(value *AssistanceInformationControlIEValue) (*q5.Broadcast, bool) { return value.AsBroadcast() }}
}
func (t AssistanceInformationControlIETable) NewOpaque(id q5.ProtocolIEID, criticality q5.Criticality, data []byte) (AssistanceInformationControlIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return AssistanceInformationControlIEField{}, q4.OperationError(q6.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case q5.ProtocolIEID(22):
		return AssistanceInformationControlIEField{}, q4.OperationError(q6.Errorf("known IE id-Assistance-Information requires its typed binding"), "Opaque")
	case q5.ProtocolIEID(23):
		return AssistanceInformationControlIEField{}, q4.OperationError(q6.Errorf("known IE id-Broadcast requires its typed binding"), "Opaque")
	default:
		budget, err := q4.BuildBudget()
		if err != nil {
			return AssistanceInformationControlIEField{}, q4.OperationError(err, "Opaque")
		}
		opaque, err := q4.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return AssistanceInformationControlIEField{}, q4.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return AssistanceInformationControlIEField{}, q4.OperationError(err, "Opaque")
		}
		return AssistanceInformationControlIEField{Id: id, Criticality: criticality, Value: AssistanceInformationControlIEValue{id: id, opaque: retained, isOpaque: true}}, q4.OperationError(nil, "Opaque")
	}
}

// AssistanceInformationCodec binds the complete APER value type.
func AssistanceInformationCodec() AssistanceInformationValueCodec {
	return AssistanceInformationControlIEs().AssistanceInformation().Codec()
}

// BroadcastCodec binds the complete APER value type.
func BroadcastCodec() q5.BroadcastValueCodec {
	return AssistanceInformationControlIEs().Broadcast().Codec()
}

// ResultUTRANItemCodec binds the complete source value type.
func ResultUTRANItemCodec() ResultUTRANItemValueCodec {
	return ResultUTRANItemValueCodec{path: "ResultUTRANItem", decode: func(data []byte, options q4.DecodeState) (ResultUTRANItem, error) {
		var value ResultUTRANItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ResultUTRANItem{}, err
		}
		value.received = true
		value.receivedBytes = q4.OriginalWire(data)
		return value, nil
	}, encode: func(value ResultUTRANItem, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ResultUTRANItem, options q4.DecodeState) (ResultUTRANItem, q4.Snapshot) {
		s := q4.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaResultUTRANItem(&v, &s)
		var root q4.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResultUTRANItem, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
		s := q4.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaResultUTRANItem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q5.BridgeCodecContext {
		sealed := q5.BridgeCodecContext{}
		*q5.BridgecodecContextFieldSource(&sealed) = "source-value:ResultUTRANItem"
		return sealed
	}(),
	}
}

// ResultsPerSSBIndexItemCodec binds the complete source value type.
func ResultsPerSSBIndexItemCodec() ResultsPerSSBIndexItemValueCodec {
	return ResultsPerSSBIndexItemValueCodec{path: "ResultsPerSSBIndexItem", decode: func(data []byte, options q4.DecodeState) (ResultsPerSSBIndexItem, error) {
		var value ResultsPerSSBIndexItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ResultsPerSSBIndexItem{}, err
		}
		value.received = true
		value.receivedBytes = q4.OriginalWire(data)
		return value, nil
	}, encode: func(value ResultsPerSSBIndexItem, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ResultsPerSSBIndexItem, options q4.DecodeState) (ResultsPerSSBIndexItem, q4.Snapshot,

	) {
		s := q4.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaResultsPerSSBIndexItem(&v, &s)
		var root q4.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResultsPerSSBIndexItem, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
		s := q4.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaResultsPerSSBIndexItem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q5.BridgeCodecContext {
		sealed := q5.BridgeCodecContext{}
		*q5.BridgecodecContextFieldSource(&sealed) = "source-value:ResultsPerSSBIndexItem"
		return sealed
	}(),
	}
}

// SystemInformationElemCodec binds the complete source value type.
func SystemInformationElemCodec() SystemInformationElemValueCodec {
	return SystemInformationElemValueCodec{path: "SystemInformationElem", decode: func(data []byte, options q4.DecodeState) (SystemInformationElem, error) {
		var value SystemInformationElem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SystemInformationElem{}, err
		}
		value.received = true
		value.receivedBytes = q4.OriginalWire(data)
		return value, nil
	}, encode: func(value SystemInformationElem, fresh bool, budget *q4.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SystemInformationElem, options q4.DecodeState) (SystemInformationElem, q4.Snapshot,
	) {
		s := q4.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaSystemInformationElem(&v, &s)
		var root q4.Snapshot
		s.OperationCounts()
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v SystemInformationElem, root q4.Snapshot, limits q4.ComparisonLimits) q4.ReplayPlan {
		s := q4.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaSystemInformationElem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() q5.BridgeCodecContext {
		sealed := q5.BridgeCodecContext{}
		*q5.BridgecodecContextFieldSource(&sealed) = "source-value:SystemInformationElem"
		return sealed
	}(),
	}
}
func BridgeAssistanceInformationAPERValueFieldContext(v *AssistanceInformationAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationAPERValueFieldReceived(v *AssistanceInformationAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationAPERValueFieldReplay(v *AssistanceInformationAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationAPERValueFieldWithoutReplay(v *AssistanceInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationControlAssistanceInformationIEBindingFieldCodec(v *AssistanceInformationControlAssistanceInformationIEBinding) *AssistanceInformationValueCodec {
	return &v.codec
}
func BridgeAssistanceInformationControlAssistanceInformationIEBindingFieldGet(v *AssistanceInformationControlAssistanceInformationIEBinding) *func(*AssistanceInformationControlIEValue) (*AssistanceInformation, bool) {
	return &v.get
}
func BridgeAssistanceInformationControlAssistanceInformationIEBindingFieldInfo(v *AssistanceInformationControlAssistanceInformationIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeAssistanceInformationControlAssistanceInformationIEBindingFieldInject(v *AssistanceInformationControlAssistanceInformationIEBinding) *func(AssistanceInformation) AssistanceInformationControlIEValue {
	return &v.inject
}
func BridgeAssistanceInformationControlBroadcastIEBindingFieldCodec(v *AssistanceInformationControlBroadcastIEBinding) *q5.BroadcastValueCodec {
	return &v.codec
}
func BridgeAssistanceInformationControlBroadcastIEBindingFieldGet(v *AssistanceInformationControlBroadcastIEBinding) *func(*AssistanceInformationControlIEValue) (*q5.Broadcast, bool) {
	return &v.get
}
func BridgeAssistanceInformationControlBroadcastIEBindingFieldInfo(v *AssistanceInformationControlBroadcastIEBinding) *q5.FieldInfo {
	return &v.info
}
func BridgeAssistanceInformationControlBroadcastIEBindingFieldInject(v *AssistanceInformationControlBroadcastIEBinding) *func(q5.Broadcast) AssistanceInformationControlIEValue {
	return &v.inject
}
func BridgeAssistanceInformationControlIEFieldFieldReceived(v *AssistanceInformationControlIEField) *q4.CompletePadding {
	return &v.received
}
func BridgeAssistanceInformationControlIEFieldFieldReplay(v *AssistanceInformationControlIEField) *q4.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationControlIEFieldFieldStream(v *AssistanceInformationControlIEField) *q4.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationControlIEFieldFieldWithoutReplay(v *AssistanceInformationControlIEField) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationControlIEFieldMethodMarshalAPERTo(v *AssistanceInformationControlIEField, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationControlIEFieldMethodUnmarshalAPERFrom(v *AssistanceInformationControlIEField, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationControlIETableMethodInfoAssistanceInformation(v AssistanceInformationControlIETable) q5.FieldInfo {
	return v.infoAssistanceInformation()
}
func BridgeAssistanceInformationControlIETableMethodInfoBroadcast(v AssistanceInformationControlIETable) q5.FieldInfo {
	return v.infoBroadcast()
}
func BridgeAssistanceInformationControlIEValueFieldId(v *AssistanceInformationControlIEValue) *q5.ProtocolIEID {
	return &v.id
}
func BridgeAssistanceInformationControlIEValueFieldIsOpaque(v *AssistanceInformationControlIEValue) *bool {
	return &v.isOpaque
}
func BridgeAssistanceInformationControlIEValueFieldOpaque(v *AssistanceInformationControlIEValue) **q4.OpaqueOpenType {
	return &v.opaque
}
func BridgeAssistanceInformationControlIEValueFieldReceived(v *AssistanceInformationControlIEValue) *q4.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationControlIEValueFieldReplay(v *AssistanceInformationControlIEValue) *q4.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationControlIEValueFieldRowAssistanceInformation(v *AssistanceInformationControlIEValue) **AssistanceInformation {
	return &v.rowAssistanceInformation
}
func BridgeAssistanceInformationControlIEValueFieldRowBroadcast(v *AssistanceInformationControlIEValue) **q5.Broadcast {
	return &v.rowBroadcast
}
func BridgeAssistanceInformationControlIEValueFieldWithoutReplay(v *AssistanceInformationControlIEValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationControlIEValueMethodCaptureFraming(v AssistanceInformationControlIEValue) uint64 {
	return v.captureFraming()
}
func BridgeAssistanceInformationControlIEValueMethodCaptureSemantics(v AssistanceInformationControlIEValue, a0 q4.SemanticCapture) AssistanceInformationControlIEValue {
	return v.captureSemantics(a0)
}
func BridgeAssistanceInformationControlIEValueMethodCaptureSnapshot(v AssistanceInformationControlIEValue) q4.Snapshot {
	return v.captureSnapshot()
}
func BridgeAssistanceInformationControlIEValueMethodCompareSemantics(v AssistanceInformationControlIEValue, a0 q4.SemanticComparison) q4.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeAssistanceInformationControlIEValueMethodDecode(v AssistanceInformationControlIEValue, a0 q5.ProtocolIEID, a1 q4.OpaqueOpenType) (AssistanceInformationControlIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeAssistanceInformationControlIEValueMethodEncode(v AssistanceInformationControlIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeAssistanceInformationControlIEValueMethodEncodeFresh(v AssistanceInformationControlIEValue, a0 bool, a1 *q4.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeAssistanceInformationControlIEValueMethodMatchesID(v AssistanceInformationControlIEValue, a0 q5.ProtocolIEID, a1 *q4.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeAssistanceInformationControlIEValueMethodReason(v AssistanceInformationControlIEValue, a0 q5.ProtocolIEID) q4.OpaqueReason {
	return v.reason(a0)
}
func BridgeAssistanceInformationControlIEValueMethodRule(v AssistanceInformationControlIEValue) q4.SourceRule {
	return v.rule()
}
func BridgeAssistanceInformationFieldExtCount(v *AssistanceInformation) *int64   { return &v.extCount }
func BridgeAssistanceInformationFieldExtData(v *AssistanceInformation) *[][]byte { return &v.extData }
func BridgeAssistanceInformationFieldExtOrigin(v *AssistanceInformation) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeAssistanceInformationFieldExtPresent(v *AssistanceInformation) *[]bool {
	return &v.extPresent
}
func BridgeAssistanceInformationFieldExtWire(v *AssistanceInformation) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeAssistanceInformationFieldIEExtensionsIndef(v *AssistanceInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgeAssistanceInformationFieldPerExtPadding(v *AssistanceInformation) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeAssistanceInformationFieldPerPadding(v *AssistanceInformation) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeAssistanceInformationFieldReceived(v *AssistanceInformation) *bool { return &v.received }
func BridgeAssistanceInformationFieldReceivedBytes(v *AssistanceInformation) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeAssistanceInformationFieldReplay(v *AssistanceInformation) *q4.Snapshot { return &v.replay }
func BridgeAssistanceInformationFieldStream(v *AssistanceInformation) *q4.WireSpan { return &v.stream }
func BridgeAssistanceInformationFieldSystemInformationIndef(v *AssistanceInformation) *bool {
	return &v.systemInformationIndef
}
func BridgeAssistanceInformationFieldWithoutReplay(v *AssistanceInformation) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationMethodMarshalAPERBudget(v *AssistanceInformation, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAssistanceInformationMethodMarshalAPERChanged(v *AssistanceInformation, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAssistanceInformationMethodMarshalAPERChangedValue(v *AssistanceInformation, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAssistanceInformationMethodMarshalAPERFreshValue(v *AssistanceInformation, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeAssistanceInformationMethodMarshalAPERLegacy(v *AssistanceInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAssistanceInformationMethodMarshalAPERPlanned(v *AssistanceInformation, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeAssistanceInformationMethodMarshalAPERTo(v *AssistanceInformation, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationMethodUnmarshalAPERFrom(v *AssistanceInformation, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationMethodUnmarshalAPERLegacy(v *AssistanceInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAssistanceInformationMethodUnmarshalAPERWithOptions(v *AssistanceInformation, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAssistanceInformationValueCodecFieldCapture(v *AssistanceInformationValueCodec) *func(AssistanceInformation, q4.DecodeState) (AssistanceInformation, q4.Snapshot) {
	return &v.capture
}
func BridgeAssistanceInformationValueCodecFieldCompare(v *AssistanceInformationValueCodec) *func(AssistanceInformation, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeAssistanceInformationValueCodecFieldContext(v *AssistanceInformationValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationValueCodecFieldDecode(v *AssistanceInformationValueCodec) *func([]byte, q4.DecodeState) (AssistanceInformation, error) {
	return &v.decode
}
func BridgeAssistanceInformationValueCodecFieldEncode(v *AssistanceInformationValueCodec) *func(AssistanceInformation, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceInformationValueCodecFieldPath(v *AssistanceInformationValueCodec) *q4.Path {
	return &v.path
}
func BridgeAssistanceInformationValueCodecMethodEncodeBudget(v AssistanceInformationValueCodec, a0 AssistanceInformation, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeAssistanceInformationValueCodecMethodEncodeChanged(v AssistanceInformationValueCodec, a0 AssistanceInformation, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultUTRANAPERValueFieldContext(v *ResultUTRANAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeResultUTRANAPERValueFieldReceived(v *ResultUTRANAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeResultUTRANAPERValueFieldReplay(v *ResultUTRANAPERValue) *q4.Snapshot { return &v.replay }
func BridgeResultUTRANAPERValueFieldWithoutReplay(v *ResultUTRANAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultUTRANItemAPERValueFieldContext(v *ResultUTRANItemAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeResultUTRANItemAPERValueFieldReceived(v *ResultUTRANItemAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeResultUTRANItemAPERValueFieldReplay(v *ResultUTRANItemAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeResultUTRANItemAPERValueFieldWithoutReplay(v *ResultUTRANItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultUTRANItemFieldExtCount(v *ResultUTRANItem) *int64              { return &v.extCount }
func BridgeResultUTRANItemFieldExtData(v *ResultUTRANItem) *[][]byte            { return &v.extData }
func BridgeResultUTRANItemFieldExtOrigin(v *ResultUTRANItem) *[]q4.OpaqueOrigin { return &v.extOrigin }
func BridgeResultUTRANItemFieldExtPresent(v *ResultUTRANItem) *[]bool           { return &v.extPresent }
func BridgeResultUTRANItemFieldExtWire(v *ResultUTRANItem) *[]q4.WireSpan       { return &v.extWire }
func BridgeResultUTRANItemFieldIEExtensionsIndef(v *ResultUTRANItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeResultUTRANItemFieldPerExtPadding(v *ResultUTRANItem) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeResultUTRANItemFieldPerPadding(v *ResultUTRANItem) *q4.FinalPadding { return &v.perPadding }
func BridgeResultUTRANItemFieldReceived(v *ResultUTRANItem) *bool              { return &v.received }
func BridgeResultUTRANItemFieldReceivedBytes(v *ResultUTRANItem) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeResultUTRANItemFieldReplay(v *ResultUTRANItem) *q4.Snapshot { return &v.replay }
func BridgeResultUTRANItemFieldStream(v *ResultUTRANItem) *q4.WireSpan { return &v.stream }
func BridgeResultUTRANItemFieldWithoutReplay(v *ResultUTRANItem) *bool { return &v.withoutReplay }
func BridgeResultUTRANItemMethodMarshalAPERBudget(v *ResultUTRANItem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultUTRANItemMethodMarshalAPERChanged(v *ResultUTRANItem, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultUTRANItemMethodMarshalAPERChangedValue(v *ResultUTRANItem, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultUTRANItemMethodMarshalAPERFreshValue(v *ResultUTRANItem, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultUTRANItemMethodMarshalAPERLegacy(v *ResultUTRANItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultUTRANItemMethodMarshalAPERPlanned(v *ResultUTRANItem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultUTRANItemMethodMarshalAPERTo(v *ResultUTRANItem, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultUTRANItemMethodUnmarshalAPERFrom(v *ResultUTRANItem, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultUTRANItemMethodUnmarshalAPERLegacy(v *ResultUTRANItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultUTRANItemMethodUnmarshalAPERWithOptions(v *ResultUTRANItem, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultUTRANItemValueCodecFieldCapture(v *ResultUTRANItemValueCodec) *func(ResultUTRANItem, q4.DecodeState) (ResultUTRANItem, q4.Snapshot) {
	return &v.capture
}
func BridgeResultUTRANItemValueCodecFieldCompare(v *ResultUTRANItemValueCodec) *func(ResultUTRANItem, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeResultUTRANItemValueCodecFieldContext(v *ResultUTRANItemValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeResultUTRANItemValueCodecFieldDecode(v *ResultUTRANItemValueCodec) *func([]byte, q4.DecodeState) (ResultUTRANItem, error) {
	return &v.decode
}
func BridgeResultUTRANItemValueCodecFieldEncode(v *ResultUTRANItemValueCodec) *func(ResultUTRANItem, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultUTRANItemValueCodecFieldPath(v *ResultUTRANItemValueCodec) *q4.Path { return &v.path }
func BridgeResultUTRANItemValueCodecMethodEncodeBudget(v ResultUTRANItemValueCodec, a0 ResultUTRANItem, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultUTRANItemValueCodecMethodEncodeChanged(v ResultUTRANItemValueCodec, a0 ResultUTRANItem, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultUTRANValueCodecFieldCapture(v *ResultUTRANValueCodec) *func(ResultUTRAN, q4.DecodeState) (ResultUTRAN, q4.Snapshot) {
	return &v.capture
}
func BridgeResultUTRANValueCodecFieldCompare(v *ResultUTRANValueCodec) *func(ResultUTRAN, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeResultUTRANValueCodecFieldContext(v *ResultUTRANValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeResultUTRANValueCodecFieldDecode(v *ResultUTRANValueCodec) *func([]byte, q4.DecodeState) (ResultUTRAN, error) {
	return &v.decode
}
func BridgeResultUTRANValueCodecFieldEncode(v *ResultUTRANValueCodec) *func(ResultUTRAN, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultUTRANValueCodecFieldPath(v *ResultUTRANValueCodec) *q4.Path { return &v.path }
func BridgeResultUTRANValueCodecMethodEncodeBudget(v ResultUTRANValueCodec, a0 ResultUTRAN, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultUTRANValueCodecMethodEncodeChanged(v ResultUTRANValueCodec, a0 ResultUTRAN, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultsPerSSBIndexItemAPERValueFieldContext(v *ResultsPerSSBIndexItemAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeResultsPerSSBIndexItemAPERValueFieldReceived(v *ResultsPerSSBIndexItemAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeResultsPerSSBIndexItemAPERValueFieldReplay(v *ResultsPerSSBIndexItemAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeResultsPerSSBIndexItemAPERValueFieldWithoutReplay(v *ResultsPerSSBIndexItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultsPerSSBIndexItemFieldExtCount(v *ResultsPerSSBIndexItem) *int64   { return &v.extCount }
func BridgeResultsPerSSBIndexItemFieldExtData(v *ResultsPerSSBIndexItem) *[][]byte { return &v.extData }
func BridgeResultsPerSSBIndexItemFieldExtOrigin(v *ResultsPerSSBIndexItem) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeResultsPerSSBIndexItemFieldExtPresent(v *ResultsPerSSBIndexItem) *[]bool {
	return &v.extPresent
}
func BridgeResultsPerSSBIndexItemFieldExtWire(v *ResultsPerSSBIndexItem) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeResultsPerSSBIndexItemFieldIEExtensionsIndef(v *ResultsPerSSBIndexItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeResultsPerSSBIndexItemFieldPerExtPadding(v *ResultsPerSSBIndexItem) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeResultsPerSSBIndexItemFieldPerPadding(v *ResultsPerSSBIndexItem) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeResultsPerSSBIndexItemFieldReceived(v *ResultsPerSSBIndexItem) *bool { return &v.received }
func BridgeResultsPerSSBIndexItemFieldReceivedBytes(v *ResultsPerSSBIndexItem) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeResultsPerSSBIndexItemFieldReplay(v *ResultsPerSSBIndexItem) *q4.Snapshot {
	return &v.replay
}
func BridgeResultsPerSSBIndexItemFieldStream(v *ResultsPerSSBIndexItem) *q4.WireSpan {
	return &v.stream
}
func BridgeResultsPerSSBIndexItemFieldWithoutReplay(v *ResultsPerSSBIndexItem) *bool {
	return &v.withoutReplay
}
func BridgeResultsPerSSBIndexItemMethodMarshalAPERBudget(v *ResultsPerSSBIndexItem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultsPerSSBIndexItemMethodMarshalAPERChanged(v *ResultsPerSSBIndexItem, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultsPerSSBIndexItemMethodMarshalAPERChangedValue(v *ResultsPerSSBIndexItem, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultsPerSSBIndexItemMethodMarshalAPERFreshValue(v *ResultsPerSSBIndexItem, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultsPerSSBIndexItemMethodMarshalAPERLegacy(v *ResultsPerSSBIndexItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultsPerSSBIndexItemMethodMarshalAPERPlanned(v *ResultsPerSSBIndexItem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultsPerSSBIndexItemMethodMarshalAPERTo(v *ResultsPerSSBIndexItem, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultsPerSSBIndexItemMethodUnmarshalAPERFrom(v *ResultsPerSSBIndexItem, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultsPerSSBIndexItemMethodUnmarshalAPERLegacy(v *ResultsPerSSBIndexItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultsPerSSBIndexItemMethodUnmarshalAPERWithOptions(v *ResultsPerSSBIndexItem, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultsPerSSBIndexItemValueCodecFieldCapture(v *ResultsPerSSBIndexItemValueCodec) *func(ResultsPerSSBIndexItem, q4.DecodeState) (ResultsPerSSBIndexItem, q4.Snapshot) {
	return &v.capture
}
func BridgeResultsPerSSBIndexItemValueCodecFieldCompare(v *ResultsPerSSBIndexItemValueCodec) *func(ResultsPerSSBIndexItem, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeResultsPerSSBIndexItemValueCodecFieldContext(v *ResultsPerSSBIndexItemValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeResultsPerSSBIndexItemValueCodecFieldDecode(v *ResultsPerSSBIndexItemValueCodec) *func([]byte, q4.DecodeState) (ResultsPerSSBIndexItem, error) {
	return &v.decode
}
func BridgeResultsPerSSBIndexItemValueCodecFieldEncode(v *ResultsPerSSBIndexItemValueCodec) *func(ResultsPerSSBIndexItem, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultsPerSSBIndexItemValueCodecFieldPath(v *ResultsPerSSBIndexItemValueCodec) *q4.Path {
	return &v.path
}
func BridgeResultsPerSSBIndexItemValueCodecMethodEncodeBudget(v ResultsPerSSBIndexItemValueCodec, a0 ResultsPerSSBIndexItem, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultsPerSSBIndexItemValueCodecMethodEncodeChanged(v ResultsPerSSBIndexItemValueCodec, a0 ResultsPerSSBIndexItem, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultsPerSSBIndexListAPERValueFieldContext(v *ResultsPerSSBIndexListAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeResultsPerSSBIndexListAPERValueFieldReceived(v *ResultsPerSSBIndexListAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeResultsPerSSBIndexListAPERValueFieldReplay(v *ResultsPerSSBIndexListAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeResultsPerSSBIndexListAPERValueFieldWithoutReplay(v *ResultsPerSSBIndexListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultsPerSSBIndexListValueCodecFieldCapture(v *ResultsPerSSBIndexListValueCodec) *func(ResultsPerSSBIndexList, q4.DecodeState) (ResultsPerSSBIndexList, q4.Snapshot) {
	return &v.capture
}
func BridgeResultsPerSSBIndexListValueCodecFieldCompare(v *ResultsPerSSBIndexListValueCodec) *func(ResultsPerSSBIndexList, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeResultsPerSSBIndexListValueCodecFieldContext(v *ResultsPerSSBIndexListValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeResultsPerSSBIndexListValueCodecFieldDecode(v *ResultsPerSSBIndexListValueCodec) *func([]byte, q4.DecodeState) (ResultsPerSSBIndexList, error) {
	return &v.decode
}
func BridgeResultsPerSSBIndexListValueCodecFieldEncode(v *ResultsPerSSBIndexListValueCodec) *func(ResultsPerSSBIndexList, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultsPerSSBIndexListValueCodecFieldPath(v *ResultsPerSSBIndexListValueCodec) *q4.Path {
	return &v.path
}
func BridgeResultsPerSSBIndexListValueCodecMethodEncodeBudget(v ResultsPerSSBIndexListValueCodec, a0 ResultsPerSSBIndexList, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultsPerSSBIndexListValueCodecMethodEncodeChanged(v ResultsPerSSBIndexListValueCodec, a0 ResultsPerSSBIndexList, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSystemInformationAPERValueFieldContext(v *SystemInformationAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeSystemInformationAPERValueFieldReceived(v *SystemInformationAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeSystemInformationAPERValueFieldReplay(v *SystemInformationAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeSystemInformationAPERValueFieldWithoutReplay(v *SystemInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSystemInformationElemAPERValueFieldContext(v *SystemInformationElemAPERValue) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeSystemInformationElemAPERValueFieldReceived(v *SystemInformationElemAPERValue) *q4.WireSpan {
	return &v.received
}
func BridgeSystemInformationElemAPERValueFieldReplay(v *SystemInformationElemAPERValue) *q4.Snapshot {
	return &v.replay
}
func BridgeSystemInformationElemAPERValueFieldWithoutReplay(v *SystemInformationElemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSystemInformationElemFieldExtCount(v *SystemInformationElem) *int64   { return &v.extCount }
func BridgeSystemInformationElemFieldExtData(v *SystemInformationElem) *[][]byte { return &v.extData }
func BridgeSystemInformationElemFieldExtOrigin(v *SystemInformationElem) *[]q4.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeSystemInformationElemFieldExtPresent(v *SystemInformationElem) *[]bool {
	return &v.extPresent
}
func BridgeSystemInformationElemFieldExtWire(v *SystemInformationElem) *[]q4.WireSpan {
	return &v.extWire
}
func BridgeSystemInformationElemFieldIEExtensionsIndef(v *SystemInformationElem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeSystemInformationElemFieldPerExtPadding(v *SystemInformationElem) *[]q4.CompletePadding {
	return &v.perExtPadding
}
func BridgeSystemInformationElemFieldPerPadding(v *SystemInformationElem) *q4.FinalPadding {
	return &v.perPadding
}
func BridgeSystemInformationElemFieldPosSIBsIndef(v *SystemInformationElem) *bool {
	return &v.posSIBsIndef
}
func BridgeSystemInformationElemFieldReceived(v *SystemInformationElem) *bool { return &v.received }
func BridgeSystemInformationElemFieldReceivedBytes(v *SystemInformationElem) *q4.WireSpan {
	return &v.receivedBytes
}
func BridgeSystemInformationElemFieldReplay(v *SystemInformationElem) *q4.Snapshot { return &v.replay }
func BridgeSystemInformationElemFieldStream(v *SystemInformationElem) *q4.WireSpan { return &v.stream }
func BridgeSystemInformationElemFieldWithoutReplay(v *SystemInformationElem) *bool {
	return &v.withoutReplay
}
func BridgeSystemInformationElemMethodMarshalAPERBudget(v *SystemInformationElem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSystemInformationElemMethodMarshalAPERChanged(v *SystemInformationElem, a0 *q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSystemInformationElemMethodMarshalAPERChangedValue(v *SystemInformationElem, a0 q4.DecodeBudget, a1 bool, a2 q4.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSystemInformationElemMethodMarshalAPERFreshValue(v *SystemInformationElem, a0 q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeSystemInformationElemMethodMarshalAPERLegacy(v *SystemInformationElem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSystemInformationElemMethodMarshalAPERPlanned(v *SystemInformationElem, a0 *q4.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeSystemInformationElemMethodMarshalAPERTo(v *SystemInformationElem, a0 *q4.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSystemInformationElemMethodUnmarshalAPERFrom(v *SystemInformationElem, a0 *q4.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSystemInformationElemMethodUnmarshalAPERLegacy(v *SystemInformationElem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSystemInformationElemMethodUnmarshalAPERWithOptions(v *SystemInformationElem, a0 []byte, a1 q4.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSystemInformationElemValueCodecFieldCapture(v *SystemInformationElemValueCodec) *func(SystemInformationElem, q4.DecodeState) (SystemInformationElem, q4.Snapshot) {
	return &v.capture
}
func BridgeSystemInformationElemValueCodecFieldCompare(v *SystemInformationElemValueCodec) *func(SystemInformationElem, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeSystemInformationElemValueCodecFieldContext(v *SystemInformationElemValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeSystemInformationElemValueCodecFieldDecode(v *SystemInformationElemValueCodec) *func([]byte, q4.DecodeState) (SystemInformationElem, error) {
	return &v.decode
}
func BridgeSystemInformationElemValueCodecFieldEncode(v *SystemInformationElemValueCodec) *func(SystemInformationElem, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSystemInformationElemValueCodecFieldPath(v *SystemInformationElemValueCodec) *q4.Path {
	return &v.path
}
func BridgeSystemInformationElemValueCodecMethodEncodeBudget(v SystemInformationElemValueCodec, a0 SystemInformationElem, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSystemInformationElemValueCodecMethodEncodeChanged(v SystemInformationElemValueCodec, a0 SystemInformationElem, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSystemInformationValueCodecFieldCapture(v *SystemInformationValueCodec) *func(SystemInformation, q4.DecodeState) (SystemInformation, q4.Snapshot) {
	return &v.capture
}
func BridgeSystemInformationValueCodecFieldCompare(v *SystemInformationValueCodec) *func(SystemInformation, q4.Snapshot, q4.ComparisonLimits) q4.ReplayPlan {
	return &v.compare
}
func BridgeSystemInformationValueCodecFieldContext(v *SystemInformationValueCodec) *q5.BridgeCodecContext {
	return &v.context
}
func BridgeSystemInformationValueCodecFieldDecode(v *SystemInformationValueCodec) *func([]byte, q4.DecodeState) (SystemInformation, error) {
	return &v.decode
}
func BridgeSystemInformationValueCodecFieldEncode(v *SystemInformationValueCodec) *func(SystemInformation, bool, *q4.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSystemInformationValueCodecFieldPath(v *SystemInformationValueCodec) *q4.Path {
	return &v.path
}
func BridgeSystemInformationValueCodecMethodEncodeBudget(v SystemInformationValueCodec, a0 SystemInformation, a1 bool, a2 q4.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSystemInformationValueCodecMethodEncodeChanged(v SystemInformationValueCodec, a0 SystemInformation, a1 bool, a2 q4.ReplayPlan, a3 q4.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
