// Code generated from the pinned S1AP source closure. DO NOT EDIT.

// Package s49 implements the github.com/gomaja/go-asn1/telecom/lte/s1ap root package.
package s49

import (
	fmt "fmt"
	s00 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s00"
	s01 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s01"
	s02 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s02"
	s06 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s06"
	s07 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s07"
	s12 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s12"
	s13 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s13"
	s14 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s14"
	s18 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s18"
	s19 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s19"
	s20 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s20"
	s21 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s21"
	s24 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s24"
	s26 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s26"
	s27 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s27"
	s29 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s29"
	s30 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s30"
	s31 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s31"
	s36 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s36"
	s37 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s37"
	s38 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s38"
	s41 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s41"
	s42 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s42"
	s43 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s43"
	s47 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s47"
	s48 "github.com/gomaja/go-asn1/telecom/lte/s1ap/internal/s48"
	runtime "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime"
	aper "github.com/gomaja/go-asn1/telecom/lte/s1ap/runtime/aper"
)

// InitialContextSetupRequestIEContainer is ProtocolIE-Container {{InitialContextSetupRequestIEs}} of TS 36.413: a list of InitialContextSetupRequestIEField values.
type InitialContextSetupRequestIEContainer []InitialContextSetupRequestIEField

// InitialContextSetupRequestIEField is ProtocolIE-Field {{InitialContextSetupRequestIEs}} of TS 36.413: an information element field.
type InitialContextSetupRequestIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         InitialContextSetupRequestIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupRequestIEField) WithoutReplay() InitialContextSetupRequestIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *InitialContextSetupRequestIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *InitialContextSetupRequestIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	// TS 36.413 V19.2.0 §9.3.7 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *InitialContextSetupRequestIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InitialContextSetupRequestIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero InitialContextSetupRequestIEValue

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

	return nil
}

// TraceStartIEContainer is ProtocolIE-Container {{TraceStartIEs}} of TS 36.413: a list of TraceStartIEField values.
type TraceStartIEContainer []TraceStartIEField

// TraceStartIEField is ProtocolIE-Field {{TraceStartIEs}} of TS 36.413: an information element field.
type TraceStartIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         TraceStartIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceStartIEField) WithoutReplay() TraceStartIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, if one is available.
func (v *TraceStartIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}

// MarshalAPERTo appends the field encoding to the supplied APER buffer.
func (v *TraceStartIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.stream.ReplayTo(bb); ok || err !=
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
	// TS 36.413 V19.2.0 §9.3.7 binds the table-selected value to @id.
	if !v.Value.matchesID(v.Id, bb.Budget()) {
		return runtime.WrapDecodePath(fmt.Errorf("%w: field id %d does not match its value selector", aper.ErrInvalidValue, v.Id), "ProtocolIEField.Id")
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.Id), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false); err != nil {
		return fmt.Errorf("encoding id: %w", err)
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.Criticality), 3, false); err != nil {
		return fmt.Errorf("encoding criticality: %w", err)
	}
	data, err := v.Value.encodeFresh(len(fresh) != 0 && fresh[0], bb.Budget())
	if err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	if err := aper.EncodeOpenTypeAligned(bb, data); err != nil {
		return fmt.Errorf("encoding value: %w", err)
	}
	return nil
}

// UnmarshalAPERFrom decodes the field from the supplied APER buffer.
func (v *TraceStartIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TraceStartIEField{}
	id, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(65535), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Id")
	}
	v.Id = s00.ProtocolIEID(id)
	criticality, err := aper.DecodeEnumeratedAligned(bb, 3, false)
	if err != nil {
		return runtime.WrapDecodePath(err, "Criticality")
	}
	v.Criticality = s00.Criticality(criticality)
	var zero TraceStartIEValue

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

	return nil
}
func BridgeHandoverRequestIEValueCaptureS1APProtocolIEContainer(v *s48.HandoverRequestIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverRequestIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverRequestIEValueCompareS1APProtocolIEContainer(v *s48.HandoverRequestIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverRequestIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeInitialContextSetupRequestIEValueCaptureS1APProtocolIEContainer(v *InitialContextSetupRequestIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeInitialContextSetupRequestIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeInitialContextSetupRequestIEValueCompareS1APProtocolIEContainer(v *InitialContextSetupRequestIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeInitialContextSetupRequestIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeTraceStartIEValueCaptureS1APProtocolIEContainer(v *TraceStartIEContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTraceStartIEValueCaptureS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTraceStartIEValueCompareS1APProtocolIEContainer(v *TraceStartIEContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTraceStartIEValueCompareS1APProtocolIEField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeWUSAssistanceInformationExtIEsValueCaptureS1APProtocolExtensionContainer(v *s12.WUSAssistanceInformationExtIEsExtContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWUSAssistanceInformationExtIEsValueCaptureS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeWUSAssistanceInformationExtIEsValueCompareS1APProtocolExtensionContainer(v *s12.WUSAssistanceInformationExtIEsExtContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeWUSAssistanceInformationExtIEsValueCompareS1APProtocolExtensionField(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// HandoverRequestTraceActivationIEBinding binds TraceActivation to the HandoverRequestIEs object set of TS 36.413.
type HandoverRequestTraceActivationIEBinding struct {
	info   s00.FieldInfo
	codec  TraceActivationValueCodec
	inject func(s48.TraceActivation,

	) s48.HandoverRequestIEValue

	get func(*s48.HandoverRequestIEValue,

	) (*s48.TraceActivation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b HandoverRequestTraceActivationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b HandoverRequestTraceActivationIEBinding) Codec() TraceActivationValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b HandoverRequestTraceActivationIEBinding) New(value s48.TraceActivation,

) (s48.HandoverRequestIEField, error) {
	if b.inject == nil {
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return s48.HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return s48.HandoverRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return s48.HandoverRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b HandoverRequestTraceActivationIEBinding) Get(field *s48.HandoverRequestIEField) (*s48.TraceActivation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// TraceActivationValueCodec is the concrete ValueCodec[TraceActivation].
type TraceActivationValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (s48.TraceActivation,

		error)
	encode func(s48.TraceActivation,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(s48.TraceActivation, aper.DecodeState,

	) (s48.TraceActivation, aper.Snapshot,

	)
	compare func(s48.TraceActivation, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TraceActivationValueCodec) New(value s48.TraceActivation,

) (TraceActivationAPERValue, error) {
	if c.encode == nil {
		return TraceActivationAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceActivationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TraceActivationAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TraceActivationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TraceActivationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TraceActivationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TraceActivationAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TraceActivationAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TraceActivationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TraceActivationAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TraceActivationValueCodec) EncodeAPER(value TraceActivationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TraceActivationValueCodec) encodeBudgetValue(value s48.TraceActivation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TraceActivationValueCodec) encodeChanged(value s48.TraceActivation,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialContextSetupRequestMMEUES1APIDIEBinding binds MMEUES1APID to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestMMEUES1APIDIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestENBUES1APIDIEBinding binds ENBUES1APID to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestENBUES1APIDIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestUEAggregateMaximumBitrateIEBinding binds UEAggregateMaximumBitrate to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestUEAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s36.UEAggregateMaximumBitrateValueCodec
	inject func(s36.UEAggregateMaximumBitrate,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s36.UEAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestUEAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestUEAggregateMaximumBitrateIEBinding) Codec() s36.UEAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestUEAggregateMaximumBitrateIEBinding) New(value s36.UEAggregateMaximumBitrate,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s36.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestUEAggregateMaximumBitrateIEBinding) Get(field *InitialContextSetupRequestIEField) (*s36.UEAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestERABToBeSetupListCtxtSUReqIEBinding binds ERABToBeSetupListCtxtSUReq to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestERABToBeSetupListCtxtSUReqIEBinding struct {
	info   s00.FieldInfo
	codec  s30.ERABToBeSetupListCtxtSUReqValueCodec
	inject func(s30.ERABToBeSetupListCtxtSUReq,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s30.ERABToBeSetupListCtxtSUReq,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestERABToBeSetupListCtxtSUReqIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestERABToBeSetupListCtxtSUReqIEBinding) Codec() s30.ERABToBeSetupListCtxtSUReqValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestERABToBeSetupListCtxtSUReqIEBinding) New(value s30.ERABToBeSetupListCtxtSUReq,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s30.BridgeERABToBeSetupListCtxtSUReqValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestERABToBeSetupListCtxtSUReqIEBinding) Get(field *InitialContextSetupRequestIEField) (*s30.ERABToBeSetupListCtxtSUReq,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestUESecurityCapabilitiesIEBinding binds UESecurityCapabilities to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestUESecurityCapabilitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s37.UESecurityCapabilitiesValueCodec
	inject func(s37.UESecurityCapabilities,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s37.UESecurityCapabilities,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestUESecurityCapabilitiesIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestUESecurityCapabilitiesIEBinding) Codec() s37.UESecurityCapabilitiesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestUESecurityCapabilitiesIEBinding) New(value s37.UESecurityCapabilities,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s37.BridgeUESecurityCapabilitiesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestUESecurityCapabilitiesIEBinding) Get(field *InitialContextSetupRequestIEField) (*s37.UESecurityCapabilities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestSecurityKeyIEBinding binds SecurityKey to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestSecurityKeyIEBinding struct {
	info   s00.FieldInfo
	codec  s01.SecurityKeyValueCodec
	inject func(s00.SecurityKey,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.SecurityKey,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestSecurityKeyIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestSecurityKeyIEBinding) Codec() s01.SecurityKeyValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestSecurityKeyIEBinding) New(value s00.SecurityKey,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeSecurityKeyValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestSecurityKeyIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.SecurityKey,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestTraceActivationIEBinding binds TraceActivation to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestTraceActivationIEBinding struct {
	info   s00.FieldInfo
	codec  TraceActivationValueCodec
	inject func(s48.TraceActivation,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s48.TraceActivation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestTraceActivationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestTraceActivationIEBinding) Codec() TraceActivationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestTraceActivationIEBinding) New(value s48.TraceActivation,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestTraceActivationIEBinding) Get(field *InitialContextSetupRequestIEField) (*s48.TraceActivation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestHandoverRestrictionListIEBinding binds HandoverRestrictionList to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestHandoverRestrictionListIEBinding struct {
	info   s00.FieldInfo
	codec  s43.HandoverRestrictionListValueCodec
	inject func(s43.HandoverRestrictionList,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s43.HandoverRestrictionList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestHandoverRestrictionListIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestHandoverRestrictionListIEBinding) Codec() s43.HandoverRestrictionListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestHandoverRestrictionListIEBinding) New(value s43.HandoverRestrictionList,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s43.BridgeHandoverRestrictionListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestHandoverRestrictionListIEBinding) Get(field *InitialContextSetupRequestIEField) (*s43.HandoverRestrictionList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestUERadioCapabilityIEBinding binds UERadioCapability to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestUERadioCapabilityIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityValueCodec
	inject func(s00.UERadioCapability,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.UERadioCapability,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestUERadioCapabilityIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestUERadioCapabilityIEBinding) Codec() s02.UERadioCapabilityValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestUERadioCapabilityIEBinding) New(value s00.UERadioCapability,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestUERadioCapabilityIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.UERadioCapability,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestSubscriberProfileIDforRFPIEBinding binds SubscriberProfileIDforRFP to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestSubscriberProfileIDforRFPIEBinding struct {
	info   s00.FieldInfo
	codec  s01.SubscriberProfileIDforRFPValueCodec
	inject func(s00.SubscriberProfileIDforRFP,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.SubscriberProfileIDforRFP,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestSubscriberProfileIDforRFPIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestSubscriberProfileIDforRFPIEBinding) Codec() s01.SubscriberProfileIDforRFPValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestSubscriberProfileIDforRFPIEBinding) New(value s00.SubscriberProfileIDforRFP,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestSubscriberProfileIDforRFPIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.SubscriberProfileIDforRFP,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestCSFallbackIndicatorIEBinding binds CSFallbackIndicator to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestCSFallbackIndicatorIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CSFallbackIndicatorValueCodec
	inject func(s00.CSFallbackIndicator,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.CSFallbackIndicator,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestCSFallbackIndicatorIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestCSFallbackIndicatorIEBinding) Codec() s00.CSFallbackIndicatorValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestCSFallbackIndicatorIEBinding) New(value s00.CSFallbackIndicator,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCSFallbackIndicatorValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestCSFallbackIndicatorIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.CSFallbackIndicator,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestSRVCCOperationPossibleIEBinding binds SRVCCOperationPossible to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestSRVCCOperationPossibleIEBinding struct {
	info   s00.FieldInfo
	codec  s01.SRVCCOperationPossibleValueCodec
	inject func(s00.SRVCCOperationPossible,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.SRVCCOperationPossible,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestSRVCCOperationPossibleIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestSRVCCOperationPossibleIEBinding) Codec() s01.SRVCCOperationPossibleValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestSRVCCOperationPossibleIEBinding) New(value s00.SRVCCOperationPossible,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeSRVCCOperationPossibleValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestSRVCCOperationPossibleIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.SRVCCOperationPossible,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestCSGMembershipStatusIEBinding binds CSGMembershipStatus to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestCSGMembershipStatusIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CSGMembershipStatusValueCodec
	inject func(s00.CSGMembershipStatus,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.CSGMembershipStatus,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestCSGMembershipStatusIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestCSGMembershipStatusIEBinding) Codec() s00.CSGMembershipStatusValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestCSGMembershipStatusIEBinding) New(value s00.CSGMembershipStatus,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestCSGMembershipStatusIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.CSGMembershipStatus,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestLAIIEBinding binds LAI to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestLAIIEBinding struct {
	info   s00.FieldInfo
	codec  s18.LAIValueCodec
	inject func(s18.LAI,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s18.LAI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestLAIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestLAIIEBinding) Codec() s18.LAIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestLAIIEBinding) New(value s18.LAI,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeLAIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestLAIIEBinding) Get(field *InitialContextSetupRequestIEField) (*s18.LAI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestGUMMEIIEBinding binds GUMMEI to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestGUMMEIIEBinding struct {
	info   s00.FieldInfo
	codec  s18.GUMMEIValueCodec
	inject func(s18.GUMMEI,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s18.GUMMEI,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestGUMMEIIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestGUMMEIIEBinding) Codec() s18.GUMMEIValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestGUMMEIIEBinding) New(value s18.GUMMEI,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeGUMMEIValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestGUMMEIIEBinding) Get(field *InitialContextSetupRequestIEField) (*s18.GUMMEI,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestManagementBasedMDTAllowedIEBinding binds ManagementBasedMDTAllowed to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestManagementBasedMDTAllowedIEBinding struct {
	info   s00.FieldInfo
	codec  s01.ManagementBasedMDTAllowedValueCodec
	inject func(s00.ManagementBasedMDTAllowed,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.ManagementBasedMDTAllowed,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestManagementBasedMDTAllowedIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestManagementBasedMDTAllowedIEBinding) Codec() s01.ManagementBasedMDTAllowedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestManagementBasedMDTAllowedIEBinding) New(value s00.ManagementBasedMDTAllowed,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeManagementBasedMDTAllowedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestManagementBasedMDTAllowedIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.ManagementBasedMDTAllowed,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestMDTPLMNListIEBinding binds MDTPLMNList to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestMDTPLMNListIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MDTPLMNListValueCodec
	inject func(s00.MDTPLMNList,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.MDTPLMNList,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestMDTPLMNListIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestMDTPLMNListIEBinding) Codec() s01.MDTPLMNListValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestMDTPLMNListIEBinding) New(value s00.MDTPLMNList,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMDTPLMNListValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestMDTPLMNListIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.MDTPLMNList,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestAdditionalCSFallbackIndicatorIEBinding binds AdditionalCSFallbackIndicator to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestAdditionalCSFallbackIndicatorIEBinding struct {
	info   s00.FieldInfo
	codec  s00.AdditionalCSFallbackIndicatorValueCodec
	inject func(s00.AdditionalCSFallbackIndicator,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.AdditionalCSFallbackIndicator,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestAdditionalCSFallbackIndicatorIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestAdditionalCSFallbackIndicatorIEBinding) Codec() s00.AdditionalCSFallbackIndicatorValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestAdditionalCSFallbackIndicatorIEBinding) New(value s00.AdditionalCSFallbackIndicator,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestAdditionalCSFallbackIndicatorIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.AdditionalCSFallbackIndicator,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestMaskedIMEISVIEBinding binds MaskedIMEISV to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestMaskedIMEISVIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MaskedIMEISVValueCodec
	inject func(s00.MaskedIMEISV,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.MaskedIMEISV,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestMaskedIMEISVIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestMaskedIMEISVIEBinding) Codec() s01.MaskedIMEISVValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestMaskedIMEISVIEBinding) New(value s00.MaskedIMEISV,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMaskedIMEISVValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestMaskedIMEISVIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.MaskedIMEISV,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestExpectedUEBehaviourIEBinding binds ExpectedUEBehaviour to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestExpectedUEBehaviourIEBinding struct {
	info   s00.FieldInfo
	codec  s18.ExpectedUEBehaviourValueCodec
	inject func(s18.ExpectedUEBehaviour,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s18.ExpectedUEBehaviour,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestExpectedUEBehaviourIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestExpectedUEBehaviourIEBinding) Codec() s18.ExpectedUEBehaviourValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestExpectedUEBehaviourIEBinding) New(value s18.ExpectedUEBehaviour,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s18.BridgeExpectedUEBehaviourValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestExpectedUEBehaviourIEBinding) Get(field *InitialContextSetupRequestIEField) (*s18.ExpectedUEBehaviour,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestProSeAuthorizedIEBinding binds ProSeAuthorized to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestProSeAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  s20.ProSeAuthorizedValueCodec
	inject func(s20.ProSeAuthorized,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s20.ProSeAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestProSeAuthorizedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestProSeAuthorizedIEBinding) Codec() s20.ProSeAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestProSeAuthorizedIEBinding) New(value s20.ProSeAuthorized,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgeProSeAuthorizedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestProSeAuthorizedIEBinding) Get(field *InitialContextSetupRequestIEField) (*s20.ProSeAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestUEUserPlaneCIoTSupportIndicatorIEBinding binds UEUserPlaneCIoTSupportIndicator to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestUEUserPlaneCIoTSupportIndicatorIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UEUserPlaneCIoTSupportIndicatorValueCodec
	inject func(s00.UEUserPlaneCIoTSupportIndicator,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.UEUserPlaneCIoTSupportIndicator,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestUEUserPlaneCIoTSupportIndicatorIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestUEUserPlaneCIoTSupportIndicatorIEBinding) Codec() s02.UEUserPlaneCIoTSupportIndicatorValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestUEUserPlaneCIoTSupportIndicatorIEBinding) New(value s00.UEUserPlaneCIoTSupportIndicator,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestUEUserPlaneCIoTSupportIndicatorIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.UEUserPlaneCIoTSupportIndicator,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestV2XServicesAuthorizedIEBinding binds V2XServicesAuthorized to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestV2XServicesAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  s47.V2XServicesAuthorizedValueCodec
	inject func(s47.V2XServicesAuthorized,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s47.V2XServicesAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestV2XServicesAuthorizedIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestV2XServicesAuthorizedIEBinding) Codec() s47.V2XServicesAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestV2XServicesAuthorizedIEBinding) New(value s47.V2XServicesAuthorized,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s47.BridgeV2XServicesAuthorizedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestV2XServicesAuthorizedIEBinding) Get(field *InitialContextSetupRequestIEField) (*s47.V2XServicesAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestUESidelinkAggregateMaximumBitrateIEBinding binds UESidelinkAggregateMaximumBitrate to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestUESidelinkAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s38.UESidelinkAggregateMaximumBitrateValueCodec
	inject func(s38.UESidelinkAggregateMaximumBitrate,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s38.UESidelinkAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestUESidelinkAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestUESidelinkAggregateMaximumBitrateIEBinding) Codec() s38.UESidelinkAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestUESidelinkAggregateMaximumBitrateIEBinding) New(value s38.UESidelinkAggregateMaximumBitrate,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s38.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestUESidelinkAggregateMaximumBitrateIEBinding) Get(field *InitialContextSetupRequestIEField) (*s38.UESidelinkAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestEnhancedCoverageRestrictedIEBinding binds EnhancedCoverageRestricted to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestEnhancedCoverageRestrictedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.EnhancedCoverageRestrictedValueCodec
	inject func(s00.EnhancedCoverageRestricted,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.EnhancedCoverageRestricted,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestEnhancedCoverageRestrictedIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestEnhancedCoverageRestrictedIEBinding) Codec() s00.EnhancedCoverageRestrictedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestEnhancedCoverageRestrictedIEBinding) New(value s00.EnhancedCoverageRestricted,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestEnhancedCoverageRestrictedIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.EnhancedCoverageRestricted,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestNRUESecurityCapabilitiesIEBinding binds NRUESecurityCapabilities to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestNRUESecurityCapabilitiesIEBinding struct {
	info   s00.FieldInfo
	codec  s19.NRUESecurityCapabilitiesValueCodec
	inject func(s19.NRUESecurityCapabilities,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s19.NRUESecurityCapabilities,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestNRUESecurityCapabilitiesIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestNRUESecurityCapabilitiesIEBinding) Codec() s19.NRUESecurityCapabilitiesValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestNRUESecurityCapabilitiesIEBinding) New(value s19.NRUESecurityCapabilities,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestNRUESecurityCapabilitiesIEBinding) Get(field *InitialContextSetupRequestIEField) (*s19.NRUESecurityCapabilities,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestCEModeBRestrictedIEBinding binds CEModeBRestricted to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestCEModeBRestrictedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CEModeBRestrictedValueCodec
	inject func(s00.CEModeBRestricted,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.CEModeBRestricted,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestCEModeBRestrictedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestCEModeBRestrictedIEBinding) Codec() s00.CEModeBRestrictedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestCEModeBRestrictedIEBinding) New(value s00.CEModeBRestricted,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCEModeBRestrictedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestCEModeBRestrictedIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.CEModeBRestricted,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestAerialUEsubscriptionInformationIEBinding binds AerialUEsubscriptionInformation to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestAerialUEsubscriptionInformationIEBinding struct {
	info   s00.FieldInfo
	codec  s00.AerialUEsubscriptionInformationValueCodec
	inject func(s00.AerialUEsubscriptionInformation,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.AerialUEsubscriptionInformation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestAerialUEsubscriptionInformationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestAerialUEsubscriptionInformationIEBinding) Codec() s00.AerialUEsubscriptionInformationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestAerialUEsubscriptionInformationIEBinding) New(value s00.AerialUEsubscriptionInformation,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestAerialUEsubscriptionInformationIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.AerialUEsubscriptionInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestPendingDataIndicationIEBinding binds PendingDataIndication to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestPendingDataIndicationIEBinding struct {
	info   s00.FieldInfo
	codec  s01.PendingDataIndicationValueCodec
	inject func(s00.PendingDataIndication,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.PendingDataIndication,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestPendingDataIndicationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestPendingDataIndicationIEBinding) Codec() s01.PendingDataIndicationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestPendingDataIndicationIEBinding) New(value s00.PendingDataIndication,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgePendingDataIndicationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestPendingDataIndicationIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.PendingDataIndication,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestSubscriptionBasedUEDifferentiationInfoIEBinding binds SubscriptionBasedUEDifferentiationInfo to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestSubscriptionBasedUEDifferentiationInfoIEBinding struct {
	info   s00.FieldInfo
	codec  s31.SubscriptionBasedUEDifferentiationInfoValueCodec
	inject func(s31.SubscriptionBasedUEDifferentiationInfo,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s31.SubscriptionBasedUEDifferentiationInfo,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestSubscriptionBasedUEDifferentiationInfoIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestSubscriptionBasedUEDifferentiationInfoIEBinding) Codec() s31.SubscriptionBasedUEDifferentiationInfoValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestSubscriptionBasedUEDifferentiationInfoIEBinding) New(value s31.SubscriptionBasedUEDifferentiationInfo,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestSubscriptionBasedUEDifferentiationInfoIEBinding) Get(field *InitialContextSetupRequestIEField) (*s31.SubscriptionBasedUEDifferentiationInfo,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestAdditionalRRMPriorityIndexIEBinding binds AdditionalRRMPriorityIndex to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestAdditionalRRMPriorityIndexIEBinding struct {
	info   s00.FieldInfo
	codec  s00.AdditionalRRMPriorityIndexValueCodec
	inject func(s00.AdditionalRRMPriorityIndex,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.AdditionalRRMPriorityIndex,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestAdditionalRRMPriorityIndexIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestAdditionalRRMPriorityIndexIEBinding) Codec() s00.AdditionalRRMPriorityIndexValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestAdditionalRRMPriorityIndexIEBinding) New(value s00.AdditionalRRMPriorityIndex,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestAdditionalRRMPriorityIndexIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.AdditionalRRMPriorityIndex,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestIABAuthorizedIEBinding binds IABAuthorized to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestIABAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  s00.IABAuthorizedValueCodec
	inject func(s00.IABAuthorized,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.IABAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestIABAuthorizedIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestIABAuthorizedIEBinding) Codec() s00.IABAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestIABAuthorizedIEBinding) New(value s00.IABAuthorized,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeIABAuthorizedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestIABAuthorizedIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.IABAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestNRV2XServicesAuthorizedIEBinding binds NRV2XServicesAuthorized to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestNRV2XServicesAuthorizedIEBinding struct {
	info   s00.FieldInfo
	codec  s20.NRV2XServicesAuthorizedValueCodec
	inject func(s20.NRV2XServicesAuthorized,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s20.NRV2XServicesAuthorized,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestNRV2XServicesAuthorizedIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestNRV2XServicesAuthorizedIEBinding) Codec() s20.NRV2XServicesAuthorizedValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestNRV2XServicesAuthorizedIEBinding) New(value s20.NRV2XServicesAuthorized,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgeNRV2XServicesAuthorizedValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestNRV2XServicesAuthorizedIEBinding) Get(field *InitialContextSetupRequestIEField) (*s20.NRV2XServicesAuthorized,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestNRUESidelinkAggregateMaximumBitrateIEBinding binds NRUESidelinkAggregateMaximumBitrate to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestNRUESidelinkAggregateMaximumBitrateIEBinding struct {
	info   s00.FieldInfo
	codec  s20.NRUESidelinkAggregateMaximumBitrateValueCodec
	inject func(s20.NRUESidelinkAggregateMaximumBitrate,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s20.NRUESidelinkAggregateMaximumBitrate,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestNRUESidelinkAggregateMaximumBitrateIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestNRUESidelinkAggregateMaximumBitrateIEBinding) Codec() s20.NRUESidelinkAggregateMaximumBitrateValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestNRUESidelinkAggregateMaximumBitrateIEBinding) New(value s20.NRUESidelinkAggregateMaximumBitrate,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s20.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestNRUESidelinkAggregateMaximumBitrateIEBinding) Get(field *InitialContextSetupRequestIEField) (*s20.NRUESidelinkAggregateMaximumBitrate,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestPC5QoSParametersIEBinding binds PC5QoSParameters to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestPC5QoSParametersIEBinding struct {
	info   s00.FieldInfo
	codec  s24.PC5QoSParametersValueCodec
	inject func(s24.PC5QoSParameters,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s24.PC5QoSParameters,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestPC5QoSParametersIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestPC5QoSParametersIEBinding) Codec() s24.PC5QoSParametersValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestPC5QoSParametersIEBinding) New(value s24.PC5QoSParameters,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s24.BridgePC5QoSParametersValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestPC5QoSParametersIEBinding) Get(field *InitialContextSetupRequestIEField) (*s24.PC5QoSParameters,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestUERadioCapabilityIDIEBinding binds UERadioCapabilityID to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestUERadioCapabilityIDIEBinding struct {
	info   s00.FieldInfo
	codec  s02.UERadioCapabilityIDValueCodec
	inject func(s00.UERadioCapabilityID,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.UERadioCapabilityID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestUERadioCapabilityIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestUERadioCapabilityIDIEBinding) Codec() s02.UERadioCapabilityIDValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestUERadioCapabilityIDIEBinding) New(value s00.UERadioCapabilityID,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestUERadioCapabilityIDIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.UERadioCapabilityID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestCoarseUELocationIEBinding binds CoarseUELocation to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestCoarseUELocationIEBinding struct {
	info   s00.FieldInfo
	codec  s00.CoarseUELocationValueCodec
	inject func(s00.CoarseUELocation,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.CoarseUELocation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestCoarseUELocationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestCoarseUELocationIEBinding) Codec() s00.CoarseUELocationValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestCoarseUELocationIEBinding) New(value s00.CoarseUELocation,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeCoarseUELocationValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestCoarseUELocationIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.CoarseUELocation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// InitialContextSetupRequestTimeRefDistributionIEBinding binds TimeRefDistribution to the InitialContextSetupRequestIEs object set of TS 36.413.
type InitialContextSetupRequestTimeRefDistributionIEBinding struct {
	info   s00.FieldInfo
	codec  s02.TimeRefDistributionValueCodec
	inject func(s00.TimeRefDistribution,

	) InitialContextSetupRequestIEValue

	get func(*InitialContextSetupRequestIEValue,

	) (*s00.TimeRefDistribution,

		bool)
}

// Info returns the source descriptor for this binding.
func (b InitialContextSetupRequestTimeRefDistributionIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b InitialContextSetupRequestTimeRefDistributionIEBinding) Codec() s02.TimeRefDistributionValueCodec {
	return b.codec
}

// New validates a source value and constructs its bound field.
func (b InitialContextSetupRequestTimeRefDistributionIEBinding) New(value s00.TimeRefDistribution,

) (InitialContextSetupRequestIEField, error) {
	if b.inject == nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s02.BridgeTimeRefDistributionValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Value.New")
	}
	return InitialContextSetupRequestIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b InitialContextSetupRequestTimeRefDistributionIEBinding) Get(field *InitialContextSetupRequestIEField) (*s00.TimeRefDistribution,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// TraceStartMMEUES1APIDIEBinding binds MMEUES1APID to the TraceStartIEs object set of TS 36.413.
type TraceStartMMEUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s01.MMEUES1APIDValueCodec
	inject func(s00.MMEUES1APID,

	) TraceStartIEValue

	get func(*TraceStartIEValue,

	) (*s00.MMEUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b TraceStartMMEUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b TraceStartMMEUES1APIDIEBinding) Codec() s01.MMEUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b TraceStartMMEUES1APIDIEBinding) New(value s00.MMEUES1APID,

) (TraceStartIEField, error) {
	if b.inject == nil {
		return TraceStartIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceStartIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return TraceStartIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return TraceStartIEField{}, aper.OperationError(err, "Value.New")
	}
	return TraceStartIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b TraceStartMMEUES1APIDIEBinding) Get(field *TraceStartIEField) (*s00.MMEUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// TraceStartENBUES1APIDIEBinding binds ENBUES1APID to the TraceStartIEs object set of TS 36.413.
type TraceStartENBUES1APIDIEBinding struct {
	info   s00.FieldInfo
	codec  s00.ENBUES1APIDValueCodec
	inject func(s00.ENBUES1APID,

	) TraceStartIEValue

	get func(*TraceStartIEValue,

	) (*s00.ENBUES1APID,

		bool)
}

// Info returns the source descriptor for this binding.
func (b TraceStartENBUES1APIDIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b TraceStartENBUES1APIDIEBinding) Codec() s00.ENBUES1APIDValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b TraceStartENBUES1APIDIEBinding) New(value s00.ENBUES1APID,

) (TraceStartIEField, error) {
	if b.inject == nil {
		return TraceStartIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceStartIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeENBUES1APIDValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return TraceStartIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return TraceStartIEField{}, aper.OperationError(err, "Value.New")
	}
	return TraceStartIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b TraceStartENBUES1APIDIEBinding) Get(field *TraceStartIEField) (*s00.ENBUES1APID,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// TraceStartTraceActivationIEBinding binds TraceActivation to the TraceStartIEs object set of TS 36.413.
type TraceStartTraceActivationIEBinding struct {
	info   s00.FieldInfo
	codec  TraceActivationValueCodec
	inject func(s48.TraceActivation,

	) TraceStartIEValue

	get func(*TraceStartIEValue,

	) (*s48.TraceActivation,

		bool)
}

// Info returns the source descriptor for this binding.
func (b TraceStartTraceActivationIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete value codec for this binding.
func (b TraceStartTraceActivationIEBinding) Codec() TraceActivationValueCodec { return b.codec }

// New validates a source value and constructs its bound field.
func (b TraceStartTraceActivationIEBinding) New(value s48.TraceActivation,

) (TraceStartIEField, error) {
	if b.inject == nil {
		return TraceStartIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceStartIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return TraceStartIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return TraceStartIEField{}, aper.OperationError(err, "Value.New")
	}
	return TraceStartIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field matches this binding.
func (b TraceStartTraceActivationIEBinding) Get(field *TraceStartIEField) (*s48.TraceActivation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// HandoverRequestValueCodec is the concrete ValueCodec[HandoverRequest].
type HandoverRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (HandoverRequest,

		error)
	encode func(HandoverRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(HandoverRequest, aper.DecodeState,

	) (HandoverRequest, aper.Snapshot,

	)
	compare func(HandoverRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c HandoverRequestValueCodec) New(value HandoverRequest,

) (HandoverRequestAPERValue, error) {
	if c.encode == nil {
		return HandoverRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return HandoverRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return HandoverRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return HandoverRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c HandoverRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (HandoverRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return HandoverRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return HandoverRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return HandoverRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return HandoverRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c HandoverRequestValueCodec) EncodeAPER(value HandoverRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c HandoverRequestValueCodec) encodeBudgetValue(value HandoverRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c HandoverRequestValueCodec) encodeChanged(value HandoverRequest,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialContextSetupRequestValueCodec is the concrete ValueCodec[InitialContextSetupRequest].
type InitialContextSetupRequestValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialContextSetupRequest,

		error)
	encode func(InitialContextSetupRequest,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialContextSetupRequest, aper.DecodeState,

	) (InitialContextSetupRequest, aper.Snapshot,

	)
	compare func(InitialContextSetupRequest, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialContextSetupRequestValueCodec) New(value InitialContextSetupRequest,

) (InitialContextSetupRequestAPERValue, error) {
	if c.encode == nil {
		return InitialContextSetupRequestAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialContextSetupRequestAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialContextSetupRequestAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialContextSetupRequestValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialContextSetupRequestAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialContextSetupRequestAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialContextSetupRequestAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialContextSetupRequestAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialContextSetupRequestAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialContextSetupRequestValueCodec) EncodeAPER(value InitialContextSetupRequestAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InitialContextSetupRequestValueCodec) encodeBudgetValue(value InitialContextSetupRequest,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialContextSetupRequestValueCodec) encodeChanged(value InitialContextSetupRequest,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TraceStartValueCodec is the concrete ValueCodec[TraceStart].
type TraceStartValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TraceStart,

		error)
	encode func(TraceStart,

		bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TraceStart, aper.DecodeState,

	) (TraceStart, aper.Snapshot,

	)
	compare func(TraceStart, aper.Snapshot, aper.DecodeBudget,

	) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TraceStartValueCodec) New(value TraceStart,

) (TraceStartAPERValue, error) {
	if c.encode == nil {
		return TraceStartAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceStartAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TraceStartAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TraceStartAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TraceStartValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TraceStartAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TraceStartAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TraceStartAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TraceStartAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TraceStartAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TraceStartValueCodec) EncodeAPER(value TraceStartAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TraceStartValueCodec) encodeBudgetValue(value TraceStart,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TraceStartValueCodec) encodeChanged(value TraceStart,

	fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeHandoverRequestIEValueValidateS1APIEContainer(fields s48.HandoverRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s48.BridgeHandoverRequestIEValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s48.BridgeHandoverRequestIEValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s48.BridgeHandoverRequestIEValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s27.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeInitialContextSetupRequestIEValueValidateS1APIEContainer(fields InitialContextSetupRequestIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = field.Value.rule().Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s27.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeTraceStartIEValueValidateS1APIEContainer(fields TraceStartIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !field.Value.matchesID(field.Id, budget) {
			rule := field.Value.rule()
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = field.Value.rule().Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s27.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeTraceActivationExtIEsValueValidateS1APExtensionContainer(fields s48.TraceActivationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s48.TraceActivationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s48.TraceActivationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeTraceActivationExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}
func BridgeWLANMeasurementConfigurationExtIEsValueValidateS1APExtensionContainer(fields s12.WLANMeasurementConfigurationExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s21.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s12.WLANMeasurementConfigurationExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s21.ValidationReport {
			sealed := s21.ValidationReport{}
			*s21.BridgeValidationReportFieldErr(&sealed) = err
			*s21.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s12.WLANMeasurementConfigurationExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeWLANMeasurementConfigurationExtIEsValueValidateS1APIEContainer(asIE, rows, path, budget)
}

// HandoverRequestIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{HandoverRequestIEs}} codec of TS 36.413.
func HandoverRequestIEValueERABIEContainerListCodec(table s00.HandoverRequestIEValueIETable) s48.HandoverRequestIEValueERABIEContainerListValueCodec {
	codec := HandoverRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s48.BridgeHandoverRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s48.HandoverRequestIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s48.HandoverRequestIEValueERABIEContainerListValueCodec {
		sealed := s48.HandoverRequestIEValueERABIEContainerListValueCodec{}
		*s48.BridgeHandoverRequestIEValueERABIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s48.HandoverRequestIEValueERABIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s48.HandoverRequestIEValueERABIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s48.HandoverRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s48.BridgeHandoverRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverRequestIEValueERABIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverRequestIEValueERABIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverRequestIEValueERABIEContainerList")
			}
			return fields, nil
		}
		*s48.BridgeHandoverRequestIEValueERABIEContainerListValueCodecFieldEncode(&sealed) = func(value s48.HandoverRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s48.BridgeHandoverRequestIEContainerValueCodecFieldEncode(&codec))(s48.HandoverRequestIEContainer(value), fresh, budget)
		}
		*s48.BridgeHandoverRequestIEValueERABIEContainerListValueCodecFieldCapture(&sealed) = func(v s48.HandoverRequestIEValueERABIEContainerList, options aper.DecodeState) (s48.HandoverRequestIEValueERABIEContainerList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s48.BridgeHandoverRequestIEValueERABIEContainerListValueCodecFieldCompare(&sealed) = func(v s48.HandoverRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverRequestIEValueCompareS1APERABIEContainerList(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s48.BridgeHandoverRequestIEValueERABIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// InitialContextSetupRequestIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{InitialContextSetupRequestIEs}} codec of TS 36.413.
func InitialContextSetupRequestIEValueERABIEContainerListCodec(table s00.InitialContextSetupRequestIEValueIETable) InitialContextSetupRequestIEValueERABIEContainerListValueCodec {
	codec := InitialContextSetupRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return InitialContextSetupRequestIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return InitialContextSetupRequestIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (InitialContextSetupRequestIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields InitialContextSetupRequestIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field InitialContextSetupRequestIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
				bb.LeaveComponent(mark)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
				}
				if next, err := aper.AppendValues(bb, fields, field); err != nil {
					return err
				} else {
					fields = next
				}
			}
			return nil
		})
		if err != nil {
			return nil, runtime.WrapDecodePath(err, "InitialContextSetupRequestIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "InitialContextSetupRequestIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "InitialContextSetupRequestIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value InitialContextSetupRequestIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(InitialContextSetupRequestIEContainer(value), fresh, budget)
	}, capture: func(v InitialContextSetupRequestIEValueERABIEContainerList, options aper.DecodeState) (InitialContextSetupRequestIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeInitialContextSetupRequestIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v InitialContextSetupRequestIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeInitialContextSetupRequestIEValueCompareS1APERABIEContainerList(&v, &s)
		s.End(f, root,

			false,
		)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// TraceStartIEValueERABIEContainerListCodec constructs the E-RAB-IE-ContainerList {{TraceStartIEs}} codec of TS 36.413.
func TraceStartIEValueERABIEContainerListCodec(table s00.TraceStartIEValueIETable) TraceStartIEValueERABIEContainerListValueCodec {
	codec := TraceStartIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return TraceStartIEValueERABIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return TraceStartIEValueERABIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (TraceStartIEValueERABIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields TraceStartIEValueERABIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field TraceStartIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
				bb.LeaveComponent(mark)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
				}
				if next, err := aper.AppendValues(bb, fields, field); err != nil {
					return err
				} else {
					fields = next
				}
			}
			return nil
		})
		if err != nil {
			return nil, runtime.WrapDecodePath(err, "TraceStartIEValueERABIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "TraceStartIEValueERABIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "TraceStartIEValueERABIEContainerList")
		}
		return fields, nil
	}, encode: func(value TraceStartIEValueERABIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(TraceStartIEContainer(value), fresh, budget)
	}, capture: func(v TraceStartIEValueERABIEContainerList, options aper.DecodeState) (TraceStartIEValueERABIEContainerList, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeTraceStartIEValueCaptureS1APERABIEContainerList(&v, &s)
		var root aper.Snapshot
		s.End(f, &root,

			false)
		return v, root
	}, compare: func(v TraceStartIEValueERABIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeTraceStartIEValueCompareS1APERABIEContainerList(&v, &s)
		s.End(f, root,

			false,
		)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// WUSAssistanceInformationExtIEsValueExtensionFieldTableCodec constructs the ProtocolExtensionField {{WUS-Assistance-Information-ExtIEs}} codec of TS 36.413.
func WUSAssistanceInformationExtIEsValueExtensionFieldTableCodec(table s00.WUSAssistanceInformationExtIEsValueExtensionTable) s12.WUSAssistanceInformationExtIEsExtFieldValueCodec {
	if !*s00.BridgeWUSAssistanceInformationExtIEsValueExtensionTableFieldBound(&table) {
		return s12.WUSAssistanceInformationExtIEsExtFieldValueCodec{}
	}
	return func() s12.WUSAssistanceInformationExtIEsExtFieldValueCodec {
		sealed := s12.WUSAssistanceInformationExtIEsExtFieldValueCodec{}
		*s12.BridgeWUSAssistanceInformationExtIEsExtFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s12.WUSAssistanceInformationExtIEsExtField, error) {
			var field s12.WUSAssistanceInformationExtIEsExtField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s12.BridgeWUSAssistanceInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "WUSAssistanceInformationExtIEsExtField")
			}
			if _, err := aper.CaptureFinalBits(bb, "WUSAssistanceInformationExtIEsExtField"); err != nil {
				return field, runtime.WrapDecodePath(err, "WUSAssistanceInformationExtIEsExtField")
			}
			return field, nil
		}
		*s12.BridgeWUSAssistanceInformationExtIEsExtFieldValueCodecFieldEncode(&sealed) = func(field s12.WUSAssistanceInformationExtIEsExtField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s12.BridgeWUSAssistanceInformationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s12.BridgeWUSAssistanceInformationExtIEsExtFieldValueCodecFieldCapture(&sealed) = func(v s12.WUSAssistanceInformationExtIEsExtField, options aper.DecodeState) (s12.WUSAssistanceInformationExtIEsExtField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeWUSAssistanceInformationExtIEsValueCaptureS1APProtocolExtensionField(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s12.BridgeWUSAssistanceInformationExtIEsExtFieldValueCodecFieldCompare(&sealed) = func(v s12.WUSAssistanceInformationExtIEsExtField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeWUSAssistanceInformationExtIEsValueCompareS1APProtocolExtensionField(&v, &s)
			s.End(f,

				root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s12.BridgeWUSAssistanceInformationExtIEsExtFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// TraceActivationExtIEsValueExtensionTableCodec constructs the ProtocolExtensionContainer {{TraceActivation-ExtIEs}} codec of TS 36.413.
func TraceActivationExtIEsValueExtensionTableCodec(table s00.TraceActivationExtIEsValueExtensionTable, bounds aper.ListBounds) s48.TraceActivationExtIEsExtContainerValueCodec {
	if !*s00.BridgeTraceActivationExtIEsValueExtensionTableFieldBound(&table) {
		return s48.TraceActivationExtIEsExtContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s48.TraceActivationExtIEsExtContainerValueCodec {
		sealed := s48.TraceActivationExtIEsExtContainerValueCodec{}
		*s48.BridgeTraceActivationExtIEsExtContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s48.TraceActivationExtIEsExtContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s48.TraceActivationExtIEsExtContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s48.TraceActivationExtIEsExtField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s48.BridgeTraceActivationExtIEsExtFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "TraceActivationExtIEsExtContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "TraceActivationExtIEsExtContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "TraceActivationExtIEsExtContainer")
			}
			return fields, nil
		}
		*s48.BridgeTraceActivationExtIEsExtContainerValueCodecFieldEncode(&sealed) = func(fields s48.TraceActivationExtIEsExtContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s48.BridgeTraceActivationExtIEsExtFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s48.BridgeTraceActivationExtIEsExtContainerValueCodecFieldCapture(&sealed) = func(v s48.TraceActivationExtIEsExtContainer, options aper.DecodeState) (s48.TraceActivationExtIEsExtContainer, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s48.BridgeTraceActivationExtIEsValueCaptureS1APProtocolExtensionContainer(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s48.BridgeTraceActivationExtIEsExtContainerValueCodecFieldCompare(&sealed) = func(v s48.TraceActivationExtIEsExtContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s48.BridgeTraceActivationExtIEsValueCompareS1APProtocolExtensionContainer(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s48.BridgeTraceActivationExtIEsExtContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolExtensionContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// HandoverRequestIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{HandoverRequestIEs}} codec of TS 36.413.
func HandoverRequestIEValueIEFieldTableCodec(table s00.HandoverRequestIEValueIETable) s48.HandoverRequestIEFieldValueCodec {
	if !*s00.BridgeHandoverRequestIEValueIETableFieldBound(&table) {
		return s48.HandoverRequestIEFieldValueCodec{}
	}
	return func() s48.HandoverRequestIEFieldValueCodec {
		sealed := s48.HandoverRequestIEFieldValueCodec{}
		*s48.BridgeHandoverRequestIEFieldValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s48.HandoverRequestIEField, error) {
			var field s48.HandoverRequestIEField
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return field, err
			}
			if err := s48.BridgeHandoverRequestIEFieldMethodUnmarshalAPERFrom(&field, bb); err != nil {
				return field, runtime.WrapDecodePath(err, "HandoverRequestIEField")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverRequestIEField"); err != nil {
				return field, runtime.WrapDecodePath(err, "HandoverRequestIEField")
			}
			return field, nil
		}
		*s48.BridgeHandoverRequestIEFieldValueCodecFieldEncode(&sealed) = func(field s48.HandoverRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			if err := s48.BridgeHandoverRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s48.BridgeHandoverRequestIEFieldValueCodecFieldCapture(&sealed) = func(v s48.HandoverRequestIEField, options aper.DecodeState) (s48.HandoverRequestIEField, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverRequestIEValueCaptureS1APProtocolIEField(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s48.BridgeHandoverRequestIEFieldValueCodecFieldCompare(&sealed) = func(v s48.HandoverRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverRequestIEValueCompareS1APProtocolIEField(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s48.BridgeHandoverRequestIEFieldValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// InitialContextSetupRequestIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{InitialContextSetupRequestIEs}} codec of TS 36.413.
func InitialContextSetupRequestIEValueIEFieldTableCodec(table s00.InitialContextSetupRequestIEValueIETable) InitialContextSetupRequestIEFieldValueCodec {
	if !*s00.BridgeInitialContextSetupRequestIEValueIETableFieldBound(&table) {
		return InitialContextSetupRequestIEFieldValueCodec{}
	}
	return InitialContextSetupRequestIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (InitialContextSetupRequestIEField, error) {
		var field InitialContextSetupRequestIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "InitialContextSetupRequestIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "InitialContextSetupRequestIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "InitialContextSetupRequestIEField")
		}
		return field, nil
	}, encode: func(field InitialContextSetupRequestIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v InitialContextSetupRequestIEField, options aper.DecodeState) (InitialContextSetupRequestIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeInitialContextSetupRequestIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v InitialContextSetupRequestIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeInitialContextSetupRequestIEValueCompareS1APProtocolIEField(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// TraceStartIEValueIEFieldTableCodec constructs the ProtocolIE-Field {{TraceStartIEs}} codec of TS 36.413.
func TraceStartIEValueIEFieldTableCodec(table s00.TraceStartIEValueIETable) TraceStartIEFieldValueCodec {
	if !*s00.BridgeTraceStartIEValueIETableFieldBound(&table) {
		return TraceStartIEFieldValueCodec{}
	}
	return TraceStartIEFieldValueCodec{decode: func(data []byte, options aper.DecodeState) (TraceStartIEField, error) {
		var field TraceStartIEField
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return field, err
		}
		if err := field.unmarshalAPERFrom(bb); err != nil {
			return field, runtime.WrapDecodePath(err, "TraceStartIEField")
		}
		if _, err := aper.CaptureFinalBits(bb, "TraceStartIEField"); err != nil {
			return field, runtime.WrapDecodePath(err, "TraceStartIEField")
		}
		return field, nil
	}, encode: func(field TraceStartIEField, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		bb := aper.NewBudgetBuffer(budget)
		if err := field.marshalAPERTo(bb, fresh); err != nil {
			return nil, err
		}
		return bb.CompleteBytes(), nil
	}, capture: func(v TraceStartIEField, options aper.DecodeState) (TraceStartIEField, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeTraceStartIEValueCaptureS1APProtocolIEField(&v, &s)
		var root aper.Snapshot
		s.End(f, &root, false)
		return v, root
	}, compare: func(v TraceStartIEField, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeTraceStartIEValueCompareS1APProtocolIEField(&v, &s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEField[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// HandoverRequestIEValueIETableCodec constructs the ProtocolIE-Container {{HandoverRequestIEs}} codec of TS 36.413.
func HandoverRequestIEValueIETableCodec(table s00.HandoverRequestIEValueIETable, bounds aper.ListBounds) s48.HandoverRequestIEContainerValueCodec {
	if !*s00.BridgeHandoverRequestIEValueIETableFieldBound(&table) {
		return s48.HandoverRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return func() s48.HandoverRequestIEContainerValueCodec {
		sealed := s48.HandoverRequestIEContainerValueCodec{}
		*s48.BridgeHandoverRequestIEContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s48.HandoverRequestIEContainer, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s48.HandoverRequestIEContainer
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s48.HandoverRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s48.BridgeHandoverRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverRequestIEContainer")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverRequestIEContainer"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverRequestIEContainer")
			}
			return fields, nil
		}
		*s48.BridgeHandoverRequestIEContainerValueCodecFieldEncode(&sealed) = func(fields s48.HandoverRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := s48.BridgeHandoverRequestIEFieldMethodMarshalAPERTo(&field, bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}
		*s48.BridgeHandoverRequestIEContainerValueCodecFieldCapture(&sealed) = func(v s48.HandoverRequestIEContainer, options aper.DecodeState) (s48.HandoverRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s48.BridgeHandoverRequestIEContainerValueCodecFieldCompare(&sealed) = func(v s48.HandoverRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s48.BridgeHandoverRequestIEContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// InitialContextSetupRequestIEValueIETableCodec constructs the ProtocolIE-Container {{InitialContextSetupRequestIEs}} codec of TS 36.413.
func InitialContextSetupRequestIEValueIETableCodec(table s00.InitialContextSetupRequestIEValueIETable, bounds aper.ListBounds) InitialContextSetupRequestIEContainerValueCodec {
	if !*s00.BridgeInitialContextSetupRequestIEValueIETableFieldBound(&table) {
		return InitialContextSetupRequestIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return InitialContextSetupRequestIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (InitialContextSetupRequestIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields InitialContextSetupRequestIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field InitialContextSetupRequestIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
				bb.LeaveComponent(mark)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
				}
				if next, err := aper.AppendValues(bb, fields, field); err != nil {
					return err
				} else {
					fields = next
				}
			}
			return nil
		})
		if err != nil {
			return nil, runtime.WrapDecodePath(err, "InitialContextSetupRequestIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "InitialContextSetupRequestIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "InitialContextSetupRequestIEContainer")
		}
		return fields, nil
	},
		encode: func(fields InitialContextSetupRequestIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := field.marshalAPERTo(bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}, capture: func(v InitialContextSetupRequestIEContainer, options aper.DecodeState) (InitialContextSetupRequestIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeInitialContextSetupRequestIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v InitialContextSetupRequestIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeInitialContextSetupRequestIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}

// TraceStartIEValueIETableCodec constructs the ProtocolIE-Container {{TraceStartIEs}} codec of TS 36.413.
func TraceStartIEValueIETableCodec(table s00.TraceStartIEValueIETable, bounds aper.ListBounds) TraceStartIEContainerValueCodec {
	if !*s00.BridgeTraceStartIEValueIETableFieldBound(&table) {
		return TraceStartIEContainerValueCodec{}
	}
	size := aper.SizeConstraint{Lower: bounds.Lower, Upper: bounds.Upper, HasLower: true, HasUpper: true}
	return TraceStartIEContainerValueCodec{decode: func(data []byte, options aper.DecodeState) (TraceStartIEContainer, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields TraceStartIEContainer
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field TraceStartIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
				bb.LeaveComponent(mark)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
				}
				if next, err := aper.AppendValues(bb, fields, field); err != nil {
					return err
				} else {
					fields = next
				}
			}
			return nil
		})
		if err != nil {
			return nil, runtime.WrapDecodePath(err, "TraceStartIEContainer")
		}
		if _, err := aper.CaptureFinalBits(bb, "TraceStartIEContainer"); err != nil {
			return nil, runtime.WrapDecodePath(err, "TraceStartIEContainer")
		}
		return fields, nil
	},
		encode: func(fields TraceStartIEContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			err := aper.EncodeCollection(bb, int64(len(fields)), size, true, func(offset, length int64) error {
				if offset < 0 || length < 0 || offset > int64(len(fields)) || length > int64(len(fields[offset:])) {
					return fmt.Errorf("%w: invalid table fragment", aper.ErrInvalidValue)
				}
				for _, field := range fields[offset:][:length] {
					if err := field.marshalAPERTo(bb, fresh); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		}, capture: func(v TraceStartIEContainer, options aper.DecodeState) (TraceStartIEContainer, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeTraceStartIEValueCaptureS1APProtocolIEContainer(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}, compare: func(v TraceStartIEContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeTraceStartIEValueCompareS1APProtocolIEContainer(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainer[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}(),
	}
}

// HandoverRequestIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{HandoverRequestIEs}} codec of TS 36.413.
func HandoverRequestIEValueProtocolErrorIEContainerListCodec(table s00.HandoverRequestIEValueIETable) s48.HandoverRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := HandoverRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if *s48.BridgeHandoverRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s48.HandoverRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return func() s48.HandoverRequestIEValueProtocolErrorIEContainerListValueCodec {
		sealed := s48.HandoverRequestIEValueProtocolErrorIEContainerListValueCodec{}
		*s48.BridgeHandoverRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s48.HandoverRequestIEValueProtocolErrorIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s48.HandoverRequestIEValueProtocolErrorIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s48.HandoverRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s48.BridgeHandoverRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverRequestIEValueProtocolErrorIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverRequestIEValueProtocolErrorIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverRequestIEValueProtocolErrorIEContainerList")
			}
			return fields, nil
		}
		*s48.BridgeHandoverRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(&sealed) = func(value s48.HandoverRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s48.BridgeHandoverRequestIEContainerValueCodecFieldEncode(&codec))(s48.HandoverRequestIEContainer(value), fresh, budget)
		}
		*s48.BridgeHandoverRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(&sealed) = func(v s48.HandoverRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (s48.HandoverRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s48.BridgeHandoverRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(&sealed) = func(v s48.HandoverRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			BridgeHandoverRequestIEValueCompareS1APProtocolErrorIEContainerList(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s48.BridgeHandoverRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}()

}

// InitialContextSetupRequestIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{InitialContextSetupRequestIEs}} codec of TS 36.413.
func InitialContextSetupRequestIEValueProtocolErrorIEContainerListCodec(table s00.InitialContextSetupRequestIEValueIETable) InitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodec {
	codec := InitialContextSetupRequestIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return InitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return InitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (InitialContextSetupRequestIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields InitialContextSetupRequestIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field InitialContextSetupRequestIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
				bb.LeaveComponent(mark)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
				}
				if next, err := aper.AppendValues(bb, fields, field); err != nil {
					return err
				} else {
					fields = next
				}
			}
			return nil
		})
		if err != nil {
			return nil, runtime.WrapDecodePath(err, "InitialContextSetupRequestIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "InitialContextSetupRequestIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "InitialContextSetupRequestIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value InitialContextSetupRequestIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(InitialContextSetupRequestIEContainer(value), fresh, budget)
	}, capture: func(v InitialContextSetupRequestIEValueProtocolErrorIEContainerList, options aper.DecodeState) (InitialContextSetupRequestIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeInitialContextSetupRequestIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v InitialContextSetupRequestIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeInitialContextSetupRequestIEValueCompareS1APProtocolErrorIEContainerList(
			&v,

			&s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// TraceStartIEValueProtocolErrorIEContainerListCodec constructs the ProtocolError-IE-ContainerList {{TraceStartIEs}} codec of TS 36.413.
func TraceStartIEValueProtocolErrorIEContainerListCodec(table s00.TraceStartIEValueIETable) TraceStartIEValueProtocolErrorIEContainerListValueCodec {
	codec := TraceStartIEValueIETableCodec(table, aper.ListBounds{Lower: 1, Upper: 256})
	if codec.decode == nil {
		return TraceStartIEValueProtocolErrorIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (aper.ListBounds{Lower: 1, Upper: 256}).Lower, Upper: (aper.ListBounds{Lower: 1, Upper: 256}).Upper, HasLower: true, HasUpper: true}
	return TraceStartIEValueProtocolErrorIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (TraceStartIEValueProtocolErrorIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields TraceStartIEValueProtocolErrorIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field TraceStartIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
				bb.LeaveComponent(mark)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
				}
				if next, err := aper.AppendValues(bb, fields, field); err != nil {
					return err
				} else {
					fields = next
				}
			}
			return nil
		})
		if err != nil {
			return nil, runtime.WrapDecodePath(err, "TraceStartIEValueProtocolErrorIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "TraceStartIEValueProtocolErrorIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "TraceStartIEValueProtocolErrorIEContainerList")
		}
		return fields, nil
	}, encode: func(value TraceStartIEValueProtocolErrorIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(TraceStartIEContainer(value), fresh, budget)
	}, capture: func(v TraceStartIEValueProtocolErrorIEContainerList, options aper.DecodeState) (TraceStartIEValueProtocolErrorIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeTraceStartIEValueCaptureS1APProtocolErrorIEContainerList(&v, &s)
		var root aper.Snapshot

		s.End(f, &root, false)
		return v, root
	}, compare: func(v TraceStartIEValueProtocolErrorIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

	) {
		s := aper.NewSemanticComparison(root, budget)
		f := s.Begin()
		BridgeTraceStartIEValueCompareS1APProtocolErrorIEContainerList(
			&v,

			&s)
		s.End(f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolErrorIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
		return sealed
	}(),
	}
}

// HandoverRequestIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {HandoverRequestIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func HandoverRequestIEValueProtocolIEContainerListCodec(table s00.HandoverRequestIEValueIETable, bounds aper.ListBounds) s48.HandoverRequestIEValueProtocolIEContainerListValueCodec {
	codec := HandoverRequestIEValueIETableCodec(table, bounds)
	if *s48.BridgeHandoverRequestIEContainerValueCodecFieldDecode(&codec) == nil {
		return s48.HandoverRequestIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return func() s48.HandoverRequestIEValueProtocolIEContainerListValueCodec {
		sealed := s48.HandoverRequestIEValueProtocolIEContainerListValueCodec{}
		*s48.BridgeHandoverRequestIEValueProtocolIEContainerListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s48.HandoverRequestIEValueProtocolIEContainerList, error) {
			bb := aper.NewCompleteDecodeBuffer(data, options)
			if err := bb.SetDecodeOptionsAligned(options); err != nil {
				return nil, err
			}
			var fields s48.HandoverRequestIEValueProtocolIEContainerList
			_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
				for i := int64(0); i < length; i++ {
					var field s48.HandoverRequestIEField
					mark := bb.EnterIndex(int64(len(fields)))
					err := s48.BridgeHandoverRequestIEFieldMethodUnmarshalAPERFrom(&field, bb)
					bb.LeaveComponent(mark)
					if err != nil {
						return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
					}
					if next, err := aper.AppendValues(bb, fields, field); err != nil {
						return err
					} else {
						fields = next
					}
				}
				return nil
			})
			if err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverRequestIEValueProtocolIEContainerList")
			}
			if _, err := aper.CaptureFinalBits(bb, "HandoverRequestIEValueProtocolIEContainerList"); err != nil {
				return nil, runtime.WrapDecodePath(err, "HandoverRequestIEValueProtocolIEContainerList")
			}
			return fields, nil
		}
		*s48.BridgeHandoverRequestIEValueProtocolIEContainerListValueCodecFieldEncode(&sealed) = func(value s48.HandoverRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (*s48.BridgeHandoverRequestIEContainerValueCodecFieldEncode(&codec))(s48.HandoverRequestIEContainer(value), fresh, budget)
		}
		*s48.BridgeHandoverRequestIEValueProtocolIEContainerListValueCodecFieldCapture(&sealed) = func(v s48.HandoverRequestIEValueProtocolIEContainerList, options aper.DecodeState) (s48.HandoverRequestIEValueProtocolIEContainerList, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeHandoverRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
			var root aper.Snapshot
			s.
				End(f, &root, false)
			return v, root
		}
		*s48.BridgeHandoverRequestIEValueProtocolIEContainerListValueCodecFieldCompare(&sealed) = func(v s48.HandoverRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			BridgeHandoverRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
			s.End(
				f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s48.BridgeHandoverRequestIEValueProtocolIEContainerListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
			*s00.BridgecodecContextFieldBounds(&sealed) = bounds
			return sealed
		}()
		return sealed
	}()

}

// InitialContextSetupRequestIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {InitialContextSetupRequestIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func InitialContextSetupRequestIEValueProtocolIEContainerListCodec(table s00.InitialContextSetupRequestIEValueIETable, bounds aper.ListBounds) InitialContextSetupRequestIEValueProtocolIEContainerListValueCodec {
	codec := InitialContextSetupRequestIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return InitialContextSetupRequestIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return InitialContextSetupRequestIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (InitialContextSetupRequestIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields InitialContextSetupRequestIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field InitialContextSetupRequestIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
				bb.LeaveComponent(mark)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
				}
				if next, err := aper.AppendValues(bb, fields, field); err != nil {
					return err
				} else {
					fields = next
				}
			}
			return nil
		})
		if err != nil {
			return nil, runtime.WrapDecodePath(err, "InitialContextSetupRequestIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "InitialContextSetupRequestIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "InitialContextSetupRequestIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value InitialContextSetupRequestIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(InitialContextSetupRequestIEContainer(value), fresh, budget)
	}, capture: func(v InitialContextSetupRequestIEValueProtocolIEContainerList, options aper.DecodeState) (InitialContextSetupRequestIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeInitialContextSetupRequestIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v InitialContextSetupRequestIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeInitialContextSetupRequestIEValueCompareS1APProtocolIEContainerList(&v, &s)
		s.End(
			f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = bounds
		return sealed
	}(),
	}
}

// TraceStartIEValueProtocolIEContainerListCodec constructs a codec for ProtocolIE-ContainerList with IEsSetParam = {TraceStartIEs} of TS 36.413, with lowerBound and upperBound supplied by its arguments.
func TraceStartIEValueProtocolIEContainerListCodec(table s00.TraceStartIEValueIETable, bounds aper.ListBounds) TraceStartIEValueProtocolIEContainerListValueCodec {
	codec := TraceStartIEValueIETableCodec(table, bounds)
	if codec.decode == nil {
		return TraceStartIEValueProtocolIEContainerListValueCodec{}
	}
	size := aper.SizeConstraint{Lower: (bounds).Lower, Upper: (bounds).Upper, HasLower: true, HasUpper: true}
	return TraceStartIEValueProtocolIEContainerListValueCodec{decode: func(data []byte, options aper.DecodeState) (TraceStartIEValueProtocolIEContainerList, error) {
		bb := aper.NewCompleteDecodeBuffer(data, options)
		if err := bb.SetDecodeOptionsAligned(options); err != nil {
			return nil, err
		}
		var fields TraceStartIEValueProtocolIEContainerList
		_, err := aper.DecodeCollection(bb, size, true, func(_ int64, length int64) error {
			for i := int64(0); i < length; i++ {
				var field TraceStartIEField
				mark := bb.EnterIndex(int64(len(fields)))
				err := field.unmarshalAPERFrom(bb)
				bb.LeaveComponent(mark)
				if err != nil {
					return runtime.WrapDecodePath(err, fmt.Sprintf("[%d]", len(fields)))
				}
				if next, err := aper.AppendValues(bb, fields, field); err != nil {
					return err
				} else {
					fields = next
				}
			}
			return nil
		})
		if err != nil {
			return nil, runtime.WrapDecodePath(err, "TraceStartIEValueProtocolIEContainerList")
		}
		if _, err := aper.CaptureFinalBits(bb, "TraceStartIEValueProtocolIEContainerList"); err != nil {
			return nil, runtime.WrapDecodePath(err, "TraceStartIEValueProtocolIEContainerList")
		}
		return fields, nil
	}, encode: func(value TraceStartIEValueProtocolIEContainerList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return codec.encode(TraceStartIEContainer(value), fresh, budget)
	}, capture: func(v TraceStartIEValueProtocolIEContainerList, options aper.DecodeState) (TraceStartIEValueProtocolIEContainerList, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeTraceStartIEValueCaptureS1APProtocolIEContainerList(&v, &s)
		var root aper.Snapshot
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v TraceStartIEValueProtocolIEContainerList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
	) {
		s := aper.NewSemanticComparison(root, budget)
		f :=
			s.Begin()
		BridgeTraceStartIEValueCompareS1APProtocolIEContainerList(&v, &s)
		s.End(
			f, root, false)
		return s.Plan(), s.BudgetValue()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProtocolIEContainerList[V]"
		*s00.BridgecodecContextFieldBounds(&sealed) = bounds
		return sealed
	}(),
	}
}

// handoverRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[HandoverRequestIEValue].
type HandoverRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s48.HandoverRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s48.HandoverRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeHandoverRequestIEValueCaptureS1APProtocolIEField(v *s48.HandoverRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = s48.BridgeHandoverRequestIEValueMethodCaptureSemantics(v.Value, *s)
	s.End(f, s48.BridgeHandoverRequestIEFieldFieldReplay(v), *s48.BridgeHandoverRequestIEFieldFieldWithoutReplay(v))
}
func BridgeHandoverRequestIEValueCompareS1APProtocolIEField(v *s48.HandoverRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s48.BridgeHandoverRequestIEValueMethodCompareSemantics(v.Value, *s)
	s.End(f, *s48.BridgeHandoverRequestIEFieldFieldReplay(v), *s48.BridgeHandoverRequestIEFieldFieldWithoutReplay(v))
}

// initialContextSetupRequestIEValueProtocolOpenValue is the concrete protocolOpenValue[InitialContextSetupRequestIEValue].
type InitialContextSetupRequestIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) InitialContextSetupRequestIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (InitialContextSetupRequestIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeInitialContextSetupRequestIEValueCaptureS1APProtocolIEField(v *InitialContextSetupRequestIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeInitialContextSetupRequestIEValueCompareS1APProtocolIEField(v *InitialContextSetupRequestIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// traceActivationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[TraceActivationExtIEsValue].
type TraceActivationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s48.TraceActivationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s48.TraceActivationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

// traceStartIEValueProtocolOpenValue is the concrete protocolOpenValue[TraceStartIEValue].
type TraceStartIEValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) TraceStartIEValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (TraceStartIEValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeTraceStartIEValueCaptureS1APProtocolIEField(v *TraceStartIEField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.Value = v.Value.captureSemantics(*s)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeTraceStartIEValueCompareS1APProtocolIEField(v *TraceStartIEField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = v.Value.compareSemantics(*s)
	s.End(f, v.replay, v.withoutReplay)
}

// wLANMeasurementConfigurationExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[WLANMeasurementConfigurationExtIEsValue].
type WLANMeasurementConfigurationExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s06.WLANMeasurementConfigurationExtIEsValue

	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s06.WLANMeasurementConfigurationExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, ...*aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeWUSAssistanceInformationExtIEsValueCaptureS1APProtocolExtensionField(v *s12.WUSAssistanceInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolExtensionID(&v.Id, s)
	s00.BridgeCaptureS1APCriticality(&v.Criticality, s)
	v.ExtensionValue = s06.BridgeWUSAssistanceInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.End(f, s12.BridgeWUSAssistanceInformationExtIEsExtFieldFieldReplay(v), *s12.BridgeWUSAssistanceInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeWUSAssistanceInformationExtIEsValueCompareS1APProtocolExtensionField(v *s12.WUSAssistanceInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolExtensionID(&v.Id, s)
	s02.BridgeCompareS1APCriticality(&v.Criticality, s)
	*s = s06.BridgeWUSAssistanceInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s12.BridgeWUSAssistanceInformationExtIEsExtFieldFieldReplay(v), *s12.BridgeWUSAssistanceInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// TraceActivationAPERValue is the concrete APERValue[TraceActivation].
type TraceActivationAPERValue struct {
	context s00.BridgeCodecContext
	Value   s48.TraceActivation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TraceActivationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceActivationAPERValue) WithoutReplay() TraceActivationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// HandoverRequestAPERValue is the concrete APERValue[HandoverRequest].
type HandoverRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   HandoverRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v HandoverRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v HandoverRequestAPERValue) WithoutReplay() HandoverRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialContextSetupRequestAPERValue is the concrete APERValue[InitialContextSetupRequest].
type InitialContextSetupRequestAPERValue struct {
	context s00.BridgeCodecContext
	Value   InitialContextSetupRequest

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialContextSetupRequestAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupRequestAPERValue) WithoutReplay() InitialContextSetupRequestAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TraceStartAPERValue is the concrete APERValue[TraceStart].
type TraceStartAPERValue struct {
	context s00.BridgeCodecContext
	Value   TraceStart

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TraceStartAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceStartAPERValue) WithoutReplay() TraceStartAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeTraceActivationExtIEsValueValidateS1APIEContainer(fields s48.TraceActivationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s48.BridgeTraceActivationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s48.BridgeTraceActivationExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s48.BridgeTraceActivationExtIEsValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s27.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}

// TS 36.413 V19.2.0 §§9.3.3–9.3.4 supply the selected object-set order and
// presence. §§10.3.1–10.3.6 define abstract-syntax diagnostics. Unknown IEs do
// not determine the order of known rows.
func BridgeWLANMeasurementConfigurationExtIEsValueValidateS1APIEContainer(fields s12.WLANMeasurementConfigurationExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

) s21.ValidationReport {
	report := func() s21.ValidationReport {
		sealed := s21.ValidationReport{Complete: true}
		*s21.BridgeValidationReportFieldBudget(&sealed) = budget
		return sealed
	}()
	bb := aper.NewBudgetBuffer(budget)
	if err := bb.ChargeAllocation(uint64(len(rows))+uint64(len(fields)), 32); err != nil {
		*s21.BridgeValidationReportFieldErr(&report) = err
		return report
	}
	byID := make(map[s00.ProtocolIEID]int, len(rows))
	counts := make(map[s00.ProtocolIEID]int, len(fields))
	for i, row := range rows {
		byID[row.ID] = i
	}
	lastRank := -1
	for i, field := range fields {
		if *s21.BridgeValidationReportFieldErr(&report) != nil {
			return report
		}
		if err := bb.ChargeWork(1); err != nil {
			*s21.BridgeValidationReportFieldErr(&report) = err
			return report
		}
		location := aper.Location{Path: aper.Path(fmt.Sprintf("%s[%d]{id=%d}", path, i, field.Id))}
		// TS 36.413 V19.2.0 §9.3.7 binds the selected value to @id.
		if !s06.BridgeWLANMeasurementConfigurationExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s06.BridgeWLANMeasurementConfigurationExtIEsValueMethodRule(field.Value)
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.ValueIDMismatch, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.id", location.Path))}, Table: func() s00.TableID {
				sealed := s00.TableID{}
				*s00.BridgeTableIDFieldSource(&sealed) = rule.Assignment
				return sealed
			}(), IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.ValueIDMismatch), RelatedRules: []aper.SourceRule{rule}})
		}
		rank, allowed := byID[field.Id]
		table := func() s00.TableID {
			sealed := s00.TableID{}
			*s00.BridgeTableIDFieldSource(&sealed) = s06.BridgeWLANMeasurementConfigurationExtIEsValueMethodRule(field.Value).Assignment
			return sealed
		}()
		var sourceRules []aper.SourceRule
		if allowed {
			table = rows[rank].Table
			sourceRules = append(sourceRules, rows[rank].Rule)
		}
		aper.IncrementCount(counts, field.Id)
		if counts[field.Id] > 1 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.RepeatedIE, Severity: s00.ValidationSeverityError, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.RepeatedIE), RelatedRules: append([]aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.RepeatedIE)}, sourceRules...)})
		}
		if !allowed {
			severity := s00.ValidationSeverityUnrecognized
			if _, globallyKnown := s13.BridgeKnownS1APIEIDs[field.Id]; globallyKnown {
				severity = s00.ValidationSeverityError
			}
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.NotAllowed, Severity: severity, Location: location, Table: table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.NotAllowed), RelatedRules: s27.BridgeS1apHandlingRules(s00.NotAllowed)})
			continue
		}
		row := rows[rank]
		if field.Criticality != row.Criticality {
			expected, received := row.Criticality, field.Criticality
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongCriticality, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(fmt.Sprintf("%s.criticality", location.Path))}, Table: row.Table, IEID: field.Id, HasIEID: true, ExpectedCriticality: &expected, ReceivedCriticality: &received, Rule: s27.BridgeS1apValidationRule(s00.WrongCriticality), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongCriticality), row.Rule}})
		}
		if rank < lastRank {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.WrongOrder, Severity: s00.ValidationSeverityError, Location: location, Table: row.Table, IEID: field.Id, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.WrongOrder), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.WrongOrder), row.Rule}})
		} else {
			lastRank = rank
		}
	}
	for _, row := range rows {
		if row.Presence == s00.PresenceMandatory && counts[row.ID] == 0 {
			s21.BridgeValidationReportMethodAddIssue(&report, s21.ValidationIssue{Code: s00.MissingMandatory, Severity: s00.ValidationSeverityError, Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, HasIEID: true, Rule: s27.BridgeS1apValidationRule(s00.MissingMandatory), RelatedRules: []aper.SourceRule{s27.BridgeS1apAdoptedRule(s00.MissingMandatory), row.Rule}})
		}
		if row.Presence == s00.PresenceConditional {
			s21.BridgeValidationReportMethodAddDeferred(&report, s00.DeferredCondition{Location: aper.Location{Path: aper.Path(path)}, Table: row.Table, IEID: row.ID, Rule: row.Rule})
			if *s21.BridgeValidationReportFieldErr(&report) != nil {
				return report
			}
			report.Complete = false
		}
	}
	return report
}
func BridgeHandoverRequestIEValueCaptureS1APERABIEContainerList(v *s48.HandoverRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverRequestIEValueCompareS1APERABIEContainerList(v *s48.HandoverRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// InitialContextSetupRequestIEValueERABIEContainerListValueCodec is the concrete ValueCodec[InitialContextSetupRequestIEValueERABIEContainerList].
type InitialContextSetupRequestIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialContextSetupRequestIEValueERABIEContainerList, error)
	encode  func(InitialContextSetupRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialContextSetupRequestIEValueERABIEContainerList, aper.DecodeState) (InitialContextSetupRequestIEValueERABIEContainerList, aper.Snapshot)
	compare func(InitialContextSetupRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialContextSetupRequestIEValueERABIEContainerListValueCodec) New(value InitialContextSetupRequestIEValueERABIEContainerList) (InitialContextSetupRequestIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return InitialContextSetupRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialContextSetupRequestIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialContextSetupRequestIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialContextSetupRequestIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialContextSetupRequestIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialContextSetupRequestIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialContextSetupRequestIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialContextSetupRequestIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialContextSetupRequestIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialContextSetupRequestIEValueERABIEContainerListValueCodec) EncodeAPER(value InitialContextSetupRequestIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InitialContextSetupRequestIEValueERABIEContainerListValueCodec) encodeBudgetValue(value InitialContextSetupRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialContextSetupRequestIEValueERABIEContainerListValueCodec) encodeChanged(value InitialContextSetupRequestIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialContextSetupRequestIEValueERABIEContainerList is E-RAB-IE-ContainerList {{InitialContextSetupRequestIEs}} of TS 36.413: a list of information element fields.
type InitialContextSetupRequestIEValueERABIEContainerList []InitialContextSetupRequestIEValueProtocolIESingleContainer

func BridgeInitialContextSetupRequestIEValueCaptureS1APERABIEContainerList(v *InitialContextSetupRequestIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeInitialContextSetupRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeInitialContextSetupRequestIEValueCompareS1APERABIEContainerList(v *InitialContextSetupRequestIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeInitialContextSetupRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// TraceStartIEValueERABIEContainerListValueCodec is the concrete ValueCodec[TraceStartIEValueERABIEContainerList].
type TraceStartIEValueERABIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TraceStartIEValueERABIEContainerList, error)
	encode  func(TraceStartIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TraceStartIEValueERABIEContainerList, aper.DecodeState) (TraceStartIEValueERABIEContainerList, aper.Snapshot)
	compare func(TraceStartIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TraceStartIEValueERABIEContainerListValueCodec) New(value TraceStartIEValueERABIEContainerList) (TraceStartIEValueERABIEContainerListAPERValue, error) {
	if c.encode == nil {
		return TraceStartIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceStartIEValueERABIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TraceStartIEValueERABIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TraceStartIEValueERABIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TraceStartIEValueERABIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TraceStartIEValueERABIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TraceStartIEValueERABIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TraceStartIEValueERABIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TraceStartIEValueERABIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TraceStartIEValueERABIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TraceStartIEValueERABIEContainerListValueCodec) EncodeAPER(value TraceStartIEValueERABIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TraceStartIEValueERABIEContainerListValueCodec) encodeBudgetValue(value TraceStartIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TraceStartIEValueERABIEContainerListValueCodec) encodeChanged(value TraceStartIEValueERABIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TraceStartIEValueERABIEContainerList is E-RAB-IE-ContainerList {{TraceStartIEs}} of TS 36.413: a list of information element fields.
type TraceStartIEValueERABIEContainerList []TraceStartIEValueProtocolIESingleContainer

func BridgeTraceStartIEValueCaptureS1APERABIEContainerList(v *TraceStartIEValueERABIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTraceStartIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTraceStartIEValueCompareS1APERABIEContainerList(v *TraceStartIEValueERABIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTraceStartIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// InitialContextSetupRequestIEFieldValueCodec is the concrete ValueCodec[InitialContextSetupRequestIEField].
type InitialContextSetupRequestIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialContextSetupRequestIEField, error)
	encode  func(InitialContextSetupRequestIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialContextSetupRequestIEField, aper.DecodeState) (InitialContextSetupRequestIEField, aper.Snapshot)
	compare func(InitialContextSetupRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialContextSetupRequestIEFieldValueCodec) New(value InitialContextSetupRequestIEField) (InitialContextSetupRequestIEFieldAPERValue, error) {
	if c.encode == nil {
		return InitialContextSetupRequestIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialContextSetupRequestIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialContextSetupRequestIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialContextSetupRequestIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialContextSetupRequestIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialContextSetupRequestIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialContextSetupRequestIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialContextSetupRequestIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialContextSetupRequestIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialContextSetupRequestIEFieldValueCodec) EncodeAPER(value InitialContextSetupRequestIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InitialContextSetupRequestIEFieldValueCodec) encodeBudgetValue(value InitialContextSetupRequestIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialContextSetupRequestIEFieldValueCodec) encodeChanged(value InitialContextSetupRequestIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TraceStartIEFieldValueCodec is the concrete ValueCodec[TraceStartIEField].
type TraceStartIEFieldValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TraceStartIEField, error)
	encode  func(TraceStartIEField, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TraceStartIEField, aper.DecodeState) (TraceStartIEField, aper.Snapshot)
	compare func(TraceStartIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TraceStartIEFieldValueCodec) New(value TraceStartIEField) (TraceStartIEFieldAPERValue, error) {
	if c.encode == nil {
		return TraceStartIEFieldAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceStartIEFieldAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TraceStartIEFieldAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TraceStartIEFieldAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TraceStartIEFieldValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TraceStartIEFieldAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TraceStartIEFieldAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TraceStartIEFieldAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TraceStartIEFieldAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TraceStartIEFieldAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TraceStartIEFieldValueCodec) EncodeAPER(value TraceStartIEFieldAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TraceStartIEFieldValueCodec) encodeBudgetValue(value TraceStartIEField, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TraceStartIEFieldValueCodec) encodeChanged(value TraceStartIEField, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialContextSetupRequestIEContainerValueCodec is the concrete ValueCodec[InitialContextSetupRequestIEContainer].
type InitialContextSetupRequestIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialContextSetupRequestIEContainer, error)
	encode  func(InitialContextSetupRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialContextSetupRequestIEContainer, aper.DecodeState) (InitialContextSetupRequestIEContainer, aper.Snapshot)
	compare func(InitialContextSetupRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialContextSetupRequestIEContainerValueCodec) New(value InitialContextSetupRequestIEContainer) (InitialContextSetupRequestIEContainerAPERValue, error) {
	if c.encode == nil {
		return InitialContextSetupRequestIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialContextSetupRequestIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialContextSetupRequestIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialContextSetupRequestIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialContextSetupRequestIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialContextSetupRequestIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialContextSetupRequestIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialContextSetupRequestIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialContextSetupRequestIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialContextSetupRequestIEContainerValueCodec) EncodeAPER(value InitialContextSetupRequestIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InitialContextSetupRequestIEContainerValueCodec) encodeBudgetValue(value InitialContextSetupRequestIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialContextSetupRequestIEContainerValueCodec) encodeChanged(value InitialContextSetupRequestIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TraceStartIEContainerValueCodec is the concrete ValueCodec[TraceStartIEContainer].
type TraceStartIEContainerValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TraceStartIEContainer, error)
	encode  func(TraceStartIEContainer, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TraceStartIEContainer, aper.DecodeState) (TraceStartIEContainer, aper.Snapshot)
	compare func(TraceStartIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TraceStartIEContainerValueCodec) New(value TraceStartIEContainer) (TraceStartIEContainerAPERValue, error) {
	if c.encode == nil {
		return TraceStartIEContainerAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceStartIEContainerAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TraceStartIEContainerAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TraceStartIEContainerAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TraceStartIEContainerValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TraceStartIEContainerAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TraceStartIEContainerAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TraceStartIEContainerAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TraceStartIEContainerAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TraceStartIEContainerAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TraceStartIEContainerValueCodec) EncodeAPER(value TraceStartIEContainerAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TraceStartIEContainerValueCodec) encodeBudgetValue(value TraceStartIEContainer, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TraceStartIEContainerValueCodec) encodeChanged(value TraceStartIEContainer, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func BridgeHandoverRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *s48.HandoverRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverRequestIEValueCompareS1APProtocolErrorIEContainerList(v *s48.HandoverRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// InitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[InitialContextSetupRequestIEValueProtocolErrorIEContainerList].
type InitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialContextSetupRequestIEValueProtocolErrorIEContainerList, error)
	encode  func(InitialContextSetupRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialContextSetupRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (InitialContextSetupRequestIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(InitialContextSetupRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodec) New(value InitialContextSetupRequestIEValueProtocolErrorIEContainerList) (InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value InitialContextSetupRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value InitialContextSetupRequestIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialContextSetupRequestIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{InitialContextSetupRequestIEs}} of TS 36.413: a list of information element fields.
type InitialContextSetupRequestIEValueProtocolErrorIEContainerList []InitialContextSetupRequestIEValueProtocolIESingleContainer

func BridgeInitialContextSetupRequestIEValueCaptureS1APProtocolErrorIEContainerList(v *InitialContextSetupRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeInitialContextSetupRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeInitialContextSetupRequestIEValueCompareS1APProtocolErrorIEContainerList(v *InitialContextSetupRequestIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeInitialContextSetupRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// TraceStartIEValueProtocolErrorIEContainerListValueCodec is the concrete ValueCodec[TraceStartIEValueProtocolErrorIEContainerList].
type TraceStartIEValueProtocolErrorIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TraceStartIEValueProtocolErrorIEContainerList, error)
	encode  func(TraceStartIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TraceStartIEValueProtocolErrorIEContainerList, aper.DecodeState) (TraceStartIEValueProtocolErrorIEContainerList, aper.Snapshot)
	compare func(TraceStartIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TraceStartIEValueProtocolErrorIEContainerListValueCodec) New(value TraceStartIEValueProtocolErrorIEContainerList) (TraceStartIEValueProtocolErrorIEContainerListAPERValue, error) {
	if c.encode == nil {
		return TraceStartIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceStartIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TraceStartIEValueProtocolErrorIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TraceStartIEValueProtocolErrorIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TraceStartIEValueProtocolErrorIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TraceStartIEValueProtocolErrorIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TraceStartIEValueProtocolErrorIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TraceStartIEValueProtocolErrorIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TraceStartIEValueProtocolErrorIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TraceStartIEValueProtocolErrorIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TraceStartIEValueProtocolErrorIEContainerListValueCodec) EncodeAPER(value TraceStartIEValueProtocolErrorIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TraceStartIEValueProtocolErrorIEContainerListValueCodec) encodeBudgetValue(value TraceStartIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TraceStartIEValueProtocolErrorIEContainerListValueCodec) encodeChanged(value TraceStartIEValueProtocolErrorIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TraceStartIEValueProtocolErrorIEContainerList is ProtocolError-IE-ContainerList {{TraceStartIEs}} of TS 36.413: a list of information element fields.
type TraceStartIEValueProtocolErrorIEContainerList []TraceStartIEValueProtocolIESingleContainer

func BridgeTraceStartIEValueCaptureS1APProtocolErrorIEContainerList(v *TraceStartIEValueProtocolErrorIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTraceStartIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTraceStartIEValueCompareS1APProtocolErrorIEContainerList(v *TraceStartIEValueProtocolErrorIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTraceStartIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverRequestIEValueCaptureS1APProtocolIEContainerList(v *s48.HandoverRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeHandoverRequestIEValueCompareS1APProtocolIEContainerList(v *s48.HandoverRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeHandoverRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// InitialContextSetupRequestIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[InitialContextSetupRequestIEValueProtocolIEContainerList].
type InitialContextSetupRequestIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (InitialContextSetupRequestIEValueProtocolIEContainerList, error)
	encode  func(InitialContextSetupRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(InitialContextSetupRequestIEValueProtocolIEContainerList, aper.DecodeState) (InitialContextSetupRequestIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(InitialContextSetupRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c InitialContextSetupRequestIEValueProtocolIEContainerListValueCodec) New(value InitialContextSetupRequestIEValueProtocolIEContainerList) (InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c InitialContextSetupRequestIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c InitialContextSetupRequestIEValueProtocolIEContainerListValueCodec) EncodeAPER(value InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c InitialContextSetupRequestIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value InitialContextSetupRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c InitialContextSetupRequestIEValueProtocolIEContainerListValueCodec) encodeChanged(value InitialContextSetupRequestIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// InitialContextSetupRequestIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {InitialContextSetupRequestIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type InitialContextSetupRequestIEValueProtocolIEContainerList []InitialContextSetupRequestIEValueProtocolIESingleContainer

func BridgeInitialContextSetupRequestIEValueCaptureS1APProtocolIEContainerList(v *InitialContextSetupRequestIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeInitialContextSetupRequestIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeInitialContextSetupRequestIEValueCompareS1APProtocolIEContainerList(v *InitialContextSetupRequestIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeInitialContextSetupRequestIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}

// TraceStartIEValueProtocolIEContainerListValueCodec is the concrete ValueCodec[TraceStartIEValueProtocolIEContainerList].
type TraceStartIEValueProtocolIEContainerListValueCodec struct {
	path    aper.Path
	context s00.BridgeCodecContext
	decode  func([]byte, aper.DecodeState) (TraceStartIEValueProtocolIEContainerList, error)
	encode  func(TraceStartIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error)
	capture func(TraceStartIEValueProtocolIEContainerList, aper.DecodeState) (TraceStartIEValueProtocolIEContainerList, aper.Snapshot)
	compare func(TraceStartIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget)
}

// New validates a source value and returns its complete APER value.
func (c TraceStartIEValueProtocolIEContainerListValueCodec) New(value TraceStartIEValueProtocolIEContainerList) (TraceStartIEValueProtocolIEContainerListAPERValue, error) {
	if c.encode == nil {
		return TraceStartIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.ErrInvalidValue, "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return TraceStartIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return TraceStartIEValueProtocolIEContainerListAPERValue{}, aper.OperationError(aper.OperationError(err, c.path), "Value.New")
	}
	return TraceStartIEValueProtocolIEContainerListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete value and retains its received form.
func (c TraceStartIEValueProtocolIEContainerListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (TraceStartIEValueProtocolIEContainerListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil || c.capture == nil {
		return TraceStartIEValueProtocolIEContainerListAPERValue{}, aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	data, state := aper.StartDecode(data, options...)
	value, err := c.decode(data, state)
	if err == nil {
		value, replay := c.capture(value, state)
		report, err := aper.FinishDecode(state, nil)
		if err != nil {
			return TraceStartIEValueProtocolIEContainerListAPERValue{}, report, aper.OperationError(err, c.path)
		}
		return TraceStartIEValueProtocolIEContainerListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
	}
	report, err := aper.FinishDecode(state, aper.OperationError(err, c.path))
	return TraceStartIEValueProtocolIEContainerListAPERValue{}, report, err
}

// EncodeAPER encodes a complete value, replaying unchanged received forms.
func (c TraceStartIEValueProtocolIEContainerListValueCodec) EncodeAPER(value TraceStartIEValueProtocolIEContainerListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
	if c.encode == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, c.path)
	}
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, c.path)
	}
	fresh := value.withoutReplay || aper.EncodeWithoutReplay(options...)
	if value.context == c.context && !fresh && value.replay.Present() {
		plan, next := c.compare(value.Value, value.replay, budget)
		budget = next
		if err := aper.NewBudgetBuffer(&budget).CheckOutput(0); err != nil {
			return nil, aper.OperationError(err, c.path)
		}
		if plan.Unchanged(value.replay) {
			out, err := aper.CopyReplay(value.received, &budget)
			return out, aper.OperationError(err, c.path)
		}
		return c.encodeChanged(value.Value, fresh, budget, plan)
	}
	return c.encodeBudgetValue(value.Value, fresh, budget)
}
func (c TraceStartIEValueProtocolIEContainerListValueCodec) encodeBudgetValue(value TraceStartIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}
func (c TraceStartIEValueProtocolIEContainerListValueCodec) encodeChanged(value TraceStartIEValueProtocolIEContainerList, fresh bool, budget aper.DecodeBudget, plan aper.ReplayPlan) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	if failure := aper.NewBudgetBuffer(&budget).CheckOutput(0); failure != nil {
		err = failure
	}
	return out, aper.OperationError(err, c.path)
}

// TraceStartIEValueProtocolIEContainerList is ProtocolIE-ContainerList with IEsSetParam = {TraceStartIEs} of TS 36.413: a list of information element fields with lowerBound and upperBound supplied by its concrete factory.
type TraceStartIEValueProtocolIEContainerList []TraceStartIEValueProtocolIESingleContainer

func BridgeTraceStartIEValueCaptureS1APProtocolIEContainerList(v *TraceStartIEValueProtocolIEContainerList, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTraceStartIEValueCaptureS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, nil, false)
	}
	s.End(f, nil, false)
}
func BridgeTraceStartIEValueCompareS1APProtocolIEContainerList(v *TraceStartIEValueProtocolIEContainerList, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	{
		f := s.Begin()
		s.Elements(len((*v)))
		s.Uint(uint64(len((*v))))
		for i := range *v {
			if s.Err() != nil {
				break
			}
			BridgeTraceStartIEValueCompareS1APProtocolIESingleContainer(&(*v)[i], s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeHandoverRequestIEValueCaptureS1APProtocolIESingleContainer(v *s48.HandoverRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeHandoverRequestIEValueCompareS1APProtocolIESingleContainer(v *s48.HandoverRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// InitialContextSetupRequestIEValueERABIEContainerListAPERValue is the concrete APERValue[InitialContextSetupRequestIEValueERABIEContainerList].
type InitialContextSetupRequestIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialContextSetupRequestIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialContextSetupRequestIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupRequestIEValueERABIEContainerListAPERValue) WithoutReplay() InitialContextSetupRequestIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialContextSetupRequestIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{InitialContextSetupRequestIEs}} of TS 36.413: a single information element field.
type InitialContextSetupRequestIEValueProtocolIESingleContainer = InitialContextSetupRequestIEField

func BridgeInitialContextSetupRequestIEValueCaptureS1APProtocolIESingleContainer(v *InitialContextSetupRequestIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeInitialContextSetupRequestIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeInitialContextSetupRequestIEValueCompareS1APProtocolIESingleContainer(v *InitialContextSetupRequestIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeInitialContextSetupRequestIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// TraceStartIEValueERABIEContainerListAPERValue is the concrete APERValue[TraceStartIEValueERABIEContainerList].
type TraceStartIEValueERABIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TraceStartIEValueERABIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TraceStartIEValueERABIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceStartIEValueERABIEContainerListAPERValue) WithoutReplay() TraceStartIEValueERABIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TraceStartIEValueProtocolIESingleContainer is ProtocolIE-SingleContainer {{TraceStartIEs}} of TS 36.413: a single information element field.
type TraceStartIEValueProtocolIESingleContainer = TraceStartIEField

func BridgeTraceStartIEValueCaptureS1APProtocolIESingleContainer(v *TraceStartIEValueProtocolIESingleContainer, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeTraceStartIEValueCaptureS1APProtocolIEField(v, s)
	s.End(f, nil, false)
}
func BridgeTraceStartIEValueCompareS1APProtocolIESingleContainer(v *TraceStartIEValueProtocolIESingleContainer, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeTraceStartIEValueCompareS1APProtocolIEField(v, s)
	s.End(f, aper.Snapshot{}, false)
}

// InitialContextSetupRequestIEFieldAPERValue is the concrete APERValue[InitialContextSetupRequestIEField].
type InitialContextSetupRequestIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialContextSetupRequestIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialContextSetupRequestIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupRequestIEFieldAPERValue) WithoutReplay() InitialContextSetupRequestIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TraceStartIEFieldAPERValue is the concrete APERValue[TraceStartIEField].
type TraceStartIEFieldAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TraceStartIEField
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TraceStartIEFieldAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceStartIEFieldAPERValue) WithoutReplay() TraceStartIEFieldAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialContextSetupRequestIEContainerAPERValue is the concrete APERValue[InitialContextSetupRequestIEContainer].
type InitialContextSetupRequestIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialContextSetupRequestIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialContextSetupRequestIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupRequestIEContainerAPERValue) WithoutReplay() InitialContextSetupRequestIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TraceStartIEContainerAPERValue is the concrete APERValue[TraceStartIEContainer].
type TraceStartIEContainerAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TraceStartIEContainer
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TraceStartIEContainerAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceStartIEContainerAPERValue) WithoutReplay() TraceStartIEContainerAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[InitialContextSetupRequestIEValueProtocolErrorIEContainerList].
type InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialContextSetupRequestIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TraceStartIEValueProtocolErrorIEContainerListAPERValue is the concrete APERValue[TraceStartIEValueProtocolErrorIEContainerList].
type TraceStartIEValueProtocolErrorIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TraceStartIEValueProtocolErrorIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TraceStartIEValueProtocolErrorIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceStartIEValueProtocolErrorIEContainerListAPERValue) WithoutReplay() TraceStartIEValueProtocolErrorIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue is the concrete APERValue[InitialContextSetupRequestIEValueProtocolIEContainerList].
type InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         InitialContextSetupRequestIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue) WithoutReplay() InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TraceStartIEValueProtocolIEContainerListAPERValue is the concrete APERValue[TraceStartIEValueProtocolIEContainerList].
type TraceStartIEValueProtocolIEContainerListAPERValue struct {
	context       s00.BridgeCodecContext
	Value         TraceStartIEValueProtocolIEContainerList
	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, if one is available.
func (v TraceStartIEValueProtocolIEContainerListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that uses fresh encoding without changing the original.
func (v TraceStartIEValueProtocolIEContainerListAPERValue) WithoutReplay() TraceStartIEValueProtocolIEContainerListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}
func BridgeCaptureS1APHandoverRequest(v *HandoverRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverRequestIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APHandoverRequest(v *HandoverRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeHandoverRequestIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APInitialContextSetupRequest(v *InitialContextSetupRequest, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeInitialContextSetupRequestIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APInitialContextSetupRequest(v *InitialContextSetupRequest, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeInitialContextSetupRequestIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APInitialContextSetupRequestIEValue(v *InitialContextSetupRequestIEValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowMMEUES1APID == nil)
				if v.rowMMEUES1APID != nil {
					s00.BridgeCaptureS1APMMEUES1APID(v.rowMMEUES1APID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(8):
			{
				f := s.Begin()
				s.Bool(v.rowENBUES1APID == nil)
				if v.rowENBUES1APID != nil {
					s00.BridgeCaptureS1APENBUES1APID(v.rowENBUES1APID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(66):
			{
				f := s.Begin()
				s.Bool(v.rowUEaggregateMaximumBitrate == nil)
				if v.rowUEaggregateMaximumBitrate != nil {
					s36.BridgeCaptureS1APUEAggregateMaximumBitrate(v.rowUEaggregateMaximumBitrate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(24):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSetupListCtxtSUReq == nil)
				if v.rowERABToBeSetupListCtxtSUReq != nil {
					s30.BridgeCaptureS1APERABToBeSetupListCtxtSUReq(v.rowERABToBeSetupListCtxtSUReq, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(107):
			{
				f := s.Begin()
				s.Bool(v.rowUESecurityCapabilities == nil)
				if v.rowUESecurityCapabilities != nil {
					s37.BridgeCaptureS1APUESecurityCapabilities(v.rowUESecurityCapabilities, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(73):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityKey == nil)
				if v.rowSecurityKey != nil {
					s00.BridgeCaptureS1APSecurityKey(v.rowSecurityKey, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(25):
			{
				f := s.Begin()
				s.Bool(v.rowTraceActivation == nil)
				if v.rowTraceActivation != nil {
					s48.BridgeCaptureS1APTraceActivation(v.rowTraceActivation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(41):
			{
				f := s.Begin()
				s.Bool(v.rowHandoverRestrictionList == nil)
				if v.rowHandoverRestrictionList != nil {
					s43.BridgeCaptureS1APHandoverRestrictionList(v.rowHandoverRestrictionList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(74):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapability == nil)
				if v.rowUERadioCapability != nil {
					s00.BridgeCaptureS1APUERadioCapability(v.rowUERadioCapability, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(106):
			{
				f := s.Begin()
				s.Bool(v.rowSubscriberProfileIDforRFP == nil)
				if v.rowSubscriberProfileIDforRFP != nil {
					s00.BridgeCaptureS1APSubscriberProfileIDforRFP(v.rowSubscriberProfileIDforRFP, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(108):
			{
				f := s.Begin()
				s.Bool(v.rowCSFallbackIndicator == nil)
				if v.rowCSFallbackIndicator != nil {
					s00.BridgeCaptureS1APCSFallbackIndicator(v.rowCSFallbackIndicator, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(124):
			{
				f := s.Begin()
				s.Bool(v.rowSRVCCOperationPossible == nil)
				if v.rowSRVCCOperationPossible != nil {
					s00.BridgeCaptureS1APSRVCCOperationPossible(v.rowSRVCCOperationPossible, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(146):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipStatus == nil)
				if v.rowCSGMembershipStatus != nil {
					s00.BridgeCaptureS1APCSGMembershipStatus(v.rowCSGMembershipStatus, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(159):
			{
				f := s.Begin()
				s.Bool(v.rowRegisteredLAI == nil)
				if v.rowRegisteredLAI != nil {
					s18.BridgeCaptureS1APLAI(v.rowRegisteredLAI, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(75):
			{
				f := s.Begin()
				s.Bool(v.rowGUMMEIID == nil)
				if v.rowGUMMEIID != nil {
					s18.BridgeCaptureS1APGUMMEI(v.rowGUMMEIID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(158):
			{
				f := s.Begin()
				s.Bool(v.rowMMEUES1APID2 == nil)
				if v.rowMMEUES1APID2 != nil {
					s00.BridgeCaptureS1APMMEUES1APID(v.rowMMEUES1APID2, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(165):
			{
				f := s.Begin()
				s.Bool(v.rowManagementBasedMDTAllowed == nil)
				if v.rowManagementBasedMDTAllowed != nil {
					s00.BridgeCaptureS1APManagementBasedMDTAllowed(v.rowManagementBasedMDTAllowed, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(177):
			{
				f := s.Begin()
				s.Bool(v.rowManagementBasedMDTPLMNList == nil)
				if v.rowManagementBasedMDTPLMNList != nil {
					s00.BridgeCaptureS1APMDTPLMNList(v.rowManagementBasedMDTPLMNList, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(187):
			{
				f := s.Begin()
				s.Bool(v.rowAdditionalCSFallbackIndicator == nil)
				if v.rowAdditionalCSFallbackIndicator != nil {
					s00.BridgeCaptureS1APAdditionalCSFallbackIndicator(v.rowAdditionalCSFallbackIndicator, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(192):
			{
				f := s.Begin()
				s.Bool(v.rowMaskedIMEISV == nil)
				if v.rowMaskedIMEISV != nil {
					s00.BridgeCaptureS1APMaskedIMEISV(v.rowMaskedIMEISV, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(196):
			{
				f := s.Begin()
				s.Bool(v.rowExpectedUEBehaviour == nil)
				if v.rowExpectedUEBehaviour != nil {
					s18.BridgeCaptureS1APExpectedUEBehaviour(v.rowExpectedUEBehaviour, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(195):
			{
				f := s.Begin()
				s.Bool(v.rowProSeAuthorized == nil)
				if v.rowProSeAuthorized != nil {
					s20.BridgeCaptureS1APProSeAuthorized(v.rowProSeAuthorized, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(241):
			{
				f := s.Begin()
				s.Bool(v.rowUEUserPlaneCIoTSupportIndicator == nil)
				if v.rowUEUserPlaneCIoTSupportIndicator != nil {
					s00.BridgeCaptureS1APUEUserPlaneCIoTSupportIndicator(v.rowUEUserPlaneCIoTSupportIndicator, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(240):
			{
				f := s.Begin()
				s.Bool(v.rowV2XServicesAuthorized == nil)
				if v.rowV2XServicesAuthorized != nil {
					s47.BridgeCaptureS1APV2XServicesAuthorized(v.rowV2XServicesAuthorized, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(248):
			{
				f := s.Begin()
				s.Bool(v.rowUESidelinkAggregateMaximumBitrate == nil)
				if v.rowUESidelinkAggregateMaximumBitrate != nil {
					s38.BridgeCaptureS1APUESidelinkAggregateMaximumBitrate(v.rowUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(251):
			{
				f := s.Begin()
				s.Bool(v.rowEnhancedCoverageRestricted == nil)
				if v.rowEnhancedCoverageRestricted != nil {
					s00.BridgeCaptureS1APEnhancedCoverageRestricted(v.rowEnhancedCoverageRestricted, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(269):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESecurityCapabilities == nil)
				if v.rowNRUESecurityCapabilities != nil {
					s19.BridgeCaptureS1APNRUESecurityCapabilities(v.rowNRUESecurityCapabilities, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(271):
			{
				f := s.Begin()
				s.Bool(v.rowCEModeBRestricted == nil)
				if v.rowCEModeBRestricted != nil {
					s00.BridgeCaptureS1APCEModeBRestricted(v.rowCEModeBRestricted, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(277):
			{
				f := s.Begin()
				s.Bool(v.rowAerialUEsubscriptionInformation == nil)
				if v.rowAerialUEsubscriptionInformation != nil {
					s00.BridgeCaptureS1APAerialUEsubscriptionInformation(v.rowAerialUEsubscriptionInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(283):
			{
				f := s.Begin()
				s.Bool(v.rowPendingDataIndication == nil)
				if v.rowPendingDataIndication != nil {
					s00.BridgeCaptureS1APPendingDataIndication(v.rowPendingDataIndication, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(278):
			{
				f := s.Begin()
				s.Bool(v.rowSubscriptionBasedUEDifferentiationInfo == nil)
				if v.rowSubscriptionBasedUEDifferentiationInfo != nil {
					s31.BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(v.rowSubscriptionBasedUEDifferentiationInfo, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(299):
			{
				f := s.Begin()
				s.Bool(v.rowAdditionalRRMPriorityIndex == nil)
				if v.rowAdditionalRRMPriorityIndex != nil {
					s00.BridgeCaptureS1APAdditionalRRMPriorityIndex(v.rowAdditionalRRMPriorityIndex, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(301):
			{
				f := s.Begin()
				s.Bool(v.rowIABAuthorized == nil)
				if v.rowIABAuthorized != nil {
					s00.BridgeCaptureS1APIABAuthorized(v.rowIABAuthorized, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(306):
			{
				f := s.Begin()
				s.Bool(v.rowNRV2XServicesAuthorized == nil)
				if v.rowNRV2XServicesAuthorized != nil {
					s20.BridgeCaptureS1APNRV2XServicesAuthorized(v.rowNRV2XServicesAuthorized, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(307):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESidelinkAggregateMaximumBitrate == nil)
				if v.rowNRUESidelinkAggregateMaximumBitrate != nil {
					s20.BridgeCaptureS1APNRUESidelinkAggregateMaximumBitrate(v.rowNRUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(308):
			{
				f := s.Begin()
				s.Bool(v.rowPC5QoSParameters == nil)
				if v.rowPC5QoSParameters != nil {
					s24.BridgeCaptureS1APPC5QoSParameters(v.rowPC5QoSParameters, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(314):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityID == nil)
				if v.rowUERadioCapabilityID != nil {
					s00.BridgeCaptureS1APUERadioCapabilityID(v.rowUERadioCapabilityID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(354):
			{
				f := s.Begin()
				s.Bool(v.rowCoarseUELocation == nil)
				if v.rowCoarseUELocation != nil {
					s00.BridgeCaptureS1APCoarseUELocation(v.rowCoarseUELocation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(355):
			{
				f := s.Begin()
				s.Bool(v.rowTimeRefDistribution == nil)
				if v.rowTimeRefDistribution != nil {
					s00.BridgeCaptureS1APTimeRefDistribution(v.rowTimeRefDistribution, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v InitialContextSetupRequestIEValue) captureSemantics(s aper.SemanticCapture) InitialContextSetupRequestIEValue {
	BridgeCaptureS1APInitialContextSetupRequestIEValue(&v, &s)
	return v
}
func BridgeCompareS1APInitialContextSetupRequestIEValue(v *InitialContextSetupRequestIEValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowMMEUES1APID == nil)
				if v.rowMMEUES1APID != nil {
					s02.BridgeCompareS1APMMEUES1APID(v.rowMMEUES1APID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(8):
			{
				f := s.Begin()
				s.Bool(v.rowENBUES1APID == nil)
				if v.rowENBUES1APID != nil {
					s02.BridgeCompareS1APENBUES1APID(v.rowENBUES1APID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(66):
			{
				f := s.Begin()
				s.Bool(v.rowUEaggregateMaximumBitrate == nil)
				if v.rowUEaggregateMaximumBitrate != nil {
					s36.BridgeCompareS1APUEAggregateMaximumBitrate(v.rowUEaggregateMaximumBitrate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(24):
			{
				f := s.Begin()
				s.Bool(v.rowERABToBeSetupListCtxtSUReq == nil)
				if v.rowERABToBeSetupListCtxtSUReq != nil {
					s30.BridgeCompareS1APERABToBeSetupListCtxtSUReq(v.rowERABToBeSetupListCtxtSUReq, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(107):
			{
				f := s.Begin()
				s.Bool(v.rowUESecurityCapabilities == nil)
				if v.rowUESecurityCapabilities != nil {
					s37.BridgeCompareS1APUESecurityCapabilities(v.rowUESecurityCapabilities, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(73):
			{
				f := s.Begin()
				s.Bool(v.rowSecurityKey == nil)
				if v.rowSecurityKey != nil {
					s07.BridgeCompareS1APSecurityKey(v.rowSecurityKey, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(25):
			{
				f := s.Begin()
				s.Bool(v.rowTraceActivation == nil)
				if v.rowTraceActivation != nil {
					s48.BridgeCompareS1APTraceActivation(v.rowTraceActivation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(41):
			{
				f := s.Begin()
				s.Bool(v.rowHandoverRestrictionList == nil)
				if v.rowHandoverRestrictionList != nil {
					s43.BridgeCompareS1APHandoverRestrictionList(v.rowHandoverRestrictionList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(74):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapability == nil)
				if v.rowUERadioCapability != nil {
					s07.BridgeCompareS1APUERadioCapability(v.rowUERadioCapability, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(106):
			{
				f := s.Begin()
				s.Bool(v.rowSubscriberProfileIDforRFP == nil)
				if v.rowSubscriberProfileIDforRFP != nil {
					s07.BridgeCompareS1APSubscriberProfileIDforRFP(v.rowSubscriberProfileIDforRFP, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(108):
			{
				f := s.Begin()
				s.Bool(v.rowCSFallbackIndicator == nil)
				if v.rowCSFallbackIndicator != nil {
					s02.BridgeCompareS1APCSFallbackIndicator(v.rowCSFallbackIndicator, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(124):
			{
				f := s.Begin()
				s.Bool(v.rowSRVCCOperationPossible == nil)
				if v.rowSRVCCOperationPossible != nil {
					s06.BridgeCompareS1APSRVCCOperationPossible(v.rowSRVCCOperationPossible, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(146):
			{
				f := s.Begin()
				s.Bool(v.rowCSGMembershipStatus == nil)
				if v.rowCSGMembershipStatus != nil {
					s02.BridgeCompareS1APCSGMembershipStatus(v.rowCSGMembershipStatus, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(159):
			{
				f := s.Begin()
				s.Bool(v.rowRegisteredLAI == nil)
				if v.rowRegisteredLAI != nil {
					s18.BridgeCompareS1APLAI(v.rowRegisteredLAI, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(75):
			{
				f := s.Begin()
				s.Bool(v.rowGUMMEIID == nil)
				if v.rowGUMMEIID != nil {
					s18.BridgeCompareS1APGUMMEI(v.rowGUMMEIID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(158):
			{
				f := s.Begin()
				s.Bool(v.rowMMEUES1APID2 == nil)
				if v.rowMMEUES1APID2 != nil {
					s02.BridgeCompareS1APMMEUES1APID(v.rowMMEUES1APID2, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(165):
			{
				f := s.Begin()
				s.Bool(v.rowManagementBasedMDTAllowed == nil)
				if v.rowManagementBasedMDTAllowed != nil {
					s02.BridgeCompareS1APManagementBasedMDTAllowed(v.rowManagementBasedMDTAllowed, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(177):
			{
				f := s.Begin()
				s.Bool(v.rowManagementBasedMDTPLMNList == nil)
				if v.rowManagementBasedMDTPLMNList != nil {
					s07.BridgeCompareS1APMDTPLMNList(v.rowManagementBasedMDTPLMNList, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(187):
			{
				f := s.Begin()
				s.Bool(v.rowAdditionalCSFallbackIndicator == nil)
				if v.rowAdditionalCSFallbackIndicator != nil {
					s02.BridgeCompareS1APAdditionalCSFallbackIndicator(v.rowAdditionalCSFallbackIndicator, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(192):
			{
				f := s.Begin()
				s.Bool(v.rowMaskedIMEISV == nil)
				if v.rowMaskedIMEISV != nil {
					s02.BridgeCompareS1APMaskedIMEISV(v.rowMaskedIMEISV, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(196):
			{
				f := s.Begin()
				s.Bool(v.rowExpectedUEBehaviour == nil)
				if v.rowExpectedUEBehaviour != nil {
					s18.BridgeCompareS1APExpectedUEBehaviour(v.rowExpectedUEBehaviour, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(195):
			{
				f := s.Begin()
				s.Bool(v.rowProSeAuthorized == nil)
				if v.rowProSeAuthorized != nil {
					s20.BridgeCompareS1APProSeAuthorized(v.rowProSeAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(241):
			{
				f := s.Begin()
				s.Bool(v.rowUEUserPlaneCIoTSupportIndicator == nil)
				if v.rowUEUserPlaneCIoTSupportIndicator != nil {
					s07.BridgeCompareS1APUEUserPlaneCIoTSupportIndicator(v.rowUEUserPlaneCIoTSupportIndicator, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(240):
			{
				f := s.Begin()
				s.Bool(v.rowV2XServicesAuthorized == nil)
				if v.rowV2XServicesAuthorized != nil {
					s47.BridgeCompareS1APV2XServicesAuthorized(v.rowV2XServicesAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(248):
			{
				f := s.Begin()
				s.Bool(v.rowUESidelinkAggregateMaximumBitrate == nil)
				if v.rowUESidelinkAggregateMaximumBitrate != nil {
					s38.BridgeCompareS1APUESidelinkAggregateMaximumBitrate(v.rowUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(251):
			{
				f := s.Begin()
				s.Bool(v.rowEnhancedCoverageRestricted == nil)
				if v.rowEnhancedCoverageRestricted != nil {
					s02.BridgeCompareS1APEnhancedCoverageRestricted(v.rowEnhancedCoverageRestricted, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(269):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESecurityCapabilities == nil)
				if v.rowNRUESecurityCapabilities != nil {
					s19.BridgeCompareS1APNRUESecurityCapabilities(v.rowNRUESecurityCapabilities, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(271):
			{
				f := s.Begin()
				s.Bool(v.rowCEModeBRestricted == nil)
				if v.rowCEModeBRestricted != nil {
					s02.BridgeCompareS1APCEModeBRestricted(v.rowCEModeBRestricted, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(277):
			{
				f := s.Begin()
				s.Bool(v.rowAerialUEsubscriptionInformation == nil)
				if v.rowAerialUEsubscriptionInformation != nil {
					s02.BridgeCompareS1APAerialUEsubscriptionInformation(v.rowAerialUEsubscriptionInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(283):
			{
				f := s.Begin()
				s.Bool(v.rowPendingDataIndication == nil)
				if v.rowPendingDataIndication != nil {
					s02.BridgeCompareS1APPendingDataIndication(v.rowPendingDataIndication, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(278):
			{
				f := s.Begin()
				s.Bool(v.rowSubscriptionBasedUEDifferentiationInfo == nil)
				if v.rowSubscriptionBasedUEDifferentiationInfo != nil {
					s31.BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(v.rowSubscriptionBasedUEDifferentiationInfo, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(299):
			{
				f := s.Begin()
				s.Bool(v.rowAdditionalRRMPriorityIndex == nil)
				if v.rowAdditionalRRMPriorityIndex != nil {
					s02.BridgeCompareS1APAdditionalRRMPriorityIndex(v.rowAdditionalRRMPriorityIndex, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(301):
			{
				f := s.Begin()
				s.Bool(v.rowIABAuthorized == nil)
				if v.rowIABAuthorized != nil {
					s02.BridgeCompareS1APIABAuthorized(v.rowIABAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(306):
			{
				f := s.Begin()
				s.Bool(v.rowNRV2XServicesAuthorized == nil)
				if v.rowNRV2XServicesAuthorized != nil {
					s20.BridgeCompareS1APNRV2XServicesAuthorized(v.rowNRV2XServicesAuthorized, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(307):
			{
				f := s.Begin()
				s.Bool(v.rowNRUESidelinkAggregateMaximumBitrate == nil)
				if v.rowNRUESidelinkAggregateMaximumBitrate != nil {
					s20.BridgeCompareS1APNRUESidelinkAggregateMaximumBitrate(v.rowNRUESidelinkAggregateMaximumBitrate, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(308):
			{
				f := s.Begin()
				s.Bool(v.rowPC5QoSParameters == nil)
				if v.rowPC5QoSParameters != nil {
					s24.BridgeCompareS1APPC5QoSParameters(v.rowPC5QoSParameters, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(314):
			{
				f := s.Begin()
				s.Bool(v.rowUERadioCapabilityID == nil)
				if v.rowUERadioCapabilityID != nil {
					s07.BridgeCompareS1APUERadioCapabilityID(v.rowUERadioCapabilityID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(354):
			{
				f := s.Begin()
				s.Bool(v.rowCoarseUELocation == nil)
				if v.rowCoarseUELocation != nil {
					s02.BridgeCompareS1APCoarseUELocation(v.rowCoarseUELocation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(355):
			{
				f := s.Begin()
				s.Bool(v.rowTimeRefDistribution == nil)
				if v.rowTimeRefDistribution != nil {
					s07.BridgeCompareS1APTimeRefDistribution(v.rowTimeRefDistribution, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v InitialContextSetupRequestIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APInitialContextSetupRequestIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APTraceStart(v *TraceStart, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeTraceStartIEValueCaptureS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APTraceStart(v *TraceStart, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	BridgeTraceStartIEValueCompareS1APProtocolIEContainer(&v.ProtocolIEs, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureS1APTraceStartIEValue(v *TraceStartIEValue, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowMMEUES1APID == nil)
				if v.rowMMEUES1APID != nil {
					s00.BridgeCaptureS1APMMEUES1APID(v.rowMMEUES1APID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(8):
			{
				f := s.Begin()
				s.Bool(v.rowENBUES1APID == nil)
				if v.rowENBUES1APID != nil {
					s00.BridgeCaptureS1APENBUES1APID(v.rowENBUES1APID, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(25):
			{
				f := s.Begin()
				s.Bool(v.rowTraceActivation == nil)
				if v.rowTraceActivation != nil {
					s48.BridgeCaptureS1APTraceActivation(v.rowTraceActivation, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v TraceStartIEValue) captureSemantics(s aper.SemanticCapture) TraceStartIEValue {
	BridgeCaptureS1APTraceStartIEValue(&v, &s)
	return v
}
func BridgeCompareS1APTraceStartIEValue(v *TraceStartIEValue, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APProtocolIEID(&v.id, s)
	if v.isOpaque {
		s.Opaque(v.opaque)
	}
	s.Bool(v.isOpaque)
	if !(v.isOpaque) {
		switch v.id {
		case s00.ProtocolIEID(0):
			{
				f := s.Begin()
				s.Bool(v.rowMMEUES1APID == nil)
				if v.rowMMEUES1APID != nil {
					s02.BridgeCompareS1APMMEUES1APID(v.rowMMEUES1APID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(8):
			{
				f := s.Begin()
				s.Bool(v.rowENBUES1APID == nil)
				if v.rowENBUES1APID != nil {
					s02.BridgeCompareS1APENBUES1APID(v.rowENBUES1APID, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(25):
			{
				f := s.Begin()
				s.Bool(v.rowTraceActivation == nil)
				if v.rowTraceActivation != nil {
					s48.BridgeCompareS1APTraceActivation(v.rowTraceActivation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, false)
	s.CheckReceived(v.replay, v.received)
}
func (v TraceStartIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareS1APTraceStartIEValue(&v, &s)
	return s
}
func BridgeCaptureS1APWUSAssistanceInformation(v *WUSAssistanceInformation, s *aper.SemanticCapture) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s00.BridgeCaptureS1APPagingProbabilityInformation(&v.PagingProbabilityInformation, s)
	s.Bool(v.IEExtensions == nil)
	BridgeWUSAssistanceInformationExtIEsValueCaptureS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareS1APWUSAssistanceInformation(v *WUSAssistanceInformation, s *aper.SemanticComparison) {
	if s.Err() != nil {
		return
	}
	f := s.Begin()
	s02.BridgeCompareS1APPagingProbabilityInformation(&v.PagingProbabilityInformation, s)
	s.Bool(v.IEExtensions == nil)
	BridgeWUSAssistanceInformationExtIEsValueCompareS1APProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire, 0)
	s.End(f, v.replay, v.withoutReplay)
}

// WUSAssistanceInformation represents the ASN.1 type WUS-Assistance-Information (SEQUENCE).
type WUSAssistanceInformation struct {
	replay                       aper.Snapshot
	stream                       aper.WireSpan
	received                     bool
	withoutReplay                bool
	receivedAbsolute             bool
	receivedBytes                aper.WireSpan
	receivedLocation             aper.Location
	PagingProbabilityInformation s00.PagingProbabilityInformation               `asn1:"tag:0,context,implicit"`
	IEExtensions                 s12.WUSAssistanceInformationExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef            bool                                           `asn1:"-" json:"-"`
	extCount                     int64                                          `asn1:"-" json:"-"`
	extPresent                   []bool                                         `asn1:"-" json:"-"`
	extData                      [][]byte                                       `asn1:"-" json:"-"`
	perPadding                   aper.FinalPadding                              `asn1:"-" json:"-"`
	perExtPadding                []aper.CompletePadding                         `asn1:"-" json:"-"`
	extOrigin                    []aper.OpaqueOrigin
	extWire                      []aper.WireSpan
}

// MarshalAPER encodes WUSAssistanceInformation to APER format.
func (v *WUSAssistanceInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *WUSAssistanceInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
		if ok, err := v.stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s14.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
	}
	if err := aper.EncodeBoolean(bb, hasExtensions); err != nil {
		return err
	}
	// Preamble bitmap for optional root fields
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.PagingProbabilityInformation), 21, true); err != nil {
		return fmt.Errorf("encoding pagingProbabilityInformation: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s12.BridgeWUSAssistanceInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:437
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:441
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:448
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

// UnmarshalAPER decodes WUSAssistanceInformation from APER format.
func (v *WUSAssistanceInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes WUSAssistanceInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *WUSAssistanceInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "WUSAssistanceInformation")
	}
	bb.EnterComponent("WUSAssistanceInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "WUSAssistanceInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "WUSAssistanceInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "WUSAssistanceInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *WUSAssistanceInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = WUSAssistanceInformation{}
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
	val_pagingprobabilityinformation, err := aper.DecodeEnumeratedAligned(bb, 21, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PagingProbabilityInformation"})
	if err != nil {
		return runtime.WrapDecodePath(err, "PagingProbabilityInformation")
	}
	v.PagingProbabilityInformation = s00.PagingProbabilityInformation(val_pagingprobabilityinformation)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s12.WUSAssistanceInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s12.WUSAssistanceInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s12.BridgeWUSAssistanceInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:625
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:628
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.4"})
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
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
			v.extWire = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *WUSAssistanceInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "WUSAssistanceInformation", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "WUSAssistanceInformation", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v WUSAssistanceInformation) WithoutReplay() WUSAssistanceInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero WUSAssistanceInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *WUSAssistanceInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *WUSAssistanceInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("WUSAssistanceInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("WUSAssistanceInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *WUSAssistanceInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("WUSAssistanceInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("WUSAssistanceInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *WUSAssistanceInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "WUSAssistanceInformation")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *WUSAssistanceInformation) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "WUSAssistanceInformation")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APWUSAssistanceInformation(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "WUSAssistanceInformation")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "WUSAssistanceInformation")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *WUSAssistanceInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "WUSAssistanceInformation")
}
func (v *WUSAssistanceInformation) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "WUSAssistanceInformation")
}
func (v *WUSAssistanceInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APWUSAssistanceInformation(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *WUSAssistanceInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *WUSAssistanceInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *WUSAssistanceInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "WUSAssistanceInformation")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded WUSAssistanceInformation
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APWUSAssistanceInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = WUSAssistanceInformation{}
		return report, aper.OperationError(err, "WUSAssistanceInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "WUSAssistanceInformation")
}

// HandoverRequest represents the ASN.1 type HandoverRequest (SEQUENCE).
type HandoverRequest struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      s48.HandoverRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                           `asn1:"-" json:"-"`
	extCount         int64                          `asn1:"-" json:"-"`
	extPresent       []bool                         `asn1:"-" json:"-"`
	extData          [][]byte                       `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding              `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding         `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// InitialContextSetupRequest represents the ASN.1 type InitialContextSetupRequest (SEQUENCE).
type InitialContextSetupRequest struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      InitialContextSetupRequestIEContainer `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                                  `asn1:"-" json:"-"`
	extCount         int64                                 `asn1:"-" json:"-"`
	extPresent       []bool                                `asn1:"-" json:"-"`
	extData          [][]byte                              `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// TraceStart represents the ASN.1 type TraceStart (SEQUENCE).
type TraceStart struct {
	replay           aper.Snapshot
	stream           aper.WireSpan
	received         bool
	withoutReplay    bool
	receivedAbsolute bool
	receivedBytes    aper.WireSpan
	receivedLocation aper.Location
	ProtocolIEs      TraceStartIEContainer  `asn1:"tag:0,context,implicit"`
	protocolIEsIndef bool                   `asn1:"-" json:"-"`
	extCount         int64                  `asn1:"-" json:"-"`
	extPresent       []bool                 `asn1:"-" json:"-"`
	extData          [][]byte               `asn1:"-" json:"-"`
	perPadding       aper.FinalPadding      `asn1:"-" json:"-"`
	perExtPadding    []aper.CompletePadding `asn1:"-" json:"-"`
	extOrigin        []aper.OpaqueOrigin
	extWire          []aper.WireSpan
}

// MarshalAPER encodes HandoverRequest to APER format.
func (v *HandoverRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *HandoverRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s14.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
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
			if err := s48.BridgeHandoverRequestIEFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:437
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:441
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:448
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

// UnmarshalAPER decodes HandoverRequest from APER format.
func (v *HandoverRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes HandoverRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *HandoverRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequest")
	}
	bb.EnterComponent("HandoverRequest")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "HandoverRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "HandoverRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *HandoverRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = HandoverRequest{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(s48.HandoverRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem s48.HandoverRequestIEField
			elementMark := bb.EnterIndex(fragmentOffset_protocolies + i)
			if err := s48.BridgeHandoverRequestIEFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:625
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:628
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
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
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
			v.extWire = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes InitialContextSetupRequest to APER format.
func (v *InitialContextSetupRequest) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *InitialContextSetupRequest) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s14.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:437
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:441
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:448
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

// UnmarshalAPER decodes InitialContextSetupRequest from APER format.
func (v *InitialContextSetupRequest) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes InitialContextSetupRequest with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *InitialContextSetupRequest) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "InitialContextSetupRequest")
	}
	bb.EnterComponent("InitialContextSetupRequest")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "InitialContextSetupRequest")
	}
	padding, err := aper.CaptureFinalBits(bb, "InitialContextSetupRequest")
	if err != nil {
		return runtime.WrapDecodePath(err, "InitialContextSetupRequest")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *InitialContextSetupRequest) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = InitialContextSetupRequest{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(InitialContextSetupRequestIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem InitialContextSetupRequestIEField
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:625
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:628
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
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
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
			v.extWire = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// MarshalAPER encodes TraceStart to APER format.
func (v *TraceStart) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *TraceStart) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
			stream.
			ReplayTo(bb); ok || err != nil {
			return err
		}
	}
	extensionEncodingData, extensionCopyErr := aper.CopyExtensionContents(v.extData,
		v.extWire,

		bb.Budget())
	if extensionCopyErr != nil {
		return extensionCopyErr
	}

	if v.withoutReplay {
		fresh = []bool{true}
	}

	extensionCount := v.extCount
	if len(fresh) != 0 && fresh[0] {
		extensionCount, _ = s14.BridgePreferredSequenceTail(v.extPresent, extensionEncodingData)
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	recoveryStart := bb.BitsWritten()
	hasExtensions := false
	for i, present := range v.extPresent {
		if i >= 0 {
			hasExtensions = hasExtensions || present
		}
	}
	for i, data := range extensionEncodingData {
		if i >= 0 {
			hasExtensions = hasExtensions || data != nil
		}
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
		// arithmetic pattern APER_EXT_BITMAP_LENGTH: 0 <= extCount < 16383; gen/codegen_aper.go:437
		if extCount < 0 || extCount >= 16383 {
			return fmt.Errorf("%w: extension bitmap index %d", aper.ErrUnsupportedFragmentedNormallySmallLength, extCount)
		}
		if err := aper.EncodeNormallySmallLengthAligned(bb, extCount+1); err != nil {
			return err
		}
		// arithmetic pattern APER_EXT_VALUE_1: 0 <= extCount < max int; gen/codegen_aper.go:441
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			p := (i < int64(len(v.extPresent)) && v.extPresent[i]) || (i < int64(len(extensionEncodingData)) && extensionEncodingData[i] != nil)
			if err := aper.EncodeBoolean(bb, p); err != nil {
				return err
			}
		}
		// arithmetic pattern APER_EXT_VALUE_2: 0 <= extCount < max int; gen/codegen_aper.go:448
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

// UnmarshalAPER decodes TraceStart from APER format.
func (v *TraceStart) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes TraceStart with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *TraceStart) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "TraceStart")
	}
	bb.EnterComponent("TraceStart")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "TraceStart")
	}
	padding, err := aper.CaptureFinalBits(bb, "TraceStart")
	if err != nil {
		return runtime.WrapDecodePath(err, "TraceStart")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *TraceStart) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = TraceStart{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	toleranceMark_protocolies := bb.EnterComponent("ProtocolIEs")
	v.ProtocolIEs = make(TraceStartIEContainer, 0)
	_, errCollection_protocolies := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 0, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_protocolies, fragmentLength_protocolies int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1128
		if fragmentOffset_protocolies < 0 || fragmentLength_protocolies < 0 || fragmentLength_protocolies > int64(^uint(0)>>1) || fragmentOffset_protocolies > int64(^uint(0)>>1)-fragmentLength_protocolies {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_protocolies; i++ {
			var elem TraceStartIEField
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
		// arithmetic pattern APER_EXT_COUNT_ALLOC_3: 0 <= extCount < max int; gen/codegen_aper.go:625
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
		// arithmetic pattern APER_EXT_COUNT_LOOP_2: 0 <= extCount < max int; gen/codegen_aper.go:628
		if extCount < 0 || extCount >= int64(^uint(0)>>1) {
			return fmt.Errorf("extension count out of range")
		}
		for i := int64(0); i <= extCount; i++ {
			if extPresent[i] && extAdditions.Received(bb, i) {
				opaque, err := aper.DecodeOpaqueOpenTypeAligned(bb, aper.UnknownSelector, aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3"})
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
				v.extOrigin[i] = opaque.WithPath("Extensions").Origin()
			}
		}
		if extAdditions.Emptied() {
			v.extCount, v.extPresent, v.extData, v.perExtPadding = 0, nil, nil, nil
			v.extOrigin = nil
			v.extWire = nil
		}
	}

	{
		v.perPadding = extAdditions.Record(v.perPadding)
	}
	v.stream = bb.CaptureWireSpan(replayStart)

	return nil
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *HandoverRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "HandoverRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "HandoverRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v HandoverRequest) WithoutReplay() HandoverRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero HandoverRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *InitialContextSetupRequest) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "InitialContextSetupRequest", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "InitialContextSetupRequest", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v InitialContextSetupRequest) WithoutReplay() InitialContextSetupRequest {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero InitialContextSetupRequest
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *TraceStart) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	if v.receivedLocation.HasWireLocation {
		return s14.BridgeReceivedFormAt(v.received, v.receivedBytes, "TraceStart", v.receivedLocation, v.perPadding)
	}
	return aper.NewCompleteReceivedSpanForm(v.received, v.receivedBytes, "TraceStart", v.receivedAbsolute, v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v TraceStart) WithoutReplay() TraceStart {
	v.withoutReplay = true
	v.received = false
	v.receivedAbsolute = false
	v.receivedBytes = aper.WireSpan{}
	v.receivedLocation = aper.Location{}
	var zero TraceStart
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *HandoverRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *HandoverRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *HandoverRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("HandoverRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("HandoverRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *InitialContextSetupRequest) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *InitialContextSetupRequest) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("InitialContextSetupRequest.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("InitialContextSetupRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *InitialContextSetupRequest) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("InitialContextSetupRequest.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("InitialContextSetupRequest.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *TraceStart) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *TraceStart) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TraceStart.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TraceStart.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *TraceStart) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("TraceStart.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("TraceStart.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *HandoverRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "HandoverRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *HandoverRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "HandoverRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APHandoverRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "HandoverRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "HandoverRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *HandoverRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "HandoverRequest")
}
func (v *HandoverRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "HandoverRequest")
}
func (v *HandoverRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APHandoverRequest(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *HandoverRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *HandoverRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *InitialContextSetupRequest) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "InitialContextSetupRequest")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *InitialContextSetupRequest) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "InitialContextSetupRequest")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APInitialContextSetupRequest(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "InitialContextSetupRequest")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "InitialContextSetupRequest")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *InitialContextSetupRequest) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "InitialContextSetupRequest")
}
func (v *InitialContextSetupRequest) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "InitialContextSetupRequest")
}
func (v *InitialContextSetupRequest) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APInitialContextSetupRequest(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *InitialContextSetupRequest) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *InitialContextSetupRequest) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// MarshalAPER encodes a complete value using one per-call change plan.
func (v *TraceStart) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	budget, err := aper.EncodeBudgetValue(options...)
	if err != nil {
		return nil, aper.OperationError(err, "TraceStart")
	}
	return v.marshalAPERBudgetValue(budget, aper.EncodeWithoutReplay(options...))
}
func (v *TraceStart) marshalAPERBudgetValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "TraceStart")
	}
	fresh = fresh || v.withoutReplay
	if !fresh && v.replay.Present() {
		s := aper.NewSemanticComparison(v.replay, budget)
		BridgeCompareS1APTraceStart(v, &s)
		budget = s.BudgetValue()
		decisions := s.Plan()
		if s.Err() != nil {
			return nil, aper.OperationError(s.Err(), "TraceStart")
		}
		if decisions.Unchanged(v.replay) && v.received {
			out, err := aper.CopyReplay(v.receivedBytes, &budget)
			return out, aper.OperationError(err, "TraceStart")
		}
		return v.marshalAPERChangedValue(budget, fresh, decisions)
	}
	return v.marshalAPERNewValue(budget, fresh)
}
func (v *TraceStart) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, &plan)
	return out, aper.OperationError(err, "TraceStart")
}
func (v *TraceStart) marshalAPERNewValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	out, err := v.marshalAPERPlanned(&budget, fresh, nil)
	return out, aper.OperationError(err, "TraceStart")
}
func (v *TraceStart) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if !fresh && v.replay.Present() && plan == nil {
		s := aper.NewSemanticComparison(v.replay, *budget)
		BridgeCompareS1APTraceStart(v, &s)
		decisions := s.Plan()
		*budget = s.BudgetValue()
		if s.Err() != nil {
			return nil, s.Err()
		}
		if decisions.Unchanged(v.replay) && v.received {
			return aper.CopyReplay(v.receivedBytes, budget)
		}
		return v.marshalAPERChanged(budget, fresh, decisions)
	}
	if !fresh && plan != nil && plan.Unchanged(v.replay) && v.received {
		return aper.CopyReplay(v.receivedBytes, budget)
	}
	return v.marshalAPERPlanned(budget, fresh, plan)
}
func (v *TraceStart) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(budget, fresh, &plan)
}
func (v *TraceStart) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool, plan *aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(plan)
	defer budget.SetReplayPlan(previous)
	if fresh {
		budget.SetReplayPlan(nil)
	}
	bb := aper.NewBudgetBuffer(budget)
	if fresh {
		copy := v.WithoutReplay()
		v = &copy
	}
	if err := v.marshalAPERTo(bb, fresh); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *HandoverRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "HandoverRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded HandoverRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APHandoverRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = HandoverRequest{}
		return report, aper.OperationError(err, "HandoverRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "HandoverRequest")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *InitialContextSetupRequest) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "InitialContextSetupRequest")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded InitialContextSetupRequest
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APInitialContextSetupRequest(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = InitialContextSetupRequest{}
		return report, aper.OperationError(err, "InitialContextSetupRequest")
	}
	*v = decoded
	return report, aper.OperationError(nil, "InitialContextSetupRequest")
}

// UnmarshalAPER decodes one complete value and returns its report.
func (v *TraceStart) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "TraceStart")
	}
	data, state := aper.StartDecode(data, options...)
	var decoded TraceStart
	err := decoded.unmarshalAPERWithOptions(data, state)
	if err == nil {
		decoded.received = true
		decoded.receivedAbsolute = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(state)
		BridgeCaptureS1APTraceStart(&decoded, &s)
	}
	report, err := aper.FinishDecode(state, err)
	if err != nil {
		*v = TraceStart{}
		return report, aper.OperationError(err, "TraceStart")
	}
	*v = decoded
	return report, aper.OperationError(nil, "TraceStart")
}

type InitialContextSetupRequestIEValue struct {
	id                                        s00.ProtocolIEID
	received                                  aper.WireSpan
	replay                                    aper.Snapshot
	opaque                                    aper.OpaqueOpenType
	isOpaque                                  bool
	rowMMEUES1APID                            *s00.MMEUES1APID
	rowENBUES1APID                            *s00.ENBUES1APID
	rowUEaggregateMaximumBitrate              *s36.UEAggregateMaximumBitrate
	rowERABToBeSetupListCtxtSUReq             *s30.ERABToBeSetupListCtxtSUReq
	rowUESecurityCapabilities                 *s37.UESecurityCapabilities
	rowSecurityKey                            *s00.SecurityKey
	rowTraceActivation                        *s48.TraceActivation
	rowHandoverRestrictionList                *s43.HandoverRestrictionList
	rowUERadioCapability                      *s00.UERadioCapability
	rowSubscriberProfileIDforRFP              *s00.SubscriberProfileIDforRFP
	rowCSFallbackIndicator                    *s00.CSFallbackIndicator
	rowSRVCCOperationPossible                 *s00.SRVCCOperationPossible
	rowCSGMembershipStatus                    *s00.CSGMembershipStatus
	rowRegisteredLAI                          *s18.LAI
	rowGUMMEIID                               *s18.GUMMEI
	rowMMEUES1APID2                           *s00.MMEUES1APID
	rowManagementBasedMDTAllowed              *s00.ManagementBasedMDTAllowed
	rowManagementBasedMDTPLMNList             *s00.MDTPLMNList
	rowAdditionalCSFallbackIndicator          *s00.AdditionalCSFallbackIndicator
	rowMaskedIMEISV                           *s00.MaskedIMEISV
	rowExpectedUEBehaviour                    *s18.ExpectedUEBehaviour
	rowProSeAuthorized                        *s20.ProSeAuthorized
	rowUEUserPlaneCIoTSupportIndicator        *s00.UEUserPlaneCIoTSupportIndicator
	rowV2XServicesAuthorized                  *s47.V2XServicesAuthorized
	rowUESidelinkAggregateMaximumBitrate      *s38.UESidelinkAggregateMaximumBitrate
	rowEnhancedCoverageRestricted             *s00.EnhancedCoverageRestricted
	rowNRUESecurityCapabilities               *s19.NRUESecurityCapabilities
	rowCEModeBRestricted                      *s00.CEModeBRestricted
	rowAerialUEsubscriptionInformation        *s00.AerialUEsubscriptionInformation
	rowPendingDataIndication                  *s00.PendingDataIndication
	rowSubscriptionBasedUEDifferentiationInfo *s31.SubscriptionBasedUEDifferentiationInfo
	rowAdditionalRRMPriorityIndex             *s00.AdditionalRRMPriorityIndex
	rowIABAuthorized                          *s00.IABAuthorized
	rowNRV2XServicesAuthorized                *s20.NRV2XServicesAuthorized
	rowNRUESidelinkAggregateMaximumBitrate    *s20.NRUESidelinkAggregateMaximumBitrate
	rowPC5QoSParameters                       *s24.PC5QoSParameters
	rowUERadioCapabilityID                    *s00.UERadioCapabilityID
	rowCoarseUELocation                       *s00.CoarseUELocation
	rowTimeRefDistribution                    *s00.TimeRefDistribution
}

func (v InitialContextSetupRequestIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(0):
		return v.rowMMEUES1APID != nil
	case s00.ProtocolIEID(8):
		return v.rowENBUES1APID != nil
	case s00.ProtocolIEID(66):
		return v.rowUEaggregateMaximumBitrate != nil
	case s00.ProtocolIEID(24):
		return v.rowERABToBeSetupListCtxtSUReq != nil
	case s00.ProtocolIEID(107):
		return v.rowUESecurityCapabilities != nil
	case s00.ProtocolIEID(73):
		return v.rowSecurityKey != nil
	case s00.ProtocolIEID(25):
		return v.rowTraceActivation != nil
	case s00.ProtocolIEID(41):
		return v.rowHandoverRestrictionList != nil
	case s00.ProtocolIEID(74):
		return v.rowUERadioCapability != nil
	case s00.ProtocolIEID(106):
		return v.rowSubscriberProfileIDforRFP != nil
	case s00.ProtocolIEID(108):
		return v.rowCSFallbackIndicator != nil
	case s00.ProtocolIEID(124):
		return v.rowSRVCCOperationPossible != nil
	case s00.ProtocolIEID(146):
		return v.rowCSGMembershipStatus != nil
	case s00.ProtocolIEID(159):
		return v.rowRegisteredLAI != nil
	case s00.ProtocolIEID(75):
		return v.rowGUMMEIID != nil
	case s00.ProtocolIEID(158):
		return v.rowMMEUES1APID2 != nil
	case s00.ProtocolIEID(165):
		return v.rowManagementBasedMDTAllowed != nil
	case s00.ProtocolIEID(177):
		return v.rowManagementBasedMDTPLMNList != nil
	case s00.ProtocolIEID(187):
		return v.rowAdditionalCSFallbackIndicator != nil
	case s00.ProtocolIEID(192):
		return v.rowMaskedIMEISV != nil
	case s00.ProtocolIEID(196):
		return v.rowExpectedUEBehaviour != nil
	case s00.ProtocolIEID(195):
		return v.rowProSeAuthorized != nil
	case s00.ProtocolIEID(241):
		return v.rowUEUserPlaneCIoTSupportIndicator != nil
	case s00.ProtocolIEID(240):
		return v.rowV2XServicesAuthorized != nil
	case s00.ProtocolIEID(248):
		return v.rowUESidelinkAggregateMaximumBitrate != nil
	case s00.ProtocolIEID(251):
		return v.rowEnhancedCoverageRestricted != nil
	case s00.ProtocolIEID(269):
		return v.rowNRUESecurityCapabilities != nil
	case s00.ProtocolIEID(271):
		return v.rowCEModeBRestricted != nil
	case s00.ProtocolIEID(277):
		return v.rowAerialUEsubscriptionInformation != nil
	case s00.ProtocolIEID(283):
		return v.rowPendingDataIndication != nil
	case s00.ProtocolIEID(278):
		return v.rowSubscriptionBasedUEDifferentiationInfo != nil
	case s00.ProtocolIEID(299):
		return v.rowAdditionalRRMPriorityIndex != nil
	case s00.ProtocolIEID(301):
		return v.rowIABAuthorized != nil
	case s00.ProtocolIEID(306):
		return v.rowNRV2XServicesAuthorized != nil
	case s00.ProtocolIEID(307):
		return v.rowNRUESidelinkAggregateMaximumBitrate != nil
	case s00.ProtocolIEID(308):
		return v.rowPC5QoSParameters != nil
	case s00.ProtocolIEID(314):
		return v.rowUERadioCapabilityID != nil
	case s00.ProtocolIEID(354):
		return v.rowCoarseUELocation != nil
	case s00.ProtocolIEID(355):
		return v.rowTimeRefDistribution != nil
	}
	return false
}

// Opaque returns the retained opaque open value of InitialContextSetupRequestIEValue and reports whether the opaque alternative is selected.
func (v *InitialContextSetupRequestIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (InitialContextSetupRequestIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs"}}
}
func (InitialContextSetupRequestIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(66):
		return aper.UnknownSelector
	case s00.ProtocolIEID(24):
		return aper.UnknownSelector
	case s00.ProtocolIEID(107):
		return aper.UnknownSelector
	case s00.ProtocolIEID(73):
		return aper.UnknownSelector
	case s00.ProtocolIEID(25):
		return aper.UnknownSelector
	case s00.ProtocolIEID(41):
		return aper.UnknownSelector
	case s00.ProtocolIEID(74):
		return aper.UnknownSelector
	case s00.ProtocolIEID(106):
		return aper.UnknownSelector
	case s00.ProtocolIEID(108):
		return aper.UnknownSelector
	case s00.ProtocolIEID(124):
		return aper.UnknownSelector
	case s00.ProtocolIEID(146):
		return aper.UnknownSelector
	case s00.ProtocolIEID(159):
		return aper.UnknownSelector
	case s00.ProtocolIEID(75):
		return aper.UnknownSelector
	case s00.ProtocolIEID(158):
		return aper.UnknownSelector
	case s00.ProtocolIEID(165):
		return aper.UnknownSelector
	case s00.ProtocolIEID(177):
		return aper.UnknownSelector
	case s00.ProtocolIEID(187):
		return aper.UnknownSelector
	case s00.ProtocolIEID(192):
		return aper.UnknownSelector
	case s00.ProtocolIEID(196):
		return aper.UnknownSelector
	case s00.ProtocolIEID(195):
		return aper.UnknownSelector
	case s00.ProtocolIEID(241):
		return aper.UnknownSelector
	case s00.ProtocolIEID(240):
		return aper.UnknownSelector
	case s00.ProtocolIEID(248):
		return aper.UnknownSelector
	case s00.ProtocolIEID(251):
		return aper.UnknownSelector
	case s00.ProtocolIEID(269):
		return aper.UnknownSelector
	case s00.ProtocolIEID(271):
		return aper.UnknownSelector
	case s00.ProtocolIEID(277):
		return aper.UnknownSelector
	case s00.ProtocolIEID(283):
		return aper.UnknownSelector
	case s00.ProtocolIEID(278):
		return aper.UnknownSelector
	case s00.ProtocolIEID(299):
		return aper.UnknownSelector
	case s00.ProtocolIEID(301):
		return aper.UnknownSelector
	case s00.ProtocolIEID(306):
		return aper.UnknownSelector
	case s00.ProtocolIEID(307):
		return aper.UnknownSelector
	case s00.ProtocolIEID(308):
		return aper.UnknownSelector
	case s00.ProtocolIEID(314):
		return aper.UnknownSelector
	case s00.ProtocolIEID(354):
		return aper.UnknownSelector
	case s00.ProtocolIEID(355):
		return aper.UnknownSelector
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
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
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(43):
		return aper.NotInTable
	case s00.ProtocolIEID(44):
		return aper.NotInTable
	case s00.ProtocolIEID(46):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(80):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(109):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(151):
		return aper.NotInTable
	case s00.ProtocolIEID(152):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(179):
		return aper.NotInTable
	case s00.ProtocolIEID(180):
		return aper.NotInTable
	case s00.ProtocolIEID(181):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(198):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(211):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(217):
		return aper.NotInTable
	case s00.ProtocolIEID(218):
		return aper.NotInTable
	case s00.ProtocolIEID(219):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(239):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(323):
		return aper.NotInTable
	case s00.ProtocolIEID(324):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}

// AsMMEUES1APID returns the selected MMEUES1APID value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsUEaggregateMaximumBitrate returns the selected UEaggregateMaximumBitrate value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsUEaggregateMaximumBitrate() (*s36.UEAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(66) || v.rowUEaggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowUEaggregateMaximumBitrate, true
}

// AsERABToBeSetupListCtxtSUReq returns the selected ERABToBeSetupListCtxtSUReq value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsERABToBeSetupListCtxtSUReq() (*s30.ERABToBeSetupListCtxtSUReq, bool) {
	if v == nil || v.id != s00.ProtocolIEID(24) || v.rowERABToBeSetupListCtxtSUReq == nil {
		return nil, false
	}
	return v.rowERABToBeSetupListCtxtSUReq, true
}

// AsUESecurityCapabilities returns the selected UESecurityCapabilities value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsUESecurityCapabilities() (*s37.UESecurityCapabilities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(107) || v.rowUESecurityCapabilities == nil {
		return nil, false
	}
	return v.rowUESecurityCapabilities, true
}

// AsSecurityKey returns the selected SecurityKey value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsSecurityKey() (*s00.SecurityKey, bool) {
	if v == nil || v.id != s00.ProtocolIEID(73) || v.rowSecurityKey == nil {
		return nil, false
	}
	return v.rowSecurityKey, true
}

// AsTraceActivation returns the selected TraceActivation value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsTraceActivation() (*s48.TraceActivation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(25) || v.rowTraceActivation == nil {
		return nil, false
	}
	return v.rowTraceActivation, true
}

// AsHandoverRestrictionList returns the selected HandoverRestrictionList value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsHandoverRestrictionList() (*s43.HandoverRestrictionList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(41) || v.rowHandoverRestrictionList == nil {
		return nil, false
	}
	return v.rowHandoverRestrictionList, true
}

// AsUERadioCapability returns the selected UERadioCapability value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsUERadioCapability() (*s00.UERadioCapability, bool) {
	if v == nil || v.id != s00.ProtocolIEID(74) || v.rowUERadioCapability == nil {
		return nil, false
	}
	return v.rowUERadioCapability, true
}

// AsSubscriberProfileIDforRFP returns the selected SubscriberProfileIDforRFP value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsSubscriberProfileIDforRFP() (*s00.SubscriberProfileIDforRFP, bool) {
	if v == nil || v.id != s00.ProtocolIEID(106) || v.rowSubscriberProfileIDforRFP == nil {
		return nil, false
	}
	return v.rowSubscriberProfileIDforRFP, true
}

// AsCSFallbackIndicator returns the selected CSFallbackIndicator value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsCSFallbackIndicator() (*s00.CSFallbackIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(108) || v.rowCSFallbackIndicator == nil {
		return nil, false
	}
	return v.rowCSFallbackIndicator, true
}

// AsSRVCCOperationPossible returns the selected SRVCCOperationPossible value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsSRVCCOperationPossible() (*s00.SRVCCOperationPossible, bool) {
	if v == nil || v.id != s00.ProtocolIEID(124) || v.rowSRVCCOperationPossible == nil {
		return nil, false
	}
	return v.rowSRVCCOperationPossible, true
}

// AsCSGMembershipStatus returns the selected CSGMembershipStatus value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsCSGMembershipStatus() (*s00.CSGMembershipStatus, bool) {
	if v == nil || v.id != s00.ProtocolIEID(146) || v.rowCSGMembershipStatus == nil {
		return nil, false
	}
	return v.rowCSGMembershipStatus, true
}

// AsRegisteredLAI returns the selected RegisteredLAI value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsRegisteredLAI() (*s18.LAI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(159) || v.rowRegisteredLAI == nil {
		return nil, false
	}
	return v.rowRegisteredLAI, true
}

// AsGUMMEIID returns the selected GUMMEIID value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsGUMMEIID() (*s18.GUMMEI, bool) {
	if v == nil || v.id != s00.ProtocolIEID(75) || v.rowGUMMEIID == nil {
		return nil, false
	}
	return v.rowGUMMEIID, true
}

// AsMMEUES1APID2 returns the selected MMEUES1APID2 value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsMMEUES1APID2() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(158) || v.rowMMEUES1APID2 == nil {
		return nil, false
	}
	return v.rowMMEUES1APID2, true
}

// AsManagementBasedMDTAllowed returns the selected ManagementBasedMDTAllowed value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsManagementBasedMDTAllowed() (*s00.ManagementBasedMDTAllowed, bool) {
	if v == nil || v.id != s00.ProtocolIEID(165) || v.rowManagementBasedMDTAllowed == nil {
		return nil, false
	}
	return v.rowManagementBasedMDTAllowed, true
}

// AsManagementBasedMDTPLMNList returns the selected ManagementBasedMDTPLMNList value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsManagementBasedMDTPLMNList() (*s00.MDTPLMNList, bool) {
	if v == nil || v.id != s00.ProtocolIEID(177) || v.rowManagementBasedMDTPLMNList == nil {
		return nil, false
	}
	return v.rowManagementBasedMDTPLMNList, true
}

// AsAdditionalCSFallbackIndicator returns the selected AdditionalCSFallbackIndicator value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsAdditionalCSFallbackIndicator() (*s00.AdditionalCSFallbackIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(187) || v.rowAdditionalCSFallbackIndicator == nil {
		return nil, false
	}
	return v.rowAdditionalCSFallbackIndicator, true
}

// AsMaskedIMEISV returns the selected MaskedIMEISV value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsMaskedIMEISV() (*s00.MaskedIMEISV, bool) {
	if v == nil || v.id != s00.ProtocolIEID(192) || v.rowMaskedIMEISV == nil {
		return nil, false
	}
	return v.rowMaskedIMEISV, true
}

// AsExpectedUEBehaviour returns the selected ExpectedUEBehaviour value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsExpectedUEBehaviour() (*s18.ExpectedUEBehaviour, bool) {
	if v == nil || v.id != s00.ProtocolIEID(196) || v.rowExpectedUEBehaviour == nil {
		return nil, false
	}
	return v.rowExpectedUEBehaviour, true
}

// AsProSeAuthorized returns the selected ProSeAuthorized value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsProSeAuthorized() (*s20.ProSeAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(195) || v.rowProSeAuthorized == nil {
		return nil, false
	}
	return v.rowProSeAuthorized, true
}

// AsUEUserPlaneCIoTSupportIndicator returns the selected UEUserPlaneCIoTSupportIndicator value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsUEUserPlaneCIoTSupportIndicator() (*s00.UEUserPlaneCIoTSupportIndicator, bool) {
	if v == nil || v.id != s00.ProtocolIEID(241) || v.rowUEUserPlaneCIoTSupportIndicator == nil {
		return nil, false
	}
	return v.rowUEUserPlaneCIoTSupportIndicator, true
}

// AsV2XServicesAuthorized returns the selected V2XServicesAuthorized value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsV2XServicesAuthorized() (*s47.V2XServicesAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(240) || v.rowV2XServicesAuthorized == nil {
		return nil, false
	}
	return v.rowV2XServicesAuthorized, true
}

// AsUESidelinkAggregateMaximumBitrate returns the selected UESidelinkAggregateMaximumBitrate value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsUESidelinkAggregateMaximumBitrate() (*s38.UESidelinkAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(248) || v.rowUESidelinkAggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowUESidelinkAggregateMaximumBitrate, true
}

// AsEnhancedCoverageRestricted returns the selected EnhancedCoverageRestricted value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsEnhancedCoverageRestricted() (*s00.EnhancedCoverageRestricted, bool) {
	if v == nil || v.id != s00.ProtocolIEID(251) || v.rowEnhancedCoverageRestricted == nil {
		return nil, false
	}
	return v.rowEnhancedCoverageRestricted, true
}

// AsNRUESecurityCapabilities returns the selected NRUESecurityCapabilities value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsNRUESecurityCapabilities() (*s19.NRUESecurityCapabilities, bool) {
	if v == nil || v.id != s00.ProtocolIEID(269) || v.rowNRUESecurityCapabilities == nil {
		return nil, false
	}
	return v.rowNRUESecurityCapabilities, true
}

// AsCEModeBRestricted returns the selected CEModeBRestricted value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsCEModeBRestricted() (*s00.CEModeBRestricted, bool) {
	if v == nil || v.id != s00.ProtocolIEID(271) || v.rowCEModeBRestricted == nil {
		return nil, false
	}
	return v.rowCEModeBRestricted, true
}

// AsAerialUEsubscriptionInformation returns the selected AerialUEsubscriptionInformation value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsAerialUEsubscriptionInformation() (*s00.AerialUEsubscriptionInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(277) || v.rowAerialUEsubscriptionInformation == nil {
		return nil, false
	}
	return v.rowAerialUEsubscriptionInformation, true
}

// AsPendingDataIndication returns the selected PendingDataIndication value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsPendingDataIndication() (*s00.PendingDataIndication, bool) {
	if v == nil || v.id != s00.ProtocolIEID(283) || v.rowPendingDataIndication == nil {
		return nil, false
	}
	return v.rowPendingDataIndication, true
}

// AsSubscriptionBasedUEDifferentiationInfo returns the selected SubscriptionBasedUEDifferentiationInfo value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsSubscriptionBasedUEDifferentiationInfo() (*s31.SubscriptionBasedUEDifferentiationInfo, bool) {
	if v == nil || v.id != s00.ProtocolIEID(278) || v.rowSubscriptionBasedUEDifferentiationInfo == nil {
		return nil, false
	}
	return v.rowSubscriptionBasedUEDifferentiationInfo, true
}

// AsAdditionalRRMPriorityIndex returns the selected AdditionalRRMPriorityIndex value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsAdditionalRRMPriorityIndex() (*s00.AdditionalRRMPriorityIndex, bool) {
	if v == nil || v.id != s00.ProtocolIEID(299) || v.rowAdditionalRRMPriorityIndex == nil {
		return nil, false
	}
	return v.rowAdditionalRRMPriorityIndex, true
}

// AsIABAuthorized returns the selected IABAuthorized value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsIABAuthorized() (*s00.IABAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(301) || v.rowIABAuthorized == nil {
		return nil, false
	}
	return v.rowIABAuthorized, true
}

// AsNRV2XServicesAuthorized returns the selected NRV2XServicesAuthorized value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsNRV2XServicesAuthorized() (*s20.NRV2XServicesAuthorized, bool) {
	if v == nil || v.id != s00.ProtocolIEID(306) || v.rowNRV2XServicesAuthorized == nil {
		return nil, false
	}
	return v.rowNRV2XServicesAuthorized, true
}

// AsNRUESidelinkAggregateMaximumBitrate returns the selected NRUESidelinkAggregateMaximumBitrate value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsNRUESidelinkAggregateMaximumBitrate() (*s20.NRUESidelinkAggregateMaximumBitrate, bool) {
	if v == nil || v.id != s00.ProtocolIEID(307) || v.rowNRUESidelinkAggregateMaximumBitrate == nil {
		return nil, false
	}
	return v.rowNRUESidelinkAggregateMaximumBitrate, true
}

// AsPC5QoSParameters returns the selected PC5QoSParameters value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsPC5QoSParameters() (*s24.PC5QoSParameters, bool) {
	if v == nil || v.id != s00.ProtocolIEID(308) || v.rowPC5QoSParameters == nil {
		return nil, false
	}
	return v.rowPC5QoSParameters, true
}

// AsUERadioCapabilityID returns the selected UERadioCapabilityID value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsUERadioCapabilityID() (*s00.UERadioCapabilityID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(314) || v.rowUERadioCapabilityID == nil {
		return nil, false
	}
	return v.rowUERadioCapabilityID, true
}

// AsCoarseUELocation returns the selected CoarseUELocation value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsCoarseUELocation() (*s00.CoarseUELocation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(354) || v.rowCoarseUELocation == nil {
		return nil, false
	}
	return v.rowCoarseUELocation, true
}

// AsTimeRefDistribution returns the selected TimeRefDistribution value of InitialContextSetupRequestIEValue and reports whether that alternative is active.
func (v *InitialContextSetupRequestIEValue) AsTimeRefDistribution() (*s00.TimeRefDistribution, bool) {
	if v == nil || v.id != s00.ProtocolIEID(355) || v.rowTimeRefDistribution == nil {
		return nil, false
	}
	return v.rowTimeRefDistribution, true
}
func (v InitialContextSetupRequestIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (InitialContextSetupRequestIEValue, error) {
	out := InitialContextSetupRequestIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(0):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
		value := s00.MMEUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "MMEUES1APID:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowMMEUES1APID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(8):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false)
		value := s00.ENBUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ENBUES1APID:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowENBUES1APID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(66):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s36.UEAggregateMaximumBitrate
		child := scope
		if err := s36.BridgeUEAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UEaggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UEAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s36.BridgeUEAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s36.BridgeUEAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s36.BridgeUEAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s36.BridgeUEAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUEaggregateMaximumBitrate = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(24):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s41.BridgeUnmarshalAPERERABToBeSetupListCtxtSUReqFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ERABToBeSetupListCtxtSUReq:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowERABToBeSetupListCtxtSUReq = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(107):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s37.UESecurityCapabilities
		child := scope
		if err := s37.BridgeUESecurityCapabilitiesMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UESecurityCapabilities:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UESecurityCapabilities")
		if err != nil {
			return out, err
		}
		*s37.BridgeUESecurityCapabilitiesFieldPerPadding(&value) = padding
		*s37.BridgeUESecurityCapabilitiesFieldReceived(&value) = true
		raw.RetainContents(s37.BridgeUESecurityCapabilitiesFieldReceivedBytes(&value))
		*s37.BridgeUESecurityCapabilitiesFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUESecurityCapabilities = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(73):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.SecurityKey, error) {
			var v struct{ Value s00.SecurityKey }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 256, 256, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
				return nil
			}()
			return v.Value, err
		})(child)
		if err != nil {
			return out, err
		}
		if _, err := aper.CompleteOpenTypeValue(child, value); err != nil {
			return out, err
		}
		out.rowSecurityKey = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(25):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s48.TraceActivation
		child := scope
		if err := s48.BridgeTraceActivationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "TraceActivation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TraceActivation")
		if err != nil {
			return out, err
		}
		*s48.BridgeTraceActivationFieldPerPadding(&value) = padding
		*s48.BridgeTraceActivationFieldReceived(&value) = true
		raw.RetainContents(s48.BridgeTraceActivationFieldReceivedBytes(&value))
		*s48.BridgeTraceActivationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowTraceActivation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(41):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s43.HandoverRestrictionList
		child := scope
		if err := s43.BridgeHandoverRestrictionListMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "HandoverRestrictionList:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "HandoverRestrictionList")
		if err != nil {
			return out, err
		}
		*s43.BridgeHandoverRestrictionListFieldPerPadding(&value) = padding
		*s43.BridgeHandoverRestrictionListFieldReceived(&value) = true
		raw.RetainContents(s43.BridgeHandoverRestrictionListFieldReceivedBytes(&value))
		*s43.BridgeHandoverRestrictionListFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowHandoverRestrictionList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(74):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.UERadioCapability, error) {
			var v struct{ Value s00.UERadioCapability }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.UERadioCapability(val_value)
				return nil
			}()
			return v.Value, err
		})(child)
		if err != nil {
			return out, err
		}
		if _, err := aper.CompleteOpenTypeValue(child, value); err != nil {
			return out, err
		}
		out.rowUERadioCapability = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(106):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(1), s07.BridgeInt64Ptr(256), false)
		value := s00.SubscriberProfileIDforRFP(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SubscriberProfileIDforRFP:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowSubscriberProfileIDforRFP = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(108):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 1, Path: "CSFallbackIndicator"})
		value := s00.CSFallbackIndicator(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CSFallbackIndicator:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCSFallbackIndicator = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(124):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "SRVCCOperationPossible"})
		value := s00.SRVCCOperationPossible(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "SRVCCOperationPossible:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowSRVCCOperationPossible = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(146):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, false, aper.EnumerationSource{KnownExtensions: 0, Path: "CSGMembershipStatus"})
		value := s00.CSGMembershipStatus(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CSGMembershipStatus:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCSGMembershipStatus = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(159):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s18.LAI
		child := scope
		if err := s18.BridgeLAIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "RegisteredLAI:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "LAI")
		if err != nil {
			return out, err
		}
		*s18.BridgeLAIFieldPerPadding(&value) = padding
		*s18.BridgeLAIFieldReceived(&value) = true
		raw.RetainContents(s18.BridgeLAIFieldReceivedBytes(&value))
		*s18.BridgeLAIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowRegisteredLAI = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(75):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s18.GUMMEI
		child := scope
		if err := s18.BridgeGUMMEIMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "GUMMEIID:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "GUMMEI")
		if err != nil {
			return out, err
		}
		*s18.BridgeGUMMEIFieldPerPadding(&value) = padding
		*s18.BridgeGUMMEIFieldReceived(&value) = true
		raw.RetainContents(s18.BridgeGUMMEIFieldReceivedBytes(&value))
		*s18.BridgeGUMMEIFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowGUMMEIID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(158):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
		value := s00.MMEUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "MMEUES1APID2:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowMMEUES1APID2 = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(165):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "ManagementBasedMDTAllowed"})
		value := s00.ManagementBasedMDTAllowed(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ManagementBasedMDTAllowed:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowManagementBasedMDTAllowed = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(177):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		list, err := s42.BridgeUnmarshalAPERMDTPLMNListFrom(child)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ManagementBasedMDTPLMNList:", err)
		}
		padding, err := aper.CaptureOpenTypePadding(child)
		if err != nil {
			return out, err
		}
		_ = padding
		value := list
		out.rowManagementBasedMDTPLMNList = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(187):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "AdditionalCSFallbackIndicator"})
		value := s00.AdditionalCSFallbackIndicator(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "AdditionalCSFallbackIndicator:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowAdditionalCSFallbackIndicator = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(192):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.MaskedIMEISV, error) {
			var v struct{ Value s00.MaskedIMEISV }
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 64, 64, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
				return nil
			}()
			return v.Value, err
		})(child)
		if err != nil {
			return out, err
		}
		if _, err := aper.CompleteOpenTypeValue(child, value); err != nil {
			return out, err
		}
		out.rowMaskedIMEISV = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(196):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s18.ExpectedUEBehaviour
		child := scope
		if err := s18.BridgeExpectedUEBehaviourMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "ExpectedUEBehaviour:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ExpectedUEBehaviour")
		if err != nil {
			return out, err
		}
		*s18.BridgeExpectedUEBehaviourFieldPerPadding(&value) = padding
		*s18.BridgeExpectedUEBehaviourFieldReceived(&value) = true
		raw.RetainContents(s18.BridgeExpectedUEBehaviourFieldReceivedBytes(&value))
		*s18.BridgeExpectedUEBehaviourFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowExpectedUEBehaviour = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(195):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s20.ProSeAuthorized
		child := scope
		if err := s20.BridgeProSeAuthorizedMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "ProSeAuthorized:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "ProSeAuthorized")
		if err != nil {
			return out, err
		}
		*s20.BridgeProSeAuthorizedFieldPerPadding(&value) = padding
		*s20.BridgeProSeAuthorizedFieldReceived(&value) = true
		raw.RetainContents(s20.BridgeProSeAuthorizedFieldReceivedBytes(&value))
		*s20.BridgeProSeAuthorizedFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowProSeAuthorized = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(241):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "UEUserPlaneCIoTSupportIndicator"})
		value := s00.UEUserPlaneCIoTSupportIndicator(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "UEUserPlaneCIoTSupportIndicator:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowUEUserPlaneCIoTSupportIndicator = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(240):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s47.V2XServicesAuthorized
		child := scope
		if err := s47.BridgeV2XServicesAuthorizedMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "V2XServicesAuthorized:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "V2XServicesAuthorized")
		if err != nil {
			return out, err
		}
		*s47.BridgeV2XServicesAuthorizedFieldPerPadding(&value) = padding
		*s47.BridgeV2XServicesAuthorizedFieldReceived(&value) = true
		raw.RetainContents(s47.BridgeV2XServicesAuthorizedFieldReceivedBytes(&value))
		*s47.BridgeV2XServicesAuthorizedFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowV2XServicesAuthorized = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(248):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s38.UESidelinkAggregateMaximumBitrate
		child := scope
		if err := s38.BridgeUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "UESidelinkAggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "UESidelinkAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s38.BridgeUESidelinkAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s38.BridgeUESidelinkAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s38.BridgeUESidelinkAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s38.BridgeUESidelinkAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowUESidelinkAggregateMaximumBitrate = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(251):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "EnhancedCoverageRestricted"})
		value := s00.EnhancedCoverageRestricted(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "EnhancedCoverageRestricted:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowEnhancedCoverageRestricted = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(269):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s19.NRUESecurityCapabilities
		child := scope
		if err := s19.BridgeNRUESecurityCapabilitiesMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NRUESecurityCapabilities:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NRUESecurityCapabilities")
		if err != nil {
			return out, err
		}
		*s19.BridgeNRUESecurityCapabilitiesFieldPerPadding(&value) = padding
		*s19.BridgeNRUESecurityCapabilitiesFieldReceived(&value) = true
		raw.RetainContents(s19.BridgeNRUESecurityCapabilitiesFieldReceivedBytes(&value))
		*s19.BridgeNRUESecurityCapabilitiesFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowNRUESecurityCapabilities = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(271):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "CEModeBRestricted"})
		value := s00.CEModeBRestricted(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "CEModeBRestricted:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowCEModeBRestricted = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(277):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "AerialUEsubscriptionInformation"})
		value := s00.AerialUEsubscriptionInformation(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "AerialUEsubscriptionInformation:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowAerialUEsubscriptionInformation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(283):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "PendingDataIndication"})
		value := s00.PendingDataIndication(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "PendingDataIndication:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowPendingDataIndication = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(278):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s31.SubscriptionBasedUEDifferentiationInfo
		child := scope
		if err := s31.BridgeSubscriptionBasedUEDifferentiationInfoMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "SubscriptionBasedUEDifferentiationInfo:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "SubscriptionBasedUEDifferentiationInfo")
		if err != nil {
			return out, err
		}
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoFieldPerPadding(&value) = padding
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoFieldReceived(&value) = true
		raw.RetainContents(s31.BridgeSubscriptionBasedUEDifferentiationInfoFieldReceivedBytes(&value))
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowSubscriptionBasedUEDifferentiationInfo = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(299):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.AdditionalRRMPriorityIndex, error) {
			var v struct {
				Value s00.AdditionalRRMPriorityIndex
			}
			err := func() error {
				bsBytes_value, bsBitLen_value, err := aper.DecodeBitStringAligned(bb, 32, 32, true)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = runtime.BitString{Bytes: bsBytes_value, BitLength: bsBitLen_value}
				return nil
			}()
			return v.Value, err
		})(child)
		if err != nil {
			return out, err
		}
		if _, err := aper.CompleteOpenTypeValue(child, value); err != nil {
			return out, err
		}
		out.rowAdditionalRRMPriorityIndex = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(301):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "IABAuthorized"})
		value := s00.IABAuthorized(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "IABAuthorized:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowIABAuthorized = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(306):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s20.NRV2XServicesAuthorized
		child := scope
		if err := s20.BridgeNRV2XServicesAuthorizedMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NRV2XServicesAuthorized:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NRV2XServicesAuthorized")
		if err != nil {
			return out, err
		}
		*s20.BridgeNRV2XServicesAuthorizedFieldPerPadding(&value) = padding
		*s20.BridgeNRV2XServicesAuthorizedFieldReceived(&value) = true
		raw.RetainContents(s20.BridgeNRV2XServicesAuthorizedFieldReceivedBytes(&value))
		*s20.BridgeNRV2XServicesAuthorizedFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowNRV2XServicesAuthorized = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(307):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s20.NRUESidelinkAggregateMaximumBitrate
		child := scope
		if err := s20.BridgeNRUESidelinkAggregateMaximumBitrateMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "NRUESidelinkAggregateMaximumBitrate:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "NRUESidelinkAggregateMaximumBitrate")
		if err != nil {
			return out, err
		}
		*s20.BridgeNRUESidelinkAggregateMaximumBitrateFieldPerPadding(&value) = padding
		*s20.BridgeNRUESidelinkAggregateMaximumBitrateFieldReceived(&value) = true
		raw.RetainContents(s20.BridgeNRUESidelinkAggregateMaximumBitrateFieldReceivedBytes(&value))
		*s20.BridgeNRUESidelinkAggregateMaximumBitrateFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowNRUESidelinkAggregateMaximumBitrate = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(308):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s24.PC5QoSParameters
		child := scope
		if err := s24.BridgePC5QoSParametersMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "PC5QoSParameters:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "PC5QoSParameters")
		if err != nil {
			return out, err
		}
		*s24.BridgePC5QoSParametersFieldPerPadding(&value) = padding
		*s24.BridgePC5QoSParametersFieldReceived(&value) = true
		raw.RetainContents(s24.BridgePC5QoSParametersFieldReceivedBytes(&value))
		*s24.BridgePC5QoSParametersFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowPC5QoSParameters = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(314):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.UERadioCapabilityID, error) {
			var v struct{ Value s00.UERadioCapabilityID }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.UERadioCapabilityID(val_value)
				return nil
			}()
			return v.Value, err
		})(child)
		if err != nil {
			return out, err
		}
		if _, err := aper.CompleteOpenTypeValue(child, value); err != nil {
			return out, err
		}
		out.rowUERadioCapabilityID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(354):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		child := scope
		value, err := (func(bb *aper.BitBuffer) (s00.CoarseUELocation, error) {
			var v struct{ Value s00.CoarseUELocation }
			err := func() error {
				val_value, err := aper.DecodeOctetStringAligned(bb, 0, 0, false)
				if err != nil {
					return runtime.WrapDecodePath(err, "Value")
				}
				v.Value = s00.CoarseUELocation(val_value)
				return nil
			}()
			return v.Value, err
		})(child)
		if err != nil {
			return out, err
		}
		if _, err := aper.CompleteOpenTypeValue(child, value); err != nil {
			return out, err
		}
		out.rowCoarseUELocation = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(355):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeEnumeratedAligned(bb, 1, true, aper.EnumerationSource{KnownExtensions: 0, Path: "TimeRefDistribution"})
		value := s00.TimeRefDistribution(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "TimeRefDistribution:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowTimeRefDistribution = &value
		raw.RetainContents(&out.received)
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v InitialContextSetupRequestIEValue) encode() ([]byte, error) {
	return v.encodeFresh(false, nil)
}
func (v InitialContextSetupRequestIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if budget == nil {
		var err error
		budget, err = aper.EncodeBudget()
		if err != nil {
			return nil, err
		}
	}
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	case s00.ProtocolIEID(0):
		if v.rowMMEUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-MME-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(8):
		if v.rowENBUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-eNB-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(66):
		if v.rowUEaggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-uEaggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s36.BridgeUEAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowUEaggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(24):
		if v.rowERABToBeSetupListCtxtSUReq == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-E-RABToBeSetupListCtxtSUReq:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s41.ERABToBeSetupListCtxtSUReqComplete{Value: *v.rowERABToBeSetupListCtxtSUReq}
		candidate, err := s41.BridgeERABToBeSetupListCtxtSUReqCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(107):
		if v.rowUESecurityCapabilities == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-UESecurityCapabilities:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s37.BridgeUESecurityCapabilitiesMethodMarshalAPERBudget(v.rowUESecurityCapabilities, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(73):
		if v.rowSecurityKey == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-SecurityKey:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.SecurityKey, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.SecurityKey }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 256, 256, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowSecurityKey, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(25):
		if v.rowTraceActivation == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-TraceActivation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s48.BridgeTraceActivationMethodMarshalAPERBudget(v.rowTraceActivation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(41):
		if v.rowHandoverRestrictionList == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-HandoverRestrictionList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s43.BridgeHandoverRestrictionListMethodMarshalAPERBudget(v.rowHandoverRestrictionList, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(74):
		if v.rowUERadioCapability == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-UERadioCapability:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.UERadioCapability, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.UERadioCapability }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 0, 0, false); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowUERadioCapability, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(106):
		if v.rowSubscriberProfileIDforRFP == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-SubscriberProfileIDforRFP:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowSubscriberProfileIDforRFP), s07.BridgeInt64Ptr(1), s07.BridgeInt64Ptr(256), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(108):
		if v.rowCSFallbackIndicator == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-CSFallbackIndicator:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCSFallbackIndicator), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(124):
		if v.rowSRVCCOperationPossible == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-SRVCCOperationPossible:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowSRVCCOperationPossible), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(146):
		if v.rowCSGMembershipStatus == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-CSGMembershipStatus:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCSGMembershipStatus), 2, false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(159):
		if v.rowRegisteredLAI == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-RegisteredLAI:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeLAIMethodMarshalAPERBudget(v.rowRegisteredLAI, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(75):
		if v.rowGUMMEIID == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-GUMMEI-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeGUMMEIMethodMarshalAPERBudget(v.rowGUMMEIID, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(158):
		if v.rowMMEUES1APID2 == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-MME-UE-S1AP-ID-2:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID2), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(165):
		if v.rowManagementBasedMDTAllowed == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-ManagementBasedMDTAllowed:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowManagementBasedMDTAllowed), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(177):
		if v.rowManagementBasedMDTPLMNList == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-ManagementBasedMDTPLMNList:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		complete := s42.MDTPLMNListComplete{Value: *v.rowManagementBasedMDTPLMNList}
		candidate, err := s42.BridgeMDTPLMNListCompleteMethodMarshalAPERBudget(&complete, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(187):
		if v.rowAdditionalCSFallbackIndicator == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-AdditionalCSFallbackIndicator:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowAdditionalCSFallbackIndicator), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(192):
		if v.rowMaskedIMEISV == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-Masked-IMEISV:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.MaskedIMEISV, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.MaskedIMEISV }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 64, 64, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowMaskedIMEISV, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(196):
		if v.rowExpectedUEBehaviour == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-ExpectedUEBehaviour:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s18.BridgeExpectedUEBehaviourMethodMarshalAPERBudget(v.rowExpectedUEBehaviour, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(195):
		if v.rowProSeAuthorized == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-ProSeAuthorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s20.BridgeProSeAuthorizedMethodMarshalAPERBudget(v.rowProSeAuthorized, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(241):
		if v.rowUEUserPlaneCIoTSupportIndicator == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-UEUserPlaneCIoTSupportIndicator:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowUEUserPlaneCIoTSupportIndicator), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(240):
		if v.rowV2XServicesAuthorized == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-V2XServicesAuthorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s47.BridgeV2XServicesAuthorizedMethodMarshalAPERBudget(v.rowV2XServicesAuthorized, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(248):
		if v.rowUESidelinkAggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-UESidelinkAggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s38.BridgeUESidelinkAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowUESidelinkAggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(251):
		if v.rowEnhancedCoverageRestricted == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-EnhancedCoverageRestricted:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowEnhancedCoverageRestricted), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(269):
		if v.rowNRUESecurityCapabilities == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-NRUESecurityCapabilities:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s19.BridgeNRUESecurityCapabilitiesMethodMarshalAPERBudget(v.rowNRUESecurityCapabilities, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(271):
		if v.rowCEModeBRestricted == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-CE-ModeBRestricted:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowCEModeBRestricted), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(277):
		if v.rowAerialUEsubscriptionInformation == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-AerialUEsubscriptionInformation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowAerialUEsubscriptionInformation), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(283):
		if v.rowPendingDataIndication == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-PendingDataIndication:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowPendingDataIndication), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(278):
		if v.rowSubscriptionBasedUEDifferentiationInfo == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-Subscription-Based-UE-DifferentiationInfo:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s31.BridgeSubscriptionBasedUEDifferentiationInfoMethodMarshalAPERBudget(v.rowSubscriptionBasedUEDifferentiationInfo, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(299):
		if v.rowAdditionalRRMPriorityIndex == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-AdditionalRRMPriorityIndex:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.AdditionalRRMPriorityIndex, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct {
				Value s00.AdditionalRRMPriorityIndex
			}{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeBitStringAligned(bb, v.Value.Bytes, v.Value.BitLength, 32, 32, true); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowAdditionalRRMPriorityIndex, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(301):
		if v.rowIABAuthorized == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-IAB-Authorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowIABAuthorized), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(306):
		if v.rowNRV2XServicesAuthorized == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-NRV2XServicesAuthorized:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s20.BridgeNRV2XServicesAuthorizedMethodMarshalAPERBudget(v.rowNRV2XServicesAuthorized, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(307):
		if v.rowNRUESidelinkAggregateMaximumBitrate == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-NRUESidelinkAggregateMaximumBitrate:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s20.BridgeNRUESidelinkAggregateMaximumBitrateMethodMarshalAPERBudget(v.rowNRUESidelinkAggregateMaximumBitrate, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(308):
		if v.rowPC5QoSParameters == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-PC5QoSParameters:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s24.BridgePC5QoSParametersMethodMarshalAPERBudget(v.rowPC5QoSParameters, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(314):
		if v.rowUERadioCapabilityID == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-UERadioCapabilityID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.UERadioCapabilityID, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.UERadioCapabilityID }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 0, 0, false); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowUERadioCapabilityID, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(354):
		if v.rowCoarseUELocation == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-CoarseUELocation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := (func(value s00.CoarseUELocation, budget *aper.DecodeBudget) ([]byte, error) {
			bb := aper.NewBudgetBuffer(budget)
			v := struct{ Value s00.CoarseUELocation }{Value: value}
			_ = v
			err := func() error {
				if err := aper.EncodeOctetStringAligned(bb, []byte(v.Value), 0, 0, false); err != nil {
					return fmt.Errorf("encoding value: %w", err)
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			return bb.CompleteBytes(), nil
		})(*v.rowCoarseUELocation, budget)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	case s00.ProtocolIEID(355):
		if v.rowTimeRefDistribution == nil {
			return nil, fmt.Errorf("%s missing value", "InitialContextSetupRequestIEs.id-TimeRefDistribution:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowTimeRefDistribution), 1, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "InitialContextSetupRequestIEValue:", v.id)
	}
}

type TraceStartIEValue struct {
	id                 s00.ProtocolIEID
	received           aper.WireSpan
	replay             aper.Snapshot
	opaque             aper.OpaqueOpenType
	isOpaque           bool
	rowMMEUES1APID     *s00.MMEUES1APID
	rowENBUES1APID     *s00.ENBUES1APID
	rowTraceActivation *s48.TraceActivation
}

func (v TraceStartIEValue) matchesID(id s00.ProtocolIEID, _ ...*aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return true
	}
	switch id {
	case s00.ProtocolIEID(0):
		return v.rowMMEUES1APID != nil
	case s00.ProtocolIEID(8):
		return v.rowENBUES1APID != nil
	case s00.ProtocolIEID(25):
		return v.rowTraceActivation != nil
	}
	return false
}

// Opaque returns the retained opaque open value of TraceStartIEValue and reports whether the opaque alternative is selected.
func (v *TraceStartIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque {
		return aper.OpaqueOpenType{}, false
	}
	return v.opaque, true
}
func (TraceStartIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TraceStartIEs"}}
}
func (TraceStartIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(0):
		return aper.UnknownSelector
	case s00.ProtocolIEID(8):
		return aper.UnknownSelector
	case s00.ProtocolIEID(25):
		return aper.UnknownSelector
	case s00.ProtocolIEID(1):
		return aper.NotInTable
	case s00.ProtocolIEID(2):
		return aper.NotInTable
	case s00.ProtocolIEID(4):
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
	case s00.ProtocolIEID(26):
		return aper.NotInTable
	case s00.ProtocolIEID(27):
		return aper.NotInTable
	case s00.ProtocolIEID(28):
		return aper.NotInTable
	case s00.ProtocolIEID(29):
		return aper.NotInTable
	case s00.ProtocolIEID(30):
		return aper.NotInTable
	case s00.ProtocolIEID(31):
		return aper.NotInTable
	case s00.ProtocolIEID(32):
		return aper.NotInTable
	case s00.ProtocolIEID(33):
		return aper.NotInTable
	case s00.ProtocolIEID(34):
		return aper.NotInTable
	case s00.ProtocolIEID(35):
		return aper.NotInTable
	case s00.ProtocolIEID(36):
		return aper.NotInTable
	case s00.ProtocolIEID(37):
		return aper.NotInTable
	case s00.ProtocolIEID(39):
		return aper.NotInTable
	case s00.ProtocolIEID(40):
		return aper.NotInTable
	case s00.ProtocolIEID(41):
		return aper.NotInTable
	case s00.ProtocolIEID(43):
		return aper.NotInTable
	case s00.ProtocolIEID(44):
		return aper.NotInTable
	case s00.ProtocolIEID(46):
		return aper.NotInTable
	case s00.ProtocolIEID(47):
		return aper.NotInTable
	case s00.ProtocolIEID(48):
		return aper.NotInTable
	case s00.ProtocolIEID(50):
		return aper.NotInTable
	case s00.ProtocolIEID(51):
		return aper.NotInTable
	case s00.ProtocolIEID(52):
		return aper.NotInTable
	case s00.ProtocolIEID(53):
		return aper.NotInTable
	case s00.ProtocolIEID(58):
		return aper.NotInTable
	case s00.ProtocolIEID(59):
		return aper.NotInTable
	case s00.ProtocolIEID(60):
		return aper.NotInTable
	case s00.ProtocolIEID(61):
		return aper.NotInTable
	case s00.ProtocolIEID(64):
		return aper.NotInTable
	case s00.ProtocolIEID(65):
		return aper.NotInTable
	case s00.ProtocolIEID(66):
		return aper.NotInTable
	case s00.ProtocolIEID(67):
		return aper.NotInTable
	case s00.ProtocolIEID(69):
		return aper.NotInTable
	case s00.ProtocolIEID(70):
		return aper.NotInTable
	case s00.ProtocolIEID(71):
		return aper.NotInTable
	case s00.ProtocolIEID(72):
		return aper.NotInTable
	case s00.ProtocolIEID(73):
		return aper.NotInTable
	case s00.ProtocolIEID(74):
		return aper.NotInTable
	case s00.ProtocolIEID(75):
		return aper.NotInTable
	case s00.ProtocolIEID(78):
		return aper.NotInTable
	case s00.ProtocolIEID(79):
		return aper.NotInTable
	case s00.ProtocolIEID(80):
		return aper.NotInTable
	case s00.ProtocolIEID(83):
		return aper.NotInTable
	case s00.ProtocolIEID(84):
		return aper.NotInTable
	case s00.ProtocolIEID(86):
		return aper.NotInTable
	case s00.ProtocolIEID(87):
		return aper.NotInTable
	case s00.ProtocolIEID(88):
		return aper.NotInTable
	case s00.ProtocolIEID(89):
		return aper.NotInTable
	case s00.ProtocolIEID(90):
		return aper.NotInTable
	case s00.ProtocolIEID(91):
		return aper.NotInTable
	case s00.ProtocolIEID(92):
		return aper.NotInTable
	case s00.ProtocolIEID(93):
		return aper.NotInTable
	case s00.ProtocolIEID(94):
		return aper.NotInTable
	case s00.ProtocolIEID(95):
		return aper.NotInTable
	case s00.ProtocolIEID(96):
		return aper.NotInTable
	case s00.ProtocolIEID(97):
		return aper.NotInTable
	case s00.ProtocolIEID(98):
		return aper.NotInTable
	case s00.ProtocolIEID(99):
		return aper.NotInTable
	case s00.ProtocolIEID(100):
		return aper.NotInTable
	case s00.ProtocolIEID(101):
		return aper.NotInTable
	case s00.ProtocolIEID(102):
		return aper.NotInTable
	case s00.ProtocolIEID(104):
		return aper.NotInTable
	case s00.ProtocolIEID(105):
		return aper.NotInTable
	case s00.ProtocolIEID(106):
		return aper.NotInTable
	case s00.ProtocolIEID(107):
		return aper.NotInTable
	case s00.ProtocolIEID(108):
		return aper.NotInTable
	case s00.ProtocolIEID(109):
		return aper.NotInTable
	case s00.ProtocolIEID(110):
		return aper.NotInTable
	case s00.ProtocolIEID(111):
		return aper.NotInTable
	case s00.ProtocolIEID(112):
		return aper.NotInTable
	case s00.ProtocolIEID(113):
		return aper.NotInTable
	case s00.ProtocolIEID(114):
		return aper.NotInTable
	case s00.ProtocolIEID(115):
		return aper.NotInTable
	case s00.ProtocolIEID(116):
		return aper.NotInTable
	case s00.ProtocolIEID(117):
		return aper.NotInTable
	case s00.ProtocolIEID(118):
		return aper.NotInTable
	case s00.ProtocolIEID(119):
		return aper.NotInTable
	case s00.ProtocolIEID(120):
		return aper.NotInTable
	case s00.ProtocolIEID(121):
		return aper.NotInTable
	case s00.ProtocolIEID(122):
		return aper.NotInTable
	case s00.ProtocolIEID(123):
		return aper.NotInTable
	case s00.ProtocolIEID(124):
		return aper.NotInTable
	case s00.ProtocolIEID(125):
		return aper.NotInTable
	case s00.ProtocolIEID(127):
		return aper.NotInTable
	case s00.ProtocolIEID(128):
		return aper.NotInTable
	case s00.ProtocolIEID(129):
		return aper.NotInTable
	case s00.ProtocolIEID(130):
		return aper.NotInTable
	case s00.ProtocolIEID(131):
		return aper.NotInTable
	case s00.ProtocolIEID(132):
		return aper.NotInTable
	case s00.ProtocolIEID(133):
		return aper.NotInTable
	case s00.ProtocolIEID(134):
		return aper.NotInTable
	case s00.ProtocolIEID(135):
		return aper.NotInTable
	case s00.ProtocolIEID(136):
		return aper.NotInTable
	case s00.ProtocolIEID(137):
		return aper.NotInTable
	case s00.ProtocolIEID(138):
		return aper.NotInTable
	case s00.ProtocolIEID(139):
		return aper.NotInTable
	case s00.ProtocolIEID(140):
		return aper.NotInTable
	case s00.ProtocolIEID(141):
		return aper.NotInTable
	case s00.ProtocolIEID(142):
		return aper.NotInTable
	case s00.ProtocolIEID(143):
		return aper.NotInTable
	case s00.ProtocolIEID(144):
		return aper.NotInTable
	case s00.ProtocolIEID(145):
		return aper.NotInTable
	case s00.ProtocolIEID(146):
		return aper.NotInTable
	case s00.ProtocolIEID(147):
		return aper.NotInTable
	case s00.ProtocolIEID(148):
		return aper.NotInTable
	case s00.ProtocolIEID(149):
		return aper.NotInTable
	case s00.ProtocolIEID(150):
		return aper.NotInTable
	case s00.ProtocolIEID(151):
		return aper.NotInTable
	case s00.ProtocolIEID(152):
		return aper.NotInTable
	case s00.ProtocolIEID(153):
		return aper.NotInTable
	case s00.ProtocolIEID(154):
		return aper.NotInTable
	case s00.ProtocolIEID(155):
		return aper.NotInTable
	case s00.ProtocolIEID(156):
		return aper.NotInTable
	case s00.ProtocolIEID(157):
		return aper.NotInTable
	case s00.ProtocolIEID(158):
		return aper.NotInTable
	case s00.ProtocolIEID(159):
		return aper.NotInTable
	case s00.ProtocolIEID(160):
		return aper.NotInTable
	case s00.ProtocolIEID(161):
		return aper.NotInTable
	case s00.ProtocolIEID(162):
		return aper.NotInTable
	case s00.ProtocolIEID(163):
		return aper.NotInTable
	case s00.ProtocolIEID(164):
		return aper.NotInTable
	case s00.ProtocolIEID(165):
		return aper.NotInTable
	case s00.ProtocolIEID(166):
		return aper.NotInTable
	case s00.ProtocolIEID(167):
		return aper.NotInTable
	case s00.ProtocolIEID(168):
		return aper.NotInTable
	case s00.ProtocolIEID(169):
		return aper.NotInTable
	case s00.ProtocolIEID(170):
		return aper.NotInTable
	case s00.ProtocolIEID(171):
		return aper.NotInTable
	case s00.ProtocolIEID(172):
		return aper.NotInTable
	case s00.ProtocolIEID(173):
		return aper.NotInTable
	case s00.ProtocolIEID(174):
		return aper.NotInTable
	case s00.ProtocolIEID(175):
		return aper.NotInTable
	case s00.ProtocolIEID(176):
		return aper.NotInTable
	case s00.ProtocolIEID(177):
		return aper.NotInTable
	case s00.ProtocolIEID(178):
		return aper.NotInTable
	case s00.ProtocolIEID(179):
		return aper.NotInTable
	case s00.ProtocolIEID(180):
		return aper.NotInTable
	case s00.ProtocolIEID(181):
		return aper.NotInTable
	case s00.ProtocolIEID(182):
		return aper.NotInTable
	case s00.ProtocolIEID(183):
		return aper.NotInTable
	case s00.ProtocolIEID(184):
		return aper.NotInTable
	case s00.ProtocolIEID(185):
		return aper.NotInTable
	case s00.ProtocolIEID(186):
		return aper.NotInTable
	case s00.ProtocolIEID(187):
		return aper.NotInTable
	case s00.ProtocolIEID(188):
		return aper.NotInTable
	case s00.ProtocolIEID(189):
		return aper.NotInTable
	case s00.ProtocolIEID(190):
		return aper.NotInTable
	case s00.ProtocolIEID(191):
		return aper.NotInTable
	case s00.ProtocolIEID(192):
		return aper.NotInTable
	case s00.ProtocolIEID(193):
		return aper.NotInTable
	case s00.ProtocolIEID(194):
		return aper.NotInTable
	case s00.ProtocolIEID(195):
		return aper.NotInTable
	case s00.ProtocolIEID(196):
		return aper.NotInTable
	case s00.ProtocolIEID(197):
		return aper.NotInTable
	case s00.ProtocolIEID(198):
		return aper.NotInTable
	case s00.ProtocolIEID(199):
		return aper.NotInTable
	case s00.ProtocolIEID(200):
		return aper.NotInTable
	case s00.ProtocolIEID(201):
		return aper.NotInTable
	case s00.ProtocolIEID(202):
		return aper.NotInTable
	case s00.ProtocolIEID(203):
		return aper.NotInTable
	case s00.ProtocolIEID(204):
		return aper.NotInTable
	case s00.ProtocolIEID(205):
		return aper.NotInTable
	case s00.ProtocolIEID(206):
		return aper.NotInTable
	case s00.ProtocolIEID(207):
		return aper.NotInTable
	case s00.ProtocolIEID(208):
		return aper.NotInTable
	case s00.ProtocolIEID(209):
		return aper.NotInTable
	case s00.ProtocolIEID(210):
		return aper.NotInTable
	case s00.ProtocolIEID(211):
		return aper.NotInTable
	case s00.ProtocolIEID(212):
		return aper.NotInTable
	case s00.ProtocolIEID(213):
		return aper.NotInTable
	case s00.ProtocolIEID(214):
		return aper.NotInTable
	case s00.ProtocolIEID(215):
		return aper.NotInTable
	case s00.ProtocolIEID(216):
		return aper.NotInTable
	case s00.ProtocolIEID(217):
		return aper.NotInTable
	case s00.ProtocolIEID(218):
		return aper.NotInTable
	case s00.ProtocolIEID(219):
		return aper.NotInTable
	case s00.ProtocolIEID(220):
		return aper.NotInTable
	case s00.ProtocolIEID(221):
		return aper.NotInTable
	case s00.ProtocolIEID(222):
		return aper.NotInTable
	case s00.ProtocolIEID(223):
		return aper.NotInTable
	case s00.ProtocolIEID(224):
		return aper.NotInTable
	case s00.ProtocolIEID(225):
		return aper.NotInTable
	case s00.ProtocolIEID(226):
		return aper.NotInTable
	case s00.ProtocolIEID(227):
		return aper.NotInTable
	case s00.ProtocolIEID(228):
		return aper.NotInTable
	case s00.ProtocolIEID(230):
		return aper.NotInTable
	case s00.ProtocolIEID(231):
		return aper.NotInTable
	case s00.ProtocolIEID(232):
		return aper.NotInTable
	case s00.ProtocolIEID(233):
		return aper.NotInTable
	case s00.ProtocolIEID(234):
		return aper.NotInTable
	case s00.ProtocolIEID(235):
		return aper.NotInTable
	case s00.ProtocolIEID(236):
		return aper.NotInTable
	case s00.ProtocolIEID(237):
		return aper.NotInTable
	case s00.ProtocolIEID(238):
		return aper.NotInTable
	case s00.ProtocolIEID(239):
		return aper.NotInTable
	case s00.ProtocolIEID(240):
		return aper.NotInTable
	case s00.ProtocolIEID(241):
		return aper.NotInTable
	case s00.ProtocolIEID(242):
		return aper.NotInTable
	case s00.ProtocolIEID(243):
		return aper.NotInTable
	case s00.ProtocolIEID(244):
		return aper.NotInTable
	case s00.ProtocolIEID(245):
		return aper.NotInTable
	case s00.ProtocolIEID(246):
		return aper.NotInTable
	case s00.ProtocolIEID(247):
		return aper.NotInTable
	case s00.ProtocolIEID(248):
		return aper.NotInTable
	case s00.ProtocolIEID(249):
		return aper.NotInTable
	case s00.ProtocolIEID(250):
		return aper.NotInTable
	case s00.ProtocolIEID(251):
		return aper.NotInTable
	case s00.ProtocolIEID(252):
		return aper.NotInTable
	case s00.ProtocolIEID(253):
		return aper.NotInTable
	case s00.ProtocolIEID(254):
		return aper.NotInTable
	case s00.ProtocolIEID(255):
		return aper.NotInTable
	case s00.ProtocolIEID(256):
		return aper.NotInTable
	case s00.ProtocolIEID(257):
		return aper.NotInTable
	case s00.ProtocolIEID(258):
		return aper.NotInTable
	case s00.ProtocolIEID(259):
		return aper.NotInTable
	case s00.ProtocolIEID(260):
		return aper.NotInTable
	case s00.ProtocolIEID(261):
		return aper.NotInTable
	case s00.ProtocolIEID(262):
		return aper.NotInTable
	case s00.ProtocolIEID(263):
		return aper.NotInTable
	case s00.ProtocolIEID(264):
		return aper.NotInTable
	case s00.ProtocolIEID(265):
		return aper.NotInTable
	case s00.ProtocolIEID(266):
		return aper.NotInTable
	case s00.ProtocolIEID(267):
		return aper.NotInTable
	case s00.ProtocolIEID(268):
		return aper.NotInTable
	case s00.ProtocolIEID(269):
		return aper.NotInTable
	case s00.ProtocolIEID(270):
		return aper.NotInTable
	case s00.ProtocolIEID(271):
		return aper.NotInTable
	case s00.ProtocolIEID(272):
		return aper.NotInTable
	case s00.ProtocolIEID(273):
		return aper.NotInTable
	case s00.ProtocolIEID(274):
		return aper.NotInTable
	case s00.ProtocolIEID(275):
		return aper.NotInTable
	case s00.ProtocolIEID(276):
		return aper.NotInTable
	case s00.ProtocolIEID(277):
		return aper.NotInTable
	case s00.ProtocolIEID(278):
		return aper.NotInTable
	case s00.ProtocolIEID(280):
		return aper.NotInTable
	case s00.ProtocolIEID(281):
		return aper.NotInTable
	case s00.ProtocolIEID(282):
		return aper.NotInTable
	case s00.ProtocolIEID(283):
		return aper.NotInTable
	case s00.ProtocolIEID(284):
		return aper.NotInTable
	case s00.ProtocolIEID(285):
		return aper.NotInTable
	case s00.ProtocolIEID(286):
		return aper.NotInTable
	case s00.ProtocolIEID(287):
		return aper.NotInTable
	case s00.ProtocolIEID(288):
		return aper.NotInTable
	case s00.ProtocolIEID(290):
		return aper.NotInTable
	case s00.ProtocolIEID(291):
		return aper.NotInTable
	case s00.ProtocolIEID(292):
		return aper.NotInTable
	case s00.ProtocolIEID(293):
		return aper.NotInTable
	case s00.ProtocolIEID(294):
		return aper.NotInTable
	case s00.ProtocolIEID(295):
		return aper.NotInTable
	case s00.ProtocolIEID(296):
		return aper.NotInTable
	case s00.ProtocolIEID(297):
		return aper.NotInTable
	case s00.ProtocolIEID(298):
		return aper.NotInTable
	case s00.ProtocolIEID(299):
		return aper.NotInTable
	case s00.ProtocolIEID(300):
		return aper.NotInTable
	case s00.ProtocolIEID(301):
		return aper.NotInTable
	case s00.ProtocolIEID(302):
		return aper.NotInTable
	case s00.ProtocolIEID(303):
		return aper.NotInTable
	case s00.ProtocolIEID(304):
		return aper.NotInTable
	case s00.ProtocolIEID(305):
		return aper.NotInTable
	case s00.ProtocolIEID(306):
		return aper.NotInTable
	case s00.ProtocolIEID(307):
		return aper.NotInTable
	case s00.ProtocolIEID(308):
		return aper.NotInTable
	case s00.ProtocolIEID(309):
		return aper.NotInTable
	case s00.ProtocolIEID(310):
		return aper.NotInTable
	case s00.ProtocolIEID(311):
		return aper.NotInTable
	case s00.ProtocolIEID(312):
		return aper.NotInTable
	case s00.ProtocolIEID(313):
		return aper.NotInTable
	case s00.ProtocolIEID(314):
		return aper.NotInTable
	case s00.ProtocolIEID(315):
		return aper.NotInTable
	case s00.ProtocolIEID(316):
		return aper.NotInTable
	case s00.ProtocolIEID(317):
		return aper.NotInTable
	case s00.ProtocolIEID(318):
		return aper.NotInTable
	case s00.ProtocolIEID(319):
		return aper.NotInTable
	case s00.ProtocolIEID(320):
		return aper.NotInTable
	case s00.ProtocolIEID(321):
		return aper.NotInTable
	case s00.ProtocolIEID(322):
		return aper.NotInTable
	case s00.ProtocolIEID(323):
		return aper.NotInTable
	case s00.ProtocolIEID(324):
		return aper.NotInTable
	case s00.ProtocolIEID(325):
		return aper.NotInTable
	case s00.ProtocolIEID(326):
		return aper.NotInTable
	case s00.ProtocolIEID(327):
		return aper.NotInTable
	case s00.ProtocolIEID(328):
		return aper.NotInTable
	case s00.ProtocolIEID(329):
		return aper.NotInTable
	case s00.ProtocolIEID(330):
		return aper.NotInTable
	case s00.ProtocolIEID(331):
		return aper.NotInTable
	case s00.ProtocolIEID(332):
		return aper.NotInTable
	case s00.ProtocolIEID(334):
		return aper.NotInTable
	case s00.ProtocolIEID(335):
		return aper.NotInTable
	case s00.ProtocolIEID(336):
		return aper.NotInTable
	case s00.ProtocolIEID(337):
		return aper.NotInTable
	case s00.ProtocolIEID(339):
		return aper.NotInTable
	case s00.ProtocolIEID(340):
		return aper.NotInTable
	case s00.ProtocolIEID(341):
		return aper.NotInTable
	case s00.ProtocolIEID(342):
		return aper.NotInTable
	case s00.ProtocolIEID(343):
		return aper.NotInTable
	case s00.ProtocolIEID(344):
		return aper.NotInTable
	case s00.ProtocolIEID(345):
		return aper.NotInTable
	case s00.ProtocolIEID(346):
		return aper.NotInTable
	case s00.ProtocolIEID(347):
		return aper.NotInTable
	case s00.ProtocolIEID(348):
		return aper.NotInTable
	case s00.ProtocolIEID(349):
		return aper.NotInTable
	case s00.ProtocolIEID(350):
		return aper.NotInTable
	case s00.ProtocolIEID(351):
		return aper.NotInTable
	case s00.ProtocolIEID(352):
		return aper.NotInTable
	case s00.ProtocolIEID(353):
		return aper.NotInTable
	case s00.ProtocolIEID(354):
		return aper.NotInTable
	case s00.ProtocolIEID(355):
		return aper.NotInTable
	case s00.ProtocolIEID(356):
		return aper.NotInTable
	default:
		return aper.UnknownSelector
	}
}

// AsMMEUES1APID returns the selected MMEUES1APID value of TraceStartIEValue and reports whether that alternative is active.
func (v *TraceStartIEValue) AsMMEUES1APID() (*s00.MMEUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(0) || v.rowMMEUES1APID == nil {
		return nil, false
	}
	return v.rowMMEUES1APID, true
}

// AsENBUES1APID returns the selected ENBUES1APID value of TraceStartIEValue and reports whether that alternative is active.
func (v *TraceStartIEValue) AsENBUES1APID() (*s00.ENBUES1APID, bool) {
	if v == nil || v.id != s00.ProtocolIEID(8) || v.rowENBUES1APID == nil {
		return nil, false
	}
	return v.rowENBUES1APID, true
}

// AsTraceActivation returns the selected TraceActivation value of TraceStartIEValue and reports whether that alternative is active.
func (v *TraceStartIEValue) AsTraceActivation() (*s48.TraceActivation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(25) || v.rowTraceActivation == nil {
		return nil, false
	}
	return v.rowTraceActivation, true
}
func (v TraceStartIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (TraceStartIEValue, error) {
	out := TraceStartIEValue{id: id}
	switch id {
	case s00.ProtocolIEID(0):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false)
		value := s00.MMEUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "MMEUES1APID:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowMMEUES1APID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(8):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		bb := scope
		decoded, err := aper.DecodeIntegerAligned(bb, s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false)
		value := s00.ENBUES1APID(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "ENBUES1APID:", err)
		}
		if _, err := aper.CompleteOpenTypeValue(bb, value); err != nil {
			return out, err
		}
		out.rowENBUES1APID = &value
		raw.RetainContents(&out.received)
	case s00.ProtocolIEID(25):
		scope := raw.ChildDecodeBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
		var value s48.TraceActivation
		child := scope
		if err := s48.BridgeTraceActivationMethodUnmarshalAPERFrom(&value, child); err != nil {
			return out, fmt.Errorf("%s %w", "TraceActivation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "TraceActivation")
		if err != nil {
			return out, err
		}
		*s48.BridgeTraceActivationFieldPerPadding(&value) = padding
		*s48.BridgeTraceActivationFieldReceived(&value) = true
		raw.RetainContents(s48.BridgeTraceActivationFieldReceivedBytes(&value))
		*s48.BridgeTraceActivationFieldReceivedLocation(&value) = raw.ContentLocation()
		out.rowTraceActivation = &value
		raw.RetainContents(&out.received)
	default:
		if err := raw.Observe(aper.UnknownIE); err != nil {
			return out, err
		}
		out.opaque = raw.Detached()
		out.isOpaque = true
	}
	return out, nil
}
func (v TraceStartIEValue) encode() ([]byte, error) { return v.encodeFresh(false, nil) }
func (v TraceStartIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
	if budget == nil {
		var err error
		budget, err = aper.EncodeBudget()
		if err != nil {
			return nil, err
		}
	}
	plan := aper.NewBudgetBuffer(budget).ReplayPlan()
	if v.isOpaque {
		return aper.CopyOpaque(v.opaque, budget)
	}
	switch v.id {
	case s00.ProtocolIEID(0):
		if v.rowMMEUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "TraceStartIEs.id-MME-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowMMEUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(4294967295), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(8):
		if v.rowENBUES1APID == nil {
			return nil, fmt.Errorf("%s missing value", "TraceStartIEs.id-eNB-UE-S1AP-ID:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeIntegerAligned(encodeBB, int64(*v.rowENBUES1APID), s07.BridgeInt64Ptr(0), s07.BridgeInt64Ptr(16777215), false); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	case s00.ProtocolIEID(25):
		if v.rowTraceActivation == nil {
			return nil, fmt.Errorf("%s missing value", "TraceStartIEs.id-TraceActivation:")
		}
		if !fresh && plan != nil && plan.Unchanged(v.replay) {
			return aper.CopyReplay(v.received, budget)
		}
		candidate, err := s48.BridgeTraceActivationMethodMarshalAPERBudget(v.rowTraceActivation, budget, fresh)
		if err != nil {
			return nil, err
		}
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "TraceStartIEValue:", v.id)
	}
}

type HandoverRequestIETable struct{}

func HandoverRequestIEs() HandoverRequestIETable { return HandoverRequestIETable{} }

// ID returns the ASN.1 object-set identity of HandoverRequestIETable.
func (HandoverRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by HandoverRequestIETable.
func (HandoverRequestIETable) Table() s00.HandoverRequestIEValueIETable {
	return func() s00.HandoverRequestIEValueIETable {
		sealed := s00.HandoverRequestIEValueIETable{}
		*s00.BridgeHandoverRequestIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (HandoverRequestIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of HandoverRequestIETable.
func (t HandoverRequestIETable) MMEUES1APID() s48.HandoverRequestMMEUES1APIDIEBinding {
	return func() s48.HandoverRequestMMEUES1APIDIEBinding {
		sealed := s48.HandoverRequestMMEUES1APIDIEBinding{}
		*s48.BridgeHandoverRequestMMEUES1APIDIEBindingFieldInfo(&sealed) = t.infoMMEUES1APID()
		*s48.BridgeHandoverRequestMMEUES1APIDIEBindingFieldCodec(&sealed) = func() s01.MMEUES1APIDValueCodec {
			sealed := s01.MMEUES1APIDValueCodec{}
			*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
			*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MMEUES1APID")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(0), raw)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
				}
				value, ok := decoded.AsMMEUES1APID()
				if !ok {
					var empty s00.MMEUES1APID
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-MME-UE-S1AP-ID: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
					*s48.BridgeHandoverRequestIEValueFieldRowMMEUES1APID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.MMEUES1APID, options aper.DecodeState) (s00.MMEUES1APID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APMMEUES1APID(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.MMEUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APMMEUES1APID(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEUES1APID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestMMEUES1APIDIEBindingFieldInject(&sealed) = func(value s00.MMEUES1APID) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(0)
				*s48.BridgeHandoverRequestIEValueFieldRowMMEUES1APID(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestMMEUES1APIDIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }
		return sealed
	}()
}
func (HandoverRequestIETable) infoHandoverType() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(1), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "HandoverType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-HandoverType"}}}
}

// HandoverType returns the typed binding for the HandoverType row of HandoverRequestIETable.
func (t HandoverRequestIETable) HandoverType() s48.HandoverRequestHandoverTypeIEBinding {
	return func() s48.HandoverRequestHandoverTypeIEBinding {
		sealed := s48.HandoverRequestHandoverTypeIEBinding{}
		*s48.BridgeHandoverRequestHandoverTypeIEBindingFieldInfo(&sealed) = t.infoHandoverType()
		*s48.BridgeHandoverRequestHandoverTypeIEBindingFieldCodec(&sealed) = func() s00.HandoverTypeValueCodec {
			sealed := s00.HandoverTypeValueCodec{}
			*s00.BridgeHandoverTypeValueCodecFieldPath(&sealed) = "HandoverType"
			*s00.BridgeHandoverTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.HandoverType, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.HandoverType
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("HandoverType")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(1), raw)
				if err != nil {
					var empty s00.HandoverType
					return empty, runtime.WrapDecodePath(err, "HandoverType")
				}
				value, ok := decoded.AsHandoverType()
				if !ok {
					var empty s00.HandoverType
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-HandoverType: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeHandoverTypeValueCodecFieldEncode(&sealed) = func(value s00.HandoverType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(1)
					*s48.BridgeHandoverRequestIEValueFieldRowHandoverType(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeHandoverTypeValueCodecFieldCapture(&sealed) = func(v s00.HandoverType, options aper.DecodeState) (s00.HandoverType, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APHandoverType(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeHandoverTypeValueCodecFieldCompare(&sealed) = func(v s00.HandoverType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APHandoverType(&v, &s)
				s.End(f, root, false)
				return s.Plan(),
					s.
						BudgetValue()
			}
			*s00.BridgeHandoverTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverType"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestHandoverTypeIEBindingFieldInject(&sealed) = func(value s00.HandoverType) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(1)
				*s48.BridgeHandoverRequestIEValueFieldRowHandoverType(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestHandoverTypeIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.HandoverType, bool) { return value.AsHandoverType() }
		return sealed
	}()
}
func (HandoverRequestIETable) infoCause() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(2), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Cause"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-Cause"}}}
}

// Cause returns the typed binding for the Cause row of HandoverRequestIETable.
func (t HandoverRequestIETable) Cause() s48.HandoverRequestCauseIEBinding {
	return func() s48.HandoverRequestCauseIEBinding {
		sealed := s48.HandoverRequestCauseIEBinding{}
		*s48.BridgeHandoverRequestCauseIEBindingFieldInfo(&sealed) = t.infoCause()
		*s48.BridgeHandoverRequestCauseIEBindingFieldCodec(&sealed) = func() s14.CauseValueCodec {
			sealed := s14.CauseValueCodec{}
			*s14.BridgeCauseValueCodecFieldPath(&sealed) = "Cause"
			*s14.BridgeCauseValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s14.Cause, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s14.Cause
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("Cause")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(2), raw)
				if err != nil {
					var empty s14.Cause
					return empty, runtime.WrapDecodePath(err, "Cause")
				}
				value, ok := decoded.AsCause()
				if !ok {
					var empty s14.Cause
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-Cause: no selected value")
				}
				return *value, nil
			}
			*s14.BridgeCauseValueCodecFieldEncode(&sealed) = func(value s14.Cause, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
					*s48.BridgeHandoverRequestIEValueFieldRowCause(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s14.BridgeCauseValueCodecFieldCapture(&sealed) = func(v s14.Cause, options aper.DecodeState) (s14.Cause, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s14.BridgeCaptureS1APCause(&v, &s)
				var root aper.Snapshot
				s.End(f,
					&root, false)
				return v, root
			}
			*s14.BridgeCauseValueCodecFieldCompare(&sealed) = func(v s14.Cause, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s14.BridgeCompareS1APCause(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s14.BridgeCauseValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Cause"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestCauseIEBindingFieldInject(&sealed) = func(value s14.Cause) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(2)
				*s48.BridgeHandoverRequestIEValueFieldRowCause(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestCauseIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s14.Cause, bool) { return value.AsCause() }
		return sealed
	}()
}
func (HandoverRequestIETable) infoUEaggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(66), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-uEaggregateMaximumBitrate"}}}
}

// UEaggregateMaximumBitrate returns the typed binding for the UEaggregateMaximumBitrate row of HandoverRequestIETable.
func (t HandoverRequestIETable) UEaggregateMaximumBitrate() s48.HandoverRequestUEAggregateMaximumBitrateIEBinding {
	return func() s48.HandoverRequestUEAggregateMaximumBitrateIEBinding {
		sealed := s48.HandoverRequestUEAggregateMaximumBitrateIEBinding{}
		*s48.BridgeHandoverRequestUEAggregateMaximumBitrateIEBindingFieldInfo(&sealed) = t.infoUEaggregateMaximumBitrate()
		*s48.BridgeHandoverRequestUEAggregateMaximumBitrateIEBindingFieldCodec(&sealed) = func() s36.UEAggregateMaximumBitrateValueCodec {
			sealed := s36.UEAggregateMaximumBitrateValueCodec{}
			*s36.BridgeUEAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "UEAggregateMaximumBitrate"
			*s36.BridgeUEAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.UEAggregateMaximumBitrate, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s36.UEAggregateMaximumBitrate
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("UEAggregateMaximumBitrate")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(66), raw)
				if err != nil {
					var empty s36.UEAggregateMaximumBitrate
					return empty, runtime.WrapDecodePath(err, "UEAggregateMaximumBitrate")
				}
				value, ok := decoded.AsUEaggregateMaximumBitrate()
				if !ok {
					var empty s36.UEAggregateMaximumBitrate
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-uEaggregateMaximumBitrate: no selected value")
				}
				return *value, nil
			}
			*s36.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s36.UEAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
					*s48.BridgeHandoverRequestIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s36.BridgeUEAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s36.UEAggregateMaximumBitrate, options aper.DecodeState) (s36.UEAggregateMaximumBitrate, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s36.BridgeCaptureS1APUEAggregateMaximumBitrate(&v, &s)
				var root aper.Snapshot
				s.End(
					f,
					&root, false)
				return v, root
			}
			*s36.BridgeUEAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s36.UEAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s36.BridgeCompareS1APUEAggregateMaximumBitrate(&v, &s)
				s.End(f, root,

					false)
				return s.Plan(), s.BudgetValue()
			}
			*s36.BridgeUEAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEAggregateMaximumBitrate"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestUEAggregateMaximumBitrateIEBindingFieldInject(&sealed) = func(value s36.UEAggregateMaximumBitrate) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(66)
				*s48.BridgeHandoverRequestIEValueFieldRowUEaggregateMaximumBitrate(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestUEAggregateMaximumBitrateIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s36.UEAggregateMaximumBitrate, bool) {
			return value.AsUEaggregateMaximumBitrate()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoERABToBeSetupListHOReq() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(53), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupListHOReq"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-E-RABToBeSetupListHOReq"}}}
}

// ERABToBeSetupListHOReq returns the typed binding for the ERABToBeSetupListHOReq row of HandoverRequestIETable.
func (t HandoverRequestIETable) ERABToBeSetupListHOReq() s48.HandoverRequestERABToBeSetupListHOReqIEBinding {
	return func() s48.HandoverRequestERABToBeSetupListHOReqIEBinding {
		sealed := s48.HandoverRequestERABToBeSetupListHOReqIEBinding{}
		*s48.BridgeHandoverRequestERABToBeSetupListHOReqIEBindingFieldInfo(&sealed) = t.infoERABToBeSetupListHOReq()
		*s48.BridgeHandoverRequestERABToBeSetupListHOReqIEBindingFieldCodec(&sealed) = func() s30.ERABToBeSetupListHOReqValueCodec {
			sealed := s30.ERABToBeSetupListHOReqValueCodec{}
			*s30.BridgeERABToBeSetupListHOReqValueCodecFieldPath(&sealed) = "ERABToBeSetupListHOReq"
			*s30.BridgeERABToBeSetupListHOReqValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s30.ERABToBeSetupListHOReq, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s30.ERABToBeSetupListHOReq
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ERABToBeSetupListHOReq")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(53), raw)
				if err != nil {
					var empty s30.ERABToBeSetupListHOReq
					return empty, runtime.WrapDecodePath(err, "ERABToBeSetupListHOReq")
				}
				value, ok := decoded.AsERABToBeSetupListHOReq()
				if !ok {
					var empty s30.ERABToBeSetupListHOReq
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-E-RABToBeSetupListHOReq: no selected value")
				}
				return *value, nil
			}
			*s30.BridgeERABToBeSetupListHOReqValueCodecFieldEncode(&sealed) = func(value s30.ERABToBeSetupListHOReq, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(53)
					*s48.BridgeHandoverRequestIEValueFieldRowERABToBeSetupListHOReq(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s30.BridgeERABToBeSetupListHOReqValueCodecFieldCapture(&sealed) = func(v s30.ERABToBeSetupListHOReq, options aper.DecodeState) (s30.ERABToBeSetupListHOReq, aper.Snapshot,

			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s30.BridgeCaptureS1APERABToBeSetupListHOReq(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s30.BridgeERABToBeSetupListHOReqValueCodecFieldCompare(&sealed) = func(v s30.ERABToBeSetupListHOReq, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s30.BridgeCompareS1APERABToBeSetupListHOReq(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s30.BridgeERABToBeSetupListHOReqValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeSetupListHOReq"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestERABToBeSetupListHOReqIEBindingFieldInject(&sealed) = func(value s30.ERABToBeSetupListHOReq) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(53)
				*s48.BridgeHandoverRequestIEValueFieldRowERABToBeSetupListHOReq(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestERABToBeSetupListHOReqIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s30.ERABToBeSetupListHOReq, bool) {
			return value.AsERABToBeSetupListHOReq()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoSourceToTargetTransparentContainer() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(104), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Source-ToTarget-TransparentContainer"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-Source-ToTarget-TransparentContainer"}}}
}

// SourceToTargetTransparentContainer returns the typed binding for the SourceToTargetTransparentContainer row of HandoverRequestIETable.
func (t HandoverRequestIETable) SourceToTargetTransparentContainer() s48.HandoverRequestSourceToTargetTransparentContainerIEBinding {
	return func() s48.HandoverRequestSourceToTargetTransparentContainerIEBinding {
		sealed := s48.HandoverRequestSourceToTargetTransparentContainerIEBinding{}
		*s48.BridgeHandoverRequestSourceToTargetTransparentContainerIEBindingFieldInfo(&sealed) = t.infoSourceToTargetTransparentContainer()
		*s48.BridgeHandoverRequestSourceToTargetTransparentContainerIEBindingFieldCodec(&sealed) = func() s01.SourceToTargetTransparentContainerValueCodec {
			sealed := s01.SourceToTargetTransparentContainerValueCodec{}
			*s01.BridgeSourceToTargetTransparentContainerValueCodecFieldPath(&sealed) = "SourceToTargetTransparentContainer"
			*s01.BridgeSourceToTargetTransparentContainerValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SourceToTargetTransparentContainer, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.SourceToTargetTransparentContainer
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("SourceToTargetTransparentContainer")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(104), raw)
				if err != nil {
					var empty s00.SourceToTargetTransparentContainer
					return empty, runtime.WrapDecodePath(err, "SourceToTargetTransparentContainer")
				}
				value, ok := decoded.AsSourceToTargetTransparentContainer()
				if !ok {
					var empty s00.SourceToTargetTransparentContainer
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-Source-ToTarget-TransparentContainer: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeSourceToTargetTransparentContainerValueCodecFieldEncode(&sealed) = func(value s00.SourceToTargetTransparentContainer, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(104)
					*s48.BridgeHandoverRequestIEValueFieldRowSourceToTargetTransparentContainer(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeSourceToTargetTransparentContainerValueCodecFieldCapture(&sealed) = func(v s00.SourceToTargetTransparentContainer, options aper.DecodeState) (s00.SourceToTargetTransparentContainer, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APSourceToTargetTransparentContainer(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s01.BridgeSourceToTargetTransparentContainerValueCodecFieldCompare(&sealed) = func(v s00.SourceToTargetTransparentContainer, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s07.BridgeCompareS1APSourceToTargetTransparentContainer(
					&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s01.BridgeSourceToTargetTransparentContainerValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SourceToTargetTransparentContainer"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestSourceToTargetTransparentContainerIEBindingFieldInject(&sealed) = func(value s00.SourceToTargetTransparentContainer) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(104)
				*s48.BridgeHandoverRequestIEValueFieldRowSourceToTargetTransparentContainer(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestSourceToTargetTransparentContainerIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.SourceToTargetTransparentContainer, bool) {
			return value.AsSourceToTargetTransparentContainer()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoUESecurityCapabilities() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(107), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UESecurityCapabilities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-UESecurityCapabilities"}}}
}

// UESecurityCapabilities returns the typed binding for the UESecurityCapabilities row of HandoverRequestIETable.
func (t HandoverRequestIETable) UESecurityCapabilities() s48.HandoverRequestUESecurityCapabilitiesIEBinding {
	return func() s48.HandoverRequestUESecurityCapabilitiesIEBinding {
		sealed := s48.HandoverRequestUESecurityCapabilitiesIEBinding{}
		*s48.BridgeHandoverRequestUESecurityCapabilitiesIEBindingFieldInfo(&sealed) = t.infoUESecurityCapabilities()
		*s48.BridgeHandoverRequestUESecurityCapabilitiesIEBindingFieldCodec(&sealed) = func() s37.UESecurityCapabilitiesValueCodec {
			sealed := s37.UESecurityCapabilitiesValueCodec{}
			*s37.BridgeUESecurityCapabilitiesValueCodecFieldPath(&sealed) = "UESecurityCapabilities"
			*s37.BridgeUESecurityCapabilitiesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s37.UESecurityCapabilities, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s37.UESecurityCapabilities
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("UESecurityCapabilities")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(107), raw)
				if err != nil {
					var empty s37.UESecurityCapabilities
					return empty, runtime.WrapDecodePath(err, "UESecurityCapabilities")
				}
				value, ok := decoded.AsUESecurityCapabilities()
				if !ok {
					var empty s37.UESecurityCapabilities
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-UESecurityCapabilities: no selected value")
				}
				return *value, nil
			}
			*s37.BridgeUESecurityCapabilitiesValueCodecFieldEncode(&sealed) = func(value s37.UESecurityCapabilities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(107)
					*s48.BridgeHandoverRequestIEValueFieldRowUESecurityCapabilities(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s37.BridgeUESecurityCapabilitiesValueCodecFieldCapture(&sealed) = func(v s37.UESecurityCapabilities, options aper.DecodeState) (s37.UESecurityCapabilities, aper.Snapshot,

			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s37.BridgeCaptureS1APUESecurityCapabilities(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s37.BridgeUESecurityCapabilitiesValueCodecFieldCompare(&sealed) = func(v s37.UESecurityCapabilities, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s37.BridgeCompareS1APUESecurityCapabilities(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s37.BridgeUESecurityCapabilitiesValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UESecurityCapabilities"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestUESecurityCapabilitiesIEBindingFieldInject(&sealed) = func(value s37.UESecurityCapabilities) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(107)
				*s48.BridgeHandoverRequestIEValueFieldRowUESecurityCapabilities(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestUESecurityCapabilitiesIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s37.UESecurityCapabilities, bool) {
			return value.AsUESecurityCapabilities()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoHandoverRestrictionList() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(41), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "HandoverRestrictionList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-HandoverRestrictionList"}}}
}

// HandoverRestrictionList returns the typed binding for the HandoverRestrictionList row of HandoverRequestIETable.
func (t HandoverRequestIETable) HandoverRestrictionList() s48.HandoverRequestHandoverRestrictionListIEBinding {
	return func() s48.HandoverRequestHandoverRestrictionListIEBinding {
		sealed := s48.HandoverRequestHandoverRestrictionListIEBinding{}
		*s48.BridgeHandoverRequestHandoverRestrictionListIEBindingFieldInfo(&sealed) = t.infoHandoverRestrictionList()
		*s48.BridgeHandoverRequestHandoverRestrictionListIEBindingFieldCodec(&sealed) = func() s43.HandoverRestrictionListValueCodec {
			sealed := s43.HandoverRestrictionListValueCodec{}
			*s43.BridgeHandoverRestrictionListValueCodecFieldPath(&sealed) = "HandoverRestrictionList"
			*s43.BridgeHandoverRestrictionListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s43.HandoverRestrictionList, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s43.HandoverRestrictionList
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("HandoverRestrictionList")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(41), raw)
				if err != nil {
					var empty s43.HandoverRestrictionList
					return empty, runtime.WrapDecodePath(err, "HandoverRestrictionList")
				}
				value, ok := decoded.AsHandoverRestrictionList()
				if !ok {
					var empty s43.HandoverRestrictionList
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-HandoverRestrictionList: no selected value")
				}
				return *value, nil
			}
			*s43.BridgeHandoverRestrictionListValueCodecFieldEncode(&sealed) = func(value s43.HandoverRestrictionList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(41)
					*s48.BridgeHandoverRequestIEValueFieldRowHandoverRestrictionList(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s43.BridgeHandoverRestrictionListValueCodecFieldCapture(&sealed) = func(v s43.HandoverRestrictionList, options aper.DecodeState) (s43.HandoverRestrictionList, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s43.BridgeCaptureS1APHandoverRestrictionList(&v, &s)
				var root aper.Snapshot
				s.End(f, &root,

					false,
				)
				return v, root
			}
			*s43.BridgeHandoverRestrictionListValueCodecFieldCompare(&sealed) = func(v s43.HandoverRestrictionList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s43.BridgeCompareS1APHandoverRestrictionList(&v, &s)
				s.End(f, root,
					false,
				)
				return s.Plan(), s.BudgetValue()
			}
			*s43.BridgeHandoverRestrictionListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverRestrictionList"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestHandoverRestrictionListIEBindingFieldInject(&sealed) = func(value s43.HandoverRestrictionList) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(41)
				*s48.BridgeHandoverRequestIEValueFieldRowHandoverRestrictionList(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestHandoverRestrictionListIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s43.HandoverRestrictionList, bool) {
			return value.AsHandoverRestrictionList()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoTraceActivation() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(25), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TraceActivation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-TraceActivation"}}}
}

// TraceActivation returns the typed binding for the TraceActivation row of HandoverRequestIETable.
func (t HandoverRequestIETable) TraceActivation() HandoverRequestTraceActivationIEBinding {
	return HandoverRequestTraceActivationIEBinding{info: t.infoTraceActivation(), codec: TraceActivationValueCodec{path: "TraceActivation",
		decode: func(data []byte, options aper.DecodeState) (s48.TraceActivation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s48.TraceActivation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TraceActivation")
			var zero s48.HandoverRequestIEValue
			decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(25), raw)
			if err != nil {
				var empty s48.TraceActivation
				return empty, runtime.WrapDecodePath(err, "TraceActivation")
			}
			value, ok := decoded.AsTraceActivation()
			if !ok {
				var empty s48.TraceActivation
				return empty, fmt.Errorf("binding HandoverRequestIEs.id-TraceActivation: no selected value")
			}
			return *value, nil
		},
		encode: func(value s48.TraceActivation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(25)
				*s48.BridgeHandoverRequestIEValueFieldRowTraceActivation(&sealed) = &value
				return sealed
			}()), fresh, budget)
		}, capture: func(v s48.TraceActivation, options aper.DecodeState) (s48.TraceActivation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s48.BridgeCaptureS1APTraceActivation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v s48.TraceActivation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s48.BridgeCompareS1APTraceActivation(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TraceActivation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s48.TraceActivation) s48.HandoverRequestIEValue {
		return func() s48.HandoverRequestIEValue {
			sealed := s48.HandoverRequestIEValue{}
			*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(25)
			*s48.BridgeHandoverRequestIEValueFieldRowTraceActivation(&sealed) = &value
			return sealed
		}()
	}, get: func(value *s48.HandoverRequestIEValue) (*s48.TraceActivation, bool) {
		return value.AsTraceActivation()
	}}
}
func (HandoverRequestIETable) infoRequestType() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(98), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "RequestType"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-RequestType"}}}
}

// RequestType returns the typed binding for the RequestType row of HandoverRequestIETable.
func (t HandoverRequestIETable) RequestType() s48.HandoverRequestRequestTypeIEBinding {
	return func() s48.HandoverRequestRequestTypeIEBinding {
		sealed := s48.HandoverRequestRequestTypeIEBinding{}
		*s48.BridgeHandoverRequestRequestTypeIEBindingFieldInfo(&sealed) = t.infoRequestType()
		*s48.BridgeHandoverRequestRequestTypeIEBindingFieldCodec(&sealed) = func() s26.RequestTypeValueCodec {
			sealed := s26.RequestTypeValueCodec{}
			*s26.BridgeRequestTypeValueCodecFieldPath(&sealed) = "RequestType"
			*s26.BridgeRequestTypeValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s26.RequestType, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s26.RequestType
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("RequestType")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(98), raw)
				if err != nil {
					var empty s26.RequestType
					return empty, runtime.WrapDecodePath(err, "RequestType")
				}
				value, ok := decoded.AsRequestType()
				if !ok {
					var empty s26.RequestType
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-RequestType: no selected value")
				}
				return *value, nil
			}
			*s26.BridgeRequestTypeValueCodecFieldEncode(&sealed) = func(value s26.RequestType, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(98)
					*s48.BridgeHandoverRequestIEValueFieldRowRequestType(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s26.BridgeRequestTypeValueCodecFieldCapture(&sealed) = func(v s26.RequestType, options aper.DecodeState) (s26.RequestType, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s26.BridgeCaptureS1APRequestType(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s26.BridgeRequestTypeValueCodecFieldCompare(&sealed) = func(v s26.RequestType, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s26.BridgeCompareS1APRequestType(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s26.BridgeRequestTypeValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:RequestType"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestRequestTypeIEBindingFieldInject(&sealed) = func(value s26.RequestType) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(98)
				*s48.BridgeHandoverRequestIEValueFieldRowRequestType(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestRequestTypeIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s26.RequestType, bool) { return value.AsRequestType() }
		return sealed
	}()
}
func (HandoverRequestIETable) infoSRVCCOperationPossible() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(124), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SRVCCOperationPossible"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-SRVCCOperationPossible"}}}
}

// SRVCCOperationPossible returns the typed binding for the SRVCCOperationPossible row of HandoverRequestIETable.
func (t HandoverRequestIETable) SRVCCOperationPossible() s48.HandoverRequestSRVCCOperationPossibleIEBinding {
	return func() s48.HandoverRequestSRVCCOperationPossibleIEBinding {
		sealed := s48.HandoverRequestSRVCCOperationPossibleIEBinding{}
		*s48.BridgeHandoverRequestSRVCCOperationPossibleIEBindingFieldInfo(&sealed) = t.infoSRVCCOperationPossible()
		*s48.BridgeHandoverRequestSRVCCOperationPossibleIEBindingFieldCodec(&sealed) = func() s01.SRVCCOperationPossibleValueCodec {
			sealed := s01.SRVCCOperationPossibleValueCodec{}
			*s01.BridgeSRVCCOperationPossibleValueCodecFieldPath(&sealed) = "SRVCCOperationPossible"
			*s01.BridgeSRVCCOperationPossibleValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SRVCCOperationPossible, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.SRVCCOperationPossible
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("SRVCCOperationPossible")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(124), raw)
				if err != nil {
					var empty s00.SRVCCOperationPossible
					return empty, runtime.WrapDecodePath(err, "SRVCCOperationPossible")
				}
				value, ok := decoded.AsSRVCCOperationPossible()
				if !ok {
					var empty s00.SRVCCOperationPossible
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-SRVCCOperationPossible: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeSRVCCOperationPossibleValueCodecFieldEncode(&sealed) = func(value s00.SRVCCOperationPossible, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(124)
					*s48.BridgeHandoverRequestIEValueFieldRowSRVCCOperationPossible(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeSRVCCOperationPossibleValueCodecFieldCapture(&sealed) = func(v s00.SRVCCOperationPossible, options aper.DecodeState) (s00.SRVCCOperationPossible, aper.Snapshot,

			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APSRVCCOperationPossible(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s01.BridgeSRVCCOperationPossibleValueCodecFieldCompare(&sealed) = func(v s00.SRVCCOperationPossible, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s06.BridgeCompareS1APSRVCCOperationPossible(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s01.BridgeSRVCCOperationPossibleValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SRVCCOperationPossible"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestSRVCCOperationPossibleIEBindingFieldInject(&sealed) = func(value s00.SRVCCOperationPossible) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(124)
				*s48.BridgeHandoverRequestIEValueFieldRowSRVCCOperationPossible(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestSRVCCOperationPossibleIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.SRVCCOperationPossible, bool) {
			return value.AsSRVCCOperationPossible()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoSecurityContext() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(40), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecurityContext"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-SecurityContext"}}}
}

// SecurityContext returns the typed binding for the SecurityContext row of HandoverRequestIETable.
func (t HandoverRequestIETable) SecurityContext() s48.HandoverRequestSecurityContextIEBinding {
	return func() s48.HandoverRequestSecurityContextIEBinding {
		sealed := s48.HandoverRequestSecurityContextIEBinding{}
		*s48.BridgeHandoverRequestSecurityContextIEBindingFieldInfo(&sealed) = t.infoSecurityContext()
		*s48.BridgeHandoverRequestSecurityContextIEBindingFieldCodec(&sealed) = func() s29.SecurityContextValueCodec {
			sealed := s29.SecurityContextValueCodec{}
			*s29.BridgeSecurityContextValueCodecFieldPath(&sealed) = "SecurityContext"
			*s29.BridgeSecurityContextValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s29.SecurityContext, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s29.SecurityContext
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("SecurityContext")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(40), raw)
				if err != nil {
					var empty s29.SecurityContext
					return empty, runtime.WrapDecodePath(err, "SecurityContext")
				}
				value, ok := decoded.AsSecurityContext()
				if !ok {
					var empty s29.SecurityContext
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-SecurityContext: no selected value")
				}
				return *value, nil
			}
			*s29.BridgeSecurityContextValueCodecFieldEncode(&sealed) = func(value s29.SecurityContext, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(40)
					*s48.BridgeHandoverRequestIEValueFieldRowSecurityContext(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s29.BridgeSecurityContextValueCodecFieldCapture(&sealed) = func(v s29.SecurityContext, options aper.DecodeState) (s29.SecurityContext, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s29.BridgeCaptureS1APSecurityContext(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s29.BridgeSecurityContextValueCodecFieldCompare(&sealed) = func(v s29.SecurityContext, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s29.BridgeCompareS1APSecurityContext(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s29.BridgeSecurityContextValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityContext"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestSecurityContextIEBindingFieldInject(&sealed) = func(value s29.SecurityContext) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(40)
				*s48.BridgeHandoverRequestIEValueFieldRowSecurityContext(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestSecurityContextIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s29.SecurityContext, bool) {
			return value.AsSecurityContext()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoNASSecurityParameterstoEUTRAN() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(136), Criticality: s00.CriticalityReject, Presence: s00.PresenceConditional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NASSecurityParameterstoE-UTRAN"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-NASSecurityParameterstoE-UTRAN"}}}
}

// NASSecurityParameterstoEUTRAN returns the typed binding for the NASSecurityParameterstoEUTRAN row of HandoverRequestIETable.
func (t HandoverRequestIETable) NASSecurityParameterstoEUTRAN() s48.HandoverRequestNASSecurityParameterstoEUTRANIEBinding {
	return func() s48.HandoverRequestNASSecurityParameterstoEUTRANIEBinding {
		sealed := s48.HandoverRequestNASSecurityParameterstoEUTRANIEBinding{}
		*s48.BridgeHandoverRequestNASSecurityParameterstoEUTRANIEBindingFieldInfo(&sealed) = t.infoNASSecurityParameterstoEUTRAN()
		*s48.BridgeHandoverRequestNASSecurityParameterstoEUTRANIEBindingFieldCodec(&sealed) = func() s01.NASSecurityParameterstoEUTRANValueCodec {
			sealed := s01.NASSecurityParameterstoEUTRANValueCodec{}
			*s01.BridgeNASSecurityParameterstoEUTRANValueCodecFieldPath(&sealed) = "NASSecurityParameterstoEUTRAN"
			*s01.BridgeNASSecurityParameterstoEUTRANValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.NASSecurityParameterstoEUTRAN, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.NASSecurityParameterstoEUTRAN
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("NASSecurityParameterstoEUTRAN")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(136), raw)
				if err != nil {
					var empty s00.NASSecurityParameterstoEUTRAN
					return empty, runtime.WrapDecodePath(err, "NASSecurityParameterstoEUTRAN")
				}
				value, ok := decoded.AsNASSecurityParameterstoEUTRAN()
				if !ok {
					var empty s00.NASSecurityParameterstoEUTRAN
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-NASSecurityParameterstoE-UTRAN: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeNASSecurityParameterstoEUTRANValueCodecFieldEncode(&sealed) = func(value s00.NASSecurityParameterstoEUTRAN, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(136)
					*s48.BridgeHandoverRequestIEValueFieldRowNASSecurityParameterstoEUTRAN(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeNASSecurityParameterstoEUTRANValueCodecFieldCapture(&sealed) = func(v s00.NASSecurityParameterstoEUTRAN, options aper.DecodeState) (s00.NASSecurityParameterstoEUTRAN, aper.Snapshot,

			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APNASSecurityParameterstoEUTRAN(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s01.BridgeNASSecurityParameterstoEUTRANValueCodecFieldCompare(&sealed) = func(v s00.NASSecurityParameterstoEUTRAN, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f :=
					s.Begin()
				s02.BridgeCompareS1APNASSecurityParameterstoEUTRAN(&v, &s)
				s.
					End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s01.BridgeNASSecurityParameterstoEUTRANValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NASSecurityParameterstoEUTRAN"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestNASSecurityParameterstoEUTRANIEBindingFieldInject(&sealed) = func(value s00.NASSecurityParameterstoEUTRAN) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(136)
				*s48.BridgeHandoverRequestIEValueFieldRowNASSecurityParameterstoEUTRAN(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestNASSecurityParameterstoEUTRANIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.NASSecurityParameterstoEUTRAN, bool) {
			return value.AsNASSecurityParameterstoEUTRAN()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoCSGId() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(127), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSG-Id"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-CSG-Id"}}}
}

// CSGId returns the typed binding for the CSGId row of HandoverRequestIETable.
func (t HandoverRequestIETable) CSGId() s48.HandoverRequestCSGIdIEBinding {
	return func() s48.HandoverRequestCSGIdIEBinding {
		sealed := s48.HandoverRequestCSGIdIEBinding{}
		*s48.BridgeHandoverRequestCSGIdIEBindingFieldInfo(&sealed) = t.infoCSGId()
		*s48.BridgeHandoverRequestCSGIdIEBindingFieldCodec(&sealed) = func() s00.CSGIdValueCodec {
			sealed := s00.CSGIdValueCodec{}
			*s00.BridgeCSGIdValueCodecFieldPath(&sealed) = "CSGId"
			*s00.BridgeCSGIdValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSGId, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.CSGId
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CSGId")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(127), raw)
				if err != nil {
					var empty s00.CSGId
					return empty, runtime.WrapDecodePath(err, "CSGId")
				}
				value, ok := decoded.AsCSGId()
				if !ok {
					var empty s00.CSGId
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-CSG-Id: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCSGIdValueCodecFieldEncode(&sealed) = func(value s00.CSGId, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(127)
					*s48.BridgeHandoverRequestIEValueFieldRowCSGId(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeCSGIdValueCodecFieldCapture(&sealed) = func(v s00.CSGId, options aper.DecodeState) (s00.CSGId, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APCSGId(&v, &s)
				var root aper.Snapshot
				s.End(f,
					&root, false)
				return v, root
			}
			*s00.BridgeCSGIdValueCodecFieldCompare(&sealed) = func(v s00.CSGId, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APCSGId(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s00.BridgeCSGIdValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSGId"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestCSGIdIEBindingFieldInject(&sealed) = func(value s00.CSGId) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(127)
				*s48.BridgeHandoverRequestIEValueFieldRowCSGId(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestCSGIdIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.CSGId, bool) { return value.AsCSGId() }
		return sealed
	}()
}
func (HandoverRequestIETable) infoCSGMembershipStatus() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(146), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSGMembershipStatus"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-CSGMembershipStatus"}}}
}

// CSGMembershipStatus returns the typed binding for the CSGMembershipStatus row of HandoverRequestIETable.
func (t HandoverRequestIETable) CSGMembershipStatus() s48.HandoverRequestCSGMembershipStatusIEBinding {
	return func() s48.HandoverRequestCSGMembershipStatusIEBinding {
		sealed := s48.HandoverRequestCSGMembershipStatusIEBinding{}
		*s48.BridgeHandoverRequestCSGMembershipStatusIEBindingFieldInfo(&sealed) = t.infoCSGMembershipStatus()
		*s48.BridgeHandoverRequestCSGMembershipStatusIEBindingFieldCodec(&sealed) = func() s00.CSGMembershipStatusValueCodec {
			sealed := s00.CSGMembershipStatusValueCodec{}
			*s00.BridgeCSGMembershipStatusValueCodecFieldPath(&sealed) = "CSGMembershipStatus"
			*s00.BridgeCSGMembershipStatusValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSGMembershipStatus, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.CSGMembershipStatus
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CSGMembershipStatus")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(146), raw)
				if err != nil {
					var empty s00.CSGMembershipStatus
					return empty, runtime.WrapDecodePath(err, "CSGMembershipStatus")
				}
				value, ok := decoded.AsCSGMembershipStatus()
				if !ok {
					var empty s00.CSGMembershipStatus
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-CSGMembershipStatus: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&sealed) = func(value s00.CSGMembershipStatus, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
					*s48.BridgeHandoverRequestIEValueFieldRowCSGMembershipStatus(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeCSGMembershipStatusValueCodecFieldCapture(&sealed) = func(v s00.CSGMembershipStatus, options aper.DecodeState) (s00.CSGMembershipStatus, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APCSGMembershipStatus(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeCSGMembershipStatusValueCodecFieldCompare(&sealed) = func(v s00.CSGMembershipStatus, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APCSGMembershipStatus(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s00.BridgeCSGMembershipStatusValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSGMembershipStatus"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestCSGMembershipStatusIEBindingFieldInject(&sealed) = func(value s00.CSGMembershipStatus) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(146)
				*s48.BridgeHandoverRequestIEValueFieldRowCSGMembershipStatus(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestCSGMembershipStatusIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.CSGMembershipStatus, bool) {
			return value.AsCSGMembershipStatus()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoGUMMEIID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(75), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GUMMEI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-GUMMEI-ID"}}}
}

// GUMMEIID returns the typed binding for the GUMMEIID row of HandoverRequestIETable.
func (t HandoverRequestIETable) GUMMEIID() s48.HandoverRequestGUMMEIIEBinding {
	return func() s48.HandoverRequestGUMMEIIEBinding {
		sealed := s48.HandoverRequestGUMMEIIEBinding{}
		*s48.BridgeHandoverRequestGUMMEIIEBindingFieldInfo(&sealed) = t.infoGUMMEIID()
		*s48.BridgeHandoverRequestGUMMEIIEBindingFieldCodec(&sealed) = func() s18.GUMMEIValueCodec {
			sealed := s18.GUMMEIValueCodec{}
			*s18.BridgeGUMMEIValueCodecFieldPath(&sealed) = "GUMMEI"
			*s18.BridgeGUMMEIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.GUMMEI, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s18.GUMMEI
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("GUMMEI")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(75), raw)
				if err != nil {
					var empty s18.GUMMEI
					return empty, runtime.WrapDecodePath(err, "GUMMEI")
				}
				value, ok := decoded.AsGUMMEIID()
				if !ok {
					var empty s18.GUMMEI
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-GUMMEI-ID: no selected value")
				}
				return *value, nil
			}
			*s18.BridgeGUMMEIValueCodecFieldEncode(&sealed) = func(value s18.GUMMEI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(75)
					*s48.BridgeHandoverRequestIEValueFieldRowGUMMEIID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s18.BridgeGUMMEIValueCodecFieldCapture(&sealed) = func(v s18.GUMMEI, options aper.DecodeState) (s18.GUMMEI, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.
					Begin()
				s18.BridgeCaptureS1APGUMMEI(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s18.BridgeGUMMEIValueCodecFieldCompare(&sealed) = func(v s18.GUMMEI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s18.BridgeCompareS1APGUMMEI(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s18.BridgeGUMMEIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GUMMEI"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestGUMMEIIEBindingFieldInject(&sealed) = func(value s18.GUMMEI) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(75)
				*s48.BridgeHandoverRequestIEValueFieldRowGUMMEIID(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestGUMMEIIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s18.GUMMEI, bool) { return value.AsGUMMEIID() }
		return sealed
	}()
}
func (HandoverRequestIETable) infoMMEUES1APID2() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(158), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-MME-UE-S1AP-ID-2"}}}
}

// MMEUES1APID2 returns the typed binding for the MMEUES1APID2 row of HandoverRequestIETable.
func (t HandoverRequestIETable) MMEUES1APID2() s48.HandoverRequestMMEUES1APIDIEBinding {
	return func() s48.HandoverRequestMMEUES1APIDIEBinding {
		sealed := s48.HandoverRequestMMEUES1APIDIEBinding{}
		*s48.BridgeHandoverRequestMMEUES1APIDIEBindingFieldInfo(&sealed) = t.infoMMEUES1APID2()
		*s48.BridgeHandoverRequestMMEUES1APIDIEBindingFieldCodec(&sealed) = func() s01.MMEUES1APIDValueCodec {
			sealed := s01.MMEUES1APIDValueCodec{}
			*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
			*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MMEUES1APID")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(158), raw)
				if err != nil {
					var empty s00.MMEUES1APID
					return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
				}
				value, ok := decoded.AsMMEUES1APID2()
				if !ok {
					var empty s00.MMEUES1APID
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-MME-UE-S1AP-ID-2: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(158)
					*s48.BridgeHandoverRequestIEValueFieldRowMMEUES1APID2(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.MMEUES1APID, options aper.DecodeState) (s00.MMEUES1APID, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APMMEUES1APID(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.MMEUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APMMEUES1APID(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s01.BridgeMMEUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEUES1APID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestMMEUES1APIDIEBindingFieldInject(&sealed) = func(value s00.MMEUES1APID) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(158)
				*s48.BridgeHandoverRequestIEValueFieldRowMMEUES1APID2(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestMMEUES1APIDIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID2() }
		return sealed
	}()
}
func (HandoverRequestIETable) infoManagementBasedMDTAllowed() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(165), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ManagementBasedMDTAllowed"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-ManagementBasedMDTAllowed"}}}
}

// ManagementBasedMDTAllowed returns the typed binding for the ManagementBasedMDTAllowed row of HandoverRequestIETable.
func (t HandoverRequestIETable) ManagementBasedMDTAllowed() s48.HandoverRequestManagementBasedMDTAllowedIEBinding {
	return func() s48.HandoverRequestManagementBasedMDTAllowedIEBinding {
		sealed := s48.HandoverRequestManagementBasedMDTAllowedIEBinding{}
		*s48.BridgeHandoverRequestManagementBasedMDTAllowedIEBindingFieldInfo(&sealed) = t.infoManagementBasedMDTAllowed()
		*s48.BridgeHandoverRequestManagementBasedMDTAllowedIEBindingFieldCodec(&sealed) = func() s01.ManagementBasedMDTAllowedValueCodec {
			sealed := s01.ManagementBasedMDTAllowedValueCodec{}
			*s01.BridgeManagementBasedMDTAllowedValueCodecFieldPath(&sealed) = "ManagementBasedMDTAllowed"
			*s01.BridgeManagementBasedMDTAllowedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ManagementBasedMDTAllowed, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.ManagementBasedMDTAllowed
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ManagementBasedMDTAllowed")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(165), raw)
				if err != nil {
					var empty s00.ManagementBasedMDTAllowed
					return empty, runtime.WrapDecodePath(err, "ManagementBasedMDTAllowed")
				}
				value, ok := decoded.AsManagementBasedMDTAllowed()
				if !ok {
					var empty s00.ManagementBasedMDTAllowed
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-ManagementBasedMDTAllowed: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeManagementBasedMDTAllowedValueCodecFieldEncode(&sealed) = func(value s00.ManagementBasedMDTAllowed, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(165)
					*s48.BridgeHandoverRequestIEValueFieldRowManagementBasedMDTAllowed(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeManagementBasedMDTAllowedValueCodecFieldCapture(&sealed) = func(v s00.ManagementBasedMDTAllowed, options aper.DecodeState) (s00.ManagementBasedMDTAllowed, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APManagementBasedMDTAllowed(&v, &s)
				var root aper.Snapshot
				s.End(
					f,
					&root, false)
				return v, root
			}
			*s01.BridgeManagementBasedMDTAllowedValueCodecFieldCompare(&sealed) = func(v s00.ManagementBasedMDTAllowed, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APManagementBasedMDTAllowed(&v, &s)
				s.End(f, root,

					false)
				return s.Plan(), s.BudgetValue()
			}
			*s01.BridgeManagementBasedMDTAllowedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ManagementBasedMDTAllowed"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestManagementBasedMDTAllowedIEBindingFieldInject(&sealed) = func(value s00.ManagementBasedMDTAllowed) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(165)
				*s48.BridgeHandoverRequestIEValueFieldRowManagementBasedMDTAllowed(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestManagementBasedMDTAllowedIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.ManagementBasedMDTAllowed, bool) {
			return value.AsManagementBasedMDTAllowed()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoManagementBasedMDTPLMNList() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(177), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MDTPLMNList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-ManagementBasedMDTPLMNList"}}}
}

// ManagementBasedMDTPLMNList returns the typed binding for the ManagementBasedMDTPLMNList row of HandoverRequestIETable.
func (t HandoverRequestIETable) ManagementBasedMDTPLMNList() s48.HandoverRequestMDTPLMNListIEBinding {
	return func() s48.HandoverRequestMDTPLMNListIEBinding {
		sealed := s48.HandoverRequestMDTPLMNListIEBinding{}
		*s48.BridgeHandoverRequestMDTPLMNListIEBindingFieldInfo(&sealed) = t.infoManagementBasedMDTPLMNList()
		*s48.BridgeHandoverRequestMDTPLMNListIEBindingFieldCodec(&sealed) = func() s01.MDTPLMNListValueCodec {
			sealed := s01.MDTPLMNListValueCodec{}
			*s01.BridgeMDTPLMNListValueCodecFieldPath(&sealed) = "MDTPLMNList"
			*s01.BridgeMDTPLMNListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MDTPLMNList, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MDTPLMNList
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MDTPLMNList")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(177), raw)
				if err != nil {
					var empty s00.MDTPLMNList
					return empty, runtime.WrapDecodePath(err, "MDTPLMNList")
				}
				value, ok := decoded.AsManagementBasedMDTPLMNList()
				if !ok {
					var empty s00.MDTPLMNList
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-ManagementBasedMDTPLMNList: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMDTPLMNListValueCodecFieldEncode(&sealed) = func(value s00.MDTPLMNList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(177)
					*s48.BridgeHandoverRequestIEValueFieldRowManagementBasedMDTPLMNList(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeMDTPLMNListValueCodecFieldCapture(&sealed) = func(v s00.MDTPLMNList, options aper.DecodeState) (s00.MDTPLMNList, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APMDTPLMNList(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s01.BridgeMDTPLMNListValueCodecFieldCompare(&sealed) = func(v s00.MDTPLMNList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s07.BridgeCompareS1APMDTPLMNList(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s01.BridgeMDTPLMNListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MDTPLMNList"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestMDTPLMNListIEBindingFieldInject(&sealed) = func(value s00.MDTPLMNList) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(177)
				*s48.BridgeHandoverRequestIEValueFieldRowManagementBasedMDTPLMNList(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestMDTPLMNListIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.MDTPLMNList, bool) {
			return value.AsManagementBasedMDTPLMNList()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoMaskedIMEISV() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(192), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Masked-IMEISV"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-Masked-IMEISV"}}}
}

// MaskedIMEISV returns the typed binding for the MaskedIMEISV row of HandoverRequestIETable.
func (t HandoverRequestIETable) MaskedIMEISV() s48.HandoverRequestMaskedIMEISVIEBinding {
	return func() s48.HandoverRequestMaskedIMEISVIEBinding {
		sealed := s48.HandoverRequestMaskedIMEISVIEBinding{}
		*s48.BridgeHandoverRequestMaskedIMEISVIEBindingFieldInfo(&sealed) = t.infoMaskedIMEISV()
		*s48.BridgeHandoverRequestMaskedIMEISVIEBindingFieldCodec(&sealed) = func() s01.MaskedIMEISVValueCodec {
			sealed := s01.MaskedIMEISVValueCodec{}
			*s01.BridgeMaskedIMEISVValueCodecFieldPath(&sealed) = "MaskedIMEISV"
			*s01.BridgeMaskedIMEISVValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MaskedIMEISV, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.MaskedIMEISV
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("MaskedIMEISV")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(192), raw)
				if err != nil {
					var empty s00.MaskedIMEISV
					return empty, runtime.WrapDecodePath(err, "MaskedIMEISV")
				}
				value, ok := decoded.AsMaskedIMEISV()
				if !ok {
					var empty s00.MaskedIMEISV
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-Masked-IMEISV: no selected value")
				}
				return *value, nil
			}
			*s01.BridgeMaskedIMEISVValueCodecFieldEncode(&sealed) = func(value s00.MaskedIMEISV, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(192)
					*s48.BridgeHandoverRequestIEValueFieldRowMaskedIMEISV(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgeMaskedIMEISVValueCodecFieldCapture(&sealed) = func(v s00.MaskedIMEISV, options aper.DecodeState) (s00.MaskedIMEISV, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APMaskedIMEISV(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s01.BridgeMaskedIMEISVValueCodecFieldCompare(&sealed) = func(v s00.MaskedIMEISV, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APMaskedIMEISV(&v, &s)
				s.End(f, root, false)
				return s.Plan(),
					s.
						BudgetValue()
			}
			*s01.BridgeMaskedIMEISVValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MaskedIMEISV"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestMaskedIMEISVIEBindingFieldInject(&sealed) = func(value s00.MaskedIMEISV) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(192)
				*s48.BridgeHandoverRequestIEValueFieldRowMaskedIMEISV(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestMaskedIMEISVIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.MaskedIMEISV, bool) { return value.AsMaskedIMEISV() }
		return sealed
	}()
}
func (HandoverRequestIETable) infoExpectedUEBehaviour() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(196), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ExpectedUEBehaviour"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-ExpectedUEBehaviour"}}}
}

// ExpectedUEBehaviour returns the typed binding for the ExpectedUEBehaviour row of HandoverRequestIETable.
func (t HandoverRequestIETable) ExpectedUEBehaviour() s48.HandoverRequestExpectedUEBehaviourIEBinding {
	return func() s48.HandoverRequestExpectedUEBehaviourIEBinding {
		sealed := s48.HandoverRequestExpectedUEBehaviourIEBinding{}
		*s48.BridgeHandoverRequestExpectedUEBehaviourIEBindingFieldInfo(&sealed) = t.infoExpectedUEBehaviour()
		*s48.BridgeHandoverRequestExpectedUEBehaviourIEBindingFieldCodec(&sealed) = func() s18.ExpectedUEBehaviourValueCodec {
			sealed := s18.ExpectedUEBehaviourValueCodec{}
			*s18.BridgeExpectedUEBehaviourValueCodecFieldPath(&sealed) = "ExpectedUEBehaviour"
			*s18.BridgeExpectedUEBehaviourValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ExpectedUEBehaviour, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s18.ExpectedUEBehaviour
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ExpectedUEBehaviour")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(196), raw)
				if err != nil {
					var empty s18.ExpectedUEBehaviour
					return empty, runtime.WrapDecodePath(err, "ExpectedUEBehaviour")
				}
				value, ok := decoded.AsExpectedUEBehaviour()
				if !ok {
					var empty s18.ExpectedUEBehaviour
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-ExpectedUEBehaviour: no selected value")
				}
				return *value, nil
			}
			*s18.BridgeExpectedUEBehaviourValueCodecFieldEncode(&sealed) = func(value s18.ExpectedUEBehaviour, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(196)
					*s48.BridgeHandoverRequestIEValueFieldRowExpectedUEBehaviour(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s18.BridgeExpectedUEBehaviourValueCodecFieldCapture(&sealed) = func(v s18.ExpectedUEBehaviour, options aper.DecodeState) (s18.ExpectedUEBehaviour, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s18.BridgeCaptureS1APExpectedUEBehaviour(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s18.BridgeExpectedUEBehaviourValueCodecFieldCompare(&sealed) = func(v s18.ExpectedUEBehaviour, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s18.BridgeCompareS1APExpectedUEBehaviour(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s18.BridgeExpectedUEBehaviourValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ExpectedUEBehaviour"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestExpectedUEBehaviourIEBindingFieldInject(&sealed) = func(value s18.ExpectedUEBehaviour) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(196)
				*s48.BridgeHandoverRequestIEValueFieldRowExpectedUEBehaviour(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestExpectedUEBehaviourIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s18.ExpectedUEBehaviour, bool) {
			return value.AsExpectedUEBehaviour()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoProSeAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(195), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ProSeAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-ProSeAuthorized"}}}
}

// ProSeAuthorized returns the typed binding for the ProSeAuthorized row of HandoverRequestIETable.
func (t HandoverRequestIETable) ProSeAuthorized() s48.HandoverRequestProSeAuthorizedIEBinding {
	return func() s48.HandoverRequestProSeAuthorizedIEBinding {
		sealed := s48.HandoverRequestProSeAuthorizedIEBinding{}
		*s48.BridgeHandoverRequestProSeAuthorizedIEBindingFieldInfo(&sealed) = t.infoProSeAuthorized()
		*s48.BridgeHandoverRequestProSeAuthorizedIEBindingFieldCodec(&sealed) = func() s20.ProSeAuthorizedValueCodec {
			sealed := s20.ProSeAuthorizedValueCodec{}
			*s20.BridgeProSeAuthorizedValueCodecFieldPath(&sealed) = "ProSeAuthorized"
			*s20.BridgeProSeAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ProSeAuthorized, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s20.ProSeAuthorized
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("ProSeAuthorized")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(195), raw)
				if err != nil {
					var empty s20.ProSeAuthorized
					return empty, runtime.WrapDecodePath(err, "ProSeAuthorized")
				}
				value, ok := decoded.AsProSeAuthorized()
				if !ok {
					var empty s20.ProSeAuthorized
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-ProSeAuthorized: no selected value")
				}
				return *value, nil
			}
			*s20.BridgeProSeAuthorizedValueCodecFieldEncode(&sealed) = func(value s20.ProSeAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(195)
					*s48.BridgeHandoverRequestIEValueFieldRowProSeAuthorized(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s20.BridgeProSeAuthorizedValueCodecFieldCapture(&sealed) = func(v s20.ProSeAuthorized, options aper.DecodeState) (s20.ProSeAuthorized, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s20.BridgeCaptureS1APProSeAuthorized(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s20.BridgeProSeAuthorizedValueCodecFieldCompare(&sealed) = func(v s20.ProSeAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s20.BridgeCompareS1APProSeAuthorized(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s20.BridgeProSeAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProSeAuthorized"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestProSeAuthorizedIEBindingFieldInject(&sealed) = func(value s20.ProSeAuthorized) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(195)
				*s48.BridgeHandoverRequestIEValueFieldRowProSeAuthorized(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestProSeAuthorizedIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s20.ProSeAuthorized, bool) {
			return value.AsProSeAuthorized()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoUEUserPlaneCIoTSupportIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(241), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEUserPlaneCIoTSupportIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-UEUserPlaneCIoTSupportIndicator"}}}
}

// UEUserPlaneCIoTSupportIndicator returns the typed binding for the UEUserPlaneCIoTSupportIndicator row of HandoverRequestIETable.
func (t HandoverRequestIETable) UEUserPlaneCIoTSupportIndicator() s48.HandoverRequestUEUserPlaneCIoTSupportIndicatorIEBinding {
	return func() s48.HandoverRequestUEUserPlaneCIoTSupportIndicatorIEBinding {
		sealed := s48.HandoverRequestUEUserPlaneCIoTSupportIndicatorIEBinding{}
		*s48.BridgeHandoverRequestUEUserPlaneCIoTSupportIndicatorIEBindingFieldInfo(&sealed) = t.infoUEUserPlaneCIoTSupportIndicator()
		*s48.BridgeHandoverRequestUEUserPlaneCIoTSupportIndicatorIEBindingFieldCodec(&sealed) = func() s02.UEUserPlaneCIoTSupportIndicatorValueCodec {
			sealed := s02.UEUserPlaneCIoTSupportIndicatorValueCodec{}
			*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldPath(&sealed) = "UEUserPlaneCIoTSupportIndicator"
			*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UEUserPlaneCIoTSupportIndicator, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.UEUserPlaneCIoTSupportIndicator
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("UEUserPlaneCIoTSupportIndicator")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(241), raw)
				if err != nil {
					var empty s00.UEUserPlaneCIoTSupportIndicator
					return empty, runtime.WrapDecodePath(err, "UEUserPlaneCIoTSupportIndicator")
				}
				value, ok := decoded.AsUEUserPlaneCIoTSupportIndicator()
				if !ok {
					var empty s00.UEUserPlaneCIoTSupportIndicator
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-UEUserPlaneCIoTSupportIndicator: no selected value")
				}
				return *value, nil
			}
			*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldEncode(&sealed) = func(value s00.UEUserPlaneCIoTSupportIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(241)
					*s48.BridgeHandoverRequestIEValueFieldRowUEUserPlaneCIoTSupportIndicator(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldCapture(&sealed) = func(v s00.UEUserPlaneCIoTSupportIndicator, options aper.DecodeState) (s00.UEUserPlaneCIoTSupportIndicator, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APUEUserPlaneCIoTSupportIndicator(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldCompare(&sealed) = func(v s00.UEUserPlaneCIoTSupportIndicator, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s07.BridgeCompareS1APUEUserPlaneCIoTSupportIndicator(&v, &s)

				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEUserPlaneCIoTSupportIndicator"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestUEUserPlaneCIoTSupportIndicatorIEBindingFieldInject(&sealed) = func(value s00.UEUserPlaneCIoTSupportIndicator) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(241)
				*s48.BridgeHandoverRequestIEValueFieldRowUEUserPlaneCIoTSupportIndicator(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestUEUserPlaneCIoTSupportIndicatorIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.UEUserPlaneCIoTSupportIndicator, bool) {
			return value.AsUEUserPlaneCIoTSupportIndicator()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoV2XServicesAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(240), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "V2XServicesAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-V2XServicesAuthorized"}}}
}

// V2XServicesAuthorized returns the typed binding for the V2XServicesAuthorized row of HandoverRequestIETable.
func (t HandoverRequestIETable) V2XServicesAuthorized() s48.HandoverRequestV2XServicesAuthorizedIEBinding {
	return func() s48.HandoverRequestV2XServicesAuthorizedIEBinding {
		sealed := s48.HandoverRequestV2XServicesAuthorizedIEBinding{}
		*s48.BridgeHandoverRequestV2XServicesAuthorizedIEBindingFieldInfo(&sealed) = t.infoV2XServicesAuthorized()
		*s48.BridgeHandoverRequestV2XServicesAuthorizedIEBindingFieldCodec(&sealed) = func() s47.V2XServicesAuthorizedValueCodec {
			sealed := s47.V2XServicesAuthorizedValueCodec{}
			*s47.BridgeV2XServicesAuthorizedValueCodecFieldPath(&sealed) = "V2XServicesAuthorized"
			*s47.BridgeV2XServicesAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s47.V2XServicesAuthorized, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s47.V2XServicesAuthorized
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("V2XServicesAuthorized")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(240), raw)
				if err != nil {
					var empty s47.V2XServicesAuthorized
					return empty, runtime.WrapDecodePath(err, "V2XServicesAuthorized")
				}
				value, ok := decoded.AsV2XServicesAuthorized()
				if !ok {
					var empty s47.V2XServicesAuthorized
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-V2XServicesAuthorized: no selected value")
				}
				return *value, nil
			}
			*s47.BridgeV2XServicesAuthorizedValueCodecFieldEncode(&sealed) = func(value s47.V2XServicesAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(240)
					*s48.BridgeHandoverRequestIEValueFieldRowV2XServicesAuthorized(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s47.BridgeV2XServicesAuthorizedValueCodecFieldCapture(&sealed) = func(v s47.V2XServicesAuthorized, options aper.DecodeState) (s47.V2XServicesAuthorized, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s47.BridgeCaptureS1APV2XServicesAuthorized(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)

				return v, root
			}
			*s47.BridgeV2XServicesAuthorizedValueCodecFieldCompare(&sealed) = func(v s47.V2XServicesAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s47.BridgeCompareS1APV2XServicesAuthorized(&v, &s)
				s.End(f, root, false)

				return s.Plan(), s.BudgetValue()
			}
			*s47.BridgeV2XServicesAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:V2XServicesAuthorized"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestV2XServicesAuthorizedIEBindingFieldInject(&sealed) = func(value s47.V2XServicesAuthorized) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(240)
				*s48.BridgeHandoverRequestIEValueFieldRowV2XServicesAuthorized(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestV2XServicesAuthorizedIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s47.V2XServicesAuthorized, bool) {
			return value.AsV2XServicesAuthorized()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoUESidelinkAggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(248), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UESidelinkAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-UESidelinkAggregateMaximumBitrate"}}}
}

// UESidelinkAggregateMaximumBitrate returns the typed binding for the UESidelinkAggregateMaximumBitrate row of HandoverRequestIETable.
func (t HandoverRequestIETable) UESidelinkAggregateMaximumBitrate() s48.HandoverRequestUESidelinkAggregateMaximumBitrateIEBinding {
	return func() s48.HandoverRequestUESidelinkAggregateMaximumBitrateIEBinding {
		sealed := s48.HandoverRequestUESidelinkAggregateMaximumBitrateIEBinding{}
		*s48.BridgeHandoverRequestUESidelinkAggregateMaximumBitrateIEBindingFieldInfo(&sealed) = t.infoUESidelinkAggregateMaximumBitrate()
		*s48.BridgeHandoverRequestUESidelinkAggregateMaximumBitrateIEBindingFieldCodec(&sealed) = func() s38.UESidelinkAggregateMaximumBitrateValueCodec {
			sealed := s38.UESidelinkAggregateMaximumBitrateValueCodec{}
			*s38.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "UESidelinkAggregateMaximumBitrate"
			*s38.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s38.UESidelinkAggregateMaximumBitrate, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s38.UESidelinkAggregateMaximumBitrate
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("UESidelinkAggregateMaximumBitrate")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(248), raw)
				if err != nil {
					var empty s38.UESidelinkAggregateMaximumBitrate
					return empty, runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitrate")
				}
				value, ok := decoded.AsUESidelinkAggregateMaximumBitrate()
				if !ok {
					var empty s38.UESidelinkAggregateMaximumBitrate
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-UESidelinkAggregateMaximumBitrate: no selected value")
				}
				return *value, nil
			}
			*s38.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s38.UESidelinkAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(248)
					*s48.BridgeHandoverRequestIEValueFieldRowUESidelinkAggregateMaximumBitrate(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s38.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s38.UESidelinkAggregateMaximumBitrate, options aper.DecodeState) (s38.UESidelinkAggregateMaximumBitrate, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s38.BridgeCaptureS1APUESidelinkAggregateMaximumBitrate(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s38.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s38.UESidelinkAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s38.BridgeCompareS1APUESidelinkAggregateMaximumBitrate(
					&v,

					&s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s38.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UESidelinkAggregateMaximumBitrate"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestUESidelinkAggregateMaximumBitrateIEBindingFieldInject(&sealed) = func(value s38.UESidelinkAggregateMaximumBitrate) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(248)
				*s48.BridgeHandoverRequestIEValueFieldRowUESidelinkAggregateMaximumBitrate(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestUESidelinkAggregateMaximumBitrateIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s38.UESidelinkAggregateMaximumBitrate, bool) {
			return value.AsUESidelinkAggregateMaximumBitrate()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoEnhancedCoverageRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(251), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EnhancedCoverageRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-EnhancedCoverageRestricted"}}}
}

// EnhancedCoverageRestricted returns the typed binding for the EnhancedCoverageRestricted row of HandoverRequestIETable.
func (t HandoverRequestIETable) EnhancedCoverageRestricted() s48.HandoverRequestEnhancedCoverageRestrictedIEBinding {
	return func() s48.HandoverRequestEnhancedCoverageRestrictedIEBinding {
		sealed := s48.HandoverRequestEnhancedCoverageRestrictedIEBinding{}
		*s48.BridgeHandoverRequestEnhancedCoverageRestrictedIEBindingFieldInfo(&sealed) = t.infoEnhancedCoverageRestricted()
		*s48.BridgeHandoverRequestEnhancedCoverageRestrictedIEBindingFieldCodec(&sealed) = func() s00.EnhancedCoverageRestrictedValueCodec {
			sealed := s00.EnhancedCoverageRestrictedValueCodec{}
			*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldPath(&sealed) = "EnhancedCoverageRestricted"
			*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EnhancedCoverageRestricted, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.EnhancedCoverageRestricted
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("EnhancedCoverageRestricted")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(251), raw)
				if err != nil {
					var empty s00.EnhancedCoverageRestricted
					return empty, runtime.WrapDecodePath(err, "EnhancedCoverageRestricted")
				}
				value, ok := decoded.AsEnhancedCoverageRestricted()
				if !ok {
					var empty s00.EnhancedCoverageRestricted
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-EnhancedCoverageRestricted: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldEncode(&sealed) = func(value s00.EnhancedCoverageRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(251)
					*s48.BridgeHandoverRequestIEValueFieldRowEnhancedCoverageRestricted(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldCapture(&sealed) = func(v s00.EnhancedCoverageRestricted, options aper.DecodeState) (s00.EnhancedCoverageRestricted, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APEnhancedCoverageRestricted(&v, &s)
				var root aper.Snapshot
				s.End(
					f, &root, false)
				return v, root
			}
			*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldCompare(&sealed) = func(v s00.EnhancedCoverageRestricted, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APEnhancedCoverageRestricted(&v, &s)
				s.End(f,
					root,

					false)
				return s.Plan(), s.BudgetValue()
			}
			*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EnhancedCoverageRestricted"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestEnhancedCoverageRestrictedIEBindingFieldInject(&sealed) = func(value s00.EnhancedCoverageRestricted) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(251)
				*s48.BridgeHandoverRequestIEValueFieldRowEnhancedCoverageRestricted(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestEnhancedCoverageRestrictedIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.EnhancedCoverageRestricted, bool) {
			return value.AsEnhancedCoverageRestricted()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoNRUESecurityCapabilities() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(269), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESecurityCapabilities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-NRUESecurityCapabilities"}}}
}

// NRUESecurityCapabilities returns the typed binding for the NRUESecurityCapabilities row of HandoverRequestIETable.
func (t HandoverRequestIETable) NRUESecurityCapabilities() s48.HandoverRequestNRUESecurityCapabilitiesIEBinding {
	return func() s48.HandoverRequestNRUESecurityCapabilitiesIEBinding {
		sealed := s48.HandoverRequestNRUESecurityCapabilitiesIEBinding{}
		*s48.BridgeHandoverRequestNRUESecurityCapabilitiesIEBindingFieldInfo(&sealed) = t.infoNRUESecurityCapabilities()
		*s48.BridgeHandoverRequestNRUESecurityCapabilitiesIEBindingFieldCodec(&sealed) = func() s19.NRUESecurityCapabilitiesValueCodec {
			sealed := s19.NRUESecurityCapabilitiesValueCodec{}
			*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldPath(&sealed) = "NRUESecurityCapabilities"
			*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NRUESecurityCapabilities, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s19.NRUESecurityCapabilities
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("NRUESecurityCapabilities")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(269), raw)
				if err != nil {
					var empty s19.NRUESecurityCapabilities
					return empty, runtime.WrapDecodePath(err, "NRUESecurityCapabilities")
				}
				value, ok := decoded.AsNRUESecurityCapabilities()
				if !ok {
					var empty s19.NRUESecurityCapabilities
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-NRUESecurityCapabilities: no selected value")
				}
				return *value, nil
			}
			*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(&sealed) = func(value s19.NRUESecurityCapabilities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(269)
					*s48.BridgeHandoverRequestIEValueFieldRowNRUESecurityCapabilities(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldCapture(&sealed) = func(v s19.NRUESecurityCapabilities, options aper.DecodeState) (s19.NRUESecurityCapabilities, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s19.BridgeCaptureS1APNRUESecurityCapabilities(&v, &s)
				var root aper.Snapshot
				s.End(f, &root,

					false)
				return v, root
			}
			*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldCompare(&sealed) = func(v s19.NRUESecurityCapabilities, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s19.BridgeCompareS1APNRUESecurityCapabilities(&v, &s)
				s.End(f, root,

					false,
				)
				return s.Plan(), s.BudgetValue()
			}
			*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRUESecurityCapabilities"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestNRUESecurityCapabilitiesIEBindingFieldInject(&sealed) = func(value s19.NRUESecurityCapabilities) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(269)
				*s48.BridgeHandoverRequestIEValueFieldRowNRUESecurityCapabilities(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestNRUESecurityCapabilitiesIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s19.NRUESecurityCapabilities, bool) {
			return value.AsNRUESecurityCapabilities()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoCEModeBRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(271), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CE-ModeBRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-CE-ModeBRestricted"}}}
}

// CEModeBRestricted returns the typed binding for the CEModeBRestricted row of HandoverRequestIETable.
func (t HandoverRequestIETable) CEModeBRestricted() s48.HandoverRequestCEModeBRestrictedIEBinding {
	return func() s48.HandoverRequestCEModeBRestrictedIEBinding {
		sealed := s48.HandoverRequestCEModeBRestrictedIEBinding{}
		*s48.BridgeHandoverRequestCEModeBRestrictedIEBindingFieldInfo(&sealed) = t.infoCEModeBRestricted()
		*s48.BridgeHandoverRequestCEModeBRestrictedIEBindingFieldCodec(&sealed) = func() s00.CEModeBRestrictedValueCodec {
			sealed := s00.CEModeBRestrictedValueCodec{}
			*s00.BridgeCEModeBRestrictedValueCodecFieldPath(&sealed) = "CEModeBRestricted"
			*s00.BridgeCEModeBRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CEModeBRestricted, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.CEModeBRestricted
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("CEModeBRestricted")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(271), raw)
				if err != nil {
					var empty s00.CEModeBRestricted
					return empty, runtime.WrapDecodePath(err, "CEModeBRestricted")
				}
				value, ok := decoded.AsCEModeBRestricted()
				if !ok {
					var empty s00.CEModeBRestricted
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-CE-ModeBRestricted: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeCEModeBRestrictedValueCodecFieldEncode(&sealed) = func(value s00.CEModeBRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(271)
					*s48.BridgeHandoverRequestIEValueFieldRowCEModeBRestricted(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeCEModeBRestrictedValueCodecFieldCapture(&sealed) = func(v s00.CEModeBRestricted, options aper.DecodeState) (s00.CEModeBRestricted, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APCEModeBRestricted(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v,
					root

			}
			*s00.BridgeCEModeBRestrictedValueCodecFieldCompare(&sealed) = func(v s00.CEModeBRestricted, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APCEModeBRestricted(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s00.BridgeCEModeBRestrictedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CEModeBRestricted"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestCEModeBRestrictedIEBindingFieldInject(&sealed) = func(value s00.CEModeBRestricted) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(271)
				*s48.BridgeHandoverRequestIEValueFieldRowCEModeBRestricted(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestCEModeBRestrictedIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.CEModeBRestricted, bool) {
			return value.AsCEModeBRestricted()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoAerialUEsubscriptionInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(277), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AerialUEsubscriptionInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-AerialUEsubscriptionInformation"}}}
}

// AerialUEsubscriptionInformation returns the typed binding for the AerialUEsubscriptionInformation row of HandoverRequestIETable.
func (t HandoverRequestIETable) AerialUEsubscriptionInformation() s48.HandoverRequestAerialUEsubscriptionInformationIEBinding {
	return func() s48.HandoverRequestAerialUEsubscriptionInformationIEBinding {
		sealed := s48.HandoverRequestAerialUEsubscriptionInformationIEBinding{}
		*s48.BridgeHandoverRequestAerialUEsubscriptionInformationIEBindingFieldInfo(&sealed) = t.infoAerialUEsubscriptionInformation()
		*s48.BridgeHandoverRequestAerialUEsubscriptionInformationIEBindingFieldCodec(&sealed) = func() s00.AerialUEsubscriptionInformationValueCodec {
			sealed := s00.AerialUEsubscriptionInformationValueCodec{}
			*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldPath(&sealed) = "AerialUEsubscriptionInformation"
			*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AerialUEsubscriptionInformation, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.AerialUEsubscriptionInformation
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("AerialUEsubscriptionInformation")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(277), raw)
				if err != nil {
					var empty s00.AerialUEsubscriptionInformation
					return empty, runtime.WrapDecodePath(err, "AerialUEsubscriptionInformation")
				}
				value, ok := decoded.AsAerialUEsubscriptionInformation()
				if !ok {
					var empty s00.AerialUEsubscriptionInformation
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-AerialUEsubscriptionInformation: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldEncode(&sealed) = func(value s00.AerialUEsubscriptionInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(277)
					*s48.BridgeHandoverRequestIEValueFieldRowAerialUEsubscriptionInformation(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldCapture(&sealed) = func(v s00.AerialUEsubscriptionInformation, options aper.DecodeState) (s00.AerialUEsubscriptionInformation, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APAerialUEsubscriptionInformation(&v, &s)
				var root aper.Snapshot

				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldCompare(&sealed) = func(v s00.AerialUEsubscriptionInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APAerialUEsubscriptionInformation(&v, &s)

				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AerialUEsubscriptionInformation"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestAerialUEsubscriptionInformationIEBindingFieldInject(&sealed) = func(value s00.AerialUEsubscriptionInformation) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(277)
				*s48.BridgeHandoverRequestIEValueFieldRowAerialUEsubscriptionInformation(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestAerialUEsubscriptionInformationIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.AerialUEsubscriptionInformation, bool) {
			return value.AsAerialUEsubscriptionInformation()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoPendingDataIndication() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(283), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PendingDataIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-PendingDataIndication"}}}
}

// PendingDataIndication returns the typed binding for the PendingDataIndication row of HandoverRequestIETable.
func (t HandoverRequestIETable) PendingDataIndication() s48.HandoverRequestPendingDataIndicationIEBinding {
	return func() s48.HandoverRequestPendingDataIndicationIEBinding {
		sealed := s48.HandoverRequestPendingDataIndicationIEBinding{}
		*s48.BridgeHandoverRequestPendingDataIndicationIEBindingFieldInfo(&sealed) = t.infoPendingDataIndication()
		*s48.BridgeHandoverRequestPendingDataIndicationIEBindingFieldCodec(&sealed) = func() s01.PendingDataIndicationValueCodec {
			sealed := s01.PendingDataIndicationValueCodec{}
			*s01.BridgePendingDataIndicationValueCodecFieldPath(&sealed) = "PendingDataIndication"
			*s01.BridgePendingDataIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PendingDataIndication, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.PendingDataIndication
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("PendingDataIndication")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(283), raw)
				if err != nil {
					var empty s00.PendingDataIndication
					return empty, runtime.WrapDecodePath(err, "PendingDataIndication")
				}
				value, ok := decoded.AsPendingDataIndication()
				if !ok {
					var empty s00.PendingDataIndication
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-PendingDataIndication: no selected value")
				}
				return *value, nil
			}
			*s01.BridgePendingDataIndicationValueCodecFieldEncode(&sealed) = func(value s00.PendingDataIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(283)
					*s48.BridgeHandoverRequestIEValueFieldRowPendingDataIndication(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s01.BridgePendingDataIndicationValueCodecFieldCapture(&sealed) = func(v s00.PendingDataIndication, options aper.DecodeState) (s00.PendingDataIndication, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APPendingDataIndication(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)

				return v, root
			}
			*s01.BridgePendingDataIndicationValueCodecFieldCompare(&sealed) = func(v s00.PendingDataIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APPendingDataIndication(&v, &s)
				s.End(f, root, false)

				return s.Plan(), s.BudgetValue()
			}
			*s01.BridgePendingDataIndicationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PendingDataIndication"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestPendingDataIndicationIEBindingFieldInject(&sealed) = func(value s00.PendingDataIndication) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(283)
				*s48.BridgeHandoverRequestIEValueFieldRowPendingDataIndication(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestPendingDataIndicationIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.PendingDataIndication, bool) {
			return value.AsPendingDataIndication()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoSubscriptionBasedUEDifferentiationInfo() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(278), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Subscription-Based-UE-DifferentiationInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-Subscription-Based-UE-DifferentiationInfo"}}}
}

// SubscriptionBasedUEDifferentiationInfo returns the typed binding for the SubscriptionBasedUEDifferentiationInfo row of HandoverRequestIETable.
func (t HandoverRequestIETable) SubscriptionBasedUEDifferentiationInfo() s48.HandoverRequestSubscriptionBasedUEDifferentiationInfoIEBinding {
	return func() s48.HandoverRequestSubscriptionBasedUEDifferentiationInfoIEBinding {
		sealed := s48.HandoverRequestSubscriptionBasedUEDifferentiationInfoIEBinding{}
		*s48.BridgeHandoverRequestSubscriptionBasedUEDifferentiationInfoIEBindingFieldInfo(&sealed) = t.infoSubscriptionBasedUEDifferentiationInfo()
		*s48.BridgeHandoverRequestSubscriptionBasedUEDifferentiationInfoIEBindingFieldCodec(&sealed) = func() s31.SubscriptionBasedUEDifferentiationInfoValueCodec {
			sealed := s31.SubscriptionBasedUEDifferentiationInfoValueCodec{}
			*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldPath(&sealed) = "SubscriptionBasedUEDifferentiationInfo"
			*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.SubscriptionBasedUEDifferentiationInfo, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s31.SubscriptionBasedUEDifferentiationInfo
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("SubscriptionBasedUEDifferentiationInfo")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(278), raw)
				if err != nil {
					var empty s31.SubscriptionBasedUEDifferentiationInfo
					return empty, runtime.WrapDecodePath(err, "SubscriptionBasedUEDifferentiationInfo")
				}
				value, ok := decoded.AsSubscriptionBasedUEDifferentiationInfo()
				if !ok {
					var empty s31.SubscriptionBasedUEDifferentiationInfo
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-Subscription-Based-UE-DifferentiationInfo: no selected value")
				}
				return *value, nil
			}
			*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldEncode(&sealed) = func(value s31.SubscriptionBasedUEDifferentiationInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(278)
					*s48.BridgeHandoverRequestIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldCapture(&sealed) = func(v s31.SubscriptionBasedUEDifferentiationInfo, options aper.DecodeState) (s31.SubscriptionBasedUEDifferentiationInfo, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s31.BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(
					&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldCompare(&sealed) = func(v s31.SubscriptionBasedUEDifferentiationInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s31.BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.
					BudgetValue()
			}
			*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SubscriptionBasedUEDifferentiationInfo"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestSubscriptionBasedUEDifferentiationInfoIEBindingFieldInject(&sealed) = func(value s31.SubscriptionBasedUEDifferentiationInfo) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(278)
				*s48.BridgeHandoverRequestIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestSubscriptionBasedUEDifferentiationInfoIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s31.SubscriptionBasedUEDifferentiationInfo, bool) {
			return value.AsSubscriptionBasedUEDifferentiationInfo()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoAdditionalRRMPriorityIndex() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(299), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AdditionalRRMPriorityIndex"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-AdditionalRRMPriorityIndex"}}}
}

// AdditionalRRMPriorityIndex returns the typed binding for the AdditionalRRMPriorityIndex row of HandoverRequestIETable.
func (t HandoverRequestIETable) AdditionalRRMPriorityIndex() s48.HandoverRequestAdditionalRRMPriorityIndexIEBinding {
	return func() s48.HandoverRequestAdditionalRRMPriorityIndexIEBinding {
		sealed := s48.HandoverRequestAdditionalRRMPriorityIndexIEBinding{}
		*s48.BridgeHandoverRequestAdditionalRRMPriorityIndexIEBindingFieldInfo(&sealed) = t.infoAdditionalRRMPriorityIndex()
		*s48.BridgeHandoverRequestAdditionalRRMPriorityIndexIEBindingFieldCodec(&sealed) = func() s00.AdditionalRRMPriorityIndexValueCodec {
			sealed := s00.AdditionalRRMPriorityIndexValueCodec{}
			*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldPath(&sealed) = "AdditionalRRMPriorityIndex"
			*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AdditionalRRMPriorityIndex, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.AdditionalRRMPriorityIndex
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("AdditionalRRMPriorityIndex")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(299), raw)
				if err != nil {
					var empty s00.AdditionalRRMPriorityIndex
					return empty, runtime.WrapDecodePath(err, "AdditionalRRMPriorityIndex")
				}
				value, ok := decoded.AsAdditionalRRMPriorityIndex()
				if !ok {
					var empty s00.AdditionalRRMPriorityIndex
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-AdditionalRRMPriorityIndex: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldEncode(&sealed) = func(value s00.AdditionalRRMPriorityIndex, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(299)
					*s48.BridgeHandoverRequestIEValueFieldRowAdditionalRRMPriorityIndex(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldCapture(&sealed) = func(v s00.AdditionalRRMPriorityIndex, options aper.DecodeState) (s00.AdditionalRRMPriorityIndex, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APAdditionalRRMPriorityIndex(&v, &s)
				var root aper.Snapshot
				s.End(
					f, &root, false)
				return v, root
			}
			*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldCompare(&sealed) = func(v s00.AdditionalRRMPriorityIndex, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APAdditionalRRMPriorityIndex(&v, &s)
				s.End(f,
					root,

					false)
				return s.Plan(), s.BudgetValue()
			}
			*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AdditionalRRMPriorityIndex"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestAdditionalRRMPriorityIndexIEBindingFieldInject(&sealed) = func(value s00.AdditionalRRMPriorityIndex) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(299)
				*s48.BridgeHandoverRequestIEValueFieldRowAdditionalRRMPriorityIndex(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestAdditionalRRMPriorityIndexIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.AdditionalRRMPriorityIndex, bool) {
			return value.AsAdditionalRRMPriorityIndex()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoIABAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(301), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "IAB-Authorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-IAB-Authorized"}}}
}

// IABAuthorized returns the typed binding for the IABAuthorized row of HandoverRequestIETable.
func (t HandoverRequestIETable) IABAuthorized() s48.HandoverRequestIABAuthorizedIEBinding {
	return func() s48.HandoverRequestIABAuthorizedIEBinding {
		sealed := s48.HandoverRequestIABAuthorizedIEBinding{}
		*s48.BridgeHandoverRequestIABAuthorizedIEBindingFieldInfo(&sealed) = t.infoIABAuthorized()
		*s48.BridgeHandoverRequestIABAuthorizedIEBindingFieldCodec(&sealed) = func() s00.IABAuthorizedValueCodec {
			sealed := s00.IABAuthorizedValueCodec{}
			*s00.BridgeIABAuthorizedValueCodecFieldPath(&sealed) = "IABAuthorized"
			*s00.BridgeIABAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.IABAuthorized, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.IABAuthorized
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("IABAuthorized")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(301), raw)
				if err != nil {
					var empty s00.IABAuthorized
					return empty, runtime.WrapDecodePath(err, "IABAuthorized")
				}
				value, ok := decoded.AsIABAuthorized()
				if !ok {
					var empty s00.IABAuthorized
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-IAB-Authorized: no selected value")
				}
				return *value, nil
			}
			*s00.BridgeIABAuthorizedValueCodecFieldEncode(&sealed) = func(value s00.IABAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(301)
					*s48.BridgeHandoverRequestIEValueFieldRowIABAuthorized(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s00.BridgeIABAuthorizedValueCodecFieldCapture(&sealed) = func(v s00.IABAuthorized, options aper.DecodeState) (s00.IABAuthorized, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APIABAuthorized(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s00.BridgeIABAuthorizedValueCodecFieldCompare(&sealed) = func(v s00.IABAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s02.BridgeCompareS1APIABAuthorized(&v, &s)
				s.End(f, root, false)
				return s.Plan(),

					s.BudgetValue()
			}
			*s00.BridgeIABAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:IABAuthorized"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestIABAuthorizedIEBindingFieldInject(&sealed) = func(value s00.IABAuthorized) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(301)
				*s48.BridgeHandoverRequestIEValueFieldRowIABAuthorized(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestIABAuthorizedIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.IABAuthorized, bool) { return value.AsIABAuthorized() }
		return sealed
	}()
}
func (HandoverRequestIETable) infoNRV2XServicesAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(306), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRV2XServicesAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-NRV2XServicesAuthorized"}}}
}

// NRV2XServicesAuthorized returns the typed binding for the NRV2XServicesAuthorized row of HandoverRequestIETable.
func (t HandoverRequestIETable) NRV2XServicesAuthorized() s48.HandoverRequestNRV2XServicesAuthorizedIEBinding {
	return func() s48.HandoverRequestNRV2XServicesAuthorizedIEBinding {
		sealed := s48.HandoverRequestNRV2XServicesAuthorizedIEBinding{}
		*s48.BridgeHandoverRequestNRV2XServicesAuthorizedIEBindingFieldInfo(&sealed) = t.infoNRV2XServicesAuthorized()
		*s48.BridgeHandoverRequestNRV2XServicesAuthorizedIEBindingFieldCodec(&sealed) = func() s20.NRV2XServicesAuthorizedValueCodec {
			sealed := s20.NRV2XServicesAuthorizedValueCodec{}
			*s20.BridgeNRV2XServicesAuthorizedValueCodecFieldPath(&sealed) = "NRV2XServicesAuthorized"
			*s20.BridgeNRV2XServicesAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.NRV2XServicesAuthorized, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s20.NRV2XServicesAuthorized
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("NRV2XServicesAuthorized")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(306), raw)
				if err != nil {
					var empty s20.NRV2XServicesAuthorized
					return empty, runtime.WrapDecodePath(err, "NRV2XServicesAuthorized")
				}
				value, ok := decoded.AsNRV2XServicesAuthorized()
				if !ok {
					var empty s20.NRV2XServicesAuthorized
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-NRV2XServicesAuthorized: no selected value")
				}
				return *value, nil
			}
			*s20.BridgeNRV2XServicesAuthorizedValueCodecFieldEncode(&sealed) = func(value s20.NRV2XServicesAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(306)
					*s48.BridgeHandoverRequestIEValueFieldRowNRV2XServicesAuthorized(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s20.BridgeNRV2XServicesAuthorizedValueCodecFieldCapture(&sealed) = func(v s20.NRV2XServicesAuthorized, options aper.DecodeState) (s20.NRV2XServicesAuthorized, aper.Snapshot) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s20.BridgeCaptureS1APNRV2XServicesAuthorized(&v, &s)
				var root aper.Snapshot
				s.End(f, &root,

					false,
				)
				return v, root
			}
			*s20.BridgeNRV2XServicesAuthorizedValueCodecFieldCompare(&sealed) = func(v s20.NRV2XServicesAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s20.BridgeCompareS1APNRV2XServicesAuthorized(&v, &s)
				s.End(f, root,
					false,
				)
				return s.Plan(), s.BudgetValue()
			}
			*s20.BridgeNRV2XServicesAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRV2XServicesAuthorized"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestNRV2XServicesAuthorizedIEBindingFieldInject(&sealed) = func(value s20.NRV2XServicesAuthorized) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(306)
				*s48.BridgeHandoverRequestIEValueFieldRowNRV2XServicesAuthorized(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestNRV2XServicesAuthorizedIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s20.NRV2XServicesAuthorized, bool) {
			return value.AsNRV2XServicesAuthorized()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoNRUESidelinkAggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(307), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESidelinkAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-NRUESidelinkAggregateMaximumBitrate"}}}
}

// NRUESidelinkAggregateMaximumBitrate returns the typed binding for the NRUESidelinkAggregateMaximumBitrate row of HandoverRequestIETable.
func (t HandoverRequestIETable) NRUESidelinkAggregateMaximumBitrate() s48.HandoverRequestNRUESidelinkAggregateMaximumBitrateIEBinding {
	return func() s48.HandoverRequestNRUESidelinkAggregateMaximumBitrateIEBinding {
		sealed := s48.HandoverRequestNRUESidelinkAggregateMaximumBitrateIEBinding{}
		*s48.BridgeHandoverRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldInfo(&sealed) = t.infoNRUESidelinkAggregateMaximumBitrate()
		*s48.BridgeHandoverRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldCodec(&sealed) = func() s20.NRUESidelinkAggregateMaximumBitrateValueCodec {
			sealed := s20.NRUESidelinkAggregateMaximumBitrateValueCodec{}
			*s20.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "NRUESidelinkAggregateMaximumBitrate"
			*s20.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.NRUESidelinkAggregateMaximumBitrate, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s20.NRUESidelinkAggregateMaximumBitrate
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("NRUESidelinkAggregateMaximumBitrate")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(307), raw)
				if err != nil {
					var empty s20.NRUESidelinkAggregateMaximumBitrate
					return empty, runtime.WrapDecodePath(err, "NRUESidelinkAggregateMaximumBitrate")
				}
				value, ok := decoded.AsNRUESidelinkAggregateMaximumBitrate()
				if !ok {
					var empty s20.NRUESidelinkAggregateMaximumBitrate
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-NRUESidelinkAggregateMaximumBitrate: no selected value")
				}
				return *value, nil
			}
			*s20.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s20.NRUESidelinkAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(307)
					*s48.BridgeHandoverRequestIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s20.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s20.NRUESidelinkAggregateMaximumBitrate, options aper.DecodeState) (s20.NRUESidelinkAggregateMaximumBitrate, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s20.BridgeCaptureS1APNRUESidelinkAggregateMaximumBitrate(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root

			}
			*s20.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s20.NRUESidelinkAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s20.BridgeCompareS1APNRUESidelinkAggregateMaximumBitrate(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s20.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRUESidelinkAggregateMaximumBitrate"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldInject(&sealed) = func(value s20.NRUESidelinkAggregateMaximumBitrate) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(307)
				*s48.BridgeHandoverRequestIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s20.NRUESidelinkAggregateMaximumBitrate, bool) {
			return value.AsNRUESidelinkAggregateMaximumBitrate()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoPC5QoSParameters() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(308), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PC5QoSParameters"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-PC5QoSParameters"}}}
}

// PC5QoSParameters returns the typed binding for the PC5QoSParameters row of HandoverRequestIETable.
func (t HandoverRequestIETable) PC5QoSParameters() s48.HandoverRequestPC5QoSParametersIEBinding {
	return func() s48.HandoverRequestPC5QoSParametersIEBinding {
		sealed := s48.HandoverRequestPC5QoSParametersIEBinding{}
		*s48.BridgeHandoverRequestPC5QoSParametersIEBindingFieldInfo(&sealed) = t.infoPC5QoSParameters()
		*s48.BridgeHandoverRequestPC5QoSParametersIEBindingFieldCodec(&sealed) = func() s24.PC5QoSParametersValueCodec {
			sealed := s24.PC5QoSParametersValueCodec{}
			*s24.BridgePC5QoSParametersValueCodecFieldPath(&sealed) = "PC5QoSParameters"
			*s24.BridgePC5QoSParametersValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.PC5QoSParameters, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s24.PC5QoSParameters
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("PC5QoSParameters")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(308), raw)
				if err != nil {
					var empty s24.PC5QoSParameters
					return empty, runtime.WrapDecodePath(err, "PC5QoSParameters")
				}
				value, ok := decoded.AsPC5QoSParameters()
				if !ok {
					var empty s24.PC5QoSParameters
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-PC5QoSParameters: no selected value")
				}
				return *value, nil
			}
			*s24.BridgePC5QoSParametersValueCodecFieldEncode(&sealed) = func(value s24.PC5QoSParameters, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(308)
					*s48.BridgeHandoverRequestIEValueFieldRowPC5QoSParameters(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s24.BridgePC5QoSParametersValueCodecFieldCapture(&sealed) = func(v s24.PC5QoSParameters, options aper.DecodeState) (s24.PC5QoSParameters, aper.Snapshot) {
				s := aper.SemanticCaptureFor(
					options)
				f := s.Begin()
				s24.BridgeCaptureS1APPC5QoSParameters(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s24.BridgePC5QoSParametersValueCodecFieldCompare(&sealed) = func(v s24.PC5QoSParameters, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s24.BridgeCompareS1APPC5QoSParameters(&v, &s)
				s.End(f, root, false)
				return s.
					Plan(), s.BudgetValue()
			}
			*s24.BridgePC5QoSParametersValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PC5QoSParameters"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestPC5QoSParametersIEBindingFieldInject(&sealed) = func(value s24.PC5QoSParameters) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(308)
				*s48.BridgeHandoverRequestIEValueFieldRowPC5QoSParameters(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestPC5QoSParametersIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s24.PC5QoSParameters, bool) {
			return value.AsPC5QoSParameters()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoUERadioCapabilityID() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(314), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapabilityID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-UERadioCapabilityID"}}}
}

// UERadioCapabilityID returns the typed binding for the UERadioCapabilityID row of HandoverRequestIETable.
func (t HandoverRequestIETable) UERadioCapabilityID() s48.HandoverRequestUERadioCapabilityIDIEBinding {
	return func() s48.HandoverRequestUERadioCapabilityIDIEBinding {
		sealed := s48.HandoverRequestUERadioCapabilityIDIEBinding{}
		*s48.BridgeHandoverRequestUERadioCapabilityIDIEBindingFieldInfo(&sealed) = t.infoUERadioCapabilityID()
		*s48.BridgeHandoverRequestUERadioCapabilityIDIEBindingFieldCodec(&sealed) = func() s02.UERadioCapabilityIDValueCodec {
			sealed := s02.UERadioCapabilityIDValueCodec{}
			*s02.BridgeUERadioCapabilityIDValueCodecFieldPath(&sealed) = "UERadioCapabilityID"
			*s02.BridgeUERadioCapabilityIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapabilityID, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.UERadioCapabilityID
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("UERadioCapabilityID")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(314), raw)
				if err != nil {
					var empty s00.UERadioCapabilityID
					return empty, runtime.WrapDecodePath(err, "UERadioCapabilityID")
				}
				value, ok := decoded.AsUERadioCapabilityID()
				if !ok {
					var empty s00.UERadioCapabilityID
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-UERadioCapabilityID: no selected value")
				}
				return *value, nil
			}
			*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapabilityID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
					*s48.BridgeHandoverRequestIEValueFieldRowUERadioCapabilityID(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s02.BridgeUERadioCapabilityIDValueCodecFieldCapture(&sealed) = func(v s00.UERadioCapabilityID, options aper.DecodeState) (s00.UERadioCapabilityID, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APUERadioCapabilityID(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s02.BridgeUERadioCapabilityIDValueCodecFieldCompare(&sealed) = func(v s00.UERadioCapabilityID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s07.BridgeCompareS1APUERadioCapabilityID(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s02.BridgeUERadioCapabilityIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UERadioCapabilityID"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestUERadioCapabilityIDIEBindingFieldInject(&sealed) = func(value s00.UERadioCapabilityID) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(314)
				*s48.BridgeHandoverRequestIEValueFieldRowUERadioCapabilityID(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestUERadioCapabilityIDIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.UERadioCapabilityID, bool) {
			return value.AsUERadioCapabilityID()
		}
		return sealed
	}()
}
func (HandoverRequestIETable) infoTimeRefDistribution() s00.FieldInfo {
	return s00.FieldInfo{Table: HandoverRequestIEs().ID(), ID: s00.ProtocolIEID(355), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TimeRefDistribution"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "HandoverRequestIEs", Row: "id-TimeRefDistribution"}}}
}

// TimeRefDistribution returns the typed binding for the TimeRefDistribution row of HandoverRequestIETable.
func (t HandoverRequestIETable) TimeRefDistribution() s48.HandoverRequestTimeRefDistributionIEBinding {
	return func() s48.HandoverRequestTimeRefDistributionIEBinding {
		sealed := s48.HandoverRequestTimeRefDistributionIEBinding{}
		*s48.BridgeHandoverRequestTimeRefDistributionIEBindingFieldInfo(&sealed) = t.infoTimeRefDistribution()
		*s48.BridgeHandoverRequestTimeRefDistributionIEBindingFieldCodec(&sealed) = func() s02.TimeRefDistributionValueCodec {
			sealed := s02.TimeRefDistributionValueCodec{}
			*s02.BridgeTimeRefDistributionValueCodecFieldPath(&sealed) = "TimeRefDistribution"
			*s02.BridgeTimeRefDistributionValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TimeRefDistribution, error) {
				raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
				if err != nil {
					var empty s00.TimeRefDistribution
					return empty, err
				}
				raw.BudgetBuffer().EnterComponent("TimeRefDistribution")
				var zero s48.HandoverRequestIEValue
				decoded, err := s48.BridgeHandoverRequestIEValueMethodDecode(zero, s00.ProtocolIEID(355), raw)
				if err != nil {
					var empty s00.TimeRefDistribution
					return empty, runtime.WrapDecodePath(err, "TimeRefDistribution")
				}
				value, ok := decoded.AsTimeRefDistribution()
				if !ok {
					var empty s00.TimeRefDistribution
					return empty, fmt.Errorf("binding HandoverRequestIEs.id-TimeRefDistribution: no selected value")
				}
				return *value, nil
			}
			*s02.BridgeTimeRefDistributionValueCodecFieldEncode(&sealed) = func(value s00.TimeRefDistribution, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
				return s48.BridgeHandoverRequestIEValueMethodEncodeFresh((func() s48.HandoverRequestIEValue {
					sealed := s48.HandoverRequestIEValue{}
					*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(355)
					*s48.BridgeHandoverRequestIEValueFieldRowTimeRefDistribution(&sealed) = &value
					return sealed
				}()), fresh, budget)
			}
			*s02.BridgeTimeRefDistributionValueCodecFieldCapture(&sealed) = func(v s00.TimeRefDistribution, options aper.DecodeState) (s00.TimeRefDistribution, aper.Snapshot,
			) {
				s := aper.SemanticCaptureFor(options)
				f := s.Begin()
				s00.BridgeCaptureS1APTimeRefDistribution(&v, &s)
				var root aper.Snapshot
				s.End(f, &root, false)
				return v, root
			}
			*s02.BridgeTimeRefDistributionValueCodecFieldCompare(&sealed) = func(v s00.TimeRefDistribution, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
			) {
				s := aper.NewSemanticComparison(root, budget)
				f := s.Begin()
				s07.BridgeCompareS1APTimeRefDistribution(&v, &s)
				s.End(f, root, false)
				return s.Plan(), s.BudgetValue()
			}
			*s02.BridgeTimeRefDistributionValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
				sealed := s00.BridgeCodecContext{}
				*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TimeRefDistribution"
				*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
				return sealed
			}()
			return sealed
		}()
		*s48.BridgeHandoverRequestTimeRefDistributionIEBindingFieldInject(&sealed) = func(value s00.TimeRefDistribution) s48.HandoverRequestIEValue {
			return func() s48.HandoverRequestIEValue {
				sealed := s48.HandoverRequestIEValue{}
				*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = s00.ProtocolIEID(355)
				*s48.BridgeHandoverRequestIEValueFieldRowTimeRefDistribution(&sealed) = &value
				return sealed
			}()
		}
		*s48.BridgeHandoverRequestTimeRefDistributionIEBindingFieldGet(&sealed) = func(value *s48.HandoverRequestIEValue) (*s00.TimeRefDistribution, bool) {
			return value.AsTimeRefDistribution()
		}
		return sealed
	}()
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in HandoverRequestIETable.
func (t HandoverRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (s48.HandoverRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(1):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-HandoverType requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(2):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-Cause requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(66):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-uEaggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(53):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeSetupListHOReq requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(104):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-Source-ToTarget-TransparentContainer requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(107):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UESecurityCapabilities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(41):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-HandoverRestrictionList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(25):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-TraceActivation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(98):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-RequestType requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(124):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SRVCCOperationPossible requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(40):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecurityContext requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(136):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-NASSecurityParameterstoE-UTRAN requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(127):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSG-Id requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(146):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSGMembershipStatus requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(75):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-GUMMEI-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(158):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID-2 requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(165):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-ManagementBasedMDTAllowed requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(177):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-ManagementBasedMDTPLMNList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(192):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-Masked-IMEISV requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(196):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-ExpectedUEBehaviour requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(195):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-ProSeAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(241):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UEUserPlaneCIoTSupportIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(240):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-V2XServicesAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(248):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UESidelinkAggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(251):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-EnhancedCoverageRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(269):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRUESecurityCapabilities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(271):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-CE-ModeBRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(277):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-AerialUEsubscriptionInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(283):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-PendingDataIndication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(278):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-Subscription-Based-UE-DifferentiationInfo requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(299):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-AdditionalRRMPriorityIndex requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(301):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-IAB-Authorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(306):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRV2XServicesAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(307):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRUESidelinkAggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(308):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-PC5QoSParameters requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(314):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapabilityID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(355):
		return s48.HandoverRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-TimeRefDistribution requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return s48.HandoverRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return s48.HandoverRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return s48.HandoverRequestIEField{Id: id, Criticality: criticality, Value: func() s48.HandoverRequestIEValue {
			sealed := s48.HandoverRequestIEValue{}
			*s48.BridgeHandoverRequestIEValueFieldId(&sealed) = id
			*s48.BridgeHandoverRequestIEValueFieldOpaque(&sealed) = opaque
			*s48.BridgeHandoverRequestIEValueFieldIsOpaque(&sealed) = true
			return sealed
		}()}, aper.OperationError(nil, "Opaque")
	}
}

type InitialContextSetupRequestIETable struct{}

func InitialContextSetupRequestIEs() InitialContextSetupRequestIETable {
	return InitialContextSetupRequestIETable{}
}

// ID returns the ASN.1 object-set identity of InitialContextSetupRequestIETable.
func (InitialContextSetupRequestIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by InitialContextSetupRequestIETable.
func (InitialContextSetupRequestIETable) Table() s00.InitialContextSetupRequestIEValueIETable {
	return func() s00.InitialContextSetupRequestIEValueIETable {
		sealed := s00.InitialContextSetupRequestIEValueIETable{}
		*s00.BridgeInitialContextSetupRequestIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (InitialContextSetupRequestIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) MMEUES1APID() InitialContextSetupRequestMMEUES1APIDIEBinding {
	return InitialContextSetupRequestMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.MMEUES1APID, options aper.DecodeState) (s00.MMEUES1APID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APMMEUES1APID(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.MMEUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMMEUES1APID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEUES1APID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MMEUES1APID) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (InitialContextSetupRequestIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) ENBUES1APID() InitialContextSetupRequestENBUES1APIDIEBinding {
	return InitialContextSetupRequestENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeENBUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.ENBUES1APID, options aper.DecodeState) (s00.ENBUES1APID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APENBUES1APID(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeENBUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.ENBUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APENBUES1APID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s00.BridgeENBUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBUES1APID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.ENBUES1APID) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (InitialContextSetupRequestIETable) infoUEaggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(66), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-uEaggregateMaximumBitrate"}}}
}

// UEaggregateMaximumBitrate returns the typed binding for the UEaggregateMaximumBitrate row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) UEaggregateMaximumBitrate() InitialContextSetupRequestUEAggregateMaximumBitrateIEBinding {
	return InitialContextSetupRequestUEAggregateMaximumBitrateIEBinding{info: t.infoUEaggregateMaximumBitrate(), codec: func() s36.UEAggregateMaximumBitrateValueCodec {
		sealed := s36.UEAggregateMaximumBitrateValueCodec{}
		*s36.BridgeUEAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "UEAggregateMaximumBitrate"
		*s36.BridgeUEAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s36.UEAggregateMaximumBitrate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s36.UEAggregateMaximumBitrate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEAggregateMaximumBitrate")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(66), raw)
			if err != nil {
				var empty s36.UEAggregateMaximumBitrate
				return empty, runtime.WrapDecodePath(err, "UEAggregateMaximumBitrate")
			}
			value, ok := decoded.AsUEaggregateMaximumBitrate()
			if !ok {
				var empty s36.UEAggregateMaximumBitrate
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-uEaggregateMaximumBitrate: no selected value")
			}
			return *value, nil
		}
		*s36.BridgeUEAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s36.UEAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(66), rowUEaggregateMaximumBitrate: &value}).encodeFresh(fresh, budget)
		}
		*s36.BridgeUEAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s36.UEAggregateMaximumBitrate, options aper.DecodeState) (s36.UEAggregateMaximumBitrate, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s36.BridgeCaptureS1APUEAggregateMaximumBitrate(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s36.BridgeUEAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s36.UEAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s36.BridgeCompareS1APUEAggregateMaximumBitrate(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s36.BridgeUEAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEAggregateMaximumBitrate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s36.UEAggregateMaximumBitrate) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(66), rowUEaggregateMaximumBitrate: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s36.UEAggregateMaximumBitrate, bool) {
			return value.AsUEaggregateMaximumBitrate()
		}}
}
func (InitialContextSetupRequestIETable) infoERABToBeSetupListCtxtSUReq() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(24), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "E-RABToBeSetupListCtxtSUReq"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-E-RABToBeSetupListCtxtSUReq"}}}
}

// ERABToBeSetupListCtxtSUReq returns the typed binding for the ERABToBeSetupListCtxtSUReq row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) ERABToBeSetupListCtxtSUReq() InitialContextSetupRequestERABToBeSetupListCtxtSUReqIEBinding {
	return InitialContextSetupRequestERABToBeSetupListCtxtSUReqIEBinding{info: t.infoERABToBeSetupListCtxtSUReq(), codec: func() s30.ERABToBeSetupListCtxtSUReqValueCodec {
		sealed := s30.ERABToBeSetupListCtxtSUReqValueCodec{}
		*s30.BridgeERABToBeSetupListCtxtSUReqValueCodecFieldPath(&sealed) = "ERABToBeSetupListCtxtSUReq"
		*s30.BridgeERABToBeSetupListCtxtSUReqValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s30.ERABToBeSetupListCtxtSUReq, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s30.ERABToBeSetupListCtxtSUReq
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ERABToBeSetupListCtxtSUReq")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(24), raw)
			if err != nil {
				var empty s30.ERABToBeSetupListCtxtSUReq
				return empty, runtime.WrapDecodePath(err, "ERABToBeSetupListCtxtSUReq")
			}
			value, ok := decoded.AsERABToBeSetupListCtxtSUReq()
			if !ok {
				var empty s30.ERABToBeSetupListCtxtSUReq
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-E-RABToBeSetupListCtxtSUReq: no selected value")
			}
			return *value, nil
		}
		*s30.BridgeERABToBeSetupListCtxtSUReqValueCodecFieldEncode(&sealed) = func(value s30.ERABToBeSetupListCtxtSUReq, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(24), rowERABToBeSetupListCtxtSUReq: &value}).encodeFresh(fresh, budget)
		}
		*s30.BridgeERABToBeSetupListCtxtSUReqValueCodecFieldCapture(&sealed) = func(v s30.ERABToBeSetupListCtxtSUReq, options aper.DecodeState) (s30.ERABToBeSetupListCtxtSUReq, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s30.BridgeCaptureS1APERABToBeSetupListCtxtSUReq(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s30.BridgeERABToBeSetupListCtxtSUReqValueCodecFieldCompare(&sealed) = func(v s30.ERABToBeSetupListCtxtSUReq, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s30.BridgeCompareS1APERABToBeSetupListCtxtSUReq(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s30.BridgeERABToBeSetupListCtxtSUReqValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ERABToBeSetupListCtxtSUReq"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s30.ERABToBeSetupListCtxtSUReq) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(24), rowERABToBeSetupListCtxtSUReq: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s30.ERABToBeSetupListCtxtSUReq, bool) {
			return value.AsERABToBeSetupListCtxtSUReq()
		}}
}
func (InitialContextSetupRequestIETable) infoUESecurityCapabilities() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(107), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UESecurityCapabilities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-UESecurityCapabilities"}}}
}

// UESecurityCapabilities returns the typed binding for the UESecurityCapabilities row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) UESecurityCapabilities() InitialContextSetupRequestUESecurityCapabilitiesIEBinding {
	return InitialContextSetupRequestUESecurityCapabilitiesIEBinding{info: t.infoUESecurityCapabilities(), codec: func() s37.UESecurityCapabilitiesValueCodec {
		sealed := s37.UESecurityCapabilitiesValueCodec{}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldPath(&sealed) = "UESecurityCapabilities"
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s37.UESecurityCapabilities, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s37.UESecurityCapabilities
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UESecurityCapabilities")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(107), raw)
			if err != nil {
				var empty s37.UESecurityCapabilities
				return empty, runtime.WrapDecodePath(err, "UESecurityCapabilities")
			}
			value, ok := decoded.AsUESecurityCapabilities()
			if !ok {
				var empty s37.UESecurityCapabilities
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-UESecurityCapabilities: no selected value")
			}
			return *value, nil
		}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldEncode(&sealed) = func(value s37.UESecurityCapabilities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(107), rowUESecurityCapabilities: &value}).encodeFresh(fresh, budget)
		}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldCapture(&sealed) = func(v s37.UESecurityCapabilities, options aper.DecodeState) (s37.UESecurityCapabilities, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s37.BridgeCaptureS1APUESecurityCapabilities(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldCompare(&sealed) = func(v s37.UESecurityCapabilities, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s37.BridgeCompareS1APUESecurityCapabilities(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s37.BridgeUESecurityCapabilitiesValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UESecurityCapabilities"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s37.UESecurityCapabilities) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(107), rowUESecurityCapabilities: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s37.UESecurityCapabilities, bool) {
			return value.AsUESecurityCapabilities()
		}}
}
func (InitialContextSetupRequestIETable) infoSecurityKey() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(73), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SecurityKey"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-SecurityKey"}}}
}

// SecurityKey returns the typed binding for the SecurityKey row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) SecurityKey() InitialContextSetupRequestSecurityKeyIEBinding {
	return InitialContextSetupRequestSecurityKeyIEBinding{info: t.infoSecurityKey(), codec: func() s01.SecurityKeyValueCodec {
		sealed := s01.SecurityKeyValueCodec{}
		*s01.BridgeSecurityKeyValueCodecFieldPath(&sealed) = "SecurityKey"
		*s01.BridgeSecurityKeyValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SecurityKey, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SecurityKey
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SecurityKey")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(73), raw)
			if err != nil {
				var empty s00.SecurityKey
				return empty, runtime.WrapDecodePath(err, "SecurityKey")
			}
			value, ok := decoded.AsSecurityKey()
			if !ok {
				var empty s00.SecurityKey
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-SecurityKey: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeSecurityKeyValueCodecFieldEncode(&sealed) = func(value s00.SecurityKey, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(73), rowSecurityKey: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeSecurityKeyValueCodecFieldCapture(&sealed) = func(v s00.SecurityKey, options aper.DecodeState) (s00.SecurityKey, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSecurityKey(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeSecurityKeyValueCodecFieldCompare(&sealed) = func(v s00.SecurityKey, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APSecurityKey(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s01.BridgeSecurityKeyValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SecurityKey"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.SecurityKey) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(73), rowSecurityKey: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.SecurityKey, bool) { return value.AsSecurityKey() }}
}
func (InitialContextSetupRequestIETable) infoTraceActivation() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(25), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TraceActivation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-TraceActivation"}}}
}

// TraceActivation returns the typed binding for the TraceActivation row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) TraceActivation() InitialContextSetupRequestTraceActivationIEBinding {
	return InitialContextSetupRequestTraceActivationIEBinding{info: t.infoTraceActivation(), codec: TraceActivationValueCodec{path: "TraceActivation",
		decode: func(data []byte, options aper.DecodeState) (s48.TraceActivation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s48.TraceActivation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TraceActivation")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(25), raw)
			if err != nil {
				var empty s48.TraceActivation
				return empty, runtime.WrapDecodePath(err, "TraceActivation")
			}
			value, ok := decoded.AsTraceActivation()
			if !ok {
				var empty s48.TraceActivation
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-TraceActivation: no selected value")
			}
			return *value, nil
		},
		encode: func(value s48.TraceActivation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(25), rowTraceActivation: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s48.TraceActivation, options aper.DecodeState) (s48.TraceActivation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s48.BridgeCaptureS1APTraceActivation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v s48.TraceActivation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s48.BridgeCompareS1APTraceActivation(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TraceActivation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s48.TraceActivation) InitialContextSetupRequestIEValue {
		return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(25), rowTraceActivation: &value}
	}, get: func(value *InitialContextSetupRequestIEValue) (*s48.TraceActivation, bool) {
		return value.AsTraceActivation()
	}}
}
func (InitialContextSetupRequestIETable) infoHandoverRestrictionList() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(41), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "HandoverRestrictionList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-HandoverRestrictionList"}}}
}

// HandoverRestrictionList returns the typed binding for the HandoverRestrictionList row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) HandoverRestrictionList() InitialContextSetupRequestHandoverRestrictionListIEBinding {
	return InitialContextSetupRequestHandoverRestrictionListIEBinding{info: t.infoHandoverRestrictionList(), codec: func() s43.HandoverRestrictionListValueCodec {
		sealed := s43.HandoverRestrictionListValueCodec{}
		*s43.BridgeHandoverRestrictionListValueCodecFieldPath(&sealed) = "HandoverRestrictionList"
		*s43.BridgeHandoverRestrictionListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s43.HandoverRestrictionList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s43.HandoverRestrictionList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("HandoverRestrictionList")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(41), raw)
			if err != nil {
				var empty s43.HandoverRestrictionList
				return empty, runtime.WrapDecodePath(err, "HandoverRestrictionList")
			}
			value, ok := decoded.AsHandoverRestrictionList()
			if !ok {
				var empty s43.HandoverRestrictionList
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-HandoverRestrictionList: no selected value")
			}
			return *value, nil
		}
		*s43.BridgeHandoverRestrictionListValueCodecFieldEncode(&sealed) = func(value s43.HandoverRestrictionList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(41), rowHandoverRestrictionList: &value}).encodeFresh(fresh, budget)
		}
		*s43.BridgeHandoverRestrictionListValueCodecFieldCapture(&sealed) = func(v s43.HandoverRestrictionList, options aper.DecodeState) (s43.HandoverRestrictionList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s43.BridgeCaptureS1APHandoverRestrictionList(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s43.BridgeHandoverRestrictionListValueCodecFieldCompare(&sealed) = func(v s43.HandoverRestrictionList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s43.BridgeCompareS1APHandoverRestrictionList(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s43.BridgeHandoverRestrictionListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:HandoverRestrictionList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s43.HandoverRestrictionList) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(41), rowHandoverRestrictionList: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s43.HandoverRestrictionList, bool) {
			return value.AsHandoverRestrictionList()
		}}
}
func (InitialContextSetupRequestIETable) infoUERadioCapability() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(74), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapability"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-UERadioCapability"}}}
}

// UERadioCapability returns the typed binding for the UERadioCapability row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) UERadioCapability() InitialContextSetupRequestUERadioCapabilityIEBinding {
	return InitialContextSetupRequestUERadioCapabilityIEBinding{info: t.infoUERadioCapability(), codec: func() s02.UERadioCapabilityValueCodec {
		sealed := s02.UERadioCapabilityValueCodec{}
		*s02.BridgeUERadioCapabilityValueCodecFieldPath(&sealed) = "UERadioCapability"
		*s02.BridgeUERadioCapabilityValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapability, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapability
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UERadioCapability")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(74), raw)
			if err != nil {
				var empty s00.UERadioCapability
				return empty, runtime.WrapDecodePath(err, "UERadioCapability")
			}
			value, ok := decoded.AsUERadioCapability()
			if !ok {
				var empty s00.UERadioCapability
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-UERadioCapability: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapability, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(74), rowUERadioCapability: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUERadioCapabilityValueCodecFieldCapture(&sealed) = func(v s00.UERadioCapability, options aper.DecodeState) (s00.UERadioCapability, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUERadioCapability(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s02.BridgeUERadioCapabilityValueCodecFieldCompare(&sealed) = func(v s00.UERadioCapability, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APUERadioCapability(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s02.BridgeUERadioCapabilityValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UERadioCapability"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UERadioCapability) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(74), rowUERadioCapability: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.UERadioCapability, bool) {
			return value.AsUERadioCapability()
		}}
}
func (InitialContextSetupRequestIETable) infoSubscriberProfileIDforRFP() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(106), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SubscriberProfileIDforRFP"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-SubscriberProfileIDforRFP"}}}
}

// SubscriberProfileIDforRFP returns the typed binding for the SubscriberProfileIDforRFP row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) SubscriberProfileIDforRFP() InitialContextSetupRequestSubscriberProfileIDforRFPIEBinding {
	return InitialContextSetupRequestSubscriberProfileIDforRFPIEBinding{info: t.infoSubscriberProfileIDforRFP(), codec: func() s01.SubscriberProfileIDforRFPValueCodec {
		sealed := s01.SubscriberProfileIDforRFPValueCodec{}
		*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldPath(&sealed) = "SubscriberProfileIDforRFP"
		*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SubscriberProfileIDforRFP, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SubscriberProfileIDforRFP
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SubscriberProfileIDforRFP")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(106), raw)
			if err != nil {
				var empty s00.SubscriberProfileIDforRFP
				return empty, runtime.WrapDecodePath(err, "SubscriberProfileIDforRFP")
			}
			value, ok := decoded.AsSubscriberProfileIDforRFP()
			if !ok {
				var empty s00.SubscriberProfileIDforRFP
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-SubscriberProfileIDforRFP: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldEncode(&sealed) = func(value s00.SubscriberProfileIDforRFP, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(106), rowSubscriberProfileIDforRFP: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldCapture(&sealed) = func(v s00.SubscriberProfileIDforRFP, options aper.DecodeState) (s00.SubscriberProfileIDforRFP, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSubscriberProfileIDforRFP(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldCompare(&sealed) = func(v s00.SubscriberProfileIDforRFP, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APSubscriberProfileIDforRFP(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeSubscriberProfileIDforRFPValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SubscriberProfileIDforRFP"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.SubscriberProfileIDforRFP) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(106), rowSubscriberProfileIDforRFP: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.SubscriberProfileIDforRFP, bool) {
			return value.AsSubscriberProfileIDforRFP()
		}}
}
func (InitialContextSetupRequestIETable) infoCSFallbackIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(108), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSFallbackIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-CSFallbackIndicator"}}}
}

// CSFallbackIndicator returns the typed binding for the CSFallbackIndicator row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) CSFallbackIndicator() InitialContextSetupRequestCSFallbackIndicatorIEBinding {
	return InitialContextSetupRequestCSFallbackIndicatorIEBinding{info: t.infoCSFallbackIndicator(), codec: func() s00.CSFallbackIndicatorValueCodec {
		sealed := s00.CSFallbackIndicatorValueCodec{}
		*s00.BridgeCSFallbackIndicatorValueCodecFieldPath(&sealed) = "CSFallbackIndicator"
		*s00.BridgeCSFallbackIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSFallbackIndicator, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CSFallbackIndicator
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSFallbackIndicator")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(108), raw)
			if err != nil {
				var empty s00.CSFallbackIndicator
				return empty, runtime.WrapDecodePath(err, "CSFallbackIndicator")
			}
			value, ok := decoded.AsCSFallbackIndicator()
			if !ok {
				var empty s00.CSFallbackIndicator
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-CSFallbackIndicator: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCSFallbackIndicatorValueCodecFieldEncode(&sealed) = func(value s00.CSFallbackIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(108), rowCSFallbackIndicator: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCSFallbackIndicatorValueCodecFieldCapture(&sealed) = func(v s00.CSFallbackIndicator, options aper.DecodeState) (s00.CSFallbackIndicator, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCSFallbackIndicator(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCSFallbackIndicatorValueCodecFieldCompare(&sealed) = func(v s00.CSFallbackIndicator, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCSFallbackIndicator(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCSFallbackIndicatorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSFallbackIndicator"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CSFallbackIndicator) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(108), rowCSFallbackIndicator: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.CSFallbackIndicator, bool) {
			return value.AsCSFallbackIndicator()
		}}
}
func (InitialContextSetupRequestIETable) infoSRVCCOperationPossible() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(124), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "SRVCCOperationPossible"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-SRVCCOperationPossible"}}}
}

// SRVCCOperationPossible returns the typed binding for the SRVCCOperationPossible row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) SRVCCOperationPossible() InitialContextSetupRequestSRVCCOperationPossibleIEBinding {
	return InitialContextSetupRequestSRVCCOperationPossibleIEBinding{info: t.infoSRVCCOperationPossible(), codec: func() s01.SRVCCOperationPossibleValueCodec {
		sealed := s01.SRVCCOperationPossibleValueCodec{}
		*s01.BridgeSRVCCOperationPossibleValueCodecFieldPath(&sealed) = "SRVCCOperationPossible"
		*s01.BridgeSRVCCOperationPossibleValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.SRVCCOperationPossible, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.SRVCCOperationPossible
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SRVCCOperationPossible")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(124), raw)
			if err != nil {
				var empty s00.SRVCCOperationPossible
				return empty, runtime.WrapDecodePath(err, "SRVCCOperationPossible")
			}
			value, ok := decoded.AsSRVCCOperationPossible()
			if !ok {
				var empty s00.SRVCCOperationPossible
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-SRVCCOperationPossible: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeSRVCCOperationPossibleValueCodecFieldEncode(&sealed) = func(value s00.SRVCCOperationPossible, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(124), rowSRVCCOperationPossible: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeSRVCCOperationPossibleValueCodecFieldCapture(&sealed) = func(v s00.SRVCCOperationPossible, options aper.DecodeState) (s00.SRVCCOperationPossible, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APSRVCCOperationPossible(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeSRVCCOperationPossibleValueCodecFieldCompare(&sealed) = func(v s00.SRVCCOperationPossible, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s06.BridgeCompareS1APSRVCCOperationPossible(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeSRVCCOperationPossibleValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SRVCCOperationPossible"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.SRVCCOperationPossible) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(124), rowSRVCCOperationPossible: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.SRVCCOperationPossible, bool) {
			return value.AsSRVCCOperationPossible()
		}}
}
func (InitialContextSetupRequestIETable) infoCSGMembershipStatus() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(146), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CSGMembershipStatus"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-CSGMembershipStatus"}}}
}

// CSGMembershipStatus returns the typed binding for the CSGMembershipStatus row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) CSGMembershipStatus() InitialContextSetupRequestCSGMembershipStatusIEBinding {
	return InitialContextSetupRequestCSGMembershipStatusIEBinding{info: t.infoCSGMembershipStatus(), codec: func() s00.CSGMembershipStatusValueCodec {
		sealed := s00.CSGMembershipStatusValueCodec{}
		*s00.BridgeCSGMembershipStatusValueCodecFieldPath(&sealed) = "CSGMembershipStatus"
		*s00.BridgeCSGMembershipStatusValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CSGMembershipStatus, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CSGMembershipStatus
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CSGMembershipStatus")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(146), raw)
			if err != nil {
				var empty s00.CSGMembershipStatus
				return empty, runtime.WrapDecodePath(err, "CSGMembershipStatus")
			}
			value, ok := decoded.AsCSGMembershipStatus()
			if !ok {
				var empty s00.CSGMembershipStatus
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-CSGMembershipStatus: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldEncode(&sealed) = func(value s00.CSGMembershipStatus, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(146), rowCSGMembershipStatus: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldCapture(&sealed) = func(v s00.CSGMembershipStatus, options aper.DecodeState) (s00.CSGMembershipStatus, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCSGMembershipStatus(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldCompare(&sealed) = func(v s00.CSGMembershipStatus, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCSGMembershipStatus(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeCSGMembershipStatusValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CSGMembershipStatus"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CSGMembershipStatus) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(146), rowCSGMembershipStatus: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.CSGMembershipStatus, bool) {
			return value.AsCSGMembershipStatus()
		}}
}
func (InitialContextSetupRequestIETable) infoRegisteredLAI() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(159), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "LAI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-RegisteredLAI"}}}
}

// RegisteredLAI returns the typed binding for the RegisteredLAI row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) RegisteredLAI() InitialContextSetupRequestLAIIEBinding {
	return InitialContextSetupRequestLAIIEBinding{info: t.infoRegisteredLAI(), codec: func() s18.LAIValueCodec {
		sealed := s18.LAIValueCodec{}
		*s18.BridgeLAIValueCodecFieldPath(&sealed) = "LAI"
		*s18.BridgeLAIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.LAI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.LAI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("LAI")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(159), raw)
			if err != nil {
				var empty s18.LAI
				return empty, runtime.WrapDecodePath(err, "LAI")
			}
			value, ok := decoded.AsRegisteredLAI()
			if !ok {
				var empty s18.LAI
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-RegisteredLAI: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeLAIValueCodecFieldEncode(&sealed) = func(value s18.LAI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(159), rowRegisteredLAI: &value}).encodeFresh(fresh, budget)
		}
		*s18.BridgeLAIValueCodecFieldCapture(&sealed) = func(v s18.LAI, options aper.DecodeState) (s18.LAI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s18.BridgeCaptureS1APLAI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,
				false)
			return v, root
		}
		*s18.BridgeLAIValueCodecFieldCompare(&sealed) = func(v s18.LAI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s18.BridgeCompareS1APLAI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeLAIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:LAI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s18.LAI) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(159), rowRegisteredLAI: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s18.LAI, bool) { return value.AsRegisteredLAI() }}
}
func (InitialContextSetupRequestIETable) infoGUMMEIID() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(75), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "GUMMEI"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-GUMMEI-ID"}}}
}

// GUMMEIID returns the typed binding for the GUMMEIID row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) GUMMEIID() InitialContextSetupRequestGUMMEIIEBinding {
	return InitialContextSetupRequestGUMMEIIEBinding{info: t.infoGUMMEIID(), codec: func() s18.GUMMEIValueCodec {
		sealed := s18.GUMMEIValueCodec{}
		*s18.BridgeGUMMEIValueCodecFieldPath(&sealed) = "GUMMEI"
		*s18.BridgeGUMMEIValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.GUMMEI, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.GUMMEI
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("GUMMEI")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(75), raw)
			if err != nil {
				var empty s18.GUMMEI
				return empty, runtime.WrapDecodePath(err, "GUMMEI")
			}
			value, ok := decoded.AsGUMMEIID()
			if !ok {
				var empty s18.GUMMEI
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-GUMMEI-ID: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeGUMMEIValueCodecFieldEncode(&sealed) = func(value s18.GUMMEI, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(75), rowGUMMEIID: &value}).encodeFresh(fresh, budget)
		}
		*s18.BridgeGUMMEIValueCodecFieldCapture(&sealed) = func(v s18.GUMMEI, options aper.DecodeState) (s18.GUMMEI, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s18.BridgeCaptureS1APGUMMEI(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeGUMMEIValueCodecFieldCompare(&sealed) = func(v s18.GUMMEI, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s18.BridgeCompareS1APGUMMEI(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeGUMMEIValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:GUMMEI"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s18.GUMMEI) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(75), rowGUMMEIID: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s18.GUMMEI, bool) { return value.AsGUMMEIID() }}
}
func (InitialContextSetupRequestIETable) infoMMEUES1APID2() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(158), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-MME-UE-S1AP-ID-2"}}}
}

// MMEUES1APID2 returns the typed binding for the MMEUES1APID2 row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) MMEUES1APID2() InitialContextSetupRequestMMEUES1APIDIEBinding {
	return InitialContextSetupRequestMMEUES1APIDIEBinding{info: t.infoMMEUES1APID2(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(158), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID2()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-MME-UE-S1AP-ID-2: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(158), rowMMEUES1APID2: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.MMEUES1APID, options aper.DecodeState) (s00.MMEUES1APID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APMMEUES1APID(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.MMEUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMMEUES1APID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEUES1APID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MMEUES1APID) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(158), rowMMEUES1APID2: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.MMEUES1APID, bool) {
			return value.AsMMEUES1APID2()
		}}
}
func (InitialContextSetupRequestIETable) infoManagementBasedMDTAllowed() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(165), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ManagementBasedMDTAllowed"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-ManagementBasedMDTAllowed"}}}
}

// ManagementBasedMDTAllowed returns the typed binding for the ManagementBasedMDTAllowed row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) ManagementBasedMDTAllowed() InitialContextSetupRequestManagementBasedMDTAllowedIEBinding {
	return InitialContextSetupRequestManagementBasedMDTAllowedIEBinding{info: t.infoManagementBasedMDTAllowed(), codec: func() s01.ManagementBasedMDTAllowedValueCodec {
		sealed := s01.ManagementBasedMDTAllowedValueCodec{}
		*s01.BridgeManagementBasedMDTAllowedValueCodecFieldPath(&sealed) = "ManagementBasedMDTAllowed"
		*s01.BridgeManagementBasedMDTAllowedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ManagementBasedMDTAllowed, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ManagementBasedMDTAllowed
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ManagementBasedMDTAllowed")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(165), raw)
			if err != nil {
				var empty s00.ManagementBasedMDTAllowed
				return empty, runtime.WrapDecodePath(err, "ManagementBasedMDTAllowed")
			}
			value, ok := decoded.AsManagementBasedMDTAllowed()
			if !ok {
				var empty s00.ManagementBasedMDTAllowed
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-ManagementBasedMDTAllowed: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeManagementBasedMDTAllowedValueCodecFieldEncode(&sealed) = func(value s00.ManagementBasedMDTAllowed, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(165), rowManagementBasedMDTAllowed: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeManagementBasedMDTAllowedValueCodecFieldCapture(&sealed) = func(v s00.ManagementBasedMDTAllowed, options aper.DecodeState) (s00.ManagementBasedMDTAllowed, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APManagementBasedMDTAllowed(&v, &s)
			var root aper.Snapshot
			s.End(
				f,
				&root, false)
			return v, root
		}
		*s01.BridgeManagementBasedMDTAllowedValueCodecFieldCompare(&sealed) = func(v s00.ManagementBasedMDTAllowed, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APManagementBasedMDTAllowed(&v, &s)
			s.End(f, root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgeManagementBasedMDTAllowedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ManagementBasedMDTAllowed"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.ManagementBasedMDTAllowed) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(165), rowManagementBasedMDTAllowed: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.ManagementBasedMDTAllowed, bool) {
			return value.AsManagementBasedMDTAllowed()
		}}
}
func (InitialContextSetupRequestIETable) infoManagementBasedMDTPLMNList() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(177), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MDTPLMNList"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-ManagementBasedMDTPLMNList"}}}
}

// ManagementBasedMDTPLMNList returns the typed binding for the ManagementBasedMDTPLMNList row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) ManagementBasedMDTPLMNList() InitialContextSetupRequestMDTPLMNListIEBinding {
	return InitialContextSetupRequestMDTPLMNListIEBinding{info: t.infoManagementBasedMDTPLMNList(), codec: func() s01.MDTPLMNListValueCodec {
		sealed := s01.MDTPLMNListValueCodec{}
		*s01.BridgeMDTPLMNListValueCodecFieldPath(&sealed) = "MDTPLMNList"
		*s01.BridgeMDTPLMNListValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MDTPLMNList, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MDTPLMNList
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MDTPLMNList")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(177), raw)
			if err != nil {
				var empty s00.MDTPLMNList
				return empty, runtime.WrapDecodePath(err, "MDTPLMNList")
			}
			value, ok := decoded.AsManagementBasedMDTPLMNList()
			if !ok {
				var empty s00.MDTPLMNList
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-ManagementBasedMDTPLMNList: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMDTPLMNListValueCodecFieldEncode(&sealed) = func(value s00.MDTPLMNList, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(177), rowManagementBasedMDTPLMNList: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMDTPLMNListValueCodecFieldCapture(&sealed) = func(v s00.MDTPLMNList, options aper.DecodeState) (s00.MDTPLMNList, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APMDTPLMNList(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeMDTPLMNListValueCodecFieldCompare(&sealed) = func(v s00.MDTPLMNList, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APMDTPLMNList(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s01.BridgeMDTPLMNListValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MDTPLMNList"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MDTPLMNList) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(177), rowManagementBasedMDTPLMNList: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.MDTPLMNList, bool) {
			return value.AsManagementBasedMDTPLMNList()
		}}
}
func (InitialContextSetupRequestIETable) infoAdditionalCSFallbackIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(187), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceConditional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AdditionalCSFallbackIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-AdditionalCSFallbackIndicator"}}}
}

// AdditionalCSFallbackIndicator returns the typed binding for the AdditionalCSFallbackIndicator row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) AdditionalCSFallbackIndicator() InitialContextSetupRequestAdditionalCSFallbackIndicatorIEBinding {
	return InitialContextSetupRequestAdditionalCSFallbackIndicatorIEBinding{info: t.infoAdditionalCSFallbackIndicator(), codec: func() s00.AdditionalCSFallbackIndicatorValueCodec {
		sealed := s00.AdditionalCSFallbackIndicatorValueCodec{}
		*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldPath(&sealed) = "AdditionalCSFallbackIndicator"
		*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AdditionalCSFallbackIndicator, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.AdditionalCSFallbackIndicator
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("AdditionalCSFallbackIndicator")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(187), raw)
			if err != nil {
				var empty s00.AdditionalCSFallbackIndicator
				return empty, runtime.WrapDecodePath(err, "AdditionalCSFallbackIndicator")
			}
			value, ok := decoded.AsAdditionalCSFallbackIndicator()
			if !ok {
				var empty s00.AdditionalCSFallbackIndicator
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-AdditionalCSFallbackIndicator: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldEncode(&sealed) = func(value s00.AdditionalCSFallbackIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(187), rowAdditionalCSFallbackIndicator: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldCapture(&sealed) = func(v s00.AdditionalCSFallbackIndicator, options aper.DecodeState) (s00.AdditionalCSFallbackIndicator, aper.Snapshot,

		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APAdditionalCSFallbackIndicator(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldCompare(&sealed) = func(v s00.AdditionalCSFallbackIndicator, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f :=
				s.Begin()
			s02.BridgeCompareS1APAdditionalCSFallbackIndicator(&v, &s)
			s.
				End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeAdditionalCSFallbackIndicatorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AdditionalCSFallbackIndicator"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.AdditionalCSFallbackIndicator) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(187), rowAdditionalCSFallbackIndicator: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.AdditionalCSFallbackIndicator, bool) {
			return value.AsAdditionalCSFallbackIndicator()
		}}
}
func (InitialContextSetupRequestIETable) infoMaskedIMEISV() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(192), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Masked-IMEISV"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-Masked-IMEISV"}}}
}

// MaskedIMEISV returns the typed binding for the MaskedIMEISV row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) MaskedIMEISV() InitialContextSetupRequestMaskedIMEISVIEBinding {
	return InitialContextSetupRequestMaskedIMEISVIEBinding{info: t.infoMaskedIMEISV(), codec: func() s01.MaskedIMEISVValueCodec {
		sealed := s01.MaskedIMEISVValueCodec{}
		*s01.BridgeMaskedIMEISVValueCodecFieldPath(&sealed) = "MaskedIMEISV"
		*s01.BridgeMaskedIMEISVValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MaskedIMEISV, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MaskedIMEISV
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MaskedIMEISV")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(192), raw)
			if err != nil {
				var empty s00.MaskedIMEISV
				return empty, runtime.WrapDecodePath(err, "MaskedIMEISV")
			}
			value, ok := decoded.AsMaskedIMEISV()
			if !ok {
				var empty s00.MaskedIMEISV
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-Masked-IMEISV: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMaskedIMEISVValueCodecFieldEncode(&sealed) = func(value s00.MaskedIMEISV, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(192), rowMaskedIMEISV: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMaskedIMEISVValueCodecFieldCapture(&sealed) = func(v s00.MaskedIMEISV, options aper.DecodeState) (s00.MaskedIMEISV, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APMaskedIMEISV(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeMaskedIMEISVValueCodecFieldCompare(&sealed) = func(v s00.MaskedIMEISV, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMaskedIMEISV(&v, &s)
			s.End(f, root, false)
			return s.Plan(),
				s.
					BudgetValue()
		}
		*s01.BridgeMaskedIMEISVValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MaskedIMEISV"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MaskedIMEISV) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(192), rowMaskedIMEISV: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.MaskedIMEISV, bool) {
			return value.AsMaskedIMEISV()
		}}
}
func (InitialContextSetupRequestIETable) infoExpectedUEBehaviour() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(196), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ExpectedUEBehaviour"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-ExpectedUEBehaviour"}}}
}

// ExpectedUEBehaviour returns the typed binding for the ExpectedUEBehaviour row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) ExpectedUEBehaviour() InitialContextSetupRequestExpectedUEBehaviourIEBinding {
	return InitialContextSetupRequestExpectedUEBehaviourIEBinding{info: t.infoExpectedUEBehaviour(), codec: func() s18.ExpectedUEBehaviourValueCodec {
		sealed := s18.ExpectedUEBehaviourValueCodec{}
		*s18.BridgeExpectedUEBehaviourValueCodecFieldPath(&sealed) = "ExpectedUEBehaviour"
		*s18.BridgeExpectedUEBehaviourValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s18.ExpectedUEBehaviour, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s18.ExpectedUEBehaviour
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ExpectedUEBehaviour")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(196), raw)
			if err != nil {
				var empty s18.ExpectedUEBehaviour
				return empty, runtime.WrapDecodePath(err, "ExpectedUEBehaviour")
			}
			value, ok := decoded.AsExpectedUEBehaviour()
			if !ok {
				var empty s18.ExpectedUEBehaviour
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-ExpectedUEBehaviour: no selected value")
			}
			return *value, nil
		}
		*s18.BridgeExpectedUEBehaviourValueCodecFieldEncode(&sealed) = func(value s18.ExpectedUEBehaviour, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(196), rowExpectedUEBehaviour: &value}).encodeFresh(fresh, budget)
		}
		*s18.BridgeExpectedUEBehaviourValueCodecFieldCapture(&sealed) = func(v s18.ExpectedUEBehaviour, options aper.DecodeState) (s18.ExpectedUEBehaviour, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s18.BridgeCaptureS1APExpectedUEBehaviour(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s18.BridgeExpectedUEBehaviourValueCodecFieldCompare(&sealed) = func(v s18.ExpectedUEBehaviour, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s18.BridgeCompareS1APExpectedUEBehaviour(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s18.BridgeExpectedUEBehaviourValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ExpectedUEBehaviour"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s18.ExpectedUEBehaviour) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(196), rowExpectedUEBehaviour: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s18.ExpectedUEBehaviour, bool) {
			return value.AsExpectedUEBehaviour()
		}}
}
func (InitialContextSetupRequestIETable) infoProSeAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(195), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ProSeAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-ProSeAuthorized"}}}
}

// ProSeAuthorized returns the typed binding for the ProSeAuthorized row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) ProSeAuthorized() InitialContextSetupRequestProSeAuthorizedIEBinding {
	return InitialContextSetupRequestProSeAuthorizedIEBinding{info: t.infoProSeAuthorized(), codec: func() s20.ProSeAuthorizedValueCodec {
		sealed := s20.ProSeAuthorizedValueCodec{}
		*s20.BridgeProSeAuthorizedValueCodecFieldPath(&sealed) = "ProSeAuthorized"
		*s20.BridgeProSeAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.ProSeAuthorized, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s20.ProSeAuthorized
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ProSeAuthorized")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(195), raw)
			if err != nil {
				var empty s20.ProSeAuthorized
				return empty, runtime.WrapDecodePath(err, "ProSeAuthorized")
			}
			value, ok := decoded.AsProSeAuthorized()
			if !ok {
				var empty s20.ProSeAuthorized
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-ProSeAuthorized: no selected value")
			}
			return *value, nil
		}
		*s20.BridgeProSeAuthorizedValueCodecFieldEncode(&sealed) = func(value s20.ProSeAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(195), rowProSeAuthorized: &value}).encodeFresh(fresh, budget)
		}
		*s20.BridgeProSeAuthorizedValueCodecFieldCapture(&sealed) = func(v s20.ProSeAuthorized, options aper.DecodeState) (s20.ProSeAuthorized, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s20.BridgeCaptureS1APProSeAuthorized(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s20.BridgeProSeAuthorizedValueCodecFieldCompare(&sealed) = func(v s20.ProSeAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s20.BridgeCompareS1APProSeAuthorized(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s20.BridgeProSeAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ProSeAuthorized"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s20.ProSeAuthorized) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(195), rowProSeAuthorized: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s20.ProSeAuthorized, bool) {
			return value.AsProSeAuthorized()
		}}
}
func (InitialContextSetupRequestIETable) infoUEUserPlaneCIoTSupportIndicator() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(241), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UEUserPlaneCIoTSupportIndicator"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-UEUserPlaneCIoTSupportIndicator"}}}
}

// UEUserPlaneCIoTSupportIndicator returns the typed binding for the UEUserPlaneCIoTSupportIndicator row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) UEUserPlaneCIoTSupportIndicator() InitialContextSetupRequestUEUserPlaneCIoTSupportIndicatorIEBinding {
	return InitialContextSetupRequestUEUserPlaneCIoTSupportIndicatorIEBinding{info: t.infoUEUserPlaneCIoTSupportIndicator(), codec: func() s02.UEUserPlaneCIoTSupportIndicatorValueCodec {
		sealed := s02.UEUserPlaneCIoTSupportIndicatorValueCodec{}
		*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldPath(&sealed) = "UEUserPlaneCIoTSupportIndicator"
		*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UEUserPlaneCIoTSupportIndicator, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UEUserPlaneCIoTSupportIndicator
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UEUserPlaneCIoTSupportIndicator")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(241), raw)
			if err != nil {
				var empty s00.UEUserPlaneCIoTSupportIndicator
				return empty, runtime.WrapDecodePath(err, "UEUserPlaneCIoTSupportIndicator")
			}
			value, ok := decoded.AsUEUserPlaneCIoTSupportIndicator()
			if !ok {
				var empty s00.UEUserPlaneCIoTSupportIndicator
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-UEUserPlaneCIoTSupportIndicator: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldEncode(&sealed) = func(value s00.UEUserPlaneCIoTSupportIndicator, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(241), rowUEUserPlaneCIoTSupportIndicator: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldCapture(&sealed) = func(v s00.UEUserPlaneCIoTSupportIndicator, options aper.DecodeState) (s00.UEUserPlaneCIoTSupportIndicator, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUEUserPlaneCIoTSupportIndicator(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldCompare(&sealed) = func(v s00.UEUserPlaneCIoTSupportIndicator, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APUEUserPlaneCIoTSupportIndicator(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeUEUserPlaneCIoTSupportIndicatorValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UEUserPlaneCIoTSupportIndicator"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UEUserPlaneCIoTSupportIndicator) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(241), rowUEUserPlaneCIoTSupportIndicator: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.UEUserPlaneCIoTSupportIndicator, bool) {
			return value.AsUEUserPlaneCIoTSupportIndicator()
		}}
}
func (InitialContextSetupRequestIETable) infoV2XServicesAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(240), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "V2XServicesAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-V2XServicesAuthorized"}}}
}

// V2XServicesAuthorized returns the typed binding for the V2XServicesAuthorized row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) V2XServicesAuthorized() InitialContextSetupRequestV2XServicesAuthorizedIEBinding {
	return InitialContextSetupRequestV2XServicesAuthorizedIEBinding{info: t.infoV2XServicesAuthorized(), codec: func() s47.V2XServicesAuthorizedValueCodec {
		sealed := s47.V2XServicesAuthorizedValueCodec{}
		*s47.BridgeV2XServicesAuthorizedValueCodecFieldPath(&sealed) = "V2XServicesAuthorized"
		*s47.BridgeV2XServicesAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s47.V2XServicesAuthorized, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s47.V2XServicesAuthorized
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("V2XServicesAuthorized")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(240), raw)
			if err != nil {
				var empty s47.V2XServicesAuthorized
				return empty, runtime.WrapDecodePath(err, "V2XServicesAuthorized")
			}
			value, ok := decoded.AsV2XServicesAuthorized()
			if !ok {
				var empty s47.V2XServicesAuthorized
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-V2XServicesAuthorized: no selected value")
			}
			return *value, nil
		}
		*s47.BridgeV2XServicesAuthorizedValueCodecFieldEncode(&sealed) = func(value s47.V2XServicesAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(240), rowV2XServicesAuthorized: &value}).encodeFresh(fresh, budget)
		}
		*s47.BridgeV2XServicesAuthorizedValueCodecFieldCapture(&sealed) = func(v s47.V2XServicesAuthorized, options aper.DecodeState) (s47.V2XServicesAuthorized, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s47.BridgeCaptureS1APV2XServicesAuthorized(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s47.BridgeV2XServicesAuthorizedValueCodecFieldCompare(&sealed) = func(v s47.V2XServicesAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s47.BridgeCompareS1APV2XServicesAuthorized(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s47.BridgeV2XServicesAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:V2XServicesAuthorized"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s47.V2XServicesAuthorized) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(240), rowV2XServicesAuthorized: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s47.V2XServicesAuthorized, bool) {
			return value.AsV2XServicesAuthorized()
		}}
}
func (InitialContextSetupRequestIETable) infoUESidelinkAggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(248), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UESidelinkAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-UESidelinkAggregateMaximumBitrate"}}}
}

// UESidelinkAggregateMaximumBitrate returns the typed binding for the UESidelinkAggregateMaximumBitrate row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) UESidelinkAggregateMaximumBitrate() InitialContextSetupRequestUESidelinkAggregateMaximumBitrateIEBinding {
	return InitialContextSetupRequestUESidelinkAggregateMaximumBitrateIEBinding{info: t.infoUESidelinkAggregateMaximumBitrate(), codec: func() s38.UESidelinkAggregateMaximumBitrateValueCodec {
		sealed := s38.UESidelinkAggregateMaximumBitrateValueCodec{}
		*s38.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "UESidelinkAggregateMaximumBitrate"
		*s38.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s38.UESidelinkAggregateMaximumBitrate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s38.UESidelinkAggregateMaximumBitrate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UESidelinkAggregateMaximumBitrate")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(248), raw)
			if err != nil {
				var empty s38.UESidelinkAggregateMaximumBitrate
				return empty, runtime.WrapDecodePath(err, "UESidelinkAggregateMaximumBitrate")
			}
			value, ok := decoded.AsUESidelinkAggregateMaximumBitrate()
			if !ok {
				var empty s38.UESidelinkAggregateMaximumBitrate
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-UESidelinkAggregateMaximumBitrate: no selected value")
			}
			return *value, nil
		}
		*s38.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s38.UESidelinkAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(248), rowUESidelinkAggregateMaximumBitrate: &value}).encodeFresh(fresh, budget)
		}
		*s38.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s38.UESidelinkAggregateMaximumBitrate, options aper.DecodeState) (s38.UESidelinkAggregateMaximumBitrate, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s38.BridgeCaptureS1APUESidelinkAggregateMaximumBitrate(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s38.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s38.UESidelinkAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s38.BridgeCompareS1APUESidelinkAggregateMaximumBitrate(
				&v,

				&s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s38.BridgeUESidelinkAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UESidelinkAggregateMaximumBitrate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s38.UESidelinkAggregateMaximumBitrate) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(248), rowUESidelinkAggregateMaximumBitrate: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s38.UESidelinkAggregateMaximumBitrate, bool) {
			return value.AsUESidelinkAggregateMaximumBitrate()
		}}
}
func (InitialContextSetupRequestIETable) infoEnhancedCoverageRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(251), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "EnhancedCoverageRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-EnhancedCoverageRestricted"}}}
}

// EnhancedCoverageRestricted returns the typed binding for the EnhancedCoverageRestricted row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) EnhancedCoverageRestricted() InitialContextSetupRequestEnhancedCoverageRestrictedIEBinding {
	return InitialContextSetupRequestEnhancedCoverageRestrictedIEBinding{info: t.infoEnhancedCoverageRestricted(), codec: func() s00.EnhancedCoverageRestrictedValueCodec {
		sealed := s00.EnhancedCoverageRestrictedValueCodec{}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldPath(&sealed) = "EnhancedCoverageRestricted"
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.EnhancedCoverageRestricted, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.EnhancedCoverageRestricted
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("EnhancedCoverageRestricted")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(251), raw)
			if err != nil {
				var empty s00.EnhancedCoverageRestricted
				return empty, runtime.WrapDecodePath(err, "EnhancedCoverageRestricted")
			}
			value, ok := decoded.AsEnhancedCoverageRestricted()
			if !ok {
				var empty s00.EnhancedCoverageRestricted
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-EnhancedCoverageRestricted: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldEncode(&sealed) = func(value s00.EnhancedCoverageRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(251), rowEnhancedCoverageRestricted: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldCapture(&sealed) = func(v s00.EnhancedCoverageRestricted, options aper.DecodeState) (s00.EnhancedCoverageRestricted, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APEnhancedCoverageRestricted(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldCompare(&sealed) = func(v s00.EnhancedCoverageRestricted, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APEnhancedCoverageRestricted(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeEnhancedCoverageRestrictedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:EnhancedCoverageRestricted"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.EnhancedCoverageRestricted) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(251), rowEnhancedCoverageRestricted: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.EnhancedCoverageRestricted, bool) {
			return value.AsEnhancedCoverageRestricted()
		}}
}
func (InitialContextSetupRequestIETable) infoNRUESecurityCapabilities() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(269), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESecurityCapabilities"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-NRUESecurityCapabilities"}}}
}

// NRUESecurityCapabilities returns the typed binding for the NRUESecurityCapabilities row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) NRUESecurityCapabilities() InitialContextSetupRequestNRUESecurityCapabilitiesIEBinding {
	return InitialContextSetupRequestNRUESecurityCapabilitiesIEBinding{info: t.infoNRUESecurityCapabilities(), codec: func() s19.NRUESecurityCapabilitiesValueCodec {
		sealed := s19.NRUESecurityCapabilitiesValueCodec{}
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldPath(&sealed) = "NRUESecurityCapabilities"
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s19.NRUESecurityCapabilities, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s19.NRUESecurityCapabilities
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NRUESecurityCapabilities")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(269), raw)
			if err != nil {
				var empty s19.NRUESecurityCapabilities
				return empty, runtime.WrapDecodePath(err, "NRUESecurityCapabilities")
			}
			value, ok := decoded.AsNRUESecurityCapabilities()
			if !ok {
				var empty s19.NRUESecurityCapabilities
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-NRUESecurityCapabilities: no selected value")
			}
			return *value, nil
		}
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldEncode(&sealed) = func(value s19.NRUESecurityCapabilities, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(269), rowNRUESecurityCapabilities: &value}).encodeFresh(fresh, budget)
		}
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldCapture(&sealed) = func(v s19.NRUESecurityCapabilities, options aper.DecodeState) (s19.NRUESecurityCapabilities, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s19.BridgeCaptureS1APNRUESecurityCapabilities(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false)
			return v, root
		}
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldCompare(&sealed) = func(v s19.NRUESecurityCapabilities, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s19.BridgeCompareS1APNRUESecurityCapabilities(&v, &s)
			s.End(f, root,

				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s19.BridgeNRUESecurityCapabilitiesValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRUESecurityCapabilities"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s19.NRUESecurityCapabilities) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(269), rowNRUESecurityCapabilities: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s19.NRUESecurityCapabilities, bool) {
			return value.AsNRUESecurityCapabilities()
		}}
}
func (InitialContextSetupRequestIETable) infoCEModeBRestricted() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(271), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CE-ModeBRestricted"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-CE-ModeBRestricted"}}}
}

// CEModeBRestricted returns the typed binding for the CEModeBRestricted row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) CEModeBRestricted() InitialContextSetupRequestCEModeBRestrictedIEBinding {
	return InitialContextSetupRequestCEModeBRestrictedIEBinding{info: t.infoCEModeBRestricted(), codec: func() s00.CEModeBRestrictedValueCodec {
		sealed := s00.CEModeBRestrictedValueCodec{}
		*s00.BridgeCEModeBRestrictedValueCodecFieldPath(&sealed) = "CEModeBRestricted"
		*s00.BridgeCEModeBRestrictedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CEModeBRestricted, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CEModeBRestricted
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CEModeBRestricted")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(271), raw)
			if err != nil {
				var empty s00.CEModeBRestricted
				return empty, runtime.WrapDecodePath(err, "CEModeBRestricted")
			}
			value, ok := decoded.AsCEModeBRestricted()
			if !ok {
				var empty s00.CEModeBRestricted
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-CE-ModeBRestricted: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCEModeBRestrictedValueCodecFieldEncode(&sealed) = func(value s00.CEModeBRestricted, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(271), rowCEModeBRestricted: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCEModeBRestrictedValueCodecFieldCapture(&sealed) = func(v s00.CEModeBRestricted, options aper.DecodeState) (s00.CEModeBRestricted, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APCEModeBRestricted(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v,
				root

		}
		*s00.BridgeCEModeBRestrictedValueCodecFieldCompare(&sealed) = func(v s00.CEModeBRestricted, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCEModeBRestricted(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeCEModeBRestrictedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CEModeBRestricted"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CEModeBRestricted) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(271), rowCEModeBRestricted: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.CEModeBRestricted, bool) {
			return value.AsCEModeBRestricted()
		}}
}
func (InitialContextSetupRequestIETable) infoAerialUEsubscriptionInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(277), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AerialUEsubscriptionInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-AerialUEsubscriptionInformation"}}}
}

// AerialUEsubscriptionInformation returns the typed binding for the AerialUEsubscriptionInformation row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) AerialUEsubscriptionInformation() InitialContextSetupRequestAerialUEsubscriptionInformationIEBinding {
	return InitialContextSetupRequestAerialUEsubscriptionInformationIEBinding{info: t.infoAerialUEsubscriptionInformation(), codec: func() s00.AerialUEsubscriptionInformationValueCodec {
		sealed := s00.AerialUEsubscriptionInformationValueCodec{}
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldPath(&sealed) = "AerialUEsubscriptionInformation"
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AerialUEsubscriptionInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.AerialUEsubscriptionInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("AerialUEsubscriptionInformation")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(277), raw)
			if err != nil {
				var empty s00.AerialUEsubscriptionInformation
				return empty, runtime.WrapDecodePath(err, "AerialUEsubscriptionInformation")
			}
			value, ok := decoded.AsAerialUEsubscriptionInformation()
			if !ok {
				var empty s00.AerialUEsubscriptionInformation
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-AerialUEsubscriptionInformation: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldEncode(&sealed) = func(value s00.AerialUEsubscriptionInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(277), rowAerialUEsubscriptionInformation: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldCapture(&sealed) = func(v s00.AerialUEsubscriptionInformation, options aper.DecodeState) (s00.AerialUEsubscriptionInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APAerialUEsubscriptionInformation(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldCompare(&sealed) = func(v s00.AerialUEsubscriptionInformation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APAerialUEsubscriptionInformation(&v, &s)

			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeAerialUEsubscriptionInformationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AerialUEsubscriptionInformation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.AerialUEsubscriptionInformation) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(277), rowAerialUEsubscriptionInformation: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.AerialUEsubscriptionInformation, bool) {
			return value.AsAerialUEsubscriptionInformation()
		}}
}
func (InitialContextSetupRequestIETable) infoPendingDataIndication() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(283), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PendingDataIndication"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-PendingDataIndication"}}}
}

// PendingDataIndication returns the typed binding for the PendingDataIndication row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) PendingDataIndication() InitialContextSetupRequestPendingDataIndicationIEBinding {
	return InitialContextSetupRequestPendingDataIndicationIEBinding{info: t.infoPendingDataIndication(), codec: func() s01.PendingDataIndicationValueCodec {
		sealed := s01.PendingDataIndicationValueCodec{}
		*s01.BridgePendingDataIndicationValueCodecFieldPath(&sealed) = "PendingDataIndication"
		*s01.BridgePendingDataIndicationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.PendingDataIndication, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.PendingDataIndication
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PendingDataIndication")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(283), raw)
			if err != nil {
				var empty s00.PendingDataIndication
				return empty, runtime.WrapDecodePath(err, "PendingDataIndication")
			}
			value, ok := decoded.AsPendingDataIndication()
			if !ok {
				var empty s00.PendingDataIndication
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-PendingDataIndication: no selected value")
			}
			return *value, nil
		}
		*s01.BridgePendingDataIndicationValueCodecFieldEncode(&sealed) = func(value s00.PendingDataIndication, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(283), rowPendingDataIndication: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgePendingDataIndicationValueCodecFieldCapture(&sealed) = func(v s00.PendingDataIndication, options aper.DecodeState) (s00.PendingDataIndication, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APPendingDataIndication(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)

			return v, root
		}
		*s01.BridgePendingDataIndicationValueCodecFieldCompare(&sealed) = func(v s00.PendingDataIndication, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APPendingDataIndication(&v, &s)
			s.End(f, root, false)

			return s.Plan(), s.BudgetValue()
		}
		*s01.BridgePendingDataIndicationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PendingDataIndication"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.PendingDataIndication) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(283), rowPendingDataIndication: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.PendingDataIndication, bool) {
			return value.AsPendingDataIndication()
		}}
}
func (InitialContextSetupRequestIETable) infoSubscriptionBasedUEDifferentiationInfo() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(278), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "Subscription-Based-UE-DifferentiationInfo"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-Subscription-Based-UE-DifferentiationInfo"}}}
}

// SubscriptionBasedUEDifferentiationInfo returns the typed binding for the SubscriptionBasedUEDifferentiationInfo row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) SubscriptionBasedUEDifferentiationInfo() InitialContextSetupRequestSubscriptionBasedUEDifferentiationInfoIEBinding {
	return InitialContextSetupRequestSubscriptionBasedUEDifferentiationInfoIEBinding{info: t.infoSubscriptionBasedUEDifferentiationInfo(), codec: func() s31.SubscriptionBasedUEDifferentiationInfoValueCodec {
		sealed := s31.SubscriptionBasedUEDifferentiationInfoValueCodec{}
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldPath(&sealed) = "SubscriptionBasedUEDifferentiationInfo"
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s31.SubscriptionBasedUEDifferentiationInfo, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s31.SubscriptionBasedUEDifferentiationInfo
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("SubscriptionBasedUEDifferentiationInfo")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(278), raw)
			if err != nil {
				var empty s31.SubscriptionBasedUEDifferentiationInfo
				return empty, runtime.WrapDecodePath(err, "SubscriptionBasedUEDifferentiationInfo")
			}
			value, ok := decoded.AsSubscriptionBasedUEDifferentiationInfo()
			if !ok {
				var empty s31.SubscriptionBasedUEDifferentiationInfo
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-Subscription-Based-UE-DifferentiationInfo: no selected value")
			}
			return *value, nil
		}
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldEncode(&sealed) = func(value s31.SubscriptionBasedUEDifferentiationInfo, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(278), rowSubscriptionBasedUEDifferentiationInfo: &value}).encodeFresh(fresh, budget)
		}
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldCapture(&sealed) = func(v s31.SubscriptionBasedUEDifferentiationInfo, options aper.DecodeState) (s31.SubscriptionBasedUEDifferentiationInfo, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s31.BridgeCaptureS1APSubscriptionBasedUEDifferentiationInfo(
				&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldCompare(&sealed) = func(v s31.SubscriptionBasedUEDifferentiationInfo, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s31.BridgeCompareS1APSubscriptionBasedUEDifferentiationInfo(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s31.BridgeSubscriptionBasedUEDifferentiationInfoValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SubscriptionBasedUEDifferentiationInfo"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s31.SubscriptionBasedUEDifferentiationInfo) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(278), rowSubscriptionBasedUEDifferentiationInfo: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s31.SubscriptionBasedUEDifferentiationInfo, bool) {
			return value.AsSubscriptionBasedUEDifferentiationInfo()
		}}
}
func (InitialContextSetupRequestIETable) infoAdditionalRRMPriorityIndex() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(299), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "AdditionalRRMPriorityIndex"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-AdditionalRRMPriorityIndex"}}}
}

// AdditionalRRMPriorityIndex returns the typed binding for the AdditionalRRMPriorityIndex row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) AdditionalRRMPriorityIndex() InitialContextSetupRequestAdditionalRRMPriorityIndexIEBinding {
	return InitialContextSetupRequestAdditionalRRMPriorityIndexIEBinding{info: t.infoAdditionalRRMPriorityIndex(), codec: func() s00.AdditionalRRMPriorityIndexValueCodec {
		sealed := s00.AdditionalRRMPriorityIndexValueCodec{}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldPath(&sealed) = "AdditionalRRMPriorityIndex"
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.AdditionalRRMPriorityIndex, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("AdditionalRRMPriorityIndex")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(299), raw)
			if err != nil {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, runtime.WrapDecodePath(err, "AdditionalRRMPriorityIndex")
			}
			value, ok := decoded.AsAdditionalRRMPriorityIndex()
			if !ok {
				var empty s00.AdditionalRRMPriorityIndex
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-AdditionalRRMPriorityIndex: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldEncode(&sealed) = func(value s00.AdditionalRRMPriorityIndex, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(299), rowAdditionalRRMPriorityIndex: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldCapture(&sealed) = func(v s00.AdditionalRRMPriorityIndex, options aper.DecodeState) (s00.AdditionalRRMPriorityIndex, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APAdditionalRRMPriorityIndex(&v, &s)
			var root aper.Snapshot
			s.End(
				f, &root, false)
			return v, root
		}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldCompare(&sealed) = func(v s00.AdditionalRRMPriorityIndex, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APAdditionalRRMPriorityIndex(&v, &s)
			s.End(f,
				root,

				false)
			return s.Plan(), s.BudgetValue()
		}
		*s00.BridgeAdditionalRRMPriorityIndexValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AdditionalRRMPriorityIndex"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.AdditionalRRMPriorityIndex) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(299), rowAdditionalRRMPriorityIndex: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.AdditionalRRMPriorityIndex, bool) {
			return value.AsAdditionalRRMPriorityIndex()
		}}
}
func (InitialContextSetupRequestIETable) infoIABAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(301), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "IAB-Authorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-IAB-Authorized"}}}
}

// IABAuthorized returns the typed binding for the IABAuthorized row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) IABAuthorized() InitialContextSetupRequestIABAuthorizedIEBinding {
	return InitialContextSetupRequestIABAuthorizedIEBinding{info: t.infoIABAuthorized(), codec: func() s00.IABAuthorizedValueCodec {
		sealed := s00.IABAuthorizedValueCodec{}
		*s00.BridgeIABAuthorizedValueCodecFieldPath(&sealed) = "IABAuthorized"
		*s00.BridgeIABAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.IABAuthorized, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.IABAuthorized
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("IABAuthorized")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(301), raw)
			if err != nil {
				var empty s00.IABAuthorized
				return empty, runtime.WrapDecodePath(err, "IABAuthorized")
			}
			value, ok := decoded.AsIABAuthorized()
			if !ok {
				var empty s00.IABAuthorized
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-IAB-Authorized: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeIABAuthorizedValueCodecFieldEncode(&sealed) = func(value s00.IABAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(301), rowIABAuthorized: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeIABAuthorizedValueCodecFieldCapture(&sealed) = func(v s00.IABAuthorized, options aper.DecodeState) (s00.IABAuthorized, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APIABAuthorized(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeIABAuthorizedValueCodecFieldCompare(&sealed) = func(v s00.IABAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APIABAuthorized(&v, &s)
			s.End(f, root, false)
			return s.Plan(),

				s.BudgetValue()
		}
		*s00.BridgeIABAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:IABAuthorized"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.IABAuthorized) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(301), rowIABAuthorized: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.IABAuthorized, bool) {
			return value.AsIABAuthorized()
		}}
}
func (InitialContextSetupRequestIETable) infoNRV2XServicesAuthorized() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(306), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRV2XServicesAuthorized"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-NRV2XServicesAuthorized"}}}
}

// NRV2XServicesAuthorized returns the typed binding for the NRV2XServicesAuthorized row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) NRV2XServicesAuthorized() InitialContextSetupRequestNRV2XServicesAuthorizedIEBinding {
	return InitialContextSetupRequestNRV2XServicesAuthorizedIEBinding{info: t.infoNRV2XServicesAuthorized(), codec: func() s20.NRV2XServicesAuthorizedValueCodec {
		sealed := s20.NRV2XServicesAuthorizedValueCodec{}
		*s20.BridgeNRV2XServicesAuthorizedValueCodecFieldPath(&sealed) = "NRV2XServicesAuthorized"
		*s20.BridgeNRV2XServicesAuthorizedValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.NRV2XServicesAuthorized, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s20.NRV2XServicesAuthorized
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NRV2XServicesAuthorized")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(306), raw)
			if err != nil {
				var empty s20.NRV2XServicesAuthorized
				return empty, runtime.WrapDecodePath(err, "NRV2XServicesAuthorized")
			}
			value, ok := decoded.AsNRV2XServicesAuthorized()
			if !ok {
				var empty s20.NRV2XServicesAuthorized
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-NRV2XServicesAuthorized: no selected value")
			}
			return *value, nil
		}
		*s20.BridgeNRV2XServicesAuthorizedValueCodecFieldEncode(&sealed) = func(value s20.NRV2XServicesAuthorized, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(306), rowNRV2XServicesAuthorized: &value}).encodeFresh(fresh, budget)
		}
		*s20.BridgeNRV2XServicesAuthorizedValueCodecFieldCapture(&sealed) = func(v s20.NRV2XServicesAuthorized, options aper.DecodeState) (s20.NRV2XServicesAuthorized, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s20.BridgeCaptureS1APNRV2XServicesAuthorized(&v, &s)
			var root aper.Snapshot
			s.End(f, &root,

				false,
			)
			return v, root
		}
		*s20.BridgeNRV2XServicesAuthorizedValueCodecFieldCompare(&sealed) = func(v s20.NRV2XServicesAuthorized, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s20.BridgeCompareS1APNRV2XServicesAuthorized(&v, &s)
			s.End(f, root,
				false,
			)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeNRV2XServicesAuthorizedValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRV2XServicesAuthorized"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s20.NRV2XServicesAuthorized) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(306), rowNRV2XServicesAuthorized: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s20.NRV2XServicesAuthorized, bool) {
			return value.AsNRV2XServicesAuthorized()
		}}
}
func (InitialContextSetupRequestIETable) infoNRUESidelinkAggregateMaximumBitrate() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(307), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "NRUESidelinkAggregateMaximumBitrate"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-NRUESidelinkAggregateMaximumBitrate"}}}
}

// NRUESidelinkAggregateMaximumBitrate returns the typed binding for the NRUESidelinkAggregateMaximumBitrate row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) NRUESidelinkAggregateMaximumBitrate() InitialContextSetupRequestNRUESidelinkAggregateMaximumBitrateIEBinding {
	return InitialContextSetupRequestNRUESidelinkAggregateMaximumBitrateIEBinding{info: t.infoNRUESidelinkAggregateMaximumBitrate(), codec: func() s20.NRUESidelinkAggregateMaximumBitrateValueCodec {
		sealed := s20.NRUESidelinkAggregateMaximumBitrateValueCodec{}
		*s20.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldPath(&sealed) = "NRUESidelinkAggregateMaximumBitrate"
		*s20.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s20.NRUESidelinkAggregateMaximumBitrate, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s20.NRUESidelinkAggregateMaximumBitrate
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("NRUESidelinkAggregateMaximumBitrate")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(307), raw)
			if err != nil {
				var empty s20.NRUESidelinkAggregateMaximumBitrate
				return empty, runtime.WrapDecodePath(err, "NRUESidelinkAggregateMaximumBitrate")
			}
			value, ok := decoded.AsNRUESidelinkAggregateMaximumBitrate()
			if !ok {
				var empty s20.NRUESidelinkAggregateMaximumBitrate
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-NRUESidelinkAggregateMaximumBitrate: no selected value")
			}
			return *value, nil
		}
		*s20.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldEncode(&sealed) = func(value s20.NRUESidelinkAggregateMaximumBitrate, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(307), rowNRUESidelinkAggregateMaximumBitrate: &value}).encodeFresh(fresh, budget)
		}
		*s20.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldCapture(&sealed) = func(v s20.NRUESidelinkAggregateMaximumBitrate, options aper.DecodeState) (s20.NRUESidelinkAggregateMaximumBitrate, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s20.BridgeCaptureS1APNRUESidelinkAggregateMaximumBitrate(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root

		}
		*s20.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldCompare(&sealed) = func(v s20.NRUESidelinkAggregateMaximumBitrate, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,

		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s20.BridgeCompareS1APNRUESidelinkAggregateMaximumBitrate(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s20.BridgeNRUESidelinkAggregateMaximumBitrateValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:NRUESidelinkAggregateMaximumBitrate"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s20.NRUESidelinkAggregateMaximumBitrate) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(307), rowNRUESidelinkAggregateMaximumBitrate: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s20.NRUESidelinkAggregateMaximumBitrate, bool) {
			return value.AsNRUESidelinkAggregateMaximumBitrate()
		}}
}
func (InitialContextSetupRequestIETable) infoPC5QoSParameters() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(308), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "PC5QoSParameters"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-PC5QoSParameters"}}}
}

// PC5QoSParameters returns the typed binding for the PC5QoSParameters row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) PC5QoSParameters() InitialContextSetupRequestPC5QoSParametersIEBinding {
	return InitialContextSetupRequestPC5QoSParametersIEBinding{info: t.infoPC5QoSParameters(), codec: func() s24.PC5QoSParametersValueCodec {
		sealed := s24.PC5QoSParametersValueCodec{}
		*s24.BridgePC5QoSParametersValueCodecFieldPath(&sealed) = "PC5QoSParameters"
		*s24.BridgePC5QoSParametersValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s24.PC5QoSParameters, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s24.PC5QoSParameters
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("PC5QoSParameters")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(308), raw)
			if err != nil {
				var empty s24.PC5QoSParameters
				return empty, runtime.WrapDecodePath(err, "PC5QoSParameters")
			}
			value, ok := decoded.AsPC5QoSParameters()
			if !ok {
				var empty s24.PC5QoSParameters
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-PC5QoSParameters: no selected value")
			}
			return *value, nil
		}
		*s24.BridgePC5QoSParametersValueCodecFieldEncode(&sealed) = func(value s24.PC5QoSParameters, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(308), rowPC5QoSParameters: &value}).encodeFresh(fresh, budget)
		}
		*s24.BridgePC5QoSParametersValueCodecFieldCapture(&sealed) = func(v s24.PC5QoSParameters, options aper.DecodeState) (s24.PC5QoSParameters, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s24.BridgeCaptureS1APPC5QoSParameters(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s24.BridgePC5QoSParametersValueCodecFieldCompare(&sealed) = func(v s24.PC5QoSParameters, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s24.BridgeCompareS1APPC5QoSParameters(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s24.BridgePC5QoSParametersValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:PC5QoSParameters"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s24.PC5QoSParameters) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(308), rowPC5QoSParameters: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s24.PC5QoSParameters, bool) {
			return value.AsPC5QoSParameters()
		}}
}
func (InitialContextSetupRequestIETable) infoUERadioCapabilityID() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(314), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "UERadioCapabilityID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-UERadioCapabilityID"}}}
}

// UERadioCapabilityID returns the typed binding for the UERadioCapabilityID row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) UERadioCapabilityID() InitialContextSetupRequestUERadioCapabilityIDIEBinding {
	return InitialContextSetupRequestUERadioCapabilityIDIEBinding{info: t.infoUERadioCapabilityID(), codec: func() s02.UERadioCapabilityIDValueCodec {
		sealed := s02.UERadioCapabilityIDValueCodec{}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldPath(&sealed) = "UERadioCapabilityID"
		*s02.BridgeUERadioCapabilityIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.UERadioCapabilityID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("UERadioCapabilityID")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(314), raw)
			if err != nil {
				var empty s00.UERadioCapabilityID
				return empty, runtime.WrapDecodePath(err, "UERadioCapabilityID")
			}
			value, ok := decoded.AsUERadioCapabilityID()
			if !ok {
				var empty s00.UERadioCapabilityID
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-UERadioCapabilityID: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldEncode(&sealed) = func(value s00.UERadioCapabilityID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(314), rowUERadioCapabilityID: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldCapture(&sealed) = func(v s00.UERadioCapabilityID, options aper.DecodeState) (s00.UERadioCapabilityID, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APUERadioCapabilityID(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldCompare(&sealed) = func(v s00.UERadioCapabilityID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APUERadioCapabilityID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeUERadioCapabilityIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:UERadioCapabilityID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.UERadioCapabilityID) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(314), rowUERadioCapabilityID: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.UERadioCapabilityID, bool) {
			return value.AsUERadioCapabilityID()
		}}
}
func (InitialContextSetupRequestIETable) infoCoarseUELocation() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(354), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "CoarseUELocation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-CoarseUELocation"}}}
}

// CoarseUELocation returns the typed binding for the CoarseUELocation row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) CoarseUELocation() InitialContextSetupRequestCoarseUELocationIEBinding {
	return InitialContextSetupRequestCoarseUELocationIEBinding{info: t.infoCoarseUELocation(), codec: func() s00.CoarseUELocationValueCodec {
		sealed := s00.CoarseUELocationValueCodec{}
		*s00.BridgeCoarseUELocationValueCodecFieldPath(&sealed) = "CoarseUELocation"
		*s00.BridgeCoarseUELocationValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.CoarseUELocation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.CoarseUELocation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("CoarseUELocation")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(354), raw)
			if err != nil {
				var empty s00.CoarseUELocation
				return empty, runtime.WrapDecodePath(err, "CoarseUELocation")
			}
			value, ok := decoded.AsCoarseUELocation()
			if !ok {
				var empty s00.CoarseUELocation
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-CoarseUELocation: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeCoarseUELocationValueCodecFieldEncode(&sealed) = func(value s00.CoarseUELocation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(354), rowCoarseUELocation: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeCoarseUELocationValueCodecFieldCapture(&sealed) = func(v s00.CoarseUELocation, options aper.DecodeState) (s00.CoarseUELocation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(
				options)
			f := s.Begin()
			s00.BridgeCaptureS1APCoarseUELocation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeCoarseUELocationValueCodecFieldCompare(&sealed) = func(v s00.CoarseUELocation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APCoarseUELocation(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}
		*s00.BridgeCoarseUELocationValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:CoarseUELocation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.CoarseUELocation) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(354), rowCoarseUELocation: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.CoarseUELocation, bool) {
			return value.AsCoarseUELocation()
		}}
}
func (InitialContextSetupRequestIETable) infoTimeRefDistribution() s00.FieldInfo {
	return s00.FieldInfo{Table: InitialContextSetupRequestIEs().ID(), ID: s00.ProtocolIEID(355), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TimeRefDistribution"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "InitialContextSetupRequestIEs", Row: "id-TimeRefDistribution"}}}
}

// TimeRefDistribution returns the typed binding for the TimeRefDistribution row of InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) TimeRefDistribution() InitialContextSetupRequestTimeRefDistributionIEBinding {
	return InitialContextSetupRequestTimeRefDistributionIEBinding{info: t.infoTimeRefDistribution(), codec: func() s02.TimeRefDistributionValueCodec {
		sealed := s02.TimeRefDistributionValueCodec{}
		*s02.BridgeTimeRefDistributionValueCodecFieldPath(&sealed) = "TimeRefDistribution"
		*s02.BridgeTimeRefDistributionValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.TimeRefDistribution, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.TimeRefDistribution
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TimeRefDistribution")
			var zero InitialContextSetupRequestIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(355), raw)
			if err != nil {
				var empty s00.TimeRefDistribution
				return empty, runtime.WrapDecodePath(err, "TimeRefDistribution")
			}
			value, ok := decoded.AsTimeRefDistribution()
			if !ok {
				var empty s00.TimeRefDistribution
				return empty, fmt.Errorf("binding InitialContextSetupRequestIEs.id-TimeRefDistribution: no selected value")
			}
			return *value, nil
		}
		*s02.BridgeTimeRefDistributionValueCodecFieldEncode(&sealed) = func(value s00.TimeRefDistribution, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(355), rowTimeRefDistribution: &value}).encodeFresh(fresh, budget)
		}
		*s02.BridgeTimeRefDistributionValueCodecFieldCapture(&sealed) = func(v s00.TimeRefDistribution, options aper.DecodeState) (s00.TimeRefDistribution, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APTimeRefDistribution(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}
		*s02.BridgeTimeRefDistributionValueCodecFieldCompare(&sealed) = func(v s00.TimeRefDistribution, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget,
		) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s07.BridgeCompareS1APTimeRefDistribution(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.BudgetValue()
		}
		*s02.BridgeTimeRefDistributionValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TimeRefDistribution"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.TimeRefDistribution) InitialContextSetupRequestIEValue {
			return InitialContextSetupRequestIEValue{id: s00.ProtocolIEID(355), rowTimeRefDistribution: &value}
		}, get: func(value *InitialContextSetupRequestIEValue) (*s00.TimeRefDistribution, bool) {
			return value.AsTimeRefDistribution()
		}}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in InitialContextSetupRequestIETable.
func (t InitialContextSetupRequestIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (InitialContextSetupRequestIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(66):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-uEaggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(24):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-E-RABToBeSetupListCtxtSUReq requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(107):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UESecurityCapabilities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(73):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SecurityKey requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(25):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-TraceActivation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(41):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-HandoverRestrictionList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(74):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapability requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(106):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SubscriberProfileIDforRFP requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(108):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSFallbackIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(124):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-SRVCCOperationPossible requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(146):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-CSGMembershipStatus requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(159):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-RegisteredLAI requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(75):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-GUMMEI-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(158):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID-2 requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(165):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-ManagementBasedMDTAllowed requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(177):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-ManagementBasedMDTPLMNList requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(187):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-AdditionalCSFallbackIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(192):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-Masked-IMEISV requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(196):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-ExpectedUEBehaviour requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(195):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-ProSeAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(241):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UEUserPlaneCIoTSupportIndicator requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(240):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-V2XServicesAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(248):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UESidelinkAggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(251):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-EnhancedCoverageRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(269):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRUESecurityCapabilities requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(271):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-CE-ModeBRestricted requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(277):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-AerialUEsubscriptionInformation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(283):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-PendingDataIndication requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(278):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-Subscription-Based-UE-DifferentiationInfo requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(299):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-AdditionalRRMPriorityIndex requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(301):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-IAB-Authorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(306):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRV2XServicesAuthorized requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(307):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-NRUESidelinkAggregateMaximumBitrate requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(308):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-PC5QoSParameters requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(314):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-UERadioCapabilityID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(354):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-CoarseUELocation requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(355):
		return InitialContextSetupRequestIEField{}, aper.OperationError(fmt.Errorf("known IE id-TimeRefDistribution requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return InitialContextSetupRequestIEField{}, aper.OperationError(err, "Opaque")
		}
		return InitialContextSetupRequestIEField{Id: id, Criticality: criticality, Value: InitialContextSetupRequestIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

type TraceStartIETable struct{}

func TraceStartIEs() TraceStartIETable { return TraceStartIETable{} }

// ID returns the ASN.1 object-set identity of TraceStartIETable.
func (TraceStartIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TraceStartIEs"}
		return sealed
	}()
}

// Table returns the ASN.1 object-set table described by TraceStartIETable.
func (TraceStartIETable) Table() s00.TraceStartIEValueIETable {
	return func() s00.TraceStartIEValueIETable {
		sealed := s00.TraceStartIEValueIETable{}
		*s00.BridgeTraceStartIEValueIETableFieldBound(&sealed) = true
		return sealed
	}()
}
func (TraceStartIETable) infoMMEUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: TraceStartIEs().ID(), ID: s00.ProtocolIEID(0), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "MME-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TraceStartIEs", Row: "id-MME-UE-S1AP-ID"}}}
}

// MMEUES1APID returns the typed binding for the MMEUES1APID row of TraceStartIETable.
func (t TraceStartIETable) MMEUES1APID() TraceStartMMEUES1APIDIEBinding {
	return TraceStartMMEUES1APIDIEBinding{info: t.infoMMEUES1APID(), codec: func() s01.MMEUES1APIDValueCodec {
		sealed := s01.MMEUES1APIDValueCodec{}
		*s01.BridgeMMEUES1APIDValueCodecFieldPath(&sealed) = "MMEUES1APID"
		*s01.BridgeMMEUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.MMEUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("MMEUES1APID")
			var zero TraceStartIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(0), raw)
			if err != nil {
				var empty s00.MMEUES1APID
				return empty, runtime.WrapDecodePath(err, "MMEUES1APID")
			}
			value, ok := decoded.AsMMEUES1APID()
			if !ok {
				var empty s00.MMEUES1APID
				return empty, fmt.Errorf("binding TraceStartIEs.id-MME-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.MMEUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (TraceStartIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}).encodeFresh(fresh, budget)
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.MMEUES1APID, options aper.DecodeState) (s00.MMEUES1APID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APMMEUES1APID(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.MMEUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APMMEUES1APID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s01.BridgeMMEUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:MMEUES1APID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.MMEUES1APID) TraceStartIEValue {
			return TraceStartIEValue{id: s00.ProtocolIEID(0), rowMMEUES1APID: &value}
		}, get: func(value *TraceStartIEValue) (*s00.MMEUES1APID, bool) { return value.AsMMEUES1APID() }}
}
func (TraceStartIETable) infoENBUES1APID() s00.FieldInfo {
	return s00.FieldInfo{Table: TraceStartIEs().ID(), ID: s00.ProtocolIEID(8), Criticality: s00.CriticalityReject, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "ENB-UE-S1AP-ID"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TraceStartIEs", Row: "id-eNB-UE-S1AP-ID"}}}
}

// ENBUES1APID returns the typed binding for the ENBUES1APID row of TraceStartIETable.
func (t TraceStartIETable) ENBUES1APID() TraceStartENBUES1APIDIEBinding {
	return TraceStartENBUES1APIDIEBinding{info: t.infoENBUES1APID(), codec: func() s00.ENBUES1APIDValueCodec {
		sealed := s00.ENBUES1APIDValueCodec{}
		*s00.BridgeENBUES1APIDValueCodecFieldPath(&sealed) = "ENBUES1APID"
		*s00.BridgeENBUES1APIDValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.ENBUES1APID, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("ENBUES1APID")
			var zero TraceStartIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(8), raw)
			if err != nil {
				var empty s00.ENBUES1APID
				return empty, runtime.WrapDecodePath(err, "ENBUES1APID")
			}
			value, ok := decoded.AsENBUES1APID()
			if !ok {
				var empty s00.ENBUES1APID
				return empty, fmt.Errorf("binding TraceStartIEs.id-eNB-UE-S1AP-ID: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeENBUES1APIDValueCodecFieldEncode(&sealed) = func(value s00.ENBUES1APID, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (TraceStartIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeENBUES1APIDValueCodecFieldCapture(&sealed) = func(v s00.ENBUES1APID, options aper.DecodeState) (s00.ENBUES1APID, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s00.BridgeCaptureS1APENBUES1APID(&v, &s)
			var root aper.Snapshot

			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeENBUES1APIDValueCodecFieldCompare(&sealed) = func(v s00.ENBUES1APID, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s02.BridgeCompareS1APENBUES1APID(&v, &s)
			s.End(f, root, false)
			return s.Plan(), s.
				BudgetValue()
		}
		*s00.BridgeENBUES1APIDValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ENBUES1APID"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.ENBUES1APID) TraceStartIEValue {
			return TraceStartIEValue{id: s00.ProtocolIEID(8), rowENBUES1APID: &value}
		}, get: func(value *TraceStartIEValue) (*s00.ENBUES1APID, bool) { return value.AsENBUES1APID() }}
}
func (TraceStartIETable) infoTraceActivation() s00.FieldInfo {
	return s00.FieldInfo{Table: TraceStartIEs().ID(), ID: s00.ProtocolIEID(25), Criticality: s00.CriticalityIgnore, Presence: s00.PresenceMandatory, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "S1AP-IEs", Assignment: "TraceActivation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.413", Edition: "V19.2.0", Clause: "§9.3.3", Assignment: aper.SourceAssignment{Module: "S1AP-PDU-Contents", Assignment: "TraceStartIEs", Row: "id-TraceActivation"}}}
}

// TraceActivation returns the typed binding for the TraceActivation row of TraceStartIETable.
func (t TraceStartIETable) TraceActivation() TraceStartTraceActivationIEBinding {
	return TraceStartTraceActivationIEBinding{info: t.infoTraceActivation(), codec: TraceActivationValueCodec{path: "TraceActivation",
		decode: func(data []byte, options aper.DecodeState) (s48.TraceActivation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s48.TraceActivation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("TraceActivation")
			var zero TraceStartIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(25), raw)
			if err != nil {
				var empty s48.TraceActivation
				return empty, runtime.WrapDecodePath(err, "TraceActivation")
			}
			value, ok := decoded.AsTraceActivation()
			if !ok {
				var empty s48.TraceActivation
				return empty, fmt.Errorf("binding TraceStartIEs.id-TraceActivation: no selected value")
			}
			return *value, nil
		},
		encode: func(value s48.TraceActivation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (TraceStartIEValue{id: s00.ProtocolIEID(25), rowTraceActivation: &value}).encodeFresh(fresh, budget)
		}, capture: func(v s48.TraceActivation, options aper.DecodeState) (s48.TraceActivation, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			s48.BridgeCaptureS1APTraceActivation(&v, &s)
			var root aper.Snapshot
			s.End(f, &root, false)
			return v, root
		}, compare: func(v s48.TraceActivation, root aper.Snapshot, budget aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
			s := aper.NewSemanticComparison(root, budget)
			f := s.Begin()
			s48.BridgeCompareS1APTraceActivation(&v, &s)
			s.End(f, root, false)
			return s.
				Plan(), s.BudgetValue()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:TraceActivation"
			*s00.BridgecodecContextFieldBounds(&sealed) = aper.ListBounds{}
			return sealed
		}(),
	}, inject: func(value s48.TraceActivation) TraceStartIEValue {
		return TraceStartIEValue{id: s00.ProtocolIEID(25), rowTraceActivation: &value}
	}, get: func(value *TraceStartIEValue) (*s48.TraceActivation, bool) { return value.AsTraceActivation() }}
}

// NewOpaque constructs an owned opaque field for an identifier without a typed row in TraceStartIETable.
func (t TraceStartIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (TraceStartIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return TraceStartIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(0):
		return TraceStartIEField{}, aper.OperationError(fmt.Errorf("known IE id-MME-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(8):
		return TraceStartIEField{}, aper.OperationError(fmt.Errorf("known IE id-eNB-UE-S1AP-ID requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(25):
		return TraceStartIEField{}, aper.OperationError(fmt.Errorf("known IE id-TraceActivation requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return TraceStartIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return TraceStartIEField{}, aper.OperationError(err, "Opaque")
		}
		return TraceStartIEField{Id: id, Criticality: criticality, Value: TraceStartIEValue{id: id, opaque: opaque, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// AdditionalCSFallbackIndicatorCodec binds the complete APER value type.
func AdditionalCSFallbackIndicatorCodec() s00.AdditionalCSFallbackIndicatorValueCodec {
	return InitialContextSetupRequestIEs().AdditionalCSFallbackIndicator().Codec()
}

// AerialUEsubscriptionInformationCodec binds the complete APER value type.
func AerialUEsubscriptionInformationCodec() s00.AerialUEsubscriptionInformationValueCodec {
	return HandoverRequestIEs().AerialUEsubscriptionInformation().Codec()
}

// CSFallbackIndicatorCodec binds the complete APER value type.
func CSFallbackIndicatorCodec() s00.CSFallbackIndicatorValueCodec {
	return InitialContextSetupRequestIEs().CSFallbackIndicator().Codec()
}

// ERABToBeSetupListCtxtSUReqCodec binds the complete APER value type.
func ERABToBeSetupListCtxtSUReqCodec() s30.ERABToBeSetupListCtxtSUReqValueCodec {
	return InitialContextSetupRequestIEs().ERABToBeSetupListCtxtSUReq().Codec()
}

// ERABToBeSetupListHOReqCodec binds the complete APER value type.
func ERABToBeSetupListHOReqCodec() s30.ERABToBeSetupListHOReqValueCodec {
	return HandoverRequestIEs().ERABToBeSetupListHOReq().Codec()
}

// ExpectedUEBehaviourCodec binds the complete APER value type.
func ExpectedUEBehaviourCodec() s18.ExpectedUEBehaviourValueCodec {
	return HandoverRequestIEs().ExpectedUEBehaviour().Codec()
}

// GUMMEICodec binds the complete APER value type.
func GUMMEICodec() s18.GUMMEIValueCodec { return HandoverRequestIEs().GUMMEIID().Codec() }

// IABAuthorizedCodec binds the complete APER value type.
func IABAuthorizedCodec() s00.IABAuthorizedValueCodec {
	return HandoverRequestIEs().IABAuthorized().Codec()
}

// LAICodec binds the complete APER value type.
func LAICodec() s18.LAIValueCodec { return InitialContextSetupRequestIEs().RegisteredLAI().Codec() }

// ManagementBasedMDTAllowedCodec binds the complete APER value type.
func ManagementBasedMDTAllowedCodec() s01.ManagementBasedMDTAllowedValueCodec {
	return HandoverRequestIEs().ManagementBasedMDTAllowed().Codec()
}

// NASSecurityParameterstoEUTRANCodec binds the complete APER value type.
func NASSecurityParameterstoEUTRANCodec() s01.NASSecurityParameterstoEUTRANValueCodec {
	return HandoverRequestIEs().NASSecurityParameterstoEUTRAN().Codec()
}

// NRUESidelinkAggregateMaximumBitrateCodec binds the complete APER value type.
func NRUESidelinkAggregateMaximumBitrateCodec() s20.NRUESidelinkAggregateMaximumBitrateValueCodec {
	return HandoverRequestIEs().NRUESidelinkAggregateMaximumBitrate().Codec()
}

// NRV2XServicesAuthorizedCodec binds the complete APER value type.
func NRV2XServicesAuthorizedCodec() s20.NRV2XServicesAuthorizedValueCodec {
	return HandoverRequestIEs().NRV2XServicesAuthorized().Codec()
}

// PC5QoSParametersCodec binds the complete APER value type.
func PC5QoSParametersCodec() s24.PC5QoSParametersValueCodec {
	return HandoverRequestIEs().PC5QoSParameters().Codec()
}

// ProSeAuthorizedCodec binds the complete APER value type.
func ProSeAuthorizedCodec() s20.ProSeAuthorizedValueCodec {
	return HandoverRequestIEs().ProSeAuthorized().Codec()
}

// RequestTypeCodec binds the complete APER value type.
func RequestTypeCodec() s26.RequestTypeValueCodec { return HandoverRequestIEs().RequestType().Codec() }

// SecurityContextCodec binds the complete APER value type.
func SecurityContextCodec() s29.SecurityContextValueCodec {
	return HandoverRequestIEs().SecurityContext().Codec()
}

// SecurityKeyCodec binds the complete APER value type.
func SecurityKeyCodec() s01.SecurityKeyValueCodec {
	return InitialContextSetupRequestIEs().SecurityKey().Codec()
}

// SourceToTargetTransparentContainerCodec binds the complete APER value type.
func SourceToTargetTransparentContainerCodec() s01.SourceToTargetTransparentContainerValueCodec {
	return HandoverRequestIEs().SourceToTargetTransparentContainer().Codec()
}

// TimeRefDistributionCodec binds the complete APER value type.
func TimeRefDistributionCodec() s02.TimeRefDistributionValueCodec {
	return HandoverRequestIEs().TimeRefDistribution().Codec()
}

// TraceActivationCodec binds the complete APER value type.
func TraceActivationCodec() TraceActivationValueCodec {
	return HandoverRequestIEs().TraceActivation().Codec()
}

// UESecurityCapabilitiesCodec binds the complete APER value type.
func UESecurityCapabilitiesCodec() s37.UESecurityCapabilitiesValueCodec {
	return HandoverRequestIEs().UESecurityCapabilities().Codec()
}

// UESidelinkAggregateMaximumBitrateCodec binds the complete APER value type.
func UESidelinkAggregateMaximumBitrateCodec() s38.UESidelinkAggregateMaximumBitrateValueCodec {
	return HandoverRequestIEs().UESidelinkAggregateMaximumBitrate().Codec()
}

// UEUserPlaneCIoTSupportIndicatorCodec binds the complete APER value type.
func UEUserPlaneCIoTSupportIndicatorCodec() s02.UEUserPlaneCIoTSupportIndicatorValueCodec {
	return HandoverRequestIEs().UEUserPlaneCIoTSupportIndicator().Codec()
}

// V2XServicesAuthorizedCodec binds the complete APER value type.
func V2XServicesAuthorizedCodec() s47.V2XServicesAuthorizedValueCodec {
	return HandoverRequestIEs().V2XServicesAuthorized().Codec()
}
func BridgeHandoverRequestAPERValueFieldContext(v *HandoverRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestAPERValueFieldReceived(v *HandoverRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeHandoverRequestAPERValueFieldReplay(v *HandoverRequestAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeHandoverRequestAPERValueFieldWithoutReplay(v *HandoverRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeHandoverRequestFieldExtCount(v *HandoverRequest) *int64   { return &v.extCount }
func BridgeHandoverRequestFieldExtData(v *HandoverRequest) *[][]byte { return &v.extData }
func BridgeHandoverRequestFieldExtOrigin(v *HandoverRequest) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeHandoverRequestFieldExtPresent(v *HandoverRequest) *[]bool       { return &v.extPresent }
func BridgeHandoverRequestFieldExtWire(v *HandoverRequest) *[]aper.WireSpan { return &v.extWire }
func BridgeHandoverRequestFieldPerExtPadding(v *HandoverRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeHandoverRequestFieldPerPadding(v *HandoverRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeHandoverRequestFieldProtocolIEsIndef(v *HandoverRequest) *bool { return &v.protocolIEsIndef }
func BridgeHandoverRequestFieldReceived(v *HandoverRequest) *bool         { return &v.received }
func BridgeHandoverRequestFieldReceivedAbsolute(v *HandoverRequest) *bool { return &v.receivedAbsolute }
func BridgeHandoverRequestFieldReceivedBytes(v *HandoverRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeHandoverRequestFieldReceivedLocation(v *HandoverRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeHandoverRequestFieldReplay(v *HandoverRequest) *aper.Snapshot { return &v.replay }
func BridgeHandoverRequestFieldStream(v *HandoverRequest) *aper.WireSpan { return &v.stream }
func BridgeHandoverRequestFieldWithoutReplay(v *HandoverRequest) *bool   { return &v.withoutReplay }
func BridgeHandoverRequestIETableMethodInfoAdditionalRRMPriorityIndex(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoAdditionalRRMPriorityIndex()
}
func BridgeHandoverRequestIETableMethodInfoAerialUEsubscriptionInformation(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoAerialUEsubscriptionInformation()
}
func BridgeHandoverRequestIETableMethodInfoCEModeBRestricted(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoCEModeBRestricted()
}
func BridgeHandoverRequestIETableMethodInfoCSGId(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoCSGId()
}
func BridgeHandoverRequestIETableMethodInfoCSGMembershipStatus(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoCSGMembershipStatus()
}
func BridgeHandoverRequestIETableMethodInfoCause(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoCause()
}
func BridgeHandoverRequestIETableMethodInfoERABToBeSetupListHOReq(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoERABToBeSetupListHOReq()
}
func BridgeHandoverRequestIETableMethodInfoEnhancedCoverageRestricted(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoEnhancedCoverageRestricted()
}
func BridgeHandoverRequestIETableMethodInfoExpectedUEBehaviour(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoExpectedUEBehaviour()
}
func BridgeHandoverRequestIETableMethodInfoGUMMEIID(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoGUMMEIID()
}
func BridgeHandoverRequestIETableMethodInfoHandoverRestrictionList(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoHandoverRestrictionList()
}
func BridgeHandoverRequestIETableMethodInfoHandoverType(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoHandoverType()
}
func BridgeHandoverRequestIETableMethodInfoIABAuthorized(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoIABAuthorized()
}
func BridgeHandoverRequestIETableMethodInfoMMEUES1APID(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeHandoverRequestIETableMethodInfoMMEUES1APID2(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoMMEUES1APID2()
}
func BridgeHandoverRequestIETableMethodInfoManagementBasedMDTAllowed(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoManagementBasedMDTAllowed()
}
func BridgeHandoverRequestIETableMethodInfoManagementBasedMDTPLMNList(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoManagementBasedMDTPLMNList()
}
func BridgeHandoverRequestIETableMethodInfoMaskedIMEISV(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoMaskedIMEISV()
}
func BridgeHandoverRequestIETableMethodInfoNASSecurityParameterstoEUTRAN(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoNASSecurityParameterstoEUTRAN()
}
func BridgeHandoverRequestIETableMethodInfoNRUESecurityCapabilities(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoNRUESecurityCapabilities()
}
func BridgeHandoverRequestIETableMethodInfoNRUESidelinkAggregateMaximumBitrate(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoNRUESidelinkAggregateMaximumBitrate()
}
func BridgeHandoverRequestIETableMethodInfoNRV2XServicesAuthorized(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoNRV2XServicesAuthorized()
}
func BridgeHandoverRequestIETableMethodInfoPC5QoSParameters(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoPC5QoSParameters()
}
func BridgeHandoverRequestIETableMethodInfoPendingDataIndication(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoPendingDataIndication()
}
func BridgeHandoverRequestIETableMethodInfoProSeAuthorized(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoProSeAuthorized()
}
func BridgeHandoverRequestIETableMethodInfoRequestType(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoRequestType()
}
func BridgeHandoverRequestIETableMethodInfoSRVCCOperationPossible(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoSRVCCOperationPossible()
}
func BridgeHandoverRequestIETableMethodInfoSecurityContext(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoSecurityContext()
}
func BridgeHandoverRequestIETableMethodInfoSourceToTargetTransparentContainer(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoSourceToTargetTransparentContainer()
}
func BridgeHandoverRequestIETableMethodInfoSubscriptionBasedUEDifferentiationInfo(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoSubscriptionBasedUEDifferentiationInfo()
}
func BridgeHandoverRequestIETableMethodInfoTimeRefDistribution(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoTimeRefDistribution()
}
func BridgeHandoverRequestIETableMethodInfoTraceActivation(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoTraceActivation()
}
func BridgeHandoverRequestIETableMethodInfoUERadioCapabilityID(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoUERadioCapabilityID()
}
func BridgeHandoverRequestIETableMethodInfoUESecurityCapabilities(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoUESecurityCapabilities()
}
func BridgeHandoverRequestIETableMethodInfoUESidelinkAggregateMaximumBitrate(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoUESidelinkAggregateMaximumBitrate()
}
func BridgeHandoverRequestIETableMethodInfoUEUserPlaneCIoTSupportIndicator(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoUEUserPlaneCIoTSupportIndicator()
}
func BridgeHandoverRequestIETableMethodInfoUEaggregateMaximumBitrate(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoUEaggregateMaximumBitrate()
}
func BridgeHandoverRequestIETableMethodInfoV2XServicesAuthorized(v HandoverRequestIETable) s00.FieldInfo {
	return v.infoV2XServicesAuthorized()
}
func BridgeHandoverRequestMethodMarshalAPERBudget(v *HandoverRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeHandoverRequestMethodMarshalAPERBudgetValue(v *HandoverRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeHandoverRequestMethodMarshalAPERChanged(v *HandoverRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeHandoverRequestMethodMarshalAPERChangedValue(v *HandoverRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeHandoverRequestMethodMarshalAPERLegacy(v *HandoverRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeHandoverRequestMethodMarshalAPERNewValue(v *HandoverRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeHandoverRequestMethodMarshalAPERPlanned(v *HandoverRequest, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeHandoverRequestMethodMarshalAPERTo(v *HandoverRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeHandoverRequestMethodUnmarshalAPERFrom(v *HandoverRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeHandoverRequestMethodUnmarshalAPERLegacy(v *HandoverRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeHandoverRequestMethodUnmarshalAPERWithOptions(v *HandoverRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeHandoverRequestTraceActivationIEBindingFieldCodec(v *HandoverRequestTraceActivationIEBinding) *TraceActivationValueCodec {
	return &v.codec
}
func BridgeHandoverRequestTraceActivationIEBindingFieldGet(v *HandoverRequestTraceActivationIEBinding) *func(*s48.HandoverRequestIEValue) (*s48.TraceActivation, bool) {
	return &v.get
}
func BridgeHandoverRequestTraceActivationIEBindingFieldInfo(v *HandoverRequestTraceActivationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeHandoverRequestTraceActivationIEBindingFieldInject(v *HandoverRequestTraceActivationIEBinding) *func(s48.TraceActivation) s48.HandoverRequestIEValue {
	return &v.inject
}
func BridgeHandoverRequestValueCodecFieldCapture(v *HandoverRequestValueCodec) *func(HandoverRequest, aper.DecodeState) (HandoverRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeHandoverRequestValueCodecFieldCompare(v *HandoverRequestValueCodec) *func(HandoverRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeHandoverRequestValueCodecFieldContext(v *HandoverRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeHandoverRequestValueCodecFieldDecode(v *HandoverRequestValueCodec) *func([]byte, aper.DecodeState) (HandoverRequest, error) {
	return &v.decode
}
func BridgeHandoverRequestValueCodecFieldEncode(v *HandoverRequestValueCodec) *func(HandoverRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeHandoverRequestValueCodecFieldPath(v *HandoverRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeHandoverRequestValueCodecMethodEncodeBudgetValue(v HandoverRequestValueCodec, a0 HandoverRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeHandoverRequestValueCodecMethodEncodeChanged(v HandoverRequestValueCodec, a0 HandoverRequest, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialContextSetupRequestAPERValueFieldContext(v *InitialContextSetupRequestAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupRequestAPERValueFieldReceived(v *InitialContextSetupRequestAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupRequestAPERValueFieldReplay(v *InitialContextSetupRequestAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupRequestAPERValueFieldWithoutReplay(v *InitialContextSetupRequestAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupRequestAdditionalCSFallbackIndicatorIEBindingFieldCodec(v *InitialContextSetupRequestAdditionalCSFallbackIndicatorIEBinding) *s00.AdditionalCSFallbackIndicatorValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestAdditionalCSFallbackIndicatorIEBindingFieldGet(v *InitialContextSetupRequestAdditionalCSFallbackIndicatorIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.AdditionalCSFallbackIndicator, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestAdditionalCSFallbackIndicatorIEBindingFieldInfo(v *InitialContextSetupRequestAdditionalCSFallbackIndicatorIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestAdditionalCSFallbackIndicatorIEBindingFieldInject(v *InitialContextSetupRequestAdditionalCSFallbackIndicatorIEBinding) *func(s00.AdditionalCSFallbackIndicator) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestAdditionalRRMPriorityIndexIEBindingFieldCodec(v *InitialContextSetupRequestAdditionalRRMPriorityIndexIEBinding) *s00.AdditionalRRMPriorityIndexValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestAdditionalRRMPriorityIndexIEBindingFieldGet(v *InitialContextSetupRequestAdditionalRRMPriorityIndexIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.AdditionalRRMPriorityIndex, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestAdditionalRRMPriorityIndexIEBindingFieldInfo(v *InitialContextSetupRequestAdditionalRRMPriorityIndexIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestAdditionalRRMPriorityIndexIEBindingFieldInject(v *InitialContextSetupRequestAdditionalRRMPriorityIndexIEBinding) *func(s00.AdditionalRRMPriorityIndex) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestAerialUEsubscriptionInformationIEBindingFieldCodec(v *InitialContextSetupRequestAerialUEsubscriptionInformationIEBinding) *s00.AerialUEsubscriptionInformationValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestAerialUEsubscriptionInformationIEBindingFieldGet(v *InitialContextSetupRequestAerialUEsubscriptionInformationIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.AerialUEsubscriptionInformation, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestAerialUEsubscriptionInformationIEBindingFieldInfo(v *InitialContextSetupRequestAerialUEsubscriptionInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestAerialUEsubscriptionInformationIEBindingFieldInject(v *InitialContextSetupRequestAerialUEsubscriptionInformationIEBinding) *func(s00.AerialUEsubscriptionInformation) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestCEModeBRestrictedIEBindingFieldCodec(v *InitialContextSetupRequestCEModeBRestrictedIEBinding) *s00.CEModeBRestrictedValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestCEModeBRestrictedIEBindingFieldGet(v *InitialContextSetupRequestCEModeBRestrictedIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.CEModeBRestricted, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestCEModeBRestrictedIEBindingFieldInfo(v *InitialContextSetupRequestCEModeBRestrictedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestCEModeBRestrictedIEBindingFieldInject(v *InitialContextSetupRequestCEModeBRestrictedIEBinding) *func(s00.CEModeBRestricted) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestCSFallbackIndicatorIEBindingFieldCodec(v *InitialContextSetupRequestCSFallbackIndicatorIEBinding) *s00.CSFallbackIndicatorValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestCSFallbackIndicatorIEBindingFieldGet(v *InitialContextSetupRequestCSFallbackIndicatorIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.CSFallbackIndicator, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestCSFallbackIndicatorIEBindingFieldInfo(v *InitialContextSetupRequestCSFallbackIndicatorIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestCSFallbackIndicatorIEBindingFieldInject(v *InitialContextSetupRequestCSFallbackIndicatorIEBinding) *func(s00.CSFallbackIndicator) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestCSGMembershipStatusIEBindingFieldCodec(v *InitialContextSetupRequestCSGMembershipStatusIEBinding) *s00.CSGMembershipStatusValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestCSGMembershipStatusIEBindingFieldGet(v *InitialContextSetupRequestCSGMembershipStatusIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.CSGMembershipStatus, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestCSGMembershipStatusIEBindingFieldInfo(v *InitialContextSetupRequestCSGMembershipStatusIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestCSGMembershipStatusIEBindingFieldInject(v *InitialContextSetupRequestCSGMembershipStatusIEBinding) *func(s00.CSGMembershipStatus) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestCoarseUELocationIEBindingFieldCodec(v *InitialContextSetupRequestCoarseUELocationIEBinding) *s00.CoarseUELocationValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestCoarseUELocationIEBindingFieldGet(v *InitialContextSetupRequestCoarseUELocationIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.CoarseUELocation, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestCoarseUELocationIEBindingFieldInfo(v *InitialContextSetupRequestCoarseUELocationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestCoarseUELocationIEBindingFieldInject(v *InitialContextSetupRequestCoarseUELocationIEBinding) *func(s00.CoarseUELocation) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestENBUES1APIDIEBindingFieldCodec(v *InitialContextSetupRequestENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestENBUES1APIDIEBindingFieldGet(v *InitialContextSetupRequestENBUES1APIDIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestENBUES1APIDIEBindingFieldInfo(v *InitialContextSetupRequestENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestENBUES1APIDIEBindingFieldInject(v *InitialContextSetupRequestENBUES1APIDIEBinding) *func(s00.ENBUES1APID) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestERABToBeSetupListCtxtSUReqIEBindingFieldCodec(v *InitialContextSetupRequestERABToBeSetupListCtxtSUReqIEBinding) *s30.ERABToBeSetupListCtxtSUReqValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestERABToBeSetupListCtxtSUReqIEBindingFieldGet(v *InitialContextSetupRequestERABToBeSetupListCtxtSUReqIEBinding) *func(*InitialContextSetupRequestIEValue) (*s30.ERABToBeSetupListCtxtSUReq, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestERABToBeSetupListCtxtSUReqIEBindingFieldInfo(v *InitialContextSetupRequestERABToBeSetupListCtxtSUReqIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestERABToBeSetupListCtxtSUReqIEBindingFieldInject(v *InitialContextSetupRequestERABToBeSetupListCtxtSUReqIEBinding) *func(s30.ERABToBeSetupListCtxtSUReq) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestEnhancedCoverageRestrictedIEBindingFieldCodec(v *InitialContextSetupRequestEnhancedCoverageRestrictedIEBinding) *s00.EnhancedCoverageRestrictedValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestEnhancedCoverageRestrictedIEBindingFieldGet(v *InitialContextSetupRequestEnhancedCoverageRestrictedIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.EnhancedCoverageRestricted, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestEnhancedCoverageRestrictedIEBindingFieldInfo(v *InitialContextSetupRequestEnhancedCoverageRestrictedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestEnhancedCoverageRestrictedIEBindingFieldInject(v *InitialContextSetupRequestEnhancedCoverageRestrictedIEBinding) *func(s00.EnhancedCoverageRestricted) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestExpectedUEBehaviourIEBindingFieldCodec(v *InitialContextSetupRequestExpectedUEBehaviourIEBinding) *s18.ExpectedUEBehaviourValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestExpectedUEBehaviourIEBindingFieldGet(v *InitialContextSetupRequestExpectedUEBehaviourIEBinding) *func(*InitialContextSetupRequestIEValue) (*s18.ExpectedUEBehaviour, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestExpectedUEBehaviourIEBindingFieldInfo(v *InitialContextSetupRequestExpectedUEBehaviourIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestExpectedUEBehaviourIEBindingFieldInject(v *InitialContextSetupRequestExpectedUEBehaviourIEBinding) *func(s18.ExpectedUEBehaviour) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestFieldExtCount(v *InitialContextSetupRequest) *int64 {
	return &v.extCount
}
func BridgeInitialContextSetupRequestFieldExtData(v *InitialContextSetupRequest) *[][]byte {
	return &v.extData
}
func BridgeInitialContextSetupRequestFieldExtOrigin(v *InitialContextSetupRequest) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeInitialContextSetupRequestFieldExtPresent(v *InitialContextSetupRequest) *[]bool {
	return &v.extPresent
}
func BridgeInitialContextSetupRequestFieldExtWire(v *InitialContextSetupRequest) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeInitialContextSetupRequestFieldPerExtPadding(v *InitialContextSetupRequest) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeInitialContextSetupRequestFieldPerPadding(v *InitialContextSetupRequest) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeInitialContextSetupRequestFieldProtocolIEsIndef(v *InitialContextSetupRequest) *bool {
	return &v.protocolIEsIndef
}
func BridgeInitialContextSetupRequestFieldReceived(v *InitialContextSetupRequest) *bool {
	return &v.received
}
func BridgeInitialContextSetupRequestFieldReceivedAbsolute(v *InitialContextSetupRequest) *bool {
	return &v.receivedAbsolute
}
func BridgeInitialContextSetupRequestFieldReceivedBytes(v *InitialContextSetupRequest) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeInitialContextSetupRequestFieldReceivedLocation(v *InitialContextSetupRequest) *aper.Location {
	return &v.receivedLocation
}
func BridgeInitialContextSetupRequestFieldReplay(v *InitialContextSetupRequest) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupRequestFieldStream(v *InitialContextSetupRequest) *aper.WireSpan {
	return &v.stream
}
func BridgeInitialContextSetupRequestFieldWithoutReplay(v *InitialContextSetupRequest) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupRequestGUMMEIIEBindingFieldCodec(v *InitialContextSetupRequestGUMMEIIEBinding) *s18.GUMMEIValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestGUMMEIIEBindingFieldGet(v *InitialContextSetupRequestGUMMEIIEBinding) *func(*InitialContextSetupRequestIEValue) (*s18.GUMMEI, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestGUMMEIIEBindingFieldInfo(v *InitialContextSetupRequestGUMMEIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestGUMMEIIEBindingFieldInject(v *InitialContextSetupRequestGUMMEIIEBinding) *func(s18.GUMMEI) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestHandoverRestrictionListIEBindingFieldCodec(v *InitialContextSetupRequestHandoverRestrictionListIEBinding) *s43.HandoverRestrictionListValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestHandoverRestrictionListIEBindingFieldGet(v *InitialContextSetupRequestHandoverRestrictionListIEBinding) *func(*InitialContextSetupRequestIEValue) (*s43.HandoverRestrictionList, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestHandoverRestrictionListIEBindingFieldInfo(v *InitialContextSetupRequestHandoverRestrictionListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestHandoverRestrictionListIEBindingFieldInject(v *InitialContextSetupRequestHandoverRestrictionListIEBinding) *func(s43.HandoverRestrictionList) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestIABAuthorizedIEBindingFieldCodec(v *InitialContextSetupRequestIABAuthorizedIEBinding) *s00.IABAuthorizedValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestIABAuthorizedIEBindingFieldGet(v *InitialContextSetupRequestIABAuthorizedIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.IABAuthorized, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestIABAuthorizedIEBindingFieldInfo(v *InitialContextSetupRequestIABAuthorizedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestIABAuthorizedIEBindingFieldInject(v *InitialContextSetupRequestIABAuthorizedIEBinding) *func(s00.IABAuthorized) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestIEContainerAPERValueFieldContext(v *InitialContextSetupRequestIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupRequestIEContainerAPERValueFieldReceived(v *InitialContextSetupRequestIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupRequestIEContainerAPERValueFieldReplay(v *InitialContextSetupRequestIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupRequestIEContainerAPERValueFieldWithoutReplay(v *InitialContextSetupRequestIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupRequestIEContainerValueCodecFieldCapture(v *InitialContextSetupRequestIEContainerValueCodec) *func(InitialContextSetupRequestIEContainer, aper.DecodeState) (InitialContextSetupRequestIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupRequestIEContainerValueCodecFieldCompare(v *InitialContextSetupRequestIEContainerValueCodec) *func(InitialContextSetupRequestIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupRequestIEContainerValueCodecFieldContext(v *InitialContextSetupRequestIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupRequestIEContainerValueCodecFieldDecode(v *InitialContextSetupRequestIEContainerValueCodec) *func([]byte, aper.DecodeState) (InitialContextSetupRequestIEContainer, error) {
	return &v.decode
}
func BridgeInitialContextSetupRequestIEContainerValueCodecFieldEncode(v *InitialContextSetupRequestIEContainerValueCodec) *func(InitialContextSetupRequestIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupRequestIEContainerValueCodecFieldPath(v *InitialContextSetupRequestIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialContextSetupRequestIEContainerValueCodecMethodEncodeBudgetValue(v InitialContextSetupRequestIEContainerValueCodec, a0 InitialContextSetupRequestIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialContextSetupRequestIEContainerValueCodecMethodEncodeChanged(v InitialContextSetupRequestIEContainerValueCodec, a0 InitialContextSetupRequestIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialContextSetupRequestIEFieldAPERValueFieldContext(v *InitialContextSetupRequestIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupRequestIEFieldAPERValueFieldReceived(v *InitialContextSetupRequestIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupRequestIEFieldAPERValueFieldReplay(v *InitialContextSetupRequestIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupRequestIEFieldAPERValueFieldWithoutReplay(v *InitialContextSetupRequestIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupRequestIEFieldFieldReceived(v *InitialContextSetupRequestIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeInitialContextSetupRequestIEFieldFieldReplay(v *InitialContextSetupRequestIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupRequestIEFieldFieldStream(v *InitialContextSetupRequestIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeInitialContextSetupRequestIEFieldFieldWithoutReplay(v *InitialContextSetupRequestIEField) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupRequestIEFieldMethodMarshalAPERTo(v *InitialContextSetupRequestIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInitialContextSetupRequestIEFieldMethodUnmarshalAPERFrom(v *InitialContextSetupRequestIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInitialContextSetupRequestIEFieldValueCodecFieldCapture(v *InitialContextSetupRequestIEFieldValueCodec) *func(InitialContextSetupRequestIEField, aper.DecodeState) (InitialContextSetupRequestIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupRequestIEFieldValueCodecFieldCompare(v *InitialContextSetupRequestIEFieldValueCodec) *func(InitialContextSetupRequestIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupRequestIEFieldValueCodecFieldContext(v *InitialContextSetupRequestIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupRequestIEFieldValueCodecFieldDecode(v *InitialContextSetupRequestIEFieldValueCodec) *func([]byte, aper.DecodeState) (InitialContextSetupRequestIEField, error) {
	return &v.decode
}
func BridgeInitialContextSetupRequestIEFieldValueCodecFieldEncode(v *InitialContextSetupRequestIEFieldValueCodec) *func(InitialContextSetupRequestIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupRequestIEFieldValueCodecFieldPath(v *InitialContextSetupRequestIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialContextSetupRequestIEFieldValueCodecMethodEncodeBudgetValue(v InitialContextSetupRequestIEFieldValueCodec, a0 InitialContextSetupRequestIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialContextSetupRequestIEFieldValueCodecMethodEncodeChanged(v InitialContextSetupRequestIEFieldValueCodec, a0 InitialContextSetupRequestIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialContextSetupRequestIETableMethodInfoAdditionalCSFallbackIndicator(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoAdditionalCSFallbackIndicator()
}
func BridgeInitialContextSetupRequestIETableMethodInfoAdditionalRRMPriorityIndex(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoAdditionalRRMPriorityIndex()
}
func BridgeInitialContextSetupRequestIETableMethodInfoAerialUEsubscriptionInformation(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoAerialUEsubscriptionInformation()
}
func BridgeInitialContextSetupRequestIETableMethodInfoCEModeBRestricted(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoCEModeBRestricted()
}
func BridgeInitialContextSetupRequestIETableMethodInfoCSFallbackIndicator(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoCSFallbackIndicator()
}
func BridgeInitialContextSetupRequestIETableMethodInfoCSGMembershipStatus(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoCSGMembershipStatus()
}
func BridgeInitialContextSetupRequestIETableMethodInfoCoarseUELocation(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoCoarseUELocation()
}
func BridgeInitialContextSetupRequestIETableMethodInfoENBUES1APID(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeInitialContextSetupRequestIETableMethodInfoERABToBeSetupListCtxtSUReq(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoERABToBeSetupListCtxtSUReq()
}
func BridgeInitialContextSetupRequestIETableMethodInfoEnhancedCoverageRestricted(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoEnhancedCoverageRestricted()
}
func BridgeInitialContextSetupRequestIETableMethodInfoExpectedUEBehaviour(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoExpectedUEBehaviour()
}
func BridgeInitialContextSetupRequestIETableMethodInfoGUMMEIID(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoGUMMEIID()
}
func BridgeInitialContextSetupRequestIETableMethodInfoHandoverRestrictionList(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoHandoverRestrictionList()
}
func BridgeInitialContextSetupRequestIETableMethodInfoIABAuthorized(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoIABAuthorized()
}
func BridgeInitialContextSetupRequestIETableMethodInfoMMEUES1APID(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeInitialContextSetupRequestIETableMethodInfoMMEUES1APID2(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoMMEUES1APID2()
}
func BridgeInitialContextSetupRequestIETableMethodInfoManagementBasedMDTAllowed(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoManagementBasedMDTAllowed()
}
func BridgeInitialContextSetupRequestIETableMethodInfoManagementBasedMDTPLMNList(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoManagementBasedMDTPLMNList()
}
func BridgeInitialContextSetupRequestIETableMethodInfoMaskedIMEISV(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoMaskedIMEISV()
}
func BridgeInitialContextSetupRequestIETableMethodInfoNRUESecurityCapabilities(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoNRUESecurityCapabilities()
}
func BridgeInitialContextSetupRequestIETableMethodInfoNRUESidelinkAggregateMaximumBitrate(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoNRUESidelinkAggregateMaximumBitrate()
}
func BridgeInitialContextSetupRequestIETableMethodInfoNRV2XServicesAuthorized(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoNRV2XServicesAuthorized()
}
func BridgeInitialContextSetupRequestIETableMethodInfoPC5QoSParameters(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoPC5QoSParameters()
}
func BridgeInitialContextSetupRequestIETableMethodInfoPendingDataIndication(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoPendingDataIndication()
}
func BridgeInitialContextSetupRequestIETableMethodInfoProSeAuthorized(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoProSeAuthorized()
}
func BridgeInitialContextSetupRequestIETableMethodInfoRegisteredLAI(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoRegisteredLAI()
}
func BridgeInitialContextSetupRequestIETableMethodInfoSRVCCOperationPossible(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoSRVCCOperationPossible()
}
func BridgeInitialContextSetupRequestIETableMethodInfoSecurityKey(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoSecurityKey()
}
func BridgeInitialContextSetupRequestIETableMethodInfoSubscriberProfileIDforRFP(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoSubscriberProfileIDforRFP()
}
func BridgeInitialContextSetupRequestIETableMethodInfoSubscriptionBasedUEDifferentiationInfo(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoSubscriptionBasedUEDifferentiationInfo()
}
func BridgeInitialContextSetupRequestIETableMethodInfoTimeRefDistribution(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoTimeRefDistribution()
}
func BridgeInitialContextSetupRequestIETableMethodInfoTraceActivation(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoTraceActivation()
}
func BridgeInitialContextSetupRequestIETableMethodInfoUERadioCapability(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoUERadioCapability()
}
func BridgeInitialContextSetupRequestIETableMethodInfoUERadioCapabilityID(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoUERadioCapabilityID()
}
func BridgeInitialContextSetupRequestIETableMethodInfoUESecurityCapabilities(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoUESecurityCapabilities()
}
func BridgeInitialContextSetupRequestIETableMethodInfoUESidelinkAggregateMaximumBitrate(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoUESidelinkAggregateMaximumBitrate()
}
func BridgeInitialContextSetupRequestIETableMethodInfoUEUserPlaneCIoTSupportIndicator(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoUEUserPlaneCIoTSupportIndicator()
}
func BridgeInitialContextSetupRequestIETableMethodInfoUEaggregateMaximumBitrate(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoUEaggregateMaximumBitrate()
}
func BridgeInitialContextSetupRequestIETableMethodInfoV2XServicesAuthorized(v InitialContextSetupRequestIETable) s00.FieldInfo {
	return v.infoV2XServicesAuthorized()
}
func BridgeInitialContextSetupRequestIEValueERABIEContainerListAPERValueFieldContext(v *InitialContextSetupRequestIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupRequestIEValueERABIEContainerListAPERValueFieldReceived(v *InitialContextSetupRequestIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupRequestIEValueERABIEContainerListAPERValueFieldReplay(v *InitialContextSetupRequestIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupRequestIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *InitialContextSetupRequestIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupRequestIEValueERABIEContainerListValueCodecFieldCapture(v *InitialContextSetupRequestIEValueERABIEContainerListValueCodec) *func(InitialContextSetupRequestIEValueERABIEContainerList, aper.DecodeState) (InitialContextSetupRequestIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupRequestIEValueERABIEContainerListValueCodecFieldCompare(v *InitialContextSetupRequestIEValueERABIEContainerListValueCodec) *func(InitialContextSetupRequestIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupRequestIEValueERABIEContainerListValueCodecFieldContext(v *InitialContextSetupRequestIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupRequestIEValueERABIEContainerListValueCodecFieldDecode(v *InitialContextSetupRequestIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (InitialContextSetupRequestIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeInitialContextSetupRequestIEValueERABIEContainerListValueCodecFieldEncode(v *InitialContextSetupRequestIEValueERABIEContainerListValueCodec) *func(InitialContextSetupRequestIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupRequestIEValueERABIEContainerListValueCodecFieldPath(v *InitialContextSetupRequestIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialContextSetupRequestIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v InitialContextSetupRequestIEValueERABIEContainerListValueCodec, a0 InitialContextSetupRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialContextSetupRequestIEValueERABIEContainerListValueCodecMethodEncodeChanged(v InitialContextSetupRequestIEValueERABIEContainerListValueCodec, a0 InitialContextSetupRequestIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialContextSetupRequestIEValueFieldId(v *InitialContextSetupRequestIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeInitialContextSetupRequestIEValueFieldIsOpaque(v *InitialContextSetupRequestIEValue) *bool {
	return &v.isOpaque
}
func BridgeInitialContextSetupRequestIEValueFieldOpaque(v *InitialContextSetupRequestIEValue) *aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeInitialContextSetupRequestIEValueFieldReceived(v *InitialContextSetupRequestIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupRequestIEValueFieldReplay(v *InitialContextSetupRequestIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupRequestIEValueFieldRowAdditionalCSFallbackIndicator(v *InitialContextSetupRequestIEValue) **s00.AdditionalCSFallbackIndicator {
	return &v.rowAdditionalCSFallbackIndicator
}
func BridgeInitialContextSetupRequestIEValueFieldRowAdditionalRRMPriorityIndex(v *InitialContextSetupRequestIEValue) **s00.AdditionalRRMPriorityIndex {
	return &v.rowAdditionalRRMPriorityIndex
}
func BridgeInitialContextSetupRequestIEValueFieldRowAerialUEsubscriptionInformation(v *InitialContextSetupRequestIEValue) **s00.AerialUEsubscriptionInformation {
	return &v.rowAerialUEsubscriptionInformation
}
func BridgeInitialContextSetupRequestIEValueFieldRowCEModeBRestricted(v *InitialContextSetupRequestIEValue) **s00.CEModeBRestricted {
	return &v.rowCEModeBRestricted
}
func BridgeInitialContextSetupRequestIEValueFieldRowCSFallbackIndicator(v *InitialContextSetupRequestIEValue) **s00.CSFallbackIndicator {
	return &v.rowCSFallbackIndicator
}
func BridgeInitialContextSetupRequestIEValueFieldRowCSGMembershipStatus(v *InitialContextSetupRequestIEValue) **s00.CSGMembershipStatus {
	return &v.rowCSGMembershipStatus
}
func BridgeInitialContextSetupRequestIEValueFieldRowCoarseUELocation(v *InitialContextSetupRequestIEValue) **s00.CoarseUELocation {
	return &v.rowCoarseUELocation
}
func BridgeInitialContextSetupRequestIEValueFieldRowENBUES1APID(v *InitialContextSetupRequestIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeInitialContextSetupRequestIEValueFieldRowERABToBeSetupListCtxtSUReq(v *InitialContextSetupRequestIEValue) **s30.ERABToBeSetupListCtxtSUReq {
	return &v.rowERABToBeSetupListCtxtSUReq
}
func BridgeInitialContextSetupRequestIEValueFieldRowEnhancedCoverageRestricted(v *InitialContextSetupRequestIEValue) **s00.EnhancedCoverageRestricted {
	return &v.rowEnhancedCoverageRestricted
}
func BridgeInitialContextSetupRequestIEValueFieldRowExpectedUEBehaviour(v *InitialContextSetupRequestIEValue) **s18.ExpectedUEBehaviour {
	return &v.rowExpectedUEBehaviour
}
func BridgeInitialContextSetupRequestIEValueFieldRowGUMMEIID(v *InitialContextSetupRequestIEValue) **s18.GUMMEI {
	return &v.rowGUMMEIID
}
func BridgeInitialContextSetupRequestIEValueFieldRowHandoverRestrictionList(v *InitialContextSetupRequestIEValue) **s43.HandoverRestrictionList {
	return &v.rowHandoverRestrictionList
}
func BridgeInitialContextSetupRequestIEValueFieldRowIABAuthorized(v *InitialContextSetupRequestIEValue) **s00.IABAuthorized {
	return &v.rowIABAuthorized
}
func BridgeInitialContextSetupRequestIEValueFieldRowMMEUES1APID(v *InitialContextSetupRequestIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeInitialContextSetupRequestIEValueFieldRowMMEUES1APID2(v *InitialContextSetupRequestIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID2
}
func BridgeInitialContextSetupRequestIEValueFieldRowManagementBasedMDTAllowed(v *InitialContextSetupRequestIEValue) **s00.ManagementBasedMDTAllowed {
	return &v.rowManagementBasedMDTAllowed
}
func BridgeInitialContextSetupRequestIEValueFieldRowManagementBasedMDTPLMNList(v *InitialContextSetupRequestIEValue) **s00.MDTPLMNList {
	return &v.rowManagementBasedMDTPLMNList
}
func BridgeInitialContextSetupRequestIEValueFieldRowMaskedIMEISV(v *InitialContextSetupRequestIEValue) **s00.MaskedIMEISV {
	return &v.rowMaskedIMEISV
}
func BridgeInitialContextSetupRequestIEValueFieldRowNRUESecurityCapabilities(v *InitialContextSetupRequestIEValue) **s19.NRUESecurityCapabilities {
	return &v.rowNRUESecurityCapabilities
}
func BridgeInitialContextSetupRequestIEValueFieldRowNRUESidelinkAggregateMaximumBitrate(v *InitialContextSetupRequestIEValue) **s20.NRUESidelinkAggregateMaximumBitrate {
	return &v.rowNRUESidelinkAggregateMaximumBitrate
}
func BridgeInitialContextSetupRequestIEValueFieldRowNRV2XServicesAuthorized(v *InitialContextSetupRequestIEValue) **s20.NRV2XServicesAuthorized {
	return &v.rowNRV2XServicesAuthorized
}
func BridgeInitialContextSetupRequestIEValueFieldRowPC5QoSParameters(v *InitialContextSetupRequestIEValue) **s24.PC5QoSParameters {
	return &v.rowPC5QoSParameters
}
func BridgeInitialContextSetupRequestIEValueFieldRowPendingDataIndication(v *InitialContextSetupRequestIEValue) **s00.PendingDataIndication {
	return &v.rowPendingDataIndication
}
func BridgeInitialContextSetupRequestIEValueFieldRowProSeAuthorized(v *InitialContextSetupRequestIEValue) **s20.ProSeAuthorized {
	return &v.rowProSeAuthorized
}
func BridgeInitialContextSetupRequestIEValueFieldRowRegisteredLAI(v *InitialContextSetupRequestIEValue) **s18.LAI {
	return &v.rowRegisteredLAI
}
func BridgeInitialContextSetupRequestIEValueFieldRowSRVCCOperationPossible(v *InitialContextSetupRequestIEValue) **s00.SRVCCOperationPossible {
	return &v.rowSRVCCOperationPossible
}
func BridgeInitialContextSetupRequestIEValueFieldRowSecurityKey(v *InitialContextSetupRequestIEValue) **s00.SecurityKey {
	return &v.rowSecurityKey
}
func BridgeInitialContextSetupRequestIEValueFieldRowSubscriberProfileIDforRFP(v *InitialContextSetupRequestIEValue) **s00.SubscriberProfileIDforRFP {
	return &v.rowSubscriberProfileIDforRFP
}
func BridgeInitialContextSetupRequestIEValueFieldRowSubscriptionBasedUEDifferentiationInfo(v *InitialContextSetupRequestIEValue) **s31.SubscriptionBasedUEDifferentiationInfo {
	return &v.rowSubscriptionBasedUEDifferentiationInfo
}
func BridgeInitialContextSetupRequestIEValueFieldRowTimeRefDistribution(v *InitialContextSetupRequestIEValue) **s00.TimeRefDistribution {
	return &v.rowTimeRefDistribution
}
func BridgeInitialContextSetupRequestIEValueFieldRowTraceActivation(v *InitialContextSetupRequestIEValue) **s48.TraceActivation {
	return &v.rowTraceActivation
}
func BridgeInitialContextSetupRequestIEValueFieldRowUERadioCapability(v *InitialContextSetupRequestIEValue) **s00.UERadioCapability {
	return &v.rowUERadioCapability
}
func BridgeInitialContextSetupRequestIEValueFieldRowUERadioCapabilityID(v *InitialContextSetupRequestIEValue) **s00.UERadioCapabilityID {
	return &v.rowUERadioCapabilityID
}
func BridgeInitialContextSetupRequestIEValueFieldRowUESecurityCapabilities(v *InitialContextSetupRequestIEValue) **s37.UESecurityCapabilities {
	return &v.rowUESecurityCapabilities
}
func BridgeInitialContextSetupRequestIEValueFieldRowUESidelinkAggregateMaximumBitrate(v *InitialContextSetupRequestIEValue) **s38.UESidelinkAggregateMaximumBitrate {
	return &v.rowUESidelinkAggregateMaximumBitrate
}
func BridgeInitialContextSetupRequestIEValueFieldRowUEUserPlaneCIoTSupportIndicator(v *InitialContextSetupRequestIEValue) **s00.UEUserPlaneCIoTSupportIndicator {
	return &v.rowUEUserPlaneCIoTSupportIndicator
}
func BridgeInitialContextSetupRequestIEValueFieldRowUEaggregateMaximumBitrate(v *InitialContextSetupRequestIEValue) **s36.UEAggregateMaximumBitrate {
	return &v.rowUEaggregateMaximumBitrate
}
func BridgeInitialContextSetupRequestIEValueFieldRowV2XServicesAuthorized(v *InitialContextSetupRequestIEValue) **s47.V2XServicesAuthorized {
	return &v.rowV2XServicesAuthorized
}
func BridgeInitialContextSetupRequestIEValueMethodCaptureSemantics(v InitialContextSetupRequestIEValue, a0 aper.SemanticCapture) InitialContextSetupRequestIEValue {
	return v.captureSemantics(a0)
}
func BridgeInitialContextSetupRequestIEValueMethodCompareSemantics(v InitialContextSetupRequestIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeInitialContextSetupRequestIEValueMethodDecode(v InitialContextSetupRequestIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (InitialContextSetupRequestIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeInitialContextSetupRequestIEValueMethodEncode(v InitialContextSetupRequestIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeInitialContextSetupRequestIEValueMethodEncodeFresh(v InitialContextSetupRequestIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeInitialContextSetupRequestIEValueMethodMatchesID(v InitialContextSetupRequestIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeInitialContextSetupRequestIEValueMethodReason(v InitialContextSetupRequestIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeInitialContextSetupRequestIEValueMethodRule(v InitialContextSetupRequestIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeInitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *InitialContextSetupRequestIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *InitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodec) *func(InitialContextSetupRequestIEValueProtocolErrorIEContainerList, aper.DecodeState) (InitialContextSetupRequestIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *InitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodec) *func(InitialContextSetupRequestIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *InitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *InitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (InitialContextSetupRequestIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeInitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *InitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodec) *func(InitialContextSetupRequestIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *InitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v InitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodec, a0 InitialContextSetupRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v InitialContextSetupRequestIEValueProtocolErrorIEContainerListValueCodec, a0 InitialContextSetupRequestIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialContextSetupRequestIEValueProtocolIEContainerListAPERValueFieldContext(v *InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupRequestIEValueProtocolIEContainerListAPERValueFieldReceived(v *InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeInitialContextSetupRequestIEValueProtocolIEContainerListAPERValueFieldReplay(v *InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeInitialContextSetupRequestIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *InitialContextSetupRequestIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeInitialContextSetupRequestIEValueProtocolIEContainerListValueCodecFieldCapture(v *InitialContextSetupRequestIEValueProtocolIEContainerListValueCodec) *func(InitialContextSetupRequestIEValueProtocolIEContainerList, aper.DecodeState) (InitialContextSetupRequestIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupRequestIEValueProtocolIEContainerListValueCodecFieldCompare(v *InitialContextSetupRequestIEValueProtocolIEContainerListValueCodec) *func(InitialContextSetupRequestIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupRequestIEValueProtocolIEContainerListValueCodecFieldContext(v *InitialContextSetupRequestIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupRequestIEValueProtocolIEContainerListValueCodecFieldDecode(v *InitialContextSetupRequestIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (InitialContextSetupRequestIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeInitialContextSetupRequestIEValueProtocolIEContainerListValueCodecFieldEncode(v *InitialContextSetupRequestIEValueProtocolIEContainerListValueCodec) *func(InitialContextSetupRequestIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupRequestIEValueProtocolIEContainerListValueCodecFieldPath(v *InitialContextSetupRequestIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialContextSetupRequestIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v InitialContextSetupRequestIEValueProtocolIEContainerListValueCodec, a0 InitialContextSetupRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialContextSetupRequestIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v InitialContextSetupRequestIEValueProtocolIEContainerListValueCodec, a0 InitialContextSetupRequestIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeInitialContextSetupRequestLAIIEBindingFieldCodec(v *InitialContextSetupRequestLAIIEBinding) *s18.LAIValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestLAIIEBindingFieldGet(v *InitialContextSetupRequestLAIIEBinding) *func(*InitialContextSetupRequestIEValue) (*s18.LAI, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestLAIIEBindingFieldInfo(v *InitialContextSetupRequestLAIIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestLAIIEBindingFieldInject(v *InitialContextSetupRequestLAIIEBinding) *func(s18.LAI) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestMDTPLMNListIEBindingFieldCodec(v *InitialContextSetupRequestMDTPLMNListIEBinding) *s01.MDTPLMNListValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestMDTPLMNListIEBindingFieldGet(v *InitialContextSetupRequestMDTPLMNListIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.MDTPLMNList, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestMDTPLMNListIEBindingFieldInfo(v *InitialContextSetupRequestMDTPLMNListIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestMDTPLMNListIEBindingFieldInject(v *InitialContextSetupRequestMDTPLMNListIEBinding) *func(s00.MDTPLMNList) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestMMEUES1APIDIEBindingFieldCodec(v *InitialContextSetupRequestMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestMMEUES1APIDIEBindingFieldGet(v *InitialContextSetupRequestMMEUES1APIDIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestMMEUES1APIDIEBindingFieldInfo(v *InitialContextSetupRequestMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestMMEUES1APIDIEBindingFieldInject(v *InitialContextSetupRequestMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestManagementBasedMDTAllowedIEBindingFieldCodec(v *InitialContextSetupRequestManagementBasedMDTAllowedIEBinding) *s01.ManagementBasedMDTAllowedValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestManagementBasedMDTAllowedIEBindingFieldGet(v *InitialContextSetupRequestManagementBasedMDTAllowedIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.ManagementBasedMDTAllowed, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestManagementBasedMDTAllowedIEBindingFieldInfo(v *InitialContextSetupRequestManagementBasedMDTAllowedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestManagementBasedMDTAllowedIEBindingFieldInject(v *InitialContextSetupRequestManagementBasedMDTAllowedIEBinding) *func(s00.ManagementBasedMDTAllowed) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestMaskedIMEISVIEBindingFieldCodec(v *InitialContextSetupRequestMaskedIMEISVIEBinding) *s01.MaskedIMEISVValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestMaskedIMEISVIEBindingFieldGet(v *InitialContextSetupRequestMaskedIMEISVIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.MaskedIMEISV, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestMaskedIMEISVIEBindingFieldInfo(v *InitialContextSetupRequestMaskedIMEISVIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestMaskedIMEISVIEBindingFieldInject(v *InitialContextSetupRequestMaskedIMEISVIEBinding) *func(s00.MaskedIMEISV) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestMethodMarshalAPERBudget(v *InitialContextSetupRequest, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeInitialContextSetupRequestMethodMarshalAPERBudgetValue(v *InitialContextSetupRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeInitialContextSetupRequestMethodMarshalAPERChanged(v *InitialContextSetupRequest, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeInitialContextSetupRequestMethodMarshalAPERChangedValue(v *InitialContextSetupRequest, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeInitialContextSetupRequestMethodMarshalAPERLegacy(v *InitialContextSetupRequest) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeInitialContextSetupRequestMethodMarshalAPERNewValue(v *InitialContextSetupRequest, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeInitialContextSetupRequestMethodMarshalAPERPlanned(v *InitialContextSetupRequest, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeInitialContextSetupRequestMethodMarshalAPERTo(v *InitialContextSetupRequest, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeInitialContextSetupRequestMethodUnmarshalAPERFrom(v *InitialContextSetupRequest, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeInitialContextSetupRequestMethodUnmarshalAPERLegacy(v *InitialContextSetupRequest, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeInitialContextSetupRequestMethodUnmarshalAPERWithOptions(v *InitialContextSetupRequest, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeInitialContextSetupRequestNRUESecurityCapabilitiesIEBindingFieldCodec(v *InitialContextSetupRequestNRUESecurityCapabilitiesIEBinding) *s19.NRUESecurityCapabilitiesValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestNRUESecurityCapabilitiesIEBindingFieldGet(v *InitialContextSetupRequestNRUESecurityCapabilitiesIEBinding) *func(*InitialContextSetupRequestIEValue) (*s19.NRUESecurityCapabilities, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestNRUESecurityCapabilitiesIEBindingFieldInfo(v *InitialContextSetupRequestNRUESecurityCapabilitiesIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestNRUESecurityCapabilitiesIEBindingFieldInject(v *InitialContextSetupRequestNRUESecurityCapabilitiesIEBinding) *func(s19.NRUESecurityCapabilities) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldCodec(v *InitialContextSetupRequestNRUESidelinkAggregateMaximumBitrateIEBinding) *s20.NRUESidelinkAggregateMaximumBitrateValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldGet(v *InitialContextSetupRequestNRUESidelinkAggregateMaximumBitrateIEBinding) *func(*InitialContextSetupRequestIEValue) (*s20.NRUESidelinkAggregateMaximumBitrate, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldInfo(v *InitialContextSetupRequestNRUESidelinkAggregateMaximumBitrateIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestNRUESidelinkAggregateMaximumBitrateIEBindingFieldInject(v *InitialContextSetupRequestNRUESidelinkAggregateMaximumBitrateIEBinding) *func(s20.NRUESidelinkAggregateMaximumBitrate) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestNRV2XServicesAuthorizedIEBindingFieldCodec(v *InitialContextSetupRequestNRV2XServicesAuthorizedIEBinding) *s20.NRV2XServicesAuthorizedValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestNRV2XServicesAuthorizedIEBindingFieldGet(v *InitialContextSetupRequestNRV2XServicesAuthorizedIEBinding) *func(*InitialContextSetupRequestIEValue) (*s20.NRV2XServicesAuthorized, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestNRV2XServicesAuthorizedIEBindingFieldInfo(v *InitialContextSetupRequestNRV2XServicesAuthorizedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestNRV2XServicesAuthorizedIEBindingFieldInject(v *InitialContextSetupRequestNRV2XServicesAuthorizedIEBinding) *func(s20.NRV2XServicesAuthorized) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestPC5QoSParametersIEBindingFieldCodec(v *InitialContextSetupRequestPC5QoSParametersIEBinding) *s24.PC5QoSParametersValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestPC5QoSParametersIEBindingFieldGet(v *InitialContextSetupRequestPC5QoSParametersIEBinding) *func(*InitialContextSetupRequestIEValue) (*s24.PC5QoSParameters, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestPC5QoSParametersIEBindingFieldInfo(v *InitialContextSetupRequestPC5QoSParametersIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestPC5QoSParametersIEBindingFieldInject(v *InitialContextSetupRequestPC5QoSParametersIEBinding) *func(s24.PC5QoSParameters) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestPendingDataIndicationIEBindingFieldCodec(v *InitialContextSetupRequestPendingDataIndicationIEBinding) *s01.PendingDataIndicationValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestPendingDataIndicationIEBindingFieldGet(v *InitialContextSetupRequestPendingDataIndicationIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.PendingDataIndication, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestPendingDataIndicationIEBindingFieldInfo(v *InitialContextSetupRequestPendingDataIndicationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestPendingDataIndicationIEBindingFieldInject(v *InitialContextSetupRequestPendingDataIndicationIEBinding) *func(s00.PendingDataIndication) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestProSeAuthorizedIEBindingFieldCodec(v *InitialContextSetupRequestProSeAuthorizedIEBinding) *s20.ProSeAuthorizedValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestProSeAuthorizedIEBindingFieldGet(v *InitialContextSetupRequestProSeAuthorizedIEBinding) *func(*InitialContextSetupRequestIEValue) (*s20.ProSeAuthorized, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestProSeAuthorizedIEBindingFieldInfo(v *InitialContextSetupRequestProSeAuthorizedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestProSeAuthorizedIEBindingFieldInject(v *InitialContextSetupRequestProSeAuthorizedIEBinding) *func(s20.ProSeAuthorized) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestSRVCCOperationPossibleIEBindingFieldCodec(v *InitialContextSetupRequestSRVCCOperationPossibleIEBinding) *s01.SRVCCOperationPossibleValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestSRVCCOperationPossibleIEBindingFieldGet(v *InitialContextSetupRequestSRVCCOperationPossibleIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.SRVCCOperationPossible, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestSRVCCOperationPossibleIEBindingFieldInfo(v *InitialContextSetupRequestSRVCCOperationPossibleIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestSRVCCOperationPossibleIEBindingFieldInject(v *InitialContextSetupRequestSRVCCOperationPossibleIEBinding) *func(s00.SRVCCOperationPossible) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestSecurityKeyIEBindingFieldCodec(v *InitialContextSetupRequestSecurityKeyIEBinding) *s01.SecurityKeyValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestSecurityKeyIEBindingFieldGet(v *InitialContextSetupRequestSecurityKeyIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.SecurityKey, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestSecurityKeyIEBindingFieldInfo(v *InitialContextSetupRequestSecurityKeyIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestSecurityKeyIEBindingFieldInject(v *InitialContextSetupRequestSecurityKeyIEBinding) *func(s00.SecurityKey) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestSubscriberProfileIDforRFPIEBindingFieldCodec(v *InitialContextSetupRequestSubscriberProfileIDforRFPIEBinding) *s01.SubscriberProfileIDforRFPValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestSubscriberProfileIDforRFPIEBindingFieldGet(v *InitialContextSetupRequestSubscriberProfileIDforRFPIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.SubscriberProfileIDforRFP, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestSubscriberProfileIDforRFPIEBindingFieldInfo(v *InitialContextSetupRequestSubscriberProfileIDforRFPIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestSubscriberProfileIDforRFPIEBindingFieldInject(v *InitialContextSetupRequestSubscriberProfileIDforRFPIEBinding) *func(s00.SubscriberProfileIDforRFP) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestSubscriptionBasedUEDifferentiationInfoIEBindingFieldCodec(v *InitialContextSetupRequestSubscriptionBasedUEDifferentiationInfoIEBinding) *s31.SubscriptionBasedUEDifferentiationInfoValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestSubscriptionBasedUEDifferentiationInfoIEBindingFieldGet(v *InitialContextSetupRequestSubscriptionBasedUEDifferentiationInfoIEBinding) *func(*InitialContextSetupRequestIEValue) (*s31.SubscriptionBasedUEDifferentiationInfo, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestSubscriptionBasedUEDifferentiationInfoIEBindingFieldInfo(v *InitialContextSetupRequestSubscriptionBasedUEDifferentiationInfoIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestSubscriptionBasedUEDifferentiationInfoIEBindingFieldInject(v *InitialContextSetupRequestSubscriptionBasedUEDifferentiationInfoIEBinding) *func(s31.SubscriptionBasedUEDifferentiationInfo) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestTimeRefDistributionIEBindingFieldCodec(v *InitialContextSetupRequestTimeRefDistributionIEBinding) *s02.TimeRefDistributionValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestTimeRefDistributionIEBindingFieldGet(v *InitialContextSetupRequestTimeRefDistributionIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.TimeRefDistribution, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestTimeRefDistributionIEBindingFieldInfo(v *InitialContextSetupRequestTimeRefDistributionIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestTimeRefDistributionIEBindingFieldInject(v *InitialContextSetupRequestTimeRefDistributionIEBinding) *func(s00.TimeRefDistribution) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestTraceActivationIEBindingFieldCodec(v *InitialContextSetupRequestTraceActivationIEBinding) *TraceActivationValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestTraceActivationIEBindingFieldGet(v *InitialContextSetupRequestTraceActivationIEBinding) *func(*InitialContextSetupRequestIEValue) (*s48.TraceActivation, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestTraceActivationIEBindingFieldInfo(v *InitialContextSetupRequestTraceActivationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestTraceActivationIEBindingFieldInject(v *InitialContextSetupRequestTraceActivationIEBinding) *func(s48.TraceActivation) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestUEAggregateMaximumBitrateIEBindingFieldCodec(v *InitialContextSetupRequestUEAggregateMaximumBitrateIEBinding) *s36.UEAggregateMaximumBitrateValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestUEAggregateMaximumBitrateIEBindingFieldGet(v *InitialContextSetupRequestUEAggregateMaximumBitrateIEBinding) *func(*InitialContextSetupRequestIEValue) (*s36.UEAggregateMaximumBitrate, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestUEAggregateMaximumBitrateIEBindingFieldInfo(v *InitialContextSetupRequestUEAggregateMaximumBitrateIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestUEAggregateMaximumBitrateIEBindingFieldInject(v *InitialContextSetupRequestUEAggregateMaximumBitrateIEBinding) *func(s36.UEAggregateMaximumBitrate) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestUERadioCapabilityIDIEBindingFieldCodec(v *InitialContextSetupRequestUERadioCapabilityIDIEBinding) *s02.UERadioCapabilityIDValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestUERadioCapabilityIDIEBindingFieldGet(v *InitialContextSetupRequestUERadioCapabilityIDIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.UERadioCapabilityID, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestUERadioCapabilityIDIEBindingFieldInfo(v *InitialContextSetupRequestUERadioCapabilityIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestUERadioCapabilityIDIEBindingFieldInject(v *InitialContextSetupRequestUERadioCapabilityIDIEBinding) *func(s00.UERadioCapabilityID) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestUERadioCapabilityIEBindingFieldCodec(v *InitialContextSetupRequestUERadioCapabilityIEBinding) *s02.UERadioCapabilityValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestUERadioCapabilityIEBindingFieldGet(v *InitialContextSetupRequestUERadioCapabilityIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.UERadioCapability, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestUERadioCapabilityIEBindingFieldInfo(v *InitialContextSetupRequestUERadioCapabilityIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestUERadioCapabilityIEBindingFieldInject(v *InitialContextSetupRequestUERadioCapabilityIEBinding) *func(s00.UERadioCapability) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestUESecurityCapabilitiesIEBindingFieldCodec(v *InitialContextSetupRequestUESecurityCapabilitiesIEBinding) *s37.UESecurityCapabilitiesValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestUESecurityCapabilitiesIEBindingFieldGet(v *InitialContextSetupRequestUESecurityCapabilitiesIEBinding) *func(*InitialContextSetupRequestIEValue) (*s37.UESecurityCapabilities, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestUESecurityCapabilitiesIEBindingFieldInfo(v *InitialContextSetupRequestUESecurityCapabilitiesIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestUESecurityCapabilitiesIEBindingFieldInject(v *InitialContextSetupRequestUESecurityCapabilitiesIEBinding) *func(s37.UESecurityCapabilities) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestUESidelinkAggregateMaximumBitrateIEBindingFieldCodec(v *InitialContextSetupRequestUESidelinkAggregateMaximumBitrateIEBinding) *s38.UESidelinkAggregateMaximumBitrateValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestUESidelinkAggregateMaximumBitrateIEBindingFieldGet(v *InitialContextSetupRequestUESidelinkAggregateMaximumBitrateIEBinding) *func(*InitialContextSetupRequestIEValue) (*s38.UESidelinkAggregateMaximumBitrate, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestUESidelinkAggregateMaximumBitrateIEBindingFieldInfo(v *InitialContextSetupRequestUESidelinkAggregateMaximumBitrateIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestUESidelinkAggregateMaximumBitrateIEBindingFieldInject(v *InitialContextSetupRequestUESidelinkAggregateMaximumBitrateIEBinding) *func(s38.UESidelinkAggregateMaximumBitrate) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestUEUserPlaneCIoTSupportIndicatorIEBindingFieldCodec(v *InitialContextSetupRequestUEUserPlaneCIoTSupportIndicatorIEBinding) *s02.UEUserPlaneCIoTSupportIndicatorValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestUEUserPlaneCIoTSupportIndicatorIEBindingFieldGet(v *InitialContextSetupRequestUEUserPlaneCIoTSupportIndicatorIEBinding) *func(*InitialContextSetupRequestIEValue) (*s00.UEUserPlaneCIoTSupportIndicator, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestUEUserPlaneCIoTSupportIndicatorIEBindingFieldInfo(v *InitialContextSetupRequestUEUserPlaneCIoTSupportIndicatorIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestUEUserPlaneCIoTSupportIndicatorIEBindingFieldInject(v *InitialContextSetupRequestUEUserPlaneCIoTSupportIndicatorIEBinding) *func(s00.UEUserPlaneCIoTSupportIndicator) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestV2XServicesAuthorizedIEBindingFieldCodec(v *InitialContextSetupRequestV2XServicesAuthorizedIEBinding) *s47.V2XServicesAuthorizedValueCodec {
	return &v.codec
}
func BridgeInitialContextSetupRequestV2XServicesAuthorizedIEBindingFieldGet(v *InitialContextSetupRequestV2XServicesAuthorizedIEBinding) *func(*InitialContextSetupRequestIEValue) (*s47.V2XServicesAuthorized, bool) {
	return &v.get
}
func BridgeInitialContextSetupRequestV2XServicesAuthorizedIEBindingFieldInfo(v *InitialContextSetupRequestV2XServicesAuthorizedIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeInitialContextSetupRequestV2XServicesAuthorizedIEBindingFieldInject(v *InitialContextSetupRequestV2XServicesAuthorizedIEBinding) *func(s47.V2XServicesAuthorized) InitialContextSetupRequestIEValue {
	return &v.inject
}
func BridgeInitialContextSetupRequestValueCodecFieldCapture(v *InitialContextSetupRequestValueCodec) *func(InitialContextSetupRequest, aper.DecodeState) (InitialContextSetupRequest, aper.Snapshot) {
	return &v.capture
}
func BridgeInitialContextSetupRequestValueCodecFieldCompare(v *InitialContextSetupRequestValueCodec) *func(InitialContextSetupRequest, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeInitialContextSetupRequestValueCodecFieldContext(v *InitialContextSetupRequestValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeInitialContextSetupRequestValueCodecFieldDecode(v *InitialContextSetupRequestValueCodec) *func([]byte, aper.DecodeState) (InitialContextSetupRequest, error) {
	return &v.decode
}
func BridgeInitialContextSetupRequestValueCodecFieldEncode(v *InitialContextSetupRequestValueCodec) *func(InitialContextSetupRequest, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeInitialContextSetupRequestValueCodecFieldPath(v *InitialContextSetupRequestValueCodec) *aper.Path {
	return &v.path
}
func BridgeInitialContextSetupRequestValueCodecMethodEncodeBudgetValue(v InitialContextSetupRequestValueCodec, a0 InitialContextSetupRequest, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeInitialContextSetupRequestValueCodecMethodEncodeChanged(v InitialContextSetupRequestValueCodec, a0 InitialContextSetupRequest, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTraceActivationAPERValueFieldContext(v *TraceActivationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceActivationAPERValueFieldReceived(v *TraceActivationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTraceActivationAPERValueFieldReplay(v *TraceActivationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTraceActivationAPERValueFieldWithoutReplay(v *TraceActivationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTraceActivationValueCodecFieldCapture(v *TraceActivationValueCodec) *func(s48.TraceActivation, aper.DecodeState) (s48.TraceActivation, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceActivationValueCodecFieldCompare(v *TraceActivationValueCodec) *func(s48.TraceActivation, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceActivationValueCodecFieldContext(v *TraceActivationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceActivationValueCodecFieldDecode(v *TraceActivationValueCodec) *func([]byte, aper.DecodeState) (s48.TraceActivation, error) {
	return &v.decode
}
func BridgeTraceActivationValueCodecFieldEncode(v *TraceActivationValueCodec) *func(s48.TraceActivation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceActivationValueCodecFieldPath(v *TraceActivationValueCodec) *aper.Path {
	return &v.path
}
func BridgeTraceActivationValueCodecMethodEncodeBudgetValue(v TraceActivationValueCodec, a0 s48.TraceActivation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTraceActivationValueCodecMethodEncodeChanged(v TraceActivationValueCodec, a0 s48.TraceActivation, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTraceStartAPERValueFieldContext(v *TraceStartAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceStartAPERValueFieldReceived(v *TraceStartAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTraceStartAPERValueFieldReplay(v *TraceStartAPERValue) *aper.Snapshot { return &v.replay }
func BridgeTraceStartAPERValueFieldWithoutReplay(v *TraceStartAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTraceStartENBUES1APIDIEBindingFieldCodec(v *TraceStartENBUES1APIDIEBinding) *s00.ENBUES1APIDValueCodec {
	return &v.codec
}
func BridgeTraceStartENBUES1APIDIEBindingFieldGet(v *TraceStartENBUES1APIDIEBinding) *func(*TraceStartIEValue) (*s00.ENBUES1APID, bool) {
	return &v.get
}
func BridgeTraceStartENBUES1APIDIEBindingFieldInfo(v *TraceStartENBUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeTraceStartENBUES1APIDIEBindingFieldInject(v *TraceStartENBUES1APIDIEBinding) *func(s00.ENBUES1APID) TraceStartIEValue {
	return &v.inject
}
func BridgeTraceStartFieldExtCount(v *TraceStart) *int64                { return &v.extCount }
func BridgeTraceStartFieldExtData(v *TraceStart) *[][]byte              { return &v.extData }
func BridgeTraceStartFieldExtOrigin(v *TraceStart) *[]aper.OpaqueOrigin { return &v.extOrigin }
func BridgeTraceStartFieldExtPresent(v *TraceStart) *[]bool             { return &v.extPresent }
func BridgeTraceStartFieldExtWire(v *TraceStart) *[]aper.WireSpan       { return &v.extWire }
func BridgeTraceStartFieldPerExtPadding(v *TraceStart) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeTraceStartFieldPerPadding(v *TraceStart) *aper.FinalPadding   { return &v.perPadding }
func BridgeTraceStartFieldProtocolIEsIndef(v *TraceStart) *bool          { return &v.protocolIEsIndef }
func BridgeTraceStartFieldReceived(v *TraceStart) *bool                  { return &v.received }
func BridgeTraceStartFieldReceivedAbsolute(v *TraceStart) *bool          { return &v.receivedAbsolute }
func BridgeTraceStartFieldReceivedBytes(v *TraceStart) *aper.WireSpan    { return &v.receivedBytes }
func BridgeTraceStartFieldReceivedLocation(v *TraceStart) *aper.Location { return &v.receivedLocation }
func BridgeTraceStartFieldReplay(v *TraceStart) *aper.Snapshot           { return &v.replay }
func BridgeTraceStartFieldStream(v *TraceStart) *aper.WireSpan           { return &v.stream }
func BridgeTraceStartFieldWithoutReplay(v *TraceStart) *bool             { return &v.withoutReplay }
func BridgeTraceStartIEContainerAPERValueFieldContext(v *TraceStartIEContainerAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceStartIEContainerAPERValueFieldReceived(v *TraceStartIEContainerAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTraceStartIEContainerAPERValueFieldReplay(v *TraceStartIEContainerAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTraceStartIEContainerAPERValueFieldWithoutReplay(v *TraceStartIEContainerAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTraceStartIEContainerValueCodecFieldCapture(v *TraceStartIEContainerValueCodec) *func(TraceStartIEContainer, aper.DecodeState) (TraceStartIEContainer, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceStartIEContainerValueCodecFieldCompare(v *TraceStartIEContainerValueCodec) *func(TraceStartIEContainer, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceStartIEContainerValueCodecFieldContext(v *TraceStartIEContainerValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceStartIEContainerValueCodecFieldDecode(v *TraceStartIEContainerValueCodec) *func([]byte, aper.DecodeState) (TraceStartIEContainer, error) {
	return &v.decode
}
func BridgeTraceStartIEContainerValueCodecFieldEncode(v *TraceStartIEContainerValueCodec) *func(TraceStartIEContainer, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceStartIEContainerValueCodecFieldPath(v *TraceStartIEContainerValueCodec) *aper.Path {
	return &v.path
}
func BridgeTraceStartIEContainerValueCodecMethodEncodeBudgetValue(v TraceStartIEContainerValueCodec, a0 TraceStartIEContainer, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTraceStartIEContainerValueCodecMethodEncodeChanged(v TraceStartIEContainerValueCodec, a0 TraceStartIEContainer, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTraceStartIEFieldAPERValueFieldContext(v *TraceStartIEFieldAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceStartIEFieldAPERValueFieldReceived(v *TraceStartIEFieldAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTraceStartIEFieldAPERValueFieldReplay(v *TraceStartIEFieldAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTraceStartIEFieldAPERValueFieldWithoutReplay(v *TraceStartIEFieldAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTraceStartIEFieldFieldReceived(v *TraceStartIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeTraceStartIEFieldFieldReplay(v *TraceStartIEField) *aper.Snapshot { return &v.replay }
func BridgeTraceStartIEFieldFieldStream(v *TraceStartIEField) *aper.WireSpan { return &v.stream }
func BridgeTraceStartIEFieldFieldWithoutReplay(v *TraceStartIEField) *bool   { return &v.withoutReplay }
func BridgeTraceStartIEFieldMethodMarshalAPERTo(v *TraceStartIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTraceStartIEFieldMethodUnmarshalAPERFrom(v *TraceStartIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTraceStartIEFieldValueCodecFieldCapture(v *TraceStartIEFieldValueCodec) *func(TraceStartIEField, aper.DecodeState) (TraceStartIEField, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceStartIEFieldValueCodecFieldCompare(v *TraceStartIEFieldValueCodec) *func(TraceStartIEField, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceStartIEFieldValueCodecFieldContext(v *TraceStartIEFieldValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceStartIEFieldValueCodecFieldDecode(v *TraceStartIEFieldValueCodec) *func([]byte, aper.DecodeState) (TraceStartIEField, error) {
	return &v.decode
}
func BridgeTraceStartIEFieldValueCodecFieldEncode(v *TraceStartIEFieldValueCodec) *func(TraceStartIEField, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceStartIEFieldValueCodecFieldPath(v *TraceStartIEFieldValueCodec) *aper.Path {
	return &v.path
}
func BridgeTraceStartIEFieldValueCodecMethodEncodeBudgetValue(v TraceStartIEFieldValueCodec, a0 TraceStartIEField, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTraceStartIEFieldValueCodecMethodEncodeChanged(v TraceStartIEFieldValueCodec, a0 TraceStartIEField, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTraceStartIETableMethodInfoENBUES1APID(v TraceStartIETable) s00.FieldInfo {
	return v.infoENBUES1APID()
}
func BridgeTraceStartIETableMethodInfoMMEUES1APID(v TraceStartIETable) s00.FieldInfo {
	return v.infoMMEUES1APID()
}
func BridgeTraceStartIETableMethodInfoTraceActivation(v TraceStartIETable) s00.FieldInfo {
	return v.infoTraceActivation()
}
func BridgeTraceStartIEValueERABIEContainerListAPERValueFieldContext(v *TraceStartIEValueERABIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceStartIEValueERABIEContainerListAPERValueFieldReceived(v *TraceStartIEValueERABIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTraceStartIEValueERABIEContainerListAPERValueFieldReplay(v *TraceStartIEValueERABIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTraceStartIEValueERABIEContainerListAPERValueFieldWithoutReplay(v *TraceStartIEValueERABIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTraceStartIEValueERABIEContainerListValueCodecFieldCapture(v *TraceStartIEValueERABIEContainerListValueCodec) *func(TraceStartIEValueERABIEContainerList, aper.DecodeState) (TraceStartIEValueERABIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceStartIEValueERABIEContainerListValueCodecFieldCompare(v *TraceStartIEValueERABIEContainerListValueCodec) *func(TraceStartIEValueERABIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceStartIEValueERABIEContainerListValueCodecFieldContext(v *TraceStartIEValueERABIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceStartIEValueERABIEContainerListValueCodecFieldDecode(v *TraceStartIEValueERABIEContainerListValueCodec) *func([]byte, aper.DecodeState) (TraceStartIEValueERABIEContainerList, error) {
	return &v.decode
}
func BridgeTraceStartIEValueERABIEContainerListValueCodecFieldEncode(v *TraceStartIEValueERABIEContainerListValueCodec) *func(TraceStartIEValueERABIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceStartIEValueERABIEContainerListValueCodecFieldPath(v *TraceStartIEValueERABIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeTraceStartIEValueERABIEContainerListValueCodecMethodEncodeBudgetValue(v TraceStartIEValueERABIEContainerListValueCodec, a0 TraceStartIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTraceStartIEValueERABIEContainerListValueCodecMethodEncodeChanged(v TraceStartIEValueERABIEContainerListValueCodec, a0 TraceStartIEValueERABIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTraceStartIEValueFieldId(v *TraceStartIEValue) *s00.ProtocolIEID        { return &v.id }
func BridgeTraceStartIEValueFieldIsOpaque(v *TraceStartIEValue) *bool              { return &v.isOpaque }
func BridgeTraceStartIEValueFieldOpaque(v *TraceStartIEValue) *aper.OpaqueOpenType { return &v.opaque }
func BridgeTraceStartIEValueFieldReceived(v *TraceStartIEValue) *aper.WireSpan     { return &v.received }
func BridgeTraceStartIEValueFieldReplay(v *TraceStartIEValue) *aper.Snapshot       { return &v.replay }
func BridgeTraceStartIEValueFieldRowENBUES1APID(v *TraceStartIEValue) **s00.ENBUES1APID {
	return &v.rowENBUES1APID
}
func BridgeTraceStartIEValueFieldRowMMEUES1APID(v *TraceStartIEValue) **s00.MMEUES1APID {
	return &v.rowMMEUES1APID
}
func BridgeTraceStartIEValueFieldRowTraceActivation(v *TraceStartIEValue) **s48.TraceActivation {
	return &v.rowTraceActivation
}
func BridgeTraceStartIEValueMethodCaptureSemantics(v TraceStartIEValue, a0 aper.SemanticCapture) TraceStartIEValue {
	return v.captureSemantics(a0)
}
func BridgeTraceStartIEValueMethodCompareSemantics(v TraceStartIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeTraceStartIEValueMethodDecode(v TraceStartIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (TraceStartIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeTraceStartIEValueMethodEncode(v TraceStartIEValue) ([]byte, error) { return v.encode() }
func BridgeTraceStartIEValueMethodEncodeFresh(v TraceStartIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeTraceStartIEValueMethodMatchesID(v TraceStartIEValue, a0 s00.ProtocolIEID, a1 ...*aper.DecodeBudget) bool {
	return v.matchesID(a0, a1...)
}
func BridgeTraceStartIEValueMethodReason(v TraceStartIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeTraceStartIEValueMethodRule(v TraceStartIEValue) aper.SourceRule { return v.rule() }
func BridgeTraceStartIEValueProtocolErrorIEContainerListAPERValueFieldContext(v *TraceStartIEValueProtocolErrorIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceStartIEValueProtocolErrorIEContainerListAPERValueFieldReceived(v *TraceStartIEValueProtocolErrorIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTraceStartIEValueProtocolErrorIEContainerListAPERValueFieldReplay(v *TraceStartIEValueProtocolErrorIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTraceStartIEValueProtocolErrorIEContainerListAPERValueFieldWithoutReplay(v *TraceStartIEValueProtocolErrorIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTraceStartIEValueProtocolErrorIEContainerListValueCodecFieldCapture(v *TraceStartIEValueProtocolErrorIEContainerListValueCodec) *func(TraceStartIEValueProtocolErrorIEContainerList, aper.DecodeState) (TraceStartIEValueProtocolErrorIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceStartIEValueProtocolErrorIEContainerListValueCodecFieldCompare(v *TraceStartIEValueProtocolErrorIEContainerListValueCodec) *func(TraceStartIEValueProtocolErrorIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceStartIEValueProtocolErrorIEContainerListValueCodecFieldContext(v *TraceStartIEValueProtocolErrorIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceStartIEValueProtocolErrorIEContainerListValueCodecFieldDecode(v *TraceStartIEValueProtocolErrorIEContainerListValueCodec) *func([]byte, aper.DecodeState) (TraceStartIEValueProtocolErrorIEContainerList, error) {
	return &v.decode
}
func BridgeTraceStartIEValueProtocolErrorIEContainerListValueCodecFieldEncode(v *TraceStartIEValueProtocolErrorIEContainerListValueCodec) *func(TraceStartIEValueProtocolErrorIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceStartIEValueProtocolErrorIEContainerListValueCodecFieldPath(v *TraceStartIEValueProtocolErrorIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeTraceStartIEValueProtocolErrorIEContainerListValueCodecMethodEncodeBudgetValue(v TraceStartIEValueProtocolErrorIEContainerListValueCodec, a0 TraceStartIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTraceStartIEValueProtocolErrorIEContainerListValueCodecMethodEncodeChanged(v TraceStartIEValueProtocolErrorIEContainerListValueCodec, a0 TraceStartIEValueProtocolErrorIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTraceStartIEValueProtocolIEContainerListAPERValueFieldContext(v *TraceStartIEValueProtocolIEContainerListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceStartIEValueProtocolIEContainerListAPERValueFieldReceived(v *TraceStartIEValueProtocolIEContainerListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeTraceStartIEValueProtocolIEContainerListAPERValueFieldReplay(v *TraceStartIEValueProtocolIEContainerListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeTraceStartIEValueProtocolIEContainerListAPERValueFieldWithoutReplay(v *TraceStartIEValueProtocolIEContainerListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeTraceStartIEValueProtocolIEContainerListValueCodecFieldCapture(v *TraceStartIEValueProtocolIEContainerListValueCodec) *func(TraceStartIEValueProtocolIEContainerList, aper.DecodeState) (TraceStartIEValueProtocolIEContainerList, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceStartIEValueProtocolIEContainerListValueCodecFieldCompare(v *TraceStartIEValueProtocolIEContainerListValueCodec) *func(TraceStartIEValueProtocolIEContainerList, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceStartIEValueProtocolIEContainerListValueCodecFieldContext(v *TraceStartIEValueProtocolIEContainerListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceStartIEValueProtocolIEContainerListValueCodecFieldDecode(v *TraceStartIEValueProtocolIEContainerListValueCodec) *func([]byte, aper.DecodeState) (TraceStartIEValueProtocolIEContainerList, error) {
	return &v.decode
}
func BridgeTraceStartIEValueProtocolIEContainerListValueCodecFieldEncode(v *TraceStartIEValueProtocolIEContainerListValueCodec) *func(TraceStartIEValueProtocolIEContainerList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceStartIEValueProtocolIEContainerListValueCodecFieldPath(v *TraceStartIEValueProtocolIEContainerListValueCodec) *aper.Path {
	return &v.path
}
func BridgeTraceStartIEValueProtocolIEContainerListValueCodecMethodEncodeBudgetValue(v TraceStartIEValueProtocolIEContainerListValueCodec, a0 TraceStartIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTraceStartIEValueProtocolIEContainerListValueCodecMethodEncodeChanged(v TraceStartIEValueProtocolIEContainerListValueCodec, a0 TraceStartIEValueProtocolIEContainerList, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeTraceStartMMEUES1APIDIEBindingFieldCodec(v *TraceStartMMEUES1APIDIEBinding) *s01.MMEUES1APIDValueCodec {
	return &v.codec
}
func BridgeTraceStartMMEUES1APIDIEBindingFieldGet(v *TraceStartMMEUES1APIDIEBinding) *func(*TraceStartIEValue) (*s00.MMEUES1APID, bool) {
	return &v.get
}
func BridgeTraceStartMMEUES1APIDIEBindingFieldInfo(v *TraceStartMMEUES1APIDIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeTraceStartMMEUES1APIDIEBindingFieldInject(v *TraceStartMMEUES1APIDIEBinding) *func(s00.MMEUES1APID) TraceStartIEValue {
	return &v.inject
}
func BridgeTraceStartMethodMarshalAPERBudget(v *TraceStart, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeTraceStartMethodMarshalAPERBudgetValue(v *TraceStart, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeTraceStartMethodMarshalAPERChanged(v *TraceStart, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeTraceStartMethodMarshalAPERChangedValue(v *TraceStart, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeTraceStartMethodMarshalAPERLegacy(v *TraceStart) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeTraceStartMethodMarshalAPERNewValue(v *TraceStart, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeTraceStartMethodMarshalAPERPlanned(v *TraceStart, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeTraceStartMethodMarshalAPERTo(v *TraceStart, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeTraceStartMethodUnmarshalAPERFrom(v *TraceStart, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeTraceStartMethodUnmarshalAPERLegacy(v *TraceStart, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeTraceStartMethodUnmarshalAPERWithOptions(v *TraceStart, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeTraceStartTraceActivationIEBindingFieldCodec(v *TraceStartTraceActivationIEBinding) *TraceActivationValueCodec {
	return &v.codec
}
func BridgeTraceStartTraceActivationIEBindingFieldGet(v *TraceStartTraceActivationIEBinding) *func(*TraceStartIEValue) (*s48.TraceActivation, bool) {
	return &v.get
}
func BridgeTraceStartTraceActivationIEBindingFieldInfo(v *TraceStartTraceActivationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeTraceStartTraceActivationIEBindingFieldInject(v *TraceStartTraceActivationIEBinding) *func(s48.TraceActivation) TraceStartIEValue {
	return &v.inject
}
func BridgeTraceStartValueCodecFieldCapture(v *TraceStartValueCodec) *func(TraceStart, aper.DecodeState) (TraceStart, aper.Snapshot) {
	return &v.capture
}
func BridgeTraceStartValueCodecFieldCompare(v *TraceStartValueCodec) *func(TraceStart, aper.Snapshot, aper.DecodeBudget) (aper.ReplayPlan, aper.DecodeBudget) {
	return &v.compare
}
func BridgeTraceStartValueCodecFieldContext(v *TraceStartValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeTraceStartValueCodecFieldDecode(v *TraceStartValueCodec) *func([]byte, aper.DecodeState) (TraceStart, error) {
	return &v.decode
}
func BridgeTraceStartValueCodecFieldEncode(v *TraceStartValueCodec) *func(TraceStart, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeTraceStartValueCodecFieldPath(v *TraceStartValueCodec) *aper.Path { return &v.path }
func BridgeTraceStartValueCodecMethodEncodeBudgetValue(v TraceStartValueCodec, a0 TraceStart, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudgetValue(a0, a1, a2)
}
func BridgeTraceStartValueCodecMethodEncodeChanged(v TraceStartValueCodec, a0 TraceStart, a1 bool, a2 aper.DecodeBudget, a3 aper.ReplayPlan) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeWUSAssistanceInformationFieldExtCount(v *WUSAssistanceInformation) *int64 {
	return &v.extCount
}
func BridgeWUSAssistanceInformationFieldExtData(v *WUSAssistanceInformation) *[][]byte {
	return &v.extData
}
func BridgeWUSAssistanceInformationFieldExtOrigin(v *WUSAssistanceInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeWUSAssistanceInformationFieldExtPresent(v *WUSAssistanceInformation) *[]bool {
	return &v.extPresent
}
func BridgeWUSAssistanceInformationFieldExtWire(v *WUSAssistanceInformation) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeWUSAssistanceInformationFieldIEExtensionsIndef(v *WUSAssistanceInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgeWUSAssistanceInformationFieldPerExtPadding(v *WUSAssistanceInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeWUSAssistanceInformationFieldPerPadding(v *WUSAssistanceInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeWUSAssistanceInformationFieldReceived(v *WUSAssistanceInformation) *bool {
	return &v.received
}
func BridgeWUSAssistanceInformationFieldReceivedAbsolute(v *WUSAssistanceInformation) *bool {
	return &v.receivedAbsolute
}
func BridgeWUSAssistanceInformationFieldReceivedBytes(v *WUSAssistanceInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeWUSAssistanceInformationFieldReceivedLocation(v *WUSAssistanceInformation) *aper.Location {
	return &v.receivedLocation
}
func BridgeWUSAssistanceInformationFieldReplay(v *WUSAssistanceInformation) *aper.Snapshot {
	return &v.replay
}
func BridgeWUSAssistanceInformationFieldStream(v *WUSAssistanceInformation) *aper.WireSpan {
	return &v.stream
}
func BridgeWUSAssistanceInformationFieldWithoutReplay(v *WUSAssistanceInformation) *bool {
	return &v.withoutReplay
}
func BridgeWUSAssistanceInformationMethodMarshalAPERBudget(v *WUSAssistanceInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeWUSAssistanceInformationMethodMarshalAPERBudgetValue(v *WUSAssistanceInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudgetValue(a0, a1)
}
func BridgeWUSAssistanceInformationMethodMarshalAPERChanged(v *WUSAssistanceInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeWUSAssistanceInformationMethodMarshalAPERChangedValue(v *WUSAssistanceInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeWUSAssistanceInformationMethodMarshalAPERLegacy(v *WUSAssistanceInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeWUSAssistanceInformationMethodMarshalAPERNewValue(v *WUSAssistanceInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERNewValue(a0, a1)
}
func BridgeWUSAssistanceInformationMethodMarshalAPERPlanned(v *WUSAssistanceInformation, a0 *aper.DecodeBudget, a1 bool, a2 *aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1, a2)
}
func BridgeWUSAssistanceInformationMethodMarshalAPERTo(v *WUSAssistanceInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeWUSAssistanceInformationMethodUnmarshalAPERFrom(v *WUSAssistanceInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeWUSAssistanceInformationMethodUnmarshalAPERLegacy(v *WUSAssistanceInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeWUSAssistanceInformationMethodUnmarshalAPERWithOptions(v *WUSAssistanceInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *InitialContextSetupRequestIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 0:
		if value, ok := v.AsMMEUES1APID(); ok {
			return value, true
		}
	case 8:
		if value, ok := v.AsENBUES1APID(); ok {
			return value, true
		}
	case 66:
		if value, ok := v.AsUEaggregateMaximumBitrate(); ok {
			return value, true
		}
	case 24:
		if value, ok := v.AsERABToBeSetupListCtxtSUReq(); ok {
			return value, true
		}
	case 107:
		if value, ok := v.AsUESecurityCapabilities(); ok {
			return value, true
		}
	case 73:
		if value, ok := v.AsSecurityKey(); ok {
			return value, true
		}
	case 25:
		if value, ok := v.AsTraceActivation(); ok {
			return value, true
		}
	case 41:
		if value, ok := v.AsHandoverRestrictionList(); ok {
			return value, true
		}
	case 74:
		if value, ok := v.AsUERadioCapability(); ok {
			return value, true
		}
	case 106:
		if value, ok := v.AsSubscriberProfileIDforRFP(); ok {
			return value, true
		}
	case 108:
		if value, ok := v.AsCSFallbackIndicator(); ok {
			return value, true
		}
	case 124:
		if value, ok := v.AsSRVCCOperationPossible(); ok {
			return value, true
		}
	case 146:
		if value, ok := v.AsCSGMembershipStatus(); ok {
			return value, true
		}
	case 159:
		if value, ok := v.AsRegisteredLAI(); ok {
			return value, true
		}
	case 75:
		if value, ok := v.AsGUMMEIID(); ok {
			return value, true
		}
	case 158:
		if value, ok := v.AsMMEUES1APID2(); ok {
			return value, true
		}
	case 165:
		if value, ok := v.AsManagementBasedMDTAllowed(); ok {
			return value, true
		}
	case 177:
		if value, ok := v.AsManagementBasedMDTPLMNList(); ok {
			return value, true
		}
	case 187:
		if value, ok := v.AsAdditionalCSFallbackIndicator(); ok {
			return value, true
		}
	case 192:
		if value, ok := v.AsMaskedIMEISV(); ok {
			return value, true
		}
	case 196:
		if value, ok := v.AsExpectedUEBehaviour(); ok {
			return value, true
		}
	case 195:
		if value, ok := v.AsProSeAuthorized(); ok {
			return value, true
		}
	case 241:
		if value, ok := v.AsUEUserPlaneCIoTSupportIndicator(); ok {
			return value, true
		}
	case 240:
		if value, ok := v.AsV2XServicesAuthorized(); ok {
			return value, true
		}
	case 248:
		if value, ok := v.AsUESidelinkAggregateMaximumBitrate(); ok {
			return value, true
		}
	case 251:
		if value, ok := v.AsEnhancedCoverageRestricted(); ok {
			return value, true
		}
	case 269:
		if value, ok := v.AsNRUESecurityCapabilities(); ok {
			return value, true
		}
	case 271:
		if value, ok := v.AsCEModeBRestricted(); ok {
			return value, true
		}
	case 277:
		if value, ok := v.AsAerialUEsubscriptionInformation(); ok {
			return value, true
		}
	case 283:
		if value, ok := v.AsPendingDataIndication(); ok {
			return value, true
		}
	case 278:
		if value, ok := v.AsSubscriptionBasedUEDifferentiationInfo(); ok {
			return value, true
		}
	case 299:
		if value, ok := v.AsAdditionalRRMPriorityIndex(); ok {
			return value, true
		}
	case 301:
		if value, ok := v.AsIABAuthorized(); ok {
			return value, true
		}
	case 306:
		if value, ok := v.AsNRV2XServicesAuthorized(); ok {
			return value, true
		}
	case 307:
		if value, ok := v.AsNRUESidelinkAggregateMaximumBitrate(); ok {
			return value, true
		}
	case 308:
		if value, ok := v.AsPC5QoSParameters(); ok {
			return value, true
		}
	case 314:
		if value, ok := v.AsUERadioCapabilityID(); ok {
			return value, true
		}
	case 354:
		if value, ok := v.AsCoarseUELocation(); ok {
			return value, true
		}
	case 355:
		if value, ok := v.AsTimeRefDistribution(); ok {
			return value, true
		}
	}
	return nil, false
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
// The field's Id distinguishes alternatives with the same Go type.
func (v *TraceStartIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 0:
		if value, ok := v.AsMMEUES1APID(); ok {
			return value, true
		}
	case 8:
		if value, ok := v.AsENBUES1APID(); ok {
			return value, true
		}
	case 25:
		if value, ok := v.AsTraceActivation(); ok {
			return value, true
		}
	}
	return nil, false
}
