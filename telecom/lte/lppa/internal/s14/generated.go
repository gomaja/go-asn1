// Code generated from the pinned LPPa source closure. DO NOT EDIT.

// Package s14 implements the github.com/gomaja/go-asn1/telecom/lte/lppa root package.
package s14

import (
	"fmt"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s00"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s02"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s03"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s04"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s05"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s08"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s09"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s10"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/internal/s13"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime"
	"github.com/gomaja/go-asn1/telecom/lte/lppa/runtime/aper"
)

// AssistanceInformationControlIEContainer is ProtocolIE-Container {{AssistanceInformationControl-IEs}} of TS 36.455: a list of AssistanceInformationControlIEField values.
type AssistanceInformationControlIEContainer []AssistanceInformationControlIEField

// AssistanceInformationControlIEField is ProtocolIE-Field {{AssistanceInformationControl-IEs}} of TS 36.455: a field carrying a value of AssistanceInformationControlIEValue.
type AssistanceInformationControlIEField struct {
	withoutReplay bool
	replay        aper.Snapshot
	stream        aper.WireSpan
	Id            s00.ProtocolIEID
	Criticality   s00.Criticality
	Value         AssistanceInformationControlIEValue

	received aper.CompletePadding
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AssistanceInformationControlIEField) WithoutReplay() AssistanceInformationControlIEField {
	v.withoutReplay = true
	v.stream = aper.WireSpan{}
	return v
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v *AssistanceInformationControlIEField) ReceivedForm() aper.ReceivedForm {
	if v == nil || v.withoutReplay {
		return aper.ReceivedForm{}
	}
	return aper.NewReceivedSpanForm(v.stream.Present(), v.stream, v.stream.ContentLocation(), nil)
}
func (v *AssistanceInformationControlIEField) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
func (v *AssistanceInformationControlIEField) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if v == nil {
		return fmt.Errorf("nil ProtocolIEField")
	}
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformationControlIEField{}
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
	var zero AssistanceInformationControlIEValue

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
func BridgeAssistanceInformationControlIEValueCaptureLPPaProtocolIEContainer(v *AssistanceInformationControlIEContainer, s *aper.SemanticCapture) {
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
func BridgeAssistanceInformationControlIEValueCompareLPPaProtocolIEContainer(v *AssistanceInformationControlIEContainer, s *aper.SemanticComparison) {
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
			s13.BridgeResultUTRANItemExtIEsValueCaptureLPPaProtocolExtensionField(&(*v)[i], s)
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
func BridgeResultsPerSSBIndexItemExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s04.ResultsPerSSBIndexItemExtIEsExtContainer, s *aper.SemanticCapture) {
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
func BridgeResultsPerSSBIndexItemExtIEsValueCompareLPPaProtocolExtensionContainer(v *s04.ResultsPerSSBIndexItemExtIEsExtContainer, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
}
func BridgeSystemInformationExtIEsValueCaptureLPPaProtocolExtensionContainer(v *s04.SystemInformationExtIEsExtContainer, s *aper.SemanticCapture) {
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
func BridgeSystemInformationExtIEsValueCompareLPPaProtocolExtensionContainer(v *s04.SystemInformationExtIEsExtContainer, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
}

// ResultsPerSSBIndexListValueCodec is the concrete ValueCodec[ResultsPerSSBIndexList].
type ResultsPerSSBIndexListValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ResultsPerSSBIndexList, aper.DecodeState,

	) (ResultsPerSSBIndexList, aper.Snapshot,

	)
	compare func(ResultsPerSSBIndexList, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ResultsPerSSBIndexList,

		error)
	encode func(ResultsPerSSBIndexList,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ResultsPerSSBIndexListValueCodec) New(value ResultsPerSSBIndexList,

) (ResultsPerSSBIndexListAPERValue, error) {
	if c.encode == nil {
		return ResultsPerSSBIndexListAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResultsPerSSBIndexListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultsPerSSBIndexListAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ResultsPerSSBIndexListAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ResultsPerSSBIndexListValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResultsPerSSBIndexListAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultsPerSSBIndexListAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ResultsPerSSBIndexListAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultsPerSSBIndexListAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ResultsPerSSBIndexListAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ResultsPerSSBIndexListAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ResultsPerSSBIndexListValueCodec) EncodeAPER(value ResultsPerSSBIndexListAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResultsPerSSBIndexListValueCodec) encodeBudget(value ResultsPerSSBIndexList,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultsPerSSBIndexListValueCodec) encodeChanged(value ResultsPerSSBIndexList,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// AssistanceInformationControlAssistanceInformationIEBinding binds AssistanceInformation to ProtocolIE-Field {{AssistanceInformationControl-IEs}} of TS 36.455.
type AssistanceInformationControlAssistanceInformationIEBinding struct {
	info   s00.FieldInfo
	codec  AssistanceInformationValueCodec
	inject func(AssistanceInformation,

	) AssistanceInformationControlIEValue

	get func(*AssistanceInformationControlIEValue,

	) (*AssistanceInformation,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b AssistanceInformationControlAssistanceInformationIEBinding) Info() s00.FieldInfo {
	return b.info
}

// Codec returns the complete APER codec for this binding's value type.
func (b AssistanceInformationControlAssistanceInformationIEBinding) Codec() AssistanceInformationValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b AssistanceInformationControlAssistanceInformationIEBinding) New(value AssistanceInformation,

) (AssistanceInformationControlIEField, error) {
	if b.inject == nil {
		return AssistanceInformationControlIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AssistanceInformationControlIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := b.codec.encode(value, false, budget); err != nil {
		return AssistanceInformationControlIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return AssistanceInformationControlIEField{}, aper.OperationError(err, "Value.New")
	}
	return AssistanceInformationControlIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b AssistanceInformationControlAssistanceInformationIEBinding) Get(field *AssistanceInformationControlIEField) (*AssistanceInformation,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// AssistanceInformationValueCodec is the concrete ValueCodec[AssistanceInformation].
type AssistanceInformationValueCodec struct {
	context s00.BridgeCodecContext
	capture func(AssistanceInformation, aper.DecodeState,

	) (AssistanceInformation, aper.Snapshot,

	)
	compare func(AssistanceInformation, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (AssistanceInformation,

		error)
	encode func(AssistanceInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c AssistanceInformationValueCodec) New(value AssistanceInformation,

) (AssistanceInformationAPERValue, error) {
	if c.encode == nil {
		return AssistanceInformationAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AssistanceInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return AssistanceInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return AssistanceInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c AssistanceInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (AssistanceInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return AssistanceInformationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return AssistanceInformationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return AssistanceInformationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return AssistanceInformationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return AssistanceInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c AssistanceInformationValueCodec) EncodeAPER(value AssistanceInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c AssistanceInformationValueCodec) encodeBudget(value AssistanceInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c AssistanceInformationValueCodec) encodeChanged(value AssistanceInformation,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// AssistanceInformationControlBroadcastIEBinding binds Broadcast to ProtocolIE-Field {{AssistanceInformationControl-IEs}} of TS 36.455.
type AssistanceInformationControlBroadcastIEBinding struct {
	info   s00.FieldInfo
	codec  s00.BroadcastValueCodec
	inject func(s00.Broadcast,

	) AssistanceInformationControlIEValue

	get func(*AssistanceInformationControlIEValue,

	) (*s00.Broadcast,

		bool)
}

// Info returns the source-derived metadata for this descriptor or binding.
func (b AssistanceInformationControlBroadcastIEBinding) Info() s00.FieldInfo { return b.info }

// Codec returns the complete APER codec for this binding's value type.
func (b AssistanceInformationControlBroadcastIEBinding) Codec() s00.BroadcastValueCodec {
	return b.codec
}

// New validates value and constructs a field with this binding's identifier and criticality.
func (b AssistanceInformationControlBroadcastIEBinding) New(value s00.Broadcast,

) (AssistanceInformationControlIEField, error) {
	if b.inject == nil {
		return AssistanceInformationControlIEField{}, aper.OperationError(fmt.Errorf("unbound IE binding"), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return AssistanceInformationControlIEField{}, aper.OperationError(err, "Value.New")
	}
	if _, err := (*s00.BridgeBroadcastValueCodecFieldEncode(&b.codec))(value, false, budget); err != nil {
		return AssistanceInformationControlIEField{}, aper.OperationError(fmt.Errorf("%s %d: %w", "IE", b.info.ID, err), "Value.New")
	}
	if err := aper.ChargeValue(aper.NewBudgetBuffer(budget), value); err != nil {
		return AssistanceInformationControlIEField{}, aper.OperationError(err, "Value.New")
	}
	return AssistanceInformationControlIEField{Id: b.info.ID, Criticality: b.info.Criticality, Value: b.inject(value)}, aper.OperationError(nil, "Value.New")
}

// Get returns the selected typed value when the field belongs to this binding.
func (b AssistanceInformationControlBroadcastIEBinding) Get(field *AssistanceInformationControlIEField) (*s00.Broadcast,

	bool) {
	if field == nil || field.Id != b.info.ID || b.get == nil {
		return nil, false
	}
	return b.get(&field.Value)
}

// ResultUTRANValueCodec is the concrete ValueCodec[ResultUTRAN].
type ResultUTRANValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ResultUTRAN, aper.DecodeState,

	) (ResultUTRAN, aper.Snapshot,

	)
	compare func(ResultUTRAN, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ResultUTRAN,

		error)
	encode func(ResultUTRAN,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ResultUTRANValueCodec) New(value ResultUTRAN,

) (ResultUTRANAPERValue, error) {
	if c.encode == nil {
		return ResultUTRANAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResultUTRANAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultUTRANAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ResultUTRANAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ResultUTRANValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResultUTRANAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultUTRANAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ResultUTRANAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultUTRANAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ResultUTRANAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ResultUTRANAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ResultUTRANValueCodec) EncodeAPER(value ResultUTRANAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResultUTRANValueCodec) encodeBudget(value ResultUTRAN,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultUTRANValueCodec) encodeChanged(value ResultUTRAN,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ResultUTRANItemValueCodec is the concrete ValueCodec[ResultUTRANItem].
type ResultUTRANItemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ResultUTRANItem, aper.DecodeState,

	) (ResultUTRANItem, aper.Snapshot,

	)
	compare func(ResultUTRANItem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ResultUTRANItem,

		error)
	encode func(ResultUTRANItem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ResultUTRANItemValueCodec) New(value ResultUTRANItem,

) (ResultUTRANItemAPERValue, error) {
	if c.encode == nil {
		return ResultUTRANItemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResultUTRANItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultUTRANItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ResultUTRANItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ResultUTRANItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResultUTRANItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultUTRANItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ResultUTRANItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultUTRANItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ResultUTRANItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ResultUTRANItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ResultUTRANItemValueCodec) EncodeAPER(value ResultUTRANItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResultUTRANItemValueCodec) encodeBudget(value ResultUTRANItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultUTRANItemValueCodec) encodeChanged(value ResultUTRANItem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// ResultsPerSSBIndexItemValueCodec is the concrete ValueCodec[ResultsPerSSBIndexItem].
type ResultsPerSSBIndexItemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(ResultsPerSSBIndexItem, aper.DecodeState,

	) (ResultsPerSSBIndexItem, aper.Snapshot,

	)
	compare func(ResultsPerSSBIndexItem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (ResultsPerSSBIndexItem,

		error)
	encode func(ResultsPerSSBIndexItem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c ResultsPerSSBIndexItemValueCodec) New(value ResultsPerSSBIndexItem,

) (ResultsPerSSBIndexItemAPERValue, error) {
	if c.encode == nil {
		return ResultsPerSSBIndexItemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return ResultsPerSSBIndexItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return ResultsPerSSBIndexItemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return ResultsPerSSBIndexItemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c ResultsPerSSBIndexItemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (ResultsPerSSBIndexItemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return ResultsPerSSBIndexItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return ResultsPerSSBIndexItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return ResultsPerSSBIndexItemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return ResultsPerSSBIndexItemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return ResultsPerSSBIndexItemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c ResultsPerSSBIndexItemValueCodec) EncodeAPER(value ResultsPerSSBIndexItemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c ResultsPerSSBIndexItemValueCodec) encodeBudget(value ResultsPerSSBIndexItem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c ResultsPerSSBIndexItemValueCodec) encodeChanged(value ResultsPerSSBIndexItem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// SystemInformationValueCodec is the concrete ValueCodec[SystemInformation].
type SystemInformationValueCodec struct {
	context s00.BridgeCodecContext
	capture func(SystemInformation, aper.DecodeState,

	) (SystemInformation, aper.Snapshot,

	)
	compare func(SystemInformation, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (SystemInformation,

		error)
	encode func(SystemInformation,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c SystemInformationValueCodec) New(value SystemInformation,

) (SystemInformationAPERValue, error) {
	if c.encode == nil {
		return SystemInformationAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SystemInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SystemInformationAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SystemInformationAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c SystemInformationValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SystemInformationAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SystemInformationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return SystemInformationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SystemInformationAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return SystemInformationAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return SystemInformationAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c SystemInformationValueCodec) EncodeAPER(value SystemInformationAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SystemInformationValueCodec) encodeBudget(value SystemInformation,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SystemInformationValueCodec) encodeChanged(value SystemInformation,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}

// SystemInformationElemValueCodec is the concrete ValueCodec[SystemInformationElem].
type SystemInformationElemValueCodec struct {
	context s00.BridgeCodecContext
	capture func(SystemInformationElem, aper.DecodeState,

	) (SystemInformationElem, aper.Snapshot,

	)
	compare func(SystemInformationElem, aper.Snapshot, aper.ComparisonLimits,

	) aper.ReplayPlan
	path   aper.Path
	decode func([]byte, aper.DecodeState) (SystemInformationElem,

		error)
	encode func(SystemInformationElem,

		bool, *aper.DecodeBudget) ([]byte, error)
}

// New validates value and returns a complete APER value.
func (c SystemInformationElemValueCodec) New(value SystemInformationElem,

) (SystemInformationElemAPERValue, error) {
	if c.encode == nil {
		return SystemInformationElemAPERValue{}, aper.OperationError(fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue), "Value.New")
	}
	budget, err := aper.BuildBudget()
	if err != nil {
		return SystemInformationElemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	if _, err := c.encode(value, false, budget); err != nil {
		return SystemInformationElemAPERValue{}, aper.OperationError(err, "Value.New")
	}
	return SystemInformationElemAPERValue{Value: value}, aper.OperationError(nil, "Value.New")
}

// DecodeAPER decodes a complete APER value with the supplied options and retains its received wire form.
func (c SystemInformationElemValueCodec) DecodeAPER(data []byte, options ...aper.DecodeOption) (SystemInformationElemAPERValue, aper.DecodeReport, error) {
	if c.decode == nil || c.encode == nil {
		return SystemInformationElemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: unbound value codec", aper.ErrInvalidValue)
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	value, err := c.decode(data, settings)
	if err != nil {
		report, err := aper.FinishDecode(settings, err)
		return SystemInformationElemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	if c.capture == nil {
		return SystemInformationElemAPERValue{}, aper.DecodeReport{}, fmt.Errorf("%w: missing semantic capture", aper.ErrInvalidValue)
	}
	value, replay := c.capture(value, settings)
	report, err := aper.FinishDecode(settings, nil)
	if err != nil {
		return SystemInformationElemAPERValue{}, report, aper.OperationError(err, c.path)
	}
	return SystemInformationElemAPERValue{Value: value, received: aper.OriginalWire(data), replay: replay, context: c.context}, report, nil
}

// EncodeAPER encodes a complete APER value, replaying unchanged received bytes unless fresh encoding is requested.
func (c SystemInformationElemValueCodec) EncodeAPER(value SystemInformationElemAPERValue, options ...aper.EncodeOption) ([]byte, error) {
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
func (c SystemInformationElemValueCodec) encodeBudget(value SystemInformationElem,

	fresh bool, budget aper.DecodeBudget) ([]byte, error) {
	return c.encode(value, fresh, &budget)
}
func (c SystemInformationElemValueCodec) encodeChanged(value SystemInformationElem,

	fresh bool, plan aper.ReplayPlan, budget aper.DecodeBudget) ([]byte, error) {
	budget.SetReplayPlan(&plan)
	out, err := c.encode(value, fresh, &budget)
	return out, aper.OperationError(err, c.path)
}
func BridgeResultUTRANItemExtIEsValueValidateLPPaExtensionContainer(fields s04.ResultUTRANItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s04.ResultUTRANItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s04.ResultUTRANItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeResultUTRANItemExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeResultsPerSSBIndexItemExtIEsValueValidateLPPaExtensionContainer(fields s04.ResultsPerSSBIndexItemExtIEsExtContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget) s09.ValidationReport {
	bb := aper.NewBudgetBuffer(budget)
	if err := aper.ChargeSlice[s04.ResultsPerSSBIndexItemExtIEsIEField](bb, uint64(len(fields))); err != nil {
		return func() s09.ValidationReport {
			sealed := s09.ValidationReport{}
			*s09.BridgeValidationReportFieldErr(&sealed) = err
			*s09.BridgeValidationReportFieldBudget(&sealed) = budget
			return sealed
		}()
	}
	asIE := make(s04.ResultsPerSSBIndexItemExtIEsIEContainer, len(fields))
	for i := range fields {
		asIE[i].Id = fields[i].Id
		asIE[i].Criticality = fields[i].Criticality
		asIE[i].Value = fields[i].ExtensionValue
	}
	return BridgeResultsPerSSBIndexItemExtIEsValueValidateLPPaIEContainer(asIE, rows, path, budget)
}
func BridgeAssistanceInformationControlIEValueCaptureLPPaProtocolIEField(v *AssistanceInformationControlIEField, s *aper.SemanticCapture) {
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
func BridgeAssistanceInformationControlIEValueCompareLPPaProtocolIEField(v *AssistanceInformationControlIEField, s *aper.SemanticComparison) {
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

// resultUTRANItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ResultUTRANItemExtIEsValue].
type ResultUTRANItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.ResultUTRANItemExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.ResultUTRANItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
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

// resultsPerSSBIndexItemExtIEsValueProtocolOpenValue is the concrete protocolOpenValue[ResultsPerSSBIndexItemExtIEsValue].
type ResultsPerSSBIndexItemExtIEsValueProtocolOpenValueConstraint interface {
	captureSemantics(aper.SemanticCapture) s03.ResultsPerSSBIndexItemExtIEsValue

	captureFraming() uint64
	captureSnapshot() aper.Snapshot
	compareSemantics(aper.SemanticComparison) aper.SemanticComparison
	decode(s00.ProtocolIEID, aper.OpaqueOpenType) (s03.ResultsPerSSBIndexItemExtIEsValue,

		error)
	encode() ([]byte, error)
	encodeFresh(bool, *aper.DecodeBudget) ([]byte, error)
	matchesID(s00.ProtocolIEID, *aper.DecodeBudget) bool
	reason(s00.ProtocolIEID) aper.OpaqueReason
	rule() aper.SourceRule
}

func BridgeResultsPerSSBIndexItemExtIEsValueCaptureLPPaProtocolExtensionField(v *s04.ResultsPerSSBIndexItemExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s04.BridgeResultsPerSSBIndexItemExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s03.BridgeResultsPerSSBIndexItemExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s03.BridgeResultsPerSSBIndexItemExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s03.BridgeResultsPerSSBIndexItemExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s04.BridgeResultsPerSSBIndexItemExtIEsExtFieldFieldReplay(v), *s04.BridgeResultsPerSSBIndexItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeResultsPerSSBIndexItemExtIEsValueCompareLPPaProtocolExtensionField(v *s04.ResultsPerSSBIndexItemExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s03.BridgeResultsPerSSBIndexItemExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s04.BridgeResultsPerSSBIndexItemExtIEsExtFieldFieldReplay(v), *s04.BridgeResultsPerSSBIndexItemExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSystemInformationExtIEsValueCaptureLPPaProtocolExtensionField(v *s04.SystemInformationExtIEsExtField, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(*s04.BridgeSystemInformationExtIEsExtFieldFieldStream(v))
	s00.BridgeCaptureLPPaProtocolIEID(&v.Id, s)
	s00.BridgeCaptureLPPaCriticality(&v.Criticality, s)
	s.OpenBytes(s03.BridgeSystemInformationExtIEsValueMethodCaptureFraming(v.ExtensionValue))
	v.ExtensionValue = s03.BridgeSystemInformationExtIEsValueMethodCaptureSemantics(v.ExtensionValue, *s)
	s.Child(s03.BridgeSystemInformationExtIEsValueMethodCaptureSnapshot(v.ExtensionValue))
	s.End(f, s04.BridgeSystemInformationExtIEsExtFieldFieldReplay(v), *s04.BridgeSystemInformationExtIEsExtFieldFieldWithoutReplay(v))
}
func BridgeSystemInformationExtIEsValueCompareLPPaProtocolExtensionField(v *s04.SystemInformationExtIEsExtField, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaProtocolIEID(&v.Id, s)
	s02.BridgeCompareLPPaCriticality(&v.Criticality, s)

	*s = s03.BridgeSystemInformationExtIEsValueMethodCompareSemantics(v.ExtensionValue, *s)
	s.End(f, *s04.BridgeSystemInformationExtIEsExtFieldFieldReplay(v), *s04.BridgeSystemInformationExtIEsExtFieldFieldWithoutReplay(v))
}

// ResultsPerSSBIndexListAPERValue is the concrete APERValue[ResultsPerSSBIndexList].
type ResultsPerSSBIndexListAPERValue struct {
	context s00.BridgeCodecContext
	Value   ResultsPerSSBIndexList

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ResultsPerSSBIndexListAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultsPerSSBIndexListAPERValue) WithoutReplay() ResultsPerSSBIndexListAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// AssistanceInformationAPERValue is the concrete APERValue[AssistanceInformation].
type AssistanceInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   AssistanceInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v AssistanceInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AssistanceInformationAPERValue) WithoutReplay() AssistanceInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultUTRANAPERValue is the concrete APERValue[ResultUTRAN].
type ResultUTRANAPERValue struct {
	context s00.BridgeCodecContext
	Value   ResultUTRAN

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ResultUTRANAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultUTRANAPERValue) WithoutReplay() ResultUTRANAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultUTRANItemAPERValue is the concrete APERValue[ResultUTRANItem].
type ResultUTRANItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ResultUTRANItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ResultUTRANItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultUTRANItemAPERValue) WithoutReplay() ResultUTRANItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// ResultsPerSSBIndexItemAPERValue is the concrete APERValue[ResultsPerSSBIndexItem].
type ResultsPerSSBIndexItemAPERValue struct {
	context s00.BridgeCodecContext
	Value   ResultsPerSSBIndexItem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v ResultsPerSSBIndexItemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v ResultsPerSSBIndexItemAPERValue) WithoutReplay() ResultsPerSSBIndexItemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SystemInformationAPERValue is the concrete APERValue[SystemInformation].
type SystemInformationAPERValue struct {
	context s00.BridgeCodecContext
	Value   SystemInformation

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v SystemInformationAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v SystemInformationAPERValue) WithoutReplay() SystemInformationAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// SystemInformationElemAPERValue is the concrete APERValue[SystemInformationElem].
type SystemInformationElemAPERValue struct {
	context s00.BridgeCodecContext
	Value   SystemInformationElem

	received      aper.WireSpan
	replay        aper.Snapshot
	withoutReplay bool
}

// ReceivedForm returns the retained wire form, or an empty form when no received framing is available.
func (v SystemInformationElemAPERValue) ReceivedForm() aper.ReceivedForm {
	return aper.NewReceivedSpanForm(v.received.Present(), v.received, aper.Location{}, nil)
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v SystemInformationElemAPERValue) WithoutReplay() SystemInformationElemAPERValue {
	v.received = aper.WireSpan{}
	v.replay = aper.Snapshot{}
	v.withoutReplay = true
	return v
}

// TS 36.455 V19.0.0 §§9.3.4–9.3.5 supply the selected object-set order and
// presence. Its §10 adopts TS 36.413 V19.2.0 §§10.3.1–10.3.6. Unknown IEs do
// not determine the order of known rows.
func BridgeResultUTRANItemExtIEsValueValidateLPPaIEContainer(fields s04.ResultUTRANItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s03.BridgeResultUTRANItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s03.BridgeResultUTRANItemExtIEsValueMethodRule(field.Value)
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
func BridgeResultsPerSSBIndexItemExtIEsValueValidateLPPaIEContainer(fields s04.ResultsPerSSBIndexItemExtIEsIEContainer, rows []s00.FieldInfo, path string, budget *aper.DecodeBudget,

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
		if !s03.BridgeResultsPerSSBIndexItemExtIEsValueMethodMatchesID(field.Value, field.Id, budget) {
			rule := s03.BridgeResultsPerSSBIndexItemExtIEsValueMethodRule(field.Value)
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

// AssistanceInformation represents the ASN.1 type Assistance-Information (SEQUENCE).
type AssistanceInformation struct {
	replay                 aper.Snapshot
	stream                 aper.WireSpan
	withoutReplay          bool
	received               bool
	receivedBytes          aper.WireSpan
	SystemInformation      SystemInformation                           `asn1:"tag:0,context,implicit"`
	systemInformationIndef bool                                        `asn1:"-" json:"-"`
	IEExtensions           s03.AssistanceInformationExtIEsExtContainer `asn1:"tag:1,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef      bool                                        `asn1:"-" json:"-"`
	extCount               int64                                       `asn1:"-" json:"-"`
	extPresent             []bool                                      `asn1:"-" json:"-"`
	extData                [][]byte                                    `asn1:"-" json:"-"`
	perPadding             aper.FinalPadding                           `asn1:"-" json:"-"`
	perExtPadding          []aper.CompletePadding                      `asn1:"-" json:"-"`
	extOrigin              []aper.OpaqueOrigin
	extWire                []aper.WireSpan
}
type ResultUTRAN = []ResultUTRANItem

// ResultUTRANItem represents the ASN.1 type ResultUTRAN-Item (SEQUENCE).
type ResultUTRANItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     aper.WireSpan
	UARFCN            s00.UARFCN                            `asn1:"tag:0,context,implicit"`
	PhysCellIDUTRAN   s08.ResultUTRANItemPhysCellIDUTRAN    `asn1:"tag:1,context,explicit"`
	UTRARSCP          s00.UTRARSCP                          `asn1:"tag:2,context,implicit,optional" json:"UTRARSCP,omitzero"`
	UTRAEcN0          s00.UTRAEcN0                          `asn1:"tag:3,context,implicit,optional" json:"UTRAEcN0,omitzero"`
	IEExtensions      s04.ResultUTRANItemExtIEsExtContainer `asn1:"tag:4,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                  `asn1:"-" json:"-"`
	extCount          int64                                 `asn1:"-" json:"-"`
	extPresent        []bool                                `asn1:"-" json:"-"`
	extData           [][]byte                              `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                     `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type ResultsPerSSBIndexList = []ResultsPerSSBIndexItem

// ResultsPerSSBIndexItem represents the ASN.1 type ResultsPerSSB-Index-Item (SEQUENCE).
type ResultsPerSSBIndexItem struct {
	replay            aper.Snapshot
	stream            aper.WireSpan
	withoutReplay     bool
	received          bool
	receivedBytes     aper.WireSpan
	SSBIndex          s00.SSBIndex                                 `asn1:"tag:0,context,implicit"`
	SSNRRSRPBeamValue *s00.SSNRRSRP                                `asn1:"tag:1,context,implicit,optional" json:"SSNRRSRPBeamValue,omitempty"`
	SSNRRSRQBeamValue *s00.SSNRRSRQ                                `asn1:"tag:2,context,implicit,optional" json:"SSNRRSRQBeamValue,omitempty"`
	IEExtensions      s04.ResultsPerSSBIndexItemExtIEsExtContainer `asn1:"tag:3,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef bool                                         `asn1:"-" json:"-"`
	extCount          int64                                        `asn1:"-" json:"-"`
	extPresent        []bool                                       `asn1:"-" json:"-"`
	extData           [][]byte                                     `asn1:"-" json:"-"`
	perPadding        aper.FinalPadding                            `asn1:"-" json:"-"`
	perExtPadding     []aper.CompletePadding                       `asn1:"-" json:"-"`
	extOrigin         []aper.OpaqueOrigin
	extWire           []aper.WireSpan
}
type SystemInformation = []SystemInformationElem

// SystemInformationElem represents the ASN.1 type SystemInformation-Elem (SEQUENCE).
type SystemInformationElem struct {
	replay               aper.Snapshot
	stream               aper.WireSpan
	withoutReplay        bool
	received             bool
	receivedBytes        aper.WireSpan
	BroadcastPeriodicity s00.BroadcastPeriodicity                `asn1:"tag:0,context,implicit"`
	PosSIBs              s10.PosSIBs                             `asn1:"tag:1,context,implicit"`
	posSIBsIndef         bool                                    `asn1:"-" json:"-"`
	IEExtensions         s04.SystemInformationExtIEsExtContainer `asn1:"tag:2,context,implicit,optional" json:"IEExtensions,omitzero"`
	iEExtensionsIndef    bool                                    `asn1:"-" json:"-"`
	extCount             int64                                   `asn1:"-" json:"-"`
	extPresent           []bool                                  `asn1:"-" json:"-"`
	extData              [][]byte                                `asn1:"-" json:"-"`
	perPadding           aper.FinalPadding                       `asn1:"-" json:"-"`
	perExtPadding        []aper.CompletePadding                  `asn1:"-" json:"-"`
	extOrigin            []aper.OpaqueOrigin
	extWire              []aper.WireSpan
}

// MarshalAPER encodes AssistanceInformation to APER format.
func (v *AssistanceInformation) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *AssistanceInformation) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeCollection(bb, int64(len(v.SystemInformation)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_systeminformation, fragmentLength_systeminformation int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_systeminformation < 0 || fragmentOffset_systeminformation > int64(len(v.SystemInformation)) || fragmentLength_systeminformation < 0 || fragmentLength_systeminformation > int64(len(v.SystemInformation[fragmentOffset_systeminformation:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.SystemInformation[fragmentOffset_systeminformation : fragmentOffset_systeminformation+fragmentLength_systeminformation] {
			if err := elem.marshalAPERTo(bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding systemInformation element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding systemInformation: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s03.BridgeAssistanceInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes AssistanceInformation from APER format.
func (v *AssistanceInformation) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes AssistanceInformation with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *AssistanceInformation) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformation")
	}
	bb.EnterComponent("AssistanceInformation")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformation")
	}
	padding, err := aper.CaptureFinalBits(bb, "AssistanceInformation")
	if err != nil {
		return runtime.WrapDecodePath(err, "AssistanceInformation")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *AssistanceInformation) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = AssistanceInformation{}
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
	toleranceMark_systeminformation := bb.EnterComponent("SystemInformation")
	v.SystemInformation = make(SystemInformation, 0)
	_, errCollection_systeminformation := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_systeminformation, fragmentLength_systeminformation int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_systeminformation < 0 || fragmentLength_systeminformation < 0 || fragmentLength_systeminformation > int64(^uint(0)>>1) || fragmentOffset_systeminformation > int64(^uint(0)>>1)-fragmentLength_systeminformation {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_systeminformation; i++ {
			var elem SystemInformationElem
			elementMark := bb.EnterIndex(fragmentOffset_systeminformation + i)
			if err := elem.unmarshalAPERFrom(bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("SystemInformation[%d]", fragmentOffset_systeminformation+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.SystemInformation, elem); err != nil {
				return err
			} else {
				v.SystemInformation = next
			}
		}
		return nil
	})
	if errCollection_systeminformation != nil {
		return runtime.WrapDecodePath(errCollection_systeminformation, "SystemInformation")
	}
	bb.LeaveComponent(toleranceMark_systeminformation)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s03.AssistanceInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s03.AssistanceInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s03.BridgeAssistanceInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERResultUTRANListValue struct{ Value ResultUTRAN }

// MarshalAPERResultUTRANTo appends a ResultUTRAN list to bb.
func BridgeMarshalAPERResultUTRANTo(list ResultUTRAN, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERResultUTRANListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 8, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ResultUTRANItem to APER format.
func (v *ResultUTRANItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ResultUTRANItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.UTRARSCP != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.UTRAEcN0 != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerBigBoundsAligned(bb, v.UARFCN, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound10, true); err != nil {
		return fmt.Errorf("encoding uARFCN: %w", err)
	}
	if err := s08.BridgeResultUTRANItemPhysCellIDUTRANMethodMarshalAPERTo(&v.PhysCellIDUTRAN, bb, len(fresh) != 0 && fresh[0]); err != nil {
		return fmt.Errorf("encoding physCellIDUTRAN: %w", err)
	}
	if v.UTRARSCP != nil {
		if err := aper.EncodeIntegerBigBoundsAligned(bb, v.UTRARSCP, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound21, true); err != nil {
			return fmt.Errorf("encoding uTRA-RSCP: %w", err)
		}
	}
	if v.UTRAEcN0 != nil {
		if err := aper.EncodeIntegerBigBoundsAligned(bb, v.UTRAEcN0, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound15, true); err != nil {
			return fmt.Errorf("encoding uTRA-EcN0: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s04.BridgeResultUTRANItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ResultUTRANItem from APER format.
func (v *ResultUTRANItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResultUTRANItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResultUTRANItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ResultUTRANItem")
	}
	bb.EnterComponent("ResultUTRANItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResultUTRANItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ResultUTRANItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultUTRANItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ResultUTRANItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultUTRANItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_utrarscp, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_utraecn0, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_uarfcn, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound10, true)
	if err != nil {
		return runtime.WrapDecodePath(err, "UARFCN")
	}
	v.UARFCN = val_uarfcn
	toleranceMark_physcellidutran := bb.EnterComponent("PhysCellIDUTRAN")
	if err := s08.BridgeResultUTRANItemPhysCellIDUTRANMethodUnmarshalAPERFrom(&v.PhysCellIDUTRAN, bb); err != nil {
		return runtime.WrapDecodePath(err, "PhysCellIDUTRAN")
	}
	bb.LeaveComponent(toleranceMark_physcellidutran)
	if opt_utrarscp {
		val_utrarscp, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound0, s00.BridgeAsn1IntegerBound21, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "UTRARSCP")
		}
		v.UTRARSCP = val_utrarscp
	}
	if opt_utraecn0 {
		val_utraecn0, err := aper.DecodeIntegerBigBoundsAligned(bb, s00.BridgeAsn1IntegerBound1, s00.BridgeAsn1IntegerBound15, true)
		if err != nil {
			return runtime.WrapDecodePath(err, "UTRAEcN0")
		}
		v.UTRAEcN0 = val_utraecn0
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s04.ResultUTRANItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s04.ResultUTRANItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s04.BridgeResultUTRANItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERResultsPerSSBIndexListListValue struct{ Value ResultsPerSSBIndexList }

// MarshalAPERResultsPerSSBIndexListTo appends a ResultsPerSSBIndexList list to bb.
func BridgeMarshalAPERResultsPerSSBIndexListTo(list ResultsPerSSBIndexList, bb *aper.BitBuffer, fresh ...bool) error {
	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()

	v := BridgeAsn1cAPERResultsPerSSBIndexListListValue{Value: list}
	if err := aper.EncodeCollection(bb, int64(len(v.Value)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 64, HasUpper: true}, true, func(fragmentOffset_value, fragmentLength_value int64) error {
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

// MarshalAPER encodes ResultsPerSSBIndexItem to APER format.
func (v *ResultsPerSSBIndexItem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *ResultsPerSSBIndexItem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeBoolean(bb, v.SSNRRSRPBeamValue != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.SSNRRSRQBeamValue != nil); err != nil {
		return err
	}
	if err := aper.EncodeBoolean(bb, v.IEExtensions != nil); err != nil {
		return err
	}
	if err := aper.EncodeIntegerAligned(bb, int64(v.SSBIndex), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(63), false); err != nil {
		return fmt.Errorf("encoding sSB-Index: %w", err)
	}
	if v.SSNRRSRPBeamValue != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.SSNRRSRPBeamValue), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(127), false); err != nil {
			return fmt.Errorf("encoding sS-NRRSRPBeamValue: %w", err)
		}
	}
	if v.SSNRRSRQBeamValue != nil {
		if err := aper.EncodeIntegerAligned(bb, int64(*v.SSNRRSRQBeamValue), s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(127), false); err != nil {
			return fmt.Errorf("encoding sS-NRRSRQBeamValue: %w", err)
		}
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s04.BridgeResultsPerSSBIndexItemExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes ResultsPerSSBIndexItem from APER format.
func (v *ResultsPerSSBIndexItem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes ResultsPerSSBIndexItem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *ResultsPerSSBIndexItem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "ResultsPerSSBIndexItem")
	}
	bb.EnterComponent("ResultsPerSSBIndexItem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "ResultsPerSSBIndexItem")
	}
	padding, err := aper.CaptureFinalBits(bb, "ResultsPerSSBIndexItem")
	if err != nil {
		return runtime.WrapDecodePath(err, "ResultsPerSSBIndexItem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *ResultsPerSSBIndexItem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = ResultsPerSSBIndexItem{}
	extAdditions := aper.BeginExtensionAdditions(bb)
	hasExtensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	// Read preamble bitmap for optional root fields
	opt_ssnrrsrpbeamvalue, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ssnrrsrqbeamvalue, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	opt_ieextensions, err := aper.DecodeBoolean(bb)
	if err != nil {
		return err
	}
	val_ssbindex, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(63), false)
	if err != nil {
		return runtime.WrapDecodePath(err, "SSBIndex")
	}
	v.SSBIndex = s00.SSBIndex(val_ssbindex)
	if opt_ssnrrsrpbeamvalue {
		val_ssnrrsrpbeamvalue, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(127), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "SSNRRSRPBeamValue")
		}
		tmp_ssnrrsrpbeamvalue := s00.SSNRRSRP(val_ssnrrsrpbeamvalue)
		if err := aper.ChargeValue(bb, tmp_ssnrrsrpbeamvalue); err != nil {
			return err
		}
		v.SSNRRSRPBeamValue = (*s00.SSNRRSRP)(bb.OwnInt64(int64(tmp_ssnrrsrpbeamvalue)))
	}
	if opt_ssnrrsrqbeamvalue {
		val_ssnrrsrqbeamvalue, err := aper.DecodeIntegerAligned(bb, s03.BridgeInt64Ptr(0), s03.BridgeInt64Ptr(127), false)
		if err != nil {
			return runtime.WrapDecodePath(err, "SSNRRSRQBeamValue")
		}
		tmp_ssnrrsrqbeamvalue := s00.SSNRRSRQ(val_ssnrrsrqbeamvalue)
		if err := aper.ChargeValue(bb, tmp_ssnrrsrqbeamvalue); err != nil {
			return err
		}
		v.SSNRRSRQBeamValue = (*s00.SSNRRSRQ)(bb.OwnInt64(int64(tmp_ssnrrsrqbeamvalue)))
	}
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s04.ResultsPerSSBIndexItemExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s04.ResultsPerSSBIndexItemExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s04.BridgeResultsPerSSBIndexItemExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

type BridgeAsn1cAPERSystemInformationListValue struct{ Value SystemInformation }

// MarshalAPER encodes SystemInformationElem to APER format.
func (v *SystemInformationElem) marshalAPERLegacy() ([]byte, error) {
	bb := aper.NewBitBuffer()
	if err := v.marshalAPERTo(bb); err != nil {
		return nil, err
	}
	return bb.CompleteBytesWithFinalPadding(v.perPadding)
}
func (v *SystemInformationElem) marshalAPERTo(bb *aper.BitBuffer, fresh ...bool) error {
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
	if err := aper.EncodeEnumeratedAligned(bb, int64(v.BroadcastPeriodicity), 7, true); err != nil {
		return fmt.Errorf("encoding broadcastPeriodicity: %w", err)
	}
	if err := aper.EncodeCollection(bb, int64(len(v.PosSIBs)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_possibs, fragmentLength_possibs int64) error {
		// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
		if fragmentOffset_possibs < 0 || fragmentOffset_possibs > int64(len(v.PosSIBs)) || fragmentLength_possibs < 0 || fragmentLength_possibs > int64(len(v.PosSIBs[fragmentOffset_possibs:])) {
			return fmt.Errorf("collection fragment outside value")
		}
		for _, elem := range v.PosSIBs[fragmentOffset_possibs : fragmentOffset_possibs+fragmentLength_possibs] {
			if err := s10.BridgePosSIBsElemMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
				return fmt.Errorf("encoding posSIBs element: %w", err)
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("encoding posSIBs: %w", err)
	}
	if v.IEExtensions != nil {
		if err := aper.EncodeCollection(bb, int64(len(v.IEExtensions)), aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern PER_FRAGMENT_SLICE: fragment window lies inside the collection; gen/codegen_per_collection.go:56
			if fragmentOffset_ieextensions < 0 || fragmentOffset_ieextensions > int64(len(v.IEExtensions)) || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(len(v.IEExtensions[fragmentOffset_ieextensions:])) {
				return fmt.Errorf("collection fragment outside value")
			}
			for _, elem := range v.IEExtensions[fragmentOffset_ieextensions : fragmentOffset_ieextensions+fragmentLength_ieextensions] {
				if err := s04.BridgeSystemInformationExtIEsExtFieldMethodMarshalAPERTo(&elem, bb, len(fresh) != 0 && fresh[0]); err != nil {
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

// UnmarshalAPER decodes SystemInformationElem from APER format.
func (v *SystemInformationElem) unmarshalAPERLegacy(data []byte) error {
	return v.unmarshalAPERWithOptions(data, aper.DecodeState{})
}

// UnmarshalAPERWithOptions decodes SystemInformationElem with explicit receiver options:
// TruncatedExtensionTolerance, ExtensionRecoveryTolerance and
// MaxZeroWidthCharacters (see
// aper.BitBuffer.SetDecodeOptionsAligned).
func (v *SystemInformationElem) unmarshalAPERWithOptions(data []byte, options aper.DecodeState) error {
	bb := aper.NewCompleteDecodeBuffer(data, options)
	if err := bb.SetDecodeOptionsAligned(options); err != nil {
		return runtime.WrapDecodePath(err, "SystemInformationElem")
	}
	bb.EnterComponent("SystemInformationElem")
	if err := v.unmarshalAPERFrom(bb); err != nil {
		return runtime.WrapDecodePath(err, "SystemInformationElem")
	}
	padding, err := aper.CaptureFinalBits(bb, "SystemInformationElem")
	if err != nil {
		return runtime.WrapDecodePath(err, "SystemInformationElem")
	}
	v.perPadding = padding.WithRecords(v.perPadding)
	return nil
}
func (v *SystemInformationElem) unmarshalAPERFrom(bb *aper.BitBuffer) error {
	replayStart := bb.BitPos()
	replayUsage := bb.Usage()

	if err := bb.EnterDecodeValue(); err != nil {
		return err
	}
	defer bb.LeaveDecodeValue()
	*v = SystemInformationElem{}
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
	val_broadcastperiodicity, err := aper.DecodeEnumeratedAligned(bb, 7, true, aper.EnumerationSource{KnownExtensions: 0, Path: "BroadcastPeriodicity"})
	if err != nil {
		return runtime.WrapDecodePath(err, "BroadcastPeriodicity")
	}
	v.BroadcastPeriodicity = s00.BroadcastPeriodicity(val_broadcastperiodicity)
	toleranceMark_possibs := bb.EnterComponent("PosSIBs")
	v.PosSIBs = make(s10.PosSIBs, 0)
	_, errCollection_possibs := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 32, HasUpper: true}, true, func(fragmentOffset_possibs, fragmentLength_possibs int64) error {
		// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
		if fragmentOffset_possibs < 0 || fragmentLength_possibs < 0 || fragmentLength_possibs > int64(^uint(0)>>1) || fragmentOffset_possibs > int64(^uint(0)>>1)-fragmentLength_possibs {
			return fmt.Errorf("collection fragment count out of range")
		}
		for i := int64(0); i < fragmentLength_possibs; i++ {
			var elem s10.PosSIBsElem
			elementMark := bb.EnterIndex(fragmentOffset_possibs + i)
			if err := s10.BridgePosSIBsElemMethodUnmarshalAPERFrom(&elem, bb); err != nil {
				return runtime.WrapDecodePath(err, fmt.Sprintf("PosSIBs[%d]", fragmentOffset_possibs+i))
			}
			bb.LeaveComponent(elementMark)
			if next, err := aper.AppendValues(bb, v.PosSIBs, elem); err != nil {
				return err
			} else {
				v.PosSIBs = next
			}
		}
		return nil
	})
	if errCollection_possibs != nil {
		return runtime.WrapDecodePath(errCollection_possibs, "PosSIBs")
	}
	bb.LeaveComponent(toleranceMark_possibs)
	if opt_ieextensions {
		toleranceMark_ieextensions := bb.EnterComponent("IEExtensions")
		tmp_ieextensions := make(s04.SystemInformationExtIEsExtContainer, 0)
		_, errCollection_ieextensions := aper.DecodeCollection(bb, aper.SizeConstraint{Lower: 1, HasLower: true, Upper: 65535, HasUpper: true}, true, func(fragmentOffset_ieextensions, fragmentLength_ieextensions int64) error {
			// arithmetic pattern APER_FRAGMENT_LOOP_1: nonnegative fragment offset and length fit host int; gen/codegen_aper.go:1116
			if fragmentOffset_ieextensions < 0 || fragmentLength_ieextensions < 0 || fragmentLength_ieextensions > int64(^uint(0)>>1) || fragmentOffset_ieextensions > int64(^uint(0)>>1)-fragmentLength_ieextensions {
				return fmt.Errorf("collection fragment count out of range")
			}
			for i := int64(0); i < fragmentLength_ieextensions; i++ {
				var elem s04.SystemInformationExtIEsExtField
				elementMark := bb.EnterIndex(fragmentOffset_ieextensions + i)
				if err := s04.BridgeSystemInformationExtIEsExtFieldMethodUnmarshalAPERFrom(&elem, bb); err != nil {
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

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *AssistanceInformation) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "AssistanceInformation", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v AssistanceInformation) WithoutReplay() AssistanceInformation {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero AssistanceInformation
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultUTRANItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultUTRANItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultUTRANItem) WithoutReplay() ResultUTRANItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ResultUTRANItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *ResultsPerSSBIndexItem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "ResultsPerSSBIndexItem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v ResultsPerSSBIndexItem) WithoutReplay() ResultsPerSSBIndexItem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero ResultsPerSSBIndexItem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// ReceivedForm returns an owned view of the complete value's original bytes.
func (v *SystemInformationElem) ReceivedForm() aper.ReceivedForm {
	if v == nil {
		return aper.ReceivedForm{}
	}
	return s05.BridgeReceivedFormAt(v.received, v.receivedBytes, "SystemInformationElem", v.receivedBytes.ContentLocation(), v.perPadding)
}

// WithoutReplay clears private received framing for a fresh complete encoding.
func (v SystemInformationElem) WithoutReplay() SystemInformationElem {
	v.withoutReplay = true
	v.received = false
	v.receivedBytes = aper.WireSpan{}
	var zero SystemInformationElem
	v.perPadding = zero.perPadding
	v.perExtPadding = nil
	return v
}

// Extensions returns owned unknown sequence additions.
func (v *AssistanceInformation) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *AssistanceInformation) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AssistanceInformation.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AssistanceInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *AssistanceInformation) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("AssistanceInformation.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("AssistanceInformation.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ResultUTRANItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ResultUTRANItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResultUTRANItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResultUTRANItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ResultUTRANItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResultUTRANItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResultUTRANItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *ResultsPerSSBIndexItem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *ResultsPerSSBIndexItem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResultsPerSSBIndexItem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResultsPerSSBIndexItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *ResultsPerSSBIndexItem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("ResultsPerSSBIndexItem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("ResultsPerSSBIndexItem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// Extensions returns owned unknown sequence additions.
func (v *SystemInformationElem) Extensions() []aper.SequenceExtension {
	if v == nil {
		return nil
	}
	views := aper.SequenceExtensionViews(v.extPresent, aper.ExtensionContents(v.extData, v.extWire), v.extOrigin)
	return views
}

// SetExtension stores an owned unknown sequence addition.
func (v *SystemInformationElem) SetExtension(index uint64, contents []byte) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SystemInformationElem.Extensions[%d]", index))
	}
	if err := aper.SetSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index, contents); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SystemInformationElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// RemoveExtension removes one unknown sequence addition.
func (v *SystemInformationElem) RemoveExtension(index uint64) error {
	if v == nil {
		return runtime.WrapDecodePath(aper.ErrInvalidValue, fmt.Sprintf("SystemInformationElem.Extensions[%d]", index))
	}
	if err := aper.RemoveSequenceExtension(&v.extCount, &v.extPresent, &v.extData, &v.extOrigin, index); err != nil {
		return runtime.WrapDecodePath(err, fmt.Sprintf("SystemInformationElem.Extensions[%d]", index))
	}
	if index < uint64(len(v.extWire)) {
		v.extWire[index] = aper.WireSpan{}
	}
	v.perExtPadding = nil
	return nil
}

// MarshalAPER encodes the complete value, replaying unchanged received bytes unless fresh encoding is requested.
func (v *AssistanceInformation) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "AssistanceInformation")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "AssistanceInformation")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaAssistanceInformation(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "AssistanceInformation")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "AssistanceInformation")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "AssistanceInformation")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "AssistanceInformation")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "AssistanceInformation")
}
func (v *AssistanceInformation) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *AssistanceInformation) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *AssistanceInformation) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *AssistanceInformation) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *AssistanceInformation) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ResultUTRANItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ResultUTRANItem")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ResultUTRANItem")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaResultUTRANItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ResultUTRANItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ResultUTRANItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ResultUTRANItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ResultUTRANItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ResultUTRANItem")
}
func (v *ResultUTRANItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultUTRANItem) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultUTRANItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *ResultUTRANItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultUTRANItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *ResultsPerSSBIndexItem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "ResultsPerSSBIndexItem")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "ResultsPerSSBIndexItem")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaResultsPerSSBIndexItem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "ResultsPerSSBIndexItem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "ResultsPerSSBIndexItem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "ResultsPerSSBIndexItem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "ResultsPerSSBIndexItem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "ResultsPerSSBIndexItem")
}
func (v *ResultsPerSSBIndexItem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *ResultsPerSSBIndexItem) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *ResultsPerSSBIndexItem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *ResultsPerSSBIndexItem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *ResultsPerSSBIndexItem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *SystemInformationElem) MarshalAPER(options ...aper.EncodeOption) ([]byte, error) {
	if v == nil {
		return nil, aper.OperationError(aper.ErrInvalidValue, "SystemInformationElem")
	}
	fresh := v.withoutReplay || aper.EncodeWithoutReplay(options...)
	var budget aper.DecodeBudget
	if err := aper.InitEncodeBudget(&budget, options...); err != nil {
		return nil, aper.OperationError(err, "SystemInformationElem")
	}
	if !fresh && v.replay.Present() {

		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(&budget))
		BridgeCompareLPPaSystemInformationElem(v, &s)
		if err := s.ChargeComparison(&budget); err != nil {
			return nil, aper.OperationError(err, "SystemInformationElem")
		}
		if s.Unchanged(v.replay) && v.received {
			if err := v.replay.ApplyReplay(&budget); err != nil {
				return nil, aper.OperationError(err, "SystemInformationElem")
			}
			out, err := v.receivedBytes.ReplayBytes(&budget)
			return out, aper.OperationError(err, "SystemInformationElem")
		}
		out, err := v.marshalAPERChangedValue(budget, fresh, s.Plan())
		return out, aper.OperationError(err, "SystemInformationElem")
	}
	out, err := v.marshalAPERFreshValue(budget, fresh)
	return out, aper.OperationError(err, "SystemInformationElem")
}
func (v *SystemInformationElem) marshalAPERChangedValue(budget aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(&budget, fresh, plan)
}
func (v *SystemInformationElem) marshalAPERFreshValue(budget aper.DecodeBudget, fresh bool) ([]byte, error) {
	return v.marshalAPERBudget(&budget, fresh)
}
func (v *SystemInformationElem) marshalAPERBudget(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
	if v == nil {
		return nil, aper.ErrInvalidValue
	}
	fresh = fresh || v.withoutReplay
	bb := aper.NewBudgetBuffer(budget)
	if !fresh && v.replay.Present() && bb.ReplayPlan() == nil {
		s := aper.NewSemanticComparison(v.replay, aper.ComparisonBudget(budget))
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
func (v *SystemInformationElem) marshalAPERChanged(budget *aper.DecodeBudget, fresh bool, plan aper.ReplayPlan) ([]byte, error) {
	previous := aper.NewBudgetBuffer(budget).ReplayPlan()
	budget.SetReplayPlan(&plan)
	defer budget.SetReplayPlan(previous)
	return v.marshalAPERPlanned(budget, fresh)
}
func (v *SystemInformationElem) marshalAPERPlanned(budget *aper.DecodeBudget, fresh bool) ([]byte, error) {
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
func (v *AssistanceInformation) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "AssistanceInformation")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded AssistanceInformation
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaAssistanceInformation(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = AssistanceInformation{}
		return report, aper.OperationError(err, "AssistanceInformation")
	}
	*v = decoded
	return report, aper.OperationError(nil, "AssistanceInformation")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultUTRANItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ResultUTRANItem")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ResultUTRANItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultUTRANItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ResultUTRANItem{}
		return report, aper.OperationError(err, "ResultUTRANItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ResultUTRANItem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *ResultsPerSSBIndexItem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "ResultsPerSSBIndexItem")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded ResultsPerSSBIndexItem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaResultsPerSSBIndexItem(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = ResultsPerSSBIndexItem{}
		return report, aper.OperationError(err, "ResultsPerSSBIndexItem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "ResultsPerSSBIndexItem")
}

// UnmarshalAPER decodes one complete value and returns a per-call report.
func (v *SystemInformationElem) UnmarshalAPER(data []byte, options ...aper.DecodeOption) (aper.DecodeReport, error) {
	if v == nil {
		return aper.DecodeReport{}, aper.OperationError(aper.ErrInvalidValue, "SystemInformationElem")
	}
	data, settings := aper.OwnDecodeInputOptions(data, options...)
	var decoded SystemInformationElem
	err := decoded.unmarshalAPERWithOptions(data, settings)
	if err == nil {
		decoded.received = true
		decoded.receivedBytes = aper.OriginalWire(data)
		s := aper.SemanticCaptureFor(settings)
		BridgeCaptureLPPaSystemInformationElem(&decoded, &s)
	}
	report, err := aper.FinishDecode(settings, err)
	if err != nil {
		*v = SystemInformationElem{}
		return report, aper.OperationError(err, "SystemInformationElem")
	}
	*v = decoded
	return report, aper.OperationError(nil, "SystemInformationElem")
}
func BridgeCaptureLPPaAssistanceInformation(v *AssistanceInformation, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	BridgeCaptureLPPaSystemInformation(&v.SystemInformation, s)
	s.Bool(v.IEExtensions == nil)
	s04.BridgeAssistanceInformationExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaAssistanceInformation(v *AssistanceInformation, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	BridgeCompareLPPaSystemInformation(&v.SystemInformation, s)
	s.Bool(v.IEExtensions == nil)
	s04.BridgeAssistanceInformationExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaAssistanceInformationControlIEValue(v *AssistanceInformationControlIEValue, s *aper.SemanticCapture) {
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
		case s00.ProtocolIEID(22):
			{
				f := s.Begin()
				s.Bool(v.rowAssistanceInformation == nil)
				if v.rowAssistanceInformation != nil {
					BridgeCaptureLPPaAssistanceInformation(v.rowAssistanceInformation, s)
				}
				s.End(f, nil, false)
			}
		case s00.ProtocolIEID(23):
			{
				f := s.Begin()
				s.Bool(v.rowBroadcast == nil)
				if v.rowBroadcast != nil {
					s00.BridgeCaptureLPPaBroadcast(v.rowBroadcast, s)
				}
				s.End(f, nil, false)
			}
		}
	}
	s.End(f, &v.replay, v.withoutReplay)
}
func (v AssistanceInformationControlIEValue) captureSnapshot() aper.Snapshot { return v.replay }
func (v AssistanceInformationControlIEValue) captureFraming() uint64 {
	if v.isOpaque && v.opaque != nil {
		return v.opaque.ContentLength()
	}
	return v.received.ByteLength()
}
func (v AssistanceInformationControlIEValue) captureSemantics(s aper.SemanticCapture) AssistanceInformationControlIEValue {
	BridgeCaptureLPPaAssistanceInformationControlIEValue(&v, &s)
	return v
}
func BridgeCompareLPPaAssistanceInformationControlIEValue(v *AssistanceInformationControlIEValue, s *aper.SemanticComparison) {
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
		case s00.ProtocolIEID(22):
			{
				f := s.Begin()
				s.Bool(v.rowAssistanceInformation == nil)
				if v.rowAssistanceInformation != nil {
					BridgeCompareLPPaAssistanceInformation(v.rowAssistanceInformation, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		case s00.ProtocolIEID(23):
			{
				f := s.Begin()
				s.Bool(v.rowBroadcast == nil)
				if v.rowBroadcast != nil {
					s02.BridgeCompareLPPaBroadcast(v.rowBroadcast, s)
				}
				s.End(f, aper.Snapshot{}, false)
			}
		}
	}
	s.End(f, v.replay, v.withoutReplay)
}
func (v AssistanceInformationControlIEValue) compareSemantics(s aper.SemanticComparison) aper.SemanticComparison {
	BridgeCompareLPPaAssistanceInformationControlIEValue(&v, &s)
	return s
}

// WithoutReplay returns a copy that requests fresh encoding of this value and its nested values.
func (v AssistanceInformationControlIEValue) WithoutReplay() AssistanceInformationControlIEValue {
	v.withoutReplay = true
	v.replay = aper.Snapshot{}
	return v
}
func BridgeCaptureLPPaResultUTRAN(v *ResultUTRAN, s *aper.SemanticCapture) {
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
func BridgeCompareLPPaResultUTRAN(v *ResultUTRAN, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaResultUTRANItem(v *ResultUTRANItem, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaUARFCN(&v.UARFCN, s)
	s08.BridgeCaptureLPPaResultUTRANItemPhysCellIDUTRAN(&v.PhysCellIDUTRAN, s)
	s00.BridgeCaptureLPPaUTRARSCP(&v.UTRARSCP, s)
	s00.BridgeCaptureLPPaUTRAEcN0(&v.UTRAEcN0, s)
	s.Bool(v.IEExtensions == nil)
	BridgeResultUTRANItemExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultUTRANItem(v *ResultUTRANItem, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s03.BridgeCompareLPPaUARFCN(&v.UARFCN, s)
	s08.BridgeCompareLPPaResultUTRANItemPhysCellIDUTRAN(&v.PhysCellIDUTRAN, s)
	s03.BridgeCompareLPPaUTRARSCP(&v.UTRARSCP, s)
	s03.BridgeCompareLPPaUTRAEcN0(&v.UTRAEcN0, s)
	s.Bool(v.IEExtensions == nil)
	BridgeResultUTRANItemExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultsPerSSBIndexItem(v *ResultsPerSSBIndexItem, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaSSBIndex(&v.SSBIndex, s)
	{
		f := s.Begin()
		s.Bool(v.SSNRRSRPBeamValue == nil)
		if v.SSNRRSRPBeamValue != nil {
			s00.BridgeCaptureLPPaSSNRRSRP(v.SSNRRSRPBeamValue, s)
		}
		s.End(f, nil, false)
	}
	{
		f := s.Begin()
		s.Bool(v.SSNRRSRQBeamValue == nil)
		if v.SSNRRSRQBeamValue != nil {
			s00.BridgeCaptureLPPaSSNRRSRQ(v.SSNRRSRQBeamValue, s)
		}
		s.End(f, nil, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeResultsPerSSBIndexItemExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaResultsPerSSBIndexItem(v *ResultsPerSSBIndexItem, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s03.BridgeCompareLPPaSSBIndex(&v.SSBIndex, s)
	{
		f := s.Begin()
		s.Bool(v.SSNRRSRPBeamValue == nil)
		if v.SSNRRSRPBeamValue != nil {
			s03.BridgeCompareLPPaSSNRRSRP(v.SSNRRSRPBeamValue, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	{
		f := s.Begin()
		s.Bool(v.SSNRRSRQBeamValue == nil)
		if v.SSNRRSRQBeamValue != nil {
			s03.BridgeCompareLPPaSSNRRSRQ(v.SSNRRSRQBeamValue, s)
		}
		s.End(f, aper.Snapshot{}, false)
	}
	s.Bool(v.IEExtensions == nil)
	BridgeResultsPerSSBIndexItemExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}
func BridgeCaptureLPPaResultsPerSSBIndexList(v *ResultsPerSSBIndexList, s *aper.SemanticCapture) {
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
func BridgeCompareLPPaResultsPerSSBIndexList(v *ResultsPerSSBIndexList, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaSystemInformation(v *SystemInformation, s *aper.SemanticCapture) {
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
func BridgeCompareLPPaSystemInformation(v *SystemInformation, s *aper.SemanticComparison) {
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
		s.End(f, aper.Snapshot{}, false)
	}
	s.End(f, aper.Snapshot{}, false)
}
func BridgeCaptureLPPaSystemInformationElem(v *SystemInformationElem, s *aper.SemanticCapture) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s.Stream(v.stream)
	s00.BridgeCaptureLPPaBroadcastPeriodicity(&v.BroadcastPeriodicity, s)
	s10.BridgeCaptureLPPaPosSIBs(&v.PosSIBs, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSystemInformationExtIEsValueCaptureLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, &v.replay, v.withoutReplay)
}
func BridgeCompareLPPaSystemInformationElem(v *SystemInformationElem, s *aper.SemanticComparison) {
	if s.Failed() {
		return
	}
	f := s.Begin()
	s.Value()
	s02.BridgeCompareLPPaBroadcastPeriodicity(&v.BroadcastPeriodicity, s)
	s10.BridgeCompareLPPaPosSIBs(&v.PosSIBs, s)
	s.Bool(v.IEExtensions == nil)
	BridgeSystemInformationExtIEsValueCompareLPPaProtocolExtensionContainer(&v.IEExtensions, s)
	s.ExtensionData(v.extData, v.extWire)
	s.End(f, v.replay, v.withoutReplay)
}

type AssistanceInformationControlIEValue struct {
	id                       s00.ProtocolIEID
	withoutReplay            bool
	received                 aper.WireSpan
	replay                   aper.Snapshot
	opaque                   *aper.OpaqueOpenType
	isOpaque                 bool
	rowAssistanceInformation *AssistanceInformation
	rowBroadcast             *s00.Broadcast
}

func (v AssistanceInformationControlIEValue) matchesID(id s00.ProtocolIEID, _ *aper.DecodeBudget) bool {
	if v.id != id {
		return false
	}
	if v.isOpaque {
		return v.opaque != nil
	}
	switch id {
	case s00.ProtocolIEID(22):
		return v.rowAssistanceInformation != nil
	case s00.ProtocolIEID(23):
		return v.rowBroadcast != nil
	default:
		return false
	}
}

// Opaque returns the retained opaque open value and reports whether an opaque alternative is selected.
func (v *AssistanceInformationControlIEValue) Opaque() (aper.OpaqueOpenType, bool) {
	if v == nil || !v.isOpaque || v.opaque == nil {
		return aper.OpaqueOpenType{}, false
	}
	return *v.opaque, true
}
func (AssistanceInformationControlIEValue) rule() aper.SourceRule {
	return aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "AssistanceInformationControl-IEs"}}
}
func (AssistanceInformationControlIEValue) reason(id s00.ProtocolIEID) aper.OpaqueReason {
	switch id {
	case s00.ProtocolIEID(22):
		return aper.UnknownSelector
	case s00.ProtocolIEID(23):
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
	case s00.ProtocolIEID(20):
		return aper.NotInTable
	case s00.ProtocolIEID(21):
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

// AsAssistanceInformation returns the selected AssistanceInformation value and reports whether that alternative is active.
func (v *AssistanceInformationControlIEValue) AsAssistanceInformation() (*AssistanceInformation, bool) {
	if v == nil || v.id != s00.ProtocolIEID(22) || v.rowAssistanceInformation == nil {
		return nil, false
	}
	return v.rowAssistanceInformation, true
}

// AsBroadcast returns the selected Broadcast value and reports whether that alternative is active.
func (v *AssistanceInformationControlIEValue) AsBroadcast() (*s00.Broadcast, bool) {
	if v == nil || v.id != s00.ProtocolIEID(23) || v.rowBroadcast == nil {
		return nil, false
	}
	return v.rowBroadcast, true
}
func (v AssistanceInformationControlIEValue) decode(id s00.ProtocolIEID, raw aper.OpaqueOpenType) (AssistanceInformationControlIEValue, error) {
	out := AssistanceInformationControlIEValue{id: id}
	var scope *aper.BitBuffer
	switch id {
	case 22, 23:
		scope = raw.BudgetBuffer()
		if err := scope.EnterOpenType(); err != nil {
			return out, err
		}
		defer scope.LeaveOpenType()
	}
	switch id {
	case s00.ProtocolIEID(22):
		replayUsage := scope.Usage()
		var value AssistanceInformation
		child := raw.ChildDecodeBuffer()
		if err := value.unmarshalAPERFrom(child); err != nil {
			return out, fmt.Errorf("%s %w", "AssistanceInformation:", err)
		}
		padding, err := aper.CaptureFinalBits(child, "AssistanceInformation")
		if err != nil {
			return out, err
		}
		value.perPadding = padding
		value.received = true
		raw.RetainContents(&value.receivedBytes)
		if err := aper.ChargeValue(raw.BudgetBuffer(), value); err != nil {
			return out, err
		}
		out.rowAssistanceInformation = &value
		raw.RetainContents(&out.received)
		out.received.RecordUsage(replayUsage, scope)
	case s00.ProtocolIEID(23):
		replayUsage := scope.Usage()
		bb := raw.ChildDecodeBuffer()
		decoded, err := aper.DecodeEnumeratedAligned(bb, 2, true, aper.EnumerationSource{KnownExtensions: 0, Path: "Broadcast"})
		value := s00.Broadcast(decoded)
		if err != nil {
			return out, fmt.Errorf("%s %w", "Broadcast:", err)
		}
		if _, err := aper.CaptureOpenTypePadding(bb); err != nil {
			return out, err
		}
		out.rowBroadcast = (*s00.Broadcast)(scope.OwnInt64(int64(value)))
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
func (v AssistanceInformationControlIEValue) encode() ([]byte, error) {
	budget, err := aper.EncodeBudget()
	if err != nil {
		return nil, err
	}
	return v.encodeFresh(false, budget)
}
func (v AssistanceInformationControlIEValue) encodeFresh(fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
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
	case s00.ProtocolIEID(22):
		if v.rowAssistanceInformation == nil {
			return nil, fmt.Errorf("%s missing value", "AssistanceInformationControl-IEs.id-Assistance-Information:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
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
	case s00.ProtocolIEID(23):
		if v.rowBroadcast == nil {
			return nil, fmt.Errorf("%s missing value", "AssistanceInformationControl-IEs.id-Broadcast:")
		}
		if !fresh && aper.NewBudgetBuffer(budget).ReplayPlan() != nil && aper.NewBudgetBuffer(budget).ReplayPlan().Unchanged(v.replay) {
			if err := v.replay.ApplyReplay(budget); err != nil {
				return nil, err
			}
			return v.received.ReplayBytes(budget)
		}
		encodeBB := aper.NewBudgetBuffer(budget)
		if err := aper.EncodeEnumeratedAligned(encodeBB, int64(*v.rowBroadcast), 2, true); err != nil {
			return nil, err
		}
		candidate := encodeBB.CompleteBytes()
		return candidate, nil
	default:
		return nil, fmt.Errorf("%s id %d has no value", "AssistanceInformationControlIEValue:", v.id)
	}
}

type AssistanceInformationControlIETable struct{}

func AssistanceInformationControlIEs() AssistanceInformationControlIETable {
	return AssistanceInformationControlIETable{}
}

// ID returns the ASN.1 source assignment identifying this table.
func (AssistanceInformationControlIETable) ID() s00.TableID {
	return func() s00.TableID {
		sealed := s00.TableID{}
		*s00.BridgeTableIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "AssistanceInformationControl-IEs"}
		return sealed
	}()
}
func (AssistanceInformationControlIETable) infoAssistanceInformation() s00.FieldInfo {
	return s00.FieldInfo{Table: AssistanceInformationControlIEs().ID(), ID: s00.ProtocolIEID(22), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "AssistanceInformation"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "AssistanceInformationControl-IEs", Row: "id-Assistance-Information"}}}
}

// AssistanceInformation returns the selected sistanceInformation value and reports whether that alternative is active.
func (t AssistanceInformationControlIETable) AssistanceInformation() AssistanceInformationControlAssistanceInformationIEBinding {
	return AssistanceInformationControlAssistanceInformationIEBinding{info: t.infoAssistanceInformation(), codec: AssistanceInformationValueCodec{path: "AssistanceInformation",
		decode: func(data []byte, options aper.DecodeState) (AssistanceInformation, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty AssistanceInformation
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("AssistanceInformation")
			var zero AssistanceInformationControlIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(22), raw)
			if err != nil {
				var empty AssistanceInformation
				return empty, runtime.WrapDecodePath(err, "AssistanceInformation")
			}
			value, ok := decoded.AsAssistanceInformation()
			if !ok {
				var empty AssistanceInformation
				return empty, fmt.Errorf("binding AssistanceInformationControl-IEs.id-Assistance-Information: no selected value")
			}
			return *value, nil
		},
		encode: func(value AssistanceInformation, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (AssistanceInformationControlIEValue{id: s00.ProtocolIEID(22), rowAssistanceInformation: &value}).encodeFresh(fresh, budget)
		}, capture: func(v AssistanceInformation, options aper.DecodeState) (AssistanceInformation, aper.Snapshot,
		) {
			s := aper.SemanticCaptureFor(options)
			f := s.Begin()
			BridgeCaptureLPPaAssistanceInformation(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.
				End(f, &root, false)
			return v, root
		}, compare: func(v AssistanceInformation, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			BridgeCompareLPPaAssistanceInformation(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}, context: func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:AssistanceInformation"
			return sealed
		}(),
	}, inject: func(value AssistanceInformation) AssistanceInformationControlIEValue {
		return AssistanceInformationControlIEValue{id: s00.ProtocolIEID(22), rowAssistanceInformation: &value}
	}, get: func(value *AssistanceInformationControlIEValue) (*AssistanceInformation, bool) {
		return value.AsAssistanceInformation()
	}}
}
func (AssistanceInformationControlIETable) infoBroadcast() s00.FieldInfo {
	return s00.FieldInfo{Table: AssistanceInformationControlIEs().ID(), ID: s00.ProtocolIEID(23), Criticality: s00.CriticalityReject, Presence: s00.PresenceOptional, ValueType: func() s00.TypeID {
		sealed := s00.TypeID{}
		*s00.BridgeTypeIDFieldSource(&sealed) = aper.SourceAssignment{Module: "LPPA-IEs", Assignment: "Broadcast"}
		return sealed
	}(), Rule: aper.SourceRule{Document: "3GPP TS 36.455", Edition: "V19.0.0", Clause: "§9.3.4", Assignment: aper.SourceAssignment{Module: "LPPA-PDU-Contents", Assignment: "AssistanceInformationControl-IEs", Row: "id-Broadcast"}}}
}

// Broadcast returns the typed binding for the Broadcast row of this table.
func (t AssistanceInformationControlIETable) Broadcast() AssistanceInformationControlBroadcastIEBinding {
	return AssistanceInformationControlBroadcastIEBinding{info: t.infoBroadcast(), codec: func() s00.BroadcastValueCodec {
		sealed := s00.BroadcastValueCodec{}
		*s00.BridgeBroadcastValueCodecFieldPath(&sealed) = "Broadcast"
		*s00.BridgeBroadcastValueCodecFieldDecode(&sealed) = func(data []byte, options aper.DecodeState) (s00.Broadcast, error) {
			raw, err := aper.NewOpaqueOpenTypeWithState(data, options)
			if err != nil {
				var empty s00.Broadcast
				return empty, err
			}
			raw.BudgetBuffer().EnterComponent("Broadcast")
			var zero AssistanceInformationControlIEValue
			decoded, err := zero.decode(s00.ProtocolIEID(23), raw)
			if err != nil {
				var empty s00.Broadcast
				return empty, runtime.WrapDecodePath(err, "Broadcast")
			}
			value, ok := decoded.AsBroadcast()
			if !ok {
				var empty s00.Broadcast
				return empty, fmt.Errorf("binding AssistanceInformationControl-IEs.id-Broadcast: no selected value")
			}
			return *value, nil
		}
		*s00.BridgeBroadcastValueCodecFieldEncode(&sealed) = func(value s00.Broadcast, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
			return (AssistanceInformationControlIEValue{id: s00.ProtocolIEID(23), rowBroadcast: &value}).encodeFresh(fresh, budget)
		}
		*s00.BridgeBroadcastValueCodecFieldCapture(&sealed) = func(v s00.Broadcast, options aper.DecodeState) (s00.Broadcast, aper.Snapshot) {
			s := aper.SemanticCaptureFor(options)
			f := s.
				Begin()
			s00.BridgeCaptureLPPaBroadcast(&v, &s)
			var root aper.Snapshot
			s.OperationCounts()
			s.End(f, &root, false)
			return v, root
		}
		*s00.BridgeBroadcastValueCodecFieldCompare(&sealed) = func(v s00.Broadcast, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
			s := aper.NewSemanticComparison(root, limits)
			f := s.Begin()
			s02.BridgeCompareLPPaBroadcast(&v, &s)
			s.End(f, root, false)
			return s.Plan()
		}
		*s00.BridgeBroadcastValueCodecFieldContext(&sealed) = func() s00.BridgeCodecContext {
			sealed := s00.BridgeCodecContext{}
			*s00.BridgecodecContextFieldSource(&sealed) = "source-value:Broadcast"
			return sealed
		}()
		return sealed
	}(),
		inject: func(value s00.Broadcast) AssistanceInformationControlIEValue {
			return AssistanceInformationControlIEValue{id: s00.ProtocolIEID(23), rowBroadcast: &value}
		}, get: func(value *AssistanceInformationControlIEValue) (*s00.Broadcast, bool) { return value.AsBroadcast() }}
}

// NewOpaque constructs an owned field for an identifier without a typed row in this table.
func (t AssistanceInformationControlIETable) NewOpaque(id s00.ProtocolIEID, criticality s00.Criticality, data []byte) (AssistanceInformationControlIEField, error) {
	if id < 0 || id > 65535 || criticality < 0 || criticality > 2 {
		return AssistanceInformationControlIEField{}, aper.OperationError(fmt.Errorf("invalid opaque IE selector or criticality"), "Opaque")
	}
	switch id {
	case s00.ProtocolIEID(22):
		return AssistanceInformationControlIEField{}, aper.OperationError(fmt.Errorf("known IE id-Assistance-Information requires its typed binding"), "Opaque")
	case s00.ProtocolIEID(23):
		return AssistanceInformationControlIEField{}, aper.OperationError(fmt.Errorf("known IE id-Broadcast requires its typed binding"), "Opaque")
	default:
		budget, err := aper.BuildBudget()
		if err != nil {
			return AssistanceInformationControlIEField{}, aper.OperationError(err, "Opaque")
		}
		opaque, err := aper.BuildOpaqueOpenType(data, budget)
		if err != nil {
			return AssistanceInformationControlIEField{}, aper.OperationError(err, "Opaque")
		}
		retained, err := opaque.Retained(budget)
		if err != nil {
			return AssistanceInformationControlIEField{}, aper.OperationError(err, "Opaque")
		}
		return AssistanceInformationControlIEField{Id: id, Criticality: criticality, Value: AssistanceInformationControlIEValue{id: id, opaque: retained, isOpaque: true}}, aper.OperationError(nil, "Opaque")
	}
}

// AssistanceInformationCodec binds the complete APER value type.
func AssistanceInformationCodec() AssistanceInformationValueCodec {
	return AssistanceInformationControlIEs().AssistanceInformation().Codec()
}

// BroadcastCodec binds the complete APER value type.
func BroadcastCodec() s00.BroadcastValueCodec {
	return AssistanceInformationControlIEs().Broadcast().Codec()
}

// ResultUTRANItemCodec binds the complete source value type.
func ResultUTRANItemCodec() ResultUTRANItemValueCodec {
	return ResultUTRANItemValueCodec{path: "ResultUTRANItem", decode: func(data []byte, options aper.DecodeState) (ResultUTRANItem, error) {
		var value ResultUTRANItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ResultUTRANItem{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ResultUTRANItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ResultUTRANItem, options aper.DecodeState) (ResultUTRANItem, aper.Snapshot) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaResultUTRANItem(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResultUTRANItem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaResultUTRANItem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ResultUTRANItem"
		return sealed
	}(),
	}
}

// ResultsPerSSBIndexItemCodec binds the complete source value type.
func ResultsPerSSBIndexItemCodec() ResultsPerSSBIndexItemValueCodec {
	return ResultsPerSSBIndexItemValueCodec{path: "ResultsPerSSBIndexItem", decode: func(data []byte, options aper.DecodeState) (ResultsPerSSBIndexItem, error) {
		var value ResultsPerSSBIndexItem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return ResultsPerSSBIndexItem{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value ResultsPerSSBIndexItem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v ResultsPerSSBIndexItem, options aper.DecodeState) (ResultsPerSSBIndexItem, aper.Snapshot,

	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaResultsPerSSBIndexItem(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.End(f, &root, false)
		return v, root
	}, compare: func(v ResultsPerSSBIndexItem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaResultsPerSSBIndexItem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:ResultsPerSSBIndexItem"
		return sealed
	}(),
	}
}

// SystemInformationElemCodec binds the complete source value type.
func SystemInformationElemCodec() SystemInformationElemValueCodec {
	return SystemInformationElemValueCodec{path: "SystemInformationElem", decode: func(data []byte, options aper.DecodeState) (SystemInformationElem, error) {
		var value SystemInformationElem
		if err := value.unmarshalAPERWithOptions(data, options); err != nil {
			return SystemInformationElem{}, err
		}
		value.received = true
		value.receivedBytes = aper.OriginalWire(data)
		return value, nil
	}, encode: func(value SystemInformationElem, fresh bool, budget *aper.DecodeBudget) ([]byte, error) {
		return (&value).marshalAPERBudget(budget, fresh)
	}, capture: func(v SystemInformationElem, options aper.DecodeState) (SystemInformationElem, aper.Snapshot,
	) {
		s := aper.SemanticCaptureFor(options)
		f := s.Begin()
		BridgeCaptureLPPaSystemInformationElem(&v, &s)
		var root aper.Snapshot
		s.OperationCounts()
		s.
			End(f, &root, false)
		return v, root
	}, compare: func(v SystemInformationElem, root aper.Snapshot, limits aper.ComparisonLimits) aper.ReplayPlan {
		s := aper.NewSemanticComparison(root, limits)
		f := s.Begin()
		BridgeCompareLPPaSystemInformationElem(&v, &s)
		s.End(f, root, false)
		return s.Plan()
	}, context: func() s00.BridgeCodecContext {
		sealed := s00.BridgeCodecContext{}
		*s00.BridgecodecContextFieldSource(&sealed) = "source-value:SystemInformationElem"
		return sealed
	}(),
	}
}

// Selected returns the decoded value of the active alternative, as the matching As method returns it, or false when the value is opaque or empty.
func (v *AssistanceInformationControlIEValue) Selected() (any, bool) {
	if v == nil || v.isOpaque {
		return nil, false
	}
	switch v.id {
	case 22:
		if v.rowAssistanceInformation != nil {
			return v.rowAssistanceInformation, true
		}
	case 23:
		if v.rowBroadcast != nil {
			return v.rowBroadcast, true
		}
	}
	return nil, false
}

func BridgeAssistanceInformationAPERValueFieldContext(v *AssistanceInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationAPERValueFieldReceived(v *AssistanceInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationAPERValueFieldReplay(v *AssistanceInformationAPERValue) *aper.Snapshot {
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
func BridgeAssistanceInformationControlAssistanceInformationIEBindingFieldInfo(v *AssistanceInformationControlAssistanceInformationIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeAssistanceInformationControlAssistanceInformationIEBindingFieldInject(v *AssistanceInformationControlAssistanceInformationIEBinding) *func(AssistanceInformation) AssistanceInformationControlIEValue {
	return &v.inject
}
func BridgeAssistanceInformationControlBroadcastIEBindingFieldCodec(v *AssistanceInformationControlBroadcastIEBinding) *s00.BroadcastValueCodec {
	return &v.codec
}
func BridgeAssistanceInformationControlBroadcastIEBindingFieldGet(v *AssistanceInformationControlBroadcastIEBinding) *func(*AssistanceInformationControlIEValue) (*s00.Broadcast, bool) {
	return &v.get
}
func BridgeAssistanceInformationControlBroadcastIEBindingFieldInfo(v *AssistanceInformationControlBroadcastIEBinding) *s00.FieldInfo {
	return &v.info
}
func BridgeAssistanceInformationControlBroadcastIEBindingFieldInject(v *AssistanceInformationControlBroadcastIEBinding) *func(s00.Broadcast) AssistanceInformationControlIEValue {
	return &v.inject
}
func BridgeAssistanceInformationControlIEFieldFieldReceived(v *AssistanceInformationControlIEField) *aper.CompletePadding {
	return &v.received
}
func BridgeAssistanceInformationControlIEFieldFieldReplay(v *AssistanceInformationControlIEField) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationControlIEFieldFieldStream(v *AssistanceInformationControlIEField) *aper.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationControlIEFieldFieldWithoutReplay(v *AssistanceInformationControlIEField) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationControlIEFieldMethodMarshalAPERTo(v *AssistanceInformationControlIEField, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationControlIEFieldMethodUnmarshalAPERFrom(v *AssistanceInformationControlIEField, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationControlIETableMethodInfoAssistanceInformation(v AssistanceInformationControlIETable) s00.FieldInfo {
	return v.infoAssistanceInformation()
}
func BridgeAssistanceInformationControlIETableMethodInfoBroadcast(v AssistanceInformationControlIETable) s00.FieldInfo {
	return v.infoBroadcast()
}
func BridgeAssistanceInformationControlIEValueFieldId(v *AssistanceInformationControlIEValue) *s00.ProtocolIEID {
	return &v.id
}
func BridgeAssistanceInformationControlIEValueFieldIsOpaque(v *AssistanceInformationControlIEValue) *bool {
	return &v.isOpaque
}
func BridgeAssistanceInformationControlIEValueFieldOpaque(v *AssistanceInformationControlIEValue) **aper.OpaqueOpenType {
	return &v.opaque
}
func BridgeAssistanceInformationControlIEValueFieldReceived(v *AssistanceInformationControlIEValue) *aper.WireSpan {
	return &v.received
}
func BridgeAssistanceInformationControlIEValueFieldReplay(v *AssistanceInformationControlIEValue) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationControlIEValueFieldRowAssistanceInformation(v *AssistanceInformationControlIEValue) **AssistanceInformation {
	return &v.rowAssistanceInformation
}
func BridgeAssistanceInformationControlIEValueFieldRowBroadcast(v *AssistanceInformationControlIEValue) **s00.Broadcast {
	return &v.rowBroadcast
}
func BridgeAssistanceInformationControlIEValueFieldWithoutReplay(v *AssistanceInformationControlIEValue) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationControlIEValueMethodCaptureFraming(v AssistanceInformationControlIEValue) uint64 {
	return v.captureFraming()
}
func BridgeAssistanceInformationControlIEValueMethodCaptureSemantics(v AssistanceInformationControlIEValue, a0 aper.SemanticCapture) AssistanceInformationControlIEValue {
	return v.captureSemantics(a0)
}
func BridgeAssistanceInformationControlIEValueMethodCaptureSnapshot(v AssistanceInformationControlIEValue) aper.Snapshot {
	return v.captureSnapshot()
}
func BridgeAssistanceInformationControlIEValueMethodCompareSemantics(v AssistanceInformationControlIEValue, a0 aper.SemanticComparison) aper.SemanticComparison {
	return v.compareSemantics(a0)
}
func BridgeAssistanceInformationControlIEValueMethodDecode(v AssistanceInformationControlIEValue, a0 s00.ProtocolIEID, a1 aper.OpaqueOpenType) (AssistanceInformationControlIEValue, error) {
	return v.decode(a0, a1)
}
func BridgeAssistanceInformationControlIEValueMethodEncode(v AssistanceInformationControlIEValue) ([]byte, error) {
	return v.encode()
}
func BridgeAssistanceInformationControlIEValueMethodEncodeFresh(v AssistanceInformationControlIEValue, a0 bool, a1 *aper.DecodeBudget) ([]byte, error) {
	return v.encodeFresh(a0, a1)
}
func BridgeAssistanceInformationControlIEValueMethodMatchesID(v AssistanceInformationControlIEValue, a0 s00.ProtocolIEID, a1 *aper.DecodeBudget) bool {
	return v.matchesID(a0, a1)
}
func BridgeAssistanceInformationControlIEValueMethodReason(v AssistanceInformationControlIEValue, a0 s00.ProtocolIEID) aper.OpaqueReason {
	return v.reason(a0)
}
func BridgeAssistanceInformationControlIEValueMethodRule(v AssistanceInformationControlIEValue) aper.SourceRule {
	return v.rule()
}
func BridgeAssistanceInformationFieldExtCount(v *AssistanceInformation) *int64   { return &v.extCount }
func BridgeAssistanceInformationFieldExtData(v *AssistanceInformation) *[][]byte { return &v.extData }
func BridgeAssistanceInformationFieldExtOrigin(v *AssistanceInformation) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeAssistanceInformationFieldExtPresent(v *AssistanceInformation) *[]bool {
	return &v.extPresent
}
func BridgeAssistanceInformationFieldExtWire(v *AssistanceInformation) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeAssistanceInformationFieldIEExtensionsIndef(v *AssistanceInformation) *bool {
	return &v.iEExtensionsIndef
}
func BridgeAssistanceInformationFieldPerExtPadding(v *AssistanceInformation) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeAssistanceInformationFieldPerPadding(v *AssistanceInformation) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeAssistanceInformationFieldReceived(v *AssistanceInformation) *bool { return &v.received }
func BridgeAssistanceInformationFieldReceivedBytes(v *AssistanceInformation) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeAssistanceInformationFieldReplay(v *AssistanceInformation) *aper.Snapshot {
	return &v.replay
}
func BridgeAssistanceInformationFieldStream(v *AssistanceInformation) *aper.WireSpan {
	return &v.stream
}
func BridgeAssistanceInformationFieldSystemInformationIndef(v *AssistanceInformation) *bool {
	return &v.systemInformationIndef
}
func BridgeAssistanceInformationFieldWithoutReplay(v *AssistanceInformation) *bool {
	return &v.withoutReplay
}
func BridgeAssistanceInformationMethodMarshalAPERBudget(v *AssistanceInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeAssistanceInformationMethodMarshalAPERChanged(v *AssistanceInformation, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeAssistanceInformationMethodMarshalAPERChangedValue(v *AssistanceInformation, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeAssistanceInformationMethodMarshalAPERFreshValue(v *AssistanceInformation, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeAssistanceInformationMethodMarshalAPERLegacy(v *AssistanceInformation) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeAssistanceInformationMethodMarshalAPERPlanned(v *AssistanceInformation, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeAssistanceInformationMethodMarshalAPERTo(v *AssistanceInformation, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeAssistanceInformationMethodUnmarshalAPERFrom(v *AssistanceInformation, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeAssistanceInformationMethodUnmarshalAPERLegacy(v *AssistanceInformation, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeAssistanceInformationMethodUnmarshalAPERWithOptions(v *AssistanceInformation, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeAssistanceInformationValueCodecFieldCapture(v *AssistanceInformationValueCodec) *func(AssistanceInformation, aper.DecodeState) (AssistanceInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeAssistanceInformationValueCodecFieldCompare(v *AssistanceInformationValueCodec) *func(AssistanceInformation, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeAssistanceInformationValueCodecFieldContext(v *AssistanceInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeAssistanceInformationValueCodecFieldDecode(v *AssistanceInformationValueCodec) *func([]byte, aper.DecodeState) (AssistanceInformation, error) {
	return &v.decode
}
func BridgeAssistanceInformationValueCodecFieldEncode(v *AssistanceInformationValueCodec) *func(AssistanceInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeAssistanceInformationValueCodecFieldPath(v *AssistanceInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeAssistanceInformationValueCodecMethodEncodeBudget(v AssistanceInformationValueCodec, a0 AssistanceInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeAssistanceInformationValueCodecMethodEncodeChanged(v AssistanceInformationValueCodec, a0 AssistanceInformation, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultUTRANAPERValueFieldContext(v *ResultUTRANAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultUTRANAPERValueFieldReceived(v *ResultUTRANAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResultUTRANAPERValueFieldReplay(v *ResultUTRANAPERValue) *aper.Snapshot { return &v.replay }
func BridgeResultUTRANAPERValueFieldWithoutReplay(v *ResultUTRANAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultUTRANItemAPERValueFieldContext(v *ResultUTRANItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultUTRANItemAPERValueFieldReceived(v *ResultUTRANItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResultUTRANItemAPERValueFieldReplay(v *ResultUTRANItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResultUTRANItemAPERValueFieldWithoutReplay(v *ResultUTRANItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultUTRANItemFieldExtCount(v *ResultUTRANItem) *int64   { return &v.extCount }
func BridgeResultUTRANItemFieldExtData(v *ResultUTRANItem) *[][]byte { return &v.extData }
func BridgeResultUTRANItemFieldExtOrigin(v *ResultUTRANItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeResultUTRANItemFieldExtPresent(v *ResultUTRANItem) *[]bool       { return &v.extPresent }
func BridgeResultUTRANItemFieldExtWire(v *ResultUTRANItem) *[]aper.WireSpan { return &v.extWire }
func BridgeResultUTRANItemFieldIEExtensionsIndef(v *ResultUTRANItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeResultUTRANItemFieldPerExtPadding(v *ResultUTRANItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeResultUTRANItemFieldPerPadding(v *ResultUTRANItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeResultUTRANItemFieldReceived(v *ResultUTRANItem) *bool { return &v.received }
func BridgeResultUTRANItemFieldReceivedBytes(v *ResultUTRANItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeResultUTRANItemFieldReplay(v *ResultUTRANItem) *aper.Snapshot { return &v.replay }
func BridgeResultUTRANItemFieldStream(v *ResultUTRANItem) *aper.WireSpan { return &v.stream }
func BridgeResultUTRANItemFieldWithoutReplay(v *ResultUTRANItem) *bool   { return &v.withoutReplay }
func BridgeResultUTRANItemMethodMarshalAPERBudget(v *ResultUTRANItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultUTRANItemMethodMarshalAPERChanged(v *ResultUTRANItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultUTRANItemMethodMarshalAPERChangedValue(v *ResultUTRANItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultUTRANItemMethodMarshalAPERFreshValue(v *ResultUTRANItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultUTRANItemMethodMarshalAPERLegacy(v *ResultUTRANItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultUTRANItemMethodMarshalAPERPlanned(v *ResultUTRANItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultUTRANItemMethodMarshalAPERTo(v *ResultUTRANItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultUTRANItemMethodUnmarshalAPERFrom(v *ResultUTRANItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultUTRANItemMethodUnmarshalAPERLegacy(v *ResultUTRANItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultUTRANItemMethodUnmarshalAPERWithOptions(v *ResultUTRANItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultUTRANItemValueCodecFieldCapture(v *ResultUTRANItemValueCodec) *func(ResultUTRANItem, aper.DecodeState) (ResultUTRANItem, aper.Snapshot) {
	return &v.capture
}
func BridgeResultUTRANItemValueCodecFieldCompare(v *ResultUTRANItemValueCodec) *func(ResultUTRANItem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeResultUTRANItemValueCodecFieldContext(v *ResultUTRANItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultUTRANItemValueCodecFieldDecode(v *ResultUTRANItemValueCodec) *func([]byte, aper.DecodeState) (ResultUTRANItem, error) {
	return &v.decode
}
func BridgeResultUTRANItemValueCodecFieldEncode(v *ResultUTRANItemValueCodec) *func(ResultUTRANItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultUTRANItemValueCodecFieldPath(v *ResultUTRANItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeResultUTRANItemValueCodecMethodEncodeBudget(v ResultUTRANItemValueCodec, a0 ResultUTRANItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultUTRANItemValueCodecMethodEncodeChanged(v ResultUTRANItemValueCodec, a0 ResultUTRANItem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultUTRANValueCodecFieldCapture(v *ResultUTRANValueCodec) *func(ResultUTRAN, aper.DecodeState) (ResultUTRAN, aper.Snapshot) {
	return &v.capture
}
func BridgeResultUTRANValueCodecFieldCompare(v *ResultUTRANValueCodec) *func(ResultUTRAN, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeResultUTRANValueCodecFieldContext(v *ResultUTRANValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultUTRANValueCodecFieldDecode(v *ResultUTRANValueCodec) *func([]byte, aper.DecodeState) (ResultUTRAN, error) {
	return &v.decode
}
func BridgeResultUTRANValueCodecFieldEncode(v *ResultUTRANValueCodec) *func(ResultUTRAN, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultUTRANValueCodecFieldPath(v *ResultUTRANValueCodec) *aper.Path { return &v.path }
func BridgeResultUTRANValueCodecMethodEncodeBudget(v ResultUTRANValueCodec, a0 ResultUTRAN, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultUTRANValueCodecMethodEncodeChanged(v ResultUTRANValueCodec, a0 ResultUTRAN, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultsPerSSBIndexItemAPERValueFieldContext(v *ResultsPerSSBIndexItemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultsPerSSBIndexItemAPERValueFieldReceived(v *ResultsPerSSBIndexItemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResultsPerSSBIndexItemAPERValueFieldReplay(v *ResultsPerSSBIndexItemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResultsPerSSBIndexItemAPERValueFieldWithoutReplay(v *ResultsPerSSBIndexItemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultsPerSSBIndexItemFieldExtCount(v *ResultsPerSSBIndexItem) *int64   { return &v.extCount }
func BridgeResultsPerSSBIndexItemFieldExtData(v *ResultsPerSSBIndexItem) *[][]byte { return &v.extData }
func BridgeResultsPerSSBIndexItemFieldExtOrigin(v *ResultsPerSSBIndexItem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeResultsPerSSBIndexItemFieldExtPresent(v *ResultsPerSSBIndexItem) *[]bool {
	return &v.extPresent
}
func BridgeResultsPerSSBIndexItemFieldExtWire(v *ResultsPerSSBIndexItem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeResultsPerSSBIndexItemFieldIEExtensionsIndef(v *ResultsPerSSBIndexItem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeResultsPerSSBIndexItemFieldPerExtPadding(v *ResultsPerSSBIndexItem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeResultsPerSSBIndexItemFieldPerPadding(v *ResultsPerSSBIndexItem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeResultsPerSSBIndexItemFieldReceived(v *ResultsPerSSBIndexItem) *bool { return &v.received }
func BridgeResultsPerSSBIndexItemFieldReceivedBytes(v *ResultsPerSSBIndexItem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeResultsPerSSBIndexItemFieldReplay(v *ResultsPerSSBIndexItem) *aper.Snapshot {
	return &v.replay
}
func BridgeResultsPerSSBIndexItemFieldStream(v *ResultsPerSSBIndexItem) *aper.WireSpan {
	return &v.stream
}
func BridgeResultsPerSSBIndexItemFieldWithoutReplay(v *ResultsPerSSBIndexItem) *bool {
	return &v.withoutReplay
}
func BridgeResultsPerSSBIndexItemMethodMarshalAPERBudget(v *ResultsPerSSBIndexItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeResultsPerSSBIndexItemMethodMarshalAPERChanged(v *ResultsPerSSBIndexItem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeResultsPerSSBIndexItemMethodMarshalAPERChangedValue(v *ResultsPerSSBIndexItem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeResultsPerSSBIndexItemMethodMarshalAPERFreshValue(v *ResultsPerSSBIndexItem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeResultsPerSSBIndexItemMethodMarshalAPERLegacy(v *ResultsPerSSBIndexItem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeResultsPerSSBIndexItemMethodMarshalAPERPlanned(v *ResultsPerSSBIndexItem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeResultsPerSSBIndexItemMethodMarshalAPERTo(v *ResultsPerSSBIndexItem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeResultsPerSSBIndexItemMethodUnmarshalAPERFrom(v *ResultsPerSSBIndexItem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeResultsPerSSBIndexItemMethodUnmarshalAPERLegacy(v *ResultsPerSSBIndexItem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeResultsPerSSBIndexItemMethodUnmarshalAPERWithOptions(v *ResultsPerSSBIndexItem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeResultsPerSSBIndexItemValueCodecFieldCapture(v *ResultsPerSSBIndexItemValueCodec) *func(ResultsPerSSBIndexItem, aper.DecodeState) (ResultsPerSSBIndexItem, aper.Snapshot) {
	return &v.capture
}
func BridgeResultsPerSSBIndexItemValueCodecFieldCompare(v *ResultsPerSSBIndexItemValueCodec) *func(ResultsPerSSBIndexItem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeResultsPerSSBIndexItemValueCodecFieldContext(v *ResultsPerSSBIndexItemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultsPerSSBIndexItemValueCodecFieldDecode(v *ResultsPerSSBIndexItemValueCodec) *func([]byte, aper.DecodeState) (ResultsPerSSBIndexItem, error) {
	return &v.decode
}
func BridgeResultsPerSSBIndexItemValueCodecFieldEncode(v *ResultsPerSSBIndexItemValueCodec) *func(ResultsPerSSBIndexItem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultsPerSSBIndexItemValueCodecFieldPath(v *ResultsPerSSBIndexItemValueCodec) *aper.Path {
	return &v.path
}
func BridgeResultsPerSSBIndexItemValueCodecMethodEncodeBudget(v ResultsPerSSBIndexItemValueCodec, a0 ResultsPerSSBIndexItem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultsPerSSBIndexItemValueCodecMethodEncodeChanged(v ResultsPerSSBIndexItemValueCodec, a0 ResultsPerSSBIndexItem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeResultsPerSSBIndexListAPERValueFieldContext(v *ResultsPerSSBIndexListAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultsPerSSBIndexListAPERValueFieldReceived(v *ResultsPerSSBIndexListAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeResultsPerSSBIndexListAPERValueFieldReplay(v *ResultsPerSSBIndexListAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeResultsPerSSBIndexListAPERValueFieldWithoutReplay(v *ResultsPerSSBIndexListAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeResultsPerSSBIndexListValueCodecFieldCapture(v *ResultsPerSSBIndexListValueCodec) *func(ResultsPerSSBIndexList, aper.DecodeState) (ResultsPerSSBIndexList, aper.Snapshot) {
	return &v.capture
}
func BridgeResultsPerSSBIndexListValueCodecFieldCompare(v *ResultsPerSSBIndexListValueCodec) *func(ResultsPerSSBIndexList, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeResultsPerSSBIndexListValueCodecFieldContext(v *ResultsPerSSBIndexListValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeResultsPerSSBIndexListValueCodecFieldDecode(v *ResultsPerSSBIndexListValueCodec) *func([]byte, aper.DecodeState) (ResultsPerSSBIndexList, error) {
	return &v.decode
}
func BridgeResultsPerSSBIndexListValueCodecFieldEncode(v *ResultsPerSSBIndexListValueCodec) *func(ResultsPerSSBIndexList, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeResultsPerSSBIndexListValueCodecFieldPath(v *ResultsPerSSBIndexListValueCodec) *aper.Path {
	return &v.path
}
func BridgeResultsPerSSBIndexListValueCodecMethodEncodeBudget(v ResultsPerSSBIndexListValueCodec, a0 ResultsPerSSBIndexList, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeResultsPerSSBIndexListValueCodecMethodEncodeChanged(v ResultsPerSSBIndexListValueCodec, a0 ResultsPerSSBIndexList, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSystemInformationAPERValueFieldContext(v *SystemInformationAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSystemInformationAPERValueFieldReceived(v *SystemInformationAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSystemInformationAPERValueFieldReplay(v *SystemInformationAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSystemInformationAPERValueFieldWithoutReplay(v *SystemInformationAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSystemInformationElemAPERValueFieldContext(v *SystemInformationElemAPERValue) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSystemInformationElemAPERValueFieldReceived(v *SystemInformationElemAPERValue) *aper.WireSpan {
	return &v.received
}
func BridgeSystemInformationElemAPERValueFieldReplay(v *SystemInformationElemAPERValue) *aper.Snapshot {
	return &v.replay
}
func BridgeSystemInformationElemAPERValueFieldWithoutReplay(v *SystemInformationElemAPERValue) *bool {
	return &v.withoutReplay
}
func BridgeSystemInformationElemFieldExtCount(v *SystemInformationElem) *int64   { return &v.extCount }
func BridgeSystemInformationElemFieldExtData(v *SystemInformationElem) *[][]byte { return &v.extData }
func BridgeSystemInformationElemFieldExtOrigin(v *SystemInformationElem) *[]aper.OpaqueOrigin {
	return &v.extOrigin
}
func BridgeSystemInformationElemFieldExtPresent(v *SystemInformationElem) *[]bool {
	return &v.extPresent
}
func BridgeSystemInformationElemFieldExtWire(v *SystemInformationElem) *[]aper.WireSpan {
	return &v.extWire
}
func BridgeSystemInformationElemFieldIEExtensionsIndef(v *SystemInformationElem) *bool {
	return &v.iEExtensionsIndef
}
func BridgeSystemInformationElemFieldPerExtPadding(v *SystemInformationElem) *[]aper.CompletePadding {
	return &v.perExtPadding
}
func BridgeSystemInformationElemFieldPerPadding(v *SystemInformationElem) *aper.FinalPadding {
	return &v.perPadding
}
func BridgeSystemInformationElemFieldPosSIBsIndef(v *SystemInformationElem) *bool {
	return &v.posSIBsIndef
}
func BridgeSystemInformationElemFieldReceived(v *SystemInformationElem) *bool { return &v.received }
func BridgeSystemInformationElemFieldReceivedBytes(v *SystemInformationElem) *aper.WireSpan {
	return &v.receivedBytes
}
func BridgeSystemInformationElemFieldReplay(v *SystemInformationElem) *aper.Snapshot {
	return &v.replay
}
func BridgeSystemInformationElemFieldStream(v *SystemInformationElem) *aper.WireSpan {
	return &v.stream
}
func BridgeSystemInformationElemFieldWithoutReplay(v *SystemInformationElem) *bool {
	return &v.withoutReplay
}
func BridgeSystemInformationElemMethodMarshalAPERBudget(v *SystemInformationElem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERBudget(a0, a1)
}
func BridgeSystemInformationElemMethodMarshalAPERChanged(v *SystemInformationElem, a0 *aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChanged(a0, a1, a2)
}
func BridgeSystemInformationElemMethodMarshalAPERChangedValue(v *SystemInformationElem, a0 aper.DecodeBudget, a1 bool, a2 aper.ReplayPlan) ([]byte, error) {
	return v.marshalAPERChangedValue(a0, a1, a2)
}
func BridgeSystemInformationElemMethodMarshalAPERFreshValue(v *SystemInformationElem, a0 aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERFreshValue(a0, a1)
}
func BridgeSystemInformationElemMethodMarshalAPERLegacy(v *SystemInformationElem) ([]byte, error) {
	return v.marshalAPERLegacy()
}
func BridgeSystemInformationElemMethodMarshalAPERPlanned(v *SystemInformationElem, a0 *aper.DecodeBudget, a1 bool) ([]byte, error) {
	return v.marshalAPERPlanned(a0, a1)
}
func BridgeSystemInformationElemMethodMarshalAPERTo(v *SystemInformationElem, a0 *aper.BitBuffer, a1 ...bool) error {
	return v.marshalAPERTo(a0, a1...)
}
func BridgeSystemInformationElemMethodUnmarshalAPERFrom(v *SystemInformationElem, a0 *aper.BitBuffer) error {
	return v.unmarshalAPERFrom(a0)
}
func BridgeSystemInformationElemMethodUnmarshalAPERLegacy(v *SystemInformationElem, a0 []byte) error {
	return v.unmarshalAPERLegacy(a0)
}
func BridgeSystemInformationElemMethodUnmarshalAPERWithOptions(v *SystemInformationElem, a0 []byte, a1 aper.DecodeState) error {
	return v.unmarshalAPERWithOptions(a0, a1)
}
func BridgeSystemInformationElemValueCodecFieldCapture(v *SystemInformationElemValueCodec) *func(SystemInformationElem, aper.DecodeState) (SystemInformationElem, aper.Snapshot) {
	return &v.capture
}
func BridgeSystemInformationElemValueCodecFieldCompare(v *SystemInformationElemValueCodec) *func(SystemInformationElem, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeSystemInformationElemValueCodecFieldContext(v *SystemInformationElemValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSystemInformationElemValueCodecFieldDecode(v *SystemInformationElemValueCodec) *func([]byte, aper.DecodeState) (SystemInformationElem, error) {
	return &v.decode
}
func BridgeSystemInformationElemValueCodecFieldEncode(v *SystemInformationElemValueCodec) *func(SystemInformationElem, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSystemInformationElemValueCodecFieldPath(v *SystemInformationElemValueCodec) *aper.Path {
	return &v.path
}
func BridgeSystemInformationElemValueCodecMethodEncodeBudget(v SystemInformationElemValueCodec, a0 SystemInformationElem, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSystemInformationElemValueCodecMethodEncodeChanged(v SystemInformationElemValueCodec, a0 SystemInformationElem, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
func BridgeSystemInformationValueCodecFieldCapture(v *SystemInformationValueCodec) *func(SystemInformation, aper.DecodeState) (SystemInformation, aper.Snapshot) {
	return &v.capture
}
func BridgeSystemInformationValueCodecFieldCompare(v *SystemInformationValueCodec) *func(SystemInformation, aper.Snapshot, aper.ComparisonLimits) aper.ReplayPlan {
	return &v.compare
}
func BridgeSystemInformationValueCodecFieldContext(v *SystemInformationValueCodec) *s00.BridgeCodecContext {
	return &v.context
}
func BridgeSystemInformationValueCodecFieldDecode(v *SystemInformationValueCodec) *func([]byte, aper.DecodeState) (SystemInformation, error) {
	return &v.decode
}
func BridgeSystemInformationValueCodecFieldEncode(v *SystemInformationValueCodec) *func(SystemInformation, bool, *aper.DecodeBudget) ([]byte, error) {
	return &v.encode
}
func BridgeSystemInformationValueCodecFieldPath(v *SystemInformationValueCodec) *aper.Path {
	return &v.path
}
func BridgeSystemInformationValueCodecMethodEncodeBudget(v SystemInformationValueCodec, a0 SystemInformation, a1 bool, a2 aper.DecodeBudget) ([]byte, error) {
	return v.encodeBudget(a0, a1, a2)
}
func BridgeSystemInformationValueCodecMethodEncodeChanged(v SystemInformationValueCodec, a0 SystemInformation, a1 bool, a2 aper.ReplayPlan, a3 aper.DecodeBudget) ([]byte, error) {
	return v.encodeChanged(a0, a1, a2, a3)
}
